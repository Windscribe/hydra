//! Whether a range's addresses reach this server as they are.
//!
//! A provider can route a whole range to a server, or expect the server to
//! answer for each address on the local network, as it does for the ones it
//! holds. hydra needs to know which before it maps an address the server
//! doesn't hold: it opens a TCP connection to a host that answers (the one
//! Windscribe's locations come from) with that address as the source, and
//! counts the answers that arrive for it. The address isn't added anywhere,
//! so an answer only arrives when the range is routed to the server.

use crate::sys::Sys;
use std::net::{Ipv4Addr, SocketAddrV4};

const TABLE: &str = "hydra_probe";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Answers to the address reach this server: the range is routed here.
    Routed,
    /// They don't: the server has to hold each address it uses (or the range
    /// isn't this server's).
    NotDelivered,
}

/// How traffic for `ip`, an address of a range this server doesn't hold,
/// reaches it. An error when the check itself can't run, such as `target`
/// not answering this server's own address either.
pub fn check(sys: &Sys, ip: Ipv4Addr, target: SocketAddrV4) -> Result<Delivery, String> {
    sys.connect(None, target)
        .map_err(|e| format!("{target} doesn't answer this server either ({e})"))?;
    let rule = format!(
        "ip saddr {} ip daddr {ip} tcp sport {} counter",
        target.ip(),
        target.port()
    );
    sys.run(
        "nft",
        &["-f", "-"],
        Some(&format!(
            "table inet {TABLE}\ndelete table inet {TABLE}\ntable inet {TABLE} {{\n  chain pre {{\n    type filter hook prerouting priority raw; policy accept;\n    {rule}\n  }}\n}}\n"
        )),
    )?;
    let sent = sys.connect(Some(ip), target);
    let counted = sys
        .run("nft", &["-j", "list", "table", "inet", TABLE], None)
        .map(|out| packets(&out));
    let _ = sys.run("nft", &["delete", "table", "inet", TABLE], None);
    sent.map_err(|e| format!("couldn't send from {ip}: {e}"))?;
    Ok(if counted? > 0 {
        Delivery::Routed
    } else {
        Delivery::NotDelivered
    })
}

/// The packets `nft -j list table` counted, summed over its counters.
fn packets(json: &str) -> u64 {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return 0;
    };
    v["nftables"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|o| o["rule"]["expr"].as_array())
        .flatten()
        .filter_map(|e| e["counter"]["packets"].as_u64())
        .sum()
}

/// Connects to `to`. From `from`, an address this host doesn't hold, it only
/// sends the first packet (IP_TRANSPARENT allows the source), waits for the
/// answer to arrive, and closes: the answer isn't delivered to the socket,
/// only counted.
pub fn connect(from: Option<Ipv4Addr>, to: SocketAddrV4) -> Result<(), String> {
    use std::time::Duration;
    let Some(from) = from else {
        return std::net::TcpStream::connect_timeout(&to.into(), Duration::from_secs(5))
            .map(|_| ())
            .map_err(|e| e.to_string());
    };
    // Held open while the answer may arrive, then closed.
    let _socket = send_from(from, to)?;
    std::thread::sleep(Duration::from_secs(3));
    Ok(())
}

#[cfg(target_os = "linux")]
fn send_from(from: Ipv4Addr, to: SocketAddrV4) -> Result<std::os::fd::OwnedFd, String> {
    use std::io::Error;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

    fn addr(ip: Ipv4Addr, port: u16) -> libc::sockaddr_in {
        libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(ip).to_be(),
            },
            sin_zero: [0; 8],
        }
    }
    let len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: plain socket calls on a descriptor this function owns; OwnedFd
    // closes it on every path.
    unsafe {
        let fd = libc::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        );
        if fd < 0 {
            return Err(Error::last_os_error().to_string());
        }
        let fd = OwnedFd::from_raw_fd(fd);
        let raw = fd.as_raw_fd();
        let one: libc::c_int = 1;
        if libc::setsockopt(
            raw,
            libc::SOL_IP,
            libc::IP_TRANSPARENT,
            (&one as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) < 0
        {
            return Err(format!("IP_TRANSPARENT: {}", Error::last_os_error()));
        }
        let src = addr(from, 0);
        if libc::bind(raw, (&src as *const libc::sockaddr_in).cast(), len) < 0 {
            return Err(format!("bind: {}", Error::last_os_error()));
        }
        let dst = addr(*to.ip(), to.port());
        if libc::connect(raw, (&dst as *const libc::sockaddr_in).cast(), len) < 0 {
            let e = Error::last_os_error();
            if e.raw_os_error() != Some(libc::EINPROGRESS) {
                return Err(format!("connect: {e}"));
            }
        }
        Ok(fd)
    }
}

#[cfg(not(target_os = "linux"))]
fn send_from(_: Ipv4Addr, _: SocketAddrV4) -> Result<std::os::fd::OwnedFd, String> {
    Err("checking a range needs Linux".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    fn sys(counted: u64, reachable: bool, calls: Rc<RefCell<Vec<String>>>) -> Sys {
        let list = format!(
            r#"{{"nftables":[{{"metainfo":{{}}}},{{"table":{{"name":"hydra_probe"}}}},{{"rule":{{"expr":[{{"match":{{}}}},{{"counter":{{"packets":{counted},"bytes":60}}}}]}}}}]}}"#
        );
        let log = calls.clone();
        Sys::fixture(
            std::env::temp_dir(),
            Box::new(move |cmd, args, stdin| {
                log.borrow_mut().push(format!(
                    "{cmd} {}{}",
                    args.join(" "),
                    stdin.map(|s| format!("\n{s}")).unwrap_or_default()
                ));
                if args.iter().any(|a| a == "-j") {
                    Ok(list.clone())
                } else {
                    Ok(String::new())
                }
            }),
        )
        .with_connector(move |from, to| {
            calls.borrow_mut().push(format!("connect {from:?} {to}"));
            if reachable {
                Ok(())
            } else {
                Err("timed out".into())
            }
        })
    }

    const IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
    const TARGET: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 1), 443);

    #[test]
    fn an_answer_to_the_address_means_the_range_is_routed_here() {
        let calls = Rc::new(RefCell::new(vec![]));
        assert_eq!(
            check(&sys(1, true, calls.clone()), IP, TARGET),
            Ok(Delivery::Routed)
        );
        let calls = calls.borrow();
        assert!(calls.iter().any(
            |c| c.contains("ip saddr 198.51.100.1 ip daddr 203.0.113.1 tcp sport 443 counter")
        ));
        assert!(calls
            .iter()
            .any(|c| c == "connect Some(203.0.113.1) 198.51.100.1:443"));
        assert_eq!(
            calls.last().unwrap(),
            "nft delete table inet hydra_probe",
            "it cleans up"
        );
    }

    #[test]
    fn no_answer_means_the_server_has_to_hold_the_address() {
        let calls = Rc::new(RefCell::new(vec![]));
        assert_eq!(
            check(&sys(0, true, calls), IP, TARGET),
            Ok(Delivery::NotDelivered)
        );
    }

    #[test]
    fn a_target_that_doesnt_answer_the_server_decides_nothing() {
        let calls = Rc::new(RefCell::new(vec![]));
        let e = check(&sys(0, false, calls.clone()), IP, TARGET).unwrap_err();
        assert!(e.contains("doesn't answer this server either"), "{e}");
        assert!(
            !calls.borrow().iter().any(|c| c.starts_with("nft")),
            "no table without a control answer"
        );
    }
}
