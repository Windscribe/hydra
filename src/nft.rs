//! Renders and applies a dedicated `table inet hydra`.
//!
//! Apply sends `add table`, `delete table`, and the full table in one
//! `nft -f -` call, so the ruleset changes atomically.

use crate::state::{Entry, State};
use crate::sys::Sys;
use std::fmt::Write as _;
use std::net::Ipv4Addr;

pub const TABLE: &str = "hydra";

#[derive(Debug, Clone, Default)]
pub struct RenderOpts {
    /// Interfaces for the software flowtable fast path. Empty disables it.
    pub flowtable_devices: Vec<String>,
}

/// One rule set per entry. Each entry's traffic arrives on its own local
/// address (the entry IP, or its bind address behind 1:1 NAT) and leaves for
/// one of its datacenter's servers from that same address.
pub fn render(entries: &[Entry], o: &RenderOpts) -> Result<String, String> {
    State {
        entries: entries.to_vec(),
        ..State::default()
    }
    .validate()?;
    for d in &o.flowtable_devices {
        if d.is_empty()
            || !d
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.@".contains(c))
        {
            return Err(format!("invalid interface name {d:?}"));
        }
    }
    for e in entries {
        if e.servers.is_empty() {
            return Err(format!(
                "entry {} has no servers: {} resolved to nothing",
                e.endpoint(),
                e.front().datacenter
            ));
        }
    }
    let mut s = String::new();
    let _ = writeln!(s, "table inet {TABLE} {{");
    if !o.flowtable_devices.is_empty() {
        let _ = writeln!(
            s,
            "  flowtable ft {{\n    hook ingress priority 0; devices = {{ {} }};\n  }}",
            o.flowtable_devices.join(", ")
        );
    }
    s.push_str("  chain prerouting {\n");
    s.push_str("    type nat hook prerouting priority dstnat; policy accept;\n");
    // New connections spread over the datacenter's servers by a hash of the
    // client's address and port, so a WireGuard session stays on one server.
    for e in entries {
        let f = e.front();
        let to = match e.servers.as_slice() {
            [one] => format!("{one}:{}", f.exit_port),
            many => format!(
                "jhash ip saddr . udp sport mod {} map {{ {} }}",
                many.len(),
                many.iter()
                    .enumerate()
                    .map(|(i, ip)| format!("{i} : {ip} . {}", f.exit_port))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
        let _ = writeln!(
            s,
            "    ip daddr {} udp dport {} counter dnat ip to {to}",
            e.local(),
            f.entry_port
        );
    }
    s.push_str("  }\n  chain postrouting {\n");
    s.push_str("    type nat hook postrouting priority srcnat; policy accept;\n");
    // Matched on the address the client dialled, not only the servers: two
    // entries can front the same datacenter, and each must leave from its own
    // IP.
    for e in entries {
        let f = e.front();
        let _ = writeln!(
            s,
            "    ip daddr {} udp dport {} ct original ip daddr {} ct original proto-dst {} ct status dnat snat ip to {}",
            set(&e.servers),
            f.exit_port,
            e.local(),
            f.entry_port,
            e.local()
        );
    }
    s.push_str("  }\n  chain forward {\n");
    s.push_str("    type filter hook forward priority filter; policy accept;\n");
    for e in entries {
        let (servers, port) = (set(&e.servers), e.front().exit_port);
        if !o.flowtable_devices.is_empty() {
            let _ = writeln!(
                s,
                "    ip daddr {servers} udp dport {port} ct state established flow add @ft"
            );
        }
        let _ = writeln!(s, "    ip daddr {servers} udp dport {port} accept");
        let _ = writeln!(s, "    ip saddr {servers} udp sport {port} accept");
    }
    s.push_str("  }\n}\n");
    Ok(s)
}

/// One address, or an nftables set of several.
fn set(servers: &[Ipv4Addr]) -> String {
    match servers {
        [one] => one.to_string(),
        many => format!(
            "{{ {} }}",
            many.iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Script that replaces the table. `add table` makes the delete valid on a
/// clean host, so one transaction works on first and later runs.
pub fn apply_script(entries: &[Entry], o: &RenderOpts) -> Result<String, String> {
    Ok(format!(
        "add table inet {TABLE}\ndelete table inet {TABLE}\n{}",
        render(entries, o)?
    ))
}

pub fn delete_script() -> String {
    format!("add table inet {TABLE}\ndelete table inet {TABLE}\n")
}

/// Applies the table. If the kernel rejects the flowtable, retries without it
/// and returns a warning instead of failing.
pub fn apply(sys: &Sys, entries: &[Entry], o: &RenderOpts) -> Result<Option<String>, String> {
    let script = apply_script(entries, o)?;
    match sys.run("nft", &["-f", "-"], Some(&script)) {
        Ok(_) => Ok(None),
        Err(e) if !o.flowtable_devices.is_empty() => {
            let plain = RenderOpts {
                flowtable_devices: vec![],
            };
            sys.run("nft", &["-f", "-"], Some(&apply_script(entries, &plain)?))?;
            let why = e.lines().next().unwrap_or_default();
            Ok(Some(format!(
                "flowtable fast path unavailable ({why}); using the normal forwarding path"
            )))
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{Front, Profile};

    fn entry(entry_ip: &str, servers: &[&str], bind: Option<&str>) -> Entry {
        Entry::new(
            Profile::new(
                "h",
                vec![Front {
                    location: String::new(),
                    datacenter: "yyz-1-wg.example".into(),
                    datacenter_id: 1,
                    exit_port: 443,
                    entry_ip: entry_ip.parse().unwrap(),
                    entry_port: 443,
                    protocol: "wireguard".into(),
                }],
            ),
            bind.map(|b| b.parse().unwrap()),
        )
        .with_servers(servers.iter().map(|s| s.parse().unwrap()).collect())
    }

    fn sample() -> Vec<Entry> {
        vec![entry("203.0.113.5", &["198.51.100.10"], None)]
    }

    #[test]
    fn renders_dnat_and_snat() {
        let s = render(&sample(), &RenderOpts::default()).unwrap();
        for want in [
            "table inet hydra",
            "ip daddr 203.0.113.5 udp dport 443 counter dnat ip to 198.51.100.10:443",
            "ip daddr 198.51.100.10 udp dport 443 ct original ip daddr 203.0.113.5 ct original proto-dst 443 ct status dnat snat ip to 203.0.113.5",
        ] {
            assert!(s.contains(want), "missing {want:?} in\n{s}");
        }
        assert!(!s.contains("flowtable"));
    }

    #[test]
    fn spreads_new_connections_over_the_datacenters_servers() {
        let e = entry(
            "203.0.113.5",
            &["198.51.100.10", "198.51.100.11", "198.51.100.12"],
            None,
        );
        let s = render(&[e], &RenderOpts::default()).unwrap();
        for want in [
            "ip daddr 203.0.113.5 udp dport 443 counter dnat ip to jhash ip saddr . udp sport mod 3 map { 0 : 198.51.100.10 . 443, 1 : 198.51.100.11 . 443, 2 : 198.51.100.12 . 443 }",
            "ip daddr { 198.51.100.10, 198.51.100.11, 198.51.100.12 } udp dport 443 ct original ip daddr 203.0.113.5",
            "ip saddr { 198.51.100.10, 198.51.100.11, 198.51.100.12 } udp sport 443 accept",
        ] {
            assert!(s.contains(want), "missing {want:?} in\n{s}");
        }
    }

    #[test]
    fn refuses_an_entry_without_servers() {
        let e = render(&[entry("203.0.113.5", &[], None)], &RenderOpts::default()).unwrap_err();
        assert!(e.contains("yyz-1-wg.example resolved to nothing"), "{e}");
    }

    #[test]
    fn bind_replaces_local_address_not_profile() {
        let s = render(
            &[entry("203.0.113.5", &["198.51.100.10"], Some("10.0.0.5"))],
            &RenderOpts::default(),
        )
        .unwrap();
        assert!(s.contains("ip daddr 10.0.0.5 udp dport 443 counter dnat"));
        assert!(s.contains("snat ip to 10.0.0.5"));
        assert!(!s.contains("203.0.113.5"));
    }

    #[test]
    fn each_entry_has_its_own_local_address() {
        let s = render(
            &[
                entry("192.0.2.50", &["198.51.100.10"], Some("10.0.0.5")),
                entry("192.0.2.51", &["198.51.100.20"], Some("10.0.0.6")),
            ],
            &RenderOpts::default(),
        )
        .unwrap();
        assert!(s.contains("ip daddr 10.0.0.5 udp dport 443 counter dnat ip to 198.51.100.10:443"));
        assert!(s.contains("ip daddr 10.0.0.6 udp dport 443 counter dnat ip to 198.51.100.20:443"));
    }

    #[test]
    fn two_entries_to_one_datacenter_each_leave_from_their_own_address() {
        let s = render(
            &[
                entry("203.0.113.5", &["198.51.100.10"], None),
                entry("203.0.113.6", &["198.51.100.10"], None),
            ],
            &RenderOpts::default(),
        )
        .unwrap();
        for ip in ["203.0.113.5", "203.0.113.6"] {
            let want = format!("ct original ip daddr {ip} ct original proto-dst 443 ct status dnat snat ip to {ip}");
            assert!(s.contains(&want), "missing {want:?} in\n{s}");
        }
    }

    #[test]
    fn refuses_two_entries_on_one_local_address() {
        let e = render(
            &[
                entry("203.0.113.5", &["198.51.100.10"], None),
                entry("192.0.2.50", &["198.51.100.20"], Some("203.0.113.5")),
            ],
            &RenderOpts::default(),
        )
        .unwrap_err();
        assert!(e.contains("203.0.113.5:443"), "{e}");
    }

    #[test]
    fn flowtable_rendering_and_validation() {
        let o = RenderOpts {
            flowtable_devices: vec!["eth0".into()],
        };
        let s = render(&sample(), &o).unwrap();
        assert!(s.contains("flowtable ft {"));
        assert!(s.contains("devices = { eth0 }"));
        assert!(s.contains("ct state established flow add @ft"));
        let bad = RenderOpts {
            flowtable_devices: vec!["eth0; flush ruleset".into()],
        };
        assert!(render(&sample(), &bad).is_err());
    }

    #[test]
    fn apply_is_single_idempotent_transaction() {
        let s = apply_script(&sample(), &RenderOpts::default()).unwrap();
        assert!(s.starts_with("add table inet hydra\ndelete table inet hydra\ntable inet hydra {"));
    }

    #[test]
    fn apply_falls_back_without_flowtable() {
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::<String>::new()));
        let s2 = seen.clone();
        let sys = Sys::fixture(
            "/nonexistent",
            Box::new(move |_, _, stdin| {
                let script = stdin.unwrap_or_default().to_string();
                let has_ft = script.contains("flowtable");
                s2.borrow_mut().push(script);
                if has_ft {
                    Err("nft failed: Error: Could not process rule: No such file or directory\nflowtable ft {\n^^^^^^^^".into())
                } else {
                    Ok(String::new())
                }
            }),
        );
        let o = RenderOpts {
            flowtable_devices: vec!["eth0".into()],
        };
        let warn = apply(&sys, &sample(), &o).unwrap().unwrap();
        assert!(warn.contains("No such file or directory"), "{warn}");
        assert!(!warn.contains('\n') && !warn.contains("^^^"), "{warn}");
        assert_eq!(seen.borrow().len(), 2);
    }
}
