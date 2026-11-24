//! Latency probing and best-datacenter ranking.
//!
//! Probes Windscribe WireGuard datacenter hostnames concurrently using ICMP
//! echo requests (falling back to TCP connect timing if ICMP is unavailable or
//! blocked), then ranks candidates by a combined latency + server-load score.

use crate::datacenters::Datacenter;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs as _};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default per-probe timeout when benchmarking datacenters.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(1200);

/// Maximum number of concurrent DNS + ping worker threads.
const MAX_WORKERS: usize = 32;

/// Penalty in milliseconds added per 1% of datacenter load.
/// Example: 10% load adds 5.0 ms to the effective score.
const LOAD_WEIGHT_MS: f64 = 0.5;

/// Datacenters at or above this load percentage are heavily penalized so
/// congested servers are avoided when healthy ones exist.
const HIGH_LOAD_THRESHOLD: i64 = 80;
const HIGH_LOAD_PENALTY_MS: f64 = 1000.0;

/// A datacenter with its measured latency and combined ranking score.
#[derive(Debug, Clone)]
pub struct Ranked {
    pub dc: Datacenter,
    /// Minimum observed round-trip time in milliseconds, or `None` if unreachable.
    pub rtt_ms: Option<f64>,
    /// Lower is better.
    pub score: f64,
}

/// Computes the ranking score (lower is better) from latency (ms) and load (%).
pub fn score(rtt_ms: f64, load: i64) -> f64 {
    let clamped_load = load.max(0) as f64;
    let penalty = if load >= HIGH_LOAD_THRESHOLD {
        HIGH_LOAD_PENALTY_MS
    } else {
        0.0
    };
    rtt_ms + clamped_load * LOAD_WEIGHT_MS + penalty
}

/// Ranks `dcs` using the provided probe results (one optional RTT per datacenter,
/// aligned by index). Usable datacenters are preferred; reachable datacenters
/// always rank before unreachable ones.
pub fn rank(dcs: Vec<Datacenter>, rtts: Vec<Option<Duration>>) -> Vec<Ranked> {
    let mut ranked: Vec<Ranked> = dcs
        .into_iter()
        .zip(rtts)
        .map(|(dc, rtt)| match rtt {
            Some(d) => {
                let ms = d.as_secs_f64() * 1000.0;
                let s = score(ms, dc.load);
                Ranked {
                    dc,
                    rtt_ms: Some(ms),
                    score: s,
                }
            }
            None => Ranked {
                score: f64::INFINITY,
                dc,
                rtt_ms: None,
            },
        })
        .collect();

    ranked.sort_by(|a, b| {
        // Usable before drained, then reachable before unreachable, then score, then load.
        b.dc.usable
            .cmp(&a.dc.usable)
            .then_with(|| a.rtt_ms.is_none().cmp(&b.rtt_ms.is_none()))
            .then_with(|| a.score.total_cmp(&b.score))
            .then_with(|| a.dc.load.cmp(&b.dc.load))
            .then_with(|| a.dc.id.cmp(&b.dc.id))
    });
    ranked
}

/// Filters `dcs` to usable ones if any exist (falling back to all otherwise),
/// probes them with `probe_fn`, and returns them sorted best-first.
pub fn rank_datacenters(
    dcs: Vec<Datacenter>,
    timeout: Duration,
    probe_fn: impl Fn(&[String], Duration) -> Vec<Option<Duration>>,
) -> Vec<Ranked> {
    let has_usable = dcs.iter().any(|d| d.usable);
    let candidates: Vec<Datacenter> = if has_usable {
        dcs.into_iter().filter(|d| d.usable).collect()
    } else {
        dcs
    };
    if candidates.is_empty() {
        return vec![];
    }
    let hosts: Vec<String> = candidates.iter().map(|d| d.hostname.clone()).collect();
    let rtts = probe_fn(&hosts, timeout);
    rank(candidates, rtts)
}

/// Resolves and measures RTT for each hostname in `hosts` concurrently.
pub fn probe_hosts(hosts: &[String], timeout: Duration) -> Vec<Option<Duration>> {
    let n = hosts.len();
    if n == 0 {
        return vec![];
    }
    let results: Vec<Mutex<Option<Duration>>> = (0..n).map(|_| Mutex::new(None)).collect();
    let next = AtomicUsize::new(0);
    let workers = n.min(MAX_WORKERS);
    let pid = std::process::id() as u16;

    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| loop {
                let idx = next.fetch_add(1, Ordering::Relaxed);
                if idx >= n {
                    break;
                }
                let rtt = resolve_first_v4(&hosts[idx]).and_then(|ip| {
                    let icmp_id = pid.wrapping_add((idx as u16).wrapping_mul(17)).max(1);
                    measure_rtt(ip, icmp_id, timeout)
                });
                if let Ok(mut slot) = results[idx].lock() {
                    *slot = rtt;
                }
            });
        }
    });

    results
        .into_iter()
        .map(|m| m.into_inner().unwrap_or(None))
        .collect()
}

fn resolve_first_v4(host: &str) -> Option<Ipv4Addr> {
    (host, 0)
        .to_socket_addrs()
        .ok()?
        .find_map(|sa| match sa.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
}

/// Measures RTT to `ip`: tries ICMP Echo first (2 probes, taking minimum RTT),
/// then falls back to TCP connect RTT on port 443 if ICMP is unavailable/blocked.
pub fn measure_rtt(ip: Ipv4Addr, icmp_id: u16, timeout: Duration) -> Option<Duration> {
    if let Some(rtt1) = icmp_probe(ip, icmp_id, 1, timeout) {
        let second_timeout = timeout.min(Duration::from_millis(500));
        return match icmp_probe(ip, icmp_id, 2, second_timeout) {
            Some(rtt2) => Some(rtt1.min(rtt2)),
            None => Some(rtt1),
        };
    }
    tcp_rtt(ip, 443, timeout)
}

/// Measures 1-RTT latency using a TCP connect attempt. Both a completed
/// handshake and an immediate `ConnectionRefused` (TCP RST) indicate an active
/// round-trip response from the remote host.
fn tcp_rtt(ip: Ipv4Addr, port: u16, timeout: Duration) -> Option<Duration> {
    let addr = SocketAddr::from((ip, port));
    let start = Instant::now();
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => Some(start.elapsed()),
        Err(e) if e.kind() == ErrorKind::ConnectionRefused => Some(start.elapsed()),
        Err(_) => None,
    }
}

/// RFC 1071 16-bit one's complement ICMP checksum.
fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&b) = chunks.remainder().first() {
        sum += u32::from(b) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_echo_request(id: u16, seq: u16) -> [u8; 16] {
    let mut pkt = [0u8; 16];
    pkt[0] = 8; // ICMP Echo Request
    pkt[1] = 0; // code 0
    pkt[4..6].copy_from_slice(&id.to_be_bytes());
    pkt[6..8].copy_from_slice(&seq.to_be_bytes());
    pkt[8..16].copy_from_slice(b"hydrapng");
    let csum = icmp_checksum(&pkt);
    pkt[2..4].copy_from_slice(&csum.to_be_bytes());
    pkt
}

#[cfg(unix)]
fn icmp_probe(ip: Ipv4Addr, id: u16, seq: u16, timeout: Duration) -> Option<Duration> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

    // SAFETY: Standard POSIX socket / sendto / recvfrom calls on a descriptor
    // owned exclusively by this function and closed automatically by OwnedFd.
    unsafe {
        // Prefer unprivileged ICMP datagram socket; fall back to raw ICMP (root).
        let (raw_fd, is_dgram) = {
            let d = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP);
            if d >= 0 {
                (d, true)
            } else {
                let r = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP);
                if r < 0 {
                    return None;
                }
                (r, false)
            }
        };
        let fd = OwnedFd::from_raw_fd(raw_fd);
        let sock = fd.as_raw_fd();

        let mut dst: libc::sockaddr_in = std::mem::zeroed();
        #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
        {
            dst.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
        }
        dst.sin_family = libc::AF_INET as libc::sa_family_t;
        dst.sin_addr = libc::in_addr {
            s_addr: u32::from(ip).to_be(),
        };

        let pkt = build_echo_request(id, seq);
        let start = Instant::now();
        let sent = libc::sendto(
            sock,
            pkt.as_ptr().cast(),
            pkt.len(),
            0,
            (&dst as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        if sent < 0 {
            return None;
        }

        let deadline = start + timeout;
        let mut buf = [0u8; 512];
        loop {
            let remaining = deadline.checked_duration_since(Instant::now())?;
            if remaining.is_zero() {
                return None;
            }
            let tv = libc::timeval {
                tv_sec: remaining.as_secs() as libc::time_t,
                tv_usec: remaining.subsec_micros() as libc::suseconds_t,
            };
            libc::setsockopt(
                sock,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&tv as *const libc::timeval).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );

            let mut src: libc::sockaddr_in = std::mem::zeroed();
            let mut srclen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            let n = libc::recvfrom(
                sock,
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                (&mut src as *mut libc::sockaddr_in).cast(),
                &mut srclen,
            );
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == ErrorKind::Interrupted {
                    continue;
                }
                return None;
            }
            let rtt = start.elapsed();
            let from_ip = Ipv4Addr::from(u32::from_be(src.sin_addr.s_addr));
            if from_ip != ip {
                continue;
            }
            let data = &buf[..n as usize];

            // On Linux, SOCK_DGRAM IPPROTO_ICMP strips the IPv4 header and rewrites
            // the ICMP id internally; on raw sockets (and macOS dgram ICMP), the
            // IPv4 header is present.
            let (icmp, check_id) = if is_dgram && cfg!(target_os = "linux") {
                (data, false)
            } else {
                if data.len() < 20 {
                    continue;
                }
                let ihl = ((data[0] & 0x0f) as usize) * 4;
                if ihl < 20 || data.len() < ihl + 8 {
                    continue;
                }
                (&data[ihl..], !is_dgram)
            };

            if icmp.len() < 8 {
                continue;
            }
            let reply_type = icmp[0];
            let reply_code = icmp[1];
            let reply_id = u16::from_be_bytes([icmp[4], icmp[5]]);
            let reply_seq = u16::from_be_bytes([icmp[6], icmp[7]]);

            if reply_type == 0
                && reply_code == 0
                && reply_seq == seq
                && (!check_id || reply_id == id)
            {
                return Some(rtt);
            }
        }
    }
}

#[cfg(not(unix))]
fn icmp_probe(_ip: Ipv4Addr, _id: u16, _seq: u16, _timeout: Duration) -> Option<Duration> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dc(id: u32, city: &str, hostname: &str, load: i64, usable: bool) -> Datacenter {
        Datacenter {
            id,
            location: city.into(),
            country: "XX".into(),
            city: city.into(),
            nick: String::new(),
            hostname: hostname.into(),
            load,
            usable,
        }
    }

    #[test]
    fn checksum_verifies_echo_packet() {
        let pkt = build_echo_request(0x1234, 1);
        // Checksum over a valid ICMP packet (including checksum field) folds to 0.
        assert_eq!(icmp_checksum(&pkt), 0);
    }

    #[test]
    fn ranks_by_combined_latency_and_load() {
        let dcs = vec![
            dc(1, "Far", "far-1-wg.example.com", 1, true),
            dc(2, "NearBusy", "busy-2-wg.example.com", 90, true),
            dc(3, "NearBest", "best-3-wg.example.com", 4, true),
            dc(4, "Unreachable", "dead-4-wg.example.com", 1, true),
        ];
        let ranked = rank_datacenters(dcs, DEFAULT_TIMEOUT, |hosts, _| {
            hosts
                .iter()
                .map(|h| match h.as_str() {
                    "far-1-wg.example.com" => Some(Duration::from_millis(80)),
                    "busy-2-wg.example.com" => Some(Duration::from_millis(2)),
                    "best-3-wg.example.com" => Some(Duration::from_millis(5)),
                    _ => None,
                })
                .collect()
        });
        let order: Vec<&str> = ranked.iter().map(|r| r.dc.city.as_str()).collect();
        assert_eq!(order, vec!["NearBest", "Far", "NearBusy", "Unreachable"]);
        assert_eq!(ranked[0].rtt_ms, Some(5.0));
        assert_eq!(ranked[3].rtt_ms, None);
    }

    #[test]
    fn skips_drained_datacenters_when_usable_ones_exist() {
        let dcs = vec![
            dc(1, "DrainedFast", "a-1-wg.example.com", 1, false),
            dc(2, "Usable", "b-2-wg.example.com", 10, true),
        ];
        let ranked = rank_datacenters(dcs, DEFAULT_TIMEOUT, |hosts, _| {
            assert_eq!(hosts, &["b-2-wg.example.com"]);
            vec![Some(Duration::from_millis(15))]
        });
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].dc.city, "Usable");
    }
}
