//! Host helpers: addresses, interfaces, hostname.

use crate::sys::Sys;
use std::net::Ipv4Addr;

/// Interface and source address of the IPv4 default route.
pub fn default_route(sys: &Sys) -> Option<(String, Ipv4Addr)> {
    let out = sys
        .run("ip", &["-j", "-4", "route", "get", "192.0.2.1"], None)
        .ok()?;
    let v: serde_json::Value = serde_json::from_str(&out).ok()?;
    let r = v.as_array()?.first()?;
    Some((
        r["dev"].as_str()?.to_string(),
        r["prefsrc"].as_str()?.parse().ok()?,
    ))
}

/// IPv4 addresses assigned to local interfaces.
pub fn local_ipv4s(sys: &Sys) -> Vec<Ipv4Addr> {
    let Ok(out) = sys.run("ip", &["-j", "-4", "addr", "show"], None) else {
        return vec![];
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&out) else {
        return vec![];
    };
    v.as_array()
        .into_iter()
        .flatten()
        .flat_map(|i| i["addr_info"].as_array().cloned().unwrap_or_default())
        .filter_map(|a| a["local"].as_str().and_then(|s| s.parse().ok()))
        .collect()
}

/// The gateway of the IPv4 default route, if it has one.
pub fn default_gateway(sys: &Sys) -> Option<Ipv4Addr> {
    let out = sys
        .run("ip", &["-j", "-4", "route", "show", "default"], None)
        .ok()?;
    let v: serde_json::Value = serde_json::from_str(&out).ok()?;
    v.as_array()?
        .iter()
        .find_map(|r| r["gateway"].as_str()?.parse().ok())
}

/// The largest block an interface's prefix may imply and still be listed as
/// a range of this server's own: a bigger one (a cloud's /20) is the network
/// the server shares with others.
pub const MAX_RANGE_PREFIX: u8 = 22;

/// A block of public addresses an interface's address carries with it, such
/// as a /24: the provider may route all of it to this server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Range {
    pub network: Ipv4Addr,
    pub prefix: u8,
    pub iface: String,
    /// The addresses an entry can use: not the network or broadcast address,
    /// not the default gateway, and none the server already holds.
    pub addresses: Vec<Ipv4Addr>,
    /// Whether the default gateway is in it: then it is the network the
    /// server is on, which may be shared with others.
    pub has_gateway: bool,
}

impl Range {
    /// "203.0.113.0/24"
    pub fn cidr(&self) -> String {
        format!("{}/{}", self.network, self.prefix)
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = u32::MAX << (32 - u32::from(self.prefix));
        u32::from(ip) & mask == u32::from(self.network)
    }
}

/// The ranges this server's public addresses carry: a prefix from /22 to /30.
pub fn ranges(sys: &Sys) -> Vec<Range> {
    let Ok(out) = sys.run("ip", &["-j", "-4", "addr", "show"], None) else {
        return vec![];
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&out) else {
        return vec![];
    };
    let held = local_ipv4s(sys);
    let gateway = default_gateway(sys);
    let mut out: Vec<Range> = vec![];
    for i in v.as_array().into_iter().flatten() {
        let iface = i["ifname"].as_str().unwrap_or_default().to_string();
        for a in i["addr_info"].as_array().into_iter().flatten() {
            let (Some(ip), Some(prefix)) = (
                a["local"].as_str().and_then(|s| s.parse::<Ipv4Addr>().ok()),
                a["prefixlen"].as_u64().and_then(|p| u8::try_from(p).ok()),
            ) else {
                continue;
            };
            if !(MAX_RANGE_PREFIX..=30).contains(&prefix) || !is_public(ip) {
                continue;
            }
            let mask = u32::MAX << (32 - u32::from(prefix));
            let network = Ipv4Addr::from(u32::from(ip) & mask);
            if out
                .iter()
                .any(|r| r.network == network && r.prefix == prefix)
            {
                continue;
            }
            let broadcast = u32::from(network) | !mask;
            let addresses = (u32::from(network) + 1..broadcast)
                .map(Ipv4Addr::from)
                .filter(|a| !held.contains(a) && Some(*a) != gateway)
                .collect();
            let range = Range {
                network,
                prefix,
                iface: iface.clone(),
                addresses,
                has_gateway: false,
            };
            out.push(Range {
                has_gateway: gateway.is_some_and(|g| range.contains(g)),
                ..range
            });
        }
    }
    out
}

/// Interface that holds `ip`, if any.
pub fn iface_for(sys: &Sys, ip: Ipv4Addr) -> Option<String> {
    let out = sys.run("ip", &["-j", "-4", "addr", "show"], None).ok()?;
    let v: serde_json::Value = serde_json::from_str(&out).ok()?;
    v.as_array()?.iter().find_map(|i| {
        let has = i["addr_info"]
            .as_array()?
            .iter()
            .any(|a| a["local"].as_str() == Some(&ip.to_string()));
        has.then(|| i["ifname"].as_str().map(str::to_string))?
    })
}

/// Whether this process runs as root (its effective uid is 0).
pub fn is_root(sys: &Sys) -> bool {
    sys.read("/proc/self/status")
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Uid:"))
                .and_then(|ids| ids.split_whitespace().nth(1).map(|e| e == "0"))
        })
        .unwrap_or(false)
}

pub fn is_public(ip: Ipv4Addr) -> bool {
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_documentation()
        || ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64)
}

pub fn node_name(sys: &Sys) -> String {
    sys.read("/proc/sys/kernel/hostname")
        .and_then(|h| h.split('.').next().map(str::to_string))
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "hydra".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_checks() {
        assert!(is_public("8.8.8.8".parse().unwrap()));
        assert!(!is_public("10.0.0.1".parse().unwrap()));
        assert!(!is_public("100.64.1.1".parse().unwrap()));
        assert!(!is_public("203.0.113.5".parse().unwrap()));
    }

    #[test]
    fn parses_ip_json() {
        let sys = Sys::fixture(
            "/nonexistent",
            Box::new(|_, args, _| {
                Ok(if args.iter().any(|a| a == "route") {
                    r#"[{"dst":"192.0.2.1","gateway":"10.0.0.1","dev":"ens5","prefsrc":"10.0.0.5"}]"#
                } else {
                    r#"[{"ifname":"lo","addr_info":[{"local":"127.0.0.1"}]},{"ifname":"ens5","addr_info":[{"local":"10.0.0.5"}]}]"#
                }
                .to_string())
            }),
        );
        assert_eq!(
            default_route(&sys),
            Some(("ens5".into(), "10.0.0.5".parse().unwrap()))
        );
        assert_eq!(local_ipv4s(&sys).len(), 2);
        assert_eq!(
            iface_for(&sys, "10.0.0.5".parse().unwrap()).as_deref(),
            Some("ens5")
        );
    }

    /// bond0 holds an address of a /28 (the server's network: the gateway is
    /// in it) and the first address of a /24; ens5 a cloud's /20; eth1 a
    /// private network.
    fn ranged() -> Sys {
        Sys::fixture(
            "/nonexistent",
            Box::new(|_, args, _| {
                Ok(if args.iter().any(|a| a == "route") {
                    r#"[{"dst":"default","gateway":"45.33.20.206","dev":"bond0"}]"#
                } else {
                    r#"[{"ifname":"lo","addr_info":[{"local":"127.0.0.1","prefixlen":8}]},
                        {"ifname":"bond0","addr_info":[
                          {"local":"45.33.20.193","prefixlen":28},
                          {"local":"45.33.30.0","prefixlen":24},
                          {"local":"45.33.30.9","prefixlen":32}]},
                        {"ifname":"ens5","addr_info":[{"local":"45.34.0.5","prefixlen":20}]},
                        {"ifname":"eth1","addr_info":[{"local":"10.0.0.5","prefixlen":24}]}]"#
                }
                .to_string())
            }),
        )
    }

    #[test]
    fn the_default_gateway() {
        assert_eq!(
            default_gateway(&ranged()),
            Some("45.33.20.206".parse().unwrap())
        );
    }

    #[test]
    fn lists_the_ranges_public_addresses_carry() {
        let r = ranges(&ranged());
        let cidrs: Vec<String> = r.iter().map(Range::cidr).collect();
        assert_eq!(
            cidrs,
            ["45.33.20.192/28", "45.33.30.0/24"],
            "no /20, no private network"
        );

        let lan = &r[0];
        assert_eq!(lan.iface, "bond0");
        assert!(lan.has_gateway);
        assert_eq!(
            lan.addresses.len(),
            12,
            "16, less the network, broadcast, held and gateway"
        );
        assert_eq!(
            lan.addresses[0],
            "45.33.20.194".parse::<Ipv4Addr>().unwrap()
        );
        assert!(!lan.addresses.contains(&"45.33.20.206".parse().unwrap()));

        let routed = &r[1];
        assert!(!routed.has_gateway);
        assert_eq!(
            routed.addresses.len(),
            253,
            "254, less the address bond0 holds"
        );
        assert!(!routed.addresses.contains(&"45.33.30.9".parse().unwrap()));
        assert!(routed.contains("45.33.30.255".parse().unwrap()));
        assert!(!routed.contains("45.33.31.1".parse().unwrap()));
    }

    #[test]
    fn root_is_the_effective_uid() {
        let dir = std::env::temp_dir().join(format!("hydra-uid-{}", std::process::id()));
        let sys = Sys::fixture(&dir, Box::new(|_, _, _| Err("none".into())));
        assert!(!is_root(&sys), "no status file");
        sys.write("/proc/self/status", "Name:\thydra\nUid:\t1000\t0\t0\t0\n")
            .unwrap();
        assert!(is_root(&sys), "sudo: real 1000, effective 0");
        sys.write("/proc/self/status", "Uid:\t0\t1000\t1000\t1000\n")
            .unwrap();
        assert!(!is_root(&sys), "dropped privileges");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
