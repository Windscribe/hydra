//! Host audit: gathers facts, then derives findings with optional fixes.
//!
//! Gathering touches the system. Deriving findings is pure, so it is tested
//! with fixture facts.

use crate::sys::Sys;
use serde::Serialize;
use std::collections::BTreeMap;

pub const SYSCTL_FILE: &str = "/etc/sysctl.d/90-hydra.conf";

/// Conntrack ceiling recommended once the host has at least 1 GiB of RAM.
/// One WireGuard client uses one entry; memory is allocated on use.
pub const CONNTRACK_TARGET: u64 = 262_144;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Ok,
    Info,
    Warn,
    Fail,
}

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Severity::Ok => "ok",
            Severity::Info => "info",
            Severity::Warn => "warn",
            Severity::Fail => "FAIL",
        }
    }
}

/// How a fix is applied, and how disruptive it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Fix {
    /// Runtime sysctl. Persisted to SYSCTL_FILE with `--persist`.
    Sysctl { name: String, value: String },
    /// Write a sysfs value (RPS masks). Not persistent.
    Sysfs { path: String, value: String },
    /// ethtool change. Only applied with `--nic`; may reset the link briefly.
    Ethtool { args: Vec<String> },
}

impl Fix {
    pub fn command(&self) -> String {
        match self {
            Fix::Sysctl { name, value } => format!("sysctl -w {name}={value}"),
            Fix::Sysfs { path, value } => format!("echo {value} > {path}"),
            Fix::Ethtool { args } => format!("ethtool {}", args.join(" ")),
        }
    }

    pub fn is_nic(&self) -> bool {
        matches!(self, Fix::Ethtool { .. })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: String,
    pub area: &'static str,
    pub severity: Severity,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<Fix>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Pair {
    pub current: u64,
    pub max: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Nic {
    pub name: String,
    pub mtu: Option<u64>,
    pub driver: Option<String>,
    pub channels: Option<Pair>,
    pub rx_ring: Option<Pair>,
    pub tx_ring: Option<Pair>,
    /// ethtool -k features, e.g. "generic-receive-offload" -> "on".
    pub features: BTreeMap<String, String>,
    pub rx_queues: usize,
    pub rps_cpus: Option<String>,
    pub rx_dropped: Option<u64>,
    pub rx_missed: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Facts {
    pub kernel: Option<String>,
    pub cpus: usize,
    pub mem_total_kb: Option<u64>,
    pub sysctl: BTreeMap<String, String>,
    pub conntrack_count: Option<u64>,
    pub conntrack_drops: Option<u64>,
    pub softnet_dropped: u64,
    pub softnet_squeezed: u64,
    pub nic: Option<Nic>,
    pub nft_available: bool,
    /// "family table chain" for forward-hook chains with policy drop.
    pub forward_drop_chains: Vec<String>,
    pub iptables_legacy_forward_drop: bool,
    pub hydra_table: bool,
    pub hydra_flowtable: bool,
    pub hydra_new_flows: Option<u64>,
    pub irqbalance: bool,
    /// What the entries forward to: each datacenter's hostname and port.
    pub profile_exits: Vec<String>,
    /// Whether the `conntrack` tool is installed, which hydra uses to move
    /// connected clients when a datacenter changes.
    pub conntrack_tool: bool,
}

pub const SYSCTLS: &[&str] = &[
    "net.ipv4.ip_forward",
    "net.core.netdev_max_backlog",
    "net.core.netdev_budget",
    "net.core.netdev_budget_usecs",
    "net.netfilter.nf_conntrack_max",
    "net.netfilter.nf_conntrack_udp_timeout",
    "net.netfilter.nf_conntrack_udp_timeout_stream",
    "net.ipv4.conf.all.rp_filter",
];

/// Recommended values. Only raised, never lowered.
const RAISE: &[(&str, u64, &str)] = &[
    (
        "net.core.netdev_max_backlog",
        16_384,
        "per-CPU input queue; small values drop bursts at high packet rates",
    ),
    (
        "net.core.netdev_budget",
        600,
        "packets handled per softirq cycle",
    ),
    (
        "net.core.netdev_budget_usecs",
        8_000,
        "time budget per softirq cycle",
    ),
];

// ---------- gathering ----------

/// `exits`: what the entries forward to, `hostname:port`.
pub fn gather(sys: &Sys, iface: Option<&str>, exits: &[String]) -> Facts {
    let mut f = Facts {
        kernel: sys.read("/proc/sys/kernel/osrelease"),
        cpus: sys
            .read("/sys/devices/system/cpu/online")
            .map(|s| count_cpu_list(&s))
            .unwrap_or(1),
        mem_total_kb: sys.read("/proc/meminfo").and_then(|m| parse_meminfo(&m)),
        ..Default::default()
    };
    for name in SYSCTLS {
        if let Some(v) = sys.sysctl(name) {
            f.sysctl.insert(name.to_string(), v);
        }
    }
    f.conntrack_count = sys
        .sysctl("net.netfilter.nf_conntrack_count")
        .and_then(|v| v.parse().ok());
    f.conntrack_drops = sys
        .read("/proc/net/stat/nf_conntrack")
        .and_then(|s| parse_conntrack_stat(&s));
    if let Some(s) = sys.read("/proc/net/softnet_stat") {
        let (d, q) = parse_softnet(&s);
        f.softnet_dropped = d;
        f.softnet_squeezed = q;
    }

    let iface = iface
        .map(str::to_string)
        .or_else(|| default_route_iface(sys));
    if let Some(name) = iface {
        f.nic = Some(gather_nic(sys, &name));
    }

    match sys.run("nft", &["-j", "list", "ruleset"], None) {
        Ok(json) => {
            f.nft_available = true;
            let r = parse_ruleset(&json);
            f.forward_drop_chains = r.forward_drop_chains;
            f.hydra_table = r.hydra_table;
            f.hydra_flowtable = r.hydra_flowtable;
            f.hydra_new_flows = r.hydra_new_flows;
        }
        Err(_) => f.nft_available = false,
    }
    f.iptables_legacy_forward_drop = sys
        .run("iptables-legacy", &["-S", "FORWARD"], None)
        .map(|s| s.lines().any(|l| l.trim() == "-P FORWARD DROP"))
        .unwrap_or(false);
    f.irqbalance = sys
        .run("pidof", &["irqbalance"], None)
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    f.profile_exits = exits.to_vec();
    f.conntrack_tool = sys.run("conntrack", &["--version"], None).is_ok();
    f
}

fn gather_nic(sys: &Sys, name: &str) -> Nic {
    let base = format!("/sys/class/net/{name}");
    let mut nic = Nic {
        name: name.to_string(),
        mtu: sys
            .read(&format!("{base}/mtu"))
            .and_then(|v| v.parse().ok()),
        driver: sys.link_name(&format!("{base}/device/driver")),
        rx_dropped: sys
            .read(&format!("{base}/statistics/rx_dropped"))
            .and_then(|v| v.parse().ok()),
        rx_missed: sys
            .read(&format!("{base}/statistics/rx_missed_errors"))
            .and_then(|v| v.parse().ok()),
        ..Default::default()
    };
    let queues: Vec<String> = sys
        .list(&format!("{base}/queues"))
        .into_iter()
        .filter(|q| q.starts_with("rx-"))
        .collect();
    nic.rx_queues = queues.len();
    nic.rps_cpus = sys.read(&format!("{base}/queues/rx-0/rps_cpus"));
    if let Ok(out) = sys.run("ethtool", &["-l", name], None) {
        nic.channels = parse_ethtool_pair(&out, "Combined");
    }
    if let Ok(out) = sys.run("ethtool", &["-g", name], None) {
        nic.rx_ring = parse_ethtool_pair(&out, "RX");
        nic.tx_ring = parse_ethtool_pair(&out, "TX");
    }
    if let Ok(out) = sys.run("ethtool", &["-k", name], None) {
        nic.features = parse_ethtool_features(&out);
    }
    nic
}

fn default_route_iface(sys: &Sys) -> Option<String> {
    let routes = sys.read("/proc/net/route")?;
    routes.lines().skip(1).find_map(|l| {
        let cols: Vec<&str> = l.split_whitespace().collect();
        (cols.len() > 2 && cols[1] == "00000000").then(|| cols[0].to_string())
    })
}

// ---------- parsers ----------

pub fn count_cpu_list(s: &str) -> usize {
    s.trim()
        .split(',')
        .filter(|p| !p.is_empty())
        .map(|part| match part.split_once('-') {
            Some((a, b)) => match (a.parse::<usize>(), b.parse::<usize>()) {
                (Ok(a), Ok(b)) if b >= a => b - a + 1,
                _ => 0,
            },
            None => usize::from(part.parse::<usize>().is_ok()),
        })
        .sum::<usize>()
        .max(1)
}

pub fn parse_meminfo(s: &str) -> Option<u64> {
    s.lines()
        .find(|l| l.starts_with("MemTotal:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
}

/// Sum of drop + early_drop + insert_failed across CPUs (hex columns).
pub fn parse_conntrack_stat(s: &str) -> Option<u64> {
    let mut lines = s.lines();
    let header: Vec<&str> = lines.next()?.split_whitespace().collect();
    let idx: Vec<usize> = header
        .iter()
        .enumerate()
        .filter(|(_, h)| matches!(**h, "drop" | "early_drop" | "insert_failed"))
        .map(|(i, _)| i)
        .collect();
    if idx.is_empty() {
        return None;
    }
    let mut total = 0u64;
    for l in lines {
        let cols: Vec<&str> = l.split_whitespace().collect();
        for &i in &idx {
            if let Some(v) = cols.get(i).and_then(|c| u64::from_str_radix(c, 16).ok()) {
                total += v;
            }
        }
    }
    Some(total)
}

/// (dropped, time_squeeze) summed across CPUs.
pub fn parse_softnet(s: &str) -> (u64, u64) {
    s.lines().fold((0, 0), |(d, q), l| {
        let cols: Vec<&str> = l.split_whitespace().collect();
        let hex = |i: usize| {
            cols.get(i)
                .and_then(|c| u64::from_str_radix(c, 16).ok())
                .unwrap_or(0)
        };
        (d + hex(1), q + hex(2))
    })
}

/// Reads `<key>:` under "Pre-set maximums" and "Current hardware settings".
pub fn parse_ethtool_pair(s: &str, key: &str) -> Option<Pair> {
    let mut section = "";
    let (mut max, mut cur) = (None, None);
    for l in s.lines() {
        let t = l.trim();
        if t.starts_with("Pre-set maximums") {
            section = "max";
            continue;
        }
        if t.starts_with("Current hardware settings") {
            section = "cur";
            continue;
        }
        if let Some((k, v)) = t.split_once(':') {
            if k.trim() == key {
                let v = v.trim().parse::<u64>().ok();
                match section {
                    "max" => max = v,
                    "cur" => cur = v,
                    _ => {}
                }
            }
        }
    }
    Some(Pair {
        current: cur?,
        max: max?,
    })
}

pub fn parse_ethtool_features(s: &str) -> BTreeMap<String, String> {
    s.lines()
        .skip(1)
        .filter_map(|l| {
            let (k, v) = l.trim().split_once(':')?;
            let v = v.split_whitespace().next()?.to_string();
            let v = if l.contains("[fixed]") {
                format!("{v}-fixed")
            } else {
                v
            };
            Some((k.trim().to_string(), v))
        })
        .collect()
}

#[derive(Default)]
pub struct Ruleset {
    pub forward_drop_chains: Vec<String>,
    pub hydra_table: bool,
    pub hydra_flowtable: bool,
    pub hydra_new_flows: Option<u64>,
}

pub fn parse_ruleset(json: &str) -> Ruleset {
    let mut r = Ruleset::default();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return r;
    };
    let Some(items) = v.get("nftables").and_then(|x| x.as_array()) else {
        return r;
    };
    for item in items {
        if let Some(t) = item.get("table") {
            if t["family"] == "inet" && t["name"] == "hydra" {
                r.hydra_table = true;
            }
        }
        if let Some(ft) = item.get("flowtable") {
            if ft["family"] == "inet" && ft["table"] == "hydra" {
                r.hydra_flowtable = true;
            }
        }
        if let Some(c) = item.get("chain") {
            let hydra = c["family"] == "inet" && c["table"] == "hydra";
            if c["hook"] == "forward" && c["policy"] == "drop" && !hydra {
                r.forward_drop_chains.push(format!(
                    "{} {} {}",
                    c["family"].as_str().unwrap_or("?"),
                    c["table"].as_str().unwrap_or("?"),
                    c["name"].as_str().unwrap_or("?")
                ));
            }
        }
        if let Some(rule) = item.get("rule") {
            if rule["family"] == "inet" && rule["table"] == "hydra" && rule["chain"] == "prerouting"
            {
                let packets = rule["expr"].as_array().and_then(|exprs| {
                    exprs
                        .iter()
                        .find_map(|e| e.get("counter").and_then(|c| c["packets"].as_u64()))
                });
                if let Some(p) = packets {
                    r.hydra_new_flows = Some(r.hydra_new_flows.unwrap_or(0) + p);
                }
            }
        }
    }
    r
}

// ---------- findings ----------

fn sysctl_u64(f: &Facts, name: &str) -> Option<u64> {
    f.sysctl.get(name).and_then(|v| v.parse().ok())
}

fn fix_sysctl(name: &str, value: impl ToString) -> Option<Fix> {
    Some(Fix::Sysctl {
        name: name.into(),
        value: value.to_string(),
    })
}

/// CPU mask covering `n` CPUs, in the comma-grouped hex format sysfs uses.
pub fn cpu_mask(n: usize) -> String {
    let n = n.clamp(1, 1024);
    let mut words: Vec<String> = Vec::new();
    let mut left = n;
    while left > 0 {
        let bits = left.min(32);
        let w: u64 = if bits == 32 {
            0xffff_ffff
        } else {
            (1u64 << bits) - 1
        };
        words.push(format!("{w:08x}"));
        left -= bits;
    }
    words.reverse();
    let s = words.join(",");
    let trimmed = s.trim_start_matches('0');
    if trimmed.is_empty() || trimmed.starts_with(',') {
        s
    } else {
        trimmed.to_string()
    }
}

fn mask_is_zero(mask: &str) -> bool {
    mask.chars().all(|c| c == '0' || c == ',')
}

pub fn findings(f: &Facts) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut push = |id: &str, area: &'static str, sev: Severity, summary: String, fix| {
        out.push(Finding {
            id: id.into(),
            area,
            severity: sev,
            summary,
            fix,
        })
    };

    // Forwarding is required.
    match f.sysctl.get("net.ipv4.ip_forward").map(String::as_str) {
        Some("1") => push(
            "ip_forward",
            "sysctl",
            Severity::Ok,
            "IPv4 forwarding is on".into(),
            None,
        ),
        _ => push(
            "ip_forward",
            "sysctl",
            Severity::Fail,
            "IPv4 forwarding is off; nothing will be forwarded".into(),
            fix_sysctl("net.ipv4.ip_forward", 1),
        ),
    }

    for (name, target, why) in RAISE {
        match sysctl_u64(f, name) {
            Some(cur) if cur < *target => push(
                name,
                "sysctl",
                Severity::Warn,
                format!("{name} = {cur}, recommend {target} ({why})"),
                fix_sysctl(name, target),
            ),
            Some(cur) => push(
                name,
                "sysctl",
                Severity::Ok,
                format!("{name} = {cur}"),
                None,
            ),
            None => {}
        }
    }

    // Conntrack: every forwarded WireGuard client is one NAT entry.
    let ct_max = sysctl_u64(f, "net.netfilter.nf_conntrack_max");
    match ct_max {
        None => push(
            "conntrack",
            "conntrack",
            Severity::Info,
            "conntrack not loaded yet (it loads with the first NAT rule)".into(),
            None,
        ),
        Some(max) => {
            let big_enough_host = f.mem_total_kb.unwrap_or(0) >= 1024 * 1024;
            let count = f.conntrack_count.unwrap_or(0);
            let used = (count * 100).checked_div(max).unwrap_or(0);
            if max < CONNTRACK_TARGET && big_enough_host {
                push(
                    "conntrack_max",
                    "conntrack",
                    Severity::Warn,
                    format!(
                        "nf_conntrack_max = {max} ({count} in use), recommend {CONNTRACK_TARGET}"
                    ),
                    fix_sysctl("net.netfilter.nf_conntrack_max", CONNTRACK_TARGET),
                );
            } else if used >= 80 {
                let target = (max * 2).min(4 * 1024 * 1024);
                push(
                    "conntrack_max",
                    "conntrack",
                    Severity::Warn,
                    format!("conntrack table {used}% full ({count}/{max})"),
                    fix_sysctl("net.netfilter.nf_conntrack_max", target),
                );
            } else {
                push(
                    "conntrack_max",
                    "conntrack",
                    Severity::Ok,
                    format!("nf_conntrack_max = {max} ({count} in use)"),
                    None,
                );
            }
        }
    }
    if let Some(d) = f.conntrack_drops.filter(|d| *d > 0) {
        push(
            "conntrack_drops",
            "conntrack",
            Severity::Warn,
            format!("{d} conntrack drops/insert failures since boot (table pressure)"),
            None,
        );
    }
    if let Some(t) = sysctl_u64(f, "net.netfilter.nf_conntrack_udp_timeout_stream") {
        if t < 60 {
            push(
                "udp_timeout_stream",
                "conntrack",
                Severity::Warn,
                format!("nf_conntrack_udp_timeout_stream = {t}s; idle tunnels lose their NAT entry quickly"),
                fix_sysctl("net.netfilter.nf_conntrack_udp_timeout_stream", 120),
            );
        }
    }

    if f.softnet_dropped > 0 {
        push(
            "softnet_dropped",
            "cpu",
            Severity::Warn,
            format!(
                "{} packets dropped by full CPU backlogs since boot",
                f.softnet_dropped
            ),
            None,
        );
    }
    if f.softnet_squeezed > 0 {
        push(
            "softnet_squeezed",
            "cpu",
            Severity::Info,
            format!(
                "softirq ran out of budget {} times since boot",
                f.softnet_squeezed
            ),
            None,
        );
    }

    // Firewall.
    if !f.nft_available {
        push(
            "nft",
            "firewall",
            Severity::Fail,
            "nft not found or not permitted; install nftables and run as root".into(),
            None,
        );
    }
    for chain in &f.forward_drop_chains {
        push(
            "forward_drop",
            "firewall",
            Severity::Fail,
            format!(
                "chain `{chain}` drops forwarded traffic by default; an accept in hydra does not override it. Allow the connections hydra redirects there: `ct status dnat accept` (nftables) or `-m conntrack --ctstate DNAT -j ACCEPT` (iptables). Docker and ufw set this"
            ),
            None,
        );
    }
    if !f.conntrack_tool && !f.profile_exits.is_empty() {
        push(
            "conntrack_tool",
            "failover",
            Severity::Warn,
            "`conntrack` is missing; clients follow datacenter changes only when they reconnect (apt install conntrack)".into(),
            None,
        );
    }
    if f.iptables_legacy_forward_drop {
        push(
            "legacy_forward_drop",
            "firewall",
            Severity::Fail,
            "iptables-legacy FORWARD policy is DROP; allow the hydra flow there too".into(),
            None,
        );
    }
    if f.nft_available {
        if f.hydra_table {
            let flows = f
                .hydra_new_flows
                .map(|n| format!(", {n} flows NATed"))
                .unwrap_or_default();
            push(
                "hydra_table",
                "hydra",
                Severity::Ok,
                format!("table inet hydra is loaded{flows}"),
                None,
            );
            if !f.hydra_flowtable {
                push(
                    "flowtable",
                    "hydra",
                    Severity::Info,
                    "no flowtable fast path; established flows go through the full netfilter path. Re-run `hydra up` (it enables one when the kernel supports it)".into(),
                    None,
                );
            }
        } else {
            push(
                "hydra_table",
                "hydra",
                Severity::Info,
                "table inet hydra is not loaded (run `hydra up`)".into(),
                None,
            );
        }
    }

    if let Some(nic) = &f.nic {
        nic_findings(f, nic, &mut push);
    }

    out.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.area.cmp(b.area)));
    out
}

fn nic_findings(
    f: &Facts,
    nic: &Nic,
    push: &mut impl FnMut(&str, &'static str, Severity, String, Option<Fix>),
) {
    let n = &nic.name;
    let drv = nic.driver.as_deref().unwrap_or("unknown driver");
    push(
        "nic",
        "nic",
        Severity::Info,
        format!(
            "{n}: {drv}, {} rx queue(s), {} CPU(s), irqbalance {}",
            nic.rx_queues,
            f.cpus,
            if f.irqbalance {
                "running"
            } else {
                "not running"
            }
        ),
        None,
    );
    if let Some(mtu) = nic.mtu.filter(|m| *m < 1500) {
        push(
            "mtu",
            "nic",
            Severity::Warn,
            format!("{n} MTU is {mtu}; WireGuard packets sized for 1500 may fragment or drop"),
            None,
        );
    }
    if let Some(ch) = &nic.channels {
        if ch.current < ch.max {
            push(
                "channels",
                "nic",
                Severity::Warn,
                format!(
                    "{n} uses {}/{} queues; more queues spread packets over more CPUs",
                    ch.current, ch.max
                ),
                Some(Fix::Ethtool {
                    args: vec![
                        "-L".into(),
                        n.clone(),
                        "combined".into(),
                        ch.max.to_string(),
                    ],
                }),
            );
        }
    }
    if let (Some(rx), Some(tx)) = (&nic.rx_ring, &nic.tx_ring) {
        if rx.current < rx.max || tx.current < tx.max {
            push(
                "rings",
                "nic",
                Severity::Warn,
                format!(
                    "{n} rings rx {}/{} tx {}/{}; larger rings absorb bursts",
                    rx.current, rx.max, tx.current, tx.max
                ),
                Some(Fix::Ethtool {
                    args: vec![
                        "-G".into(),
                        n.clone(),
                        "rx".into(),
                        rx.max.to_string(),
                        "tx".into(),
                        tx.max.to_string(),
                    ],
                }),
            );
        }
    }
    let feat = |k: &str| nic.features.get(k).map(String::as_str);
    if feat("generic-receive-offload") == Some("on") {
        if feat("rx-udp-gro-forwarding") == Some("off") {
            push(
                "udp_gro_forwarding",
                "nic",
                Severity::Warn,
                format!("{n} rx-udp-gro-forwarding is off; turning it on batches forwarded UDP"),
                Some(Fix::Ethtool {
                    args: vec![
                        "-K".into(),
                        n.clone(),
                        "rx-udp-gro-forwarding".into(),
                        "on".into(),
                    ],
                }),
            );
        }
    } else if feat("generic-receive-offload") == Some("off") {
        push(
            "gro",
            "nic",
            Severity::Warn,
            format!("{n} GRO is off"),
            Some(Fix::Ethtool {
                args: vec!["-K".into(), n.clone(), "gro".into(), "on".into()],
            }),
        );
    }
    // One RX queue on a multi-CPU host: spread with RPS instead.
    if nic.rx_queues == 1 && f.cpus > 1 {
        let single_hw_queue = nic.channels.as_ref().map(|c| c.max <= 1).unwrap_or(true);
        if single_hw_queue {
            if let Some(mask) = &nic.rps_cpus {
                if mask_is_zero(mask) {
                    push(
                        "rps",
                        "cpu",
                        Severity::Warn,
                        format!("{n} has one RX queue and RPS is off; all packets land on one CPU"),
                        Some(Fix::Sysfs {
                            path: format!("/sys/class/net/{n}/queues/rx-0/rps_cpus"),
                            value: cpu_mask(f.cpus),
                        }),
                    );
                }
            }
        }
    }
    if let Some(d) = nic.rx_dropped.filter(|d| *d > 0) {
        push(
            "rx_dropped",
            "nic",
            Severity::Info,
            format!("{n} rx_dropped = {d} since boot"),
            None,
        );
    }
    if let Some(m) = nic.rx_missed.filter(|m| *m > 0) {
        push(
            "rx_missed",
            "nic",
            Severity::Warn,
            format!("{n} rx_missed_errors = {m}; the NIC ring overflowed"),
            None,
        );
    }
}

// ---------- output and apply ----------

pub fn render_text(f: &Facts, findings: &[Finding]) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "kernel {}  cpus {}  mem {} MiB\n\n",
        f.kernel.as_deref().unwrap_or("?"),
        f.cpus,
        f.mem_total_kb.map(|k| k / 1024).unwrap_or(0)
    ));
    for x in findings {
        s.push_str(&format!(
            "[{:<4}] {:<9} {}\n",
            x.severity.label(),
            x.area,
            x.summary
        ));
        if let Some(fix) = &x.fix {
            s.push_str(&format!("                 fix: {}\n", fix.command()));
        }
    }
    s
}

pub struct ApplyOpts {
    pub nic: bool,
    pub persist: bool,
}

pub struct ApplyReport {
    pub applied: Vec<String>,
    pub skipped: Vec<String>,
    pub errors: Vec<String>,
}

pub fn apply(sys: &Sys, findings: &[Finding], opts: &ApplyOpts) -> ApplyReport {
    let mut rep = ApplyReport {
        applied: vec![],
        skipped: vec![],
        errors: vec![],
    };
    let mut persisted: Vec<(String, String)> = vec![];
    for fx in findings.iter().filter_map(|x| x.fix.as_ref()) {
        if fx.is_nic() && !opts.nic {
            rep.skipped.push(format!(
                "{} (needs --nic; may reset the link)",
                fx.command()
            ));
            continue;
        }
        let res = match fx {
            Fix::Sysctl { name, value } => {
                let r = sys.set_sysctl(name, value);
                if r.is_ok() {
                    persisted.push((name.clone(), value.clone()));
                }
                r
            }
            Fix::Sysfs { path, value } => sys.write(path, &format!("{value}\n")),
            Fix::Ethtool { args } => {
                let a: Vec<&str> = args.iter().map(String::as_str).collect();
                sys.run("ethtool", &a, None).map(|_| ())
            }
        };
        match res {
            Ok(()) => rep.applied.push(fx.command()),
            Err(e) => rep.errors.push(format!("{}: {e}", fx.command())),
        }
    }
    if opts.persist && !persisted.is_empty() {
        match persist_sysctls(sys, &persisted) {
            Ok(()) => rep.applied.push(format!("wrote {SYSCTL_FILE}")),
            Err(e) => rep.errors.push(e),
        }
    }
    rep
}

/// Merges into SYSCTL_FILE so repeated runs keep earlier keys.
fn persist_sysctls(sys: &Sys, new: &[(String, String)]) -> Result<(), String> {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    if let Some(existing) = sys.read(SYSCTL_FILE) {
        for l in existing.lines() {
            if let Some((k, v)) = l.split_once('=') {
                if !l.trim_start().starts_with('#') {
                    map.insert(k.trim().into(), v.trim().into());
                }
            }
        }
    }
    for (k, v) in new {
        map.insert(k.clone(), v.clone());
    }
    let mut body = String::from("# Written by hydra tune --persist\n");
    for (k, v) in &map {
        body.push_str(&format!("{k} = {v}\n"));
    }
    sys.write(SYSCTL_FILE, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> Facts {
        let mut f = Facts {
            cpus: 4,
            mem_total_kb: Some(4 * 1024 * 1024),
            nft_available: true,
            ..Default::default()
        };
        for (k, v) in [
            ("net.ipv4.ip_forward", "0"),
            ("net.core.netdev_max_backlog", "1000"),
            ("net.core.netdev_budget", "300"),
            ("net.core.netdev_budget_usecs", "2000"),
            ("net.netfilter.nf_conntrack_max", "65536"),
            ("net.netfilter.nf_conntrack_udp_timeout_stream", "120"),
        ] {
            f.sysctl.insert(k.into(), v.into());
        }
        f
    }

    fn by_id<'a>(v: &'a [Finding], id: &str) -> &'a Finding {
        v.iter()
            .find(|x| x.id == id)
            .unwrap_or_else(|| panic!("no {id}"))
    }

    #[test]
    fn defaults_produce_fixes() {
        let out = findings(&facts());
        assert_eq!(by_id(&out, "ip_forward").severity, Severity::Fail);
        assert_eq!(
            by_id(&out, "net.core.netdev_max_backlog").fix,
            fix_sysctl("net.core.netdev_max_backlog", 16_384)
        );
        assert_eq!(
            by_id(&out, "conntrack_max").fix,
            fix_sysctl("net.netfilter.nf_conntrack_max", CONNTRACK_TARGET)
        );
        assert_eq!(out[0].severity, Severity::Fail, "sorted worst first");
    }

    #[test]
    fn never_lowers_tuned_values() {
        let mut f = facts();
        f.sysctl
            .insert("net.core.netdev_max_backlog".into(), "250000".into());
        f.sysctl
            .insert("net.netfilter.nf_conntrack_max".into(), "1048576".into());
        let out = findings(&f);
        assert!(by_id(&out, "net.core.netdev_max_backlog").fix.is_none());
        assert!(by_id(&out, "conntrack_max").fix.is_none());
    }

    #[test]
    fn small_host_keeps_conntrack_unless_full() {
        let mut f = facts();
        f.mem_total_kb = Some(512 * 1024);
        assert!(by_id(&findings(&f), "conntrack_max").fix.is_none());
        f.conntrack_count = Some(60_000);
        assert_eq!(
            by_id(&findings(&f), "conntrack_max").fix,
            fix_sysctl("net.netfilter.nf_conntrack_max", 131_072)
        );
    }

    #[test]
    fn forward_drop_chain_is_fail() {
        let mut f = facts();
        f.forward_drop_chains = vec!["ip filter FORWARD".into()];
        f.profile_exits = vec!["yyz-1-wg.example:443".into()];
        let out = findings(&f);
        let x = by_id(&out, "forward_drop");
        assert_eq!(x.severity, Severity::Fail);
        assert!(x.summary.contains("ct status dnat accept"), "{}", x.summary);
    }

    #[test]
    fn a_missing_conntrack_tool_is_a_warning_once_there_are_entries() {
        let mut f = facts();
        assert!(findings(&f).iter().all(|x| x.id != "conntrack_tool"));
        f.profile_exits = vec!["yyz-1-wg.example:443".into()];
        assert_eq!(
            by_id(&findings(&f), "conntrack_tool").severity,
            Severity::Warn
        );
        f.conntrack_tool = true;
        assert!(findings(&f).iter().all(|x| x.id != "conntrack_tool"));
    }

    #[test]
    fn nic_fixes() {
        let mut f = facts();
        let mut features = BTreeMap::new();
        features.insert("generic-receive-offload".into(), "on".into());
        features.insert("rx-udp-gro-forwarding".into(), "off".into());
        f.nic = Some(Nic {
            name: "eth0".into(),
            mtu: Some(1500),
            channels: Some(Pair { current: 1, max: 4 }),
            rx_ring: Some(Pair {
                current: 256,
                max: 4096,
            }),
            tx_ring: Some(Pair {
                current: 256,
                max: 4096,
            }),
            features,
            rx_queues: 1,
            rps_cpus: Some("0".into()),
            ..Default::default()
        });
        let out = findings(&f);
        assert_eq!(
            by_id(&out, "channels").fix.as_ref().unwrap().command(),
            "ethtool -L eth0 combined 4"
        );
        assert!(by_id(&out, "rings").fix.as_ref().unwrap().is_nic());
        assert!(by_id(&out, "udp_gro_forwarding").fix.is_some());
        // Multi-queue hardware: use channels, not RPS.
        assert!(!out.iter().any(|x| x.id == "rps"));
    }

    #[test]
    fn rps_for_single_queue_nic() {
        let mut f = facts();
        f.nic = Some(Nic {
            name: "ens3".into(),
            rx_queues: 1,
            rps_cpus: Some("00000000".into()),
            ..Default::default()
        });
        let out = findings(&f);
        let x = by_id(&out, "rps").fix.clone().unwrap();
        assert_eq!(
            x,
            Fix::Sysfs {
                path: "/sys/class/net/ens3/queues/rx-0/rps_cpus".into(),
                value: "f".into()
            }
        );
    }

    #[test]
    fn masks() {
        assert_eq!(cpu_mask(1), "1");
        assert_eq!(cpu_mask(4), "f");
        assert_eq!(cpu_mask(32), "ffffffff");
        assert_eq!(cpu_mask(36), "f,ffffffff");
        assert!(mask_is_zero("00000000,00000000"));
    }

    #[test]
    fn parses_cpu_list_and_meminfo() {
        assert_eq!(count_cpu_list("0-3"), 4);
        assert_eq!(count_cpu_list("0,2-3,8"), 4);
        assert_eq!(
            parse_meminfo("MemTotal:  2048000 kB\nMemFree: 1 kB"),
            Some(2_048_000)
        );
    }

    #[test]
    fn parses_ethtool() {
        let l = "Channel parameters for eth0:\nPre-set maximums:\nRX:\t\tn/a\nTX:\t\tn/a\nOther:\t\tn/a\nCombined:\t8\nCurrent hardware settings:\nRX:\t\tn/a\nTX:\t\tn/a\nOther:\t\tn/a\nCombined:\t2\n";
        assert_eq!(
            parse_ethtool_pair(l, "Combined"),
            Some(Pair { current: 2, max: 8 })
        );
        assert_eq!(parse_ethtool_pair(l, "RX"), None);
        let k = "Features for eth0:\ngeneric-receive-offload: on\nrx-gro-hw: off [fixed]\nrx-udp-gro-forwarding: off\n";
        let feats = parse_ethtool_features(k);
        assert_eq!(feats["generic-receive-offload"], "on");
        assert_eq!(feats["rx-gro-hw"], "off-fixed");
        assert_eq!(feats["rx-udp-gro-forwarding"], "off");
    }

    #[test]
    fn parses_proc_counters() {
        let ct = "entries clashres found new invalid ignore delete chainlength insert insert_failed drop early_drop\n\
                  00000010 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001 00000002 00000000\n\
                  00000010 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000003 00000001\n";
        assert_eq!(parse_conntrack_stat(ct), Some(7));
        let sn = "0000a000 00000002 00000010 00000000\n0000b000 00000001 00000000 00000000\n";
        assert_eq!(parse_softnet(sn), (3, 16));
    }

    #[test]
    fn parses_ruleset() {
        let json = r#"{"nftables":[{"metainfo":{}},
          {"table":{"family":"ip","name":"filter"}},
          {"chain":{"family":"ip","table":"filter","name":"FORWARD","type":"filter","hook":"forward","prio":0,"policy":"drop"}},
          {"table":{"family":"inet","name":"hydra"}},
          {"flowtable":{"family":"inet","table":"hydra","name":"ft"}},
          {"chain":{"family":"inet","table":"hydra","name":"forward","type":"filter","hook":"forward","prio":0,"policy":"accept"}},
          {"rule":{"family":"inet","table":"hydra","chain":"prerouting","expr":[{"counter":{"packets":42,"bytes":9000}}]}}]}"#;
        let r = parse_ruleset(json);
        assert_eq!(r.forward_drop_chains, vec!["ip filter FORWARD"]);
        assert!(r.hydra_table && r.hydra_flowtable);
        assert_eq!(r.hydra_new_flows, Some(42));
    }

    #[test]
    fn apply_respects_nic_gate_and_persists() {
        let dir = std::env::temp_dir().join(format!("hydra-apply-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("proc/sys/net/core")).unwrap();
        std::fs::write(dir.join("proc/sys/net/core/netdev_budget"), "300\n").unwrap();
        let calls = std::rc::Rc::new(std::cell::RefCell::new(Vec::<String>::new()));
        let c2 = calls.clone();
        let sys = Sys::fixture(
            &dir,
            Box::new(move |cmd, args, _| {
                c2.borrow_mut().push(format!("{cmd} {}", args.join(" ")));
                Ok(String::new())
            }),
        );
        let fs = vec![
            Finding {
                id: "a".into(),
                area: "sysctl",
                severity: Severity::Warn,
                summary: String::new(),
                fix: fix_sysctl("net.core.netdev_budget", 600),
            },
            Finding {
                id: "b".into(),
                area: "nic",
                severity: Severity::Warn,
                summary: String::new(),
                fix: Some(Fix::Ethtool {
                    args: vec!["-G".into(), "eth0".into()],
                }),
            },
        ];
        let rep = apply(
            &sys,
            &fs,
            &ApplyOpts {
                nic: false,
                persist: true,
            },
        );
        assert!(rep.errors.is_empty(), "{:?}", rep.errors);
        assert_eq!(rep.skipped.len(), 1);
        assert!(
            calls.borrow().is_empty(),
            "ethtool must not run without --nic"
        );
        assert_eq!(
            sys.read("/proc/sys/net/core/netdev_budget").as_deref(),
            Some("600")
        );
        let persisted = sys.read(SYSCTL_FILE).unwrap();
        assert!(persisted.contains("net.core.netdev_budget = 600"));

        let rep = apply(
            &sys,
            &fs,
            &ApplyOpts {
                nic: true,
                persist: false,
            },
        );
        assert!(rep.errors.is_empty());
        assert_eq!(calls.borrow().as_slice(), ["ethtool -G eth0"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
