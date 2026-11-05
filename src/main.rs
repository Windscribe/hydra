/// stdout writes that exit quietly when the reader goes away
/// (`hydra lookup | head`), instead of panicking on a broken pipe.
macro_rules! out {
    ($($arg:tt)*) => {
        $crate::emit(&format!("{}\n", format_args!($($arg)*)))
    };
}
macro_rules! outp {
    ($($arg:tt)*) => {
        $crate::emit(&format!($($arg)*))
    };
}

fn emit(s: &str) {
    use std::io::Write as _;
    let mut o = std::io::stdout().lock();
    if let Err(e) = o.write_all(s.as_bytes()).and_then(|_| o.flush()) {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            std::process::exit(0);
        }
        eprintln!("hydra: write stdout: {e}");
        std::process::exit(1);
    }
}

mod audit;
mod datacenters;
mod host;
mod look;
mod nft;
mod probe;
mod profile;
mod setup;
mod state;
mod sys;

use profile::{Front, Profile};
use state::{Entry, State};
use std::net::Ipv4Addr;
use std::process::ExitCode;
use sys::Sys;

const USAGE: &str = "hydra - self-hosted WireGuard entry for Windscribe

Usage:
  hydra setup [--status-url URL] [--wg-zone Z]   guided: add, remove and share
                                                 entries
  hydra lookup <city|country|name> [--limit N] [--status-url URL] [--wg-zone Z]
  hydra check-range <CIDR> [--status-url URL]
  hydra up [options]
  hydra apply [--refresh] [--no-flowtable] [--dry-run] [--skip-sysctl]
  hydra down [--entry IP:PORT | --forget] [--dry-run]
  hydra doctor [--iface IF] [--from FILE] [--json]
  hydra tune [--apply] [--persist] [--nic] [--iface IF] [--from FILE]
  hydra export [--entry IP:PORT] [--from FILE]
  hydra status [--from FILE]
  hydra version

`hydra` on its own in a terminal starts `hydra setup`.
Every command that reads or changes the host's entries takes
--state FILE (default /etc/hydra/entries.json).

up options:
  --location Q        the least-loaded datacenter matching a city, country or
                      name in Windscribe's locations
  --datacenter H      a datacenter by its WireGuard hostname, the one its
                      custom configs use
  --label TEXT        how the profile names the place (default: from the list)
  --exit-port P       the datacenter's UDP port (default 443)
  --listen IP         public IPv4 clients connect to (default: auto)
  --bind IP           local address traffic arrives on, if different from
                      --listen (hosts behind 1:1 NAT; default: auto)
  --add-address       hold --listen on this server (as a /32) while it
                      forwards: for an address of a range the provider
                      doesn't route here (see check-range)
  --port P            UDP port clients connect to (default 443)
  --id NAME           name written into the profile (default: hostname)
  --write FILE        profile path (default hydra.json)
  --from FILE         apply an existing profile instead of building one
  --status-url U      where Windscribe's locations come from, for --location
                      and --datacenter (default: its public WebsiteStatus)
  --wg-zone Z         the DNS zone of the datacenters' WireGuard hostnames
                      (default: the one Windscribe's configs use)
  --no-flowtable      do not use the nftables flowtable fast path
  --dry-run           print the nftables script and profile, change nothing
  --skip-nft          write the profile only
  --skip-sysctl       do not set net.ipv4.ip_forward

apply:  forwards every saved entry again (at boot). --refresh, from the
        timer, follows changes Windscribe makes to the datacenters, and
        leaves stopped forwarding stopped.
down:   stops forwarding and keeps the saved entries. --entry removes one
        entry for good and keeps forwarding the others; --forget deletes
        them all.
check-range: whether the addresses of one of this server's ranges reach it as
        they are (the provider routes the range here), or only once the
        server holds each one it uses (--add-address). It connects to the
        host Windscribe's locations come from, from an address of the range.
export: prints the profile to share: with several entries, one profile for
        all of them (the apps hold one at a time), or one entry's with
        --entry.
doctor: read-only audit of forwarding, conntrack, CPU, NIC and firewall
        settings. Exits 2 if any check fails.
tune:   shows the fixes doctor recommends. --apply changes sysctl/RPS values,
        --persist also writes /etc/sysctl.d/90-hydra.conf, --nic also applies
        ethtool changes (may reset the link briefly).

One entry (listen IP:port) forwards to one Windscribe datacenter, and
follows it as Windscribe changes it. Each `hydra up` adds or replaces one
entry and keeps the others, so one host can forward several IPs and ports to
several datacenters. `hydra export` and `hydra setup` write one profile for
all of them; after importing it, pick one of its locations in the app.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&Sys::real(), &args) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("hydra: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(sys: &Sys, args: &[String]) -> Result<u8, String> {
    let Some((cmd, rest)) = args.split_first() else {
        if setup::interactive() {
            return cmd_setup(sys, &Flags::parse(&[], SETUP_FLAGS)?).map(|_| 0);
        }
        eprint!("{USAGE}");
        return Err("command required".into());
    };
    match cmd.as_str() {
        "setup" => cmd_setup(sys, &Flags::parse(rest, SETUP_FLAGS)?).map(|_| 0),
        "up" => cmd_up(sys, &Flags::parse(rest, UP_FLAGS)?).map(|_| 0),
        "apply" => cmd_apply(
            sys,
            &Flags::parse(
                rest,
                &[
                    ("state", true),
                    ("refresh", false),
                    ("no-flowtable", false),
                    ("dry-run", false),
                    ("skip-sysctl", false),
                ],
            )?,
        )
        .map(|_| 0),
        "down" => cmd_down(
            sys,
            &Flags::parse(
                rest,
                &[
                    ("dry-run", false),
                    ("entry", true),
                    ("forget", false),
                    ("state", true),
                ],
            )?,
        )
        .map(|_| 0),
        "doctor" => cmd_doctor(
            sys,
            &Flags::parse(
                rest,
                &[
                    ("iface", true),
                    ("from", true),
                    ("json", false),
                    ("state", true),
                ],
            )?,
        ),
        "tune" => cmd_tune(
            sys,
            &Flags::parse(
                rest,
                &[
                    ("iface", true),
                    ("from", true),
                    ("apply", false),
                    ("persist", false),
                    ("nic", false),
                    ("state", true),
                ],
            )?,
        ),
        "export" => cmd_export(&Flags::parse(
            rest,
            &[("from", true), ("entry", true), ("state", true)],
        )?)
        .map(|_| 0),
        "status" => cmd_status(&Flags::parse(rest, &[("from", true), ("state", true)])?).map(|_| 0),
        "lookup" => cmd_lookup(
            sys,
            &Flags::parse(
                rest,
                &[("limit", true), ("status-url", true), ("wg-zone", true)],
            )?,
        )
        .map(|_| 0),
        "check-range" => cmd_check_range(
            sys,
            &Flags::parse(rest, &[("status-url", true), ("state", true)])?,
        )
        .map(|_| 0),
        "version" | "--version" | "-V" => {
            out!("{}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        "help" | "--help" | "-h" => {
            outp!("{USAGE}");
            Ok(0)
        }
        other => Err(format!("unknown command {other:?}")),
    }
}

const SETUP_FLAGS: &[(&str, bool)] = &[("state", true), ("status-url", true), ("wg-zone", true)];

const UP_FLAGS: &[(&str, bool)] = &[
    ("location", true),
    ("datacenter", true),
    ("label", true),
    ("exit-port", true),
    ("listen", true),
    ("bind", true),
    ("port", true),
    ("id", true),
    ("write", true),
    ("from", true),
    ("state", true),
    ("status-url", true),
    ("wg-zone", true),
    ("add-address", false),
    ("no-flowtable", false),
    ("dry-run", false),
    ("skip-nft", false),
    ("skip-sysctl", false),
];

/// Minimal `--name value` / `--name=value` / `--flag` parser.
struct Flags {
    values: Vec<(String, String)>,
    switches: Vec<String>,
    positional: Vec<String>,
}

impl Flags {
    fn parse(args: &[String], spec: &[(&str, bool)]) -> Result<Self, String> {
        let mut f = Flags {
            values: vec![],
            switches: vec![],
            positional: vec![],
        };
        let mut it = args.iter();
        while let Some(a) = it.next() {
            let Some(body) = a.strip_prefix("--") else {
                f.positional.push(a.clone());
                continue;
            };
            let (name, inline) = match body.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (body, None),
            };
            let Some(&(_, takes)) = spec.iter().find(|(n, _)| *n == name) else {
                return Err(format!("unknown flag --{name}"));
            };
            if takes {
                let v = match inline {
                    Some(v) => v,
                    None => it
                        .next()
                        .cloned()
                        .ok_or_else(|| format!("--{name} needs a value"))?,
                };
                f.values.push((name.to_string(), v));
            } else if inline.is_some() {
                return Err(format!("--{name} takes no value"));
            } else {
                f.switches.push(name.to_string());
            }
        }
        Ok(f)
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    fn has(&self, name: &str) -> bool {
        self.switches.iter().any(|s| s == name)
    }

    fn port(&self, name: &str, default: u16) -> Result<u16, String> {
        match self.get(name) {
            None => Ok(default),
            Some(v) => match v.parse::<u16>() {
                Ok(p) if p > 0 => Ok(p),
                _ => Err(format!("--{name}: invalid port {v:?}")),
            },
        }
    }

    fn ipv4(&self, name: &str) -> Result<Option<Ipv4Addr>, String> {
        self.get(name)
            .map(|v| {
                v.parse()
                    .map_err(|_| format!("--{name}: invalid IPv4 {v:?}"))
            })
            .transpose()
    }
}

/// Public address for the profile and local address for nftables.
struct Addresses {
    listen: Ipv4Addr,
    bind: Option<Ipv4Addr>,
}

fn resolve_addresses(sys: &Sys, f: &Flags) -> Result<Addresses, String> {
    let listen = f.ipv4("listen")?;
    let bind = f.ipv4("bind")?;
    match (listen, bind) {
        (Some(l), Some(b)) => Ok(Addresses {
            listen: l,
            bind: (l != b).then_some(b),
        }),
        (Some(l), None) => {
            let locals = host::local_ipv4s(sys);
            if locals.is_empty() || locals.contains(&l) {
                return Ok(Addresses {
                    listen: l,
                    bind: None,
                });
            }
            // An address of one of this host's ranges arrives as it is.
            if let Some(r) = host::ranges(sys).into_iter().find(|r| r.contains(l)) {
                eprintln!("{l} is in {}, a range of this server's", r.cidr());
                return Ok(Addresses {
                    listen: l,
                    bind: None,
                });
            }
            // Public IP is not on this host: 1:1 NAT (most clouds).
            let (_, src) = host::default_route(sys).ok_or_else(|| {
                format!("{l} is not a local address and no default route was found; pass --bind")
            })?;
            eprintln!("{l} is not local; forwarding traffic that arrives on {src} (1:1 NAT)");
            Ok(Addresses {
                listen: l,
                bind: Some(src),
            })
        }
        (None, b) => {
            let (_, src) = host::default_route(sys).ok_or("no default route; pass --listen")?;
            if !host::is_public(src) {
                return Err(format!(
                    "default source {src} is not a public address (behind NAT?); pass --listen <public IP>"
                ));
            }
            let public: Vec<String> = host::local_ipv4s(sys)
                .into_iter()
                .filter(|ip| host::is_public(*ip))
                .map(|ip| ip.to_string())
                .collect();
            if public.len() > 1 {
                eprintln!(
                    "this host has {} public IPv4 addresses ({}); using {src}, the default route's; pass --listen to pick another",
                    public.len(),
                    public.join(", ")
                );
            }
            Ok(Addresses {
                listen: src,
                bind: b.filter(|b| *b != src),
            })
        }
    }
}

fn load_datacenters(sys: &Sys, f: &Flags) -> Result<Vec<datacenters::Datacenter>, String> {
    load_datacenters_from(sys, f.get("status-url"), f.get("wg-zone"))
}

fn load_datacenters_from(
    sys: &Sys,
    url: Option<&str>,
    zone: Option<&str>,
) -> Result<Vec<datacenters::Datacenter>, String> {
    let zone = zone
        .unwrap_or(datacenters::DEFAULT_ZONE)
        .trim()
        .to_ascii_lowercase();
    if !profile::is_hostname(&zone) {
        return Err(format!("--wg-zone: {zone:?} is not a DNS zone"));
    }
    let dcs = datacenters::parse(&sys.fetch(url.unwrap_or(datacenters::DEFAULT_URL))?, &zone)?;
    if dcs.is_empty() {
        return Err("Windscribe listed no datacenters hydra can front".into());
    }
    Ok(dcs)
}

/// The profile for one new entry, and its datacenter's country code.
fn build_profile(sys: &Sys, f: &Flags, listen: Ipv4Addr) -> Result<(Profile, String), String> {
    let d = if let Some(h) = f.get("datacenter") {
        let h = h.trim().to_ascii_lowercase();
        if !profile::is_hostname(&h) {
            return Err(format!("--datacenter: {h:?} is not a hostname"));
        }
        // The apps match a front on the datacenter's id, which only the list has.
        load_datacenters(sys, f)?
            .into_iter()
            .find(|d| d.hostname == h)
            .ok_or_else(|| format!("--datacenter: {h} is not one of Windscribe's datacenters"))?
    } else if let Some(q) = f.get("location") {
        let dcs = datacenters::filter(load_datacenters(sys, f)?, q);
        let d = datacenters::pick_least_loaded(&dcs)
            .ok_or_else(|| format!("no datacenter matched {q:?}"))?;
        eprintln!("picked {} ({}): load {}%", d.label(), d.hostname, d.load);
        d.clone()
    } else {
        return Err("need --location or --datacenter".into());
    };
    let label = f.get("label").map_or_else(|| d.label(), str::to_string);

    let p = Profile::new(
        f.get("id")
            .map(str::to_string)
            .unwrap_or_else(|| host::node_name(sys)),
        vec![Front {
            location: label,
            datacenter: d.hostname,
            datacenter_id: d.id,
            exit_port: f.port("exit-port", 443)?,
            entry_ip: listen,
            entry_port: f.port("port", 443)?,
            protocol: "wireguard".into(),
        }],
    );
    Ok((p, d.country))
}

/// The entry's datacenter's servers: what its hostname resolves to.
fn servers_of(sys: &Sys, e: &Entry) -> Result<Vec<Ipv4Addr>, String> {
    let dc = &e.front().datacenter;
    let ips = sys.resolve(dc)?;
    if ips.is_empty() {
        return Err(format!("{dc} resolved to no IPv4 address"));
    }
    Ok(ips)
}

fn table_loaded(sys: &Sys) -> bool {
    sys.run("nft", &["list", "table", "inet", nft::TABLE], None)
        .is_ok()
}

/// Ends the connections hydra forwards for `e`, to `server` or to any of its
/// servers, so the client's next packet is forwarded afresh: to a server still
/// in its datacenter, or nowhere once the entry is gone. False when the
/// `conntrack` tool is missing.
fn clear_flows(sys: &Sys, e: &Entry, server: Option<Ipv4Addr>) -> bool {
    let (local, port) = (e.local().to_string(), e.front().entry_port.to_string());
    let server = server.map(|s| s.to_string());
    let mut args = vec![
        "-D",
        "-p",
        "udp",
        "--orig-dst",
        &local,
        "--orig-port-dst",
        &port,
    ];
    if let Some(s) = &server {
        args.extend(["--reply-src", s.as_str()]);
    }
    match sys.run("conntrack", &args, None) {
        Ok(_) => true,
        // It exits 1 when nothing matched.
        Err(e) => e.contains("flow entries"),
    }
}

const NO_CONNTRACK: &str = "warning: install the conntrack tool (apt install conntrack) so \
     connected clients follow a datacenter's changes at once; until then they follow when they \
     reconnect";

fn state_path(f: &Flags) -> &str {
    f.get("state").unwrap_or(state::DEFAULT_PATH)
}

/// Interfaces the entries' traffic arrives on, for the flowtable fast path.
fn flowtable_devices(sys: &Sys, enabled: bool, entries: &[Entry]) -> Vec<String> {
    if !enabled {
        return vec![];
    }
    let mut devices: Vec<String> = vec![];
    for e in entries {
        let dev =
            host::iface_for(sys, e.local()).or_else(|| host::default_route(sys).map(|(d, _)| d));
        if let Some(d) = dev.filter(|d| !devices.contains(d)) {
            devices.push(d);
        }
    }
    devices
}

fn forwarding_line(e: &Entry) -> String {
    let fr = e.front();
    if fr.location.is_empty() {
        format!("{} -> {}", fr.endpoint(), fr.datacenter)
    } else {
        format!("{} -> {} ({})", fr.endpoint(), fr.location, fr.datacenter)
    }
}

/// Turns on IPv4 forwarding, loads the table for every entry in `st`, and
/// saves `st`.
fn forward(sys: &Sys, path: &str, st: &State, flowtable: bool, sysctl: bool) -> Result<(), String> {
    if sysctl {
        sys.set_sysctl("net.ipv4.ip_forward", "1")?;
    }
    hold_addresses(sys, &st.entries)?;
    let opts = nft::RenderOpts {
        flowtable_devices: flowtable_devices(sys, flowtable, &st.entries),
    };
    if let Some(w) = nft::apply(sys, &st.entries, &opts)? {
        eprintln!("warning: {w}");
    }
    st.save(path)
}

/// Forgets one entry and keeps forwarding the others. Removing an entry while
/// forwarding is stopped leaves it stopped. Returns the entry and whether
/// forwarding was running.
fn remove_entry(
    sys: &Sys,
    path: &str,
    endpoint: &str,
    flowtable: bool,
) -> Result<(Entry, bool), String> {
    let mut st = State::load(path)?;
    let gone = st.remove(endpoint).ok_or_else(|| no_entry(endpoint, &st))?;
    let running = table_loaded(sys);
    if running && st.entries.is_empty() {
        sys.run("nft", &["-f", "-"], Some(&nft::delete_script()))?;
    } else if running {
        let opts = nft::RenderOpts {
            flowtable_devices: flowtable_devices(sys, flowtable, &st.entries),
        };
        if let Some(w) = nft::apply(sys, &st.entries, &opts)? {
            eprintln!("warning: {w}");
        }
    }
    st.save(path)?;
    release_address(sys, &gone, &st.entries);
    if !clear_flows(sys, &gone, None) {
        eprintln!("{NO_CONNTRACK}");
    }
    Ok((gone, running))
}

/// The interface to hold `ip` on: its range's, or the default route's.
fn claim_iface(sys: &Sys, ip: Ipv4Addr) -> Result<String, String> {
    host::ranges(sys)
        .into_iter()
        .find(|r| r.contains(ip))
        .map(|r| r.iface)
        .or_else(|| host::default_route(sys).map(|(d, _)| d))
        .ok_or_else(|| format!("no interface to add {ip} to; this host has no default route"))
}

/// Adds each entry's held address that the host doesn't hold yet: after a
/// reboot, or a new entry.
fn hold_addresses(sys: &Sys, entries: &[Entry]) -> Result<(), String> {
    let held = host::local_ipv4s(sys);
    let mut done: Vec<Ipv4Addr> = vec![];
    for e in entries {
        let Some(iface) = &e.claim else { continue };
        let ip = e.local();
        if held.contains(&ip) || done.contains(&ip) {
            continue;
        }
        sys.run(
            "ip",
            &["-4", "addr", "add", &format!("{ip}/32"), "dev", iface],
            None,
        )
        .map_err(|err| format!("adding {ip} to {iface}: {err}"))?;
        done.push(ip);
    }
    Ok(())
}

/// Removes the address `gone` held, unless another entry still uses it.
fn release_address(sys: &Sys, gone: &Entry, rest: &[Entry]) {
    let Some(iface) = &gone.claim else { return };
    let ip = gone.local();
    if rest.iter().any(|e| e.claim.is_some() && e.local() == ip) {
        return;
    }
    if let Err(err) = sys.run(
        "ip",
        &["-4", "addr", "del", &format!("{ip}/32"), "dev", iface],
        None,
    ) {
        eprintln!("warning: removing {ip} from {iface}: {err}");
    }
}

/// Where to check a range against: the host Windscribe's locations come from.
fn probe_target(sys: &Sys, url: &str) -> Result<std::net::SocketAddrV4, String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("{url} is not a URL"))?;
    let authority = rest.split('/').next().unwrap_or_default();
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().map_err(|_| format!("{url}: bad port"))?),
        None => (authority, if scheme == "http" { 80 } else { 443 }),
    };
    let ip = match host.parse::<Ipv4Addr>() {
        Ok(ip) => ip,
        Err(_) => *sys
            .resolve(host)?
            .first()
            .ok_or_else(|| format!("{host} has no IPv4 address"))?,
    };
    Ok(std::net::SocketAddrV4::new(ip, port))
}

fn cmd_check_range(sys: &Sys, f: &Flags) -> Result<(), String> {
    let [cidr] = f.positional.as_slice() else {
        return Err("usage: hydra check-range <CIDR>".into());
    };
    let r = host::ranges(sys)
        .into_iter()
        .find(|r| &r.cidr() == cidr)
        .ok_or_else(|| {
            let have: Vec<String> = host::ranges(sys).iter().map(host::Range::cidr).collect();
            format!(
                "{cidr} isn't a range of this server's (it has: {})",
                if have.is_empty() {
                    "none".to_string()
                } else {
                    have.join(", ")
                }
            )
        })?;
    let st = State::load(state_path(f)).unwrap_or_default();
    let ip = r
        .addresses
        .iter()
        .copied()
        .find(|a| !st.entries.iter().any(|e| e.local() == *a))
        .ok_or_else(|| format!("{cidr} has no free address to check with"))?;
    let target = probe_target(sys, f.get("status-url").unwrap_or(datacenters::DEFAULT_URL))?;
    match probe::check(sys, ip, target)? {
        probe::Delivery::Routed => out!("{cidr}: routed to this server; its addresses work as they are"),
        probe::Delivery::NotDelivered => out!(
            "{cidr}: not routed to this server; each address hydra uses has to be held here (hydra up --add-address, or hydra setup)"
        ),
    }
    Ok(())
}

fn no_entry(endpoint: &str, st: &State) -> String {
    if st.entries.is_empty() {
        format!("no entry {endpoint}: this host has no saved entries")
    } else {
        format!("no entry {endpoint}; entries: {}", st.endpoints())
    }
}

fn cmd_up(sys: &Sys, f: &Flags) -> Result<(), String> {
    // The profile to write, and the entries it adds to this host: one per front.
    let (p, added) = if let Some(path) = f.get("from") {
        let p = Profile::load(path)?;
        if p.fronts.len() > 1 && f.get("bind").is_some() {
            return Err(format!(
                "{path} has {} fronts and --bind sets one local address; run `hydra up` once per entry",
                p.fronts.len()
            ));
        }
        let mut added = vec![];
        for front in &p.fronts {
            let lf = Flags {
                values: vec![("listen".into(), front.entry_ip.to_string())]
                    .into_iter()
                    .chain(f.get("bind").map(|b| ("bind".to_string(), b.to_string())))
                    .collect(),
                switches: vec![],
                positional: vec![],
            };
            let a = resolve_addresses(sys, &lf)?;
            let one = Profile {
                fronts: vec![front.clone()],
                ..p.clone()
            };
            added.push(Entry::new(one, a.bind));
        }
        (p, added)
    } else {
        let a = resolve_addresses(sys, f)?;
        let (p, country) = build_profile(sys, f, a.listen)?;
        let claim = match (f.has("add-address"), a.bind) {
            (false, _) => None,
            (true, Some(b)) => {
                return Err(format!(
                    "--add-address holds the address clients dial on this server, but traffic for {} arrives on {b}",
                    a.listen
                ))
            }
            // Not hydra's to remove later.
            (true, None) if host::local_ipv4s(sys).contains(&a.listen) => {
                eprintln!(
                    "{} is already on this server; --add-address leaves it as it is",
                    a.listen
                );
                None
            }
            (true, None) => Some(claim_iface(sys, a.listen)?),
        };
        let e = Entry::new(p.clone(), a.bind)
            .with_country(&country)
            .with_claim(claim);
        (p, vec![e])
    };
    let mut added = added;
    State {
        entries: added.clone(),
        ..State::default()
    }
    .validate()
    .map_err(|e| {
        format!("{e}; behind 1:1 NAT, run `hydra up` once per entry with its own --bind")
    })?;
    let json = p.to_json()?;
    let write = f.get("write").unwrap_or("hydra.json");

    // --skip-nft writes the profile only and leaves the host's entries alone.
    if !f.has("skip-nft") || f.has("dry-run") {
        for e in &mut added {
            e.servers = servers_of(sys, e)?;
        }
    }
    let path = state_path(f);
    let mut st = if f.has("skip-nft") {
        State::default()
    } else {
        State::load(path)?
    };
    let mut replaced = vec![];
    for e in &added {
        replaced.extend(st.upsert(e.clone()));
    }
    replaced.retain(|r| !added.iter().any(|e| &e.endpoint() == r));
    let opts = nft::RenderOpts {
        flowtable_devices: flowtable_devices(sys, !f.has("no-flowtable"), &st.entries),
    };

    if f.has("dry-run") {
        outp!("{}", nft::apply_script(&st.entries, &opts)?);
        out!("{json}");
        return Ok(());
    }
    if f.has("skip-nft") {
        if !f.has("skip-sysctl") {
            sys.set_sysctl("net.ipv4.ip_forward", "1")?;
        }
    } else {
        forward(
            sys,
            path,
            &st,
            !f.has("no-flowtable"),
            !f.has("skip-sysctl"),
        )?;
    }
    std::fs::write(write, format!("{json}\n")).map_err(|e| format!("{write}: {e}"))?;
    for r in &replaced {
        eprintln!("replaced entry {r}");
    }
    for e in &added {
        eprintln!("forwarding {}", forwarding_line(e));
    }
    if !f.has("skip-nft") && st.entries.len() > added.len() {
        eprintln!(
            "this host forwards {} entries; `hydra status` lists them",
            st.entries.len()
        );
    }
    if p.fronts.len() > 1 {
        eprintln!(
            "{write} names {} datacenters; to share one, `hydra export --entry IP:PORT`",
            p.fronts.len()
        );
    } else if st.entries.len() > 1 {
        eprintln!(
            "the app takes one profile: `hydra export` prints one for all {} entries",
            st.entries.len()
        );
    }
    eprintln!("wrote {write} (no keys; share privately)");
    eprintln!(
        "in the app, import it, then connect to {}: only the locations it maps go through hydra",
        p.fronts
            .iter()
            .map(|f| if f.location.is_empty() {
                f.datacenter.as_str()
            } else {
                f.location.as_str()
            })
            .collect::<Vec<_>>()
            .join(" or ")
    );
    eprintln!("run `hydra doctor` to check the host");
    Ok(())
}

fn cmd_setup(sys: &Sys, f: &Flags) -> Result<(), String> {
    if !setup::interactive() {
        return Err(
            "hydra setup asks questions, so it needs a terminal; in scripts use `hydra up`".into(),
        );
    }
    if !host::is_root(sys) {
        return Err(
            "hydra setup changes nftables and IPv4 forwarding: run it as root (sudo hydra setup)"
                .into(),
        );
    }
    let url = f.get("status-url").map(str::to_string);
    let zone = f.get("wg-zone").map(str::to_string);
    let probe_url = url
        .clone()
        .unwrap_or_else(|| datacenters::DEFAULT_URL.to_string());
    setup::catch_ctrl_c();
    let mut ui = setup::Terminal::default();
    let mut s = setup::Setup {
        sys,
        state: state_path(f),
        ui: &mut ui,
        load_datacenters: Box::new(move || {
            load_datacenters_from(sys, url.as_deref(), zone.as_deref())
        }),
        datacenters: None,
        dir: std::env::current_dir().map_err(|e| format!("working directory: {e}"))?,
        emoji: look::wants_emoji(),
        check_range: Box::new(move |ip| probe::check(sys, ip, probe_target(sys, &probe_url)?)),
    };
    setup::run(&mut s)
}

fn cmd_apply(sys: &Sys, f: &Flags) -> Result<(), String> {
    let path = state_path(f);
    let refresh = f.has("refresh");
    let mut st = State::load(path)?;
    if st.entries.is_empty() {
        if refresh {
            return Ok(());
        }
        return Err(format!(
            "no saved entries in {path}; add one with `hydra up`"
        ));
    }
    // Each datacenter's servers now. DNS that fails keeps the last ones known.
    let mut changes: Vec<String> = vec![];
    let mut left: Vec<(usize, Ipv4Addr)> = vec![];
    for (i, e) in st.entries.iter_mut().enumerate() {
        match servers_of(sys, e) {
            Ok(now) if now != e.servers => {
                left.extend(
                    e.servers
                        .iter()
                        .filter(|s| !now.contains(s))
                        .map(|s| (i, *s)),
                );
                changes.push(format!(
                    "{}: {} changed; following it",
                    e.endpoint(),
                    e.front().datacenter
                ));
                e.servers = now;
            }
            Ok(_) => {}
            Err(err) if !e.servers.is_empty() => {
                eprintln!("warning: {err}; keeping the addresses it had");
            }
            Err(err) => return Err(err),
        }
    }
    let opts = nft::RenderOpts {
        flowtable_devices: flowtable_devices(sys, !f.has("no-flowtable"), &st.entries),
    };
    if f.has("dry-run") {
        outp!("{}", nft::apply_script(&st.entries, &opts)?);
        return Ok(());
    }
    if refresh {
        if changes.is_empty() {
            return Ok(());
        }
        if !table_loaded(sys) {
            st.save(path)?;
            for c in &changes {
                eprintln!("{c}");
            }
            eprintln!("forwarding is stopped; `hydra apply` picks up the change");
            return Ok(());
        }
    }
    forward(
        sys,
        path,
        &st,
        !f.has("no-flowtable"),
        !f.has("skip-sysctl"),
    )?;
    // The new table sends new connections to the servers left; these were
    // still pinned to servers that have gone.
    let mut tool = true;
    for (i, server) in &left {
        tool &= clear_flows(sys, &st.entries[*i], Some(*server));
    }
    for c in &changes {
        eprintln!("{c}");
    }
    if !tool {
        eprintln!("{NO_CONNTRACK}");
    }
    if !refresh {
        for e in &st.entries {
            eprintln!("forwarding {}", forwarding_line(e));
        }
    }
    Ok(())
}

fn cmd_down(sys: &Sys, f: &Flags) -> Result<(), String> {
    let path = state_path(f);
    if let Some(endpoint) = f.get("entry") {
        let mut st = State::load(path)?;
        st.remove(endpoint).ok_or_else(|| no_entry(endpoint, &st))?;
        let opts = nft::RenderOpts {
            flowtable_devices: flowtable_devices(sys, !f.has("no-flowtable"), &st.entries),
        };
        if f.has("dry-run") {
            if st.entries.is_empty() {
                outp!("{}", nft::delete_script());
            } else {
                outp!("{}", nft::apply_script(&st.entries, &opts)?);
            }
            return Ok(());
        }
        let (gone, running) = remove_entry(sys, path, endpoint, !f.has("no-flowtable"))?;
        eprintln!("removed {}", forwarding_line(&gone));
        if !running {
            eprintln!("forwarding is stopped; `hydra apply` starts the other entries");
        }
        return Ok(());
    }
    let script = nft::delete_script();
    if f.has("dry-run") {
        outp!("{script}");
        return Ok(());
    }
    sys.run("nft", &["-f", "-"], Some(&script))?;
    // Connections already forwarded would carry on without the table.
    let st = State::load(path).unwrap_or_default();
    // `hydra apply` holds them again.
    for (i, e) in st.entries.iter().enumerate() {
        release_address(sys, e, &st.entries[..i]);
    }
    if !st.entries.iter().all(|e| clear_flows(sys, e, None)) {
        eprintln!("{NO_CONNTRACK}");
    }
    if f.has("forget") {
        State::remove_file(path)?;
    } else if let Some(n) = State::load(path)
        .ok()
        .map(|st| st.entries.len())
        .filter(|n| *n > 0)
    {
        eprintln!(
            "kept {n} saved entr{}; `hydra apply` forwards them again, `hydra down --forget` deletes them",
            if n == 1 { "y" } else { "ies" }
        );
    }
    Ok(())
}

fn audit_facts(sys: &Sys, f: &Flags) -> Result<audit::Facts, String> {
    let names = |p: Profile| -> Vec<String> {
        p.fronts
            .iter()
            .map(|fr| format!("{}:{}", fr.datacenter, fr.exit_port))
            .collect()
    };
    let mut exits = match f.get("from") {
        Some(p) => names(Profile::load(p)?),
        None => {
            // doctor stays read-only and works without the saved entries.
            let st = State::load(state_path(f)).unwrap_or_default();
            if st.entries.is_empty() {
                Profile::load("hydra.json").map(names).unwrap_or_default()
            } else {
                st.entries
                    .iter()
                    .map(|e| format!("{}:{}", e.front().datacenter, e.front().exit_port))
                    .collect()
            }
        }
    };
    exits.sort();
    exits.dedup();
    Ok(audit::gather(sys, f.get("iface"), &exits))
}

fn cmd_doctor(sys: &Sys, f: &Flags) -> Result<u8, String> {
    let facts = audit_facts(sys, f)?;
    let found = audit::findings(&facts);
    if f.has("json") {
        let doc = serde_json::json!({ "facts": facts, "findings": found });
        out!(
            "{}",
            serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?
        );
    } else {
        outp!("{}", audit::render_text(&facts, &found));
        let fixes = found.iter().filter(|x| x.fix.is_some()).count();
        if fixes > 0 {
            out!("\n{fixes} fix(es) available: `hydra tune` to review, `hydra tune --apply` to apply");
        }
    }
    let failed = found.iter().any(|x| x.severity == audit::Severity::Fail);
    Ok(if failed { 2 } else { 0 })
}

fn cmd_tune(sys: &Sys, f: &Flags) -> Result<u8, String> {
    let facts = audit_facts(sys, f)?;
    let found = audit::findings(&facts);
    let fixes: Vec<&audit::Finding> = found.iter().filter(|x| x.fix.is_some()).collect();
    if fixes.is_empty() {
        out!("nothing to tune");
        return Ok(0);
    }
    if !f.has("apply") {
        out!("planned changes (run with --apply):");
        for x in &fixes {
            let fx = x.fix.as_ref().expect("filtered");
            let gate = if fx.is_nic() { "  [--nic]" } else { "" };
            out!("  {}{gate}\n      {}", fx.command(), x.summary);
        }
        return Ok(0);
    }
    let rep = audit::apply(
        sys,
        &found,
        &audit::ApplyOpts {
            nic: f.has("nic"),
            persist: f.has("persist"),
        },
    );
    for a in &rep.applied {
        out!("applied  {a}");
    }
    for s in &rep.skipped {
        out!("skipped  {s}");
    }
    for e in &rep.errors {
        out!("error    {e}");
    }
    if !f.has("persist") && rep.applied.iter().any(|a| a.starts_with("sysctl")) {
        out!("\nsysctl changes last until reboot; add --persist to keep them");
    }
    Ok(if rep.errors.is_empty() { 0 } else { 1 })
}

/// The profile `export` prints: one entry's, so it names one datacenter.
fn export_profile(f: &Flags) -> Result<Profile, String> {
    if let Some(path) = f.get("from") {
        let p = Profile::load(path)?;
        let Some(endpoint) = f.get("entry") else {
            return Ok(p);
        };
        let front = p
            .fronts
            .iter()
            .find(|fr| fr.endpoint() == endpoint)
            .ok_or_else(|| format!("{path} has no entry {endpoint}"))?;
        return Ok(Profile {
            fronts: vec![front.clone()],
            ..p.clone()
        });
    }
    let st = State::load(state_path(f))?;
    if let Some(endpoint) = f.get("entry") {
        return st
            .find(endpoint)
            .map(|e| e.profile.clone())
            .ok_or_else(|| no_entry(endpoint, &st));
    }
    match st.entries.as_slice() {
        [] => Profile::load("hydra.json"),
        [one] => Ok(one.profile.clone()),
        // The apps hold one profile at a time, so it carries every entry.
        all => Ok(Profile::combined(
            all[0].profile.hydra_id.clone(),
            all.iter().map(|e| e.front().clone()).collect(),
            false,
        )),
    }
}

fn cmd_export(f: &Flags) -> Result<(), String> {
    out!("{}", export_profile(f)?.to_json()?);
    Ok(())
}

fn print_fronts<'a>(fronts: impl Iterator<Item = (&'a Front, Option<Ipv4Addr>)>) {
    for (fr, bind) in fronts {
        let arrives = bind
            .map(|b| format!("  (arrives on {b})"))
            .unwrap_or_default();
        let line = format!(
            "  {} -> {}  {}{arrives}",
            fr.endpoint(),
            fr.datacenter,
            fr.location
        );
        out!("{}", line.trim_end());
    }
}

fn cmd_status(f: &Flags) -> Result<(), String> {
    let from = match f.get("from") {
        Some(path) => Some(path),
        None => {
            let path = state_path(f);
            let st = State::load(path)?;
            if !st.entries.is_empty() {
                out!("entries {}  file {path}", st.entries.len());
                print_fronts(st.entries.iter().map(|e| (e.front(), e.bind)));
                return Ok(());
            }
            None
        }
    };
    let path = from.unwrap_or("hydra.json");
    let p = Profile::load(path)?;
    out!("id {}  fronts {}  file {path}", p.hydra_id, p.fronts.len());
    print_fronts(p.fronts.iter().map(|fr| (fr, None)));
    Ok(())
}

fn cmd_lookup(sys: &Sys, f: &Flags) -> Result<(), String> {
    if f.positional.is_empty() {
        return Err("usage: hydra lookup <city|country|name>".into());
    }
    let q = f.positional.join(" ");
    let limit: usize = match f.get("limit") {
        None => 8,
        Some(v) => v.parse().map_err(|_| format!("--limit: invalid {v:?}"))?,
    };
    let dcs = datacenters::filter(load_datacenters(sys, f)?, &q);
    if dcs.is_empty() {
        return Err(format!("no datacenters matched {q:?}"));
    }
    out!(
        "{:<30} {:<3} {:<34} LOAD",
        "DATACENTER",
        "CC",
        "WIREGUARD HOSTNAME"
    );
    for d in dcs.iter().take(limit) {
        let drained = if d.usable { "" } else { "  drained" };
        out!(
            "{:<30} {:<3} {:<34} {}%{drained}",
            d.label(),
            d.country,
            d.hostname,
            d.load
        );
    }
    if dcs.len() > limit {
        out!("... {} more", dcs.len() - limit);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    /// `ip` answers for a cloud host: private 10.0.0.5 on ens5, public IP via
    /// 1:1 NAT. Its server list has Toronto, datacenter 1.
    fn cloud_sys() -> Sys {
        let toronto = dns(&[("yyz-1-wg.whiskergalaxy.com", &["198.51.100.10"])]);
        Sys::fixture(
            "/nonexistent",
            Box::new(|cmd, args, _| match cmd {
                "ip" if args.iter().any(|a| a == "route") => {
                    Ok(r#"[{"dev":"ens5","prefsrc":"10.0.0.5"}]"#.into())
                }
                "ip" => Ok(r#"[{"ifname":"ens5","addr_info":[{"local":"10.0.0.5"}]}]"#.into()),
                _ => Err(format!("{cmd} not available in test")),
            }),
        )
        .with_fetcher(list_of(toronto))
    }

    #[test]
    fn flag_parsing() {
        let f = Flags::parse(
            &s(&["--listen=203.0.113.5", "--port", "80", "--dry-run", "x"]),
            UP_FLAGS,
        )
        .unwrap();
        assert_eq!(f.get("listen"), Some("203.0.113.5"));
        assert_eq!(f.port("port", 443).unwrap(), 80);
        assert!(f.has("dry-run"));
        assert_eq!(f.positional, vec!["x"]);
        assert!(Flags::parse(&s(&["--bogus"]), UP_FLAGS).is_err());
        assert!(Flags::parse(&s(&["--port"]), UP_FLAGS).is_err());
    }

    #[test]
    fn nat_host_binds_private_address() {
        let f = Flags::parse(&s(&["--listen", "198.51.100.77"]), UP_FLAGS).unwrap();
        let a = resolve_addresses(&cloud_sys(), &f).unwrap();
        assert_eq!(a.listen, "198.51.100.77".parse::<Ipv4Addr>().unwrap());
        assert_eq!(a.bind, Some("10.0.0.5".parse().unwrap()));
    }

    #[test]
    fn nat_host_without_listen_errors() {
        let f = Flags::parse(&s(&[]), UP_FLAGS).unwrap();
        let e = resolve_addresses(&cloud_sys(), &f).err().unwrap();
        assert!(e.contains("--listen"), "{e}");
    }

    #[test]
    fn up_builds_profile_from_pins() {
        let f = Flags::parse(
            &s(&[
                "--datacenter",
                "YYZ-1-wg.WhiskerGalaxy.com",
                "--label",
                "Toronto",
                "--id",
                "t",
            ]),
            UP_FLAGS,
        )
        .unwrap();
        let (p, _) = build_profile(&cloud_sys(), &f, "203.0.113.5".parse().unwrap()).unwrap();
        assert_eq!(p.fronts[0].endpoint(), "203.0.113.5:443");
        assert_eq!(p.fronts[0].datacenter, "yyz-1-wg.whiskergalaxy.com");
        assert_eq!(p.fronts[0].datacenter_id, 1, "from Windscribe's locations");
        assert_eq!(p.fronts[0].location, "Toronto");
        let json = p.to_json().unwrap();
        assert!(
            !json.contains("PrivateKey") && !json.contains("exit_ip"),
            "{json}"
        );
    }

    #[test]
    fn up_writes_profile_with_skip_flags() {
        let dir = std::env::temp_dir().join(format!("hydra-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hydra.json");
        let path_s = path.to_str().unwrap();
        let sys = cloud_sys();
        run(
            &sys,
            &s(&[
                "up",
                "--listen",
                "198.51.100.77",
                "--datacenter",
                "yyz-1-wg.whiskergalaxy.com",
                "--label",
                "Toronto",
                "--write",
                path_s,
                "--skip-nft",
                "--skip-sysctl",
            ]),
        )
        .unwrap();
        run(&sys, &s(&["export", "--from", path_s])).unwrap();
        run(&sys, &s(&["status", "--from", path_s])).unwrap();
        let p = Profile::load(path_s).unwrap();
        assert_eq!(p.fronts[0].entry_ip.to_string(), "198.51.100.77");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_datacenter_must_be_one_of_windscribes() {
        let f = Flags::parse(
            &s(&["--datacenter", "yyz-9-wg.whiskergalaxy.com"]),
            UP_FLAGS,
        )
        .unwrap();
        let e = build_profile(&cloud_sys(), &f, "203.0.113.5".parse().unwrap()).unwrap_err();
        assert!(e.contains("not one of Windscribe's datacenters"), "{e}");
    }

    #[test]
    fn needs_exit() {
        let f = Flags::parse(&s(&[]), UP_FLAGS).unwrap();
        assert!(build_profile(&cloud_sys(), &f, "203.0.113.5".parse().unwrap()).is_err());
    }

    type Scripts = std::rc::Rc<std::cell::RefCell<Vec<String>>>;
    type Dns = std::rc::Rc<std::cell::RefCell<Vec<(String, Vec<Ipv4Addr>)>>>;

    /// The datacenter `up_entry` names for a one-server datacenter.
    fn dc(server: &str) -> String {
        // <iata>-<id>-wg.<zone>, as hydra names a datacenter; the id is the
        // server's last octet.
        format!(
            "lab-{}-wg.{}",
            server.rsplit('.').next().unwrap(),
            datacenters::DEFAULT_ZONE
        )
    }

    fn dns(names: &[(&str, &[&str])]) -> Dns {
        Dns::new(std::cell::RefCell::new(
            names
                .iter()
                .map(|(n, ips)| {
                    (
                        n.to_string(),
                        ips.iter().map(|i| i.parse().unwrap()).collect(),
                    )
                })
                .collect(),
        ))
    }

    /// Windscribe's locations (WebsiteStatus) with one datacenter per name in
    /// `dns`, each named `<iata>-<id>-wg.<default zone>`.
    fn list_of(dns: Dns) -> impl Fn(&str) -> Result<String, String> {
        move |_| {
            let pops: Vec<serde_json::Value> = dns
                .borrow()
                .iter()
                .map(|(name, _)| {
                    let stub = name
                        .to_ascii_lowercase()
                        .strip_suffix(&format!("-wg.{}", datacenters::DEFAULT_ZONE))
                        .unwrap_or_else(|| panic!("{name} is not <iata>-<id>-wg.<zone>"))
                        .to_string();
                    let (iata, id) = stub.rsplit_once('-').unwrap();
                    serde_json::json!({"status": 1, "datacenter_id": id.parse::<u32>().unwrap(),
                                       "iata_code": iata, "name": "Lab", "usage": 0})
                })
                .collect();
            Ok(serde_json::json!({"data": {"locations": {"1": {"name": "Lab", "country_code": "XX", "pops": pops}}}})
                .to_string())
        }
    }

    fn resolver(dns: Dns) -> impl Fn(&str) -> Result<Vec<Ipv4Addr>, String> {
        move |host| {
            dns.borrow()
                .iter()
                .find(|(n, _)| n == host)
                .map(|(_, ips)| ips.clone())
                .ok_or_else(|| format!("{host}: not found"))
        }
    }

    /// A host with two addresses on eth0 that records the nftables scripts it
    /// is sent, with two one-server datacenters in DNS.
    fn lab_sys(scripts: Scripts) -> Sys {
        let names = dns(&[
            (&dc("198.51.100.10"), &["198.51.100.10"]),
            (&dc("198.51.100.20"), &["198.51.100.20"]),
        ]);
        lab_with(scripts, names, Scripts::default())
    }

    /// The lab host with `dns`, recording `conntrack` calls in `ct`.
    fn lab_with(scripts: Scripts, dns: Dns, ct: Scripts) -> Sys {
        const ADDRS: &str = r#"[{"ifname":"eth0","addr_info":[
            {"local":"203.0.113.5"},{"local":"203.0.113.6"}]}]"#;
        Sys::fixture(
            "/nonexistent",
            Box::new(move |cmd, args, stdin| match cmd {
                "ip" if args.iter().any(|a| a == "route") => {
                    Ok(r#"[{"dev":"eth0","prefsrc":"203.0.113.5"}]"#.into())
                }
                "ip" => Ok(ADDRS.into()),
                "nft" => {
                    if let Some(script) = stdin {
                        scripts.borrow_mut().push(script.to_string());
                    }
                    Ok(String::new())
                }
                "conntrack" => {
                    ct.borrow_mut()
                        .push(format!("conntrack {}", args.join(" ")));
                    Ok(String::new())
                }
                _ => Err(format!("{cmd} not available in test")),
            }),
        )
        .with_resolver(resolver(dns.clone()))
        .with_fetcher(list_of(dns))
    }

    /// The same host with forwarding stopped: no hydra table is loaded.
    fn stopped_sys(scripts: Scripts) -> Sys {
        stopped_with(scripts, dns(&[]))
    }

    fn stopped_with(scripts: Scripts, names: Dns) -> Sys {
        let lab = lab_with(scripts, names.clone(), Scripts::default());
        Sys::fixture(
            "/nonexistent",
            Box::new(move |cmd, args, stdin| {
                if cmd == "nft" && args.iter().any(|a| a == "list") {
                    return Err("Error: No such file or directory".into());
                }
                let args: Vec<&str> = args.iter().map(String::as_str).collect();
                lab.run(cmd, &args, stdin)
            }),
        )
        .with_resolver(resolver(names.clone()))
        .with_fetcher(list_of(names))
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("hydra-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Adds an entry from `listen` to the one-server datacenter of `server`.
    fn up_entry(sys: &Sys, state: &str, listen: &str, server: &str, write: &str) {
        up_dc(sys, state, listen, &dc(server), write);
    }

    fn up_dc(sys: &Sys, state: &str, listen: &str, datacenter: &str, write: &str) {
        run(
            sys,
            &s(&[
                "up",
                "--listen",
                listen,
                "--datacenter",
                datacenter,
                "--label",
                "Lab",
                "--write",
                write,
                "--state",
                state,
                "--skip-sysctl",
                "--no-flowtable",
            ]),
        )
        .unwrap();
    }

    const EXPORT_FLAGS: &[(&str, bool)] = &[("from", true), ("entry", true), ("state", true)];

    const REFRESH: &[&str] = &["apply", "--refresh", "--no-flowtable", "--skip-sysctl"];

    fn refresh(sys: &Sys, state: &str) {
        let mut args = s(REFRESH);
        args.extend(s(&["--state", state]));
        run(sys, &args).unwrap();
    }

    #[test]
    fn an_entry_spreads_over_its_datacenters_servers() {
        let dir = scratch("spread");
        let (state, w) = (dir.join("entries.json"), dir.join("p.json"));
        let (state, w) = (state.to_str().unwrap(), w.to_str().unwrap());
        let scripts = Scripts::default();
        let names = dns(&[(
            "ha-7-wg.whiskergalaxy.com",
            &["198.51.100.11", "198.51.100.10"],
        )]);
        let sys = lab_with(scripts.clone(), names, Scripts::default());
        up_dc(&sys, state, "203.0.113.5", "ha-7-wg.whiskergalaxy.com", w);

        let last = scripts.borrow().last().unwrap().clone();
        assert!(last.contains(
            "dnat ip to jhash ip saddr . udp sport mod 2 map { 0 : 198.51.100.10 . 443, 1 : 198.51.100.11 . 443 }"
        ), "{last}");
        let st = State::load(state).unwrap();
        assert_eq!(st.entries[0].servers.len(), 2);
        let p = Profile::load(w).unwrap();
        assert_eq!(p.fronts[0].datacenter, "ha-7-wg.whiskergalaxy.com");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refresh_follows_dns_and_clears_connections_to_servers_that_left() {
        let dir = scratch("refresh");
        let (state, w) = (dir.join("entries.json"), dir.join("p.json"));
        let (state, w) = (state.to_str().unwrap(), w.to_str().unwrap());
        let (scripts, ct) = (Scripts::default(), Scripts::default());
        let names = dns(&[(
            "ha-7-wg.whiskergalaxy.com",
            &["198.51.100.10", "198.51.100.11"],
        )]);
        let sys = lab_with(scripts.clone(), names.clone(), ct.clone());
        up_dc(&sys, state, "203.0.113.5", "ha-7-wg.whiskergalaxy.com", w);
        let sent = scripts.borrow().len();

        refresh(&sys, state);
        assert_eq!(
            scripts.borrow().len(),
            sent,
            "nothing changed: no new table"
        );

        names.borrow_mut()[0].1 = vec!["198.51.100.10".parse().unwrap()];
        refresh(&sys, state);
        let last = scripts.borrow().last().unwrap().clone();
        assert!(last.contains("dnat ip to 198.51.100.10:443"), "{last}");
        assert!(!last.contains("198.51.100.11"), "{last}");
        assert_eq!(
            ct.borrow().last().unwrap(),
            "conntrack -D -p udp --orig-dst 203.0.113.5 --orig-port-dst 443 --reply-src 198.51.100.11"
        );

        names.borrow_mut().clear();
        let sent = scripts.borrow().len();
        refresh(&sys, state);
        assert_eq!(scripts.borrow().len(), sent, "DNS failed: keep the table");
        assert_eq!(
            State::load(state).unwrap().entries[0].servers,
            vec!["198.51.100.10".parse::<Ipv4Addr>().unwrap()]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refresh_leaves_stopped_forwarding_stopped() {
        let dir = scratch("refresh-stopped");
        let (state, w) = (dir.join("entries.json"), dir.join("p.json"));
        let (state, w) = (state.to_str().unwrap(), w.to_str().unwrap());
        let scripts = Scripts::default();
        let names = dns(&[("ha-7-wg.whiskergalaxy.com", &["198.51.100.10"])]);
        let sys = lab_with(scripts.clone(), names.clone(), Scripts::default());
        up_dc(&sys, state, "203.0.113.5", "ha-7-wg.whiskergalaxy.com", w);
        run(&sys, &s(&["down", "--state", state])).unwrap();
        let sent = scripts.borrow().len();

        names.borrow_mut()[0].1 = vec!["198.51.100.12".parse().unwrap()];
        refresh(&stopped_with(scripts.clone(), names), state);
        assert_eq!(scripts.borrow().len(), sent, "no table loaded");
        assert_eq!(
            State::load(state).unwrap().entries[0].servers,
            vec!["198.51.100.12".parse::<Ipv4Addr>().unwrap()]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn removing_an_entry_ends_its_connections() {
        let dir = scratch("remove-ct");
        let (state, w) = (dir.join("entries.json"), dir.join("p.json"));
        let (state, w) = (state.to_str().unwrap(), w.to_str().unwrap());
        let ct = Scripts::default();
        let names = dns(&[(&dc("198.51.100.10"), &["198.51.100.10"])]);
        let sys = lab_with(Scripts::default(), names, ct.clone());
        up_entry(&sys, state, "203.0.113.5", "198.51.100.10", w);
        run(
            &sys,
            &s(&["down", "--entry", "203.0.113.5:443", "--state", state]),
        )
        .unwrap();
        assert_eq!(
            ct.borrow().last().unwrap(),
            "conntrack -D -p udp --orig-dst 203.0.113.5 --orig-port-dst 443"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn one_host_forwards_two_ips_to_two_servers_with_one_server_per_profile() {
        let dir = scratch("two-ips");
        let state = dir.join("entries.json");
        let (state, a, b) = (
            state.to_str().unwrap(),
            dir.join("a.json"),
            dir.join("b.json"),
        );
        let (a, b) = (a.to_str().unwrap(), b.to_str().unwrap());
        let scripts = Scripts::default();
        let sys = lab_sys(scripts.clone());
        up_entry(&sys, state, "203.0.113.5", "198.51.100.10", a);
        up_entry(&sys, state, "203.0.113.6", "198.51.100.20", b);

        let last = scripts.borrow().last().unwrap().clone();
        for want in [
            "ip daddr 203.0.113.5 udp dport 443 counter dnat ip to 198.51.100.10:443",
            "ip daddr 203.0.113.6 udp dport 443 counter dnat ip to 198.51.100.20:443",
        ] {
            assert!(last.contains(want), "missing {want:?} in\n{last}");
        }
        for (path, exit) in [(a, "198.51.100.10"), (b, "198.51.100.20")] {
            let p = Profile::load(path).unwrap();
            assert_eq!(p.fronts.len(), 1, "{path}");
            assert_eq!(p.fronts[0].datacenter, dc(exit));
        }

        let f = Flags::parse(&s(&["--state", state]), EXPORT_FLAGS).unwrap();
        let both = export_profile(&f).unwrap();
        let exits: Vec<String> = both.fronts.iter().map(|f| f.datacenter.clone()).collect();
        assert_eq!(exits, vec![dc("198.51.100.10"), dc("198.51.100.20")]);
        assert!(!both.all, "export doesn't know every location");
        both.validate().unwrap();
        let f = Flags::parse(
            &s(&["--state", state, "--entry", "203.0.113.6:443"]),
            EXPORT_FLAGS,
        )
        .unwrap();
        assert_eq!(export_profile(&f).unwrap(), Profile::load(b).unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn down_entry_removes_one_and_apply_restores_the_rest() {
        let dir = scratch("down-entry");
        let state = dir.join("entries.json");
        let state = state.to_str().unwrap();
        let w = dir.join("p.json");
        let w = w.to_str().unwrap();
        let scripts = Scripts::default();
        let sys = lab_sys(scripts.clone());
        up_entry(&sys, state, "203.0.113.5", "198.51.100.10", w);
        up_entry(&sys, state, "203.0.113.6", "198.51.100.20", w);
        let last = || scripts.borrow().last().unwrap().clone();

        run(
            &sys,
            &s(&["down", "--entry", "203.0.113.5:443", "--state", state]),
        )
        .unwrap();
        assert!(last().contains("ip daddr 203.0.113.6 udp dport 443 counter dnat"));
        assert!(!last().contains("203.0.113.5"), "{}", last());

        run(&sys, &s(&["down", "--state", state])).unwrap();
        assert_eq!(last(), nft::delete_script());
        assert_eq!(State::load(state).unwrap().entries.len(), 1);

        run(
            &sys,
            &s(&["apply", "--state", state, "--skip-sysctl", "--no-flowtable"]),
        )
        .unwrap();
        assert!(last().contains("ip daddr 203.0.113.6 udp dport 443 counter dnat"));

        run(&sys, &s(&["down", "--forget", "--state", state])).unwrap();
        assert!(!std::path::Path::new(state).exists());
        let e = run(
            &sys,
            &s(&["down", "--entry", "203.0.113.6:443", "--state", state]),
        )
        .unwrap_err();
        assert!(e.contains("no saved entries"), "{e}");
        let e = run(&sys, &s(&["apply", "--state", state])).unwrap_err();
        assert!(e.contains("no saved entries"), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn removing_an_entry_while_stopped_does_not_start_forwarding() {
        let dir = scratch("stopped");
        let state = dir.join("entries.json");
        let state = state.to_str().unwrap();
        let w = dir.join("p.json");
        let w = w.to_str().unwrap();
        let scripts = Scripts::default();
        let sys = lab_sys(scripts.clone());
        up_entry(&sys, state, "203.0.113.5", "198.51.100.10", w);
        up_entry(&sys, state, "203.0.113.6", "198.51.100.20", w);
        run(&sys, &s(&["down", "--state", state])).unwrap();
        let sent = scripts.borrow().len();

        let stopped = stopped_sys(scripts.clone());
        run(
            &stopped,
            &s(&["down", "--entry", "203.0.113.5:443", "--state", state]),
        )
        .unwrap();
        assert_eq!(
            scripts.borrow().len(),
            sent,
            "{:?}",
            scripts.borrow().last()
        );
        assert_eq!(State::load(state).unwrap().endpoints(), "203.0.113.6:443");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_profile_with_several_fronts_splits_into_entries() {
        let dir = scratch("split");
        let (state, multi, w) = (
            dir.join("entries.json"),
            dir.join("multi.json"),
            dir.join("w.json"),
        );
        let (state, multi, w) = (
            state.to_str().unwrap(),
            multi.to_str().unwrap(),
            w.to_str().unwrap(),
        );
        let sys = lab_sys(Scripts::default());
        up_entry(&sys, state, "203.0.113.5", "198.51.100.10", multi);
        let mut p = Profile::load(multi).unwrap();
        let mut second = p.fronts[0].clone();
        second.entry_ip = "203.0.113.6".parse().unwrap();
        second.datacenter = dc("198.51.100.20");
        p.fronts.push(second);
        std::fs::write(multi, p.to_json().unwrap()).unwrap();

        let e = run(
            &sys,
            &s(&[
                "up",
                "--from",
                multi,
                "--bind",
                "203.0.113.5",
                "--state",
                state,
            ]),
        )
        .unwrap_err();
        assert!(e.contains("once per entry"), "{e}");

        run(
            &sys,
            &s(&[
                "up",
                "--from",
                multi,
                "--write",
                w,
                "--state",
                state,
                "--skip-sysctl",
                "--no-flowtable",
            ]),
        )
        .unwrap();
        let st = State::load(state).unwrap();
        assert_eq!(st.endpoints(), "203.0.113.5:443, 203.0.113.6:443");
        assert!(st.entries.iter().all(|e| e.profile.fronts.len() == 1));

        let f = Flags::parse(
            &s(&["--from", multi, "--entry", "203.0.113.6:443"]),
            EXPORT_FLAGS,
        )
        .unwrap();
        let one = export_profile(&f).unwrap();
        assert_eq!(one.fronts.len(), 1);
        assert_eq!(one.fronts[0].datacenter, dc("198.51.100.20"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A host whose eth0 carries 45.33.30.0/24 (it holds the first address),
    /// recording its `ip`, `nft` and connection calls in `calls`. Checking the
    /// range counts `answers` packets.
    fn range_sys(calls: Scripts, answers: u64) -> Sys {
        let names = dns(&[(&dc("198.51.100.10"), &["198.51.100.10"])]);
        let log = calls.clone();
        Sys::fixture(
            "/nonexistent",
            Box::new(move |cmd, args, stdin| {
                log.borrow_mut().push(format!(
                    "{cmd} {}{}",
                    args.join(" "),
                    stdin.map(|s| format!("\n{s}")).unwrap_or_default()
                ));
                match cmd {
                    "ip" if args.iter().any(|a| a == "route") => {
                        Ok(r#"[{"dev":"eth0","prefsrc":"45.33.30.0"}]"#.into())
                    }
                    "ip" => Ok(
                        r#"[{"ifname":"eth0","addr_info":[{"local":"45.33.30.0","prefixlen":24}]}]"#
                            .into(),
                    ),
                    "nft" if args.iter().any(|a| a == "hydra_probe") && args[0] == "-j" => {
                        Ok(format!(
                            r#"{{"nftables":[{{"rule":{{"expr":[{{"counter":{{"packets":{answers},"bytes":0}}}}]}}}}]}}"#
                        ))
                    }
                    "nft" | "conntrack" => Ok(String::new()),
                    _ => Err(format!("{cmd} not available in test")),
                }
            }),
        )
        .with_resolver(resolver(names.clone()))
        .with_fetcher(list_of(names))
        .with_connector(move |from, to| {
            calls.borrow_mut().push(format!("connect {from:?} {to}"));
            Ok(())
        })
    }

    fn up_args(listen: &str, state: &str, write: &str, extra: &[&str]) -> Vec<String> {
        let mut args = s(&[
            "up",
            "--listen",
            listen,
            "--datacenter",
            &dc("198.51.100.10"),
            "--label",
            "Lab",
            "--write",
            write,
            "--state",
            state,
            "--skip-sysctl",
            "--no-flowtable",
        ]);
        args.extend(s(extra));
        args
    }

    fn count(calls: &Scripts, want: &str) -> usize {
        calls.borrow().iter().filter(|c| *c == want).count()
    }

    #[test]
    fn an_address_of_a_routed_range_arrives_as_it_is() {
        let dir = scratch("range-routed");
        let state = dir.join("entries.json");
        let state = state.to_str().unwrap();
        let w = dir.join("p.json");
        let calls = Scripts::default();
        let sys = range_sys(calls.clone(), 0);
        run(
            &sys,
            &up_args("45.33.30.8", state, w.to_str().unwrap(), &[]),
        )
        .unwrap();

        let e = &State::load(state).unwrap().entries[0];
        assert_eq!(e.bind, None, "not 1:1 NAT: the range is the server's");
        assert_eq!(e.claim, None);
        assert!(!calls.borrow().iter().any(|c| c.starts_with("ip -4 addr")));
        assert!(calls
            .borrow()
            .iter()
            .any(|c| c.contains("ip daddr 45.33.30.8 udp dport 443 counter dnat")));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn add_address_holds_the_address_while_its_entry_forwards() {
        let dir = scratch("range-held");
        let state = dir.join("entries.json");
        let state = state.to_str().unwrap();
        let w = dir.join("p.json");
        let w = w.to_str().unwrap();
        let calls = Scripts::default();
        let sys = range_sys(calls.clone(), 0);
        const ADD: &str = "ip -4 addr add 45.33.30.7/32 dev eth0";
        const DEL: &str = "ip -4 addr del 45.33.30.7/32 dev eth0";

        run(&sys, &up_args("45.33.30.7", state, w, &["--add-address"])).unwrap();
        assert_eq!(count(&calls, ADD), 1);
        let e = &State::load(state).unwrap().entries[0];
        assert_eq!(e.claim.as_deref(), Some("eth0"), "the range's interface");

        run(&sys, &s(&["down", "--state", state])).unwrap();
        assert_eq!(count(&calls, DEL), 1, "stopping lets it go");
        run(
            &sys,
            &s(&["apply", "--state", state, "--skip-sysctl", "--no-flowtable"]),
        )
        .unwrap();
        assert_eq!(count(&calls, ADD), 2, "apply (at boot) holds it again");

        run(&sys, &up_args("45.33.30.9", state, w, &[])).unwrap();
        run(
            &sys,
            &s(&["down", "--entry", "45.33.30.7:443", "--state", state]),
        )
        .unwrap();
        assert_eq!(count(&calls, DEL), 2, "removed with its entry");
        assert!(!calls
            .borrow()
            .iter()
            .any(|c| c.starts_with("ip -4 addr") && c.contains("45.33.30.9")));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn add_address_leaves_an_address_the_server_holds_alone() {
        let dir = scratch("range-own");
        let state = dir.join("entries.json");
        let state = state.to_str().unwrap();
        let w = dir.join("p.json");
        let w = w.to_str().unwrap();
        let calls = Scripts::default();
        let sys = range_sys(calls.clone(), 0);
        run(&sys, &up_args("45.33.30.0", state, w, &["--add-address"])).unwrap();
        assert_eq!(State::load(state).unwrap().entries[0].claim, None);
        run(&sys, &s(&["down", "--state", state])).unwrap();
        assert!(!calls.borrow().iter().any(|c| c.starts_with("ip -4 addr")));

        let e = run(
            &sys,
            &up_args(
                "192.0.2.50",
                state,
                w,
                &["--bind", "45.33.30.0", "--add-address"],
            ),
        )
        .unwrap_err();
        assert!(e.contains("arrives on 45.33.30.0"), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn check_range_connects_from_a_free_address_of_the_range() {
        let calls = Scripts::default();
        let sys = range_sys(calls.clone(), 1);
        let url = "http://198.51.100.99:8080/WebsiteStatus";
        run(
            &sys,
            &s(&["check-range", "45.33.30.0/24", "--status-url", url]),
        )
        .unwrap();
        let calls = calls.borrow();
        assert!(calls.iter().any(|c| c == "connect None 198.51.100.99:8080"));
        assert!(calls
            .iter()
            .any(|c| c == "connect Some(45.33.30.1) 198.51.100.99:8080"));
        assert_eq!(calls.last().unwrap(), "nft delete table inet hydra_probe");
    }

    #[test]
    fn check_range_names_the_ranges_it_knows() {
        let sys = range_sys(Scripts::default(), 0);
        let e = run(&sys, &s(&["check-range", "45.33.31.0/24"])).unwrap_err();
        assert!(e.contains("it has: 45.33.30.0/24"), "{e}");
    }

    #[test]
    fn probe_targets_come_from_the_status_url() {
        let sys = range_sys(Scripts::default(), 0);
        let t = |url: &str| probe_target(&sys, url).map(|t| t.to_string());
        assert_eq!(
            t("https://198.51.100.99/WebsiteStatus").unwrap(),
            "198.51.100.99:443"
        );
        assert_eq!(t("http://198.51.100.99/x").unwrap(), "198.51.100.99:80");
        assert_eq!(
            t("http://198.51.100.99:8080").unwrap(),
            "198.51.100.99:8080"
        );
        assert!(t("198.51.100.99").is_err());
    }
}
