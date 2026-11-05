//! `hydra setup`: a guided way to add, remove and share entries.
//!
//! It asks for what `hydra up` takes as flags and does the same work through
//! the same functions. The flow talks to a [`Ui`]: the terminal, or a script
//! of answers in tests.

use crate::audit::{self, Severity};
use crate::datacenters::{self, Datacenter};
use crate::host::{self, Range};
use crate::look::{self, bold, Tone};
use crate::probe::Delivery;
use crate::profile::{Front, Profile};
use crate::state::{Entry, RangeUse, State};
use crate::sys::Sys;
use dialoguer::console::Term;
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Input, Select};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// The questions the flow asks.
pub trait Ui {
    /// Prints a line between questions.
    fn say(&mut self, text: &str);
    /// One of `items`, or `None` when the user backs out (Esc or q).
    fn select(
        &mut self,
        prompt: &str,
        items: &[String],
        default: usize,
    ) -> Result<Option<usize>, String>;
    /// A line of text that passes `check`. An empty `default` means none.
    fn input(
        &mut self,
        prompt: &str,
        default: &str,
        check: &dyn Fn(&str) -> Result<(), String>,
    ) -> Result<String, String>;
    fn confirm(&mut self, prompt: &str, default: bool) -> Result<bool, String>;
}

/// Whether a person is at the keyboard: setup needs to ask them things.
pub fn interactive() -> bool {
    use std::io::IsTerminal as _;
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

/// The terminal: arrow-key menus and prompts on stderr, in hydra's colours.
pub struct Terminal {
    theme: ColorfulTheme,
}

impl Default for Terminal {
    fn default() -> Self {
        Terminal {
            theme: look::theme(),
        }
    }
}

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// Ctrl-C ends setup at the next question instead of killing it, so it never
/// stops halfway through changing the table, and the cursor a menu hides comes
/// back. A second Ctrl-C exits at once.
pub fn catch_ctrl_c() {
    let _ = ctrlc::set_handler(|| {
        if INTERRUPTED.swap(true, Ordering::SeqCst) {
            let _ = Term::stderr().show_cursor();
            std::process::exit(130);
        }
    });
}

fn not_interrupted() -> Result<(), String> {
    if INTERRUPTED.load(Ordering::SeqCst) {
        let _ = Term::stderr().show_cursor();
        return Err("setup stopped (Ctrl-C)".into());
    }
    Ok(())
}

/// Ctrl-C or a closed terminal ends setup; the cursor the menu hid comes back.
fn stopped(e: dialoguer::Error) -> String {
    let _ = Term::stderr().show_cursor();
    // A menu reads Ctrl-C as an interrupted read, before the handler runs.
    #[allow(unreachable_patterns)]
    let ctrl_c = match &e {
        dialoguer::Error::IO(io) => io.kind() == std::io::ErrorKind::Interrupted,
        _ => false,
    };
    if ctrl_c || INTERRUPTED.load(Ordering::SeqCst) {
        return "setup stopped (Ctrl-C)".into();
    }
    format!("setup stopped ({e})")
}

impl Ui for Terminal {
    fn say(&mut self, text: &str) {
        eprintln!("{text}");
    }

    fn select(
        &mut self,
        prompt: &str,
        items: &[String],
        default: usize,
    ) -> Result<Option<usize>, String> {
        not_interrupted()?;
        Select::with_theme(&self.theme)
            .with_prompt(prompt)
            .items(items)
            .default(default)
            .max_length(15)
            .interact_opt()
            .map_err(stopped)
    }

    fn input(
        &mut self,
        prompt: &str,
        default: &str,
        check: &dyn Fn(&str) -> Result<(), String>,
    ) -> Result<String, String> {
        not_interrupted()?;
        let mut q = Input::<String>::with_theme(&self.theme)
            .with_prompt(prompt)
            .allow_empty(true)
            .validate_with(|v: &String| check(v.trim()));
        if !default.is_empty() {
            q = q.default(default.to_string());
        }
        q.interact_text()
            .map(|v| v.trim().to_string())
            .map_err(stopped)
    }

    fn confirm(&mut self, prompt: &str, default: bool) -> Result<bool, String> {
        not_interrupted()?;
        Confirm::with_theme(&self.theme)
            .with_prompt(prompt)
            .default(default)
            .interact()
            .map_err(stopped)
    }
}

pub struct Setup<'a> {
    pub sys: &'a Sys,
    /// The saved entries (`--state`).
    pub state: &'a str,
    pub ui: &'a mut dyn Ui,
    /// Loads Windscribe's datacenters, once, when the flow first needs them.
    pub load_datacenters: Box<dyn FnMut() -> Result<Vec<Datacenter>, String> + 'a>,
    pub datacenters: Option<Vec<Datacenter>>,
    /// Where profiles are written unless the user says otherwise.
    pub dir: PathBuf,
    /// Whether the terminal draws emoji: flags, or country codes.
    pub emoji: bool,
    /// How an address of a range the server doesn't hold reaches it (probe.rs).
    pub check_range: Box<dyn FnMut(Ipv4Addr) -> Result<Delivery, String> + 'a>,
}

const MENU: [&str; 6] = [
    "Map addresses to locations",
    "Remove an entry",
    "Share the profile",
    "Check this server",
    "Keep hydra running after a reboot",
    "Quit",
];

pub fn run(s: &mut Setup) -> Result<(), String> {
    s.ui.say(&look::banner());
    let st = State::load(s.state)?;
    welcome(s, &st);
    loop {
        let st = State::load(s.state)?;
        if st.entries.is_empty() {
            s.ui.say(&para(
                "This server forwards nothing yet. Map an address on it to a Windscribe location: \
                 each mapping is an entry, and its profile is what you share.",
                0,
            ));
            if !map_addresses(s)? {
                break;
            }
            continue;
        }
        show_entries(s, &st);
        let items: Vec<String> = MENU.iter().map(|m| m.to_string()).collect();
        match s.ui.select("What next?", &items, 0)? {
            Some(0) => {
                map_addresses(s)?;
            }
            Some(1) => remove(s, &st)?,
            Some(2) => share(s, &st)?,
            Some(3) => doctor(s, &st),
            Some(4) => boot(s)?,
            _ => break,
        }
    }
    s.ui.say(&format!(
        "\n{} {}\n",
        Tone::Green.style().bold().apply_to("✔ Done.".to_string()),
        note("`sudo hydra status` lists the entries; `sudo hydra setup` brings you back here.")
    ));
    Ok(())
}

fn ok(text: &str) -> String {
    format!("{} {text}", Tone::Green.paint("✔"))
}

fn warn(text: &str) -> String {
    format!(
        "{} {text}",
        Tone::Yellow.style().bold().apply_to("▲".to_string())
    )
}

fn note(text: &str) -> String {
    Tone::Dim.paint(text).to_string()
}

/// A dim paragraph, wrapped to the terminal.
fn para(text: &str, indent: usize) -> String {
    note(&look::wrap(text, indent))
}

/// What the entries forward to, `hostname:port`, for the doctor.
fn exits(st: &State) -> Vec<String> {
    let mut out: Vec<String> = st
        .entries
        .iter()
        .map(|e| format!("{}:{}", e.front().datacenter, e.front().exit_port))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The addresses that can take traffic: all but loopback and link-local.
fn local_addresses(sys: &Sys) -> Vec<Ipv4Addr> {
    host::local_ipv4s(sys)
        .into_iter()
        .filter(|ip| !ip.is_loopback() && !ip.is_link_local())
        .collect()
}

/// The welcome card: this host, its addresses and entries, and the doctor's
/// verdict, with its failures and warnings below. Forwarding being off doesn't
/// count: hydra turns it on when it starts forwarding.
fn welcome(s: &mut Setup, st: &State) {
    let facts = audit::gather(s.sys, None, &exits(st));
    let found: Vec<audit::Finding> = audit::findings(&facts)
        .into_iter()
        .filter(|f| f.severity >= Severity::Warn && f.id != "ip_forward")
        .collect();
    let locals = local_addresses(s.sys);
    let public = locals.iter().filter(|ip| host::is_public(**ip)).count();
    let ranges: Vec<String> = host::ranges(s.sys).iter().map(Range::cidr).collect();
    let ranges = if ranges.is_empty() {
        String::new()
    } else {
        format!(" · ranges {}", ranges.join(", "))
    };
    let entries = match st.entries.len() {
        0 => note("none yet"),
        1 => Tone::Green.paint("1 forwarding").to_string(),
        n => Tone::Green.paint(format!("{n} forwarding")).to_string(),
    };
    let checks = match found.len() {
        0 => Tone::Green.paint("✔ all good").to_string(),
        n => Tone::Yellow
            .paint(format!("▲ {n} to look at, below"))
            .to_string(),
    };
    s.ui.say(&look::card(
        "hydra setup",
        &[
            ("host", bold(host::node_name(s.sys)).to_string()),
            (
                "addresses",
                format!("{} IPv4 · {public} public{ranges}", locals.len()),
            ),
            ("entries", entries),
            ("checks", checks),
        ],
    ));
    for f in &found {
        s.ui.say(&warn(&f.summary));
    }
    if !found.is_empty() {
        s.ui.say(&para(
            "`sudo hydra doctor` explains these; `sudo hydra tune --apply` fixes the tunable ones.",
            2,
        ));
    }
    s.ui.say("");
}

fn show_entries(s: &mut Setup, st: &State) {
    let n = st.entries.len();
    s.ui.say(&format!(
        "\n{}",
        bold(format!(
            "This server forwards {n} entr{}",
            if n == 1 { "y" } else { "ies" }
        ))
    ));
    for e in &st.entries {
        s.ui.say(&format!("  {}", entry_line(e, s.emoji)));
    }
    s.ui.say("");
}

/// `🇨🇦 203.0.113.5:443  → Toronto · The 6`
fn entry_line(e: &Entry, emoji: bool) -> String {
    let f = e.front();
    let arrives = e
        .bind
        .map(|b| note(&format!("  arrives on {b}")))
        .unwrap_or_default();
    format!(
        "{} {} {} {}{arrives}",
        look::flag(&e.country, emoji),
        bold(format!("{:<21}", f.endpoint())),
        look::arrow(),
        Tone::Blue.paint(&f.location)
    )
}

/// A flag and a space, or nothing without a country code.
fn flag_prefix(code: &str, emoji: bool) -> String {
    if code.is_empty() {
        String::new()
    } else {
        format!("{} ", look::flag(code, emoji))
    }
}

/// The mapping screen: every address on this server and what it forwards.
/// Each pick maps one address to a Windscribe location, until Done. Returns
/// whether anything was mapped.
fn map_addresses(s: &mut Setup) -> Result<bool, String> {
    if offer_map_all(s)? {
        offer_boot(s)?;
        return Ok(true);
    }
    let mut mapped = false;
    while let Some((listen, bind, claim)) = pick_address(s)? {
        mapped |= add_entry(s, listen, bind, claim)?;
    }
    let n = State::load(s.state)?.entries.len();
    if mapped && n > 1 {
        s.ui.say(&para(
            &format!(
                "The app takes one profile at a time: \"Share the profile\" writes one for all {n} entries."
            ),
            0,
        ));
    }
    if mapped {
        offer_boot(s)?;
    }
    Ok(mapped)
}

/// An address picked for a new entry: the one clients dial, the local one its
/// traffic arrives on behind 1:1 NAT, and the interface hydra holds it on.
type Picked = (Ipv4Addr, Option<Ipv4Addr>, Option<String>);

/// The addresses of `r` no entry uses.
fn free_in(r: &Range, st: &State) -> Vec<Ipv4Addr> {
    r.addresses
        .iter()
        .copied()
        .filter(|a| !st.entries.iter().any(|e| e.local() == *a))
        .collect()
}

/// Whether `r` is this server's to use, and whether hydra has to hold each
/// address it maps there: asked once, then kept with the entries. None when
/// the user backs out.
fn approve_range(s: &mut Setup, r: &Range) -> Result<Option<RangeUse>, String> {
    let cidr = r.cidr();
    if let Some(u) = State::load(s.state)?
        .ranges
        .into_iter()
        .find(|u| u.cidr == cidr)
    {
        return Ok(Some(u));
    }
    if r.has_gateway {
        s.ui.say(&warn(&format!(
            "{cidr} holds this server's gateway: it's the network the server is on, which \
             providers often share with other customers."
        )));
    }
    if !s.ui.confirm(
        &format!("Is all of {cidr} assigned to this server by your provider?"),
        false,
    )? {
        return Ok(None);
    }
    let hold = format!(
        "Add each address hydra maps to {} (and remove it with its entry)?",
        r.iface
    );
    let claim = if r.has_gateway {
        // The provider's router asks for each address on the server's own network.
        s.ui.say(&para(
            "On the network the server is on, an address only reaches it once the server holds it.",
            2,
        ));
        if !s.ui.confirm(&hold, true)? {
            return Ok(None);
        }
        true
    } else {
        let Some(probe) = free_in(r, &State::load(s.state)?).first().copied() else {
            return Ok(None);
        };
        s.ui.say(&note(&format!("Checking how {cidr} reaches this server…")));
        match (s.check_range)(probe) {
            Ok(Delivery::Routed) => {
                s.ui.say(&ok(&format!(
                    "{cidr} is routed to this server: hydra uses its addresses as they are."
                )));
                false
            }
            Ok(Delivery::NotDelivered) => {
                s.ui.say(&warn(&format!(
                    "Traffic for {cidr} doesn't reach this server on its own: your provider \
                     expects the server to hold each address it uses."
                )));
                if !s.ui.confirm(&hold, true)? {
                    return Ok(None);
                }
                true
            }
            Err(e) => {
                s.ui.say(&warn(&format!(
                    "Couldn't check how {cidr} reaches this server: {e}"
                )));
                let items = vec![
                    format!(
                        "Add each address hydra maps to {} (works either way)",
                        r.iface
                    ),
                    "My provider routes it to this server: use its addresses as they are"
                        .to_string(),
                    note("← Back"),
                ];
                match s
                    .ui
                    .select(&format!("How does {cidr} reach this server?"), &items, 0)?
                {
                    Some(0) => true,
                    Some(1) => false,
                    _ => return Ok(None),
                }
            }
        }
    };
    let u = RangeUse {
        cidr,
        iface: r.iface.clone(),
        claim,
    };
    let mut st = State::load(s.state)?;
    st.ranges.push(u.clone());
    st.save(s.state)?;
    Ok(Some(u))
}

/// An address of `r` for one entry, and the interface to hold it on when the
/// range isn't routed here. None when the user backs out.
fn pick_in_range(s: &mut Setup, r: &Range) -> Result<Option<Picked>, String> {
    let Some(u) = approve_range(s, r)? else {
        return Ok(None);
    };
    let free = free_in(r, &State::load(s.state)?);
    let Some(first) = free.first() else {
        s.ui.say(&warn(&format!(
            "Every address in {} is mapped already.",
            r.cidr()
        )));
        return Ok(None);
    };
    let usable = r.addresses.clone();
    let cidr = r.cidr();
    let v = s.ui.input(
        &format!("Which address in {cidr}?"),
        &first.to_string(),
        &|v| match parse_ipv4(v) {
            Ok(ip) if usable.contains(&ip) => Ok(()),
            Ok(ip) => Err(format!("{ip} isn't a usable address in {cidr}")),
            Err(e) => Err(e),
        },
    )?;
    let ip = parse_ipv4(&v)?;
    Ok(Some((ip, None, u.claim.then(|| u.iface.clone()))))
}

/// This server's public addresses that no entry uses.
fn free_public(sys: &Sys, st: &State) -> Vec<Ipv4Addr> {
    local_addresses(sys)
        .into_iter()
        .filter(|ip| host::is_public(*ip) && !st.entries.iter().any(|e| e.local() == *ip))
        .collect()
}

/// Whether `fronts` cover every Windscribe location the apps can use now.
fn covers_every_location(fronts: &[Front], dcs: &[Datacenter]) -> bool {
    let usable: Vec<&Datacenter> = dcs.iter().filter(|d| d.usable).collect();
    !usable.is_empty()
        && usable
            .iter()
            .all(|d| fronts.iter().any(|f| f.datacenter_id == d.id))
}

/// One profile for every entry, marked as covering every location when it
/// does: the apps hold one profile at a time.
fn combined_profile(s: &mut Setup, st: &State) -> Profile {
    let fronts: Vec<Front> = st.entries.iter().map(|e| e.front().clone()).collect();
    let all = match datacenters(s) {
        Ok(dcs) => covers_every_location(&fronts, &dcs),
        Err(e) => {
            s.ui.say(&warn(&format!(
                "Couldn't check whether it maps every location: {e}"
            )));
            false
        }
    };
    Profile::combined(host::node_name(s.sys), fronts, all)
}

/// When this server has a free public address for every Windscribe location
/// it doesn't map yet, offers to map them all at once, one address each on
/// port 443, and writes one profile for every entry. True when it did.
fn offer_map_all(s: &mut Setup) -> Result<bool, String> {
    let st = State::load(s.state)?;
    let singles = free_public(s.sys, &st);
    let ranges: Vec<(Range, Vec<Ipv4Addr>)> = host::ranges(s.sys)
        .into_iter()
        .map(|r| {
            let free = free_in(&r, &st);
            (r, free)
        })
        .collect();
    let most = ranges
        .iter()
        .map(|(_, f)| f.len())
        .max()
        .unwrap_or(0)
        .max(singles.len());
    // One location is what the address picker is for.
    if most < 2 {
        return Ok(false);
    }
    let Ok(all) = datacenters(s) else {
        return Ok(false);
    };
    let mapped: HashSet<u32> = st.entries.iter().map(|e| e.front().datacenter_id).collect();
    let todo: Vec<Datacenter> = all
        .iter()
        .filter(|d| d.usable && !mapped.contains(&d.id))
        .cloned()
        .collect();
    if todo.len() < 2 || most < todo.len() {
        return Ok(false);
    }
    // The server's own addresses when there are enough, else the largest range.
    let (free, claim) = if singles.len() >= todo.len() {
        s.ui.say(&para(
            &format!(
                "This server has {} free public addresses: enough to map every Windscribe \
                 location ({}) to its own address, on port 443.",
                singles.len(),
                todo.len()
            ),
            0,
        ));
        if !s
            .ui
            .confirm(&format!("Map all {} locations at once?", todo.len()), false)?
        {
            return Ok(false);
        }
        (singles, None)
    } else {
        let Some((r, free)) = ranges
            .into_iter()
            .filter(|(_, f)| f.len() >= todo.len())
            .max_by_key(|(_, f)| f.len())
        else {
            return Ok(false);
        };
        s.ui.say(&para(
            &format!(
                "{} has {} free addresses: enough to map every Windscribe location ({}) to \
                 its own address, on port 443.",
                r.cidr(),
                free.len(),
                todo.len()
            ),
            0,
        ));
        if !s.ui.confirm(
            &format!(
                "Map all {} locations to addresses in {}?",
                todo.len(),
                r.cidr()
            ),
            false,
        )? {
            return Ok(false);
        }
        let Some(u) = approve_range(s, &r)? else {
            return Ok(false);
        };
        (free, u.claim.then_some(u.iface))
    };

    let mut addrs = free.into_iter();
    let mut added: Vec<Entry> = vec![];
    for dc in &todo {
        let found = match s.sys.resolve(&dc.hostname) {
            Ok(ips) if !ips.is_empty() => ips,
            _ => {
                s.ui.say(&warn(&format!(
                    "Skipped {}: it has no address right now.",
                    dc.label()
                )));
                continue;
            }
        };
        let Some(ip) = addrs.next() else { break };
        let profile = Profile::new(
            host::node_name(s.sys),
            vec![Front {
                location: dc.label(),
                datacenter: dc.hostname.clone(),
                datacenter_id: dc.id,
                exit_port: 443,
                entry_ip: ip,
                entry_port: 443,
                protocol: "wireguard".into(),
            }],
        );
        added.push(
            Entry::new(profile, None)
                .with_country(&dc.country)
                .with_servers(found)
                .with_claim(claim.clone()),
        );
    }
    if added.is_empty() {
        s.ui.say(&warn(
            "None of the locations has an address right now; try again in a minute.",
        ));
        return Ok(false);
    }
    let mut st = State::load(s.state)?;
    for e in &added {
        st.upsert(e.clone());
    }
    crate::forward(s.sys, s.state, &st, true, true)?;
    s.ui.say(&ok(&format!(
        "Forwarding {} locations, one address each.",
        added.len()
    )));
    let profile = combined_profile(s, &st);
    let path = pick_path(s, "hydra")?;
    write_profile(&path, &profile)?;
    s.ui.say(&ok(&format!(
        "Wrote {}. Share it privately: it maps {} and holds no keys.",
        path.display(),
        if profile.all {
            "every Windscribe location".to_string()
        } else {
            format!("{} locations", profile.fronts.len())
        }
    )));
    s.ui.say(&para(
        "Open UDP 443 on these addresses in your provider's firewall, if it has one.",
        2,
    ));
    s.ui.say("");
    Ok(true)
}

/// Maps `listen` (arriving on `bind` behind 1:1 NAT) to a datacenter the user
/// picks, and starts forwarding. False when they back out.
fn add_entry(
    s: &mut Setup,
    listen: Ipv4Addr,
    bind: Option<Ipv4Addr>,
    claim: Option<String>,
) -> Result<bool, String> {
    let st = State::load(s.state)?;
    let port = pick_port(s, &st, listen, bind.unwrap_or(listen))?;
    let Some(dc) = pick_datacenter(s)? else {
        return Ok(false);
    };
    let found = match s.sys.resolve(&dc.hostname) {
        Ok(ips) if !ips.is_empty() => ips,
        Ok(_) => {
            s.ui.say(&warn(&format!(
                "{} has no address right now; try again in a minute.",
                dc.label()
            )));
            return Ok(false);
        }
        Err(e) => {
            s.ui.say(&warn(&format!(
                "Couldn't look up {} ({e}); try again in a minute.",
                dc.label()
            )));
            return Ok(false);
        }
    };
    let profile = Profile::new(
        host::node_name(s.sys),
        vec![Front {
            location: dc.label(),
            datacenter: dc.hostname.clone(),
            datacenter_id: dc.id,
            exit_port: 443,
            entry_ip: listen,
            entry_port: port,
            protocol: "wireguard".into(),
        }],
    );
    let path = pick_path(s, &dc.city)?;
    let entry = Entry::new(profile, bind)
        .with_country(&dc.country)
        .with_servers(found)
        .with_claim(claim);
    let mut rows = vec![
        ("clients dial", bold(format!("{listen}:{port}")).to_string()),
        (
            "goes to",
            format!(
                "{}{}  load {}",
                flag_prefix(&dc.country, s.emoji),
                Tone::Blue.paint(dc.label()),
                look::load(dc.load, 0)
            ),
        ),
    ];
    if let Some(b) = bind {
        rows.push(("arrives on", b.to_string()));
    }
    if let Some(iface) = &entry.claim {
        rows.push(("adds", format!("{listen}/32 to {iface}")));
    }
    rows.push(("profile", path.display().to_string()));
    s.ui.say("");
    s.ui.say(&look::card("new entry", &rows));
    if !s.ui.confirm("Start forwarding?", true)? {
        return Ok(false);
    }

    let mut st = State::load(s.state)?;
    for r in st.upsert(entry.clone()) {
        s.ui.say(&warn(&format!("Replaced the entry on {r}.")));
    }
    crate::forward(s.sys, s.state, &st, true, true)?;
    write_profile(&path, &entry.profile)?;
    s.ui.say(&ok(&format!("Forwarding {}", entry_line(&entry, s.emoji))));
    s.ui.say(&ok(&format!(
        "Wrote {}. Share it privately: it names one datacenter and holds no keys.",
        path.display()
    )));
    s.ui.say(&para(
        &format!(
            "In the app, import it, then connect to {}: only that location goes through hydra.",
            dc.label()
        ),
        2,
    ));
    s.ui.say(&para(
        &format!(
            "If your provider has a firewall or security group, open UDP {port} on {listen} there."
        ),
        2,
    ));
    s.ui.say("");
    Ok(true)
}

/// The mapping screen's question: the public address clients will dial, and
/// the local one its traffic arrives on when they differ (1:1 NAT). `None` is
/// Done.
fn pick_address(s: &mut Setup) -> Result<Option<Picked>, String> {
    let locals = local_addresses(s.sys);
    let ranges = host::ranges(s.sys);
    let emoji = s.emoji;
    let route_src = host::default_route(s.sys).map(|(_, ip)| ip);
    let st = State::load(s.state)?;
    let maps = |ip: Ipv4Addr| -> Vec<String> {
        st.entries
            .iter()
            .filter(|e| e.local() == ip)
            .map(|e| {
                let f = e.front();
                // Behind 1:1 NAT, the public endpoint clients dial.
                let entry = if f.entry_ip == ip {
                    format!(":{}", f.entry_port)
                } else {
                    f.endpoint()
                };
                format!(
                    "{} {} {}{}",
                    Tone::Turquoise.paint(entry),
                    look::arrow(),
                    flag_prefix(&e.country, emoji),
                    Tone::Blue.paint(&f.location)
                )
            })
            .collect()
    };
    let mut items: Vec<String> = locals
        .iter()
        .map(|ip| {
            let mut notes = vec![];
            if !host::is_public(*ip) {
                notes.push(note("not public"));
            }
            let here = maps(*ip);
            notes.push(if here.is_empty() {
                Tone::Green.paint("free").to_string()
            } else {
                here.join("; ")
            });
            let iface = host::iface_for(s.sys, *ip).unwrap_or_default();
            format!(
                "{} {} {}",
                bold(format!("{:<16}", ip.to_string())),
                note(&format!("{iface:<8}")),
                notes.join(&note(" · "))
            )
        })
        .collect();
    let first_range = items.len();
    for r in &ranges {
        let free = free_in(r, &st).len();
        let mapped = r.addresses.len() - free;
        let mut notes = vec![format!("range · {free} free")];
        if mapped > 0 {
            notes.push(format!("{mapped} mapped"));
        }
        items.push(format!(
            "{} {} {}",
            bold(format!("{:<16}", r.cidr())),
            note(&format!("{:<8}", r.iface)),
            notes.join(&note(" · "))
        ));
    }
    let nat = items.len();
    items.push("A public IP this server doesn't show (cloud 1:1 NAT)".into());
    let done = items.len();
    items.push(
        Tone::Green
            .style()
            .bold()
            .apply_to("Done".to_string())
            .to_string(),
    );
    let free_public = locals
        .iter()
        .position(|ip| host::is_public(*ip) && maps(*ip).is_empty());
    let no_public = !locals.iter().any(|ip| host::is_public(*ip));
    let free_range = ranges
        .iter()
        .position(|r| !free_in(r, &st).is_empty())
        .map(|j| first_range + j);
    let default = match free_public.or(free_range) {
        Some(i) => i,
        None if no_public && st.entries.is_empty() => nat,
        None => done,
    };
    if no_public && st.entries.is_empty() {
        s.ui.say(&para(
            "None of this server's addresses is public, so your provider probably maps a public \
             IP onto it (1:1 NAT, as on most clouds). Pick that option and enter the public IP.",
            0,
        ));
    }
    loop {
        let Some(i) = s.ui.select(
            "Map which address to a Windscribe location?",
            &items,
            default,
        )?
        else {
            return Ok(None);
        };
        if i == done {
            return Ok(None);
        }
        if i < first_range {
            let ip = locals[i];
            if host::is_public(ip) || s.ui.confirm(&not_public(ip), false)? {
                return Ok(Some((ip, None, None)));
            }
            continue;
        }
        if i < nat {
            if let Some(pick) = pick_in_range(s, &ranges[i - first_range])? {
                return Ok(Some(pick));
            }
            continue;
        }
        let public = s.ui.input("Public IP clients connect to", "", &|v| {
            parse_ipv4(v).map(|_| ())
        })?;
        let public = parse_ipv4(&public)?;
        if !host::is_public(public) && !s.ui.confirm(&not_public(public), false)? {
            continue;
        }
        if locals.contains(&public) {
            return Ok(Some((public, None, None)));
        }
        if locals.is_empty() {
            return Err("this server has no IPv4 address for the traffic to arrive on".into());
        }
        let names: Vec<String> = locals.iter().map(|ip| ip.to_string()).collect();
        let route = route_src
            .and_then(|r| locals.iter().position(|ip| *ip == r))
            .unwrap_or(0);
        let Some(j) = s.ui.select(
            &format!("Which address on this server does traffic for {public} arrive on?"),
            &names,
            route,
        )?
        else {
            continue;
        };
        return Ok(Some((public, Some(locals[j]), None)));
    }
}

fn not_public(ip: Ipv4Addr) -> String {
    format!("{ip} isn't a public address, so only clients that can route to it will reach it. Use it anyway?")
}

fn parse_ipv4(v: &str) -> Result<Ipv4Addr, String> {
    match v.trim().parse::<Ipv4Addr>() {
        Ok(ip) if !ip.is_unspecified() => Ok(ip),
        _ => Err(format!("{v:?} is not an IPv4 address")),
    }
}

fn parse_port(v: &str) -> Result<u16, String> {
    match v.trim().parse::<u16>() {
        Ok(p) if p > 0 => Ok(p),
        _ => Err(format!("{v:?} is not a port (1-65535)")),
    }
}

/// A free port on `local`, or one the user agrees to take over.
fn pick_port(s: &mut Setup, st: &State, listen: Ipv4Addr, local: Ipv4Addr) -> Result<u16, String> {
    let taken = |port: u16| {
        st.entries.iter().find(|e| {
            e.endpoint() == format!("{listen}:{port}")
                || (e.local() == local && e.front().entry_port == port)
        })
    };
    let default = [443u16, 8443, 2053, 80, 51820]
        .into_iter()
        .find(|p| taken(*p).is_none())
        .unwrap_or(443);
    loop {
        let v = s.ui.input("Which UDP port?", &default.to_string(), &|v| {
            parse_port(v).map(|_| ())
        })?;
        let port = parse_port(&v)?;
        match taken(port) {
            Some(e) => {
                let q = format!(
                    "{} already leads to {}. Replace it?",
                    e.endpoint(),
                    e.front().location
                );
                if s.ui.confirm(&q, false)? {
                    return Ok(port);
                }
            }
            None => return Ok(port),
        }
    }
}

fn datacenters(s: &mut Setup) -> Result<Vec<Datacenter>, String> {
    if s.datacenters.is_none() {
        s.ui.say(&note("Fetching Windscribe's locations…"));
        let dcs = (s.load_datacenters)()?;
        let locations = distinct(dcs.iter().map(|d| d.location.clone())).len();
        s.ui.say(&ok(&format!(
            "{} datacenters in {locations} locations",
            dcs.len()
        )));
        s.datacenters = Some(dcs);
    }
    Ok(s.datacenters.clone().unwrap_or_default())
}

/// The exit: a Windscribe location, then one of its datacenters (asked only
/// when it has several), or a search by name. `None` when the user backs out.
fn pick_datacenter(s: &mut Setup) -> Result<Option<Datacenter>, String> {
    let all = datacenters(s)?;
    let locations = distinct(all.iter().map(|d| d.location.clone()));
    let glass = if s.emoji { "🔍" } else { "  " };
    let mut items = vec![format!("{glass} {}", note("Search by name…"))];
    items.extend(locations.iter().map(|l| {
        let here: Vec<&Datacenter> = all.iter().filter(|d| &d.location == l).collect();
        let cities = distinct(here.iter().map(|d| d.city.clone()));
        let place = match cities.as_slice() {
            [one] => one.clone(),
            many => format!("{} cities", many.len()),
        };
        format!(
            "{} {} {} {}",
            look::flag(&here[0].country, s.emoji),
            bold(format!("{l:<22}")),
            note(&format!("{place} ·")),
            load_summary(&here)
        )
    }));
    let mut default = if locations.is_empty() { 0 } else { 1 };
    loop {
        match s.ui.select("Which Windscribe location?", &items, default)? {
            None => return Ok(None),
            Some(0) => {
                if let Some(d) = search(s, &all)? {
                    return Ok(Some(d));
                }
            }
            Some(i) => {
                default = i;
                if let Some(d) = pick_in_location(s, &all, &locations[i - 1])? {
                    return Ok(Some(d));
                }
            }
        }
    }
}

fn distinct(names: impl Iterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    for n in names {
        if !out.contains(&n) {
            out.push(n);
        }
    }
    out.sort_by_key(|n| n.to_lowercase());
    out
}

/// "lowest load 12%", in colour, over the datacenters the apps would use when
/// there are any.
fn load_summary(dcs: &[&Datacenter]) -> String {
    let low = dcs
        .iter()
        .filter(|d| d.usable)
        .map(|d| d.load)
        .min()
        .or_else(|| dcs.iter().map(|d| d.load).min())
        .unwrap_or(0);
    format!("{} {}", note("lowest load"), look::load(low, 0))
}

/// One of `location`'s datacenters, asked only when it has several.
fn pick_in_location(
    s: &mut Setup,
    all: &[Datacenter],
    location: &str,
) -> Result<Option<Datacenter>, String> {
    let mut here: Vec<Datacenter> = all
        .iter()
        .filter(|d| d.location == location)
        .cloned()
        .collect();
    if here.len() == 1 {
        return Ok(here.pop());
    }
    pick_from(
        s,
        here,
        &format!("Which datacenter in {location}? The least loaded is first."),
        false,
    )
}

/// Datacenters whose city, name, location or country contains what the user
/// types.
fn search(s: &mut Setup, all: &[Datacenter]) -> Result<Option<Datacenter>, String> {
    loop {
        let q = s.ui.input(
            "Search for a city, country or datacenter name (Enter on its own goes back)",
            "",
            &|_| Ok(()),
        )?;
        if q.is_empty() {
            return Ok(None);
        }
        let found = datacenters::filter(all.to_vec(), &q);
        if found.is_empty() {
            s.ui.say(&warn(&format!("No datacenter matches “{q}”.")));
            continue;
        }
        if let Some(d) = pick_from(
            s,
            found,
            "Which datacenter? The least loaded is first.",
            true,
        )? {
            return Ok(Some(d));
        }
    }
}

/// A datacenter from `dcs`, in the order `hydra up --location` picks: ones
/// the apps would use first, then the least loaded.
fn pick_from(
    s: &mut Setup,
    mut dcs: Vec<Datacenter>,
    prompt: &str,
    show_flag: bool,
) -> Result<Option<Datacenter>, String> {
    dcs.sort_by(|a, b| {
        (!a.usable, a.load, &a.city, &a.nick).cmp(&(!b.usable, b.load, &b.city, &b.nick))
    });
    dcs.truncate(30);
    let mut items: Vec<String> = dcs
        .iter()
        .map(|d| {
            let draining = if d.usable {
                String::new()
            } else {
                Tone::Yellow.paint("  draining").to_string()
            };
            let flag = if show_flag {
                flag_prefix(&d.country, s.emoji)
            } else {
                String::new()
            };
            format!(
                "{flag}{} {} {} {}{draining}",
                bold(format!("{:<16}", d.city)),
                Tone::Blue.paint(format!("{:<18}", d.nick)),
                note("load"),
                look::load(d.load, 3)
            )
        })
        .collect();
    items.push(note("← Back"));
    match s.ui.select(prompt, &items, 0)? {
        Some(i) if i < dcs.len() => Ok(Some(dcs.remove(i))),
        _ => Ok(None),
    }
}

fn slug(name: &str) -> String {
    let s: String = name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect();
    let s = s
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if s.is_empty() {
        "hydra".into()
    } else {
        s
    }
}

fn pick_path(s: &mut Setup, city: &str) -> Result<PathBuf, String> {
    let default = s.dir.join(format!("{}.json", slug(city)));
    loop {
        let v = s.ui.input(
            "Write the profile to",
            &default.display().to_string(),
            &|v| {
                if v.is_empty() {
                    Err("enter a file name".into())
                } else {
                    Ok(())
                }
            },
        )?;
        let path = PathBuf::from(v);
        if !path.exists()
            || s.ui
                .confirm(&format!("{} exists. Overwrite it?", path.display()), false)?
        {
            return Ok(path);
        }
    }
}

fn write_profile(path: &Path, p: &Profile) -> Result<(), String> {
    std::fs::write(path, format!("{}\n", p.to_json()?))
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn pick_entry(s: &mut Setup, st: &State, prompt: &str) -> Result<Option<usize>, String> {
    let mut items: Vec<String> = st.entries.iter().map(|e| entry_line(e, s.emoji)).collect();
    items.push(note("← Back"));
    let back = items.len() - 1;
    Ok(s.ui.select(prompt, &items, back)?.filter(|i| *i < back))
}

fn remove(s: &mut Setup, st: &State) -> Result<(), String> {
    let Some(i) = pick_entry(s, st, "Remove which entry?")? else {
        return Ok(());
    };
    let e = &st.entries[i];
    let q = format!(
        "Stop forwarding {} and forget it? People using its profile won't connect.",
        e.endpoint()
    );
    if !s.ui.confirm(&q, false)? {
        return Ok(());
    }
    let (gone, running) = crate::remove_entry(s.sys, s.state, &e.endpoint(), true)?;
    s.ui.say(&ok(&format!("Removed {}", entry_line(&gone, s.emoji))));
    if !running {
        s.ui.say("  Forwarding is stopped; `sudo hydra apply` starts the other entries.");
    }
    Ok(())
}

/// Writes the profile to share: one for every entry (the apps hold one at a
/// time), or one entry's.
fn share(s: &mut Setup, st: &State) -> Result<(), String> {
    let (profile, name) = if let [one] = st.entries.as_slice() {
        (one.profile.clone(), one.front().location.clone())
    } else {
        let mut items = vec![format!(
            "{} {}",
            bold(format!("All {} entries, in one profile", st.entries.len())),
            note("(the app takes one profile)")
        )];
        items.extend(st.entries.iter().map(|e| entry_line(e, s.emoji)));
        items.push(note("← Back"));
        let back = items.len() - 1;
        match s.ui.select("Share which?", &items, 0)? {
            Some(0) => (combined_profile(s, st), "hydra".to_string()),
            Some(i) if i < back => {
                let e = &st.entries[i - 1];
                (e.profile.clone(), e.front().location.clone())
            }
            _ => return Ok(()),
        }
    };
    let path = pick_path(s, &name)?;
    write_profile(&path, &profile)?;
    let what = match profile.fronts.as_slice() {
        _ if profile.all => "every Windscribe location".to_string(),
        [one] => one.location.clone(),
        many => format!("{} locations", many.len()),
    };
    s.ui.say(&ok(&format!(
        "Wrote {}. Share it privately: it maps {what} and holds no keys.",
        path.display()
    )));
    if !profile.all {
        s.ui.say(&para(
            "In the app, import it, then connect to a location it maps: only those go through hydra.",
            2,
        ));
    }
    Ok(())
}

fn doctor(s: &mut Setup, st: &State) {
    let facts = audit::gather(s.sys, None, &exits(st));
    s.ui.say(&audit::render_text(&facts, &audit::findings(&facts)));
}

/// hydra's systemd units, with the path the binary is installed at.
const UNITS: [(&str, &str); 3] = [
    (
        "/etc/systemd/system/hydra.service",
        include_str!("../contrib/hydra.service"),
    ),
    (
        "/etc/systemd/system/hydra-refresh.service",
        include_str!("../contrib/hydra-refresh.service"),
    ),
    (
        "/etc/systemd/system/hydra-refresh.timer",
        include_str!("../contrib/hydra-refresh.timer"),
    ),
];

/// hydra's units, with the path this binary is installed at.
fn units() -> Vec<(&'static str, String)> {
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "/usr/local/bin/hydra".into());
    UNITS
        .iter()
        .map(|(path, unit)| (*path, unit.replace("/usr/local/bin/hydra", &exe)))
        .collect()
}

/// Whether the units are installed as this binary writes them, and enabled.
fn units_ready(s: &Setup, units: &[(&str, String)]) -> bool {
    let enabled = |unit: &str| {
        s.sys
            .run("systemctl", &["is-enabled", unit], None)
            .is_ok_and(|o| o.trim() == "enabled")
    };
    units
        .iter()
        .all(|(path, unit)| s.sys.read(path).as_deref() == Some(unit.trim()))
        && enabled("hydra.service")
        && enabled("hydra-refresh.timer")
}

/// Installs the systemd units, once the user agrees: `hydra apply` at boot,
/// and `hydra apply --refresh` every minute, so the entries follow their
/// datacenters.
fn install_units(s: &mut Setup, units: &[(&str, String)]) -> Result<(), String> {
    let q = "Keep hydra running after a reboot, and following Windscribe's changes? (recommended)";
    if !s.ui.confirm(q, true)? {
        return Ok(());
    }
    for (path, unit) in units {
        s.sys.write(path, unit)?;
    }
    s.sys.run("systemctl", &["daemon-reload"], None)?;
    s.sys.run("systemctl", &["enable", "hydra.service"], None)?;
    s.sys.run(
        "systemctl",
        &["enable", "--now", "hydra-refresh.timer"],
        None,
    )?;
    s.ui.say(&ok(
        "hydra forwards its entries after a reboot and follows their datacenters every minute.",
    ));
    Ok(())
}

fn boot(s: &mut Setup) -> Result<(), String> {
    if !s.sys.path("/run/systemd/system").is_dir() {
        s.ui.say(&warn(
            "This server doesn't run systemd. Run `hydra apply` at boot and \
             `hydra apply --refresh` every minute to keep the entries forwarding.",
        ));
        return Ok(());
    }
    let units = units();
    if units_ready(s, &units) {
        s.ui.say(&ok(
            "Already set up: systemd forwards the entries at boot and follows their datacenters every minute.",
        ));
        return Ok(());
    }
    install_units(s, &units)
}

/// After mapping, until the units are set up: without them the entries stop
/// at the next reboot, and nothing follows Windscribe's changes to their
/// locations.
fn offer_boot(s: &mut Setup) -> Result<(), String> {
    let units = units();
    if !s.sys.path("/run/systemd/system").is_dir() || units_ready(s, &units) {
        return Ok(());
    }
    s.ui.say(&para(
        "Without hydra's systemd units, the entries stop forwarding at the next reboot, and \
         nothing follows Windscribe's changes to their locations as servers join and leave.",
        0,
    ));
    install_units(s, &units)
}

#[cfg(test)]
pub mod script {
    //! A [`Ui`] that answers from a list, for tests.

    use super::Ui;
    use std::collections::VecDeque;

    #[derive(Debug, Clone)]
    pub enum Answer {
        /// Picks this item from a menu.
        Pick(usize),
        /// Backs out of a menu (Esc).
        Esc,
        Text(String),
        /// Accepts the default.
        Enter,
        Yes,
        No,
    }

    #[derive(Default)]
    pub struct Script {
        pub answers: VecDeque<Answer>,
        /// What the user saw: `say` lines, and `? prompt` for each question.
        pub log: Vec<String>,
    }

    impl Script {
        pub fn new(answers: Vec<Answer>) -> Self {
            Script {
                answers: answers.into(),
                log: vec![],
            }
        }

        fn next(&mut self, prompt: &str) -> Result<Answer, String> {
            self.answers.pop_front().ok_or_else(|| {
                format!(
                    "no answer left for {prompt:?}; log:\n{}",
                    self.log.join("\n")
                )
            })
        }

        pub fn saw(&self, text: &str) -> bool {
            self.log.iter().any(|l| l.contains(text))
        }
    }

    impl Ui for Script {
        fn say(&mut self, text: &str) {
            self.log.push(text.to_string());
        }

        fn select(
            &mut self,
            prompt: &str,
            items: &[String],
            default: usize,
        ) -> Result<Option<usize>, String> {
            self.log.push(format!("? {prompt} [{}]", items.join(" | ")));
            match self.next(prompt)? {
                Answer::Pick(i) if i < items.len() => Ok(Some(i)),
                Answer::Enter => Ok(Some(default)),
                Answer::Esc => Ok(None),
                a => Err(format!("{prompt:?}: can't answer a menu with {a:?}")),
            }
        }

        fn input(
            &mut self,
            prompt: &str,
            default: &str,
            check: &dyn Fn(&str) -> Result<(), String>,
        ) -> Result<String, String> {
            loop {
                self.log.push(format!("? {prompt} ({default})"));
                let v = match self.next(prompt)? {
                    Answer::Text(t) => t,
                    Answer::Enter => default.to_string(),
                    a => return Err(format!("{prompt:?}: can't answer with {a:?}")),
                };
                match check(&v) {
                    Ok(()) => return Ok(v),
                    Err(e) => self.log.push(format!("! {e}")),
                }
            }
        }

        fn confirm(&mut self, prompt: &str, default: bool) -> Result<bool, String> {
            self.log.push(format!("? {prompt}"));
            match self.next(prompt)? {
                Answer::Yes => Ok(true),
                Answer::No => Ok(false),
                Answer::Enter => Ok(default),
                a => Err(format!("{prompt:?}: can't confirm with {a:?}")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::script::{Answer, Answer::*, Script};
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    // Locations sort as Canada East (Montreal, Toronto), Germany (Frankfurt).
    const LIST: &str = r#"{"data":{"locations":{
      "1":{"name":"Canada East","country_code":"CA","pops":[
        {"status":1,"datacenter_id":1,"iata_code":"YYZ","name":"Toronto - The 6","usage":5},
        {"status":1,"datacenter_id":2,"iata_code":"YUL","name":"Montreal - Old Port","usage":4}]},
      "2":{"name":"Germany","country_code":"DE","pops":[
        {"status":1,"datacenter_id":3,"iata_code":"FRA","name":"Frankfurt - Main","usage":5}]}}}}"#;

    const ZONE: &str = "example.com";

    /// What the datacenters' WireGuard hostnames resolve to.
    const DNS: &[(&str, &[&str])] = &[
        ("yyz-1-wg.example.com", &["198.51.100.10", "198.51.100.11"]),
        ("yul-2-wg.example.com", &["198.51.100.30"]),
        ("fra-3-wg.example.com", &["198.51.100.20"]),
    ];

    type Calls = Rc<RefCell<Vec<String>>>;

    /// A host rooted in `dir` with `addrs` on eth0 (`ip` or `ip/prefix`),
    /// recording commands and the nftables scripts it is sent.
    fn host_sys(
        dir: &Path,
        addrs: &[&str],
        gateway: Option<&str>,
        calls: Calls,
        dns: &[(&str, &[&str])],
    ) -> Sys {
        let addr_info: Vec<String> = addrs
            .iter()
            .map(|a| match a.split_once('/') {
                Some((ip, prefix)) => format!(r#"{{"local":"{ip}","prefixlen":{prefix}}}"#),
                None => format!(r#"{{"local":"{a}"}}"#),
            })
            .collect();
        let addr_json = format!(
            r#"[{{"ifname":"lo","addr_info":[{{"local":"127.0.0.1"}}]}},{{"ifname":"eth0","addr_info":[{}]}}]"#,
            addr_info.join(",")
        );
        let gateway = gateway
            .map(|g| format!(r#","gateway":"{g}""#))
            .unwrap_or_default();
        let first = addrs[0].split('/').next().unwrap();
        let route_json = format!(r#"[{{"dev":"eth0","prefsrc":"{first}"{gateway}}}]"#);
        Sys::fixture(
            dir,
            Box::new(move |cmd, args, stdin| {
                let script = stdin.map(|s| format!("\n{s}")).unwrap_or_default();
                calls
                    .borrow_mut()
                    .push(format!("{cmd} {}{script}", args.join(" ")));
                match cmd {
                    "ip" if args.iter().any(|a| a == "route") => Ok(route_json.clone()),
                    "ip" => Ok(addr_json.clone()),
                    "nft" | "systemctl" | "conntrack" => Ok(String::new()),
                    _ => Err(format!("{cmd} not available in test")),
                }
            }),
        )
        .with_hosts(dns)
    }

    struct Lab {
        dir: PathBuf,
        state: String,
        calls: Calls,
        sys: Sys,
        /// What checking a range finds (probe.rs needs a network).
        probe: Result<Delivery, String>,
    }

    fn lab(name: &str, addrs: &[&str]) -> Lab {
        lab_net(name, addrs, None, DNS)
    }

    fn lab_dns(name: &str, addrs: &[&str], dns: &[(&str, &[&str])]) -> Lab {
        lab_net(name, addrs, None, dns)
    }

    fn lab_net(name: &str, addrs: &[&str], gateway: Option<&str>, dns: &[(&str, &[&str])]) -> Lab {
        let dir = std::env::temp_dir().join(format!("hydra-setup-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("proc/sys/net/ipv4")).unwrap();
        let calls = Calls::default();
        let sys = host_sys(&dir, addrs, gateway, calls.clone(), dns);
        Lab {
            state: dir.join("entries.json").display().to_string(),
            dir,
            calls,
            sys,
            probe: Err("no network in tests".into()),
        }
    }

    /// A server with a /28 it sits on (the gateway is in it) and a /24.
    fn ranged(name: &str, probe: Result<Delivery, String>) -> Lab {
        Lab {
            probe,
            ..lab_net(
                name,
                &["45.33.20.193/28", "45.33.30.0/24"],
                Some("45.33.20.206"),
                DNS,
            )
        }
    }

    fn called(l: &Lab, want: &str) -> bool {
        l.calls.borrow().iter().any(|c| c == want)
    }

    fn setup(l: &Lab, ui: &mut Script) -> Result<(), String> {
        setup_with(l, ui, false)
    }

    fn setup_with(l: &Lab, ui: &mut Script, emoji: bool) -> Result<(), String> {
        let mut s = Setup {
            sys: &l.sys,
            state: &l.state,
            ui,
            load_datacenters: Box::new(|| datacenters::parse(LIST, ZONE)),
            datacenters: None,
            dir: l.dir.clone(),
            emoji,
            check_range: Box::new(|ip| {
                l.calls.borrow_mut().push(format!("probe {ip}"));
                l.probe.clone()
            }),
        };
        run(&mut s)
    }

    fn last_nft(l: &Lab) -> String {
        l.calls
            .borrow()
            .iter()
            .rev()
            .find(|c| c.starts_with("nft -f -"))
            .cloned()
            .unwrap_or_default()
    }

    fn txt(t: &str) -> Answer {
        Text(t.into())
    }

    /// No server's hostname reaches the screen: setup names datacenters.
    fn assert_no_server_names(ui: &Script) {
        for host in ["ca-114", "ca-115", "ca-117", "ca-301", "de-201"] {
            assert!(!ui.saw(host), "{host} shown");
        }
    }

    /// Maps the lab's first address to Toronto, then leaves the mapping screen.
    fn map_first_to_toronto() -> Vec<Answer> {
        vec![
            Pick(0), // the first address
            Yes,     // not public: use it anyway
            Enter,   // port 443
            Enter,   // the first location: Canada East
            Pick(1), // Toronto, after Montreal (load 4%)
            Enter,   // profile in the working directory
            Enter,   // start forwarding
            Enter,   // the mapping screen's default: Done
        ]
    }

    #[test]
    fn first_run_maps_an_address_to_a_datacenter() {
        let l = lab("first", &["203.0.113.5"]);
        let mut ui = Script::new([map_first_to_toronto(), vec![Pick(5)]].concat());
        setup(&l, &mut ui).unwrap();

        let st = State::load(&l.state).unwrap();
        assert_eq!(st.endpoints(), "203.0.113.5:443");
        let e = &st.entries[0];
        assert_eq!(e.front().datacenter, "yyz-1-wg.example.com");
        assert_eq!(e.front().location, "Toronto · The 6");
        assert_eq!(e.servers.len(), 2);
        let p = Profile::load(l.dir.join("toronto.json").to_str().unwrap()).unwrap();
        assert_eq!(p, e.profile);
        let json = p.to_json().unwrap();
        assert!(
            !json.contains("198.51.100") && !json.contains("ca-11"),
            "{json}"
        );
        assert!(last_nft(&l).contains(
            "ip daddr 203.0.113.5 udp dport 443 counter dnat ip to jhash ip saddr . udp sport mod 2 map { 0 : 198.51.100.10 . 443, 1 : 198.51.100.11 . 443 }"
        ));
        assert_eq!(
            std::fs::read_to_string(l.dir.join("proc/sys/net/ipv4/ip_forward")).unwrap(),
            "1\n"
        );
        assert!(!ui.saw("servers"), "no server count on screen");
        assert!(ui.saw("it names one datacenter"));
        assert_no_server_names(&ui);
        std::fs::remove_dir_all(&l.dir).unwrap();
    }

    #[test]
    fn flags_show_where_the_terminal_draws_emoji() {
        let l = lab("flags", &["203.0.113.5"]);
        let mut ui = Script::new([map_first_to_toronto(), vec![Pick(5)]].concat());
        setup_with(&l, &mut ui, true).unwrap();

        assert!(ui.saw("🇨🇦 Canada East"));
        assert!(ui.saw("🇩🇪 Germany"));
        assert!(ui.saw("🔍 Search by name…"));
        assert!(ui.saw("🇨🇦 203.0.113.5:443"), "the entries list");
        assert_eq!(State::load(&l.state).unwrap().entries[0].country, "CA");
        std::fs::remove_dir_all(&l.dir).unwrap();
    }

    #[test]
    fn the_location_menu_lists_locations_then_datacenters() {
        let l = lab("browse", &["203.0.113.5"]);
        let mut ui = Script::new(vec![
            Pick(0),
            Yes,
            Enter,
            Pick(1), // Canada East: two datacenters
            Esc,     // back to the locations
            Pick(1),
            Enter, // Montreal, the least loaded
            Enter,
            Enter,
            Enter, // Done
            Pick(5),
        ]);
        setup(&l, &mut ui).unwrap();

        assert!(ui.saw("CA Canada East "));
        assert!(ui.saw("2 cities · lowest load 4%"));
        assert!(ui.saw("DE Germany "));
        assert!(ui.saw("Frankfurt · lowest load 5%"));
        assert!(ui.saw("? Which datacenter in Canada East? The least loaded is first. [Montreal"));
        assert!(ui.saw("Old Port"));
        let st = State::load(&l.state).unwrap();
        assert_eq!(st.entries[0].front().datacenter, "yul-2-wg.example.com");
        assert_no_server_names(&ui);
        std::fs::remove_dir_all(&l.dir).unwrap();
    }

    #[test]
    fn a_location_with_one_datacenter_needs_no_second_menu() {
        let l = lab("one-dc", &["203.0.113.5"]);
        let mut ui = Script::new(vec![
            Pick(0),
            Yes,
            Enter,
            Pick(2), // Germany: Frankfurt is its only datacenter
            Enter,
            Enter,
            Enter,
            Pick(5),
        ]);
        setup(&l, &mut ui).unwrap();

        assert!(!ui.saw("? Which datacenter in Germany"));
        let st = State::load(&l.state).unwrap();
        assert_eq!(st.entries[0].front().datacenter, "fra-3-wg.example.com");
        std::fs::remove_dir_all(&l.dir).unwrap();
    }

    #[test]
    fn search_finds_datacenters_and_goes_back_on_enter() {
        let l = lab("search", &["203.0.113.5"]);
        let mut ui = Script::new(vec![
            Pick(0),
            Yes,
            Enter,
            Pick(0), // search by name
            txt("atlantis"),
            txt(""), // back to the locations
            Pick(0),
            txt("old port"),
            Enter, // Montreal · Old Port
            Enter,
            Enter,
            Enter,
            Pick(5),
        ]);
        setup(&l, &mut ui).unwrap();

        assert!(ui.saw("No datacenter matches “atlantis”"));
        let st = State::load(&l.state).unwrap();
        assert_eq!(st.entries[0].front().datacenter, "yul-2-wg.example.com");
        std::fs::remove_dir_all(&l.dir).unwrap();
    }

    #[test]
    fn a_datacenter_that_does_not_resolve_is_not_added() {
        let l = lab_dns("no-dns", &["203.0.113.5"], &[]);
        let mut ui = Script::new(vec![
            Pick(0),
            Yes,
            Enter,
            Pick(2), // Germany
            Esc,     // back on the mapping screen: leave
        ]);
        setup(&l, &mut ui).unwrap();

        assert!(ui.saw("Couldn't look up Frankfurt · Main"));
        assert!(!Path::new(&l.state).exists());
        assert!(last_nft(&l).is_empty());
        std::fs::remove_dir_all(&l.dir).unwrap();
    }

    #[test]
    fn the_mapping_screen_maps_each_address_to_its_own_datacenter() {
        let l = lab("two", &["203.0.113.5", "203.0.113.6"]);
        let mut ui = Script::new(vec![
            Pick(0),
            Yes,
            Enter,
            Enter,
            Pick(1), // 203.0.113.5 -> Toronto
            Enter,
            Enter,
            Pick(1), // back on the mapping screen: 203.0.113.6
            Yes,
            Enter,
            Pick(2), // -> Frankfurt
            Enter,
            Enter,
            Enter, // Done
            Pick(5),
        ]);
        setup(&l, &mut ui).unwrap();

        assert!(ui.saw("203.0.113.5      eth0     not public · :443 → CA Toronto · The 6"));
        assert!(ui.saw("203.0.113.6      eth0     not public · free"));
        let nft = last_nft(&l);
        assert!(nft.contains("ip daddr 203.0.113.5 udp dport 443 counter dnat ip to jhash"));
        assert!(
            nft.contains("ip daddr 203.0.113.6 udp dport 443 counter dnat ip to 198.51.100.20:443")
        );
        for (file, dc) in [
            ("toronto.json", "yyz-1-wg.example.com"),
            ("frankfurt.json", "fra-3-wg.example.com"),
        ] {
            let p = Profile::load(l.dir.join(file).to_str().unwrap()).unwrap();
            assert_eq!(p.fronts.len(), 1, "{file}");
            assert_eq!(p.fronts[0].datacenter, dc);
        }
        assert_no_server_names(&ui);
        std::fs::remove_dir_all(&l.dir).unwrap();
    }

    #[test]
    fn a_free_public_address_is_offered_first_and_needs_no_confirmation() {
        let l = lab("public", &["10.0.0.5", "93.184.216.34"]);
        let mut ui = Script::new(vec![
            Enter, // the default: 93.184.216.34, the free public one
            Enter,
            Pick(2),
            Enter,
            Enter,
            Enter, // Done: no public address is free any more
            Pick(5),
        ]);
        setup(&l, &mut ui).unwrap();

        assert!(!ui.saw("isn't a public address"));
        assert_eq!(
            State::load(&l.state).unwrap().endpoints(),
            "93.184.216.34:443"
        );
        std::fs::remove_dir_all(&l.dir).unwrap();
    }

    #[test]
    fn behind_cloud_nat_the_entry_keeps_its_private_address() {
        let l = lab("nat", &["10.0.0.5", "10.0.0.6"]);
        let mut ui = Script::new(vec![
            Enter,             // the default: a public IP this server doesn't show
            txt("192.0.2.51"), // documentation range: not public
            Yes,               // use it anyway
            Pick(1),           // arrives on 10.0.0.6
            Enter,
            Pick(2),
            Enter,
            Enter,
            Enter, // Done
            Esc,   // quit from the menu
        ]);
        setup(&l, &mut ui).unwrap();

        assert!(ui.saw("1:1 NAT, as on most clouds"));
        assert!(
            ui.saw("10.0.0.6         eth0     not public · 192.0.2.51:443 → DE Frankfurt · Main")
        );
        assert!(ui.saw("arrives on    10.0.0.6"));
        let st = State::load(&l.state).unwrap();
        let e = &st.entries[0];
        assert_eq!(e.endpoint(), "192.0.2.51:443");
        assert_eq!(e.bind, Some("10.0.0.6".parse().unwrap()));
        assert!(last_nft(&l)
            .contains("ip daddr 10.0.0.6 udp dport 443 counter dnat ip to 198.51.100.20:443"));
        std::fs::remove_dir_all(&l.dir).unwrap();
    }

    #[test]
    fn a_taken_port_asks_before_replacing_and_offers_a_free_one() {
        let l = lab("port", &["203.0.113.5"]);
        let mut first = map_first_to_toronto();
        first.pop(); // stay on the mapping screen
        let mut ui = Script::new(
            [
                first,
                vec![
                    Pick(0),
                    Yes,
                    txt("443"),
                    No,    // taken: don't replace
                    Enter, // the free default, 8443
                    Pick(2),
                    Enter,
                    Enter,
                    Enter, // Done
                    Pick(5),
                ],
            ]
            .concat(),
        );
        setup(&l, &mut ui).unwrap();

        assert!(ui.saw("? Which UDP port? (8443)"));
        assert!(ui.saw("203.0.113.5:443 already leads to Toronto · The 6. Replace it?"));
        assert_eq!(
            State::load(&l.state).unwrap().endpoints(),
            "203.0.113.5:443, 203.0.113.5:8443"
        );
        std::fs::remove_dir_all(&l.dir).unwrap();
    }

    fn two_entries(l: &Lab) {
        let mut ui = Script::new(vec![
            Pick(0),
            Yes,
            Enter,
            Enter,
            Pick(1),
            Enter,
            Enter,
            Pick(1),
            Yes,
            Enter,
            Pick(2),
            Enter,
            Enter,
            Enter,
            Pick(5),
        ]);
        setup(l, &mut ui).unwrap();
        assert_eq!(
            State::load(&l.state).unwrap().endpoints(),
            "203.0.113.5:443, 203.0.113.6:443"
        );
    }

    #[test]
    fn the_menu_removes_one_entry_and_keeps_forwarding_the_other() {
        let l = lab("remove", &["203.0.113.5", "203.0.113.6"]);
        two_entries(&l);
        let mut ui = Script::new(vec![
            Pick(1), // remove
            Pick(0), // 203.0.113.5:443
            Yes,
            Pick(5),
        ]);
        setup(&l, &mut ui).unwrap();

        assert_eq!(
            State::load(&l.state).unwrap().endpoints(),
            "203.0.113.6:443"
        );
        let nft = last_nft(&l);
        assert!(nft.contains("ip daddr 203.0.113.6 udp dport 443 counter dnat"));
        assert!(!nft.contains("203.0.113.5"), "{nft}");
        assert!(l
            .calls
            .borrow()
            .iter()
            .any(|c| c == "conntrack -D -p udp --orig-dst 203.0.113.5 --orig-port-dst 443"));
        std::fs::remove_dir_all(&l.dir).unwrap();
    }

    #[test]
    fn share_writes_one_entrys_profile_again() {
        let l = lab("share", &["203.0.113.5", "203.0.113.6"]);
        two_entries(&l);
        let again = l.dir.join("again.json");
        let mut ui = Script::new(vec![
            Pick(2), // share
            Pick(2), // 203.0.113.6:443, after "All 2 entries"
            Text(again.display().to_string()),
            Pick(5),
        ]);
        setup(&l, &mut ui).unwrap();

        let p = Profile::load(again.to_str().unwrap()).unwrap();
        assert_eq!(p.fronts.len(), 1);
        assert_eq!(p.fronts[0].datacenter, "fra-3-wg.example.com");
        std::fs::remove_dir_all(&l.dir).unwrap();
    }

    #[test]
    fn share_writes_one_profile_for_every_entry() {
        let l = lab("share-all", &["203.0.113.5", "203.0.113.6"]);
        two_entries(&l);
        let both = l.dir.join("both.json");
        let mut ui = Script::new(vec![
            Pick(2), // share
            Pick(0), // all entries, in one profile
            Text(both.display().to_string()),
            Pick(5),
        ]);
        setup(&l, &mut ui).unwrap();

        let p = Profile::load(both.to_str().unwrap()).unwrap();
        let exits: Vec<&str> = p.fronts.iter().map(|f| f.datacenter.as_str()).collect();
        assert_eq!(exits, vec!["yyz-1-wg.example.com", "fra-3-wg.example.com"]);
        assert!(!p.all, "Montreal isn't mapped");
        assert!(ui.saw("it maps 2 locations"));
        assert!(ui.saw("connect to a location it maps"));
        std::fs::remove_dir_all(&l.dir).unwrap();
    }

    #[test]
    fn maps_every_location_when_there_is_an_address_for_each() {
        let l = lab("map-all", &["45.33.10.1", "45.33.10.2", "45.33.10.3"]);
        let mut ui = Script::new(vec![
            Yes,     // map all 3 locations at once
            Enter,   // hydra.json
            Pick(5), // quit
        ]);
        setup(&l, &mut ui).unwrap();

        let st = State::load(&l.state).unwrap();
        assert_eq!(
            st.endpoints(),
            "45.33.10.1:443, 45.33.10.2:443, 45.33.10.3:443"
        );
        let p = Profile::load(l.dir.join("hydra.json").to_str().unwrap()).unwrap();
        assert!(p.all);
        let mut ids: Vec<u32> = p.fronts.iter().map(|f| f.datacenter_id).collect();
        ids.sort();
        assert_eq!(ids, vec![1, 2, 3]);
        let nft = last_nft(&l);
        for ip in ["45.33.10.1", "45.33.10.2", "45.33.10.3"] {
            assert!(
                nft.contains(&format!("ip daddr {ip} udp dport 443")),
                "{ip}"
            );
        }
        assert!(ui.saw("it maps every Windscribe location"));
        assert_no_server_names(&ui);
        std::fs::remove_dir_all(&l.dir).unwrap();
    }

    #[test]
    fn map_all_skips_a_location_without_an_address() {
        let dns: &[(&str, &[&str])] = &[
            ("yyz-1-wg.example.com", &["198.51.100.10"]),
            ("yul-2-wg.example.com", &["198.51.100.30"]),
        ];
        let l = lab_dns(
            "map-all-dns",
            &["45.33.10.1", "45.33.10.2", "45.33.10.3"],
            dns,
        );
        let mut ui = Script::new(vec![Yes, Enter, Pick(5)]);
        setup(&l, &mut ui).unwrap();

        assert_eq!(State::load(&l.state).unwrap().entries.len(), 2);
        let p = Profile::load(l.dir.join("hydra.json").to_str().unwrap()).unwrap();
        assert!(!p.all, "Frankfurt has no front");
        assert!(ui.saw("Skipped Frankfurt · Main"));
        std::fs::remove_dir_all(&l.dir).unwrap();
    }

    #[test]
    fn map_all_is_not_offered_without_an_address_for_each_location() {
        // Two public addresses, three locations: straight to the address picker.
        let l = lab("map-all-short", &["45.33.10.1", "45.33.10.2"]);
        let mut ui = Script::new(vec![Esc]);
        setup(&l, &mut ui).unwrap();
        assert!(!ui.saw("Map all"));
        assert!(State::load(&l.state).unwrap().entries.is_empty());
        std::fs::remove_dir_all(&l.dir).unwrap();
    }

    fn unit(l: &Lab, name: &str) -> Option<String> {
        std::fs::read_to_string(l.dir.join("etc/systemd/system").join(name)).ok()
    }

    #[test]
    fn after_mapping_setup_offers_to_keep_hydra_running() {
        let l = lab("boot", &["203.0.113.5"]);
        std::fs::create_dir_all(l.dir.join("run/systemd/system")).unwrap();
        let mut ui = Script::new(
            [
                map_first_to_toronto(),
                vec![
                    Enter, // keep hydra running: the recommended answer
                    Pick(5),
                ],
            ]
            .concat(),
        );
        setup(&l, &mut ui).unwrap();

        assert!(ui.saw("the entries stop forwarding at the next reboot"));
        assert!(ui.saw(
            "? Keep hydra running after a reboot, and following Windscribe's changes? (recommended)"
        ));
        assert!(unit(&l, "hydra.service").unwrap().contains(" apply\n"));
        assert!(unit(&l, "hydra-refresh.service")
            .unwrap()
            .contains(" apply --refresh\n"));
        assert!(unit(&l, "hydra-refresh.timer")
            .unwrap()
            .contains("OnUnitActiveSec=1min"));
        for want in [
            "systemctl daemon-reload",
            "systemctl enable hydra.service",
            "systemctl enable --now hydra-refresh.timer",
        ] {
            assert!(called(&l, want), "{want}");
        }
        std::fs::remove_dir_all(&l.dir).unwrap();
    }

    #[test]
    fn declining_the_offer_leaves_it_on_the_menu() {
        let l = lab("boot-later", &["203.0.113.5"]);
        std::fs::create_dir_all(l.dir.join("run/systemd/system")).unwrap();
        let mut ui = Script::new(
            [
                map_first_to_toronto(),
                vec![
                    No,      // not now
                    Pick(4), // keep running after a reboot
                    Enter,
                    Pick(5),
                ],
            ]
            .concat(),
        );
        setup(&l, &mut ui).unwrap();
        assert!(unit(&l, "hydra.service").is_some());
        assert_eq!(
            l.calls
                .borrow()
                .iter()
                .filter(|c| *c == "systemctl daemon-reload")
                .count(),
            1
        );
        std::fs::remove_dir_all(&l.dir).unwrap();
    }

    #[test]
    fn without_systemd_mapping_asks_nothing_more() {
        let l = lab("no-systemd", &["203.0.113.5"]);
        let mut ui = Script::new([map_first_to_toronto(), vec![Pick(5)]].concat());
        setup(&l, &mut ui).unwrap();
        assert!(!ui.saw("Keep hydra running after a reboot,"));
        assert!(unit(&l, "hydra.service").is_none());
        std::fs::remove_dir_all(&l.dir).unwrap();
    }

    fn st(l: &Lab) -> State {
        State::load(&l.state).unwrap()
    }

    fn asked(ui: &Script, prompt: &str) -> usize {
        ui.log
            .iter()
            .filter(|line| line.starts_with(&format!("? {prompt}")))
            .count()
    }

    #[test]
    fn the_welcome_card_shows_the_ranges() {
        let l = ranged("range-card", Ok(Delivery::Routed));
        let mut ui = Script::new(vec![No, Esc]);
        setup(&l, &mut ui).unwrap();
        assert!(ui.saw("ranges 45.33.20.192/28, 45.33.30.0/24"));
        std::fs::remove_dir_all(&l.dir).unwrap();
    }

    #[test]
    fn map_all_uses_a_routed_range_as_it_is() {
        let l = ranged("range-all", Ok(Delivery::Routed));
        let mut ui = Script::new(vec![
            Yes,     // map all 3 locations to addresses in the /24
            Yes,     // all of it is this server's
            Enter,   // hydra.json
            Pick(5), // quit
        ]);
        setup(&l, &mut ui).unwrap();

        assert!(ui.saw("? Map all 3 locations to addresses in 45.33.30.0/24?"));
        assert!(
            called(&l, "probe 45.33.30.1"),
            "checked with its first address"
        );
        assert!(ui.saw("45.33.30.0/24 is routed to this server"));
        let st = st(&l);
        assert_eq!(
            st.endpoints(),
            "45.33.30.1:443, 45.33.30.2:443, 45.33.30.3:443"
        );
        assert!(st.entries.iter().all(|e| e.claim.is_none()));
        assert_eq!(
            st.ranges,
            vec![RangeUse {
                cidr: "45.33.30.0/24".into(),
                iface: "eth0".into(),
                claim: false,
            }]
        );
        assert!(!l
            .calls
            .borrow()
            .iter()
            .any(|c| c.starts_with("ip -4 addr add")));
        assert!(last_nft(&l).contains("ip daddr 45.33.30.3 udp dport 443 counter dnat"));
        assert!(
            Profile::load(l.dir.join("hydra.json").to_str().unwrap())
                .unwrap()
                .all
        );
        std::fs::remove_dir_all(&l.dir).unwrap();
    }

    #[test]
    fn a_range_not_routed_here_holds_each_address_it_maps() {
        let l = ranged("range-held", Ok(Delivery::NotDelivered));
        let mut ui = Script::new(vec![
            No,      // not all at once
            Pick(3), // the /24: after the two addresses and the /28
            Yes,     // all of it is this server's
            Enter,   // hold each address: the default
            txt("45.33.31.7"),
            txt("45.33.30.7"),
            Enter,   // port 443
            Enter,   // Canada East
            Pick(1), // Toronto
            Enter,
            Enter,   // start forwarding
            Pick(3), // the /24 again: not asked about twice
            Enter,   // its first free address, 45.33.30.1
            Enter,
            Pick(2), // Germany: Frankfurt
            Enter,
            Enter,
            Pick(5), // Done
            Pick(1), // remove an entry
            Pick(0), // 45.33.30.7
            Yes,
            Pick(5),
        ]);
        setup(&l, &mut ui).unwrap();

        assert!(ui.saw("Traffic for 45.33.30.0/24 doesn't reach this server on its own"));
        assert!(ui.saw("! 45.33.31.7 isn't a usable address in 45.33.30.0/24"));
        assert_eq!(asked(&ui, "Is all of 45.33.30.0/24"), 1);
        assert_eq!(
            asked(&ui, "Map all"),
            1,
            "map-all is offered on the first screen only"
        );
        assert!(
            ui.saw("45.33.30.7/32 to eth0"),
            "the new entry's card says so"
        );
        assert!(called(&l, "ip -4 addr add 45.33.30.7/32 dev eth0"));
        assert!(called(&l, "ip -4 addr add 45.33.30.1/32 dev eth0"));
        assert!(
            called(&l, "ip -4 addr del 45.33.30.7/32 dev eth0"),
            "removed with its entry"
        );
        assert!(!called(&l, "ip -4 addr del 45.33.30.1/32 dev eth0"));
        let st = st(&l);
        assert_eq!(st.endpoints(), "45.33.30.1:443");
        assert_eq!(st.entries[0].claim.as_deref(), Some("eth0"));
        assert!(st.ranges[0].claim);
        std::fs::remove_dir_all(&l.dir).unwrap();
    }

    #[test]
    fn the_servers_own_network_holds_addresses_without_a_check() {
        let l = ranged("range-lan", Ok(Delivery::Routed));
        let mut ui = Script::new(vec![
            No,      // not all at once
            Pick(2), // the /28
            Enter,   // not all of it is this server's: back to the list
            Pick(2),
            Yes,
            Enter, // hold each address
            Enter, // 45.33.20.194: .193 is the server's, .192 the network
            Enter,
            Pick(2), // Germany
            Enter,
            Enter,
            Pick(5), // Done
            Pick(5),
        ]);
        setup(&l, &mut ui).unwrap();

        assert!(ui.saw("45.33.20.192/28 holds this server's gateway"));
        assert_eq!(asked(&ui, "Is all of 45.33.20.192/28"), 2);
        assert!(
            !l.calls.borrow().iter().any(|c| c.starts_with("probe")),
            "the provider's router asks for each address on its own network"
        );
        assert!(called(&l, "ip -4 addr add 45.33.20.194/32 dev eth0"));
        assert_eq!(st(&l).endpoints(), "45.33.20.194:443");
        std::fs::remove_dir_all(&l.dir).unwrap();
    }

    #[test]
    fn a_range_that_cant_be_checked_offers_both_ways() {
        let l = ranged("range-unknown", Err("timed out".into()));
        let mut ui = Script::new(vec![
            No,
            Pick(3), // the /24
            Yes,
            Pick(1), // the provider routes it here
            Enter,   // 45.33.30.1
            Enter,
            Pick(2),
            Enter,
            Enter,
            Pick(5),
            Pick(5),
        ]);
        setup(&l, &mut ui).unwrap();

        assert!(ui.saw("Couldn't check how 45.33.30.0/24 reaches this server: timed out"));
        assert!(ui.saw("? How does 45.33.30.0/24 reach this server?"));
        let st = st(&l);
        assert_eq!(st.endpoints(), "45.33.30.1:443");
        assert_eq!(st.entries[0].claim, None);
        assert!(!st.ranges[0].claim);
        assert!(!l
            .calls
            .borrow()
            .iter()
            .any(|c| c.starts_with("ip -4 addr add")));
        std::fs::remove_dir_all(&l.dir).unwrap();
    }

    #[test]
    fn backing_out_of_the_first_question_changes_nothing() {
        let l = lab("esc", &["203.0.113.5"]);
        let mut ui = Script::new(vec![Esc]);
        setup(&l, &mut ui).unwrap();
        assert!(!Path::new(&l.state).exists());
        assert!(last_nft(&l).is_empty());
        std::fs::remove_dir_all(&l.dir).unwrap();
    }

    #[test]
    fn slugs() {
        assert_eq!(slug("New York"), "new-york");
        assert_eq!(slug("São Paulo"), "são-paulo");
        assert_eq!(slug(""), "hydra");
    }
}
