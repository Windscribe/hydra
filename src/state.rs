//! The entries this host forwards.
//!
//! Each entry is the one-front profile `hydra up` wrote, plus the local
//! address its traffic arrives on when that is not the entry IP (1:1 NAT).
//! Keeping them lets `hydra up` add an entry without dropping the others, and
//! `hydra apply` restore them all after a reboot. Like profiles, the file
//! holds addresses only.

use crate::profile::{Front, Profile};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Write as _;
use std::net::Ipv4Addr;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

pub const DEFAULT_PATH: &str = "/etc/hydra/entries.json";
const VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// The profile shared for this entry: exactly one front.
    pub profile: Profile,
    /// Local address the entry's traffic arrives on, if not its entry IP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind: Option<Ipv4Addr>,
    /// The exit's ISO country code, for showing its flag. Not in the profile:
    /// the apps refuse fields they don't know.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub country: String,
    /// The datacenter's servers when the table was last loaded: what its
    /// hostname resolved to. Kept when DNS fails, and compared on refresh.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<Ipv4Addr>,
    /// The interface hydra holds the entry's address on (as a /32) while it
    /// forwards: for an address of a range the provider doesn't route to this
    /// server, which the server has to answer for itself. None for addresses
    /// the server already holds, or a range routed here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
}

impl Entry {
    pub fn new(profile: Profile, bind: Option<Ipv4Addr>) -> Self {
        let bind = bind.filter(|b| *b != profile.fronts[0].entry_ip);
        Entry {
            profile,
            bind,
            country: String::new(),
            servers: vec![],
            claim: None,
        }
    }

    pub fn with_claim(mut self, iface: Option<String>) -> Self {
        self.claim = iface;
        self
    }

    pub fn with_servers(mut self, servers: Vec<Ipv4Addr>) -> Self {
        self.servers = servers;
        self
    }

    pub fn with_country(mut self, code: &str) -> Self {
        self.country = code.to_string();
        self
    }

    pub fn front(&self) -> &Front {
        &self.profile.fronts[0]
    }

    /// The public `IP:port` clients dial.
    pub fn endpoint(&self) -> String {
        self.front().endpoint()
    }

    /// Address the DNAT rule matches.
    pub fn local(&self) -> Ipv4Addr {
        self.bind.unwrap_or(self.front().entry_ip)
    }

    fn local_endpoint(&self) -> String {
        format!("{}:{}", self.local(), self.front().entry_port)
    }

    fn validate(&self) -> Result<(), String> {
        self.profile.validate()?;
        if self.profile.fronts.len() != 1 {
            return Err(format!(
                "entry {} has {} fronts; each entry has one",
                self.endpoint(),
                self.profile.fronts.len()
            ));
        }
        Ok(())
    }
}

/// What setup learned about a range of this server's: asked once, kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RangeUse {
    /// "203.0.113.0/24"
    pub cidr: String,
    /// The interface its addresses arrive on.
    pub iface: String,
    /// Whether hydra holds each address it maps (the range isn't routed here).
    pub claim: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub version: u32,
    pub entries: Vec<Entry>,
    /// Ranges the user said are this server's, and how they reach it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ranges: Vec<RangeUse>,
}

impl Default for State {
    fn default() -> Self {
        State {
            version: VERSION,
            entries: vec![],
            ranges: vec![],
        }
    }
}

impl State {
    /// A missing file is a host with no entries yet.
    pub fn load(path: &str) -> Result<Self, String> {
        let raw = match std::fs::read_to_string(path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(State::default()),
            Err(e) => return Err(format!("{path}: {e}")),
        };
        // Entries saved by a hydra that fronted servers (profile version 1)
        // can't be read as datacenters: say how to clear them.
        let v: serde_json::Value =
            serde_json::from_str(&raw).map_err(|e| format!("{path}: {e}"))?;
        let old = v["entries"].as_array().is_some_and(|es| {
            es.iter()
                .any(|e| e["profile"]["version"].as_u64() == Some(1))
        });
        if old {
            return Err(format!(
                "{path} holds entries from an older hydra, which fronted single servers; \
                 `hydra down --forget` clears them, then add them again with `hydra up`"
            ));
        }
        let s: State = serde_json::from_value(v).map_err(|e| format!("{path}: {e}"))?;
        s.validate().map_err(|e| format!("{path}: {e}"))?;
        Ok(s)
    }

    /// Replaces the file in one rename, readable by its owner only.
    pub fn save(&self, path: &str) -> Result<(), String> {
        self.validate()?;
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        if let Some(dir) = Path::new(path)
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
        {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        let tmp = format!("{path}.tmp");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("{tmp}: {e}"))?;
        file.write_all(format!("{json}\n").as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|e| format!("{tmp}: {e}"))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("{path}: {e}"))
    }

    pub fn remove_file(path: &str) -> Result<(), String> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("{path}: {e}")),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != VERSION {
            return Err(format!("unsupported entries version {}", self.version));
        }
        let mut endpoints = HashSet::new();
        let mut locals = HashSet::new();
        for e in &self.entries {
            e.validate()?;
            if !endpoints.insert(e.endpoint()) {
                return Err(format!("entry {} is listed twice", e.endpoint()));
            }
            if !locals.insert(e.local_endpoint()) {
                return Err(format!(
                    "two entries receive traffic on {}",
                    e.local_endpoint()
                ));
            }
        }
        Ok(())
    }

    /// Adds `entry`, replacing any entry clients reach at the same `IP:port`
    /// or whose traffic arrives on the same local address and port. Returns
    /// the endpoints of the entries it replaced.
    pub fn upsert(&mut self, entry: Entry) -> Vec<String> {
        let (endpoint, local) = (entry.endpoint(), entry.local_endpoint());
        let mut replaced = vec![];
        self.entries.retain(|e| {
            let clash = e.endpoint() == endpoint || e.local_endpoint() == local;
            if clash {
                replaced.push(e.endpoint());
            }
            !clash
        });
        self.entries.push(entry);
        replaced
    }

    pub fn remove(&mut self, endpoint: &str) -> Option<Entry> {
        let i = self.entries.iter().position(|e| e.endpoint() == endpoint)?;
        Some(self.entries.remove(i))
    }

    pub fn find(&self, endpoint: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.endpoint() == endpoint)
    }

    pub fn endpoints(&self) -> String {
        let all: Vec<String> = self.entries.iter().map(Entry::endpoint).collect();
        all.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An entry to a one-server datacenter named after that server's address.
    fn entry(entry_ip: &str, port: u16, server: &str, bind: Option<&str>) -> Entry {
        Entry::new(
            Profile::new(
                "h",
                vec![Front {
                    location: "Toronto".into(),
                    datacenter: format!("dc-{}-wg.example", server.replace('.', "-")),
                    datacenter_id: 1,
                    exit_port: 443,
                    entry_ip: entry_ip.parse().unwrap(),
                    entry_port: port,
                    protocol: "wireguard".into(),
                }],
            ),
            bind.map(|b| b.parse().unwrap()),
        )
        .with_servers(vec![server.parse().unwrap()])
    }

    #[test]
    fn entries_on_two_ips_reach_two_exits() {
        let mut s = State::default();
        assert!(s
            .upsert(entry("203.0.113.5", 443, "198.51.100.10", None))
            .is_empty());
        assert!(s
            .upsert(entry("203.0.113.6", 443, "198.51.100.20", None))
            .is_empty());
        assert_eq!(s.entries.len(), 2);
        s.validate().unwrap();
        assert_eq!(
            s.find("203.0.113.6:443").unwrap().front().datacenter,
            "dc-198-51-100-20-wg.example"
        );
    }

    #[test]
    fn same_entry_replaces_its_exit() {
        let mut s = State::default();
        s.upsert(entry("203.0.113.5", 443, "198.51.100.10", None));
        let replaced = s.upsert(entry("203.0.113.5", 443, "198.51.100.20", None));
        assert_eq!(replaced, vec!["203.0.113.5:443"]);
        assert_eq!(s.entries.len(), 1);
        assert_eq!(s.entries[0].servers, vec![Ipv4Addr::new(198, 51, 100, 20)]);
    }

    #[test]
    fn same_local_address_and_port_replaces() {
        // Behind 1:1 NAT a new public IP mapped onto the same local address
        // would otherwise leave two rules matching one local IP:port.
        let mut s = State::default();
        s.upsert(entry("203.0.113.5", 443, "198.51.100.10", None));
        let replaced = s.upsert(entry(
            "192.0.2.50",
            443,
            "198.51.100.10",
            Some("203.0.113.5"),
        ));
        assert_eq!(replaced, vec!["203.0.113.5:443"]);
        assert_eq!(s.entries.len(), 1);
        assert_eq!(s.entries[0].local().to_string(), "203.0.113.5");
    }

    #[test]
    fn nat_entries_keep_their_own_local_address() {
        let mut s = State::default();
        s.upsert(entry("192.0.2.50", 443, "198.51.100.10", Some("10.0.0.5")));
        s.upsert(entry("192.0.2.51", 443, "198.51.100.20", Some("10.0.0.6")));
        let locals: Vec<String> = s.entries.iter().map(|e| e.local().to_string()).collect();
        assert_eq!(locals, vec!["10.0.0.5", "10.0.0.6"]);
    }

    #[test]
    fn remove_one_keeps_the_others() {
        let mut s = State::default();
        s.upsert(entry("203.0.113.5", 443, "198.51.100.10", None));
        s.upsert(entry("203.0.113.5", 8443, "198.51.100.20", None));
        assert!(s.remove("203.0.113.5:443").is_some());
        assert!(s.remove("203.0.113.5:443").is_none());
        assert_eq!(s.endpoints(), "203.0.113.5:8443");
    }

    #[test]
    fn rejects_an_entry_with_several_fronts() {
        let mut e = entry("203.0.113.5", 443, "198.51.100.10", None);
        let mut second = e.front().clone();
        second.entry_port = 8443;
        e.profile.fronts.push(second);
        let s = State {
            entries: vec![e],
            ..State::default()
        };
        assert!(s.validate().unwrap_err().contains("has 2 fronts"));
    }

    #[test]
    fn entries_from_an_older_hydra_say_how_to_clear_them() {
        let dir = std::env::temp_dir().join(format!("hydra-state-v1-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("entries.json");
        std::fs::write(
            &path,
            r#"{"version":1,"entries":[{"profile":{"version":1,"kind":"windscribe.hydra.profile",
            "fronts":[{"exit_hostname":"ca-114.example","exit_ip":"198.51.100.10","exit_port":443,
            "entry_ip":"203.0.113.5","entry_port":443}]}}]}"#,
        )
        .unwrap();
        let e = State::load(path.to_str().unwrap()).unwrap_err();
        assert!(
            e.contains("older hydra") && e.contains("hydra down --forget"),
            "{e}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = std::env::temp_dir().join(format!("hydra-state-{}", std::process::id()));
        let path = dir.join("sub").join("entries.json");
        let path_s = path.to_str().unwrap();
        assert_eq!(State::load(path_s).unwrap(), State::default());
        let mut s = State::default();
        s.upsert(entry("192.0.2.50", 443, "198.51.100.10", Some("10.0.0.5")));
        s.save(path_s).unwrap();
        assert_eq!(State::load(path_s).unwrap(), s);
        let mode = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&mode) & 0o777,
            0o600
        );
        State::remove_file(path_s).unwrap();
        State::remove_file(path_s).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
