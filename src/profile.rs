//! Shareable Hydra entry document.
//!
//! A profile never contains WireGuard keys, PSKs, account data, or Amnezia
//! parameters. Those stay in the VPN app's ordinary session. It names a
//! datacenter, never one of its servers. The apps match a front on the
//! datacenter's id, which no DNS change moves; the hostname is what hydra
//! resolves and what people read.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

pub const KIND: &str = "windscribe.hydra.profile";
pub const VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub version: u32,
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hydra_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub created_at: String,
    /// Set when the fronts cover every Windscribe location there was when the
    /// profile was written, so the apps can say "All locations" instead of
    /// listing them. Written only when true.
    #[serde(default, skip_serializing_if = "is_false")]
    pub all: bool,
    pub fronts: Vec<Front>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// One Hydra UDP listener mapped to one Windscribe datacenter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Front {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub location: String,
    /// The datacenter's WireGuard hostname, the one its custom configs use.
    pub datacenter: String,
    /// The datacenter's id, the server list's group `id`.
    pub datacenter_id: u32,
    pub exit_port: u16,
    pub entry_ip: Ipv4Addr,
    pub entry_port: u16,
    #[serde(default = "default_protocol")]
    pub protocol: String,
}

fn default_protocol() -> String {
    "wireguard".to_string()
}

/// A DNS name: dot-separated labels of letters, digits and inner hyphens.
pub fn is_hostname(name: &str) -> bool {
    name.len() <= 253
        && name.contains('.')
        && name.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

impl Front {
    /// host:port the app should use as the WireGuard peer endpoint.
    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.entry_ip, self.entry_port)
    }

    fn validate(&self) -> Result<(), String> {
        if self.protocol != "wireguard" {
            return Err(format!("unsupported protocol {:?}", self.protocol));
        }
        if !is_hostname(&self.datacenter) {
            return Err(format!(
                "datacenter {:?} is not a hostname",
                self.datacenter
            ));
        }
        // The apps hold it in a signed 32-bit integer.
        if self.datacenter_id == 0 || self.datacenter_id > i32::MAX as u32 {
            return Err("datacenter_id must be 1-2147483647".into());
        }
        if self.entry_port == 0 || self.exit_port == 0 {
            return Err("ports must be 1-65535".into());
        }
        Ok(())
    }
}

impl Profile {
    pub fn new(hydra_id: impl Into<String>, fronts: Vec<Front>) -> Self {
        Profile {
            version: VERSION,
            kind: KIND.to_string(),
            hydra_id: hydra_id.into(),
            created_at: rfc3339_now(),
            all: false,
            fronts,
        }
    }

    /// One profile for several entries' fronts: the apps hold one at a time.
    /// `all` says they cover every Windscribe location.
    pub fn combined(hydra_id: impl Into<String>, fronts: Vec<Front>, all: bool) -> Self {
        Profile {
            all,
            ..Profile::new(hydra_id, fronts)
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.kind != KIND {
            return Err(format!("unsupported profile kind {:?}", self.kind));
        }
        if self.version != VERSION {
            return Err(format!("unsupported profile version {}", self.version));
        }
        if self.fronts.is_empty() {
            return Err("profile has no fronts".into());
        }
        let mut seen: HashMap<String, &str> = HashMap::new();
        for (i, f) in self.fronts.iter().enumerate() {
            f.validate().map_err(|e| format!("front[{i}]: {e}"))?;
            if let Some(other) = seen.insert(f.endpoint(), &f.datacenter) {
                return Err(format!(
                    "front[{i}]: entry {} already maps to {other}",
                    f.endpoint()
                ));
            }
        }
        Ok(())
    }

    pub fn to_json(&self) -> Result<String, String> {
        self.validate()?;
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }

    pub fn from_json(raw: &str) -> Result<Self, String> {
        // A version 1 profile named one server; say so rather than fail on its
        // fields.
        let v: serde_json::Value =
            serde_json::from_str(raw).map_err(|e| format!("parse profile: {e}"))?;
        if v.get("version").and_then(|v| v.as_u64()) == Some(1) {
            return Err(
                "this is a version 1 profile, which named one server; run `hydra up` \
                 again to write one that names a datacenter"
                    .into(),
            );
        }
        let p: Profile = serde_json::from_value(v).map_err(|e| format!("parse profile: {e}"))?;
        p.validate()?;
        Ok(p)
    }

    pub fn load(path: &str) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        Self::from_json(&raw)
    }

    /// Reference for client matching: the id of the datacenter connected to.
    #[cfg(test)]
    pub fn match_datacenter(&self, id: u32) -> Option<&Front> {
        self.fronts.iter().find(|f| f.datacenter_id == id)
    }
}

fn rfc3339_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

// Howard Hinnant's days-to-civil algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn front(entry: &str, port: u16, dc: &str) -> Front {
        Front {
            location: "Toronto".into(),
            datacenter: dc.into(),
            datacenter_id: 12,
            exit_port: 443,
            entry_ip: entry.parse().unwrap(),
            entry_port: port,
            protocol: "wireguard".into(),
        }
    }

    #[test]
    fn round_trip_and_match() {
        let p = Profile::new("h", vec![front("203.0.113.5", 443, "yyz-12-wg.example")]);
        let json = p.to_json().unwrap();
        assert!(json.contains(r#""version": 2"#), "{json}");
        let back = Profile::from_json(&json).unwrap();
        assert_eq!(back, p);
        let f = back.match_datacenter(12).unwrap();
        assert_eq!(f.endpoint(), "203.0.113.5:443");
        assert!(back.match_datacenter(13).is_none());
    }

    #[test]
    fn rejects_duplicate_entry() {
        let p = Profile::new(
            "h",
            vec![
                front("203.0.113.5", 443, "a-1-wg.example"),
                front("203.0.113.5", 443, "b-2-wg.example"),
            ],
        );
        assert!(p.to_json().is_err());
    }

    #[test]
    fn rejects_unknown_fields_like_keys() {
        let raw = r#"{"version":2,"kind":"windscribe.hydra.profile","fronts":[{
            "datacenter":"a-1-wg.example","datacenter_id":1,"exit_port":443,
            "entry_ip":"203.0.113.5","entry_port":443,"PrivateKey":"x"}]}"#;
        assert!(Profile::from_json(raw).is_err());
    }

    #[test]
    fn rejects_a_server_ip_or_hostname() {
        for field in [
            r#""exit_ip":"198.51.100.10""#,
            r#""exit_hostname":"ca-114.example""#,
        ] {
            let raw = format!(
                r#"{{"version":2,"kind":"windscribe.hydra.profile","fronts":[{{
                "datacenter":"a-1-wg.example","datacenter_id":1,"exit_port":443,{field},
                "entry_ip":"203.0.113.5","entry_port":443}}]}}"#
            );
            assert!(Profile::from_json(&raw).is_err(), "{field}");
        }
    }

    #[test]
    fn needs_a_datacenter_id() {
        for id in [
            r#""#,
            r#""datacenter_id":0,"#,
            r#""datacenter_id":2147483648,"#,
        ] {
            let raw = format!(
                r#"{{"version":2,"kind":"windscribe.hydra.profile","fronts":[{{
                "datacenter":"a-1-wg.example",{id}"exit_port":443,
                "entry_ip":"203.0.113.5","entry_port":443}}]}}"#
            );
            assert!(Profile::from_json(&raw).is_err(), "{id}");
        }
        let mut f = front("203.0.113.5", 443, "a-1-wg.example");
        f.datacenter_id = 2_147_483_647;
        assert!(Profile::new("h", vec![f]).to_json().is_ok());
    }

    #[test]
    fn rejects_ipv6() {
        let raw = r#"{"version":2,"kind":"windscribe.hydra.profile","fronts":[{
            "datacenter":"a-1-wg.example","datacenter_id":1,"exit_port":443,
            "entry_ip":"2001:db8::1","entry_port":443}]}"#;
        assert!(Profile::from_json(raw).is_err());
    }

    #[test]
    fn a_version_1_profile_says_to_run_up_again() {
        let raw = r#"{"version":1,"kind":"windscribe.hydra.profile","fronts":[{
            "exit_hostname":"a.example","exit_ip":"198.51.100.10","exit_port":443,
            "entry_ip":"203.0.113.5","entry_port":443}]}"#;
        let e = Profile::from_json(raw).unwrap_err();
        assert!(e.contains("version 1") && e.contains("hydra up"), "{e}");
    }

    #[test]
    fn datacenter_must_be_a_hostname() {
        assert!(is_hostname("yyz-12-wg.windscribe.com"));
        for bad in [
            "",
            "localhost",
            "a..b",
            "-a.example",
            "a b.example",
            "a_b.example",
        ] {
            assert!(!is_hostname(bad), "{bad:?}");
        }
    }

    #[test]
    fn civil_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_754), (2026, 10, 28));
    }

    #[test]
    fn all_is_written_only_when_set() {
        let one = Profile::new(
            "lab",
            vec![front("203.0.113.5", 443, "yyz-12-wg.example.com")],
        );
        assert!(!one.to_json().unwrap().contains("\"all\""));
        let every = Profile::combined(
            "lab",
            vec![
                front("203.0.113.5", 443, "yyz-12-wg.example.com"),
                front("203.0.113.6", 443, "yyz-13-wg.example.com"),
            ],
            true,
        );
        let json = every.to_json().unwrap();
        assert!(json.contains("\"all\": true"), "{json}");
        assert_eq!(Profile::from_json(&json).unwrap(), every);
    }

    #[test]
    fn all_must_be_a_boolean() {
        let with = |all: &str| {
            format!(
                r#"{{"version":2,"kind":"windscribe.hydra.profile","all":{all},"fronts":[{{
                  "datacenter":"yyz-12-wg.example.com","datacenter_id":12,"exit_port":443,
                  "entry_ip":"203.0.113.5","entry_port":443}}]}}"#
            )
        };
        assert!(Profile::from_json(&with("true")).unwrap().all);
        assert!(!Profile::from_json(&with("false")).unwrap().all);
        assert!(Profile::from_json(&with(r#""yes""#)).is_err());
        assert!(Profile::from_json(&with("1")).is_err());
    }
}
