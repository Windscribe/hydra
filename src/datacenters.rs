//! Windscribe's datacenters, from its public status endpoint (WebsiteStatus).
//!
//! hydra fronts a datacenter, not a server, and finds where to forward by
//! resolving the datacenter's WireGuard hostname. The endpoint names each
//! datacenter by its IATA code and id, and the hostname is built from them:
//! `<iata>-<id>-wg.<zone>`, the one the datacenter's custom configs use.

use serde::Deserialize;

pub const DEFAULT_URL: &str = "https://api.windscribe.com/WebsiteStatus";

/// The DNS zone the WireGuard hostnames are in.
pub const DEFAULT_ZONE: &str = "whiskergalaxy.com";

/// A Windscribe datacenter as the apps list it: a city in a location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datacenter {
    /// Its id, which the apps match a hydra front on.
    pub id: u32,
    pub location: String,
    /// The location's ISO country code, such as `CA`.
    pub country: String,
    pub city: String,
    pub nick: String,
    /// The WireGuard hostname its custom configs use, which hydra resolves.
    pub hostname: String,
    /// Outbound traffic as a percentage of capacity, so lower is better.
    pub load: i64,
    /// Whether it has servers the apps can use right now.
    pub usable: bool,
}

impl Datacenter {
    /// "Toronto · The 6"
    pub fn label(&self) -> String {
        if self.nick.is_empty() {
            self.city.clone()
        } else {
            format!("{} · {}", self.city, self.nick)
        }
    }
}

#[derive(Deserialize)]
struct Doc {
    data: Data,
}
#[derive(Deserialize)]
struct Data {
    /// Keyed by location id: an object, or a list if the ids ever run from 0.
    #[serde(default)]
    locations: serde_json::Value,
}
#[derive(Deserialize)]
struct Loc {
    #[serde(default)]
    name: String,
    #[serde(default)]
    country_code: String,
    #[serde(default)]
    pops: Vec<Pop>,
}
#[derive(Deserialize)]
struct Pop {
    /// 1 when it has servers in service, 2 when it has none for now.
    #[serde(default)]
    status: i64,
    #[serde(default)]
    datacenter_id: Option<u32>,
    #[serde(default)]
    iata_code: Option<String>,
    /// "City - Nickname"
    #[serde(default)]
    name: String,
    #[serde(default)]
    usage: f64,
}

pub fn fetch(url: &str) -> Result<String, String> {
    // The API wants an Authorization header on every request; this endpoint
    // is public and doesn't check its value.
    let mut resp = ureq::get(url)
        .header("Authorization", "Bearer hydra")
        .call()
        .map_err(|e| format!("Windscribe's locations: {e}"))?;
    resp.body_mut()
        .with_config()
        .limit(16 * 1024 * 1024)
        .read_to_string()
        .map_err(|e| format!("Windscribe's locations: {e}"))
}

/// The datacenters in a WebsiteStatus response, with their WireGuard
/// hostnames in `zone`, sorted by location, then city.
pub fn parse(raw: &str, zone: &str) -> Result<Vec<Datacenter>, String> {
    let doc: Doc = serde_json::from_str(raw).map_err(|e| format!("Windscribe's locations: {e}"))?;
    let locs: Vec<serde_json::Value> = match doc.data.locations {
        serde_json::Value::Object(m) => m.into_iter().map(|(_, v)| v).collect(),
        serde_json::Value::Array(a) => a,
        _ => vec![],
    };
    let mut out = Vec::new();
    for v in locs {
        let Ok(loc) = serde_json::from_value::<Loc>(v) else {
            continue;
        };
        for p in loc.pops {
            // A datacenter without an id or IATA code (an older API, or its
            // cache) can't be named.
            let (Some(id), Some(iata)) = (p.datacenter_id, p.iata_code) else {
                continue;
            };
            let iata = iata.trim().to_ascii_lowercase();
            if id == 0
                || id > i32::MAX as u32
                || iata.is_empty()
                || !iata.bytes().all(|b| b.is_ascii_alphanumeric())
                || p.status == 0
            {
                continue;
            }
            let (city, nick) = match p.name.split_once(" - ") {
                Some((c, n)) => (c.trim().to_string(), n.trim().to_string()),
                None => (p.name.trim().to_string(), String::new()),
            };
            out.push(Datacenter {
                id,
                location: loc.name.clone(),
                country: loc.country_code.clone(),
                city,
                nick,
                hostname: format!("{iata}-{id}-wg.{zone}"),
                load: p.usage.round() as i64,
                usable: p.status == 1,
            });
        }
    }
    out.sort_by_key(|d| {
        (
            d.location.to_lowercase(),
            d.city.to_lowercase(),
            d.nick.to_lowercase(),
            d.id,
        )
    });
    Ok(out)
}

/// Datacenters whose city, name, location, country code or hostname contains
/// `query`, ignoring case.
pub fn filter(dcs: Vec<Datacenter>, query: &str) -> Vec<Datacenter> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return dcs;
    }
    dcs.into_iter()
        .filter(|d| {
            [&d.city, &d.nick, &d.location, &d.country, &d.hostname]
                .iter()
                .any(|f| f.to_lowercase().contains(&q))
        })
        .collect()
}

/// The least-loaded datacenter the apps can use, or the least loaded of all
/// when none can be used right now.
pub fn pick_least_loaded(dcs: &[Datacenter]) -> Option<&Datacenter> {
    dcs.iter()
        .filter(|d| d.usable)
        .min_by_key(|d| d.load)
        .or_else(|| dcs.iter().min_by_key(|d| d.load))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{"data":{"totals":{"users":1},"locations":{
      "7":{"name":"Canada East","country_code":"CA","premium_only":0,"pops":[
        {"status":1,"datacenter_id":1,"iata_code":"YYZ","name":"Toronto - The 6","usage":4.6},
        {"status":2,"datacenter_id":2,"iata_code":"yyz","name":"Toronto - Comfort Zone","usage":2},
        {"status":1,"name":"Montreal - Old Port","usage":1},
        {"status":1,"datacenter_id":4,"iata_code":"YUL","name":"Montreal","usage":0.4}]},
      "3":{"name":"Albania","country_code":"AL","pops":[
        {"status":1,"datacenter_id":9,"iata_code":"TIA","name":"Tirana - Skanderbeg","usage":30}]}}}}"#;

    #[test]
    fn names_each_datacenter_by_its_iata_code_and_id() {
        let dcs = parse(SAMPLE, "example.com").unwrap();
        let names: Vec<(&str, u32, &str)> = dcs
            .iter()
            .map(|d| (d.hostname.as_str(), d.id, d.location.as_str()))
            .collect();
        assert_eq!(
            names,
            vec![
                ("tia-9-wg.example.com", 9, "Albania"),
                ("yul-4-wg.example.com", 4, "Canada East"),
                ("yyz-2-wg.example.com", 2, "Canada East"),
                ("yyz-1-wg.example.com", 1, "Canada East"),
            ]
        );
    }

    #[test]
    fn splits_the_city_from_its_nickname() {
        let dcs = parse(SAMPLE, "example.com").unwrap();
        let toronto = dcs.iter().find(|d| d.id == 1).unwrap();
        assert_eq!(
            (toronto.city.as_str(), toronto.nick.as_str()),
            ("Toronto", "The 6")
        );
        assert_eq!(toronto.label(), "Toronto · The 6");
        assert_eq!(toronto.country, "CA");
        let montreal = dcs.iter().find(|d| d.id == 4).unwrap();
        assert_eq!(montreal.label(), "Montreal");
    }

    #[test]
    fn a_datacenter_without_servers_is_listed_but_not_usable() {
        let dcs = parse(SAMPLE, "example.com").unwrap();
        let comfort = dcs.iter().find(|d| d.id == 2).unwrap();
        assert!(!comfort.usable);
        assert_eq!(comfort.load, 2);
        let toronto = filter(dcs, "toronto");
        let picked = pick_least_loaded(&toronto).unwrap();
        assert_eq!(picked.id, 1, "the usable one, though it's busier");
    }

    #[test]
    fn skips_a_datacenter_it_cannot_name() {
        // The API's cache can hold a response from before it listed ids.
        let dcs = parse(SAMPLE, "example.com").unwrap();
        assert!(dcs.iter().all(|d| d.city != "Montreal" || d.id == 4));
        let raw = r#"{"data":{"locations":{"1":{"name":"X","country_code":"XX","pops":[
          {"status":1,"datacenter_id":5,"iata_code":"","name":"A"},
          {"status":1,"datacenter_id":0,"iata_code":"AAA","name":"B"},
          {"status":1,"datacenter_id":6,"iata_code":"a.b","name":"C"},
          {"status":0,"datacenter_id":7,"iata_code":"AAA","name":"D"}]}}}}"#;
        assert!(parse(raw, "example.com").unwrap().is_empty());
    }

    #[test]
    fn reads_locations_listed_as_an_array() {
        let raw = r#"{"data":{"locations":[{"name":"X","country_code":"XX","pops":[
          {"status":1,"datacenter_id":5,"iata_code":"AAA","name":"A - B","usage":1}]}]}}"#;
        assert_eq!(
            parse(raw, "dev.test").unwrap()[0].hostname,
            "aaa-5-wg.dev.test"
        );
    }

    #[test]
    fn filter_matches_city_name_country_and_hostname() {
        let dcs = parse(SAMPLE, "example.com").unwrap();
        assert_eq!(filter(dcs.clone(), "skanderbeg").len(), 1);
        assert_eq!(filter(dcs.clone(), "ca").len(), 3);
        assert_eq!(filter(dcs.clone(), "YUL-4").len(), 1);
        assert_eq!(filter(dcs, "").len(), 4);
    }

    #[test]
    fn refuses_a_response_that_is_not_one() {
        assert!(parse("<html>", "example.com").is_err());
        assert!(parse(r#"{"errorCode":500}"#, "example.com").is_err());
    }
}
