//! Filesystem and command access, rooted so tests can use fixture trees.

use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, ToSocketAddrs as _};
use std::path::PathBuf;
use std::process::{Command, Stdio};

type Runner = Box<dyn Fn(&str, &[String], Option<&str>) -> Result<String, String>>;
type Resolver = Box<dyn Fn(&str) -> Result<Vec<Ipv4Addr>, String>>;
type Fetcher = Box<dyn Fn(&str) -> Result<String, String>>;
type Connector = Box<dyn Fn(Option<Ipv4Addr>, SocketAddrV4) -> Result<(), String>>;

pub struct Sys {
    root: PathBuf,
    runner: Runner,
    resolver: Resolver,
    fetcher: Fetcher,
    connector: Connector,
}

impl Sys {
    pub fn real() -> Self {
        Sys {
            root: PathBuf::from("/"),
            runner: Box::new(run_command),
            resolver: Box::new(resolve_system),
            fetcher: Box::new(crate::datacenters::fetch),
            connector: Box::new(crate::probe::connect),
        }
    }

    #[cfg(test)]
    pub fn fixture(root: impl Into<PathBuf>, runner: Runner) -> Self {
        Sys {
            root: root.into(),
            runner,
            resolver: Box::new(|host| Err(format!("{host}: no DNS in tests"))),
            fetcher: Box::new(|url| Err(format!("{url}: no network in tests"))),
            connector: Box::new(|_, to| Err(format!("{to}: no network in tests"))),
        }
    }

    /// Answers `resolve` from `hosts` instead of DNS.
    #[cfg(test)]
    pub fn with_hosts(mut self, hosts: &[(&str, &[&str])]) -> Self {
        let table: Vec<(String, Vec<Ipv4Addr>)> = hosts
            .iter()
            .map(|(h, ips)| {
                (
                    h.to_string(),
                    ips.iter().map(|i| i.parse().unwrap()).collect(),
                )
            })
            .collect();
        self.resolver = Box::new(move |host| {
            table
                .iter()
                .find(|(h, _)| h == host)
                .map(|(_, ips)| ips.clone())
                .ok_or_else(|| format!("{host}: not found"))
        });
        self
    }

    /// Answers `resolve` with `resolver` instead of DNS.
    #[cfg(test)]
    pub fn with_resolver(
        mut self,
        resolver: impl Fn(&str) -> Result<Vec<Ipv4Addr>, String> + 'static,
    ) -> Self {
        self.resolver = Box::new(resolver);
        self
    }

    /// Answers `fetch` with `fetcher` instead of the network.
    #[cfg(test)]
    pub fn with_fetcher(
        mut self,
        fetcher: impl Fn(&str) -> Result<String, String> + 'static,
    ) -> Self {
        self.fetcher = Box::new(fetcher);
        self
    }

    /// Answers `connect` with `connector` instead of the network.
    #[cfg(test)]
    pub fn with_connector(
        mut self,
        connector: impl Fn(Option<Ipv4Addr>, SocketAddrV4) -> Result<(), String> + 'static,
    ) -> Self {
        self.connector = Box::new(connector);
        self
    }

    /// The body at `url`: Windscribe's locations.
    pub fn fetch(&self, url: &str) -> Result<String, String> {
        (self.fetcher)(url)
    }

    /// Opens a TCP connection to `to`; from `from`, an address this host
    /// doesn't hold, it only sends the first packet (see probe.rs).
    pub fn connect(&self, from: Option<Ipv4Addr>, to: SocketAddrV4) -> Result<(), String> {
        (self.connector)(from, to)
    }

    /// The IPv4 addresses `host` resolves to, sorted, without duplicates.
    pub fn resolve(&self, host: &str) -> Result<Vec<Ipv4Addr>, String> {
        let mut ips = (self.resolver)(host)?;
        ips.sort();
        ips.dedup();
        Ok(ips)
    }

    pub fn path(&self, p: &str) -> PathBuf {
        self.root.join(p.trim_start_matches('/'))
    }

    pub fn read(&self, p: &str) -> Option<String> {
        std::fs::read_to_string(self.path(p))
            .ok()
            .map(|s| s.trim().to_string())
    }

    pub fn write(&self, p: &str, value: &str) -> Result<(), String> {
        let path = self.path(p);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        std::fs::write(&path, value).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn list(&self, p: &str) -> Vec<String> {
        let mut out: Vec<String> = std::fs::read_dir(self.path(p))
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        out.sort();
        out
    }

    pub fn link_name(&self, p: &str) -> Option<String> {
        std::fs::read_link(self.path(p))
            .ok()
            .and_then(|t| t.file_name().map(|n| n.to_string_lossy().into_owned()))
    }

    pub fn sysctl_path(name: &str) -> String {
        format!("/proc/sys/{}", name.replace('.', "/"))
    }

    pub fn sysctl(&self, name: &str) -> Option<String> {
        self.read(&Self::sysctl_path(name))
    }

    pub fn set_sysctl(&self, name: &str, value: &str) -> Result<(), String> {
        std::fs::write(self.path(&Self::sysctl_path(name)), format!("{value}\n"))
            .map_err(|e| format!("{name}: {e}"))
    }

    pub fn run(&self, cmd: &str, args: &[&str], stdin: Option<&str>) -> Result<String, String> {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        (self.runner)(cmd, &args, stdin)
    }
}

fn run_command(cmd: &str, args: &[String], stdin: Option<&str>) -> Result<String, String> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{cmd}: {e}"))?;
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .ok_or_else(|| format!("{cmd}: stdin unavailable"))?
            .write_all(input.as_bytes())
            .map_err(|e| format!("{cmd}: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("{cmd}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{cmd} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Every IPv4 address the system resolver returns (DNS, /etc/hosts).
fn resolve_system(host: &str) -> Result<Vec<Ipv4Addr>, String> {
    Ok((host, 443)
        .to_socket_addrs()
        .map_err(|e| format!("{host}: {e}"))?
        .filter_map(|a| match a.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
        .collect())
}
