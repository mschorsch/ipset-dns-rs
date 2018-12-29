use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::result::Result as StdResult;
use std::str::FromStr;

use clap::{App, Arg};

use crate::errors::Result;
use crate::ipset::types::IPSET_MAXNAMELEN;

//
// CLI
//

pub fn build_cli() -> App<'static, 'static> {
    App::new("ipset-dns-rs")
        .version("0.1.0")
        .author("Matthias S. <matthias.schorsch@gmx.de>")
        .about("Lightweight DNS forwarding server that adds all resolved IPs to a given netfilter ipset")
        .arg(Arg::with_name("daemon")
            .short("d")
            .long("daemon")
            .required(false)
            .help("Enable deamon mode"))
        .arg(Arg::with_name("reuse")
            .short("r")
            .long("reuse")
            .required(false)
            .help("Enable port reuse"))
        .arg(Arg::with_name("dns")
            .long("dns")
            .value_name("IP")
            .takes_value(true)
            .required(false)
            .validator(is_dns_ip_valid)
            .help("Sets a custom (upstream) DNS server [default: 8.8.8.8]"))
        .arg(Arg::with_name("port")
            .short("p")
            .long("port")
            .takes_value(true)
            .required(false)
            .validator(is_port_valid)
            .help("Sets a listen port [default: 1919]"))
        .arg(Arg::with_name("CONFIG_FILE")
            .required(true)
            .validator(is_file_valid)
            .index(1)
            .default_value("ipset_dns_config.toml")
            .help("Sets a netfilter ipset-dns config file"))
}

fn is_port_valid(v: String) -> StdResult<(), String> {
    u16::from_str(&v)
        .map_err(|_| "Invalid port number".to_owned())
        .and(Ok(()))
}

fn is_file_valid(v: String) -> StdResult<(), String> {
    if Path::new(&v).is_file() {
        Ok(())
    } else {
        Err(format!("'{}' is not a file", v))
    }
}

fn is_dns_ip_valid(v: String) -> StdResult<(), String> {
    Ipv4Addr::from_str(&v)
        .map_err(|_| "Invalid ipv4 adress".to_owned())
        .and(Ok(()))
}

//
// TOML
//

#[derive(Debug, Deserialize)]
struct IpsetConfig {
    // TOML
    ipv4: BTreeMap<String, Vec<String>>,

    #[serde(default = "BTreeMap::new")]
    ipv6: BTreeMap<String, Vec<String>>,
}

trait DomainPattern {
    fn matches(&self, value: &str) -> bool;
}

impl DomainPattern for &str {
    fn matches(&self, value: &str) -> bool {
        *self == value
    }
}

impl DomainPattern for String {
    fn matches(&self, value: &str) -> bool {
        &*self == value
    }
}

impl DomainPattern for glob::Pattern {
    fn matches(&self, value: &str) -> bool {
        self.matches(value)
    }
}

impl DomainPattern for regex::Regex {
    fn matches(&self, value: &str) -> bool {
        self.is_match(value)
    }
}

struct SetnameMatcher {
    setname: String,
    domain_matcher: Box<DomainPattern>,
}

impl SetnameMatcher {
    fn new(setname: &str, matcher: Box<DomainPattern>) -> Self {
        SetnameMatcher { setname: setname.to_string(), domain_matcher: matcher }
    }

    pub fn matches(&self, value: &str) -> bool {
        self.domain_matcher.matches(value)
    }
}

pub struct Config {
    pub listen_addr: SocketAddr,
    pub dns_addr: SocketAddr,
    pub daemon_mode: bool,
    pub reuse_port: bool,
    ipset_v4: Vec<SetnameMatcher>,
    ipset_v6: Vec<SetnameMatcher>,
}

impl Config {
    pub fn find_setnames_ipv4<>(&self, value: &str) -> BTreeSet<&str> {
        find_setnames(&self.ipset_v4, value)
    }

    pub fn find_setnames_ipv6<>(&self, value: &str) -> BTreeSet<&str> {
        find_setnames(&self.ipset_v6, value)
    }
}

fn find_setnames<'a, 'b>(ipset: &'a [SetnameMatcher], value: &'b str) -> BTreeSet<&'a str> {
    ipset.iter()
        .filter(|matcher| matcher.matches(value))
        .map(|matcher| matcher.setname.as_ref())
        .collect()
}

pub trait IntoConfig {
    fn into_config(self) -> Result<Config>;
}

impl IntoConfig for App<'static, 'static> {
    fn into_config(self) -> Result<Config> {
        debug!("Parsing command line arguments ...");
        let matches = self.get_matches();

        let daemon_mode = matches.is_present("daemon");
        let reuse_port = matches.is_present("reuse");

        let listen_port = matches.value_of("port").map_or(1919u16, |port_str| u16::from_str(port_str).unwrap());
        let dns_ip = matches.value_of("dns")
            .map_or(Ipv4Addr::new(8, 8, 8, 8) /* google dns */,
                    |ip| Ipv4Addr::from_str(ip).unwrap());

        let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), listen_port);
        let dns_addr = SocketAddr::new(IpAddr::V4(dns_ip), 53);

        let path = Path::new(matches.value_of("CONFIG_FILE").unwrap());
        let ipset_config: IpsetConfig = toml::from_str(&fs::read_to_string(path)?)?;
        let setname_matcher_tup = parse_ipsetconfig(ipset_config)?;

        Ok(Config {
            listen_addr,
            dns_addr,
            daemon_mode,
            reuse_port,
            ipset_v4: setname_matcher_tup.0,
            ipset_v6: setname_matcher_tup.1,
        })
    }
}

fn parse_ipsetconfig(ipset_config: IpsetConfig) -> Result<(Vec<SetnameMatcher>, Vec<SetnameMatcher>)> {
    debug!("Creating IPv4 set ...");
    let ipv4set = to_setname_matchers(&ipset_config.ipv4)?;
    info!("IPv4: {} setnames and {} patterns found.", ipset_config.ipv4.keys().len(), ipset_config.ipv4.values().len());

    debug!("Creating IPv6 set ...");
    let ipv6set = to_setname_matchers(&ipset_config.ipv6)?;
    info!("IPv6: {} setnames and {} patterns found.", ipset_config.ipv6.keys().len(), ipset_config.ipv6.values().len());

    Ok((ipv4set, ipv6set))
}

fn to_setname_matchers(config_set: &BTreeMap<String, Vec<String>>) -> Result<Vec<SetnameMatcher>> {
    let mut ret = Vec::new();
    for entry in config_set {
        let setname = entry.0;

        for domain_pattern_str in entry.1 {
            ret.push(create_setname_matcher(setname, domain_pattern_str)?);
        }
    }
    Ok(ret)
}

fn create_setname_matcher(setname: &str, domain_pattern_str: &str) -> Result<SetnameMatcher> {
    if (setname.len() + 1) >= IPSET_MAXNAMELEN { // +1 including C-NUL
        return Err(From::from(format!("setname '{}' >= {} characters", setname, IPSET_MAXNAMELEN)));
    }

    if domain_pattern_str.starts_with("g:") {
        let pattern = &domain_pattern_str[2..];
        debug!("\tGlob: {} => {}", pattern, setname);

        let glob_pattern = glob::Pattern::new(pattern)?;
        Ok(SetnameMatcher::new(setname, Box::new(glob_pattern)))
    } else if domain_pattern_str.starts_with("r:") {
        let pattern = &domain_pattern_str[2..];
        debug!("\tRegex: {} => {}", pattern, setname);

        let regex_pattern = regex::Regex::new(pattern)?;
        Ok(SetnameMatcher::new(setname, Box::new(regex_pattern)))
    } else {
        debug!("\tExact: {} => {}", domain_pattern_str, setname);
        Ok(SetnameMatcher::new(setname, Box::new(domain_pattern_str.to_string())))
    }
}
