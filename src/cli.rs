use std::net::Ipv4Addr;
use std::str::FromStr;

use clap::{App, Arg};

use crate::ipset::types::IPSET_MAXNAMELEN;

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
            .help("Sets a custom (upstream) DNS server (default: 8.8.8.8)"))
        .arg(Arg::with_name("ipv6_setname")
            .long("ipv6_setname")
            .value_name("NAME")
            .takes_value(true)
            .required(false)
            .validator(is_ipset_name_valid)
            .help("Sets a custom ipv6 netfilter ipset setname"))
        .arg(Arg::with_name("SETNAME")
            .required(true)
            .validator(is_ipset_name_valid)
            .index(1)
            .help("Sets an ipv4 netfilter ipset setname"))
        .arg(Arg::with_name("PORT")
            .required(true)
            .validator(is_port_valid)
            .index(2)
            .help("Sets a listen port"))
}

fn is_port_valid(v: String) -> Result<(), String> {
    u16::from_str(&v)
        .map_err(|_| "Invalid port number".to_owned())
        .and(Ok(()))
}

fn is_ipset_name_valid(v: String) -> Result<(), String> {
    if (v.len() + 1) >= IPSET_MAXNAMELEN { // +1 including C-NUL
        Err(format!("Length >= {}", IPSET_MAXNAMELEN))
    } else {
        Ok(())
    }
}

fn is_dns_ip_valid(v: String) -> Result<(), String> {
    Ipv4Addr::from_str(&v)
        .map_err(|_| "Invalid ipv4 adress".to_owned())
        .and(Ok(()))
}
