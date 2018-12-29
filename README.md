# ipset-dns-rs
Lightweight DNS forwarding server that adds all resolved IPs to a given netfilter ipset.

This tool is intended to work in conjunction with `ipset` and `iptables`.

Inspired by [ipset-dns](https://git.zx2c4.com/ipset-dns/about).

## Build
Minimal Rust Version 1.31 (`edition = "2018"`)
1. Install Rust `curl https://sh.rustup.rs -sSf | sh` ([rustup.rs](https://rustup.rs))
2. Clone the repository
3. Build `cargo build --release`

## Usage
__Must be started in privileged mode!__
```bash
# create new ipset's for all setnames
sudo ipset -N youtube iphash
sudo ipset -N microsoft iphash
sudo ipset -N google iphash

# run
sudo ./ipset-dns-rs

INFO: IPv4: 3 setnames and 3 patterns found.
INFO: IPv6: 3 setnames and 3 patterns found.
INFO: Using DNS Server '8.8.8.8:53' ...
INFO: Listening on '127.0.0.1:1919' ...
```

Test:
```bash
dig @127.0.0.1 -p1919 youtube.com
```
## ipset setname configuration
All patterns are configured via a configuration file (default: `ipset_dns_config.toml`). The configuration file must be written in [TOML](https://github.com/toml-lang/toml) format. The following patterns are allowed: 
* Exact (e.g `youtube.com`)
* [Glob](https://docs.rs/glob/0.2.11/glob/struct.Pattern.html) (e.g. `g:*example.com`)
  * Note: A glob pattern always starts with the sequence `g:`
* [Regex](https://docs.rs/regex/1.1.0/regex) (e.g `r:^.*google\.(com|uk|de)$`)
  * Note: A regular expression always starts with the sequence `r:`

__Example__
```toml
[ipv4]
youtube = ['youtube.com', '*.youtube.com']
microsoft = ['g:*microsoft.com']
google = ['google.com', 'r:^.*google\.(com|uk|de)$']

[ipv6]
youtube = ['youtube.com', '*.youtube.com']
microsoft = ['g:*microsoft.com']
google = ['google.com', 'r:^.*google\.(com|uk|de)$']
```

## Logging
Can be configured via environment variable `IPSET_DNS_RS_LOG` (see [env_logger](https://docs.rs/env_logger/0.6.0/env_logger)).
```bash
export IPSET_DNS_RS_LOG=debug
```

## Command Line

```bash
./ipset-dns-rs --help

ipset-dns-rs 0.1.0
Matthias S. <matthias.schorsch@gmx.de>
Lightweight DNS forwarding server that adds all resolved IPs to a given netfilter ipset

USAGE:
    ipset-dns-rs [FLAGS] [OPTIONS] <CONFIG_FILE>

FLAGS:
    -d, --daemon     Enable deamon mode
    -h, --help       Prints help information
    -r, --reuse      Enable port reuse
    -V, --version    Prints version information

OPTIONS:
        --dns <IP>       Sets a custom (upstream) DNS server [default: 8.8.8.8]
    -p, --port <port>    Sets a listen port [default: 1919]

ARGS:
    <CONFIG_FILE>    Sets a netfilter ipset-dns config file [default: ipset_dns_config.toml]
```

## TODO
* [ ] Performance
  * [ ] Reuse socket 
  * [ ] Tokio-UDP (?)
* [ ] Documentation

## License
GPL v2