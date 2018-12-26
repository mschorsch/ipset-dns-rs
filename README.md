# ipset-dns-rs
Lightweight DNS forwarding server that adds all resolved IPs to a given netfilter ipset

Inspired by [ipset-dns](https://git.zx2c4.com/ipset-dns/about).

## Usage
__Note: Must be started in privileged mode!__
```bash
sudo ./ipset-dns-rs youtube 1919

INFO: Using DNS '8.8.8.8:53' ...
INFO: Listening on '127.0.0.1:1919' ...
```

Test:
```bash
dig @127.0.0.1 -p1919 youtube.com
```

## Logging
Can be configured via environment variable `IPSET_DNS_RS_LOG` (see [env_logger](https://docs.rs/env_logger/0.6.0/env_logger)).
```bash
export IPSET_DNS_RS_LOG=debug
```

## Command Line

```bash
ipset-dns-rs 0.1.0
Matthias S. <matthias.schorsch@gmx.de>
Lightweight DNS forwarding server that adds all resolved IPs to a given netfilter ipset

USAGE:
    ipset-dns-rs [FLAGS] [OPTIONS] <SETNAME> <PORT>

FLAGS:
    -d, --daemon     Enable deamon mode
    -h, --help       Prints help information
    -r, --reuse      Enable port reuse
    -V, --version    Prints version information

OPTIONS:
        --dns <IP>               Sets a custom (upstream) DNS server (default: 8.8.8.8)
        --ipv6_setname <NAME>    Sets a custom ipv6 netfilter ipset setname

ARGS:
    <SETNAME>    Sets an ipv4 netfilter ipset setname
    <PORT>       Sets a listen port
```

## Build from Source
Minimal Rust Version 1.31 (`edition = "2018"`)
1. Install Rust `curl https://sh.rustup.rs -sSf | sh` ([rustup.rs](https://rustup.rs))
2. Clone the repository
3. Build `cargo build --release`

## TODO
* [ ] Performance
  * [ ] Reuse socket 
  * [ ] Tokio-UDP (?)
* [ ] Multiple `setname`
  * [ ] Configuration via toml
  * [ ] Glob pattern matching
  * [ ] Regex pattern matching
* [ ] Documentation

## License
GPL v2