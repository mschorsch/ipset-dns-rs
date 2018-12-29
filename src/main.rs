#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

use std::io::Write;
use std::net::{IpAddr, UdpSocket};

use dns_parser::{Packet, RData};
use net2::{UdpBuilder, unix::UnixUdpBuilderExt};

use crate::cli::IntoConfig;
use crate::errors::Result;

mod ipset;
mod errors;
mod cli;

// DNS header size (nameser.h)
const HFIXEDSZ: usize = 12; /* bytes of fixed data in header */
const FILTER_LOG: &'static str = "IPSET_DNS_RS_LOG";

fn main() -> Result<()> {
    init_logging();

    //
    // CLI
    let cli_config: cli::Config = cli::build_cli().into_config()?;

    //
    // Daemon
    if cli_config.daemon_mode {
        info!("Daemon mode.");
        setup_daemon()?;
    }

    //
    // Init listen socket
    let listen_addr = &cli_config.listen_addr;

    let listen_socket = UdpBuilder::new_v4()?
        .reuse_address(cli_config.reuse_port)?
        .reuse_port(cli_config.reuse_port)?
        .bind(listen_addr)?;

    //
    // Listen
    info!("Using DNS Server '{}' ...", &cli_config.dns_addr);
    info!("Listening on '{}' ...", listen_addr);
    loop {
        if let Err(err) = listen(&cli_config, &listen_socket) {
            error!("{}", err);
        }
    }
}

fn init_logging() {
    use env_logger::{Builder, Env};

    let env = Env::new().filter_or(FILTER_LOG, "info");
    let mut builder = Builder::from_env(env);
    builder.format(|buf, record| {
        writeln!(buf, "{}: {}", record.level(), record.args())
    });
    builder.init();
}

fn setup_daemon() -> Result<()> {
    unsafe {
        if libc::daemon(0, 0) < 0 {
            return Err(From::from("Could not create daemon"));
        }
    }
    Ok(())
}

fn listen(cli_config: &cli::Config, listen_socket: &UdpSocket) -> Result<()> {
    // Receives a single datagram message on the listen_socket.
    // If `msg_buf` is too small to hold the message, it will be cut off.
    let mut msg_buf = [0; 512];
    let (received, src) = listen_socket.recv_from(&mut msg_buf)?;
    if received < HFIXEDSZ {
        return Err(From::from("Did not receive full DNS header from client."));
    }

    let upstream_socket = UdpSocket::bind("0.0.0.0:0")?; // TODO always recreate? is it correct?
    let _upstream_send = upstream_socket.send_to(&msg_buf[..received], &cli_config.dns_addr)?;
    let received = upstream_socket.recv(&mut msg_buf)?;
    if received < HFIXEDSZ {
        return Err(From::from("Did not receive full DNS header from upstream."));
    }

    let packet = Packet::parse(&msg_buf[..received])?;

    for answer in packet.answers {
        let dns_name = answer.name.to_string();

        match answer.data {
            RData::A(a) => {
                let setnames = cli_config.find_setnames_ipv4(&dns_name);

                if log_enabled!(log::Level::Debug) && setnames.is_empty() {
                    debug!("No setname found for '{}'.", a.0);
                }

                for setname in setnames {
                    ipset::add_to_ipset(IpAddr::V4(a.0), setname)?;
                }
            }
            RData::AAAA(aaaa) => {
                let setnames = cli_config.find_setnames_ipv6(&dns_name);

                if log_enabled!(log::Level::Debug) && setnames.is_empty() {
                    debug!("No setname found for '{}'.", aaaa.0);
                }

                for setname in setnames {
                    ipset::add_to_ipset(IpAddr::V6(aaaa.0), setname)?;
                }
            }
            _ => (),
        }
    }

    // send back
    listen_socket.send_to(&msg_buf[..received], &src)?;

    Ok(())
}
