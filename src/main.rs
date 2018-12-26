#[macro_use]
extern crate log;

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::str::FromStr;

use dns_parser::{Packet, RData};
use failure::Fail;
use net2::{unix::UnixUdpBuilderExt, UdpBuilder};

use crate::errors::Result;

mod ipset;
mod errors;
mod cli;

// DNS header size (nameser.h)
const HFIXEDSZ: usize = 12; /*%< #/bytes of fixed data in header */

fn main() -> Result<()> {
    init_logging();

    //
    // CLI
    let matches = cli::build_cli().get_matches();

    let daemon_mode = matches.is_present("daemon");
    let reuse_port = matches.is_present("reuse");
    let setname_ipv4 = matches.value_of("SETNAME").unwrap();
    let setname_ipv6 = matches.value_of("ipv6_setname").unwrap_or(setname_ipv4);
    let listen_port = u16::from_str(matches.value_of("PORT").unwrap()).unwrap();
    let dns_ip = matches.value_of("dns")
        .map_or(Ipv4Addr::new(8, 8, 8, 8) /* google dns */,
                |ip| Ipv4Addr::from_str(ip).unwrap());

    //
    // listen und upstream adress
    let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), listen_port);

    let listen_socket = UdpBuilder::new_v4()?
        .reuse_address(reuse_port)?
        .reuse_port(reuse_port)?
        .bind(listen_addr)?;

    let upstream_addr = SocketAddr::new(IpAddr::V4(dns_ip), 53);

    if daemon_mode {
        info!("Daemon mode.");
        setup_daemon()?;
    }

    info!("Using DNS '{}' ...", upstream_addr);
    info!("Listening on '{}' ...", listen_addr);
    loop {
        if let Err(err) = listen(&listen_socket, upstream_addr, setname_ipv4, setname_ipv6) {
            error!("{}", err);
            if let Some(cause) = err.cause() {
                error!("{}", cause);
            }
        }
    }
}

fn init_logging() {
    use env_logger::{Builder, Env};

    let env = Env::new().filter_or("IPSET_DNS_RS_LOG", "info");
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

fn listen(listen_socket: &UdpSocket, upstream_addr: SocketAddr, setname_ipv4: &str, setname_ipv6: &str) -> Result<()> {
    // Receives a single datagram message on the listen_socket.
    // If `msg_buf` is too small to hold the message, it will be cut off.
    let mut msg_buf = [0; 512];
    let (received, src) = listen_socket.recv_from(&mut msg_buf)?;
    if received < HFIXEDSZ {
        return Err(From::from("Did not receive full DNS header from client."));
    }

    let upstream_socket = UdpSocket::bind("0.0.0.0:0")?; // TODO always recreate? is it correct?
    let _upstream_send = upstream_socket.send_to(&msg_buf[..received], upstream_addr)?;
    let received = upstream_socket.recv(&mut msg_buf)?;
    if received < HFIXEDSZ {
        return Err(From::from("Did not receive full DNS header from upstream."));
    }

    let packet = Packet::parse(&msg_buf[..received])?;

    for answer in packet.answers {
        match answer.data {
            RData::A(a) => ipset::add_to_ipset(IpAddr::V4(a.0), setname_ipv4)?,
            RData::AAAA(aaaa) => ipset::add_to_ipset(IpAddr::V6(aaaa.0), setname_ipv6)?,
            _ => (),
        }
    }

    // send back
    listen_socket.send_to(&msg_buf[..received], &src)?;

    Ok(())
}

