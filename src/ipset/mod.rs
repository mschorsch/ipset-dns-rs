use std::io;
use std::mem::size_of;
use std::net::IpAddr;

use crslmnl as mnl;
use crslmnl::linux::netfilter::nfnetlink as nfnl;
use crslmnl::linux::netlink as netlink;
use log::Level;

use crate::errors::Result;
use crate::ipset::types::*;

pub mod types;

pub fn add_to_ipset(ip_addr: IpAddr, setname: &str) -> Result<()> {
    if (setname.len() + 1) >= IPSET_MAXNAMELEN { // +1 includes C-NUL
        return Err(From::from(format!("'{}' >= {}", setname, IPSET_MAXNAMELEN)));
    }

    let af = if ip_addr.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
    let mut buffer = vec![0u8; mnl::SOCKET_BUFFER_SIZE()];

    let mut nlh = mnl::Nlmsg::new(&mut buffer)?;
    *nlh.nlmsg_type = IPSET_CMD_ADD | (nfnl::NFNL_SUBSYS_IPSET << 8);
    *nlh.nlmsg_flags = netlink::NLM_F_REQUEST;

    let nfg = nlh.put_sized_header::<nfnl::Nfgenmsg>()?;
    nfg.nfgen_family = af as u8;
    nfg.version = nfnl::NFNETLINK_V0;
    nfg.res_id = 0u16.to_be(); // host byte order to network byte order (big endian)

    nlh.put_u8(IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL)?;
    nlh.put_strz(IPSET_ATTR_SETNAME, setname)?; // setname + NUL
    let nested_first = nlh.nest_start(IPSET_ATTR_DATA)?;
    let nested_second = nlh.nest_start(IPSET_ATTR_IP)?;

    let ipset_attr_ipaddr = if ip_addr.is_ipv4() { IPSET_ATTR_IPADDR_IPV4 } else { IPSET_ATTR_IPADDR_IPV6 };
    let a_type = ipset_attr_ipaddr | netlink::NLA_F_NET_BYTEORDER;

    match ip_addr {
        IpAddr::V4(ipv4) => {
            let v = u32::from(ipv4).to_be();
            debug!("IPv4 '{}' ({}) from DNS server for setname '{}' received.", ipv4, v, setname);
            nlh.put(a_type, &v)
        }
        IpAddr::V6(ipv6) => {
            let v = u128::from(ipv6).to_be();
            debug!("IPv6 '{}' ({}) from DNS server for setname '{}' received.", ipv6, v, setname);
            nlh.put(a_type, &v)
        }
    }?;

    nlh.nest_end(nested_second);
    nlh.nest_end(nested_first);

    if log_enabled!(Level::Trace) {
        // debug packet
        nlh.fprintf(&mut io::stdout(), size_of::<nfnl::Nfgenmsg>());
    }

    //
    // Socket
    //
    let mnl = mnl::Socket::open(netlink::Family::NETFILTER)?;
    let send_msg_result = mnl.bind(0, mnl::SOCKET_AUTOPID)
        .and_then(|_| mnl.send_nlmsg(&nlh));

    match send_msg_result {
        Ok(nlmsg_length) => debug!("{} bytes send to ipset setname '{}'.", nlmsg_length, setname),
        Err(err) => error!("Could not send message: '{}'", err),
    }

    mnl.close()?;

    Ok(())
}
