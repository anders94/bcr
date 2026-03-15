use anyhow::{anyhow, Result};
use pnet::packet::ipv4::{checksum as ipv4_checksum, MutableIpv4Packet};
use pnet::packet::tcp::{ipv4_checksum as tcp_checksum, MutableTcpPacket};
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::MutablePacket;
use std::net::Ipv4Addr;

use crate::config::NatOptions;

/// Apply NAT rewriting to packet buffer (in-place modification)
pub fn apply_nat(buf: &mut [u8], nat: &NatOptions, dest_broadcast: Ipv4Addr) -> Result<()> {
    let mut ip_pkt = MutableIpv4Packet::new(buf)
        .ok_or_else(|| anyhow!("Invalid IP packet"))?;

    // Store original values for potential checksum calculation (currently unused)
    let _orig_src_ip = ip_pkt.get_source();
    let _orig_dst_ip = ip_pkt.get_destination();

    // Apply IP-level NAT
    if let Some(new_src) = nat.source_ip {
        ip_pkt.set_source(new_src);
    }
    if let Some(new_dst) = nat.dest_ip {
        ip_pkt.set_destination(new_dst);
    } else {
        // Always rewrite destination to broadcast address for relaying
        ip_pkt.set_destination(dest_broadcast);
    }

    // Set TTL=1 for loop prevention (like bcrelay.c)
    ip_pkt.set_ttl(1);

    // Get protocol before modifying transport layer
    let protocol = ip_pkt.get_next_level_protocol();
    let ip_header_len = ((ip_pkt.get_version() & 0x0F) as usize) * 4;

    // Apply transport-layer NAT and update checksums
    match protocol {
        pnet::packet::ip::IpNextHeaderProtocols::Udp => {
            apply_udp_nat(buf, ip_header_len, nat)?;
        }
        pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
            let new_src_ip = ip_pkt.get_source();
            let new_dst_ip = ip_pkt.get_destination();
            apply_tcp_nat(buf, ip_header_len, nat, new_src_ip, new_dst_ip)?;
        }
        _ => {}
    }

    // Recalculate IP checksum (must be after all IP header modifications)
    let mut ip_pkt = MutableIpv4Packet::new(buf).unwrap();
    let checksum = ipv4_checksum(&ip_pkt.to_immutable());
    ip_pkt.set_checksum(checksum);

    Ok(())
}

fn apply_udp_nat(buf: &mut [u8], ip_header_len: usize, nat: &NatOptions) -> Result<()> {
    let mut udp_pkt = MutableUdpPacket::new(&mut buf[ip_header_len..])
        .ok_or_else(|| anyhow!("Invalid UDP packet"))?;

    // Apply port NAT
    if let Some(new_sport) = nat.source_port {
        udp_pkt.set_source(new_sport);
    }
    if let Some(new_dport) = nat.dest_port {
        udp_pkt.set_destination(new_dport);
    }

    // Set checksum to 0 as loop prevention marker (like bcrelay.c)
    // This is our "already relayed" marker
    udp_pkt.set_checksum(0);

    Ok(())
}

fn apply_tcp_nat(
    buf: &mut [u8],
    ip_header_len: usize,
    nat: &NatOptions,
    new_src_ip: Ipv4Addr,
    new_dst_ip: Ipv4Addr,
) -> Result<()> {
    let mut tcp_pkt = MutableTcpPacket::new(&mut buf[ip_header_len..])
        .ok_or_else(|| anyhow!("Invalid TCP packet"))?;

    // Apply port NAT
    if let Some(new_sport) = nat.source_port {
        tcp_pkt.set_source(new_sport);
    }
    if let Some(new_dport) = nat.dest_port {
        tcp_pkt.set_destination(new_dport);
    }

    // Recalculate TCP checksum with new IP addresses
    let checksum = tcp_checksum(&tcp_pkt.to_immutable(), &new_src_ip, &new_dst_ip);
    tcp_pkt.set_checksum(checksum);

    Ok(())
}
