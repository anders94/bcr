use anyhow::{anyhow, Result};
use pnet::packet::ipv4::{checksum as ipv4_checksum, MutableIpv4Packet};
use pnet::packet::udp::MutableUdpPacket;
use std::net::Ipv4Addr;

use crate::config::NatOptions;

/// Apply NAT rewriting to packet buffer (in-place modification)
pub fn apply_nat(buf: &mut [u8], nat: &NatOptions, dest_broadcast: Ipv4Addr) -> Result<()> {
    let mut ip_pkt = MutableIpv4Packet::new(buf)
        .ok_or_else(|| anyhow!("Invalid IP packet"))?;

    // Apply IP-level NAT
    if let Some(new_src) = nat.source_ip {
        ip_pkt.set_source(new_src);
    }
    if let Some(new_dst) = nat.dest_ip {
        ip_pkt.set_destination(new_dst);
    } else if !ip_pkt.get_destination().is_multicast() {
        // Rewrite destination to output broadcast address; preserve multicast as-is
        ip_pkt.set_destination(dest_broadcast);
    }

    // Set TTL=1 for loop prevention (like bcrelay.c)
    ip_pkt.set_ttl(1);

    // Get protocol before modifying transport layer
    let protocol = ip_pkt.get_next_level_protocol();
    let ip_header_len = ip_pkt.get_header_length() as usize * 4;

    // Apply transport-layer NAT and update checksums.
    // Only UDP is ever relayed (see Protocol), so UDP is the only case here.
    if protocol == pnet::packet::ip::IpNextHeaderProtocols::Udp {
        apply_udp_nat(buf, ip_header_len, nat)?;
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
