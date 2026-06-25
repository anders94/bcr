// SPDX-License-Identifier: GPL-2.0-or-later
use anyhow::{anyhow, Result};
use pnet::packet::ipv4::{checksum as ipv4_checksum, MutableIpv4Packet};
use pnet::packet::udp::MutableUdpPacket;
use std::net::Ipv4Addr;

use crate::config::NatOptions;
use crate::packet::{validate_ipv4_header, RELAY_MARKER_IP_ID};

/// Apply NAT rewriting to packet buffer (in-place modification)
pub fn apply_nat(buf: &mut [u8], nat: &NatOptions, dest_broadcast: Ipv4Addr) -> Result<()> {
    // Re-validate the header before any IHL-driven slicing. The relay path only
    // calls this on buffers that already passed extract_packet_info, but keeping
    // apply_nat self-defending means a malformed header yields a clean Err
    // instead of an out-of-bounds panic (which would abort under panic=abort).
    let ip_header_len = validate_ipv4_header(buf)
        .ok_or_else(|| anyhow!("Malformed IPv4 header"))?;

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

    // Loop-prevention marker: TTL=1 plus our magic Identification value. The
    // receive path drops packets carrying both (see is_already_relayed). Unlike
    // bcrelay.c we do NOT zero the UDP checksum, so relayed packets keep their
    // L4 integrity.
    ip_pkt.set_ttl(1);
    ip_pkt.set_identification(RELAY_MARKER_IP_ID);

    // Capture the final src/dst (after any IP NAT) for the UDP pseudo-header
    // checksum, and the protocol, before releasing the IP borrow.
    let protocol = ip_pkt.get_next_level_protocol();
    let final_src = ip_pkt.get_source();
    let final_dst = ip_pkt.get_destination();

    // Apply transport-layer NAT and recompute checksums.
    // Only UDP is ever relayed (see Protocol), so UDP is the only case here.
    if protocol == pnet::packet::ip::IpNextHeaderProtocols::Udp {
        apply_udp_nat(buf, ip_header_len, nat, final_src, final_dst)?;
    }

    // Recalculate IP checksum (must be after all IP header modifications)
    let mut ip_pkt = MutableIpv4Packet::new(buf).unwrap();
    let checksum = ipv4_checksum(&ip_pkt.to_immutable());
    ip_pkt.set_checksum(checksum);

    Ok(())
}

fn apply_udp_nat(
    buf: &mut [u8],
    ip_header_len: usize,
    nat: &NatOptions,
    src: Ipv4Addr,
    dst: Ipv4Addr,
) -> Result<()> {
    let mut udp_pkt = MutableUdpPacket::new(&mut buf[ip_header_len..])
        .ok_or_else(|| anyhow!("Invalid UDP packet"))?;

    // Apply port NAT
    if let Some(new_sport) = nat.source_port {
        udp_pkt.set_source(new_sport);
    }
    if let Some(new_dport) = nat.dest_port {
        udp_pkt.set_destination(new_dport);
    }

    // Recompute a valid UDP checksum over the (possibly NAT-rewritten) header,
    // payload, and IPv4 pseudo-header. The destination IP always changes (it is
    // rewritten to the output broadcast address), which is part of the UDP
    // pseudo-header, so the checksum must be recomputed regardless of NAT. The
    // loop marker now lives in the IP Identification field, so unlike bcrelay.c
    // we no longer zero the checksum — relayed packets retain L4 integrity.
    let checksum = pnet::packet::udp::ipv4_checksum(&udp_pkt.to_immutable(), &src, &dst);
    udp_pkt.set_checksum(checksum);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::is_already_relayed;
    use pnet::packet::ipv4::MutableIpv4Packet;
    use pnet::packet::udp::{ipv4_checksum, MutableUdpPacket, UdpPacket};

    /// Build a UDP-over-IPv4 packet (no Ethernet header) with the given TTL,
    /// IP identification, and UDP checksum, carrying a short payload.
    fn build_packet(ttl: u8, ip_id: u16, udp_cksum: u16) -> Vec<u8> {
        let payload = b"hello";
        let mut buf = vec![0u8; 20 + 8 + payload.len()];
        {
            let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length((20 + 8 + payload.len()) as u16);
            ip.set_identification(ip_id);
            ip.set_ttl(ttl);
            ip.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Udp);
            ip.set_source(Ipv4Addr::new(192, 168, 1, 50));
            ip.set_destination(Ipv4Addr::new(255, 255, 255, 255));
        }
        {
            let mut udp = MutableUdpPacket::new(&mut buf[20..]).unwrap();
            udp.set_source(1234);
            udp.set_destination(5353);
            udp.set_length((8 + payload.len()) as u16);
            udp.set_checksum(udp_cksum);
            udp.set_payload(payload);
        }
        buf
    }

    #[test]
    fn relayed_packet_carries_loop_marker() {
        let mut buf = build_packet(64, 0x1111, 0x9999);
        apply_nat(&mut buf, &NatOptions::default(), Ipv4Addr::new(255, 255, 255, 255)).unwrap();

        let ip = MutableIpv4Packet::new(&mut buf).unwrap();
        assert_eq!(ip.get_ttl(), 1);
        assert_eq!(ip.get_identification(), RELAY_MARKER_IP_ID);
        assert!(is_already_relayed(&build_packet(1, RELAY_MARKER_IP_ID, 0)));
        // The relayed packet round-trips through the loop check.
        assert!(is_already_relayed(&buf));
    }

    #[test]
    fn relayed_packet_has_valid_udp_checksum() {
        // Integrity must be preserved: the relayed packet carries a correct,
        // non-zero UDP checksum rather than the zeroed marker bcrelay.c used.
        let mut buf = build_packet(64, 0x1111, 0);
        let src = Ipv4Addr::new(192, 168, 1, 50);
        let dst = Ipv4Addr::new(255, 255, 255, 255);
        apply_nat(&mut buf, &NatOptions::default(), dst).unwrap();

        let udp = UdpPacket::new(&buf[20..]).unwrap();
        assert_ne!(udp.get_checksum(), 0, "checksum must not be the zeroed marker");
        // Recomputing over the relayed packet yields the same value -> valid.
        assert_eq!(udp.get_checksum(), ipv4_checksum(&udp, &src, &dst));
    }

    #[test]
    fn legit_ttl1_zero_checksum_is_not_treated_as_relayed() {
        // A real packet with TTL=1 and a (legal) zero UDP checksum but a normal
        // IP id must NOT be misidentified as already-relayed. Under the old
        // TTL+checksum marker this was a false positive that silently dropped
        // legitimate traffic.
        let buf = build_packet(1, 0x1111, 0);
        assert!(!is_already_relayed(&buf));
    }
}
