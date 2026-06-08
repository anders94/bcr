use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::net::Ipv4Addr;

use crate::config::{PacketInfo, Protocol};

/// Validate that `buf` begins with a well-formed IPv4 header that fits entirely
/// within the captured bytes, returning the header length in bytes on success.
///
/// Rejects: buffers shorter than the 20-byte minimum, non-IPv4 versions, an
/// illegal IHL < 5, and headers whose declared length runs past the buffer.
/// The IHL field is attacker-controlled, and pnet's `payload()`/options
/// accessors compute their slice offsets from it; an unvalidated IHL=0 or
/// IHL=15-on-a-short-packet can drive an out-of-bounds slice. Under
/// `panic = "abort"` that panic aborts the whole relay — a single crafted
/// packet becomes a denial of service. Validating here keeps the parsing path
/// panic-free regardless of pnet's internal bounds handling.
#[inline(always)]
pub fn validate_ipv4_header(buf: &[u8]) -> Option<usize> {
    if buf.len() < 20 {
        return None;
    }
    let version = buf[0] >> 4;
    let ihl = (buf[0] & 0x0f) as usize;
    if version != 4 || ihl < 5 {
        return None;
    }
    let header_len = ihl * 4;
    if header_len > buf.len() {
        return None;
    }
    Some(header_len)
}

/// Extract packet info for filtering (zero-allocation)
/// AF_PACKET with SOCK_DGRAM strips Ethernet header, starts with IP
pub fn extract_packet_info(buf: &[u8]) -> Option<PacketInfo> {
    // Reject malformed headers up front so the IHL-driven slicing below cannot
    // read out of bounds (see validate_ipv4_header).
    validate_ipv4_header(buf)?;

    let ip_packet = Ipv4Packet::new(buf)?;

    // Reject a packet that claims more bytes than we actually captured. This
    // catches a truncated datagram (its checksums would be recomputed over
    // partial data and relayed corrupt) and a header lying about its length.
    // total_length < 20 is also invalid (must cover at least the IP header).
    let total_length = ip_packet.get_total_length() as usize;
    if total_length < 20 || total_length > buf.len() {
        return None;
    }

    // Check if broadcast (any host bits set to 1)
    let dst_ip = ip_packet.get_destination();
    if !is_broadcast(dst_ip) {
        return None; // Not a broadcast, skip early
    }

    let src_ip = ip_packet.get_source();
    // Reject packets whose source address is not a valid unicast address.
    // Legitimate traffic never originates from 0.0.0.0, a multicast, or a
    // broadcast address. Relaying such packets would let a crafted multicast
    // source/destination packet be ping-ponged between two bcr instances
    // (e.g. eth0->eth1 and eth1->eth0), flooding the system.
    if src_ip == Ipv4Addr::new(0, 0, 0, 0) || is_broadcast(src_ip) {
        return None;
    }

    let protocol_num = ip_packet.get_next_level_protocol();

    // Parse transport layer
    let payload = ip_packet.payload();

    match protocol_num {
        pnet::packet::ip::IpNextHeaderProtocols::Udp => {
            let udp = UdpPacket::new(payload)?;
            Some(PacketInfo {
                protocol: Protocol::Udp,
                src_ip,
                dst_ip,
                src_port: udp.get_source(),
                dst_port: udp.get_destination(),
            })
        }
        _ => None, // Only UDP is relayed; other protocols ignored
    }
}

/// Check if IP is broadcast or multicast
#[inline(always)]
pub fn is_broadcast(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    // Limited broadcast, directed broadcast (last octet = 255), or multicast (224.0.0.0/4)
    ip == Ipv4Addr::new(255, 255, 255, 255) || octets[3] == 255 || ip.is_multicast()
}

/// Magic value written into the IPv4 Identification field of relayed packets,
/// combined with TTL=1, to mark them as "already relayed" for loop prevention.
///
/// The original bcrelay.c marked relayed packets with TTL=1 AND a zeroed UDP
/// checksum. That has two problems: a zero UDP checksum is a legal, common
/// value in IPv4 (so legitimate traffic was misidentified as relayed and
/// dropped), and zeroing it destroyed the packet's L4 integrity protection.
/// We instead mark with TTL=1 AND this magic Identification value: receivers
/// ignore the Identification field for non-fragmented datagrams, so it is a
/// free signal, and requiring both fields to match makes a collision with
/// real traffic ~1/65536 even among TTL=1 packets. This lets the relay keep a
/// valid UDP checksum (see nat::apply_nat).
///
/// Note: like any header-based marker this is spoofable — an on-segment
/// attacker can forge it to suppress relaying of their own traffic, which is
/// not a meaningful attack. Robust anti-spoof loop prevention would require an
/// input!=output guard and/or per-packet dedup state (tracked separately).
pub const RELAY_MARKER_IP_ID: u16 = 0xBCBC;

/// Loop prevention check: a packet we previously relayed carries TTL=1 and our
/// magic IP Identification value (see RELAY_MARKER_IP_ID).
#[inline(always)]
pub fn is_already_relayed(buf: &[u8]) -> bool {
    // Reject malformed headers before touching any header accessors.
    if validate_ipv4_header(buf).is_none() {
        return false;
    }

    let ip_packet = match Ipv4Packet::new(buf) {
        Some(p) => p,
        None => return false,
    };

    ip_packet.get_ttl() == 1 && ip_packet.get_identification() == RELAY_MARKER_IP_ID
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_broadcast() {
        assert!(is_broadcast(Ipv4Addr::new(255, 255, 255, 255)));
        assert!(is_broadcast(Ipv4Addr::new(192, 168, 1, 255)));
        assert!(!is_broadcast(Ipv4Addr::new(192, 168, 1, 100)));
        assert!(is_broadcast(Ipv4Addr::new(224, 0, 0, 251))); // mDNS multicast
        assert!(is_broadcast(Ipv4Addr::new(239, 255, 255, 250))); // SSDP multicast
        assert!(!is_broadcast(Ipv4Addr::new(10, 20, 1, 173)));
    }

    /// Build a minimal UDP-over-IPv4 packet (no Ethernet header, as delivered
    /// by AF_PACKET/SOCK_DGRAM) with the given source and destination IPs.
    fn build_udp(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        use pnet::packet::ipv4::MutableIpv4Packet;
        use pnet::packet::udp::MutableUdpPacket;

        let mut buf = vec![0u8; 20 + 8];
        {
            let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length(28);
            ip.set_ttl(64);
            ip.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Udp);
            ip.set_source(src);
            ip.set_destination(dst);
        }
        {
            let mut udp = MutableUdpPacket::new(&mut buf[20..]).unwrap();
            udp.set_source(1234);
            udp.set_destination(5353);
            udp.set_length(8);
            udp.set_checksum(0x1234);
        }
        buf
    }

    #[test]
    fn test_rejects_multicast_source() {
        // A crafted packet claiming a multicast source must be rejected even
        // though its destination is a relayable multicast/broadcast address.
        let mcast_to_mcast = build_udp(
            Ipv4Addr::new(224, 0, 0, 251),
            Ipv4Addr::new(224, 0, 0, 251),
        );
        assert!(extract_packet_info(&mcast_to_mcast).is_none());

        let mcast_to_bcast = build_udp(
            Ipv4Addr::new(239, 255, 255, 250),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        assert!(extract_packet_info(&mcast_to_bcast).is_none());
    }

    #[test]
    fn test_rejects_broadcast_source() {
        let bcast_src = build_udp(
            Ipv4Addr::new(255, 255, 255, 255),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        assert!(extract_packet_info(&bcast_src).is_none());

        // Directed broadcast as a source is also invalid.
        let directed_src = build_udp(
            Ipv4Addr::new(192, 168, 1, 255),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        assert!(extract_packet_info(&directed_src).is_none());
    }

    #[test]
    fn test_accepts_unicast_source() {
        let valid = build_udp(
            Ipv4Addr::new(192, 168, 1, 50),
            Ipv4Addr::new(224, 0, 0, 251),
        );
        let info = extract_packet_info(&valid).expect("valid packet should parse");
        assert_eq!(info.src_ip, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(info.dst_ip, Ipv4Addr::new(224, 0, 0, 251));
    }

    #[test]
    fn test_rejects_truncated_packet() {
        // A valid 28-byte datagram parses; the same packet truncated below its
        // declared total_length must be rejected rather than relayed corrupt.
        let valid = build_udp(Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(255, 255, 255, 255));
        assert!(extract_packet_info(&valid).is_some());
        assert!(extract_packet_info(&valid[..valid.len() - 1]).is_none());
    }

    #[test]
    fn test_validate_rejects_malformed_headers() {
        assert!(validate_ipv4_header(&[]).is_none()); // empty
        assert!(validate_ipv4_header(&[0u8; 19]).is_none()); // too short
        assert!(validate_ipv4_header(&[0x40, 0, 0, 0]).is_none()); // v4, but < 20 bytes
        assert!(validate_ipv4_header(&[0x45u8; 19]).is_none()); // v4 ihl=5 but 19 bytes
        assert!(validate_ipv4_header(&[0x40u8; 20]).is_none()); // v4 ihl=0 (illegal)
        assert!(validate_ipv4_header(&[0x60u8; 20]).is_none()); // v6
        // v4 ihl=15 (60-byte header) on a 28-byte buffer: header runs past end.
        let mut short = [0u8; 28];
        short[0] = 0x4f;
        assert!(validate_ipv4_header(&short).is_none());
        // Well-formed minimal header.
        assert_eq!(validate_ipv4_header(&[0x45u8; 20]), Some(20));
    }

    /// Pseudo-fuzz the parsing path: a malformed or crafted packet must never
    /// panic (under panic=abort a panic aborts the whole relay -> DoS). We drive
    /// every truncation, every IHL nibble, and a stream of deterministic
    /// "random" buffers through all three entry points and simply require that
    /// none of them panic.
    #[test]
    fn fuzz_parsing_path_never_panics() {
        use crate::config::NatOptions;
        use crate::nat::apply_nat;

        let dst = Ipv4Addr::new(10, 0, 0, 255);
        let nat = NatOptions::default();

        let exercise = |buf: &[u8]| {
            let _ = is_already_relayed(buf);
            let _ = extract_packet_info(buf);
            // apply_nat mutates in place; give it its own copy.
            let mut owned = buf.to_vec();
            let _ = apply_nat(&mut owned, &nat, dst);
        };

        // 1. Every truncation of a valid packet.
        let valid = build_udp(Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(255, 255, 255, 255));
        for len in 0..=valid.len() {
            exercise(&valid[..len]);
        }

        // 2. Every IHL nibble (0..15) over buffers of several sizes.
        for &size in &[0usize, 1, 4, 20, 28, 40, 64] {
            for ihl in 0u8..16 {
                let mut buf = vec![0x33u8; size];
                if !buf.is_empty() {
                    buf[0] = (4 << 4) | ihl;
                }
                exercise(&buf);
            }
        }

        // 3. Deterministic pseudo-random buffers (seeded LCG, reproducible).
        let mut state: u32 = 0x1234_5678;
        let mut next = || {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            state
        };
        for _ in 0..5000 {
            let len = (next() % 80) as usize;
            let mut buf = vec![0u8; len];
            for b in buf.iter_mut() {
                *b = (next() >> 16) as u8;
            }
            exercise(&buf);
        }
    }
}
