use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::net::Ipv4Addr;

use crate::config::{PacketInfo, Protocol};

/// Extract packet info for filtering (zero-allocation)
/// AF_PACKET with SOCK_DGRAM strips Ethernet header, starts with IP
pub fn extract_packet_info(buf: &[u8]) -> Option<PacketInfo> {
    let ip_packet = Ipv4Packet::new(buf)?;

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

/// Loop prevention check (mirrors bcrelay.c logic)
/// Packets we've already relayed have TTL=1 and UDP checksum=0
#[inline(always)]
pub fn is_already_relayed(buf: &[u8]) -> bool {
    let ip_packet = match Ipv4Packet::new(buf) {
        Some(p) => p,
        None => return false,
    };

    // TTL must be 1 (our marker)
    if ip_packet.get_ttl() != 1 {
        return false;
    }

    // Check UDP checksum == 0 (our marker)
    if ip_packet.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Udp {
        let udp = match UdpPacket::new(ip_packet.payload()) {
            Some(u) => u,
            None => return false,
        };

        return udp.get_checksum() == 0;
    }

    false
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
}
