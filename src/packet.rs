use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
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
    if src_ip == Ipv4Addr::new(0, 0, 0, 0) {
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
        pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
            let tcp = TcpPacket::new(payload)?;
            Some(PacketInfo {
                protocol: Protocol::Tcp,
                src_ip,
                dst_ip,
                src_port: tcp.get_source(),
                dst_port: tcp.get_destination(),
            })
        }
        _ => None, // Other protocols ignored
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
}
