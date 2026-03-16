use crate::config::{PacketInfo, Protocol};

/// One-line relay log format
/// Format: RELAY: SRC_IP:PORT -> DST_IP:PORT (PROTO, SIZE bytes) [via INTERFACE]
pub fn log_relay(pkt: &PacketInfo, size: usize, output_if: &str) {
    println!(
        "RELAY: {}:{} -> {}:{} ({}, {} bytes) via {}",
        pkt.src_ip,
        pkt.src_port,
        pkt.dst_ip,
        pkt.dst_port,
        protocol_name(pkt.protocol),
        size,
        output_if
    );
}

/// Verbose mode: log filtered packets
pub fn log_filtered(reason: &str, pkt: &PacketInfo) {
    println!(
        "FILTERED({}): {}:{} -> {}:{} ({})",
        reason,
        pkt.src_ip,
        pkt.src_port,
        pkt.dst_ip,
        pkt.dst_port,
        protocol_name(pkt.protocol)
    );
}

fn protocol_name(proto: Protocol) -> &'static str {
    match proto {
        Protocol::Tcp => "TCP",
        Protocol::Udp => "UDP",
        Protocol::Any => "ANY",
    }
}
