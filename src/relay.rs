use anyhow::Result;
use nix::sys::select::{select, FdSet};
use nix::sys::time::{TimeVal, TimeValLike};
use std::os::fd::AsFd;

use crate::filter::Filter;
use crate::logging::{log_filtered, log_relay};
use crate::nat::apply_nat;
use crate::packet::{extract_packet_info, is_already_relayed};
use crate::ratelimit::RateLimiter;
use crate::socket::PacketSocket;

pub struct Relay {
    pub input_sockets: Vec<PacketSocket>,
    pub output_sockets: Vec<PacketSocket>,
    pub filter: Filter,
    /// Optional ceiling on accepted packets/sec (None = unlimited).
    pub rate_limiter: Option<RateLimiter>,
    pub verbose: bool,
}

impl Relay {
    /// Main relay loop - CRITICAL HOTPATH
    pub fn run(&mut self) -> Result<()> {
        // Pre-allocate buffers (avoid allocation in loop)
        let mut recv_buf = vec![0u8; 2048]; // Max packet size
        let mut send_buf = vec![0u8; 2048];

        loop {
            // Build fd_set for select() across all input sockets
            let mut read_fds = FdSet::new();
            for sock in &self.input_sockets {
                read_fds.insert(sock.as_fd().as_fd());
            }

            // Wait for packet (3 second timeout like bcrelay.c)
            let mut timeout = TimeVal::seconds(3);
            let result = select(None, &mut read_fds, None, None, Some(&mut timeout))?;

            if result == 0 {
                continue;
            }

            // Find which input socket(s) have data and read from them
            for in_sock in &self.input_sockets {
                if !read_fds.contains(in_sock.as_fd().as_fd()) {
                    continue;
                }

                let len = match in_sock.recv(&mut recv_buf) {
                    Ok(l) => l,
                    Err(e) => {
                        if self.verbose {
                            eprintln!("Recv error on {}: {}", in_sock.ifname, e);
                        }
                        continue;
                    }
                };

                // HOTPATH STARTS HERE

                // 1. Loop prevention check (fast, no allocation)
                if is_already_relayed(&recv_buf[..len]) {
                    continue;
                }

                // 2. Extract packet info (stack allocation only)
                let pkt_info = match extract_packet_info(&recv_buf[..len]) {
                    Some(info) => info,
                    None => continue,
                };

                // 3. Apply filters (inline, cache-friendly sequential scan)
                if !self.filter.should_relay(&pkt_info) {
                    if self.verbose {
                        log_filtered("no match", &pkt_info);
                    }
                    continue;
                }

                // 4. Rate limit accepted packets (caps storm amplification:
                //    one accepted packet fans out to every output interface).
                if let Some(rl) = self.rate_limiter.as_mut() {
                    if !rl.allow() {
                        if self.verbose {
                            log_filtered("rate limit", &pkt_info);
                        }
                        continue;
                    }
                }

                // 5. Get NAT options (already matched, cheap lookup)
                let nat_rule = self.filter.get_nat_rule(&pkt_info).unwrap();

                // 6. Relay to all output interfaces
                for out_sock in &self.output_sockets {
                    if !should_relay_to(
                        pkt_info.dst_ip,
                        &in_sock.ifname,
                        &out_sock.ifname,
                        out_sock.broadcast_addr,
                    ) {
                        continue;
                    }

                    // Copy to send buffer (avoid modifying recv buffer)
                    send_buf[..len].copy_from_slice(&recv_buf[..len]);

                    // Apply NAT in-place, rewriting destination to the output
                    // interface's broadcast address (matching bcrelay.c behaviour)
                    if let Err(e) = apply_nat(
                        &mut send_buf[..len],
                        &nat_rule.nat,
                        out_sock.broadcast_addr,
                    ) {
                        if self.verbose {
                            eprintln!("NAT error: {}", e);
                        }
                        continue;
                    }

                    // Send packet
                    match out_sock.send(&send_buf[..len]) {
                        Ok(_) => {
                            if self.verbose {
                                log_relay(&pkt_info, len, &out_sock.ifname);
                            }
                        }
                        Err(e) => {
                            if self.verbose {
                                eprintln!("Send error on {}: {}", out_sock.ifname, e);
                            }
                        }
                    }
                }
                // HOTPATH ENDS HERE
            }
        }
    }
}

/// Decide whether a packet with destination `dst`, received on `ingress_if`,
/// should be relayed out the interface `out_if` (whose broadcast address is
/// `out_broadcast`).
///
/// The relay never echoes a packet back out the interface it arrived on. That
/// prevents a single bcr instance from relaying its own output into itself
/// (the loop the TTL/IP-id marker only papers over after the fact), and it
/// makes bidirectional configs like `-i a -i b -o a -o b` correct: a packet
/// from `a` goes only to `b`, not back onto `a`.
///
/// Otherwise: multicast and limited broadcast (255.255.255.255) go to every
/// (other) interface; a directed broadcast goes only to the interface whose
/// subnet broadcast address it matches.
#[inline(always)]
fn should_relay_to(
    dst: std::net::Ipv4Addr,
    ingress_if: &str,
    out_if: &str,
    out_broadcast: std::net::Ipv4Addr,
) -> bool {
    if ingress_if == out_if {
        return false;
    }
    dst.is_multicast()
        || dst == std::net::Ipv4Addr::new(255, 255, 255, 255)
        || dst == out_broadcast
}

#[cfg(test)]
mod tests {
    use super::should_relay_to;
    use std::net::Ipv4Addr;

    const BCAST_A: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 255);
    const LIMITED: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 255);
    const MCAST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

    #[test]
    fn never_echoes_back_to_ingress_interface() {
        // Even a limited broadcast must not be sent back out the ingress iface.
        assert!(!should_relay_to(LIMITED, "eth0", "eth0", BCAST_A));
        assert!(!should_relay_to(MCAST, "eth0", "eth0", BCAST_A));
        assert!(!should_relay_to(BCAST_A, "eth0", "eth0", BCAST_A));
    }

    #[test]
    fn relays_broadcast_and_multicast_to_other_interfaces() {
        assert!(should_relay_to(LIMITED, "eth0", "eth1", BCAST_A));
        assert!(should_relay_to(MCAST, "eth0", "eth1", BCAST_A));
    }

    #[test]
    fn directed_broadcast_only_to_matching_subnet() {
        // Goes to the interface whose subnet broadcast it matches...
        assert!(should_relay_to(BCAST_A, "eth0", "eth1", BCAST_A));
        // ...but not to an interface on a different subnet.
        assert!(!should_relay_to(BCAST_A, "eth0", "eth2", Ipv4Addr::new(10, 0, 0, 255)));
    }

    #[test]
    fn bidirectional_config_does_not_loop() {
        // `-i eth0 -i eth1 -o eth0 -o eth1`: a packet from eth0 reaches eth1 only.
        assert!(!should_relay_to(LIMITED, "eth0", "eth0", BCAST_A));
        assert!(should_relay_to(LIMITED, "eth0", "eth1", BCAST_A));
    }
}
