use anyhow::Result;
use nix::sys::select::{select, FdSet};
use nix::sys::time::{TimeVal, TimeValLike};
use std::net::Ipv4Addr;
use std::os::fd::AsFd;

use crate::config::PacketInfo;
use crate::filter::Filter;
use crate::logging::{log_filtered, log_relay};
use crate::nat::apply_nat;
use crate::packet::{extract_packet_info, is_already_relayed};
use crate::socket::PacketSocket;

pub struct Relay {
    pub input_socket: PacketSocket,
    pub output_sockets: Vec<PacketSocket>,
    pub filter: Filter,
    pub verbose: bool,
}

#[derive(Default)]
struct RelayStats {
    packets_received: u64,
    packets_relayed: u64,
    filtered_loop: u64,
    filtered_invalid: u64,
    filtered_rules: u64,
    send_errors: u64,
}

impl Relay {
    /// Main relay loop - CRITICAL HOTPATH
    pub fn run(&mut self) -> Result<()> {
        // Pre-allocate buffers (avoid allocation in loop)
        let mut recv_buf = vec![0u8; 2048]; // Max packet size
        let mut send_buf = vec![0u8; 2048];

        let mut stats = RelayStats::default();

        loop {
            // Build fd_set for select()
            let mut read_fds = FdSet::new();
            read_fds.insert(self.input_socket.as_fd().as_fd());

            // Wait for packet (3 second timeout like bcrelay.c)
            let mut timeout = TimeVal::seconds(3);
            let result = select(None, &mut read_fds, None, None, Some(&mut timeout))?;

            if result == 0 {
                // Timeout: could rediscover interfaces here in the future
                continue;
            }

            // Read packet
            let len = match self.input_socket.recv(&mut recv_buf) {
                Ok(l) => l,
                Err(e) => {
                    if self.verbose {
                        eprintln!("Recv error: {}", e);
                    }
                    continue;
                }
            };

            stats.packets_received += 1;

            // HOTPATH STARTS HERE
            // Goal: minimize work between recv and send

            // 1. Loop prevention check (fast, no allocation)
            if is_already_relayed(&recv_buf[..len]) {
                if self.verbose {
                    println!("FILTERED: Already relayed packet (TTL=1, UDP checksum=0)");
                }
                stats.filtered_loop += 1;
                continue;
            }

            // 2. Extract packet info (stack allocation only)
            let pkt_info = match extract_packet_info(&recv_buf[..len]) {
                Some(info) => info,
                None => {
                    if self.verbose {
                        println!("FILTERED: Not a valid broadcast packet");
                    }
                    stats.filtered_invalid += 1;
                    continue;
                }
            };

            // 3. Apply filters (inline, cache-friendly sequential scan)
            if !self.filter.should_relay(&pkt_info) {
                if self.verbose {
                    log_filtered("rule", &pkt_info);
                }
                stats.filtered_rules += 1;
                continue;
            }

            // 4. Get NAT options (already matched, cheap lookup)
            let nat_rule = self.filter.get_nat_rule(&pkt_info).unwrap();

            // 5. Relay to all output interfaces
            for out_sock in &self.output_sockets {
                // Copy to send buffer (avoid modifying recv buffer)
                send_buf[..len].copy_from_slice(&recv_buf[..len]);

                // Apply NAT in-place
                // Use 255.255.255.255 as default broadcast address
                // TODO: get actual interface broadcast address
                if let Err(e) = apply_nat(
                    &mut send_buf[..len],
                    &nat_rule.nat,
                    Ipv4Addr::new(255, 255, 255, 255),
                ) {
                    if self.verbose {
                        eprintln!("NAT error: {}", e);
                    }
                    continue;
                }

                // Send packet
                match out_sock.send(&send_buf[..len]) {
                    Ok(_) => {
                        stats.packets_relayed += 1;

                        // Log relay (one line to STDOUT)
                        log_relay(&pkt_info, len, &out_sock.ifname);
                    }
                    Err(e) => {
                        if self.verbose {
                            eprintln!("Send error on {}: {}", out_sock.ifname, e);
                        }
                        stats.send_errors += 1;
                    }
                }
            }
            // HOTPATH ENDS HERE
        }
    }
}
