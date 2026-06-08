# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project: BCR (Broadcast Relay)

A modern, performance-optimized broadcast relay for Linux written in Rust. This is a modernized replacement for bcrelay from the pptpd project, designed to relay UDP/TCP broadcast packets between network interfaces with configurable filtering and NAT capabilities.

## Build and Development Commands

### Building
```bash
# Development build
cargo build

# Optimized release build (required for performance testing)
cargo build --release

# The binary will be at target/release/bcr
```

### Running
```bash
# Requires root or CAP_NET_RAW capability
sudo ./target/release/bcr -i eth0 -o eth1 -c /etc/bcr.conf

# Verbose mode (shows filtered packets)
sudo ./target/release/bcr -i eth0 -o eth1 -o eth2 -c /etc/bcr.conf -v
```

### Testing
```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run tests with output
cargo test -- --nocapture

# Integration tests (requires root for veth creation)
sudo cargo test --test integration_tests
```

### Code Quality
```bash
# Run clippy lints
cargo clippy -- -D warnings

# Format code
cargo fmt

# Check without building
cargo check
```

## Architecture Overview

### Core Design Principles

1. **Performance First**: The relay hotpath is optimized for zero allocations, cache-friendly data access, and minimal syscalls
2. **Header-Only Filtering**: No deep packet inspection - all filtering decisions based on IP/UDP/TCP headers
3. **Deny-by-Default**: Allowlist security model - only explicitly allowed traffic is relayed
4. **Simple Config**: Line-based config format optimized for fast parsing and human readability

### Module Responsibilities

- **main.rs**: CLI argument parsing, initialization, permission validation, orchestration
- **config.rs**: Config file parser, rule data structures, packet matching logic with pre-computed CIDR masks
- **socket.rs**: AF_PACKET raw socket wrapper for Linux (PF_PACKET + SOCK_DGRAM); attaches a kernel BPF filter so only relayable frames (multicast/broadcast-MAC IPv4 UDP) wake userspace
- **ratelimit.rs**: Token-bucket limiter bounding accepted packets/sec to cap storm amplification
- **interface.rs**: Network interface discovery using Linux ioctls
- **packet.rs**: Zero-copy packet parsing and metadata extraction
- **filter.rs**: Fast sequential rule matching with early exits
- **nat.rs**: NAT/rewriting engine with IP/UDP/TCP checksum recalculation
- **relay.rs**: Core relay loop - THE HOTPATH - select() → recv → filter → NAT → send
- **logging.rs**: Simple one-line STDOUT logging

### Critical Performance Path

The relay loop in `relay.rs` is the most performance-critical code:

```
1. select() wait for packet on input socket
2. recv() into pre-allocated buffer
3. Loop prevention check (TTL=1 && IP Identification == 0xBCBC)
4. Extract packet info (stack-allocated struct)
5. Sequential rule matching (first match wins)
6. Rate-limit check (token bucket; drop if over budget)
7. Copy to send buffer
8. Apply NAT in-place (rewrite IPs/ports, recalc checksums)
9. send() to all output interfaces
10. Log to STDOUT
```

**Optimization requirements**:
- No heap allocations in this path
- All critical functions marked `#[inline(always)]`
- Early exits on filter mismatches
- Pre-computed CIDR masks in config
- Cache-friendly sequential Vec scans (not HashMap)

### Config File Format

Simple line-based format for fast parsing:

```
# ACTION PROTO SRC_IP[:SRC_PORT] DST_IP[:DST_PORT] [NAT_OPTIONS]

allow udp any:137-139 255.255.255.255:137-139          # NetBIOS
allow udp any:67-68 255.255.255.255:67-68              # DHCP
allow udp 10.0.0.0/24:any directed:any                 # Directed broadcasts
allow udp 192.168.1.0/24:1900 255.255.255.255:1900 snat=10.0.0.1  # SNAT

deny any any:any any:any  # Default deny
```

**Key concepts**:
- `255.255.255.255` = limited broadcast
- `directed` = subnet-specific broadcasts (e.g., 192.168.1.255)
- NAT options: `snat=IP`, `dnat=IP`, `sport=PORT`, `dport=PORT`
- First matching rule wins (top-to-bottom evaluation)

### Loop Prevention

To prevent infinite relay loops:

1. **On relay**: Set TTL=1 AND the IP Identification field to `RELAY_MARKER_IP_ID` (0xBCBC) on relayed packets
2. **On receive**: Reject packets with TTL=1 AND Identification == 0xBCBC (`is_already_relayed`)
3. This marks relayed packets so they're not relayed again

Note: bcrelay.c marked packets with TTL=1 + a zeroed UDP checksum. We moved the
marker to the IP Identification field because a zero UDP checksum is a legal,
common value (the old marker dropped legitimate traffic) and zeroing it
destroyed L4 integrity. The relay now recomputes a **valid** UDP checksum.
A header-based marker is still spoofable — robust anti-spoof loop prevention
(input!=output guard, per-packet dedup) is tracked as future work.

### Data Structure Patterns

**IpMatcher** - Optimized for fast inline matching:
```rust
enum IpMatcher {
    Any,
    Exact(Ipv4Addr),
    Cidr { addr: u32, mask: u32 },  // Pre-computed for speed
}
```

**Rule** - Stack-friendly, sequential scan:
```rust
struct Rule {
    action: Action,           // Allow/Deny
    protocol: Protocol,       // Udp/Any (TCP is not relayed)
    src_ip: IpMatcher,       // Check order: protocol → ports → IPs
    src_port: PortMatcher,   // (most selective first)
    dst_ip: IpMatcher,
    dst_port: PortMatcher,
    broadcast_type: BroadcastType,
    nat: NatOptions,
}
```

**PacketInfo** - Stack-allocated (Copy trait):
```rust
struct PacketInfo {
    protocol: Protocol,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
}
```

## Important Implementation Notes

### When Modifying the Hotpath (relay.rs)

- Profile before and after changes with `perf record -g`
- Avoid any allocations (check with `cargo +nightly build -Z build-std --target x86_64-unknown-linux-gnu` + RUSTFLAGS)
- Keep functions inline-able (avoid dynamic dispatch)
- Prefer early returns over nested ifs
- Use stack allocation only (Copy types)

### When Adding Filter Rules

- Add to config.rs parsing logic
- Update Rule::matches() with appropriate early exit placement
- Consider selectivity order (check most restrictive first)
- Update example configs and tests

### When Modifying NAT

- Always recalculate checksums after any header modification
- IP checksum: After IP header changes
- UDP checksum: Recompute a valid checksum (the dest IP in the pseudo-header always changes on relay). Do NOT zero it — the loop marker lives in the IP Identification field, not the checksum
- Only UDP is relayed; TCP has no broadcast semantics and is rejected at config parse time
- Use pnet checksum utilities (don't hand-roll)

### Privilege Requirements

- bcr requires `CAP_NET_RAW` capability or root to create AF_PACKET sockets
- Validate at startup with helpful error messages
- Consider capability dropping after socket creation (future enhancement)

### Testing with Virtual Interfaces

```bash
# Create veth pair for testing
sudo ip link add veth0 type veth peer name veth1
sudo ip addr add 192.168.100.1/24 dev veth0
sudo ip addr add 192.168.100.2/24 dev veth1
sudo ip link set veth0 up
sudo ip link set veth1 up

# Run bcr
sudo ./target/release/bcr -i veth0 -o veth1 -c test.conf -v

# Send UDP broadcast from veth0's network
sudo python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1); s.bind(('192.168.100.1', 0)); s.sendto(b'test', ('255.255.255.255', 9999))"

# Monitor on veth1
sudo tcpdump -i veth1 -n udp port 9999

# Cleanup
sudo ip link delete veth0
```

## Dependencies Philosophy

- **nix**: Safe Rust bindings for Unix syscalls (ioctls, socket operations)
- **libc**: Raw FFI when nix doesn't provide wrapper (sockaddr_ll)
- **pnet** or **etherparse**: Zero-copy packet parsing (choose based on benchmarks)
- **clap**: Ergonomic CLI with derive macros
- **anyhow/thiserror**: Error handling (anyhow for main, thiserror for lib)

Avoid heavy dependencies - keep binary small and compilation fast.

## Performance Targets

Based on bcrelay.c analysis and modern hardware expectations:

- **Throughput**: >10,000 packets/sec on modest hardware
- **Latency**: <100μs relay time (recv to send)
- **Memory**: <10MB resident (config loaded in RAM)
- **CPU**: <5% idle, <50% during broadcast storm

Profile with:
```bash
sudo perf record -g ./target/release/bcr -i veth0 -o veth1 -c test.conf
sudo perf report
```

## Security Model

1. **Deny by default**: Only explicitly allowed traffic is relayed
2. **No code execution**: Config file is pure data (no eval/embedded scripts)
3. **Loop prevention**: TTL=1 + magic IP Identification marker prevents relay loops
4. **Input validation**: All config fields validated at parse time
5. **Graceful degradation**: Malformed packets logged but don't crash relay

## Comparison with Original bcrelay

**Kept from bcrelay.c**:
- AF_PACKET socket approach (PF_PACKET + SOCK_DGRAM)
- TTL=1 loop-prevention marker (but the second signal is now a magic IP Identification value, not a zeroed UDP checksum — preserves L4 integrity)
- Interface binding and discovery pattern
- select() multiplexing

**Modernized**:
- Rust memory safety (no buffer overflows)
- Structured config file (vs regex interface matching)
- Rich filtering (IP, port, protocol, broadcast type)
- NAT capabilities (optional IP/port rewriting)
- Foreground by default (no daemon mode)
- Structured logging to STDOUT
- Deny-by-default security model

## Future Enhancement Ideas

- systemd service file and socket activation
- Per-rule rate limiting (a global `--rate-limit` token bucket already exists)
- Prometheus metrics export
- Hot config reload (SIGHUP)
- BPF filter offload for common rules (a fixed multicast/IPv4/UDP BPF filter is already attached)
- AF_XDP support for extreme performance
