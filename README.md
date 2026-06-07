# BCR - Broadcast Relay

A modern, performance-optimized broadcast relay for Linux written in Rust. BCR is a modernized replacement for `bcrelay` from the pptpd project, designed to relay UDP broadcast and multicast packets between network interfaces with configurable filtering and NAT capabilities.

## Features

- **High Performance**: Zero-allocation hotpath, optimized for >10,000 packets/sec
- **Flexible Filtering**: Filter by source IP, port, protocol, and broadcast type
- **NAT Support**: Optional source/destination IP and port rewriting
- **Security First**: Deny-by-default allowlist mode
- **Simple Config**: Human-readable line-based configuration format
- **Loop Prevention**: Automatic detection and prevention of relay loops
- **Modern Rust**: Memory-safe implementation with excellent error handling

## Installation

### Build from Source

```bash
cargo build --release
sudo cp target/release/bcr /usr/local/bin/
```

### Requirements

- Linux kernel with AF_PACKET support
- Root privileges or CAP_NET_RAW capability
- Rust 1.70+ (for building)

## Usage

### Basic Usage

```bash
# Relay broadcasts from eth0 to eth1
sudo bcr -i eth0 -o eth1 -c /etc/bcr.conf

# Relay to multiple output interfaces
sudo bcr -i eth0 -o eth1 -o eth2 -c /etc/bcr.conf

# Verbose mode (shows filtered packets)
sudo bcr -i eth0 -o eth1 -c /etc/bcr.conf -v
```

### Command Line Options

- `-i, --input <INTERFACE>` - Input interface to receive broadcasts from (required)
- `-o, --output <INTERFACE>` - Output interface(s) to relay to (can be specified multiple times, required)
- `-c, --config <FILE>` - Configuration file path (default: /etc/bcr.conf)
- `-u, --user <USER>` - User to drop privileges to after creating sockets (default: `nobody`)
- `--no-drop` - Do not drop privileges; run as root for the entire lifetime
- `--rate-limit <PPS>` - Max packets/sec to relay, `0` = unlimited (default: `0`). Caps storm amplification
- `--rate-burst <N>` - Burst capacity for the rate limiter (default: one second of `--rate-limit`)
- `-v, --verbose` - Verbose mode (show filtered packets)

### Denial-of-service hardening

A kernel BPF filter is always attached to each input socket so it only wakes
the relay for frames it could actually relay (IPv4/UDP sent to a
multicast/broadcast MAC). All other traffic — TCP, ARP, IPv6, unicast — is
dropped by the kernel before reaching userspace.

`--rate-limit` bounds how many packets per second are relayed. Because each
accepted packet is fanned out to every output interface, an unbounded
broadcast storm on an input interface would otherwise be amplified across all
outputs. The limiter uses a token bucket: up to `--rate-burst` packets may pass
back-to-back, refilling at `--rate-limit` per second.

## Configuration

BCR uses a simple line-based configuration format:

```
ACTION PROTO SRC_IP[:SRC_PORT] DST_IP[:DST_PORT] [NAT_OPTIONS]
```

### Configuration Fields

- **ACTION**: `allow` or `deny`
- **PROTO**: `udp` or `any` (TCP is not relayed — it has no broadcast/multicast semantics)
- **SRC_IP**: Source IP address (`x.x.x.x`, `x.x.x.x/CIDR`, or `any`)
- **SRC_PORT**: Source port (`port`, `start-end`, or `any`)
- **DST_IP**: Destination IP (`x.x.x.x`, `255.255.255.255`, `directed`, or `any`)
- **DST_PORT**: Destination port (`port`, `start-end`, or `any`)
- **NAT_OPTIONS** (optional, `allow` rules only):
  - `snat=IP` - Rewrite source IP
  - `dnat=IP` - Rewrite destination IP
  - `sport=PORT` - Rewrite source port
  - `dport=PORT` - Rewrite destination port

Config parsing is strict: a misspelled or unknown option (e.g. `snnat=`), an
invalid value, an inverted port range, or NAT options on a `deny` rule cause
bcr to refuse to start with a line-numbered error, rather than silently
ignoring the token (which could leak an un-masqueraded source IP).

### Special Keywords

- `255.255.255.255` - Limited broadcast (all hosts)
- `directed` - Directed broadcast (subnet-specific, e.g., 192.168.1.255)
- `any` - Match any value

### Example Configuration

```conf
# Allow NetBIOS broadcasts (Windows file sharing)
allow udp any:137-139 255.255.255.255:137-139

# Allow DHCP broadcasts
allow udp any:67-68 255.255.255.255:67-68

# Allow directed broadcasts from specific subnet
allow udp 10.0.0.0/24:any directed:any

# Allow UPnP with source NAT
allow udp 192.168.1.0/24:1900 255.255.255.255:1900 snat=10.0.0.1

# Default deny all
deny any any:any any:any
```

See `examples/sample.conf` for a complete example.

## How It Works

BCR uses Linux AF_PACKET raw sockets to capture broadcast packets on the input interface and forward them to output interfaces. The relay process:

1. Receives packet on input interface
2. Checks for relay loops (rejects packets with TTL=1 and UDP checksum=0)
3. Extracts packet headers (IP, UDP)
4. Matches against configuration rules (first match wins)
5. If allowed, applies NAT transformations (if configured)
6. Sends packet to all output interfaces
7. Logs relay to STDOUT

### Loop Prevention

To prevent infinite relay loops, BCR marks relayed packets by:
- Setting TTL to 1
- Setting UDP checksum to 0

Any packet received with these markers is rejected as already relayed.

## Performance

BCR is designed for high performance:

- **Throughput**: >10,000 packets/sec on modest hardware
- **Latency**: <100μs relay time (recv to send)
- **Memory**: <10MB resident (config loaded in RAM)
- **CPU**: <5% idle, <50% under broadcast storm

Performance characteristics:
- Zero allocations in the relay hotpath
- Pre-allocated packet buffers
- Stack-only packet metadata
- Cache-friendly sequential rule matching
- Inline critical path functions

## Testing

### Create Test Interfaces

```bash
# Create virtual ethernet pair
sudo ip link add veth0 type veth peer name veth1
sudo ip addr add 192.168.100.1/24 dev veth0
sudo ip addr add 192.168.100.2/24 dev veth1
sudo ip link set veth0 up
sudo ip link set veth1 up
```

### Run BCR

```bash
sudo ./target/release/bcr -i veth0 -o veth1 -c test.conf -v
```

### Send Test Broadcast

```bash
# Using netcat
echo "test" | nc -u -b 255.255.255.255 9999

# Using Python
python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1); s.bind(('192.168.100.1', 0)); s.sendto(b'test', ('255.255.255.255', 9999))"
```

### Monitor on Output Interface

```bash
sudo tcpdump -i veth1 -n udp port 9999
```

### Cleanup

```bash
sudo ip link delete veth0
```

## Comparison with Original bcrelay

BCR modernizes the original bcrelay from pptpd:

### Kept from bcrelay:
- AF_PACKET socket approach for performance
- Loop prevention mechanism (TTL=1, checksum=0)
- Interface binding pattern
- select() multiplexing

### Modernized in BCR:
- Rust memory safety (no buffer overflows)
- Structured configuration file (vs regex interface matching)
- Rich filtering (IP, port, protocol, broadcast type)
- NAT capabilities (optional IP/port rewriting)
- Foreground by default (no daemon mode needed with systemd)
- Structured one-line logging to STDOUT
- Deny-by-default security model

## Use Cases

- **VPN/Tunnel Scenarios**: Relay broadcasts across VPN tunnels
- **Network Segmentation**: Forward broadcasts between isolated segments
- **Windows Networking**: Enable NetBIOS/SMB across subnets
- **IoT/Discovery Protocols**: Relay mDNS, UPnP, SSDP across networks
- **DHCP Relay**: Forward DHCP broadcasts (use with caution)

## Security Considerations

- Requires root or CAP_NET_RAW (use with caution)
- Default deny policy (only relay explicitly allowed traffic)
- Loop prevention built-in
- No code execution in config (data only)
- Input validation on all config fields
- Graceful handling of malformed packets

## License

Licensed under the same terms as the original bcrelay (GPLv2).

## Authors

- Original bcrelay: TheyCallMeLuc, Richard de Vroede
- Modern Rust implementation: See CONTRIBUTORS

## Contributing

Contributions welcome! Please:
1. Keep the hotpath fast (no allocations)
2. Add tests for new features
3. Update documentation
4. Follow Rust idioms

## See Also

- Original bcrelay: https://sources.debian.org/src/pptpd/
- CLAUDE.md: Development guide for contributors
- examples/sample.conf: Example configuration
