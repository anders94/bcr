# BCR — Broadcast Relay

A modern, performance-optimized broadcast relay for Linux, written in Rust. BCR
relays UDP broadcast and multicast packets between network interfaces with
header-based filtering and optional NAT. It is a hardened, modernized
replacement for `bcrelay` from the pptpd project.

> **Heads up:** A broadcast relay deliberately moves traffic across network
> segments that are otherwise isolated. That is inherently sensitive. BCR is
> built to be conservative by default — it runs unprivileged, denies anything
> you don't explicitly allow, and rejects malformed input — but you are still
> responsible for writing a config that only relays what you intend.

## Highlights

- **Runs unprivileged by default.** BCR needs root only to open its raw
  sockets, then immediately drops to an unprivileged user (`nobody` by default)
  and verifies it cannot regain root. See [Running unprivileged](#running-unprivileged-default).
- **Deny-by-default, automatically.** Anything not matched by an explicit
  `allow` rule is dropped. You do **not** need a trailing `deny` rule.
- **Strict config parsing.** Typos, unknown options, bad values, and footguns
  (e.g. NAT options on a `deny` rule) are hard errors at startup, not silent
  no-ops.
- **DoS-aware.** A kernel BPF filter means the relay only wakes for traffic it
  could actually forward, and an optional rate limit caps broadcast-storm
  amplification.
- **Correct on the wire.** Multicast is sent to the proper `01:00:5e` multicast
  MAC, relayed packets keep a valid UDP checksum, and loops are prevented both
  structurally and with a marker.
- **Fast.** Zero-allocation hotpath, pre-allocated buffers, cache-friendly
  sequential rule matching.
- **Memory-safe Rust** with structured, one-line logging to STDOUT and no
  daemon mode (designed to run under systemd).

## Installation

```bash
cargo build --release
sudo cp target/release/bcr /usr/local/bin/
```

**Requirements**

- Linux (BCR uses `AF_PACKET` sockets; it does not run on other platforms)
- A stable Rust toolchain to build
- Permission to start as root (to create raw sockets — privileges are dropped
  immediately afterward)

## Quick start

```bash
# Relay broadcasts from eth0 to eth1, only what bcr.conf allows
sudo bcr -i eth0 -o eth1 -c /etc/bcr.conf

# Fan out to multiple output interfaces
sudo bcr -i eth0 -o eth1 -o eth2 -c /etc/bcr.conf

# Bidirectional relay between two segments (each interface is both in and out;
# bcr never echoes a packet back out the interface it arrived on)
sudo bcr -i eth0 -i eth1 -o eth0 -o eth1 -c /etc/bcr.conf

# Verbose: also log packets that were filtered out
sudo bcr -i eth0 -o eth1 -c /etc/bcr.conf -v
```

> **Without `-c`, BCR relays *all* broadcast/multicast traffic** (subject to the
> built-in loop and validity checks). That is convenient for testing but
> permissive — always supply a config in production.

## Running unprivileged (default)

Creating an `AF_PACKET` socket requires root. Rather than run as root for its
whole lifetime, BCR opens its sockets and then **drops privileges**: it sets the
supplementary groups, gid, and uid of an unprivileged account, and then
confirms it can no longer regain root. The relay loop itself only does
`read()`/`sendto()` on already-open descriptors, which need no privileges.

```bash
# Default: drop to user "nobody" after opening sockets
sudo bcr -i eth0 -o eth1 -c /etc/bcr.conf

# Drop to a specific service account instead
sudo bcr -i eth0 -o eth1 -c /etc/bcr.conf -u bcr

# Opt out (NOT recommended): stay root for the whole lifetime
sudo bcr -i eth0 -o eth1 -c /etc/bcr.conf --no-drop
```

On startup BCR prints which user it dropped to. If the drop or the
re-escalation check fails, BCR exits rather than continue running as root.

## Command-line options

| Option | Description |
| --- | --- |
| `-i, --input <IFACE>` | Input interface to receive from (repeatable, required) |
| `-o, --output <IFACE>` | Output interface to relay to (repeatable, required) |
| `-c, --config <FILE>` | Config file. **If omitted, all broadcast traffic is relayed** |
| `-u, --user <USER>` | User to drop privileges to after opening sockets (default: `nobody`) |
| `--no-drop` | Do not drop privileges; run as root for the entire lifetime |
| `--rate-limit <PPS>` | Max packets/sec to relay; `0` = unlimited (default: `0`) |
| `--rate-burst <N>` | Token-bucket burst size (default: one second of `--rate-limit`) |
| `-v, --verbose` | Also log filtered/dropped packets |

## Configuration

The config is a line-based allowlist. Blank lines and `#` comments are ignored.
Each rule is:

```
ACTION PROTO SRC_IP[:SRC_PORT] DST_IP[:DST_PORT] [NAT_OPTIONS]
```

Rules are evaluated top-to-bottom and **the first match wins**. **Any packet
that matches no rule is denied** — deny-by-default is built in, so you never
need a trailing `deny any any:any any:any`.

### Fields

- **ACTION** — `allow` or `deny`
- **PROTO** — `udp` or `any` (TCP has no broadcast/multicast semantics and is
  rejected at parse time)
- **SRC_IP / DST_IP** — `x.x.x.x`, CIDR `x.x.x.x/n`, or `any`. DST_IP also
  accepts the special keywords below.
- **SRC_PORT / DST_PORT** — a port, an inclusive range `start-end`, or `any`
- **NAT_OPTIONS** (optional, **`allow` rules only**):
  - `snat=IP` — rewrite the source IP
  - `dnat=IP` — rewrite the destination IP
  - `sport=PORT` — rewrite the source port
  - `dport=PORT` — rewrite the destination port

### Destination keywords

- `255.255.255.255` — limited broadcast (all hosts on the segment)
- `directed` — a subnet-directed broadcast (e.g. `192.168.1.255`)
- `any` — match any destination

### Strict parsing

BCR refuses to start (with a line-numbered error) rather than silently doing
the wrong thing. The following are all hard errors:

- an unknown or misspelled option (e.g. `snnat=` — silently ignoring it would
  leak the un-masqueraded source IP)
- an invalid address, port, or CIDR; an inverted port range
- NAT options on a `deny` rule (they would do nothing)

### Example

```conf
# Allow NetBIOS name/datagram service (Windows discovery)
allow udp any:137-139 255.255.255.255:137-139

# Allow DHCP
allow udp any:67-68 255.255.255.255:67-68

# Allow mDNS / Bonjour / Avahi (multicast)
allow udp any:5353 224.0.0.251:5353

# Relay directed broadcasts originating from one subnet
allow udp 10.0.0.0/24:any directed:any

# Relay SSDP while masquerading the source onto the relay's address
allow udp 192.168.1.0/24:1900 255.255.255.255:1900 snat=10.0.0.1

# Everything else is denied automatically — no explicit deny rule needed.
```

A documented, copy-pasteable starting point lives in
[`examples/sample.conf`](examples/sample.conf); a minimal config for the test
walkthrough below is in [`examples/test.conf`](examples/test.conf).

## How it works

BCR binds an `AF_PACKET`/`SOCK_DGRAM` socket to each interface. A kernel BPF
filter on each input socket discards everything that isn't IPv4 UDP to a
multicast/broadcast MAC, so userspace only wakes for relevant frames. For each
packet that does arrive:

1. **Loop check** — drop it if it carries BCR's relay marker (see below).
2. **Validate & parse** — reject malformed IPv4 headers (bad version/IHL,
   truncated, or a length that overruns the captured bytes) and packets whose
   source address is not a valid unicast address.
3. **Match rules** — first matching rule wins; no match means deny.
4. **Rate limit** — if configured, drop packets over the budget.
5. **Fan out** — for every output interface *except the one the packet arrived
   on*, rewrite the destination to that segment's broadcast (or keep a matching
   directed/multicast destination), apply any NAT, recompute the IP and UDP
   checksums, set the loop marker, and send — to the correct broadcast or
   `01:00:5e` multicast MAC.
6. **Log** one line to STDOUT.

### Loop prevention

BCR prevents relay loops two ways:

1. **Structurally** — it never relays a packet back out the interface it
   arrived on. A single instance therefore cannot loop into itself, and
   bidirectional configs (`-i eth0 -i eth1 -o eth0 -o eth1`) just work: traffic
   from each interface reaches only the other.
2. **By marker** — to catch loops between *separate* BCR instances sharing a
   segment, relayed packets are tagged with **TTL = 1** *and* a magic value in
   the **IP Identification** field (`0xBCBC`). A packet arriving with both is
   treated as already-relayed and dropped.

The original bcrelay used a *zeroed UDP checksum* as the second marker. BCR does
not: a zero UDP checksum is legal and common (so the old scheme dropped
legitimate traffic) and zeroing it discards the packet's integrity protection.
BCR recomputes a **valid** UDP checksum on every relayed packet instead. Note
that any header marker is spoofable — it defends against accidental loops, not a
determined on-segment attacker.

## Security model

- **Least privilege** — drops root to an unprivileged user after opening
  sockets, and verifies it cannot climb back ([details](#running-unprivileged-default)).
- **Deny-by-default** — only explicitly allowed traffic is relayed.
- **No code execution** — the config is pure data; there is no eval or scripting.
- **Strict input validation** — every config field is validated at parse time;
  malformed packets are dropped, not crashed on (the parsing path is fuzz-tested
  and panic-free).
- **DoS awareness** — a kernel BPF filter keeps unrelated traffic from waking
  the relay, and `--rate-limit` caps storm amplification, since each accepted
  packet fans out to every output interface.
- **Header-only** — BCR makes decisions from IP/UDP headers; it does no deep
  packet inspection.

## Performance

Targets on modest hardware:

- **Throughput**: >10,000 packets/sec
- **Latency**: <100μs recv-to-send
- **Memory**: a few MB resident (config and buffers held in RAM)
- **CPU**: low at idle, bounded under storm by the BPF filter and rate limiter

This comes from a zero-allocation hotpath, pre-allocated buffers, stack-only
packet metadata, cache-friendly sequential rule matching, and inlined critical
functions.

## Testing with virtual interfaces

```bash
# Create a veth pair
sudo ip link add veth0 type veth peer name veth1
sudo ip addr add 192.168.100.1/24 dev veth0
sudo ip addr add 192.168.100.2/24 dev veth1
sudo ip link set veth0 up
sudo ip link set veth1 up

# Run BCR with the test config
sudo ./target/release/bcr -i veth0 -o veth1 -c examples/test.conf -v

# In another shell, send a broadcast from veth0's network
sudo python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1); s.bind(('192.168.100.1', 0)); s.sendto(b'test', ('255.255.255.255', 9999))"

# Watch it arrive on veth1
sudo tcpdump -i veth1 -n udp port 9999

# Clean up
sudo ip link delete veth0
```

Run the unit tests with `cargo test`.

## Comparison with the original bcrelay

**Kept**: the `AF_PACKET`/`SOCK_DGRAM` approach, the TTL=1 loop-prevention idea,
per-interface binding, and `select()` multiplexing.

**Changed / added**: memory-safe Rust; a structured allowlist config instead of
regex interface matching; rich header filtering and optional NAT; privilege
dropping; deny-by-default; strict config parsing; a kernel BPF prefilter and
rate limiting; correct multicast MAC addressing; a non-integrity-destroying loop
marker (IP Identification instead of a zeroed UDP checksum) plus the structural
"never echo to ingress" guard; and structured one-line logging, foreground-only
(intended to run under systemd).

## Use cases

- Relaying discovery protocols (mDNS, SSDP/UPnP, NetBIOS) across subnets
- Forwarding broadcasts across VPN/tunnel links
- Bridging broadcast/multicast between segmented networks
- DHCP broadcast relay (use deliberately and scope it tightly)

## License

Licensed under the same terms as the original bcrelay (GPLv2).

## See also

- `CLAUDE.md` — development and architecture guide
- `examples/sample.conf` — documented example configuration
- Original bcrelay: https://sources.debian.org/src/pptpd/
