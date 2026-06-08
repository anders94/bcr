use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, OwnedFd};

#[cfg(target_os = "linux")]
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockProtocol, SockType};

/// Raw packet socket for AF_PACKET
pub struct PacketSocket {
    fd: OwnedFd,
    ifindex: i32,
    pub ifname: String,
    /// All IPv4 broadcast addresses of the interface (one per configured
    /// subnet/alias). Used both to decide whether a directed broadcast belongs
    /// to this interface and as the rewrite target when relaying.
    pub broadcast_addrs: Vec<Ipv4Addr>,
}

#[cfg(target_os = "linux")]
impl PacketSocket {
    /// Create AF_PACKET socket bound to interface
    pub fn new(ifname: &str) -> Result<Self> {
        // Create socket: PF_PACKET, SOCK_DGRAM (no Ethernet headers)
        let raw_fd = socket(
            AddressFamily::Packet,
            SockType::Datagram,
            SockFlag::SOCK_NONBLOCK, // Non-blocking for select/epoll
            SockProtocol::EthAll,
        )
        .context("Failed to create AF_PACKET socket")?;

        // Get interface index
        let ifindex = nix::net::if_::if_nametoindex(ifname)
            .context(format!("Failed to get index for interface '{}'", ifname))?;

        // Bind to interface with ETH_P_ALL (all protocols)
        let sll = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: (libc::ETH_P_ALL as u16).to_be(), // Big-endian
            sll_ifindex: ifindex as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };

        unsafe {
            let sa = &sll as *const libc::sockaddr_ll as *const libc::sockaddr;
            let sa_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            nix::errno::Errno::result(libc::bind(raw_fd.as_raw_fd(), sa, sa_len))
                .context(format!("Failed to bind socket to interface '{}'", ifname))?;
        }

        let fd = raw_fd;

        // Enable all-multicast reception so the NIC delivers multicast frames
        // (e.g. mDNS 224.0.0.251) even when no app on this host has joined the group.
        let mreq = libc::packet_mreq {
            mr_ifindex: ifindex as i32,
            mr_type: libc::PACKET_MR_ALLMULTI as libc::c_ushort,
            mr_alen: 0,
            mr_address: [0; 8],
        };
        unsafe {
            nix::errno::Errno::result(libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                &mreq as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::packet_mreq>() as libc::socklen_t,
            ))
            .context(format!(
                "Failed to enable all-multicast membership on interface '{}'",
                ifname
            ))?;
        }

        // Attach a kernel BPF filter so the socket only wakes userspace for
        // frames we could actually relay (multicast/broadcast-MAC IPv4 UDP).
        // Without this the ETH_P_ALL bind + ALLMULTI membership delivers every
        // frame on the wire, so a unicast/TCP/ARP flood would wake the relay
        // loop on every packet even though it relays none of them. The kernel
        // now drops non-matching frames before they reach us.
        attach_packet_filter(fd.as_raw_fd())
            .context(format!("Failed to attach BPF filter on interface '{}'", ifname))?;

        // Look up ALL of the interface's IPv4 broadcast addresses via
        // getifaddrs. An interface can carry several subnets/aliases, each with
        // its own broadcast address; capturing only the first would silently
        // refuse to relay directed broadcasts for the others.
        let mut broadcast_addrs: Vec<Ipv4Addr> = Vec::new();
        if let Ok(addrs) = nix::ifaddrs::getifaddrs() {
            for a in addrs.filter(|a| a.interface_name == ifname) {
                if let Some(bcast) = a.broadcast.and_then(|b| b.as_sockaddr_in().map(|s| s.ip())) {
                    if !broadcast_addrs.contains(&bcast) {
                        broadcast_addrs.push(bcast);
                    }
                }
            }
        }
        if broadcast_addrs.is_empty() {
            broadcast_addrs.push(Ipv4Addr::new(255, 255, 255, 255));
        }

        Ok(PacketSocket {
            fd,
            ifindex: ifindex as i32,
            ifname: ifname.to_string(),
            broadcast_addrs,
        })
    }

}

/// Attach a classic-BPF filter to an AF_PACKET SOCK_DGRAM socket that accepts
/// only IPv4/UDP packets whose destination is a multicast or broadcast address.
///
/// For SOCK_DGRAM PF_PACKET sockets the kernel runs the filter after
/// eth_type_trans has pulled `skb->data` past the Ethernet header (`packet_rcv`
/// in `net/packet/af_packet.c` only re-pushes for SOCK_RAW), so offsets are
/// measured from the start of the L3 (IPv4) header — not the L2 frame. An
/// earlier version of this filter assumed offsets-from-L2 and silently dropped
/// every packet because byte 12 of an IPv4 header is part of the source
/// address, not the EtherType.
///
/// Program:
///   0:  A = ip[0]                       ; version<<4 | IHL
///   1:  A &= 0xf0
///   2:  jeq #0x40  -> next else reject  ; IPv4 only
///   3:  A = ip[9]                       ; protocol
///   4:  jeq #17    -> next else reject  ; UDP only
///   5:  A = ip[16]                      ; first octet of dest address
///   6:  A &= 0xf0
///   7:  jeq #0xe0  -> accept            ; multicast 224.0.0.0/4
///   8:  A = ip[19]                      ; last octet of dest address
///   9:  jeq #0xff  -> accept else reject; limited or directed broadcast
///   10: accept: ret #262144
///   11: reject: ret #0
#[cfg(target_os = "linux")]
fn attach_packet_filter(fd: std::os::unix::io::RawFd) -> Result<()> {
    const BPF_LD: u16 = 0x00;
    const BPF_B: u16 = 0x10;
    const BPF_ABS: u16 = 0x20;
    const BPF_K: u16 = 0x00;
    const BPF_ALU: u16 = 0x04;
    const BPF_AND: u16 = 0x50;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_RET: u16 = 0x06;

    let prog = [
        // 0: A = ip[0] (version+IHL)
        libc::sock_filter { code: BPF_LD | BPF_B | BPF_ABS, jt: 0, jf: 0, k: 0 },
        // 1: A &= 0xf0 (isolate version nibble)
        libc::sock_filter { code: BPF_ALU | BPF_AND | BPF_K, jt: 0, jf: 0, k: 0xf0 },
        // 2: if A == 0x40 (IPv4) continue else reject (-> insn 11)
        libc::sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 0, jf: 8, k: 0x40 },
        // 3: A = ip[9] (protocol)
        libc::sock_filter { code: BPF_LD | BPF_B | BPF_ABS, jt: 0, jf: 0, k: 9 },
        // 4: if A == 17 (UDP) continue else reject (-> insn 11)
        libc::sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 0, jf: 6, k: 17 },
        // 5: A = ip[16] (first octet of dest IP)
        libc::sock_filter { code: BPF_LD | BPF_B | BPF_ABS, jt: 0, jf: 0, k: 16 },
        // 6: A &= 0xf0
        libc::sock_filter { code: BPF_ALU | BPF_AND | BPF_K, jt: 0, jf: 0, k: 0xf0 },
        // 7: if A == 0xe0 accept (multicast 224.0.0.0/4, -> insn 10), else fall through
        libc::sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 2, jf: 0, k: 0xe0 },
        // 8: A = ip[19] (last octet of dest IP)
        libc::sock_filter { code: BPF_LD | BPF_B | BPF_ABS, jt: 0, jf: 0, k: 19 },
        // 9: if A == 0xff accept (limited or directed broadcast) else reject
        libc::sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 0, jf: 1, k: 0xff },
        // 10: accept whole packet
        libc::sock_filter { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: 262144 },
        // 11: reject
        libc::sock_filter { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: 0 },
    ];

    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr() as *mut libc::sock_filter,
    };

    unsafe {
        nix::errno::Errno::result(libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &fprog as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        ))
        .context("setsockopt(SO_ATTACH_FILTER) failed")?;
    }

    Ok(())
}

/// Compute the Ethernet destination MAC (padded to the 8-byte sll_addr field)
/// for an outgoing IPv4 packet, based on its destination address at the fixed
/// offset 16..20 of the IPv4 header.
///
/// IPv4 multicast (224.0.0.0/4) maps to `01:00:5e` followed by the low 23 bits
/// of the group address (RFC 1112). Everything else — limited and directed
/// broadcasts — uses the all-ones broadcast MAC. Sending multicast to the
/// broadcast MAC (as the code previously did) forces every NIC on the segment
/// to take an interrupt and the host stack to process the frame, instead of
/// letting hardware multicast filtering drop it for uninterested hosts.
#[inline(always)]
fn dest_mac(data: &[u8]) -> [u8; 8] {
    if data.len() >= 20 {
        let d = [data[16], data[17], data[18], data[19]];
        if (224..=239).contains(&d[0]) {
            return [0x01, 0x00, 0x5e, d[1] & 0x7f, d[2], d[3], 0, 0];
        }
    }
    [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0]
}

impl PacketSocket {
    /// Receive packet (zero-copy into provided buffer)
    pub fn recv(&self, buf: &mut [u8]) -> nix::Result<usize> {
        nix::unistd::read(&self.fd, buf)
    }

    /// Send packet on the bound interface. The destination MAC is derived from
    /// the IPv4 destination address: a multicast group maps to its 01:00:5e
    /// multicast MAC, everything else (limited/directed broadcast) goes to the
    /// broadcast MAC.
    pub fn send(&self, data: &[u8]) -> nix::Result<usize> {
        let sll = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: (libc::ETH_P_IP as u16).to_be(),
            sll_ifindex: self.ifindex,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 6,
            sll_addr: dest_mac(data),
        };
        unsafe {
            let sa = &sll as *const libc::sockaddr_ll as *const libc::sockaddr;
            let sa_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            nix::errno::Errno::result(libc::sendto(
                self.fd.as_raw_fd(),
                data.as_ptr() as *const libc::c_void,
                data.len(),
                0,
                sa,
                sa_len,
            ))
            .map(|n| n as usize)
        }
    }

    pub fn as_fd(&self) -> &OwnedFd {
        &self.fd
    }
}

#[cfg(not(target_os = "linux"))]
impl PacketSocket {
    pub fn new(_ifname: &str) -> Result<Self> {
        anyhow::bail!("bcr is only supported on Linux (requires AF_PACKET sockets)")
    }
}

// OwnedFd automatically closes the file descriptor when dropped, so we don't need Drop impl

#[cfg(test)]
mod tests {
    use super::dest_mac;

    /// Build a 20-byte IPv4 header carrying the given destination address.
    fn pkt_with_dst(dst: [u8; 4]) -> Vec<u8> {
        let mut buf = vec![0u8; 20];
        buf[16..20].copy_from_slice(&dst);
        buf
    }

    #[test]
    fn multicast_maps_to_01005e_mac() {
        // 224.0.0.251 (mDNS) -> 01:00:5e:00:00:fb
        assert_eq!(
            dest_mac(&pkt_with_dst([224, 0, 0, 251])),
            [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb, 0, 0]
        );
        // 239.255.255.250 (SSDP): high bit of the second octet is masked off.
        assert_eq!(
            dest_mac(&pkt_with_dst([239, 255, 255, 250])),
            [0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa, 0, 0]
        );
    }

    #[test]
    fn broadcast_uses_all_ones_mac() {
        let bcast = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0];
        assert_eq!(dest_mac(&pkt_with_dst([255, 255, 255, 255])), bcast); // limited
        assert_eq!(dest_mac(&pkt_with_dst([192, 168, 1, 255])), bcast); // directed
    }

    #[test]
    fn short_buffer_falls_back_to_broadcast() {
        assert_eq!(
            dest_mac(&[0u8; 10]),
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0]
        );
    }
}
