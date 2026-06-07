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
    /// Broadcast address of the interface (used as relay destination)
    pub broadcast_addr: Ipv4Addr,
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
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                &mreq as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::packet_mreq>() as libc::socklen_t,
            );
        }

        // Look up the interface's broadcast address via getifaddrs
        let broadcast_addr = nix::ifaddrs::getifaddrs()
            .ok()
            .and_then(|addrs| {
                addrs
                    .filter(|a| a.interface_name == ifname)
                    .find_map(|a| {
                        a.broadcast.and_then(|b| {
                            b.as_sockaddr_in().map(|s| Ipv4Addr::from(s.ip()))
                        })
                    })
            })
            .unwrap_or(Ipv4Addr::new(255, 255, 255, 255));

        Ok(PacketSocket {
            fd,
            ifindex: ifindex as i32,
            ifname: ifname.to_string(),
            broadcast_addr,
        })
    }

}

impl PacketSocket {
    /// Receive packet (zero-copy into provided buffer)
    pub fn recv(&self, buf: &mut [u8]) -> nix::Result<usize> {
        nix::unistd::read(&self.fd, buf)
    }

    /// Send packet to broadcast address on the bound interface
    pub fn send(&self, data: &[u8]) -> nix::Result<usize> {
        let sll = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: (libc::ETH_P_IP as u16).to_be(),
            sll_ifindex: self.ifindex,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 6,
            sll_addr: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0], // Broadcast MAC
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
