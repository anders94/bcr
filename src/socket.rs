use anyhow::{Context, Result};
use std::os::unix::io::{AsRawFd, OwnedFd};

#[cfg(target_os = "linux")]
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockProtocol, SockType};

/// Raw packet socket for AF_PACKET
pub struct PacketSocket {
    fd: OwnedFd,
    #[allow(dead_code)]
    ifindex: i32,
    pub ifname: String,
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

        Ok(PacketSocket {
            fd,
            ifindex: ifindex as i32,
            ifname: ifname.to_string(),
        })
    }

}

impl PacketSocket {
    /// Receive packet (zero-copy into provided buffer)
    pub fn recv(&self, buf: &mut [u8]) -> nix::Result<usize> {
        nix::unistd::read(&self.fd, buf)
    }

    /// Send packet
    pub fn send(&self, data: &[u8]) -> nix::Result<usize> {
        nix::unistd::write(&self.fd, data)
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
