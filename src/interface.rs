use anyhow::Result;
use nix::ifaddrs::getifaddrs;
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct Interface {
    pub name: String,
    pub index: u32,
    pub ip_addr: Option<Ipv4Addr>,
    pub broadcast_addr: Option<Ipv4Addr>,
    pub is_up: bool,
}

/// Discover all active network interfaces
pub fn discover_interfaces() -> Result<Vec<Interface>> {
    let mut interfaces = Vec::new();
    let mut seen_names = std::collections::HashSet::new();

    // Get interface addresses
    let ifaddrs = getifaddrs()?;

    for ifaddr in ifaddrs {
        let name = ifaddr.interface_name;

        // Skip if we've already processed this interface
        if seen_names.contains(&name) {
            continue;
        }

        // Get interface index
        let index = match nix::net::if_::if_nametoindex(name.as_str()) {
            Ok(idx) => idx,
            Err(_) => continue,
        };

        // Get IP address if available
        let ip_addr = if let Some(addr) = ifaddr.address {
            if let Some(sin) = addr.as_sockaddr_in() {
                Some(Ipv4Addr::from(sin.ip()))
            } else {
                None
            }
        } else {
            None
        };

        // Get broadcast address
        let broadcast_addr = if let Some(b) = ifaddr.broadcast {
            if let Some(sin) = b.as_sockaddr_in() {
                Some(Ipv4Addr::from(sin.ip()))
            } else {
                None
            }
        } else {
            None
        };

        // Check if interface is up
        let is_up = ifaddr.flags.contains(nix::net::if_::InterfaceFlags::IFF_UP);

        interfaces.push(Interface {
            name: name.clone(),
            index,
            ip_addr,
            broadcast_addr,
            is_up,
        });

        seen_names.insert(name);
    }

    Ok(interfaces)
}

/// Check if an interface exists and is up
pub fn validate_interface(ifname: &str) -> Result<bool> {
    let interfaces = discover_interfaces()?;
    Ok(interfaces.iter().any(|i| i.name == ifname && i.is_up))
}
