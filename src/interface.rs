// SPDX-License-Identifier: GPL-2.0-or-later
use anyhow::Result;
use nix::ifaddrs::getifaddrs;

#[derive(Debug, Clone)]
pub struct Interface {
    pub name: String,
    pub is_up: bool,
}

/// Discover all active network interfaces
pub fn discover_interfaces() -> Result<Vec<Interface>> {
    let mut interfaces = Vec::new();
    let mut seen_names = std::collections::HashSet::new();

    let ifaddrs = getifaddrs()?;

    for ifaddr in ifaddrs {
        let name = ifaddr.interface_name;

        if seen_names.contains(&name) {
            continue;
        }

        let is_up = ifaddr.flags.contains(nix::net::if_::InterfaceFlags::IFF_UP);

        interfaces.push(Interface {
            name: name.clone(),
            is_up,
        });

        seen_names.insert(name);
    }

    Ok(interfaces)
}
