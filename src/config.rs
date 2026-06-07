use std::fs;
use std::net::Ipv4Addr;
use std::ops::RangeInclusive;
use std::str::FromStr;
use anyhow::{anyhow, Context, Result};

/// Action to take when rule matches
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Deny,
}

/// Protocol filter
///
/// Only UDP is relayed. TCP is connection-oriented unicast and has no
/// meaningful broadcast/multicast semantics, so it is intentionally not
/// supported (relaying it also had no loop-prevention marker).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Udp,
    Any,
}

/// IP address matcher (optimized for fast comparison)
#[derive(Debug, Clone)]
pub enum IpMatcher {
    Any,
    Exact(Ipv4Addr),
    Cidr { addr: u32, mask: u32 },  // Pre-computed for speed
}

impl IpMatcher {
    #[inline(always)]
    pub fn matches(&self, ip: Ipv4Addr) -> bool {
        match self {
            IpMatcher::Any => true,
            IpMatcher::Exact(addr) => *addr == ip,
            IpMatcher::Cidr { addr, mask } => {
                (u32::from_be_bytes(ip.octets()) & mask) == *addr
            }
        }
    }
}

/// Port matcher
#[derive(Debug, Clone)]
pub enum PortMatcher {
    Any,
    Exact(u16),
    Range(RangeInclusive<u16>),
}

impl PortMatcher {
    #[inline(always)]
    pub fn matches(&self, port: u16) -> bool {
        match self {
            PortMatcher::Any => true,
            PortMatcher::Exact(p) => *p == port,
            PortMatcher::Range(r) => r.contains(&port),
        }
    }
}

/// Broadcast type filter
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastType {
    Any,
    Limited,    // 255.255.255.255
    Directed,   // Subnet-specific (e.g., 192.168.1.255)
}

/// NAT rewriting options
#[derive(Debug, Clone, Default)]
pub struct NatOptions {
    pub source_ip: Option<Ipv4Addr>,
    pub dest_ip: Option<Ipv4Addr>,
    pub source_port: Option<u16>,
    pub dest_port: Option<u16>,
}

/// Extracted packet information for matching (stack-allocated)
#[derive(Debug, Clone, Copy)]
pub struct PacketInfo {
    pub protocol: Protocol,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
}

/// Single relay rule
#[derive(Debug, Clone)]
pub struct Rule {
    pub action: Action,
    pub protocol: Protocol,
    pub src_ip: IpMatcher,
    pub src_port: PortMatcher,
    pub dst_ip: IpMatcher,
    pub dst_port: PortMatcher,
    pub broadcast_type: BroadcastType,
    pub nat: NatOptions,
}

impl Rule {
    /// Fast inline matching - critical hotpath function
    #[inline(always)]
    pub fn matches(&self, pkt: &PacketInfo) -> bool {
        // Early exit on protocol mismatch (most selective)
        if self.protocol != Protocol::Any && self.protocol != pkt.protocol {
            return false;
        }

        // Port checks (cheap integer comparisons)
        if !self.src_port.matches(pkt.src_port) {
            return false;
        }
        if !self.dst_port.matches(pkt.dst_port) {
            return false;
        }

        // IP checks
        if !self.src_ip.matches(pkt.src_ip) {
            return false;
        }
        if !self.dst_ip.matches(pkt.dst_ip) {
            return false;
        }

        // Broadcast type check
        match self.broadcast_type {
            BroadcastType::Any => true,
            BroadcastType::Limited => pkt.dst_ip == Ipv4Addr::new(255, 255, 255, 255),
            BroadcastType::Directed => {
                // Directed broadcast: last octet is 255, but not 255.255.255.255
                let octets = pkt.dst_ip.octets();
                octets[3] == 255 && pkt.dst_ip != Ipv4Addr::new(255, 255, 255, 255)
            }
        }
    }
}

/// Configuration holder
pub struct Config {
    pub rules: Vec<Rule>,
}

impl Config {
    /// Find first matching rule (sequential scan, cache-friendly)
    pub fn find_match(&self, pkt: &PacketInfo) -> Option<&Rule> {
        self.rules.iter().find(|rule| rule.matches(pkt))
    }

    /// Default config that allows all broadcast traffic
    pub fn allow_all() -> Self {
        Config {
            rules: vec![Rule {
                action: Action::Allow,
                protocol: Protocol::Any,
                src_ip: IpMatcher::Any,
                src_port: PortMatcher::Any,
                dst_ip: IpMatcher::Any,
                dst_port: PortMatcher::Any,
                broadcast_type: BroadcastType::Any,
                nat: NatOptions::default(),
            }],
        }
    }

    /// Load config from file
    pub fn from_file(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path))?;
        Self::parse(&content)
    }

    /// Parse config from string
    pub fn parse(content: &str) -> Result<Self> {
        let mut rules = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse rule
            match parse_rule(line) {
                Ok(rule) => rules.push(rule),
                Err(e) => {
                    return Err(anyhow!(
                        "Config parse error at line {}: {}",
                        line_num + 1,
                        e
                    ));
                }
            }
        }

        Ok(Config { rules })
    }
}

fn parse_rule(line: &str) -> Result<Rule> {
    let parts: Vec<&str> = line.split_whitespace().collect();

    if parts.len() < 4 {
        return Err(anyhow!("Invalid rule format, expected: ACTION PROTO SRC DST [NAT...]"));
    }

    let action = match parts[0] {
        "allow" => Action::Allow,
        "deny" => Action::Deny,
        _ => return Err(anyhow!("Invalid action: {}", parts[0])),
    };

    let protocol = match parts[1] {
        "udp" => Protocol::Udp,
        "any" => Protocol::Any,
        "tcp" => {
            return Err(anyhow!(
                "TCP is not supported: TCP has no broadcast/multicast semantics and is not relayed"
            ))
        }
        _ => return Err(anyhow!("Invalid protocol: {}", parts[1])),
    };

    let (src_ip, src_port) = parse_addr_port(parts[2])?;
    let (dst_ip, dst_port, broadcast_type) = parse_dest_addr_port(parts[3])?;

    // Parse NAT options (remaining parts)
    let mut nat = NatOptions::default();
    for opt in &parts[4..] {
        if let Some(val) = opt.strip_prefix("snat=") {
            nat.source_ip = Some(Ipv4Addr::from_str(val)?);
        } else if let Some(val) = opt.strip_prefix("dnat=") {
            nat.dest_ip = Some(Ipv4Addr::from_str(val)?);
        } else if let Some(val) = opt.strip_prefix("sport=") {
            nat.source_port = Some(val.parse()?);
        } else if let Some(val) = opt.strip_prefix("dport=") {
            nat.dest_port = Some(val.parse()?);
        }
    }

    Ok(Rule {
        action,
        protocol,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        broadcast_type,
        nat,
    })
}

fn parse_addr_port(s: &str) -> Result<(IpMatcher, PortMatcher)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid address:port format: {}", s));
    }

    let ip = parse_ip_matcher(parts[0])?;
    let port = parse_port_matcher(parts[1])?;

    Ok((ip, port))
}

fn parse_ip_matcher(s: &str) -> Result<IpMatcher> {
    if s == "any" {
        return Ok(IpMatcher::Any);
    }

    if s.contains('/') {
        // CIDR notation
        let parts: Vec<&str> = s.split('/').collect();
        let addr = Ipv4Addr::from_str(parts[0])?;
        let prefix_len: u32 = parts[1].parse()?;

        if prefix_len > 32 {
            return Err(anyhow!("Invalid CIDR prefix length: {}", prefix_len));
        }

        let addr_u32 = u32::from_be_bytes(addr.octets());
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };

        Ok(IpMatcher::Cidr {
            addr: addr_u32 & mask,
            mask,
        })
    } else {
        // Exact IP
        let addr = Ipv4Addr::from_str(s)?;
        Ok(IpMatcher::Exact(addr))
    }
}

fn parse_port_matcher(s: &str) -> Result<PortMatcher> {
    if s == "any" {
        return Ok(PortMatcher::Any);
    }

    if s.contains('-') {
        // Range
        let parts: Vec<&str> = s.split('-').collect();
        let start: u16 = parts[0].parse()?;
        let end: u16 = parts[1].parse()?;
        Ok(PortMatcher::Range(start..=end))
    } else {
        // Exact port
        let port: u16 = s.parse()?;
        Ok(PortMatcher::Exact(port))
    }
}

fn parse_dest_addr_port(s: &str) -> Result<(IpMatcher, PortMatcher, BroadcastType)> {
    let (ip_str, port_str) = {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Invalid address:port format: {}", s));
        }
        (parts[0], parts[1])
    };

    let port = parse_port_matcher(port_str)?;

    // Determine broadcast type
    let (ip, bcast_type) = if ip_str == "255.255.255.255" {
        (IpMatcher::Exact(Ipv4Addr::new(255, 255, 255, 255)), BroadcastType::Limited)
    } else if ip_str == "directed" {
        (IpMatcher::Any, BroadcastType::Directed)
    } else if ip_str == "any" {
        (IpMatcher::Any, BroadcastType::Any)
    } else {
        (parse_ip_matcher(ip_str)?, BroadcastType::Any)
    };

    Ok((ip, port, bcast_type))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_allow_rule() {
        let config = Config::parse("allow udp any:137-139 255.255.255.255:137-139").unwrap();
        assert_eq!(config.rules.len(), 1);
        assert!(matches!(config.rules[0].action, Action::Allow));
        assert!(matches!(config.rules[0].protocol, Protocol::Udp));
    }

    #[test]
    fn test_tcp_protocol_rejected() {
        // TCP has no broadcast semantics and is intentionally unsupported;
        // a config using it must fail to parse rather than silently relay.
        let result = Config::parse("allow tcp any:80 255.255.255.255:80");
        let err = result.err().expect("tcp rule should be rejected");
        assert!(err.to_string().contains("TCP is not supported"));
    }

    #[test]
    fn test_parse_with_nat() {
        let config = Config::parse("allow udp 192.168.1.0/24:1900 255.255.255.255:1900 snat=10.0.0.1").unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].nat.source_ip, Some(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn test_ip_matcher_cidr() {
        let matcher = IpMatcher::Cidr {
            addr: u32::from_be_bytes([192, 168, 1, 0]),
            mask: !0u32 << 8, // /24
        };
        assert!(matcher.matches(Ipv4Addr::new(192, 168, 1, 100)));
        assert!(!matcher.matches(Ipv4Addr::new(192, 168, 2, 100)));
    }

    #[test]
    fn test_port_matcher_range() {
        let matcher = PortMatcher::Range(137..=139);
        assert!(matcher.matches(138));
        assert!(!matcher.matches(140));
    }
}
