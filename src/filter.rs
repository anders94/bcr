use crate::config::{Action, Config, PacketInfo, Rule};

pub struct Filter {
    config: Config,
}

impl Filter {
    pub fn new(config: Config) -> Self {
        Filter { config }
    }

    /// Apply filters, return true if packet should be relayed
    #[inline(always)]
    pub fn should_relay(&self, pkt: &PacketInfo) -> bool {
        match self.config.find_match(pkt) {
            Some(rule) => rule.action == Action::Allow,
            None => false, // Default deny if no match
        }
    }

    /// Get matching rule for NAT options
    pub fn get_nat_rule(&self, pkt: &PacketInfo) -> Option<&Rule> {
        self.config
            .find_match(pkt)
            .filter(|r| r.action == Action::Allow)
    }
}
