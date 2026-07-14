use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpRestrictionDecision {
    Allow,
    Deny,
}

/// Evaluates blacklist first, then requires a whitelist match when a whitelist
/// was configured. Invalid rules are ignored, but an all-invalid whitelist is
/// still fail-closed to preserve the existing gateway contract.
#[must_use]
pub fn check_ip_restriction(
    client_ip: &str,
    whitelist: &[String],
    blacklist: &[String],
) -> IpRestrictionDecision {
    let Some(client_ip) = parse_client_ip(client_ip) else {
        return IpRestrictionDecision::Deny;
    };
    if !blacklist.is_empty() && blacklist.iter().any(|rule| matches_rule(client_ip, rule)) {
        return IpRestrictionDecision::Deny;
    }
    if !whitelist.is_empty() && !whitelist.iter().any(|rule| matches_rule(client_ip, rule)) {
        return IpRestrictionDecision::Deny;
    }
    IpRestrictionDecision::Allow
}

fn parse_client_ip(value: &str) -> Option<IpAddr> {
    let value = value.trim();
    value
        .parse::<IpAddr>()
        .ok()
        .or_else(|| value.parse::<SocketAddr>().ok().map(|socket| socket.ip()))
}

fn matches_rule(client_ip: IpAddr, rule: &str) -> bool {
    let rule = rule.trim();
    if let Ok(address) = rule.parse::<IpAddr>() {
        return client_ip == address;
    }
    let Some((network, prefix)) = rule.split_once('/') else {
        return false;
    };
    let Ok(network) = network.trim().parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.trim().parse::<u8>() else {
        return false;
    };
    match (client_ip, network) {
        (IpAddr::V4(client), IpAddr::V4(network)) if prefix <= 32 => {
            ipv4_prefix(client, prefix) == ipv4_prefix(network, prefix)
        }
        (IpAddr::V6(client), IpAddr::V6(network)) if prefix <= 128 => {
            ipv6_prefix(client, prefix) == ipv6_prefix(network, prefix)
        }
        _ => false,
    }
}

fn ipv4_prefix(address: Ipv4Addr, prefix: u8) -> u32 {
    let bits = u32::from(address);
    if prefix == 0 {
        0
    } else {
        bits & u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0)
    }
}

fn ipv6_prefix(address: Ipv6Addr, prefix: u8) -> u128 {
    let bits = u128::from(address);
    if prefix == 0 {
        0
    } else {
        bits & u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn blacklist_wins_over_whitelist() {
        assert_eq!(
            check_ip_restriction(
                "10.1.2.3",
                &rules(&["10.0.0.0/8"]),
                &rules(&["10.1.0.0/16"]),
            ),
            IpRestrictionDecision::Deny
        );
    }

    #[test]
    fn supports_ipv4_ports_and_ipv6_cidr() {
        assert_eq!(
            check_ip_restriction("192.168.1.4:8080", &rules(&["192.168.1.0/24"]), &[]),
            IpRestrictionDecision::Allow
        );
        assert_eq!(
            check_ip_restriction("2001:db8::2", &rules(&["2001:db8::/32"]), &[]),
            IpRestrictionDecision::Allow
        );
    }

    #[test]
    fn configured_but_invalid_whitelist_is_fail_closed() {
        assert_eq!(
            check_ip_restriction("8.8.8.8", &rules(&["not-an-ip"]), &[]),
            IpRestrictionDecision::Deny
        );
    }
}
