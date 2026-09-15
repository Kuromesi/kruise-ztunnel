// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Native Sandbox TrafficPolicy evaluation and conversion to non-TCP firewall rules.

use std::ops::RangeInclusive;

use anyhow::{Context, ensure};
use ipnet::IpNet;

use crate::proxy::AuthorizationRejectionError;
use crate::rbac::{Connection, Direction, RbacAction, RbacDecision};
use crate::state::workload::byte_to_ip;
use crate::strng::Strng;
use crate::xds::agentio::security::{TrafficPolicy as XdsTrafficPolicy, traffic_policy as proto};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrafficPolicy {
    pub name: Strng,
    pub namespace: Strng,
    pub priority: i32,
    ingress: Option<PolicyRule>,
    egress: Option<PolicyRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PolicyRule {
    rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Rule {
    action: RbacAction,
    source_ips: Vec<IpNet>,
    destination_ips: Vec<IpNet>,
    ports: Vec<PortMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PortMatch {
    protocol: proto::Protocol,
    range: Option<RangeInclusive<u16>>,
}

impl Rule {
    fn matches_tcp(&self, conn: &Connection) -> bool {
        (self.source_ips.is_empty() || self.source_ips.iter().any(|ip| ip.contains(&conn.src.ip())))
            && (self.destination_ips.is_empty()
                || self
                    .destination_ips
                    .iter()
                    .any(|ip| ip.contains(&conn.dst.ip())))
            && (self.ports.is_empty()
                || self.ports.iter().any(|port| {
                    matches!(port.protocol, proto::Protocol::All | proto::Protocol::Tcp)
                        && port
                            .range
                            .as_ref()
                            .is_none_or(|range| range.contains(&conn.dst.port()))
                }))
    }
}

impl PolicyRule {
    fn evaluate_tcp(&self, conn: &Connection) -> RbacDecision {
        match self.rules.iter().find(|rule| rule.matches_tcp(conn)) {
            Some(rule) => match rule.action {
                RbacAction::Allow => RbacDecision::Allow,
                RbacAction::Deny => RbacDecision::Deny,
            },
            None => RbacDecision::NoMatch,
        }
    }
}

/// Evaluate the already ordered policy view against the original TCP connection.
/// A configured direction defaults to deny only after all policies miss.
/// NoMatch means this direction is absent and normal Istio authorization can run.
pub fn assert_tcp(
    policies: &[TrafficPolicy],
    conn: &Connection,
) -> Result<RbacDecision, AuthorizationRejectionError> {
    let mut configured = false;
    for policy in policies {
        let Some(rules) = (match conn.direction {
            Direction::Inbound => &policy.ingress,
            Direction::Outbound => &policy.egress,
        }) else {
            continue;
        };
        configured = true;
        match rules.evaluate_tcp(conn) {
            RbacDecision::Allow => return Ok(RbacDecision::Allow),
            RbacDecision::Deny => {
                return Err(AuthorizationRejectionError::ExplicitlyDenied(
                    policy.namespace.clone(),
                    policy.name.clone(),
                ));
            }
            RbacDecision::NoMatch => {}
        }
    }
    if configured {
        Err(AuthorizationRejectionError::ExplicitlyDenied(
            crate::strng::EMPTY,
            "SANDBOX-DEFAULT-DENY".into(),
        ))
    } else {
        Ok(RbacDecision::NoMatch)
    }
}

/// Feed native policies into the same netfilter backends used by Workload policies.
pub fn firewall_ruleset(policies: &[TrafficPolicy]) -> crate::firewall::RuleSet {
    use crate::firewall::{
        Direction as FirewallDirection, FirewallMatch, FirewallProtocol, FirewallRule, PortGroup,
        RuleAction, RuleSet,
    };

    let mut rules = Vec::new();
    for policy in policies {
        for (direction, body) in [
            (FirewallDirection::Inbound, &policy.ingress),
            (FirewallDirection::Outbound, &policy.egress),
        ] {
            let Some(body) = body else {
                continue;
            };
            for rule in &body.rules {
                let port_groups: Vec<_> = rule
                    .ports
                    .iter()
                    .filter_map(|port| {
                        let protocol = match port.protocol {
                            proto::Protocol::All => FirewallProtocol::NonTcp,
                            proto::Protocol::Udp => FirewallProtocol::Udp,
                            proto::Protocol::Icmp => FirewallProtocol::Icmp,
                            proto::Protocol::Sctp => FirewallProtocol::Sctp,
                            proto::Protocol::Tcp => return None,
                        };
                        Some(PortGroup {
                            protocol,
                            ports: port.range.iter().cloned().collect(),
                        })
                    })
                    .collect();
                if !rule.ports.is_empty() && port_groups.is_empty() {
                    continue;
                }
                rules.push(FirewallRule {
                    name: policy.name.clone(),
                    action: match rule.action {
                        RbacAction::Allow => RuleAction::Allow,
                        RbacAction::Deny => RuleAction::Deny,
                    },
                    direction,
                    priority: policy.priority,
                    clauses: vec![vec![FirewallMatch {
                        source_ips: rule.source_ips.clone(),
                        dest_ips: rule.destination_ips.clone(),
                        port_groups,
                    }]],
                });
            }
        }
    }
    RuleSet {
        rules,
        // Preserve the existing Workload firewall's default-deny behavior.
        policy_attached: !policies.is_empty(),
    }
}

impl TryFrom<XdsTrafficPolicy> for TrafficPolicy {
    type Error = anyhow::Error;

    fn try_from(resource: XdsTrafficPolicy) -> Result<Self, Self::Error> {
        ensure!(!resource.name.is_empty(), "empty TrafficPolicy name");
        ensure!(resource.priority >= 0, "negative TrafficPolicy priority");
        let scope = proto::Scope::try_from(resource.scope)?;
        ensure!(
            scope != proto::Scope::Namespace || !resource.namespace.is_empty(),
            "NAMESPACE TrafficPolicy requires a namespace"
        );
        ensure!(
            scope != proto::Scope::Global || resource.namespace.is_empty(),
            "GLOBAL TrafficPolicy must not specify a namespace"
        );
        ensure!(
            resource.ingress.is_some() || resource.egress.is_some(),
            "TrafficPolicy requires at least one direction"
        );
        Ok(Self {
            ingress: resource
                .ingress
                .map(PolicyRule::try_from)
                .transpose()
                .with_context(|| format!("TrafficPolicy {} ingress", resource.name))?,
            egress: resource
                .egress
                .map(PolicyRule::try_from)
                .transpose()
                .with_context(|| format!("TrafficPolicy {} egress", resource.name))?,
            name: resource.name.into(),
            namespace: resource.namespace.into(),
            priority: resource.priority,
        })
    }
}

impl TryFrom<proto::PolicyRule> for PolicyRule {
    type Error = anyhow::Error;

    fn try_from(value: proto::PolicyRule) -> Result<Self, Self::Error> {
        Ok(Self {
            rules: value
                .rules
                .into_iter()
                .enumerate()
                .map(|(index, rule)| Rule::try_from(rule).with_context(|| format!("rule {index}")))
                .collect::<anyhow::Result<_>>()?,
        })
    }
}

impl TryFrom<proto::Rule> for Rule {
    type Error = anyhow::Error;

    fn try_from(value: proto::Rule) -> Result<Self, Self::Error> {
        let action = match proto::Action::try_from(value.action)? {
            proto::Action::Allow => RbacAction::Allow,
            proto::Action::Deny => RbacAction::Deny,
        };
        let matches = value
            .r#match
            .context("TrafficPolicy rule requires match presence")?;
        Ok(Self {
            action,
            source_ips: matches
                .source_ips
                .into_iter()
                .map(parse_address)
                .collect::<anyhow::Result<_>>()?,
            destination_ips: matches
                .destination_ips
                .into_iter()
                .map(parse_address)
                .collect::<anyhow::Result<_>>()?,
            ports: matches
                .ports
                .into_iter()
                .map(PortMatch::try_from)
                .collect::<anyhow::Result<_>>()?,
        })
    }
}

fn parse_address(address: proto::Address) -> anyhow::Result<IpNet> {
    let ip = byte_to_ip(&address.address.into())?;
    Ok(IpNet::new(ip, address.length.try_into()?)?.trunc())
}

impl TryFrom<proto::PortMatch> for PortMatch {
    type Error = anyhow::Error;

    fn try_from(value: proto::PortMatch) -> Result<Self, Self::Error> {
        let protocol = proto::Protocol::try_from(value.protocol)?;
        let port = value.port.map(parse_port).transpose()?;
        let end_port = value.end_port.map(parse_port).transpose()?;
        ensure!(
            protocol != proto::Protocol::Icmp || (port.is_none() && end_port.is_none()),
            "ICMP cannot have a port constraint"
        );
        let range = match (port, end_port) {
            (None, None) => None,
            (Some(port), None) => Some(port..=port),
            (None, Some(end)) => Some(1..=end),
            (Some(start), Some(end)) => {
                ensure!(start <= end, "reversed port range");
                Some(start..=end)
            }
        };
        Ok(Self { protocol, range })
    }
}

fn parse_port(port: u32) -> anyhow::Result<u16> {
    ensure!(port > 0, "port must be in 1..65535");
    Ok(port.try_into()?)
}

#[cfg(test)]
mod tests;
