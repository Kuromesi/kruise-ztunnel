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

//! Native TrafficPolicy evaluation and conversion to non-TCP firewall rules.

use std::collections::HashMap;
use std::ops::RangeInclusive;
use std::sync::Arc;

use crate::strng::Strng;
use crate::xds::XdsResource;

use anyhow::{Context, ensure};
use ipnet::IpNet;
use tokio::sync::watch;

use crate::rbac::{Connection, Direction};
use crate::state::workload::byte_to_ip;
use crate::xds::agentio::security::{TrafficPolicy as XdsTrafficPolicy, traffic_policy as proto};

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficPolicy {
    ingress: Option<RuleSet>,
    egress: Option<RuleSet>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuleSet {
    #[serde(default)]
    rules: Vec<Rule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub(crate) enum Action {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Rule {
    action: Action,
    #[serde(default)]
    source_ips: Vec<IpNet>,
    #[serde(default)]
    destination_ips: Vec<IpNet>,
    #[serde(default)]
    ports: Vec<PortMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PortMatch {
    #[serde(
        serialize_with = "serialize_protocol",
        deserialize_with = "deserialize_protocol"
    )]
    protocol: proto::Protocol,
    range: Option<RangeInclusive<u16>>,
}

fn serialize_protocol<S>(protocol: &proto::Protocol, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(protocol.as_str_name())
}

fn deserialize_protocol<'de, D>(deserializer: D) -> Result<proto::Protocol, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let name = <String as serde::Deserialize>::deserialize(deserializer)?;
    proto::Protocol::from_str_name(&name).ok_or_else(|| {
        serde::de::Error::unknown_variant(&name, &["ALL", "TCP", "UDP", "ICMP", "SCTP"])
    })
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

/// Shared compiled bodies, replaced atomically after validation.
#[derive(Debug)]
pub struct TrafficPolicyStore {
    resources: HashMap<Strng, Arc<TrafficPolicy>>,
    notifier: watch::Sender<()>,
}

impl Default for TrafficPolicyStore {
    fn default() -> Self {
        Self {
            resources: Default::default(),
            notifier: watch::channel(()).0,
        }
    }
}

impl TrafficPolicyStore {
    pub fn subscribe(&self) -> watch::Receiver<()> {
        self.notifier.subscribe()
    }

    /// Notify after accepted changes to policy bodies or Sandbox policy bindings.
    pub fn send(&self) {
        self.notifier.send_replace(());
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&Strng, &TrafficPolicy)> {
        self.resources
            .iter()
            .map(|(name, policy)| (name, policy.as_ref()))
    }

    pub fn get(&self, name: &Strng) -> Option<&TrafficPolicy> {
        self.resources.get(name).map(AsRef::as_ref)
    }

    pub fn update(&mut self, update: XdsResource<XdsTrafficPolicy>) -> anyhow::Result<bool> {
        let result = (|| {
            let policy = TrafficPolicy::try_from(update.resource)?;
            self.insert(update.name.clone(), policy)
        })();
        result.map_err(|error| {
            tracing::warn!(name = %update.name, %error, "ignoring invalid TrafficPolicy update; retaining last accepted resource");
            error
        })
    }

    pub(crate) fn insert(&mut self, name: Strng, policy: TrafficPolicy) -> anyhow::Result<bool> {
        ensure!(
            !name.is_empty() && name != "*",
            "empty or wildcard TrafficPolicy name"
        );
        if self.get(&name) == Some(&policy) {
            return Ok(false);
        }
        self.resources.insert(name, Arc::new(policy));
        Ok(true)
    }

    pub fn remove(&mut self, name: &Strng) -> bool {
        self.resources.remove(name).is_some()
    }

    /// Replace the resource snapshot while preserving existing subscriptions.
    pub(crate) fn replace(&mut self, next: Self) {
        self.resources = next.resources;
    }
}

impl TrafficPolicy {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        for (direction, rules) in [("ingress", &self.ingress), ("egress", &self.egress)] {
            if let Some(rules) = rules {
                for (index, rule) in rules.rules.iter().enumerate() {
                    for port in &rule.ports {
                        port.validate()
                            .with_context(|| format!("TrafficPolicy {direction} rule {index}"))?;
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn rules_for(&self, direction: Direction) -> Option<&RuleSet> {
        match direction {
            Direction::Inbound => self.ingress.as_ref(),
            Direction::Outbound => self.egress.as_ref(),
        }
    }
}

impl RuleSet {
    pub(crate) fn match_tcp(&self, conn: &Connection) -> Option<(usize, Action)> {
        self.rules
            .iter()
            .enumerate()
            .find(|(_, rule)| rule.matches_tcp(conn))
            .map(|(index, rule)| (index, rule.action))
    }
}

#[cfg(test)]
fn firewall_ruleset(policy: &TrafficPolicy) -> crate::firewall::RuleSet {
    firewall_rulesets(std::iter::once(("inline", Some(policy))))
}

/// Feed native policies into the same netfilter backends used by Workload policies.
pub fn firewall_rulesets<'a>(
    policies: impl Iterator<Item = (&'a str, Option<&'a TrafficPolicy>)> + Clone,
) -> crate::firewall::RuleSet {
    use crate::firewall::{
        Direction as FirewallDirection, FirewallMatch, FirewallProtocol, FirewallRule, PortGroup,
        RuleAction,
    };

    let mut rules = Vec::new();
    for direction in [FirewallDirection::Inbound, FirewallDirection::Outbound] {
        let mut configured = false;
        let mut default_deny_name = "DEFAULT-DENY".into();
        let mut offset = 0;
        for (name, policy) in policies.clone() {
            let Some(policy) = policy else {
                // Unknown directions cannot safely fall through to later policies.
                configured = true;
                default_deny_name = format!("{name}/policy-unavailable").into();
                break;
            };
            let body = match direction {
                FirewallDirection::Inbound => &policy.ingress,
                FirewallDirection::Outbound => &policy.egress,
            };
            let Some(body) = body else {
                continue;
            };
            configured = true;
            for (index, rule) in body.rules.iter().enumerate() {
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
                    name: format!("{name}/rule-{index}").into(),
                    action: match rule.action {
                        Action::Allow => RuleAction::Allow,
                        Action::Deny => RuleAction::Deny,
                    },
                    direction,
                    // The shared backend sorts rules. Preserve control-plane order.
                    priority: (offset + index) as i32,
                    clauses: vec![vec![FirewallMatch {
                        source_ips: rule.source_ips.clone(),
                        dest_ips: rule.destination_ips.clone(),
                        port_groups,
                    }]],
                });
            }
            offset += body.rules.len();
        }
        if !configured {
            continue;
        }
        // A configured direction always defaults to deny, even with no rules
        // or only TCP rules. Leave absent directions untouched.
        rules.push(FirewallRule {
            name: default_deny_name,
            action: RuleAction::Deny,
            direction,
            priority: i32::MAX,
            clauses: vec![vec![FirewallMatch {
                port_groups: vec![PortGroup {
                    protocol: FirewallProtocol::NonTcp,
                    ports: vec![],
                }],
                source_ips: vec![],
                dest_ips: vec![],
            }]],
        });
    }
    crate::firewall::RuleSet {
        rules,
        // Per-direction defaults are explicit rules; this flag is the legacy
        // Workload policy's bidirectional default.
        policy_attached: false,
    }
}

impl TryFrom<XdsTrafficPolicy> for TrafficPolicy {
    type Error = anyhow::Error;

    fn try_from(resource: XdsTrafficPolicy) -> Result<Self, Self::Error> {
        let policy = Self {
            ingress: resource
                .ingress
                .map(RuleSet::try_from)
                .transpose()
                .context("TrafficPolicy ingress")?,
            egress: resource
                .egress
                .map(RuleSet::try_from)
                .transpose()
                .context("TrafficPolicy egress")?,
        };
        policy.validate()?;
        Ok(policy)
    }
}

impl TryFrom<proto::RuleSet> for RuleSet {
    type Error = anyhow::Error;

    fn try_from(value: proto::RuleSet) -> Result<Self, Self::Error> {
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
            proto::Action::Allow => Action::Allow,
            proto::Action::Deny => Action::Deny,
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
        let port = value.port.map(u16::try_from).transpose()?;
        let end_port = value.end_port.map(u16::try_from).transpose()?;
        let range = match (port, end_port) {
            (None, None) => None,
            (Some(port), None) => Some(port..=port),
            (None, Some(end)) => Some(1..=end),
            (Some(start), Some(end)) => Some(start..=end),
        };
        Ok(Self { protocol, range })
    }
}

impl PortMatch {
    fn validate(&self) -> anyhow::Result<()> {
        if let Some(range) = &self.range {
            ensure!(
                self.protocol != proto::Protocol::Icmp,
                "ICMP cannot have a port constraint"
            );
            ensure!(
                *range.start() > 0 && *range.end() > 0,
                "port must be in 1..65535"
            );
            ensure!(range.start() <= range.end(), "reversed port range");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
