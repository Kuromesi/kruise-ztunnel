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

use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::ops::RangeInclusive;
use tracing::warn;

use crate::rbac::{Authorization, RbacAction, RbacMatch, should_firewall_handle};
use crate::state::policy::PolicyStore;
use crate::state::workload::Workload;
use crate::state::{ProxyState, WorkloadInfo};
use crate::strng;
use crate::xds::kruise::networking::extensions::v1::TrafficPolicyMode;

use super::types::{
    Direction, FirewallMatch, FirewallProtocol, FirewallRule, PortGroup, RuleAction, RuleSet,
};

fn rbac_action_to_rule_action(action: RbacAction) -> RuleAction {
    match action {
        RbacAction::Allow => RuleAction::Allow,
        RbacAction::Deny => RuleAction::Deny,
    }
}

fn mode_to_direction(mode: TrafficPolicyMode) -> Direction {
    match mode {
        TrafficPolicyMode::Server => Direction::Inbound,
        TrafficPolicyMode::Client => Direction::Outbound,
    }
}

/// Map xDS protocol number to FirewallProtocol.
/// protocol=0 (ALL/unspecified) maps to NonTcp.
fn proto_i32_to_firewall_protocol(proto: i32) -> Option<FirewallProtocol> {
    match proto {
        0 => Some(FirewallProtocol::NonTcp),
        2 => Some(FirewallProtocol::Udp),
        3 => Some(FirewallProtocol::Icmp),
        4 => Some(FirewallProtocol::Sctp),
        _ => None,
    }
}

fn has_l7_fields(m: &RbacMatch) -> bool {
    !m.namespaces.is_empty()
        || !m.not_namespaces.is_empty()
        || !m.principals.is_empty()
        || !m.not_principals.is_empty()
        || !m.service_accounts.is_empty()
        || !m.not_service_accounts.is_empty()
}

/// Detect rule polarity: if ANY match in the rule has not_* fields, it's negative (deny).
fn is_negative_rule(clauses: &[Vec<RbacMatch>]) -> bool {
    clauses
        .iter()
        .any(|clause| clause.iter().any(|m| m.is_negative()))
}

/// Build port groups from xDS port ranges, filtering out TCP.
/// Returns None if all port ranges are TCP-only (nothing for the firewall).
fn firewall_port_groups(port_ranges: &[crate::rbac::PortRangeMatch]) -> Option<Vec<PortGroup>> {
    let mut groups: BTreeMap<FirewallProtocol, Vec<RangeInclusive<u16>>> = BTreeMap::new();
    let mut had_port_ranges = false;

    for pr in port_ranges {
        had_port_ranges = true;
        if !should_firewall_handle(pr.protocol) {
            continue;
        }
        let Some(fw_proto) = proto_i32_to_firewall_protocol(pr.protocol) else {
            warn!("Unknown firewall protocol {}, skipping", pr.protocol);
            continue;
        };
        groups.entry(fw_proto).or_default().push(pr.range.clone());
    }

    if had_port_ranges && groups.is_empty() {
        return None;
    }

    Some(if groups.is_empty() {
        vec![PortGroup {
            protocol: FirewallProtocol::NonTcp,
            ports: vec![],
        }]
    } else {
        groups
            .into_iter()
            .map(|(proto, ports)| PortGroup {
                protocol: proto,
                ports,
            })
            .collect()
    })
}

/// Convert an RbacMatch into a FirewallMatch.
/// Returns None if the match is TCP-only (nothing for the firewall to do).
fn rbac_match_to_firewall_match(m: &RbacMatch, negative: bool) -> Option<FirewallMatch> {
    let (src, dst, port_ranges) = if negative {
        (
            &m.not_source_ips,
            &m.not_destination_ips,
            &m.not_destination_port_ranges,
        )
    } else {
        (
            &m.source_ips,
            &m.destination_ips,
            &m.destination_port_ranges,
        )
    };

    let port_groups = firewall_port_groups(port_ranges)?;

    Some(FirewallMatch {
        source_ips: src.clone(),
        dest_ips: dst.clone(),
        port_groups,
    })
}

/// Convert RBAC clauses into firewall clauses.
/// Returns None if any non-empty clause is TCP-only (nothing to enforce),
/// or if no valid clauses remain.
fn convert_rule_clauses(
    clauses: &[Vec<RbacMatch>],
    negative: bool,
    policy_name: &str,
) -> Option<Vec<Vec<FirewallMatch>>> {
    let mut firewall_clauses: Vec<Vec<FirewallMatch>> = Vec::new();

    for clause in clauses {
        if clause.is_empty() {
            continue;
        }
        let firewall_matches: Vec<FirewallMatch> = clause
            .iter()
            .inspect(|m| {
                if has_l7_fields(m) {
                    warn!(
                        "Firewall rule '{}': L7 fields (namespace/principal/SA) ignored in netfilter rule",
                        policy_name
                    );
                }
            })
            .filter_map(|m| rbac_match_to_firewall_match(m, negative))
            .collect();

        if firewall_matches.is_empty() {
            return None;
        }
        firewall_clauses.push(firewall_matches);
    }

    if firewall_clauses.is_empty() {
        return None;
    }
    Some(firewall_clauses)
}

pub fn authorization_to_firewall_rules(auth: &Authorization) -> Vec<FirewallRule> {
    let direction = mode_to_direction(auth.mode);
    let priority = auth.priority.unwrap();
    let policy_name = auth.to_key();

    auth.rules
        .iter()
        .filter_map(|rule_clauses| {
            let negative = is_negative_rule(rule_clauses);
            let action = if negative {
                RuleAction::Deny
            } else {
                rbac_action_to_rule_action(auth.action)
            };
            let clauses = convert_rule_clauses(rule_clauses, negative, &policy_name)?;

            Some(FirewallRule {
                name: policy_name.clone(),
                action,
                direction,
                priority,
                clauses,
            })
        })
        .collect()
}

/// Collect firewall-applicable policies for a workload: namespace-scoped +
/// global + workload-selector attached, filtered to those with priority set.
pub fn collect_workload_policies<'a>(
    store: &'a PolicyStore,
    wl: &Workload,
) -> Vec<&'a Authorization> {
    let ns_keys = store.get_by_namespace(&wl.namespace);
    let global_keys = store.get_by_namespace(&strng::EMPTY);
    let wl_keys = wl.authorization_policies.iter();

    ns_keys
        .iter()
        .chain(global_keys.iter())
        .chain(wl_keys)
        .filter_map(|k| store.get(k))
        .filter(|auth| auth.priority.is_some())
        .collect()
}

pub fn hash_policies(policies: &[&Authorization]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for auth in policies {
        auth.hash(&mut hasher);
    }
    hasher.finish()
}

pub fn resolve_workload_policies<'a>(
    state: &'a ProxyState,
    info: &WorkloadInfo,
) -> Option<(Vec<&'a Authorization>, u64)> {
    let wl = state.workloads.find_by_info(info)?;
    let policies = collect_workload_policies(&state.policies, &wl);
    let policy_hash = hash_policies(&policies);
    Some((policies, policy_hash))
}

pub fn build_firewall_ruleset(mut policies: Vec<&Authorization>) -> RuleSet {
    policies.sort_by(|a, b| a.compare_traffic_policy(b));
    RuleSet {
        policy_attached: !policies.is_empty(),
        rules: policies
            .into_iter()
            .flat_map(authorization_to_firewall_rules)
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::{PortRangeMatch, RbacAction, RbacMatch, RbacScope};

    fn make_auth(
        action: RbacAction,
        mode: TrafficPolicyMode,
        priority: i32,
        rules: Vec<Vec<Vec<RbacMatch>>>,
    ) -> Authorization {
        Authorization {
            name: "test-policy".into(),
            namespace: "default".into(),
            scope: RbacScope::Namespace,
            action,
            rules,
            dry_run: false,
            priority: Some(priority),
            mode,
        }
    }

    fn one_rule(clauses: Vec<Vec<RbacMatch>>) -> Vec<Vec<Vec<RbacMatch>>> {
        vec![clauses]
    }

    fn single_match_rule(m: RbacMatch) -> Vec<Vec<Vec<RbacMatch>>> {
        one_rule(vec![vec![m]])
    }

    fn port(protocol: i32, range: RangeInclusive<u16>) -> PortRangeMatch {
        PortRangeMatch { protocol, range }
    }

    #[test]
    fn simple_udp_deny() {
        let auth = make_auth(
            RbacAction::Deny,
            TrafficPolicyMode::Server,
            10,
            single_match_rule(RbacMatch {
                destination_port_ranges: vec![port(2, 53..=53)],
                source_ips: vec!["10.0.0.0/8".parse().unwrap()],
                ..Default::default()
            }),
        );

        let rules = authorization_to_firewall_rules(&auth);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].action, RuleAction::Deny);
        assert_eq!(rules[0].direction, Direction::Inbound);
        assert_eq!(rules[0].priority, 10);
        // 1 clause with 1 match
        assert_eq!(rules[0].clauses.len(), 1);
        assert_eq!(rules[0].clauses[0].len(), 1);
        let m = &rules[0].clauses[0][0];
        assert_eq!(
            m.source_ips,
            vec!["10.0.0.0/8".parse::<ipnet::IpNet>().unwrap()]
        );
        assert_eq!(m.port_groups[0].protocol, FirewallProtocol::Udp);
        assert_eq!(m.port_groups[0].ports, vec![53..=53]);
    }

    #[test]
    fn multi_clause_merges_sources() {
        // Two OR'd source IPs in one clause + port clause
        // Should produce 1 rule with 2 clauses (AND'd), first clause has 2 matches (OR'd)
        let auth = make_auth(
            RbacAction::Deny,
            TrafficPolicyMode::Server,
            5,
            one_rule(vec![
                vec![
                    RbacMatch {
                        source_ips: vec!["10.0.0.0/8".parse().unwrap()],
                        ..Default::default()
                    },
                    RbacMatch {
                        source_ips: vec!["172.16.0.0/12".parse().unwrap()],
                        ..Default::default()
                    },
                ],
                vec![RbacMatch {
                    destination_port_ranges: vec![port(0, 53..=53)],
                    ..Default::default()
                }],
            ]),
        );

        let rules = authorization_to_firewall_rules(&auth);
        assert_eq!(rules.len(), 1);
        // 2 clauses (AND'd): source clause + port clause
        assert_eq!(rules[0].clauses.len(), 2);
        // First clause: 2 OR'd matches (two different source IPs)
        assert_eq!(rules[0].clauses[0].len(), 2);
        assert_eq!(
            rules[0].clauses[0][0].source_ips,
            vec!["10.0.0.0/8".parse::<ipnet::IpNet>().unwrap()]
        );
        assert_eq!(
            rules[0].clauses[0][1].source_ips,
            vec!["172.16.0.0/12".parse::<ipnet::IpNet>().unwrap()]
        );
        // Second clause: 1 match with port
        assert_eq!(rules[0].clauses[1].len(), 1);
        assert_eq!(
            rules[0].clauses[1][0].port_groups[0].protocol,
            FirewallProtocol::NonTcp
        );
        assert_eq!(rules[0].clauses[1][0].port_groups[0].ports, vec![53..=53]);
    }

    #[test]
    fn multiple_rules_or_ed() {
        let auth = make_auth(
            RbacAction::Allow,
            TrafficPolicyMode::Client,
            20,
            vec![
                vec![vec![RbacMatch {
                    destination_port_ranges: vec![port(0, 53..=53)],
                    ..Default::default()
                }]],
                vec![vec![RbacMatch {
                    destination_port_ranges: vec![port(0, 5353..=5353)],
                    ..Default::default()
                }]],
            ],
        );

        let rules = authorization_to_firewall_rules(&auth);
        // Two separate rules (OR'd at policy level)
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].clauses[0][0].port_groups[0].ports, vec![53..=53]);
        assert_eq!(
            rules[1].clauses[0][0].port_groups[0].ports,
            vec![5353..=5353]
        );
    }

    #[test]
    fn port_ranges_converted() {
        let auth = make_auth(
            RbacAction::Deny,
            TrafficPolicyMode::Server,
            0,
            single_match_rule(RbacMatch {
                destination_port_ranges: vec![port(2, 8000..=8080)],
                ..Default::default()
            }),
        );

        let rules = authorization_to_firewall_rules(&auth);
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0].clauses[0][0].port_groups[0].ports,
            vec![8000..=8080]
        );
    }

    #[test]
    fn empty_rules_produces_empty() {
        let auth = make_auth(RbacAction::Deny, TrafficPolicyMode::Server, 0, vec![]);
        assert!(authorization_to_firewall_rules(&auth).is_empty());
    }

    #[test]
    fn empty_clause_skipped() {
        let auth = make_auth(
            RbacAction::Deny,
            TrafficPolicyMode::Server,
            0,
            one_rule(vec![
                vec![],
                vec![RbacMatch {
                    destination_port_ranges: vec![port(0, 53..=53)],
                    ..Default::default()
                }],
            ]),
        );

        let rules = authorization_to_firewall_rules(&auth);
        assert_eq!(rules.len(), 1);
        // Empty clause produces no matches, only the port clause survives
        assert_eq!(rules[0].clauses.len(), 1);
        assert_eq!(rules[0].clauses[0][0].port_groups[0].ports, vec![53..=53]);
    }

    #[test]
    fn negative_tcp_only_rule_produces_no_firewall_rules() {
        let auth = make_auth(
            RbacAction::Deny,
            TrafficPolicyMode::Client,
            10,
            one_rule(vec![
                vec![RbacMatch {
                    not_destination_ips: vec![
                        "192.0.2.102/32".parse().unwrap(),
                        "198.51.100.103/32".parse().unwrap(),
                    ],
                    ..Default::default()
                }],
                vec![RbacMatch {
                    not_destination_port_ranges: vec![port(1, 0..=65535)],
                    ..Default::default()
                }],
            ]),
        );

        let rules = authorization_to_firewall_rules(&auth);
        assert!(
            rules.is_empty(),
            "TCP-only negative rule should produce no firewall rules, got: {:?}",
            rules
        );
    }

    #[test]
    fn mixed_protocols_produce_separate_port_groups() {
        let auth = make_auth(
            RbacAction::Deny,
            TrafficPolicyMode::Server,
            10,
            single_match_rule(RbacMatch {
                destination_port_ranges: vec![port(2, 53..=53), port(4, 443..=443)],
                ..Default::default()
            }),
        );

        let rules = authorization_to_firewall_rules(&auth);
        assert_eq!(rules.len(), 1);
        let m = &rules[0].clauses[0][0];
        assert_eq!(m.port_groups.len(), 2);
        assert_eq!(m.port_groups[0].protocol, FirewallProtocol::Udp);
        assert_eq!(m.port_groups[0].ports, vec![53..=53]);
        assert_eq!(m.port_groups[1].protocol, FirewallProtocol::Sctp);
        assert_eq!(m.port_groups[1].ports, vec![443..=443]);
    }
}
