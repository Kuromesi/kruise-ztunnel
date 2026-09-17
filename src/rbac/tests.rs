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

use super::*;
use crate::proxy::AuthorizationRejectionError;

fn connection(src: &str, dst: &str) -> Connection {
    Connection {
        src: src.parse().unwrap(),
        dst: dst.parse().unwrap(),
        src_identity: None,
        dst_network: "".into(),
        direction: Direction::Outbound,
    }
}

fn rule(action: proto::Action) -> proto::Rule {
    proto::Rule {
        action: action.into(),
        r#match: Some(proto::Match::default()),
    }
}

fn policy(egress: Option<Vec<proto::Rule>>) -> XdsTrafficPolicy {
    XdsTrafficPolicy {
        egress: egress.map(|rules| proto::RuleSet { rules }),
        ..Default::default()
    }
}

async fn check_policies(
    inline: Option<XdsTrafficPolicy>,
    policies: &[(&str, Option<&XdsTrafficPolicy>)],
    conn: &Connection,
) -> Result<(), AuthorizationRejectionError> {
    use crate::sandbox::discovery::tests::Fixture;
    use crate::state::{DemandProxyState, ProxyRbacContext};
    use crate::xds::agentio::sandbox::{PolicyReference, Sandbox, sandbox::Attester};

    let f = Fixture::new();
    {
        let mut state = f.state.write().unwrap();
        for (name, policy) in policies {
            if let Some(policy) = policy {
                state
                    .policies
                    .update(XdsResource {
                        name: (*name).into(),
                        resource: (*policy).clone(),
                    })
                    .unwrap();
            }
        }
        state
            .sandboxes
            .update(XdsResource {
                name: "sandbox-a".into(),
                resource: Sandbox {
                    uid: "sandbox-a".into(),
                    attester: Some(Attester {
                        workload_uid: f.workload.uid.to_string(),
                    }),
                    traffic_policy: inline,
                    policy_refs: HashMap::from([(
                        crate::xds::TRAFFIC_POLICY_TYPE.to_string(),
                        PolicyReference {
                            resource_names: policies
                                .iter()
                                .map(|(name, _)| (*name).into())
                                .collect(),
                        },
                    )]),
                    ..Default::default()
                },
            })
            .unwrap();
    }
    let state = DemandProxyState::new(
        f.state.clone(),
        None,
        Default::default(),
        Default::default(),
        crate::test_helpers::helpers::test_proxy_metrics(),
    );
    state
        .assert_rbac(&ProxyRbacContext {
            conn: conn.clone(),
            workload: f.workload,
            sandbox: None,
        })
        .await
}

async fn evaluate(
    policy: XdsTrafficPolicy,
    conn: &Connection,
) -> Result<(), AuthorizationRejectionError> {
    check_policies(Some(policy), &[], conn).await
}

#[tokio::test]
async fn native_policy_order_and_direction_defaults() {
    let mut conn = connection("10.1.0.1:1234", "192.0.2.1:443");
    assert_eq!(evaluate(policy(None), &conn).await, Ok(()));
    assert_eq!(
        evaluate(policy(Some(vec![])), &conn).await,
        Err(AuthorizationRejectionError::ExplicitlyDenied(
            crate::strng::EMPTY,
            "DEFAULT-DENY".into(),
        )),
    );

    let allow = rule(proto::Action::Allow);
    let deny = rule(proto::Action::Deny);
    // The first matching rule is terminal.
    assert_eq!(
        evaluate(policy(Some(vec![allow.clone(), deny.clone()])), &conn).await,
        Ok(()),
    );
    assert_eq!(
        evaluate(policy(Some(vec![deny, allow.clone()])), &conn).await,
        Err(AuthorizationRejectionError::ExplicitlyDenied(
            "inline".into(),
            "rule-0".into(),
        )),
    );
    // An earlier nonmatching rule must not introduce an intermediate default deny.
    let mut miss = rule(proto::Action::Deny);
    miss.r#match.as_mut().unwrap().ports = vec![proto::PortMatch {
        protocol: proto::Protocol::Tcp.into(),
        port: Some(80),
        end_port: None,
    }];
    assert_eq!(
        evaluate(policy(Some(vec![miss, allow])), &conn).await,
        Ok(()),
    );
    conn.direction = Direction::Inbound;
    assert_eq!(evaluate(policy(Some(vec![])), &conn).await, Ok(()));
    assert!(
        evaluate(
            XdsTrafficPolicy {
                ingress: Some(proto::RuleSet::default()),
                ..Default::default()
            },
            &conn
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn native_tcp_matches_addresses_and_port_ranges() {
    let rule = proto::Rule {
        action: proto::Action::Allow.into(),
        r#match: Some(proto::Match {
            source_ips: vec![
                proto::Address {
                    address: vec![10, 1, 2, 3],
                    length: 8,
                },
                proto::Address {
                    address: "2001:db8::123"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets()
                        .into(),
                    length: 32,
                },
            ],
            destination_ips: vec![proto::Address {
                address: vec![192, 0, 2, 0],
                length: 24,
            }],
            ports: vec![proto::PortMatch {
                protocol: proto::Protocol::Tcp.into(),
                port: Some(400),
                end_port: Some(450),
            }],
        }),
    };
    for (src, dst, allowed) in [
        ("10.9.0.1:1234", "192.0.2.1:400", true),
        ("[2001:db8:1::1]:1234", "192.0.2.2:450", true),
        ("11.0.0.1:1234", "192.0.2.1:443", false),
        ("10.9.0.1:1234", "198.51.100.1:443", false),
        ("10.9.0.1:1234", "192.0.2.1:451", false),
    ] {
        assert_eq!(
            evaluate(policy(Some(vec![rule.clone()])), &connection(src, dst))
                .await
                .is_ok(),
            allowed
        );
    }
}

#[tokio::test]
async fn native_protocol_and_optional_port_semantics() {
    for (protocol, port, end_port, allowed) in [
        (proto::Protocol::All, None, None, true),
        (proto::Protocol::Tcp, None, None, true),
        (proto::Protocol::Udp, None, None, false),
        (proto::Protocol::Icmp, None, None, false),
        (proto::Protocol::Sctp, None, None, false),
        (proto::Protocol::All, Some(443), None, true),
        (proto::Protocol::Tcp, Some(442), None, false),
        (proto::Protocol::Tcp, None, Some(443), true),
        (proto::Protocol::Tcp, None, Some(442), false),
    ] {
        let mut rule = rule(proto::Action::Allow);
        rule.r#match.as_mut().unwrap().ports = vec![proto::PortMatch {
            protocol: protocol.into(),
            port,
            end_port,
        }];
        assert_eq!(
            evaluate(
                policy(Some(vec![rule])),
                &connection("10.0.0.1:443", "192.0.2.1:443")
            )
            .await
            .is_ok(),
            allowed
        );
    }
}

#[test]
fn malformed_native_policy_is_rejected() {
    let valid = policy(Some(vec![rule(proto::Action::Allow)]));
    let mut malformed = vec![];
    let mut bad = valid.clone();
    bad.egress.as_mut().unwrap().rules[0].r#match = None;
    malformed.push(bad);
    let mut bad = valid.clone();
    bad.egress.as_mut().unwrap().rules[0].action = 99;
    malformed.push(bad);
    for address in [
        proto::Address {
            address: vec![],
            length: 0,
        },
        proto::Address {
            address: vec![0; 4],
            length: 33,
        },
        proto::Address {
            address: vec![0; 16],
            length: 129,
        },
    ] {
        let mut bad = valid.clone();
        bad.egress.as_mut().unwrap().rules[0]
            .r#match
            .as_mut()
            .unwrap()
            .source_ips
            .push(address);
        malformed.push(bad);
    }
    for (protocol, port, end_port) in [
        (99, None, None),
        (1, Some(0), None),
        (1, None, Some(65536)),
        (1, Some(100), Some(99)),
        (3, Some(80), None),
    ] {
        let mut bad = valid.clone();
        bad.egress.as_mut().unwrap().rules[0]
            .r#match
            .as_mut()
            .unwrap()
            .ports
            .push(proto::PortMatch {
                protocol,
                port,
                end_port,
            });
        malformed.push(bad);
    }
    for bad in malformed {
        assert!(TrafficPolicy::try_from(bad).is_err());
    }
}

#[tokio::test]
async fn sandbox_rbac_tracks_current_policies_and_binding() {
    use crate::sandbox::discovery::tests::Fixture;
    use crate::state::{DemandProxyState, ProxyRbacContext};
    use crate::xds::agentio::sandbox::{Sandbox, sandbox::Attester};
    use std::sync::Arc;

    let f = Fixture::new();
    let state = DemandProxyState::new(
        f.state.clone(),
        None,
        Default::default(),
        Default::default(),
        crate::test_helpers::helpers::test_proxy_metrics(),
    );

    // Shared policies only apply when referenced by a Sandbox.
    {
        let mut guard = f.state.write().unwrap();
        guard
            .policies
            .update(XdsResource {
                name: "trafficPolicies/unreferenced-deny".into(),
                resource: policy(Some(vec![rule(proto::Action::Deny)])),
            })
            .unwrap();
    }
    let mut ctx = ProxyRbacContext {
        conn: connection("10.1.0.1:1234", "192.0.2.1:443"),
        workload: f.workload.clone(),
        sandbox: None,
    };
    assert!(state.assert_rbac(&ctx).await.is_ok());
    let before_discovery = ctx.clone();
    let mut resource = crate::xds::XdsResource {
        name: "sandbox-a".into(),
        resource: Sandbox {
            uid: "sandbox-a".into(),
            attester: Some(Attester {
                workload_uid: f.workload.uid.to_string(),
            }),
            traffic_policy: Some(policy(Some(vec![rule(proto::Action::Allow)]))),
            ..Default::default()
        },
    };
    f.state
        .write()
        .unwrap()
        .sandboxes
        .update(resource.clone())
        .unwrap();
    ctx.sandbox = f.demand.fetch_sandbox(&f.workload);
    assert!(state.assert_rbac(&ctx).await.is_ok());
    assert!(state.assert_rbac(&before_discovery).await.is_ok());

    // Updating policy changes authorization of the same context, including pre-discovery ones.
    resource.resource.traffic_policy = Some(policy(Some(vec![rule(proto::Action::Deny)])));
    f.state
        .write()
        .unwrap()
        .sandboxes
        .update(resource.clone())
        .unwrap();
    assert!(state.assert_rbac(&ctx).await.is_err());
    assert!(state.assert_rbac(&before_discovery).await.is_err());

    // Keep connection tracking separate for different Sandbox identities, not policy versions.
    let mut updated = ctx.clone();
    updated.sandbox = f.demand.fetch_sandbox(&f.workload);
    assert!(!Arc::ptr_eq(
        ctx.sandbox.as_ref().unwrap(),
        updated.sandbox.as_ref().unwrap()
    ));
    let mut other = ctx.clone();
    other.sandbox = Some(Arc::new(crate::sandbox::discovery::Sandbox {
        uid: "sandbox-b".into(),
        ..(**ctx.sandbox.as_ref().unwrap()).clone()
    }));
    let contexts = std::collections::HashSet::from([ctx.clone(), updated, other]);
    assert_eq!(contexts.len(), 2);

    // Invalid policy + binding changes leave the accepted resource and binding intact.
    let accepted = f.demand.fetch_sandbox(&f.workload).unwrap();
    let mut invalid = resource.clone();
    invalid.resource.attester.as_mut().unwrap().workload_uid = "different-workload".into();
    invalid
        .resource
        .traffic_policy
        .as_mut()
        .unwrap()
        .egress
        .as_mut()
        .unwrap()
        .rules[0]
        .r#match = None;
    assert!(f.state.write().unwrap().sandboxes.update(invalid).is_err());
    assert!(Arc::ptr_eq(
        &accepted,
        &f.demand.fetch_sandbox(&f.workload).unwrap()
    ));
    assert!(state.assert_rbac(&ctx).await.is_err());

    // A Sandbox with no native rules allows traffic.
    f.publish("sandbox-a");
    assert!(state.assert_rbac(&ctx).await.is_ok());

    // Inbound selects ingress; egress ALLOW cannot override an ingress DENY.
    resource.resource.traffic_policy = Some(XdsTrafficPolicy {
        ingress: Some(proto::RuleSet {
            rules: vec![rule(proto::Action::Deny)],
        }),
        ..policy(Some(vec![rule(proto::Action::Allow)]))
    });
    f.state
        .write()
        .unwrap()
        .sandboxes
        .update(resource.clone())
        .unwrap();
    assert!(state.assert_rbac(&ctx).await.is_ok());
    ctx.conn.direction = Direction::Inbound;
    assert!(state.assert_rbac(&ctx).await.is_err());
    resource
        .resource
        .traffic_policy
        .as_mut()
        .unwrap()
        .ingress
        .as_mut()
        .unwrap()
        .rules[0]
        .action = proto::Action::Allow.into();
    f.state.write().unwrap().sandboxes.update(resource).unwrap();
    assert!(state.assert_rbac(&ctx).await.is_ok());

    // Removing the Sandbox restores the unconfigured state.
    f.state
        .write()
        .unwrap()
        .sandboxes
        .remove(&"sandbox-a".into());
    ctx.conn.direction = Direction::Outbound;
    assert!(state.assert_rbac(&ctx).await.is_ok());
    assert!(state.assert_rbac(&before_discovery).await.is_ok());
}

#[test]
fn native_firewall_rendering() {
    use crate::firewall::{
        Direction as FirewallDirection, FirewallMatch, FirewallProtocol, FirewallRule, IptBackend,
        NftBackend, PortGroup, RuleAction,
    };

    let native = TrafficPolicy::try_from(XdsTrafficPolicy {
        egress: Some(proto::RuleSet::default()),
        ingress: Some(proto::RuleSet {
            rules: vec![proto::Rule {
                action: proto::Action::Allow.into(),
                r#match: Some(proto::Match {
                    source_ips: vec![proto::Address {
                        address: vec![10, 0, 0, 0],
                        length: 8,
                    }],
                    ports: vec![proto::PortMatch {
                        protocol: proto::Protocol::Udp.into(),
                        port: Some(53),
                        end_port: None,
                    }],
                    ..Default::default()
                }),
            }],
        }),
    })
    .unwrap();
    let native_rules = firewall_ruleset(&native);
    assert_eq!(
        native_rules.rules[0],
        FirewallRule {
            name: "inline/rule-0".into(),
            action: RuleAction::Allow,
            direction: FirewallDirection::Inbound,
            priority: 0,
            clauses: vec![vec![FirewallMatch {
                source_ips: vec!["10.0.0.0/8".parse().unwrap()],
                dest_ips: vec![],
                port_groups: vec![PortGroup {
                    protocol: FirewallProtocol::Udp,
                    ports: vec![53..=53],
                }],
            }]],
        }
    );
    let ipt = IptBackend::new().render_ruleset(&native_rules);
    assert!(ipt.contains("-s 10.0.0.0/8 -p udp --dport 53 -j ACCEPT"));
    let nft = NftBackend::new().render_ruleset(&native_rules);
    assert!(nft.contains("ip saddr 10.0.0.0/8"));
    assert!(nft.contains("udp dport 53 accept"));

    // Protocol-only matches retain their wildcard ports. TCP stays in userspace.
    let mut mixed = rule(proto::Action::Deny);
    mixed.r#match.as_mut().unwrap().ports = vec![
        proto::PortMatch {
            protocol: proto::Protocol::Icmp.into(),
            port: None,
            end_port: None,
        },
        proto::PortMatch {
            protocol: proto::Protocol::Sctp.into(),
            port: None,
            end_port: None,
        },
        proto::PortMatch {
            protocol: proto::Protocol::Tcp.into(),
            port: None,
            end_port: None,
        },
    ];
    let native = TrafficPolicy::try_from(policy(Some(vec![mixed]))).unwrap();
    let rules = firewall_ruleset(&native);
    let groups = &rules.rules[0].clauses[0][0].port_groups;
    assert_eq!(groups.len(), 2);
    assert!(groups.iter().all(|g| g.ports.is_empty()));
    let ipt = IptBackend::new().render_ruleset(&rules);
    assert!(ipt.contains("-p icmp -j REJECT"));
    assert!(ipt.contains("-p sctp -j REJECT"));
    let nft = NftBackend::new().render_ruleset(&rules);
    assert!(nft.contains("icmp"));
    assert!(nft.contains("sctp"));

    // Explicit wildcard DENY is preserved, including when no port list is present.
    let catch_all = TrafficPolicy::try_from(policy(Some(vec![rule(proto::Action::Deny)]))).unwrap();
    let rules = firewall_ruleset(&catch_all);
    assert_eq!(rules.rules[0].action, crate::firewall::RuleAction::Deny);
    assert!(
        IptBackend::new()
            .render_ruleset(&rules)
            .contains("! -p tcp -j REJECT")
    );
}

#[test]
fn native_firewall_resolution_tracks_policy_updates_and_removal() {
    use crate::firewall::convert::resolve_workload_firewall;
    use crate::sandbox::discovery::tests::Fixture;
    use crate::state::WorkloadInfo;
    use crate::xds::agentio::sandbox::{Sandbox, sandbox::Attester};
    use crate::xds::{Handler, ProxyStateUpdater, XdsResource, XdsUpdate};

    let f = Fixture::new();
    let info = WorkloadInfo::new(
        f.workload.name.to_string(),
        f.workload.namespace.to_string(),
        f.workload.service_account.to_string(),
    );
    let resolve = || resolve_workload_firewall(&f.state.read().unwrap(), &info, None).unwrap();
    let initial = resolve();
    assert_eq!(initial.0, crate::firewall::RuleSet::default());
    let mut changed = f.state.read().unwrap().policies.subscribe();
    let updater = ProxyStateUpdater::new_no_fetch(f.state.clone());
    let mut resource = XdsResource {
        name: "sandbox-a".into(),
        resource: Sandbox {
            uid: "sandbox-a".into(),
            attester: Some(Attester {
                workload_uid: f.workload.uid.to_string(),
            }),
            traffic_policy: Some(policy(Some(vec![rule(proto::Action::Deny)]))),
            ..Default::default()
        },
    };
    let publish =
        |resource| updater.handle(Box::new(&mut std::iter::once(XdsUpdate::Update(resource))));
    publish(resource.clone()).unwrap();
    assert!(changed.has_changed().unwrap());
    changed.borrow_and_update();
    let deny = resolve();
    assert_ne!(initial.1, deny.1);
    assert_eq!(deny.0.rules.len(), 2);
    assert_eq!(deny.0.rules[0].action, crate::firewall::RuleAction::Deny);

    resource
        .resource
        .traffic_policy
        .as_mut()
        .unwrap()
        .egress
        .as_mut()
        .unwrap()
        .rules[0]
        .action = proto::Action::Allow.into();
    publish(resource.clone()).unwrap();
    let allow = resolve();
    assert_ne!(deny.1, allow.1);
    assert_eq!(allow.0.rules[0].action, crate::firewall::RuleAction::Allow);
    changed.borrow_and_update();

    resource
        .resource
        .traffic_policy
        .as_mut()
        .unwrap()
        .egress
        .as_mut()
        .unwrap()
        .rules[0]
        .r#match = None;
    assert!(publish(resource).is_err());
    assert!(!changed.has_changed().unwrap());
    assert_eq!(resolve(), allow);

    updater
        .handle(Box::new(&mut std::iter::once(
            XdsUpdate::<Sandbox>::Remove("sandbox-a".into()),
        )))
        .unwrap();
    assert!(changed.has_changed().unwrap());
    assert_eq!(resolve(), initial);
}

#[test]
fn native_firewall_preserves_order_and_direction_presence() {
    use crate::firewall::{Direction as FirewallDirection, IptBackend, NftBackend};

    assert!(firewall_ruleset(&TrafficPolicy::default()).rules.is_empty());
    for inbound in [false, true] {
        let mut wire = policy(Some(vec![]));
        if inbound {
            wire.ingress = wire.egress.take();
        }
        let rules = firewall_ruleset(&TrafficPolicy::try_from(wire).unwrap());
        assert_eq!(rules.rules.len(), 1);
        assert_eq!(
            rules.rules[0].direction,
            if inbound {
                FirewallDirection::Inbound
            } else {
                FirewallDirection::Outbound
            }
        );
        let ipt = IptBackend::new().render_ruleset(&rules);
        assert_eq!(
            ipt.contains("-A ISTIO_FW_FILTER_IN ! -p tcp -j REJECT"),
            inbound
        );
        assert_eq!(
            ipt.contains("-A ISTIO_FW_FILTER_OUT ! -p tcp -j REJECT"),
            !inbound
        );
        let nft = NftBackend::new().render_ruleset(&rules);
        let (input, output) = nft.split_once("chain zt_policy_output").unwrap();
        assert_eq!(input.contains("meta l4proto != tcp reject"), inbound);
        assert_eq!(output.contains("meta l4proto != tcp reject"), !inbound);
    }

    // Backend sorting must retain the published rule order.
    for allow_first in [true, false] {
        let actions = if allow_first {
            [proto::Action::Allow, proto::Action::Deny]
        } else {
            [proto::Action::Deny, proto::Action::Allow]
        };
        let mut wire = policy(Some(actions.into_iter().map(rule).collect()));
        let rules = &mut wire.egress.as_mut().unwrap().rules;
        for rule in rules.iter_mut() {
            rule.r#match.as_mut().unwrap().ports = vec![proto::PortMatch {
                protocol: proto::Protocol::Udp.into(),
                port: Some(53),
                end_port: None,
            }];
        }
        let rules = firewall_ruleset(&TrafficPolicy::try_from(wire).unwrap());
        let ipt = IptBackend::new().render_ruleset(&rules);
        assert_eq!(
            ipt.find("--dport 53 -j ACCEPT").unwrap() < ipt.find("--dport 53 -j REJECT").unwrap(),
            allow_first,
        );
        let nft = NftBackend::new().render_ruleset(&rules);
        assert_eq!(
            nft.find("udp dport 53 accept").unwrap() < nft.find("udp dport 53 reject").unwrap(),
            allow_first,
        );
    }
}

#[tokio::test]
async fn shared_policy_chain_precedence_missing_and_direction_defaults() {
    let conn = connection("10.1.0.1:1234", "192.0.2.1:443");
    let empty = policy(Some(vec![]));
    let absent = policy(None);
    let allow = policy(Some(vec![rule(proto::Action::Allow)]));
    let deny = policy(Some(vec![rule(proto::Action::Deny)]));
    let evaluate = async |chain: Vec<Option<&XdsTrafficPolicy>>| {
        let names: Vec<_> = (0..chain.len())
            .map(|index| format!("trafficPolicies/{index}"))
            .collect();
        let policies: Vec<_> = names
            .iter()
            .zip(chain)
            .map(|(name, policy)| (name.as_str(), policy))
            .collect();
        check_policies(None, &policies, &conn).await
    };
    assert_eq!(evaluate(vec![]).await, Ok(()));
    assert_eq!(evaluate(vec![Some(&absent)]).await, Ok(()));
    assert_eq!(evaluate(vec![Some(&empty), Some(&allow)]).await, Ok(()));
    assert_eq!(evaluate(vec![Some(&allow), Some(&deny)]).await, Ok(()));
    assert!(evaluate(vec![Some(&deny), Some(&allow)]).await.is_err());
    assert!(evaluate(vec![Some(&empty), Some(&absent)]).await.is_err());
    assert!(evaluate(vec![None, Some(&allow)]).await.is_err());
    assert_eq!(evaluate(vec![Some(&allow), None]).await, Ok(()));
    assert!(evaluate(vec![Some(&empty), None]).await.is_err());

    // The same chain semantics must reach both non-TCP backends.
    let empty = TrafficPolicy::try_from(empty).unwrap();
    let allow = TrafficPolicy::try_from(allow).unwrap();
    let deny = TrafficPolicy::try_from(deny).unwrap();
    let flat = TrafficPolicy::try_from(policy(Some(vec![
        rule(proto::Action::Allow),
        rule(proto::Action::Deny),
    ])))
    .unwrap();
    let chain = firewall_rulesets(
        [Some(&empty), Some(&allow), Some(&deny)]
            .into_iter()
            .map(|p| ("inline", p)),
    );
    let mut expected = firewall_ruleset(&flat);
    // The flat rule sequence has different per-policy diagnostic indices.
    for (rule, actual) in expected.rules.iter_mut().zip(&chain.rules) {
        rule.name = actual.name.clone();
    }
    assert_eq!(
        crate::firewall::IptBackend::new().render_ruleset(&chain),
        crate::firewall::IptBackend::new().render_ruleset(&expected)
    );
    assert_eq!(
        crate::firewall::NftBackend::new().render_ruleset(&chain),
        crate::firewall::NftBackend::new().render_ruleset(&expected)
    );
    let missing = firewall_rulesets(
        [Some(&empty), None, Some(&allow)]
            .into_iter()
            .map(|p| ("inline", p)),
    );
    assert_eq!(
        missing.rules.len(),
        2,
        "missing policy denies both unknown directions without reaching the later ALLOW"
    );
    assert!(
        missing
            .rules
            .iter()
            .all(|r| r.action == crate::firewall::RuleAction::Deny)
    );
}

#[tokio::test]
async fn shared_policy_updates_recheck_sandbox_context_without_replacing_sandbox() {
    use crate::sandbox::discovery::tests::Fixture;
    use crate::state::{DemandProxyState, ProxyRbacContext, WorkloadInfo};
    use crate::xds::agentio::sandbox::{PolicyReference, Sandbox, sandbox::Attester};
    use crate::xds::{Handler, ProxyStateUpdater, TRAFFIC_POLICY_TYPE, XdsUpdate};
    let f = Fixture::new();
    let state = DemandProxyState::new(
        f.state.clone(),
        None,
        Default::default(),
        Default::default(),
        crate::test_helpers::helpers::test_proxy_metrics(),
    );
    let name: Strng = "namespaces/ns/trafficPolicies/shared".into();
    for id in ["sandbox-a", "sandbox-b"] {
        f.state
            .write()
            .unwrap()
            .sandboxes
            .update(XdsResource {
                name: id.into(),
                resource: Sandbox {
                    uid: id.into(),
                    attester: Some(Attester {
                        workload_uid: f.workload.uid.to_string(),
                    }),
                    policy_refs: HashMap::from([(
                        TRAFFIC_POLICY_TYPE.to_string(),
                        PolicyReference {
                            resource_names: vec![name.to_string()],
                        },
                    )]),
                    ..Default::default()
                },
            })
            .unwrap();
    }
    let sandbox = f.demand.fetch_sandbox(&f.workload).unwrap();
    let ctx = ProxyRbacContext {
        conn: connection("10.1.0.1:1234", "192.0.2.1:443"),
        workload: f.workload.clone(),
        sandbox: Some(sandbox.clone()),
    };
    let info = WorkloadInfo {
        name: f.workload.name.to_string(),
        namespace: f.workload.namespace.to_string(),
        service_account: f.workload.service_account.to_string(),
    };
    assert!(state.assert_rbac(&ctx).await.is_err());
    let updater = ProxyStateUpdater::new_no_fetch(f.state.clone());
    let update = |action| {
        XdsUpdate::Update(XdsResource {
            name: name.clone(),
            resource: policy(Some(vec![rule(action)])),
        })
    };
    updater
        .handle(Box::new(&mut std::iter::once(update(proto::Action::Allow))))
        .unwrap();
    assert!(state.assert_rbac(&ctx).await.is_ok());
    let initial_hash =
        crate::firewall::convert::resolve_workload_firewall(&f.state.read().unwrap(), &info, None)
            .unwrap()
            .1;
    {
        let guard = f.state.read().unwrap();
        let a = guard.sandboxes.get(&"sandbox-a".into()).unwrap();
        let b = guard.sandboxes.get(&"sandbox-b".into()).unwrap();
        assert!(std::ptr::eq(
            a.traffic_policies(&guard.policies)
                .next()
                .unwrap()
                .1
                .unwrap(),
            b.traffic_policies(&guard.policies)
                .next()
                .unwrap()
                .1
                .unwrap()
        ));
    }
    updater
        .handle(Box::new(&mut std::iter::once(update(proto::Action::Deny))))
        .unwrap();
    assert!(state.assert_rbac(&ctx).await.is_err());
    assert!(Arc::ptr_eq(
        &sandbox,
        &f.demand.fetch_sandbox(&f.workload).unwrap()
    ));
    let updated_hash =
        crate::firewall::convert::resolve_workload_firewall(&f.state.read().unwrap(), &info, None)
            .unwrap()
            .1;
    assert_ne!(initial_hash, updated_hash);
    let invalid = XdsUpdate::Update(XdsResource {
        name: name.clone(),
        resource: policy(Some(vec![proto::Rule {
            action: 99,
            r#match: None,
        }])),
    });
    assert!(
        updater
            .handle(Box::new(&mut std::iter::once(invalid)))
            .is_err()
    );
    assert!(state.assert_rbac(&ctx).await.is_err());
    updater
        .handle(Box::new(&mut std::iter::once(update(proto::Action::Allow))))
        .unwrap();
    let removed: XdsUpdate<XdsTrafficPolicy> = XdsUpdate::Remove(name.clone());
    updater
        .handle(Box::new(&mut std::iter::once(removed)))
        .unwrap();
    assert!(state.assert_rbac(&ctx).await.is_err());
    updater
        .handle(Box::new(&mut std::iter::once(update(proto::Action::Allow))))
        .unwrap();
    assert!(state.assert_rbac(&ctx).await.is_ok());
}

#[test]
fn sandbox_notifications_ignore_non_policy_updates_and_handle_partial_batches() {
    use crate::sandbox::discovery::tests::Fixture;
    use crate::xds::agentio::sandbox::{
        EgressRouting, PolicyReference, Sandbox, SandboxState, sandbox::Attester,
    };
    use crate::xds::{Handler, ProxyStateUpdater, XdsUpdate};
    let f = Fixture::new();
    let updater = ProxyStateUpdater::new_no_fetch(f.state.clone());
    let mut changes = f.state.read().unwrap().policies.subscribe();
    let mut resource = XdsResource {
        name: "a".into(),
        resource: Sandbox {
            uid: "a".into(),
            attester: Some(Attester {
                workload_uid: f.workload.uid.to_string(),
            }),
            ..Default::default()
        },
    };
    let publish = |r| updater.handle(Box::new(&mut std::iter::once(XdsUpdate::Update(r))));
    publish(resource.clone()).unwrap();
    assert!(changes.has_changed().unwrap());
    changes.borrow_and_update();
    publish(resource.clone()).unwrap();
    resource.resource.state = SandboxState::Paused.into();
    resource.resource.egress_routing = Some(EgressRouting::default());
    publish(resource.clone()).unwrap();
    assert!(
        !changes.has_changed().unwrap(),
        "lifecycle/routing updates must not recheck traffic policies"
    );
    resource.resource.policy_refs.insert(
        crate::xds::TRAFFIC_POLICY_TYPE.to_string(),
        PolicyReference {
            resource_names: vec!["trafficPolicies/shared".into()],
        },
    );
    publish(resource.clone()).unwrap();
    assert!(changes.has_changed().unwrap());
    changes.borrow_and_update();
    resource.resource.attester = None;
    let mut invalid = resource.clone();
    invalid.resource.uid = "wrong-name".into();
    let mut batch = [
        XdsUpdate::Update(resource.clone()),
        XdsUpdate::Update(invalid),
    ]
    .into_iter();
    assert!(updater.handle(Box::new(&mut batch)).is_err());
    assert!(
        changes.has_changed().unwrap(),
        "accepted binding change must notify even when another update fails"
    );
    changes.borrow_and_update();
    updater
        .handle(Box::new(&mut std::iter::once(
            XdsUpdate::<Sandbox>::Remove("a".into()),
        )))
        .unwrap();
    assert!(changes.has_changed().unwrap());
    changes.borrow_and_update();
    updater
        .handle(Box::new(&mut std::iter::once(
            XdsUpdate::<Sandbox>::Remove("a".into()),
        )))
        .unwrap();
    assert!(!changes.has_changed().unwrap());
}

#[tokio::test]
async fn shared_policy_diagnostics_keep_resource_name_and_local_rule_index() {
    let conn = connection("10.1.0.1:1234", "192.0.2.1:443");
    let name = "namespaces/ns/trafficPolicies/deny-web";
    let deny = policy(Some(vec![rule(proto::Action::Deny)]));
    assert_eq!(
        check_policies(None, &[(name, Some(&deny))], &conn).await,
        Err(AuthorizationRejectionError::ExplicitlyDenied(
            name.into(),
            "rule-0".into(),
        )),
    );
    assert_eq!(
        check_policies(None, &[(name, None)], &conn).await,
        Err(AuthorizationRejectionError::ExplicitlyDenied(
            name.into(),
            "policy-unavailable".into(),
        )),
    );
    let firewall = firewall_rulesets([(name, None)].into_iter());
    assert!(
        firewall
            .rules
            .iter()
            .all(|r| r.name == format!("{name}/policy-unavailable"))
    );
}

#[test]
fn unchanged_firewall_hash_skips_build_with_and_without_sandbox() {
    use crate::firewall::convert::resolve_workload_firewall;
    use crate::sandbox::discovery::tests::Fixture;
    use crate::state::WorkloadInfo;
    let f = Fixture::new();
    let info = WorkloadInfo::new(
        f.workload.name.to_string(),
        f.workload.namespace.to_string(),
        f.workload.service_account.to_string(),
    );
    let check = || {
        let guard = f.state.read().unwrap();
        let (_, hash) = resolve_workload_firewall(&guard, &info, None).unwrap();
        assert!(resolve_workload_firewall(&guard, &info, Some(hash)).is_none());
        assert!(resolve_workload_firewall(&guard, &info, Some(hash.wrapping_add(1))).is_some());
    };
    check();
    f.publish("a");
    check();
}

#[tokio::test]
async fn sandbox_references_recheck_tcp_and_firewall() {
    use crate::proxy::AuthorizationRejectionError;
    use crate::sandbox::discovery::tests::Fixture;
    use crate::state::{DemandProxyState, ProxyRbacContext, WorkloadInfo};
    use crate::xds::agentio::sandbox::{PolicyReference, Sandbox, sandbox::Attester};
    use crate::xds::{Handler, ProxyStateUpdater, TRAFFIC_POLICY_TYPE, XdsUpdate};

    let f = Fixture::new();
    let state = DemandProxyState::new(
        f.state.clone(),
        None,
        Default::default(),
        Default::default(),
        crate::test_helpers::helpers::test_proxy_metrics(),
    );
    let updater = ProxyStateUpdater::new_no_fetch(f.state.clone());
    let mut notifications = f.state.read().unwrap().policies.subscribe();
    let names = ["trafficPolicies/allow", "trafficPolicies/deny"];
    let sandbox = |refs: Vec<String>| Sandbox {
        uid: "sandbox-a".into(),
        attester: Some(Attester {
            workload_uid: f.workload.uid.to_string(),
        }),
        policy_refs: HashMap::from([(
            TRAFFIC_POLICY_TYPE.to_string(),
            PolicyReference {
                resource_names: refs,
            },
        )]),
        ..Default::default()
    };
    let publish = |refs: &[&str]| {
        let resource = XdsUpdate::Update(XdsResource {
            name: "sandbox-a".into(),
            resource: sandbox(refs.iter().map(|s| s.to_string()).collect()),
        });
        updater.handle(Box::new(&mut std::iter::once(resource)))
    };
    // The connection was opened before its Sandbox was discovered.
    let mut ctx = ProxyRbacContext {
        conn: connection("10.1.0.1:1234", "192.0.2.1:443"),
        workload: f.workload.clone(),
        sandbox: None,
    };
    let info = WorkloadInfo {
        name: f.workload.name.to_string(),
        namespace: f.workload.namespace.to_string(),
        service_account: f.workload.service_account.to_string(),
    };
    let firewall = || {
        crate::firewall::convert::resolve_workload_firewall(&f.state.read().unwrap(), &info, None)
            .unwrap()
    };

    assert!(state.assert_rbac(&ctx).await.is_ok());
    assert!(firewall().0.rules.is_empty());
    publish(&names).unwrap();
    assert!(notifications.has_changed().unwrap());
    notifications.borrow_and_update();
    assert_eq!(
        state.assert_rbac(&ctx).await,
        Err(AuthorizationRejectionError::ExplicitlyDenied(
            names[0].into(),
            "policy-unavailable".into(),
        )),
    );
    let missing_hash = firewall().1;
    for (name, action) in names
        .iter()
        .zip([proto::Action::Allow, proto::Action::Deny])
    {
        let resource = XdsUpdate::Update(XdsResource {
            name: (*name).into(),
            resource: XdsTrafficPolicy {
                ingress: Some(proto::RuleSet {
                    rules: vec![rule(action)],
                }),
                egress: Some(proto::RuleSet {
                    rules: vec![rule(action)],
                }),
            },
        });
        updater
            .handle(Box::new(&mut std::iter::once(resource)))
            .unwrap();
    }
    assert!(state.assert_rbac(&ctx).await.is_ok());
    ctx.conn.direction = Direction::Inbound;
    assert!(state.assert_rbac(&ctx).await.is_ok());
    let (allowed, allowed_hash) = firewall();
    assert_ne!(missing_hash, allowed_hash);
    assert_eq!(allowed.rules[0].action, crate::firewall::RuleAction::Allow);
    notifications.borrow_and_update();
    publish(&[names[1], names[0]]).unwrap();
    assert!(
        notifications.has_changed().unwrap(),
        "reference-only changes must trigger rechecks"
    );
    assert_eq!(
        state.assert_rbac(&ctx).await,
        Err(AuthorizationRejectionError::ExplicitlyDenied(
            names[1].into(),
            "rule-0".into(),
        )),
    );
    ctx.conn.direction = Direction::Outbound;
    assert!(state.assert_rbac(&ctx).await.is_err());
    let (denied, denied_hash) = firewall();
    assert_ne!(allowed_hash, denied_hash);
    assert_eq!(denied.rules[0].action, crate::firewall::RuleAction::Deny);
    assert!(
        publish(&[names[0], names[0]]).is_err(),
        "reject duplicate references"
    );
    assert!(
        state.assert_rbac(&ctx).await.is_err(),
        "invalid Sandbox update must retain previous references"
    );
    publish(&[]).unwrap();
    assert!(state.assert_rbac(&ctx).await.is_ok());
    assert!(firewall().0.rules.is_empty());
}
