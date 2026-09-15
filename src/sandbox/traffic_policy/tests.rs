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
use crate::rbac::Direction;

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

fn policy(name: &str, egress: Option<Vec<proto::Rule>>) -> XdsTrafficPolicy {
    XdsTrafficPolicy {
        name: name.into(),
        priority: 1000,
        egress: egress.map(|rules| proto::PolicyRule { rules }),
        ingress: Some(proto::PolicyRule::default()),
        ..Default::default()
    }
}

fn evaluate(
    policies: Vec<XdsTrafficPolicy>,
    conn: &Connection,
) -> Result<(), AuthorizationRejectionError> {
    let policies = policies
        .into_iter()
        .map(TrafficPolicy::try_from)
        .collect::<anyhow::Result<Vec<_>>>()
        .unwrap();
    assert_tcp(&policies, conn).map(|_| ())
}

#[test]
fn native_policy_order_and_direction_defaults() {
    let conn = connection("10.1.0.1:1234", "192.0.2.1:443");
    assert!(evaluate(vec![], &conn).is_ok());
    assert!(evaluate(vec![policy("ingress-only", None)], &conn).is_ok());
    assert!(evaluate(vec![policy("empty-egress", Some(vec![]))], &conn).is_err());

    let allow = rule(proto::Action::Allow);
    let deny = rule(proto::Action::Deny);
    // Explicit match {} is a wildcard for both actions. The first rule wins.
    assert!(
        evaluate(
            vec![policy(
                "allow-first",
                Some(vec![allow.clone(), deny.clone()])
            )],
            &conn
        )
        .is_ok()
    );
    assert!(
        evaluate(
            vec![policy(
                "deny-first",
                Some(vec![deny.clone(), allow.clone()])
            )],
            &conn
        )
        .is_err()
    );
    // No per-policy default: an empty direction continues to the next policy.
    assert!(
        evaluate(
            vec![
                policy("empty", Some(vec![])),
                policy("allow", Some(vec![allow.clone()]))
            ],
            &conn
        )
        .is_ok()
    );
    let mut high = policy("higher-priority-deny", Some(vec![deny]));
    high.priority = 0;
    let low = policy("lower-priority-allow", Some(vec![allow]));
    assert_eq!(
        evaluate(vec![high, low], &conn),
        Err(AuthorizationRejectionError::ExplicitlyDenied(
            "".into(),
            "higher-priority-deny".into(),
        ))
    );
}

#[test]
fn native_tcp_matches_addresses_and_port_ranges() {
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
            evaluate(
                vec![policy("allow", Some(vec![rule.clone()]))],
                &connection(src, dst)
            )
            .is_ok(),
            allowed
        );
    }
}

#[test]
fn native_protocol_and_optional_port_semantics() {
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
                vec![policy("ports", Some(vec![rule]))],
                &connection("10.0.0.1:443", "192.0.2.1:443")
            )
            .is_ok(),
            allowed
        );
    }
}

#[test]
fn malformed_native_policy_is_rejected() {
    let valid = policy("valid", Some(vec![rule(proto::Action::Allow)]));
    let mut malformed = vec![];
    let mut bad = valid.clone();
    bad.name.clear();
    malformed.push(bad);
    let mut bad = valid.clone();
    bad.priority = -1;
    malformed.push(bad);
    let mut bad = valid.clone();
    bad.scope = 99;
    malformed.push(bad);
    let mut bad = valid.clone();
    bad.scope = proto::Scope::Namespace.into();
    malformed.push(bad);
    let mut bad = valid.clone();
    bad.ingress = None;
    bad.egress = None;
    malformed.push(bad);
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
async fn sandbox_rbac_matches_workload_policy_behavior() {
    use crate::rbac::{Authorization, RbacMatch};
    use crate::sandbox::discovery::tests::Fixture;
    use crate::state::{DemandProxyState, ProxyRbacContext};
    use crate::xds::agentio::sandbox::{Sandbox, sandbox::Attester};
    use crate::xds::kruise::networking::extensions::v1::TrafficPolicyMode;
    use std::sync::Arc;

    let f = Fixture::new();
    let state = DemandProxyState::new(
        f.state.clone(),
        None,
        Default::default(),
        Default::default(),
        crate::test_helpers::helpers::test_proxy_metrics(),
    );
    f.state.write().unwrap().policies.insert(
        "legacy-deny".into(),
        Authorization {
            name: "legacy-deny".into(),
            priority: Some(1000),
            mode: TrafficPolicyMode::Client,
            rules: vec![vec![vec![RbacMatch {
                not_destination_ips: vec!["0.0.0.0/0".parse().unwrap()],
                ..Default::default()
            }]]],
            ..Default::default()
        },
    );
    let mut ctx = ProxyRbacContext {
        conn: connection("10.1.0.1:1234", "192.0.2.1:443"),
        workload: f.workload.clone(),
        sandbox: None,
    };
    assert!(state.assert_rbac(&ctx).await.is_err());
    let before_discovery = ctx.clone();
    let mut resource = crate::xds::XdsResource {
        name: "sandbox-a".into(),
        resource: Sandbox {
            uid: "sandbox-a".into(),
            attester: Some(Attester {
                workload_uid: f.workload.uid.to_string(),
            }),
            traffic_policies: vec![policy(
                "native-allow",
                Some(vec![rule(proto::Action::Allow)]),
            )],
            ..Default::default()
        },
    };
    f.state
        .write()
        .unwrap()
        .sandboxes
        .update(resource.clone())
        .unwrap();
    ctx.sandbox = f.manager.fetch_attested_sandbox(&f.workload);
    assert!(state.assert_rbac(&ctx).await.is_ok());
    assert!(state.assert_rbac(&before_discovery).await.is_ok());

    // An explicit ALLOW bypasses ordinary Istio policies, just like Workload TrafficPolicy.
    f.state.write().unwrap().policies.insert(
        "istio-deny".into(),
        Authorization {
            name: "istio-deny".into(),
            action: RbacAction::Deny,
            mode: TrafficPolicyMode::Client,
            rules: vec![vec![]],
            ..Default::default()
        },
    );
    assert!(state.assert_rbac(&ctx).await.is_ok());

    // Updating policy changes authorization of the same context, including pre-discovery ones.
    resource.resource.traffic_policies =
        vec![policy("native-deny", Some(vec![rule(proto::Action::Deny)]))];
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
    updated.sandbox = f.manager.fetch_attested_sandbox(&f.workload);
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
    let accepted = f.manager.fetch_attested_sandbox(&f.workload).unwrap();
    let mut invalid = resource.clone();
    invalid.resource.attester.as_mut().unwrap().workload_uid = "different-workload".into();
    invalid.resource.traffic_policies[0]
        .egress
        .as_mut()
        .unwrap()
        .rules[0]
        .r#match = None;
    assert!(f.state.write().unwrap().sandboxes.update(invalid).is_err());
    assert!(Arc::ptr_eq(
        &accepted,
        &f.manager.fetch_attested_sandbox(&f.workload).unwrap()
    ));
    assert!(state.assert_rbac(&ctx).await.is_err());

    // With no native egress, skip legacy TrafficPolicy and consult Istio instead.
    f.publish("sandbox-a");
    assert_eq!(
        state.assert_rbac(&ctx).await,
        Err(AuthorizationRejectionError::ExplicitlyDenied(
            "".into(),
            "istio-deny".into(),
        ))
    );
    f.state
        .write()
        .unwrap()
        .policies
        .remove("istio-deny".into());
    assert!(state.assert_rbac(&ctx).await.is_ok());

    // Inbound selects ingress; egress ALLOW cannot override an ingress DENY.
    resource.resource.traffic_policies = vec![XdsTrafficPolicy {
        ingress: Some(proto::PolicyRule {
            rules: vec![rule(proto::Action::Deny)],
        }),
        ..policy("directions", Some(vec![rule(proto::Action::Allow)]))
    }];
    f.state
        .write()
        .unwrap()
        .sandboxes
        .update(resource.clone())
        .unwrap();
    assert!(state.assert_rbac(&ctx).await.is_ok());
    ctx.conn.direction = Direction::Inbound;
    assert!(state.assert_rbac(&ctx).await.is_err());
    resource.resource.traffic_policies[0]
        .ingress
        .as_mut()
        .unwrap()
        .rules[0]
        .action = proto::Action::Allow.into();
    f.state.write().unwrap().sandboxes.update(resource).unwrap();
    assert!(state.assert_rbac(&ctx).await.is_ok());

    // Removal restores the existing Workload policy path.
    f.state
        .write()
        .unwrap()
        .sandboxes
        .remove(&"sandbox-a".into());
    ctx.conn.direction = Direction::Outbound;
    assert!(state.assert_rbac(&ctx).await.is_err());
}

#[test]
fn native_firewall_matches_workload_rendering() {
    use crate::firewall::convert::build_firewall_ruleset;
    use crate::firewall::{IptBackend, NftBackend};
    use crate::rbac::{Authorization, PortRangeMatch, RbacMatch};
    use crate::xds::kruise::networking::extensions::v1::TrafficPolicyMode;

    let native = TrafficPolicy::try_from(XdsTrafficPolicy {
        name: "ns/dns".into(),
        namespace: "ns".into(),
        priority: 0,
        scope: proto::Scope::Namespace.into(),
        ingress: Some(proto::PolicyRule {
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
        ..Default::default()
    })
    .unwrap();
    let legacy = Authorization {
        name: "dns".into(),
        namespace: "ns".into(),
        priority: Some(0),
        action: RbacAction::Allow,
        mode: TrafficPolicyMode::Server,
        rules: vec![vec![vec![RbacMatch {
            source_ips: vec!["10.0.0.0/8".parse().unwrap()],
            destination_port_ranges: vec![PortRangeMatch {
                protocol: 2,
                range: 53..=53,
            }],
            ..Default::default()
        }]]],
        ..Default::default()
    };
    let native_rules = firewall_ruleset(&[native]);
    let legacy_rules = build_firewall_ruleset(vec![&legacy]);
    assert_eq!(native_rules, legacy_rules);
    assert_eq!(
        IptBackend::new().render_ruleset(&native_rules),
        IptBackend::new().render_ruleset(&legacy_rules)
    );
    assert_eq!(
        NftBackend::new().render_ruleset(&native_rules),
        NftBackend::new().render_ruleset(&legacy_rules)
    );

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
    let native = TrafficPolicy::try_from(policy("mixed", Some(vec![mixed]))).unwrap();
    let rules = firewall_ruleset(&[native]);
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
    let catch_all =
        TrafficPolicy::try_from(policy("deny-all", Some(vec![rule(proto::Action::Deny)]))).unwrap();
    let rules = firewall_ruleset(&[catch_all]);
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
    let resolve = || resolve_workload_firewall(&f.state.read().unwrap(), &info).unwrap();
    let initial = resolve();
    let mut changed = f.state.read().unwrap().policies.subscribe();
    let updater = ProxyStateUpdater::new_no_fetch(f.state.clone());
    let mut resource = XdsResource {
        name: "sandbox-a".into(),
        resource: Sandbox {
            uid: "sandbox-a".into(),
            attester: Some(Attester {
                workload_uid: f.workload.uid.to_string(),
            }),
            traffic_policies: vec![policy("deny", Some(vec![rule(proto::Action::Deny)]))],
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
    assert!(deny.0.policy_attached);
    assert_eq!(deny.0.rules[0].action, crate::firewall::RuleAction::Deny);

    resource.resource.traffic_policies[0]
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

    resource.resource.traffic_policies[0]
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
