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
use crate::state::workload::Workload;
use crate::state::{DemandProxyState, ProxyState};
use crate::test_helpers::test_default_workload;
use crate::xds::agentio::sandbox::sandbox::Attester;
use std::sync::RwLock;

pub(crate) struct Fixture {
    pub state: Arc<RwLock<ProxyState>>,
    pub demand: DemandProxyState,
    pub workload: Arc<Workload>,
}

impl Fixture {
    pub fn new() -> Self {
        let workload = Arc::new(Workload {
            uid: "workload-uid".into(),
            name: "pod".into(),
            namespace: "ns".into(),
            node: "node-a".into(),
            ..test_default_workload()
        });
        let state = Arc::new(RwLock::new(ProxyState::new(None)));
        state.write().unwrap().workloads.insert(workload.clone());
        let demand = DemandProxyState::new(
            state.clone(),
            None,
            Default::default(),
            Default::default(),
            Arc::new(crate::proxy::Metrics::new(
                &mut prometheus_client::registry::Registry::default(),
            )),
        );
        Self {
            state,
            demand,
            workload,
        }
    }

    pub fn bind_policies(&self, names: &[&str]) {
        let mut state = self.state.write().unwrap();
        let mut workload = (*state.workloads.find_uid(&self.workload.uid).unwrap()).clone();
        workload.traffic_policy_refs = Some(names.iter().map(|name| Strng::from(*name)).collect());
        state.workloads.insert(Arc::new(workload));
    }

    pub fn publish(&self, id: &str) {
        self.state
            .write()
            .unwrap()
            .sandboxes
            .update(resource(id, "workload-uid"))
            .unwrap();
    }
}

fn resource(id: &str, workload_uid: &str) -> XdsResource<XdsSandbox> {
    XdsResource {
        name: id.into(),
        resource: XdsSandbox {
            uid: id.into(),
            attester: Some(Attester {
                workload_uid: workload_uid.into(),
            }),
            ..Default::default()
        },
    }
}

#[test]
fn unsupported_extension_retains_last_accepted_sandbox() {
    let mut store = SandboxStore::default();
    store.update(resource("sandbox", "original")).unwrap();
    let mut update = resource("sandbox", "replacement");
    update.resource.extensions.push(prost_types::Any {
        type_url: "type.googleapis.com/unknown.Policy".into(),
        value: Vec::new(),
    });
    assert!(store.update(update).is_err());
    assert_eq!(
        store
            .get(&"sandbox".into())
            .unwrap()
            .workload_uid
            .as_deref(),
        Some("original")
    );
}

#[test]
fn config_dump_includes_sandbox_bindings_and_named_traffic_policies() {
    use crate::xds::agentio::security::{
        TrafficPolicy as XdsTrafficPolicy, traffic_policy as proto,
    };
    use serde_json::json;

    let mut state = ProxyState::new(None);
    let policy = XdsTrafficPolicy {
        egress: Some(proto::RuleSet {
            rules: vec![proto::Rule {
                action: proto::Action::Deny.into(),
                r#match: Some(proto::Match {
                    destination_ips: vec![proto::Address {
                        address: vec![10, 0, 0, 0],
                        length: 8,
                    }],
                    ports: vec![proto::PortMatch {
                        protocol: proto::Protocol::Tcp.into(),
                        port: Some(80),
                        end_port: Some(90),
                    }],
                    ..Default::default()
                }),
            }],
        }),
        ..Default::default()
    };
    let names = ["trafficPolicies/z", "trafficPolicies/a"];
    for name in names {
        state
            .policies
            .update(XdsResource {
                name: name.into(),
                resource: policy.clone(),
            })
            .unwrap();
    }
    for id in ["sandbox-z", "sandbox-a"] {
        let mut sandbox = resource(id, "workload-uid");
        sandbox.resource.traffic_policy = Some(policy.clone());
        state.sandboxes.update(sandbox).unwrap();
    }

    let dump = serde_json::to_value(&state).unwrap();
    let sandbox = &dump["sandboxes"][0];
    assert_eq!(sandbox["uid"], "sandbox-a");
    assert_eq!(dump["sandboxes"][1]["uid"], "sandbox-z");
    assert_eq!(sandbox["workloadUid"], "workload-uid");
    // Resource output is sorted; policy references retain evaluation order.
    assert!(sandbox.get("trafficPolicyRefs").is_none());
    assert_eq!(dump["trafficPolicies"][0]["name"], names[1]);
    assert_eq!(dump["trafficPolicies"][1]["name"], names[0]);
    let rule = json!({
        "action": "Deny",
        "sourceIps": [],
        "destinationIps": ["10.0.0.0/8"],
        "ports": [{"protocol": "TCP", "range": {"start": 80, "end": 90}}]
    });
    assert_eq!(sandbox["trafficPolicy"]["egress"]["rules"][0], rule);
    assert_eq!(dump["trafficPolicies"][0]["egress"]["rules"][0], rule);

    state.sandboxes.remove(&"sandbox-a".into());
    state.policies.remove(&names[1].into());
    let dump = serde_json::to_value(&state).unwrap();
    assert_eq!(dump["sandboxes"].as_array().unwrap().len(), 1);
    assert_eq!(dump["sandboxes"][0]["uid"], "sandbox-z");
    assert_eq!(dump["trafficPolicies"].as_array().unwrap().len(), 1);
    assert_eq!(dump["trafficPolicies"][0]["name"], names[0]);
}

#[test]
fn sandboxes_are_grouped_by_workload_uid() {
    let f = Fixture::new();
    let second = Workload {
        uid: "workload-2".into(),
        ..f.workload.as_ref().clone()
    };
    f.state
        .write()
        .unwrap()
        .sandboxes
        .update(resource("sandbox-b", &second.uid))
        .unwrap();
    assert!(f.demand.fetch_sandbox(&f.workload).is_none());
    f.publish("sandbox-a");
    let sandbox = f.demand.fetch_sandbox(&f.workload).unwrap();
    assert_eq!(sandbox.uid, "sandbox-a");
    assert_eq!(sandbox.workload_uid.as_ref(), Some(&f.workload.uid));
    assert_eq!(
        f.demand
            .fetch_sandbox(&second)
            .map(|sandbox| sandbox.uid.clone())
            .as_deref(),
        Some("sandbox-b")
    );
}

#[test]
fn multiple_sandboxes_use_the_first_discovered_binding() {
    let f = Fixture::new();
    f.publish("sandbox-a");
    f.publish("sandbox-b");
    // Ordinary updates preserve selection order and do not duplicate bindings.
    f.publish("sandbox-a");
    assert_eq!(
        f.demand
            .fetch_sandbox(&f.workload)
            .map(|sandbox| sandbox.uid.clone())
            .as_deref(),
        Some("sandbox-a")
    );
    assert_eq!(
        f.state
            .read()
            .unwrap()
            .sandboxes
            .get_by_workload(&f.workload.uid)
            .iter()
            .map(|sandbox| sandbox.uid.clone())
            .collect::<Vec<_>>(),
        &[Strng::from("sandbox-a"), Strng::from("sandbox-b")]
    );
    f.state
        .write()
        .unwrap()
        .sandboxes
        .remove(&"sandbox-a".into());
    assert_eq!(
        f.demand
            .fetch_sandbox(&f.workload)
            .map(|sandbox| sandbox.uid.clone())
            .as_deref(),
        Some("sandbox-b")
    );
}

#[test]
fn invalid_update_preserves_previous_resource_and_binding() {
    let f = Fixture::new();
    f.publish("sandbox-a");
    let previous = f.state.read().unwrap().sandboxes.resources[&Strng::from("sandbox-a")].clone();
    let mut invalid = resource("sandbox-a", "different-workload");
    invalid.resource.uid = "sandbox-b".into();
    assert!(f.state.write().unwrap().sandboxes.update(invalid).is_err());
    let mut invalid = resource("sandbox-a", "");
    assert!(
        f.state
            .write()
            .unwrap()
            .sandboxes
            .update(invalid.clone())
            .is_err()
    );
    invalid.resource.uid = "bad id".into();
    invalid.name = "bad id".into();
    assert!(f.state.write().unwrap().sandboxes.update(invalid).is_err());
    assert_eq!(
        f.state.read().unwrap().sandboxes.resources[&Strng::from("sandbox-a")],
        previous
    );
    assert_eq!(
        f.demand
            .fetch_sandbox(&f.workload)
            .map(|sandbox| sandbox.uid.clone())
            .as_deref(),
        Some("sandbox-a")
    );
}

#[test]
fn workload_index_tracks_rebinding_unbinding_and_removal() {
    let mut store = SandboxStore::default();
    let first: Strng = "workload-1".into();
    let second: Strng = "workload-2".into();
    store.update(resource("sandbox-a", &first)).unwrap();
    store.update(resource("sandbox-b", &first)).unwrap();
    store.update(resource("sandbox-c", &second)).unwrap();

    let original = store.get_by_workload(&first)[0].clone();
    store.update(resource("sandbox-a", &second)).unwrap();
    assert_eq!(original.workload_uid.as_ref(), Some(&first));
    let rebound = store.get_by_workload(&second)[1].clone();
    assert_eq!(rebound.uid, "sandbox-a");
    assert_eq!(rebound.workload_uid.as_ref(), Some(&second));
    assert_eq!(
        store
            .get_by_workload(&first)
            .iter()
            .map(|sandbox| sandbox.uid.clone())
            .collect::<Vec<_>>(),
        &[Strng::from("sandbox-b")]
    );
    assert_eq!(
        store
            .get_by_workload(&second)
            .iter()
            .map(|sandbox| sandbox.uid.clone())
            .collect::<Vec<_>>(),
        &[Strng::from("sandbox-c"), Strng::from("sandbox-a")]
    );

    let mut unbound = resource("sandbox-c", &second);
    unbound.resource.attester = None;
    store.update(unbound).unwrap();
    assert!(store.resources.contains_key(&Strng::from("sandbox-c")));
    assert_eq!(
        store
            .get_by_workload(&second)
            .iter()
            .map(|sandbox| sandbox.uid.clone())
            .collect::<Vec<_>>(),
        &[Strng::from("sandbox-a")]
    );

    store.remove(&"sandbox-a".into());
    store.remove(&"sandbox-a".into());
    assert!(store.get_by_workload(&second).is_empty());
    assert!(!store.by_workload.contains_key(&second));
    assert_eq!(
        store
            .get_by_workload(&first)
            .iter()
            .map(|sandbox| sandbox.uid.clone())
            .collect::<Vec<_>>(),
        &[Strng::from("sandbox-b")]
    );
}

#[test]
fn validates_id_before_using_as_identity_or_header() {
    for invalid in [
        "",
        "*",
        "id\n",
        "id\r",
        "id with space",
        "沙盒",
        &"a".repeat(513),
    ] {
        assert!(validate_id(invalid).is_err());
    }
    assert!(validate_id("namespace--sandbox-123").is_ok());
}
