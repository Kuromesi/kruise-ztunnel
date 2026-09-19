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
use crate::sandbox::discovery::tests::Fixture;
use crate::test_helpers::xds::{AdsConnection, AdsServer};
use crate::xds::agentio::sandbox::{Sandbox, sandbox::Attester};
use crate::xds::{ADDRESS_TYPE, ProxyStateUpdater, SANDBOX_TYPE, TRAFFIC_POLICY_TYPE};
use prost::Message;
use test_case::test_case;

async fn next_matching(
    conn: &mut AdsConnection,
    predicate: impl Fn(&DeltaDiscoveryRequest) -> bool,
) -> DeltaDiscoveryRequest {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let request = conn.rx.recv().await.expect("open ADS stream");
            if request.type_url == SANDBOX_TYPE || request.type_url == TRAFFIC_POLICY_TYPE {
                assert!(
                    request.resource_names_subscribe.is_empty(),
                    "Sandbox discovery must not send named subscriptions: {request:?}"
                );
                assert!(
                    request.resource_names_unsubscribe.is_empty(),
                    "Sandbox discovery must keep the wildcard subscription: {request:?}"
                );
            }
            if predicate(&request) {
                return request;
            }
        }
    })
    .await
    .expect("ADS request deadline")
}

fn response(
    nonce: &str,
    resources: Vec<ProtoResource>,
    removed: Vec<String>,
) -> DeltaDiscoveryResponse {
    DeltaDiscoveryResponse {
        type_url: SANDBOX_TYPE.to_string(),
        nonce: nonce.into(),
        system_version_info: "1".into(),
        resources,
        removed_resources: removed,
    }
}

fn resource() -> ProtoResource {
    ProtoResource {
        name: "sandbox-a".into(),
        version: "1".into(),
        resource: Some(prost_types::Any {
            type_url: SANDBOX_TYPE.to_string(),
            value: Sandbox {
                uid: "sandbox-a".into(),
                attester: Some(Attester {
                    workload_uid: "workload-uid".into(),
                }),
                ..Default::default()
            }
            .encode_to_vec(),
        }),
        ..Default::default()
    }
}

#[test_case(false, false; "workload_push_without_sandbox")]
#[test_case(true, false; "workload_on_demand_without_sandbox")]
#[test_case(false, true; "workload_push_with_sandbox")]
#[test_case(true, true; "workload_on_demand_with_sandbox")]
#[tokio::test]
async fn sandbox_mode_controls_subscription_and_readiness(on_demand: bool, sandbox_mode: bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (mut connections, mut config) = AdsServer::spawn_config(on_demand).await;
        config.sandbox_mode = sandbox_mode;
        // Token management must not implicitly enable Sandbox discovery.
        config.enable_sandbox_manager = true;
        let mut registry = prometheus_client::registry::Registry::default();
        let (awaiting_ready, mut ready) = tokio::sync::watch::channel(());
        let manager = crate::state::ProxyStateManager::new(
            Arc::new(config),
            crate::xds::Metrics::new(&mut registry),
            Arc::new(crate::proxy::Metrics::new(&mut registry)),
            awaiting_ready,
            crate::identity::mock::new_secret_manager(Duration::from_secs(10)),
        )
        .await
        .unwrap();
        assert_eq!(manager.state().supports_on_demand(), on_demand);
        let client_task = tokio::spawn(manager.run());

        // Exercise the production subscription setup on both initial connection and reconnect.
        for attempt in 0..2 {
            let mut connection = connections.recv().await.unwrap();
            let mut expected =
                HashSet::from([ADDRESS_TYPE.to_string(), TRAFFIC_POLICY_TYPE.to_string()]);
            if sandbox_mode {
                expected.insert(SANDBOX_TYPE.to_string());
            }
            for _ in 0..expected.len() {
                let initial = connection.rx.recv().await.unwrap();
                assert!(
                    expected.remove(&initial.type_url),
                    "unexpected subscription: {initial:?}"
                );
                assert!(initial.response_nonce.is_empty());
                if initial.type_url == ADDRESS_TYPE && on_demand {
                    assert_eq!(initial.resource_names_subscribe, ["*"]);
                    assert_eq!(initial.resource_names_unsubscribe, ["*"]);
                } else {
                    assert!(initial.resource_names_subscribe.is_empty());
                    assert!(initial.resource_names_unsubscribe.is_empty());
                }
                if initial.type_url != SANDBOX_TYPE {
                    connection
                        .tx
                        .send(Ok(DeltaDiscoveryResponse {
                            type_url: initial.type_url,
                            nonce: "workload-ready".into(),
                            ..Default::default()
                        }))
                        .await
                        .unwrap();
                }
            }
            assert!(expected.is_empty());
            for _ in 0..2 {
                let ack = connection.rx.recv().await.unwrap();
                assert!(ack.type_url == ADDRESS_TYPE || ack.type_url == TRAFFIC_POLICY_TYPE);
                assert_eq!(ack.response_nonce, "workload-ready");
                assert!(ack.error_detail.is_none());
            }
            if sandbox_mode {
                if attempt == 0 {
                    // All Workload responses were ACKed, but Sandbox still blocks readiness.
                    assert!(matches!(ready.has_changed(), Ok(false)));
                }
                connection
                    .tx
                    .send(Ok(response("sandbox-ready", vec![], vec![])))
                    .await
                    .unwrap();
                let ack = connection.rx.recv().await.unwrap();
                assert_eq!(ack.type_url, SANDBOX_TYPE);
                assert_eq!(ack.response_nonce, "sandbox-ready");
                assert!(ack.error_detail.is_none());
            }
            assert!(ready.changed().await.is_err());
            connection
                .tx
                .send(Err(tonic::Status::unavailable("reconnect")))
                .await
                .unwrap();
        }
        client_task.abort();
    })
    .await
    .expect("Sandbox mode ADS test deadline");
}

#[test_case(false; "workload_push")]
#[test_case(true; "workload_on_demand")]
#[tokio::test]
async fn sandbox_wildcard_push_rejection_and_reconnect(on_demand: bool) {
    let fixture = Fixture::new();
    let (mut connections, original, _state, mut ready) = AdsServer::spawn(on_demand).await;
    let AdsClient {
        config,
        metrics,
        block_ready,
        ..
    } = original;
    let client = config
        .with_watched_handler::<Sandbox>(
            SANDBOX_TYPE,
            ProxyStateUpdater::new_no_fetch(fixture.state.clone()),
        )
        .with_handler::<crate::xds::agentio::security::TrafficPolicy>(
            TRAFFIC_POLICY_TYPE,
            ProxyStateUpdater::new_no_fetch(fixture.state.clone()),
        )
        .build(metrics, block_ready.unwrap());
    let demander = client.demander();
    assert_eq!(demander.is_some(), on_demand);
    let demand = &fixture.demand;
    let client_task = tokio::spawn(client.run());
    let mut connection = tokio::time::timeout(Duration::from_secs(5), connections.recv())
        .await
        .unwrap()
        .unwrap();

    for _ in 0..3 {
        let initial = connection.rx.recv().await.unwrap();
        if initial.type_url == ADDRESS_TYPE && on_demand {
            assert_eq!(initial.resource_names_subscribe, ["*"]);
            assert_eq!(initial.resource_names_unsubscribe, ["*"]);
        } else {
            assert!(matches!(
                initial.type_url.as_str(),
                s if s == ADDRESS_TYPE || s == SANDBOX_TYPE || s == TRAFFIC_POLICY_TYPE
            ));
            assert!(initial.resource_names_subscribe.is_empty());
            assert!(initial.resource_names_unsubscribe.is_empty());
        }
        // Readiness waits for every subscribed type, so answer each even with no resources.
        connection
            .tx
            .send(Ok(DeltaDiscoveryResponse {
                type_url: initial.type_url,
                nonce: "initial".into(),
                ..Default::default()
            }))
            .await
            .unwrap();
    }
    let _ = tokio::time::timeout(Duration::from_secs(5), ready.changed())
        .await
        .unwrap();

    let policy_name = "namespaces/ns/trafficPolicies/shared";
    let policy_response = |nonce: &str, malformed: bool, remove: bool| {
        let mut response = response(nonce, vec![], vec![]);
        response.type_url = TRAFFIC_POLICY_TYPE.to_string();
        if remove {
            response.removed_resources.push(policy_name.into());
        } else {
            response.resources.push(ProtoResource {
                name: policy_name.into(),
                version: "1".into(),
                resource: Some(prost_types::Any {
                    type_url: TRAFFIC_POLICY_TYPE.to_string(),
                    value: if malformed {
                        vec![0xff]
                    } else {
                        crate::xds::agentio::security::TrafficPolicy::default().encode_to_vec()
                    },
                }),
                ..Default::default()
            });
        }
        response
    };
    for (nonce, malformed, remove, present) in [
        ("policy-malformed", true, false, false),
        ("policy-ready", false, false, true),
        ("policy-bad-update", true, false, true),
        ("policy-removed", false, true, false),
        ("policy-restored", false, false, true),
    ] {
        connection
            .tx
            .send(Ok(policy_response(nonce, malformed, remove)))
            .await
            .unwrap();
        let ack = next_matching(&mut connection, |r| r.response_nonce == nonce).await;
        assert_eq!(ack.error_detail.is_some(), malformed);
        assert_eq!(
            fixture
                .state
                .read()
                .unwrap()
                .policies
                .get(&policy_name.into())
                .is_some(),
            present
        );
    }

    assert!(demand.fetch_sandbox(&fixture.workload).is_none());
    let mut malformed = resource();
    malformed.resource.as_mut().unwrap().value = vec![0xff];
    connection
        .tx
        .send(Ok(response("initial-malformed", vec![malformed], vec![])))
        .await
        .unwrap();
    let nack = next_matching(&mut connection, |r| r.response_nonce == "initial-malformed").await;
    assert!(nack.error_detail.is_some());
    assert!(demand.fetch_sandbox(&fixture.workload).is_none());
    connection
        .tx
        .send(Ok(response("missing", vec![], vec!["sandbox-a".into()])))
        .await
        .unwrap();
    next_matching(&mut connection, |r| r.response_nonce == "missing").await;
    assert!(demand.fetch_sandbox(&fixture.workload).is_none());
    connection
        .tx
        .send(Ok(response("found", vec![resource()], vec![])))
        .await
        .unwrap();
    next_matching(&mut connection, |r| r.response_nonce == "found").await;

    assert_eq!(
        demand
            .fetch_sandbox(&fixture.workload)
            .map(|sandbox| sandbox.uid.clone())
            .as_deref(),
        Some("sandbox-a")
    );

    // Removal clears the binding; re-publication restores it.
    connection
        .tx
        .send(Ok(response("removed", vec![], vec!["sandbox-a".into()])))
        .await
        .unwrap();
    next_matching(&mut connection, |r| r.response_nonce == "removed").await;
    assert!(demand.fetch_sandbox(&fixture.workload).is_none());
    connection
        .tx
        .send(Ok(response("republished", vec![resource()], vec![])))
        .await
        .unwrap();
    next_matching(&mut connection, |r| r.response_nonce == "republished").await;
    assert_eq!(
        demand
            .fetch_sandbox(&fixture.workload)
            .map(|sandbox| sandbox.uid.clone())
            .as_deref(),
        Some("sandbox-a")
    );

    let mut malformed = resource();
    malformed.resource.as_mut().unwrap().value = vec![0xff];
    connection
        .tx
        .send(Ok(response("malformed", vec![malformed], vec![])))
        .await
        .unwrap();
    let nack = next_matching(&mut connection, |r| r.response_nonce == "malformed").await;
    assert!(nack.error_detail.is_some());
    assert_eq!(
        demand
            .fetch_sandbox(&fixture.workload)
            .map(|sandbox| sandbox.uid.clone()),
        Some("sandbox-a".into())
    );

    connection
        .tx
        .send(Ok(response("withdrawn", vec![], vec!["sandbox-a".into()])))
        .await
        .unwrap();
    next_matching(&mut connection, |r| r.response_nonce == "withdrawn").await;
    assert!(demand.fetch_sandbox(&fixture.workload).is_none());

    connection
        .tx
        .send(Err(tonic::Status::unavailable("reconnect test")))
        .await
        .unwrap();
    let mut reconnected = tokio::time::timeout(Duration::from_secs(5), connections.recv())
        .await
        .unwrap()
        .unwrap();
    for _ in 0..2 {
        let initial = next_matching(&mut reconnected, |r| {
            r.type_url == SANDBOX_TYPE || r.type_url == TRAFFIC_POLICY_TYPE
        })
        .await;
        assert!(initial.resource_names_subscribe.is_empty());
        assert!(initial.resource_names_unsubscribe.is_empty());
        if initial.type_url == TRAFFIC_POLICY_TYPE {
            // ADS tracks known names and intentionally requests a fresh version on reconnect.
            assert_eq!(
                initial
                    .initial_resource_versions
                    .get(policy_name)
                    .map(String::as_str),
                Some("")
            );
        }
    }
    connection = reconnected;
    assert!(demand.fetch_sandbox(&fixture.workload).is_none());
    connection
        .tx
        .send(Ok(response("repaired", vec![resource()], vec![])))
        .await
        .unwrap();
    let ack = next_matching(&mut connection, |r| r.response_nonce == "repaired").await;
    assert!(ack.error_detail.is_none());
    assert_eq!(
        demand
            .fetch_sandbox(&fixture.workload)
            .map(|sandbox| sandbox.uid.clone())
            .as_deref(),
        Some("sandbox-a")
    );
    if let Some(demander) = demander {
        // Workloads still support ordinary named demands on the same ADS stream.
        let demand = demander
            .demand(ADDRESS_TYPE, "another-workload".into())
            .await;
        next_matching(&mut connection, |r| {
            r.type_url == ADDRESS_TYPE && r.resource_names_subscribe == ["another-workload"]
        })
        .await;
        drop(demand);
    }
    client_task.abort();
}
