// Copyright 2026 The Kruise Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::*;
use crate::sandbox::discovery::tests::Fixture;
use crate::test_helpers::xds::{AdsConnection, AdsServer};
use crate::xds::agentio::sandbox::{Sandbox, SandboxState, sandbox::Attester};
use crate::xds::{ADDRESS_TYPE, AUTHORIZATION_TYPE, ProxyStateUpdater, SANDBOX_TYPE};
use prost::Message;
use test_case::test_case;

async fn next_matching(
    conn: &mut AdsConnection,
    predicate: impl Fn(&DeltaDiscoveryRequest) -> bool,
) -> DeltaDiscoveryRequest {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let request = conn.rx.recv().await.expect("open ADS stream");
            if request.type_url == SANDBOX_TYPE {
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
                state: SandboxState::Running.into(),
                ..Default::default()
            }
            .encode_to_vec(),
        }),
        ..Default::default()
    }
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
        .with_optional_watched_handler::<Sandbox>(
            SANDBOX_TYPE,
            ProxyStateUpdater::new_no_fetch(fixture.state.clone()),
        )
        .build(metrics, block_ready.unwrap());
    let demander = client.demander();
    assert_eq!(demander.is_some(), on_demand);
    let manager = &fixture.manager;
    let client_task = tokio::spawn(client.run());
    let mut connection = tokio::time::timeout(Duration::from_secs(5), connections.recv())
        .await
        .unwrap()
        .unwrap();

    for _ in 0..3 {
        let initial = connection.rx.recv().await.unwrap();
        if initial.type_url == SANDBOX_TYPE {
            assert!(initial.resource_names_subscribe.is_empty());
            assert!(initial.resource_names_unsubscribe.is_empty());
        } else {
            assert!(
                matches!(initial.type_url.as_str(), s if s == ADDRESS_TYPE || s == AUTHORIZATION_TYPE)
            );
            if initial.type_url == ADDRESS_TYPE && on_demand {
                assert_eq!(initial.resource_names_subscribe, ["*"]);
                assert_eq!(initial.resource_names_unsubscribe, ["*"]);
            } else {
                assert!(initial.resource_names_subscribe.is_empty());
                assert!(initial.resource_names_unsubscribe.is_empty());
            }
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
    }
    // No Sandbox response at all is needed for warm-pool pod readiness.
    let _ = tokio::time::timeout(Duration::from_secs(5), ready.changed())
        .await
        .unwrap();

    assert!(manager.fetch_attested_sandbox(&fixture.workload).is_none());
    let mut malformed = resource();
    malformed.resource.as_mut().unwrap().value = vec![0xff];
    connection
        .tx
        .send(Ok(response("initial-malformed", vec![malformed], vec![])))
        .await
        .unwrap();
    let nack = next_matching(&mut connection, |r| r.response_nonce == "initial-malformed").await;
    assert!(nack.error_detail.is_some());
    assert!(manager.fetch_attested_sandbox(&fixture.workload).is_none());
    connection
        .tx
        .send(Ok(response("missing", vec![], vec!["sandbox-a".into()])))
        .await
        .unwrap();
    next_matching(&mut connection, |r| r.response_nonce == "missing").await;
    assert!(manager.fetch_attested_sandbox(&fixture.workload).is_none());
    connection
        .tx
        .send(Ok(response("found", vec![resource()], vec![])))
        .await
        .unwrap();
    next_matching(&mut connection, |r| r.response_nonce == "found").await;

    assert_eq!(
        manager
            .fetch_attested_sandbox(&fixture.workload)
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
    assert!(manager.fetch_attested_sandbox(&fixture.workload).is_none());
    connection
        .tx
        .send(Ok(response("republished", vec![resource()], vec![])))
        .await
        .unwrap();
    next_matching(&mut connection, |r| r.response_nonce == "republished").await;
    assert_eq!(
        manager
            .fetch_attested_sandbox(&fixture.workload)
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
        manager
            .fetch_attested_sandbox(&fixture.workload)
            .map(|sandbox| sandbox.uid.clone()),
        Some("sandbox-a".into())
    );

    connection
        .tx
        .send(Ok(response("withdrawn", vec![], vec!["sandbox-a".into()])))
        .await
        .unwrap();
    next_matching(&mut connection, |r| r.response_nonce == "withdrawn").await;
    assert!(manager.fetch_attested_sandbox(&fixture.workload).is_none());

    connection
        .tx
        .send(Err(tonic::Status::unavailable("reconnect test")))
        .await
        .unwrap();
    let mut reconnected = tokio::time::timeout(Duration::from_secs(5), connections.recv())
        .await
        .unwrap()
        .unwrap();
    let initial = next_matching(&mut reconnected, |r| r.type_url == SANDBOX_TYPE).await;
    assert!(initial.resource_names_subscribe.is_empty());
    assert!(initial.resource_names_unsubscribe.is_empty());
    connection = reconnected;
    assert!(manager.fetch_attested_sandbox(&fixture.workload).is_none());
    connection
        .tx
        .send(Ok(response("repaired", vec![resource()], vec![])))
        .await
        .unwrap();
    let ack = next_matching(&mut connection, |r| r.response_nonce == "repaired").await;
    assert!(ack.error_detail.is_none());
    assert_eq!(
        manager
            .fetch_attested_sandbox(&fixture.workload)
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
