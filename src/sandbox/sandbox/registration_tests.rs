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
use crate::xds::agentio::sandbox::Sandbox as XdsSandbox;
use crate::{proxy, test_helpers, tls, xds};
use futures_util::FutureExt;
use prometheus_client::registry::Registry;
use tonic::{Code, Status};

fn new_manager(fixture: &Fixture) -> SandboxManager {
    SandboxManager::new(
        fixture.demand.clone(),
        Arc::new(WorkloadInfo::new(
            fixture.workload.name.to_string(),
            fixture.workload.namespace.to_string(),
            fixture.workload.service_account.to_string(),
        )),
    )
}

#[test]
fn registration_survives_restart_and_rejects_replacement() {
    let fixture = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let manager = new_manager(&fixture)
        .with_registration(directory.path().into())
        .unwrap();
    manager.register("kruise:one").unwrap();
    manager.register("kruise:one").unwrap();
    let error = manager.register("kruise:two").unwrap_err();
    assert_eq!(Status::from(error).code(), Code::FailedPrecondition);
    let contents = fs::read_to_string(directory.path().join(REGISTRATION_FILE)).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&contents).unwrap(),
        serde_json::json!({"sandboxId": "kruise:one"})
    );
    drop(manager);
    let restored = new_manager(&fixture)
        .with_registration(directory.path().into())
        .unwrap();
    assert_eq!(restored.id.borrow().as_deref(), Some("kruise:one"));
}

#[test]
fn invalid_identity_is_not_persisted_or_silently_ignored_on_restart() {
    let fixture = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let manager = new_manager(&fixture)
        .with_registration(directory.path().into())
        .unwrap();
    let error = manager.register("*").unwrap_err();
    assert_eq!(Status::from(error).code(), Code::InvalidArgument);
    assert!(!directory.path().join(REGISTRATION_FILE).exists());
    for contents in [
        "not json",
        "{}",
        r#"{"sandboxId":"*"}"#,
        r#"{"sandboxId":"invalid id"}"#,
    ] {
        fs::write(directory.path().join(REGISTRATION_FILE), contents).unwrap();
        assert!(
            new_manager(&fixture)
                .with_registration(directory.path().into())
                .is_err(),
            "accepted {contents}"
        );
    }
}

#[tokio::test]
async fn restored_identity_waits_for_snapshot_and_checks_binding() {
    let fixture = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    new_manager(&fixture)
        .with_registration(directory.path().into())
        .unwrap()
        .register("kruise:one")
        .unwrap();
    let mut cfg = test_helpers::test_config();
    cfg.xds_address = Some("https://localhost:15012".into());
    let tls = Box::new(tls::ControlPlaneAuthentication::RootCert(
        cfg.xds_root_cert.clone(),
    ));
    let mut registry = Registry::default();
    let client = xds::Config::new(Arc::new(cfg), tls)
        .with_on_demand_handler::<XdsSandbox>(
            xds::SANDBOX_TYPE,
            xds::ProxyStateUpdater::new_no_fetch(fixture.state.clone()),
        )
        .build(xds::Metrics::new(&mut registry), watch::channel(()).0);
    assert!(
        client.demander().is_some(),
        "Sandbox demand must be available with Workload push"
    );
    let state = DemandProxyState::new(
        fixture.state.clone(),
        client.demander(),
        Default::default(),
        Default::default(),
        Arc::new(proxy::Metrics::new(&mut registry)),
    );
    let manager = Arc::new(
        SandboxManager::new(state.clone(), new_manager(&fixture).workload.clone())
            .with_registration(directory.path().into())
            .unwrap(),
    );
    assert!(!state.supports_on_demand(&xds::ADDRESS_TYPE));
    assert!(state.supports_on_demand(&xds::SANDBOX_TYPE));

    assert!(matches!(manager.ready_sandbox(), Err(Error::NotReady)));
    let id = manager.registered_id().await;
    let ready = manager.wait_for_sandbox(&id);
    tokio::pin!(ready);
    assert!(
        ready.as_mut().now_or_never().is_none(),
        "persisted ID must not imply Ready"
    );
    fixture.publish("kruise:one");
    fixture.state.read().unwrap().policies.send();
    assert_eq!(ready.await.unwrap().uid.as_str(), "kruise:one");
    assert_eq!(manager.ready_sandbox().unwrap().uid.as_str(), "kruise:one");

    let mut other = (*fixture.workload).clone();
    other.uid = "other-workload".into();
    fixture.state.write().unwrap().sandboxes.insert(Sandbox {
        uid: "kruise:one".into(),
        workload_uid: Some(other.uid),
        traffic_policy: None,
    });
    assert!(matches!(
        manager.ready_sandbox(),
        Err(Error::WorkloadMismatch)
    ));
    fixture
        .state
        .write()
        .unwrap()
        .sandboxes
        .remove(&"kruise:one".into());
    assert!(
        matches!(manager.ready_sandbox(), Err(Error::NotReady)),
        "deletion must immediately close the gate again"
    );
}

#[tokio::test]
async fn unregistered_manager_rejects_even_if_an_unrelated_sandbox_is_cached() {
    let fixture = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let manager = new_manager(&fixture)
        .with_registration(directory.path().into())
        .unwrap();
    fixture.publish("kruise:unrelated");
    assert!(matches!(manager.ready_sandbox(), Err(Error::NotReady)));
}

#[test]
fn header_constants_have_expected_values() {
    assert_eq!(
        crate::sandbox::metadata::SANDBOX_METADATA_HEADER,
        "x-agentio-sandbox-metadata"
    );
    assert_eq!(SANDBOX_ID_HEADER, "x-agentio-sandbox-id");
    assert_eq!(SANDBOX_LABELS_HEADER, "x-agentio-sandbox-labels");
}
