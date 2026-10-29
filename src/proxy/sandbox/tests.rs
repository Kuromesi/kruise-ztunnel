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
use crate::proxy::{DefaultSocketFactory, LocalWorkloadInformation, SocketFactory};
use crate::sandbox::discovery::tests::Fixture;
use crate::sandbox::sandbox::SandboxManager;
use crate::sandbox::sandbox::rpc::sandbox_network_client::SandboxNetworkClient;
use crate::sandbox::token::FileSandboxToken;
use crate::state::workload::Workload;
use crate::state::{DemandProxyState, WorkloadInfo};
use std::path::Path;

async fn inputs(
    state: DemandProxyState,
    workload: &Workload,
    directory: &Path,
    address: std::net::SocketAddr,
    socket_factory: Arc<dyn SocketFactory + Send + Sync>,
) -> Arc<ProxyInputs> {
    let mut config = crate::test_helpers::test_config();
    config.enable_sandbox_manager = true;
    config.sandbox_token_enabled = true;
    config.sandbox_prepare_addr = address;
    let local = Arc::new(LocalWorkloadInformation::new(
        Arc::new(WorkloadInfo::new(
            workload.name.to_string(),
            workload.namespace.to_string(),
            workload.service_account.to_string(),
        )),
        state.clone(),
        crate::identity::mock::new_secret_manager(Duration::from_secs(10)),
    ));
    let mut manager = SandboxManager::new(state.clone(), local.workload_info())
        .with_registration(directory.into())
        .unwrap();
    let tokens = directory.join("tokens");
    manager.token = Some(FileSandboxToken::start(tokens.clone(), 10).await.unwrap());
    std::fs::write(
        tokens.join("sandbox.token"),
        r#"{"accessToken":"token","sandboxClientId":"client"}"#,
    )
    .unwrap();
    ProxyInputs::new(
        Arc::new(config),
        Default::default(),
        state,
        crate::test_helpers::helpers::test_proxy_metrics(),
        socket_factory,
        None,
        local,
        false,
        None,
        Some(Arc::new(manager)),
        None,
        None,
    )
}

#[tokio::test]
async fn disabled_manager_preserves_cached_sandbox_lookup() {
    let fixture = Fixture::new();
    fixture.publish("sandbox-a");
    let directory = tempfile::tempdir().unwrap();
    let mut pi = inputs(
        fixture.demand.clone(),
        &fixture.workload,
        directory.path(),
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(DefaultSocketFactory::default()),
    )
    .await;
    let inputs = Arc::get_mut(&mut pi).unwrap();
    Arc::make_mut(&mut inputs.cfg).enable_sandbox_manager = false;
    inputs.sandbox_manager = None;
    assert_eq!(
        inputs.sandbox_for_connection().unwrap().unwrap().uid,
        "sandbox-a"
    );
}

#[tokio::test]
async fn prepare_requires_a_nonempty_token_and_allows_retry() {
    for case in [
        "missing",
        "empty",
        "unreadable",
        "missing-field",
        "invalid-json",
    ] {
        let fixture = Fixture::new();
        fixture.publish("sandbox-a");
        let directory = tempfile::tempdir().unwrap();
        let pi = inputs(
            fixture.demand.clone(),
            &fixture.workload,
            directory.path(),
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(DefaultSocketFactory::default()),
        )
        .await;
        let token = directory.path().join("tokens/sandbox.token");
        match case {
            "missing" => std::fs::remove_file(&token).unwrap(),
            "empty" => std::fs::write(&token, "").unwrap(),
            "missing-field" => std::fs::write(&token, r#"{"accessToken":"token"}"#).unwrap(),
            "invalid-json" => std::fs::write(&token, "not-json").unwrap(),
            _ => std::fs::write(&token, [0xff]).unwrap(),
        }
        let service = Service { pi: pi.clone() };
        let request = || {
            Request::new(PrepareSandboxRequest {
                sandbox_id: "sandbox-a".into(),
            })
        };
        let error = service.prepare_sandbox(request()).await.unwrap_err();
        assert_eq!(
            error.code(),
            if matches!(case, "unreadable" | "missing-field" | "invalid-json") {
                Code::Internal
            } else {
                Code::FailedPrecondition
            }
        );
        assert!(error.message().contains("token"));
        assert!(!directory.path().join("sandbox.json").exists());
        assert!(pi.sandbox_for_connection().unwrap().is_none());

        std::fs::write(
            token,
            r#"{"accessToken":"ready-token","sandboxClientId":"client"}"#,
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match service.prepare_sandbox(request()).await {
                    Ok(_) => break,
                    Err(error) => assert_eq!(error.code(), Code::FailedPrecondition),
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            pi.sandbox_for_connection().unwrap().unwrap().uid,
            "sandbox-a"
        );
        assert!(directory.path().join("sandbox.json").exists());
        // The same ID remains idempotent once both configuration and token are ready.
        service.prepare_sandbox(request()).await.unwrap();
    }
}

#[tokio::test]
async fn dedicated_factory_reads_agents_token_layout() {
    for case in ["disabled", "enabled", "startup-error"] {
        let fixture = Fixture::new();
        fixture.publish("sandbox-a");
        let directory = tempfile::tempdir().unwrap();
        let tokens = directory.path().join("agent-token");
        let state = directory.path().join("state");
        let mut cfg = crate::test_helpers::test_config();
        cfg.enable_sandbox_manager = true;
        cfg.dns_proxy = false;
        cfg.proxy_mode = crate::config::ProxyMode::Dedicated;
        cfg.sandbox_prepare_addr = "127.0.0.1:0".parse().unwrap();
        cfg.sandbox_state_dir = state.clone();
        cfg.sandbox_token_path = tokens.to_str().unwrap().into();
        cfg.sandbox_token_enabled = case != "disabled";
        cfg.sandbox_watcher_debounce_ms = if case == "disabled" { 0 } else { 10 };
        if case == "startup-error" {
            std::fs::write(&tokens, "not a directory").unwrap();
        }
        let (_drain, watch) = crate::drain::new();
        let factory = crate::proxyfactory::ProxyFactory::new(
            Arc::new(cfg),
            fixture.demand.clone(),
            crate::identity::mock::new_secret_manager(Duration::from_secs(10)),
            crate::test_helpers::helpers::test_proxy_metrics(),
            None,
            watch,
            None,
        )
        .unwrap();
        let result = factory
            .new_proxies_for_dedicated(WorkloadInfo::new(
                "pod".into(),
                "ns".into(),
                "default".into(),
            ))
            .await;
        let proxies = match result {
            Ok(proxies) => {
                assert_ne!(case, "startup-error");
                proxies
            }
            Err(error) => {
                assert_eq!(case, "startup-error");
                assert!(error.to_string().contains("Sandbox token loading failed"));
                continue;
            }
        };
        let pi = proxies
            .proxy
            .as_ref()
            .unwrap()
            .sandbox
            .as_ref()
            .unwrap()
            .pi
            .clone();
        let service = Service { pi: pi.clone() };
        let request = || {
            Request::new(PrepareSandboxRequest {
                sandbox_id: "sandbox-a".into(),
            })
        };
        if case == "disabled" {
            assert!(pi.sandbox_manager.as_ref().unwrap().token.is_none());
            service.prepare_sandbox(request()).await.unwrap();
            assert!(state.join("sandbox.json").is_file());
            assert!(!tokens.exists());
            continue;
        }
        assert_eq!(
            service.prepare_sandbox(request()).await.unwrap_err().code(),
            Code::FailedPrecondition
        );
        assert!(!state.join("sandbox.json").exists());

        // agents writes a namespace/name digest filename, independent of the xDS Sandbox ID.
        let raw = r#"{"accessToken":"test-access-token","sandboxClientId":"client+/="}"#;
        std::fs::write(tokens.join("5d10446ba1916368fd4fb05d40d31db3.token"), raw).unwrap();
        service.prepare_sandbox(request()).await.unwrap();
        assert!(state.join("sandbox.json").is_file());
        assert_eq!(
            pi.sandbox_manager
                .as_ref()
                .unwrap()
                .token
                .as_ref()
                .unwrap()
                .get_or_load()
                .await
                .unwrap()
                .to_header_value()
                .unwrap()
                .to_str()
                .unwrap(),
            "agent-identity.access-token=test-access-token,agent-identity.sandbox-client-id=client+/=",
        );
    }
}

#[tokio::test]
async fn sandbox_unavailable_uses_workload_policies_while_prepare_still_waits() {
    use futures_util::FutureExt;

    let fixture = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let pi = inputs(
        fixture.demand.clone(),
        &fixture.workload,
        directory.path(),
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(DefaultSocketFactory::default()),
    )
    .await;
    let manager = pi.sandbox_manager.as_ref().unwrap();
    assert!(pi.sandbox_for_connection().unwrap().is_none());
    let service = Service { pi: pi.clone() };
    let preparation = service.prepare_sandbox(Request::new(PrepareSandboxRequest {
        sandbox_id: "sandbox-a".into(),
    }));
    tokio::pin!(preparation);
    assert!(preparation.as_mut().now_or_never().is_none());
    assert!(!directory.path().join("sandbox.json").exists());
    fixture.publish("sandbox-a");
    // Receiving a candidate in xDS alone must not publish the registration.
    assert!(pi.sandbox_for_connection().unwrap().is_none());
    fixture.state.read().unwrap().policies.send();
    preparation.await.unwrap();
    assert_eq!(
        pi.sandbox_for_connection().unwrap().unwrap().uid,
        "sandbox-a"
    );

    fixture
        .state
        .write()
        .unwrap()
        .sandboxes
        .remove(&"sandbox-a".into());
    assert!(pi.sandbox_for_connection().unwrap().is_none());
    assert!(matches!(manager.ready_sandbox(), Err(Error::NotReady)));
    fixture.publish("sandbox-a");
    assert!(pi.sandbox_for_connection().unwrap().is_some());
    let mut other = (*fixture.workload).clone();
    other.uid = "another-workload".into();
    fixture
        .state
        .write()
        .unwrap()
        .sandboxes
        .insert(crate::sandbox::discovery::Sandbox {
            uid: "sandbox-a".into(),
            workload_uid: Some(other.uid),
            traffic_policy: None,
        });
    assert!(matches!(
        pi.sandbox_for_connection(),
        Err(crate::proxy::Error::SandboxNotReady(
            Error::WorkloadMismatch
        ))
    ));
}

#[tokio::test]
async fn sandbox_rpc_and_outbound_share_per_pod_registration_and_drain() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new();
        fixture.publish("sandbox-a");
        let mut other = (*fixture.workload).clone();
        other.uid = "workload-b".into();
        other.name = "pod-b".into();
        {
            let mut state = fixture.state.write().unwrap();
            state.workloads.insert(Arc::new(other.clone()));
            state.sandboxes.insert(crate::sandbox::discovery::Sandbox {
                uid: "sandbox-b".into(),
                workload_uid: Some(other.uid.clone()),
                traffic_policy: None,
            });
        }
        let directories = tempfile::tempdir().unwrap();
        let pi_a = inputs(
            fixture.demand.clone(),
            &fixture.workload,
            &directories.path().join("pod-a"),
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(DefaultSocketFactory::default()),
        )
        .await;
        let pi_b = inputs(
            fixture.demand.clone(),
            &other,
            &directories.path().join("pod-b"),
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(DefaultSocketFactory::default()),
        )
        .await;
        let (drain_a, watch_a) = crate::drain::new();
        let (drain_b, watch_b) = crate::drain::new();
        let server_a = Server::new(pi_a.clone(), watch_a).unwrap();
        let server_b = Server::new(pi_b.clone(), watch_b).unwrap();
        let address_a = server_a.listener.local_addr().unwrap();
        let address_b = server_b.listener.local_addr().unwrap();
        let task_a = tokio::spawn(server_a.run());
        let task_b = tokio::spawn(server_b.run());
        let channel_a = tonic::transport::Endpoint::from_shared(format!("http://{address_a}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client_a = SandboxNetworkClient::new(channel_a);
        let channel_b = tonic::transport::Endpoint::from_shared(format!("http://{address_b}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client_b = SandboxNetworkClient::new(channel_b);
        assert!(pi_a.sandbox_for_connection().unwrap().is_none());
        client_a
            .prepare_sandbox(PrepareSandboxRequest {
                sandbox_id: "sandbox-a".into(),
            })
            .await
            .unwrap();
        assert_eq!(
            pi_a.sandbox_for_connection().unwrap().unwrap().uid,
            "sandbox-a"
        );
        // Preparing A must not select A's Sandbox for B.
        assert!(pi_b.sandbox_for_connection().unwrap().is_none());
        client_b
            .prepare_sandbox(PrepareSandboxRequest {
                sandbox_id: "sandbox-b".into(),
            })
            .await
            .unwrap();
        assert_eq!(
            pi_b.sandbox_for_connection().unwrap().unwrap().uid,
            "sandbox-b"
        );
        for (pod, sandbox) in [("pod-a", "sandbox-a"), ("pod-b", "sandbox-b")] {
            let file = std::fs::read(directories.path().join(pod).join("sandbox.json")).unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&file).unwrap()["sandboxId"],
                sandbox
            );
        }
        drain_a.start_drain_and_wait(DrainMode::Immediate).await;
        task_a.await.unwrap();
        assert!(tokio::net::TcpStream::connect(address_a).await.is_err());
        client_b
            .prepare_sandbox(PrepareSandboxRequest {
                sandbox_id: "sandbox-b".into(),
            })
            .await
            .unwrap();
        drop(client_b);
        drain_b.start_drain_and_wait(DrainMode::Graceful).await;
        task_b.await.unwrap();
    })
    .await
    .expect("per-Pod RPC test deadline");
}

#[tokio::test(start_paused = true)]
async fn failed_prepare_does_not_register_and_allows_corrected_id() {
    for id in ["missing", "wrong-workload", "*"] {
        let fixture = Fixture::new();
        fixture.publish("sandbox-a");
        fixture
            .state
            .write()
            .unwrap()
            .sandboxes
            .insert(crate::sandbox::discovery::Sandbox {
                uid: "wrong-workload".into(),
                workload_uid: Some("other-workload".into()),
                traffic_policy: None,
            });
        let directory = tempfile::tempdir().unwrap();
        let pi = inputs(
            fixture.demand.clone(),
            &fixture.workload,
            directory.path(),
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(DefaultSocketFactory::default()),
        )
        .await;
        let service = Service { pi: pi.clone() };
        let error = service
            .prepare_sandbox(Request::new(PrepareSandboxRequest {
                sandbox_id: id.into(),
            }))
            .await
            .unwrap_err();
        let expected = match id {
            "missing" => Code::DeadlineExceeded,
            "wrong-workload" => Code::FailedPrecondition,
            _ => Code::InvalidArgument,
        };
        assert_eq!(error.code(), expected);
        assert!(
            !directory.path().join("sandbox.json").exists(),
            "failed {id} was persisted"
        );
        assert!(pi.sandbox_for_connection().unwrap().is_none());

        service
            .prepare_sandbox(Request::new(PrepareSandboxRequest {
                sandbox_id: "sandbox-a".into(),
            }))
            .await
            .unwrap();
        assert_eq!(
            pi.sandbox_for_connection().unwrap().unwrap().uid,
            "sandbox-a"
        );
        let restored = SandboxManager::new(
            fixture.demand.clone(),
            pi.local_workload_information.workload_info(),
        )
        .with_registration(directory.path().into())
        .unwrap();
        assert_eq!(restored.ready_sandbox().unwrap().uid, "sandbox-a");
        // A successful registration still cannot be replaced, even by a missing ID.
        let error = service
            .prepare_sandbox(Request::new(PrepareSandboxRequest {
                sandbox_id: "different".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::FailedPrecondition);
    }
}

#[tokio::test]
async fn cancelled_prepare_does_not_register_and_allows_corrected_id() {
    use futures_util::FutureExt;

    let fixture = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let pi = inputs(
        fixture.demand.clone(),
        &fixture.workload,
        directory.path(),
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(DefaultSocketFactory::default()),
    )
    .await;
    let service = Service { pi: pi.clone() };
    let mut preparation = Box::pin(service.prepare_sandbox(Request::new(PrepareSandboxRequest {
        sandbox_id: "missing".into(),
    })));
    assert!(preparation.as_mut().now_or_never().is_none());
    drop(preparation);
    assert!(!directory.path().join("sandbox.json").exists());
    fixture.publish("sandbox-a");
    service
        .prepare_sandbox(Request::new(PrepareSandboxRequest {
            sandbox_id: "sandbox-a".into(),
        }))
        .await
        .unwrap();
    assert_eq!(
        pi.sandbox_for_connection().unwrap().unwrap().uid,
        "sandbox-a"
    );
}

#[tokio::test]
async fn concurrent_prepare_commits_only_one_identity() {
    let fixture = Fixture::new();
    fixture.publish("sandbox-a");
    fixture.publish("sandbox-b");
    let directory = tempfile::tempdir().unwrap();
    let pi = inputs(
        fixture.demand.clone(),
        &fixture.workload,
        directory.path(),
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(DefaultSocketFactory::default()),
    )
    .await;
    let service = Service { pi: pi.clone() };
    let (a, b) = tokio::join!(
        service.prepare_sandbox(Request::new(PrepareSandboxRequest {
            sandbox_id: "sandbox-a".into()
        })),
        service.prepare_sandbox(Request::new(PrepareSandboxRequest {
            sandbox_id: "sandbox-b".into()
        })),
    );
    let (winner, loser) = match (a, b) {
        (Ok(_), Err(error)) => ("sandbox-a", error),
        (Err(error), Ok(_)) => ("sandbox-b", error),
        other => panic!("expected exactly one successful registration: {other:?}"),
    };
    assert_eq!(loser.code(), Code::FailedPrecondition);
    assert_eq!(pi.sandbox_for_connection().unwrap().unwrap().uid, winner);
    let restored = SandboxManager::new(
        fixture.demand.clone(),
        pi.local_workload_information.workload_info(),
    )
    .with_registration(directory.path().into())
    .unwrap();
    assert_eq!(restored.ready_sandbox().unwrap().uid, winner);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn sandbox_rpc_binds_same_address_in_distinct_pod_netns() {
    if !crate::test_helpers::can_run_privilged_test() {
        eprintln!("This test requires root; skipping");
        return;
    }
    use crate::inpod::{config::InPodConfig, netns::InpodNetns, test_helpers::new_netns};
    let config = crate::config::Config {
        packet_mark: Some(123),
        inpod_port_reuse: false,
        ..crate::test_helpers::test_config()
    };
    let inpod = InPodConfig::new(&config).unwrap();
    let ns_a = InpodNetns::new(inpod.cur_netns().clone(), new_netns()).unwrap();
    let ns_b = InpodNetns::new(inpod.cur_netns().clone(), new_netns()).unwrap();
    let fixture = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let (_drain, watch) = crate::drain::new();
    let pi_a = inputs(
        fixture.demand.clone(),
        &fixture.workload,
        &directory.path().join("a"),
        "127.0.0.1:0".parse().unwrap(),
        Arc::from(inpod.socket_factory(ns_a)),
    )
    .await;
    let server_a = Server::new(pi_a, watch.clone()).unwrap();
    let address = server_a.listener.local_addr().unwrap();
    let pi_b = inputs(
        fixture.demand,
        &fixture.workload,
        &directory.path().join("b"),
        address,
        Arc::from(inpod.socket_factory(ns_b)),
    )
    .await;
    let server_b = Server::new(pi_b, watch).unwrap();
    assert_eq!(server_b.listener.local_addr().unwrap(), address);
}

#[tokio::test]
async fn sandbox_management_tls_authenticates_before_prepare() {
    use crate::tls::management::{ManagementTls, tests::client_config};
    use crate::tls::mock::{
        TEST_ROOT, TEST_ROOT_KEY, TEST_ROOT2_KEY, TestIdentity, generate_test_certs_with_root,
    };
    use std::time::SystemTime;
    use tokio::net::TcpStream;

    tokio::time::timeout(Duration::from_secs(10), async {
        let allowed = "spiffe://cluster.local/ns/system/sa/sandbox-manager";
        let gateway = "spiffe://cluster.local/ns/system/sa/sandbox-gateway";
        let now = SystemTime::now();
        let cert = |identity: TestIdentity, root, expires| {
            generate_test_certs_with_root(
                &identity,
                now - Duration::from_secs(120),
                expires,
                None,
                root,
            )
        };
        let (server_key, server_cert) = cert(
            TestIdentity::Ip("127.0.0.1".parse().unwrap()),
            TEST_ROOT_KEY,
            now + Duration::from_secs(300),
        );
        let certificates = tempfile::tempdir().unwrap();
        std::fs::write(certificates.path().join("tls.crt"), server_cert).unwrap();
        std::fs::write(certificates.path().join("tls.key"), server_key).unwrap();
        std::fs::write(certificates.path().join("ca.crt"), TEST_ROOT).unwrap();
        let tls = Arc::new(ManagementTls::load(certificates.path(), &[allowed.into()]).unwrap());
        let fixture = Fixture::new();
        fixture.publish("sandbox-a");
        let directory = tempfile::tempdir().unwrap();
        let mut pi = inputs(
            fixture.demand.clone(),
            &fixture.workload,
            directory.path(),
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(DefaultSocketFactory::default()),
        )
        .await;
        let inputs = Arc::get_mut(&mut pi).unwrap();
        Arc::make_mut(&mut inputs.cfg).sandbox_management_tls_enabled = true;
        inputs.sandbox_management_tls = Some(tls);
        let (drain, watch) = crate::drain::new();
        let server = Server::new(pi.clone(), watch).unwrap();
        let address = server.listener.local_addr().unwrap();
        let task = tokio::spawn(server.run());

        // One stalled handshake must not block authenticated clients.
        let _stalled = TcpStream::connect(address).await.unwrap();
        let endpoint = tonic::transport::Endpoint::from_static("http://127.0.0.1")
            .connect_timeout(Duration::from_secs(1))
            .timeout(Duration::from_secs(1));
        let plaintext = endpoint
            .clone()
            .connect_with_connector(tower::service_fn(move |_| async move {
                TcpStream::connect(address)
                    .await
                    .map(hyper_util::rt::TokioIo::new)
            }))
            .await;
        if let Ok(channel) = plaintext {
            assert!(
                SandboxNetworkClient::new(channel)
                    .prepare_sandbox(PrepareSandboxRequest {
                        sandbox_id: "sandbox-a".into(),
                    })
                    .await
                    .is_err()
            );
        }
        assert!(!directory.path().join("sandbox.json").exists());

        for case in ["no-cert", "untrusted", "expired", "gateway", "allowed"] {
            let credentials = (case != "no-cert").then(|| {
                cert(
                    TestIdentity::Identity(
                        if case == "gateway" { gateway } else { allowed }
                            .parse()
                            .unwrap(),
                    ),
                    if case == "untrusted" {
                        TEST_ROOT2_KEY
                    } else {
                        TEST_ROOT_KEY
                    },
                    if case == "expired" {
                        now - Duration::from_secs(60)
                    } else {
                        now + Duration::from_secs(300)
                    },
                )
            });
            let config = client_config(
                TEST_ROOT,
                credentials
                    .as_ref()
                    .map(|(key, cert)| (key.as_str(), cert.as_str())),
            );
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let channel = endpoint
                .clone()
                .connect_with_connector(tower::service_fn(move |_| {
                    let connector = connector.clone();
                    async move {
                        let stream = TcpStream::connect(address).await?;
                        let stream = connector
                            .connect("127.0.0.1".try_into().unwrap(), stream)
                            .await?;
                        Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
                    }
                }))
                .await;
            match channel {
                Ok(channel) => {
                    let mut request = Request::new(PrepareSandboxRequest {
                        sandbox_id: "sandbox-a".into(),
                    });
                    // Caller-supplied identity headers cannot override certificate authorization.
                    request
                        .metadata_mut()
                        .insert("x-client-identity", allowed.parse().unwrap());
                    let result = SandboxNetworkClient::new(channel)
                        .prepare_sandbox(request)
                        .await;
                    if case == "allowed" {
                        result.unwrap();
                    } else {
                        let error = result.unwrap_err();
                        if case == "gateway" {
                            assert_eq!(error.code(), Code::PermissionDenied);
                        }
                    }
                }
                Err(error) => assert!(case != "allowed" && case != "gateway", "{case}: {error}"),
            }
            assert_eq!(
                directory.path().join("sandbox.json").exists(),
                case == "allowed",
                "{case}"
            );
            assert_eq!(
                pi.sandbox_for_connection().unwrap().is_some(),
                case == "allowed",
                "{case}"
            );
        }
        drain.start_drain_and_wait(DrainMode::Immediate).await;
        task.await.unwrap();
    })
    .await
    .unwrap();
}
