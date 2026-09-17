// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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

use std::future::Future;
use std::io::Error;
use std::net::SocketAddr;
use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::{io, thread};

use criterion::measurement::Measurement;
use criterion::{
    BenchmarkGroup, Criterion, SamplingMode, Throughput, criterion_group, criterion_main,
};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use pprof::criterion::{Output, PProfProfiler};
use prometheus_client::registry::Registry;
use tokio::net::TcpStream;
use tracing::info;

use ztunnel::state::{DemandProxyState, ProxyRbacContext, ProxyState};
use ztunnel::test_helpers::linux::{TestMode, WorkloadManager};
use ztunnel::test_helpers::tcp::Mode;
use ztunnel::test_helpers::{tcp, test_default_workload};
use ztunnel::xds::agentio::sandbox::{PolicyReference, Sandbox as XdsSandbox, sandbox::Attester};
use ztunnel::xds::agentio::security::{TrafficPolicy as XdsTrafficPolicy, traffic_policy};
use ztunnel::xds::{TRAFFIC_POLICY_TYPE, XdsResource};
use ztunnel::{metrics, proxy, rbac, setup_netns_test, strng, test_helpers};

const KB: usize = 1024;
const MB: usize = 1024 * KB;
const GB: usize = 1024 * MB;

const N_RULES: usize = 10;
const N_POLICIES: usize = 10_000;

#[ctor::ctor(unsafe)]
fn initialize_namespace_tests() {
    ztunnel::test_helpers::namespaced::initialize_namespace_tests();
}

fn create_test_policies() -> Vec<XdsResource<XdsTrafficPolicy>> {
    let rules = (0..N_RULES)
        .map(|_| traffic_policy::Rule {
            action: traffic_policy::Action::Deny.into(),
            r#match: Some(traffic_policy::Match {
                source_ips: vec![traffic_policy::Address {
                    address: vec![198, 51, 100, 0],
                    length: 24,
                }],
                ..Default::default()
            }),
        })
        .collect::<Vec<_>>();
    (0..N_POLICIES)
        .map(|i| XdsResource {
            name: strng::format!("trafficPolicies/policy-{i}"),
            resource: XdsTrafficPolicy {
                egress: Some(traffic_policy::RuleSet {
                    rules: rules.clone(),
                }),
                ..Default::default()
            },
        })
        .collect()
}

fn run_async_blocking<Fut, O>(f: Fut) -> O
where
    Fut: Future<Output = O>,
    O: Send + 'static,
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

#[derive(Clone, Copy, Ord, PartialOrd, PartialEq, Eq)]
pub enum WorkloadMode {
    HBONE,
    TcpClient,
    Direct,
}

#[derive(Clone, Copy, Ord, PartialOrd, PartialEq, Eq)]
pub enum TestTrafficMode {
    // Each iteration sends a new request
    Request,
    // Each iteration establishes a new connection
    Connection,
}

#[allow(clippy::type_complexity)]
fn initialize_environment(
    ztunnel_mode: WorkloadMode,
    traffic_mode: TestTrafficMode,
    echo_mode: Mode,
    clients: usize,
) -> anyhow::Result<(
    WorkloadManager,
    SyncSender<usize>,
    Receiver<Result<(), io::Error>>,
)> {
    let mut manager = setup_netns_test!(TestMode::Shared);
    let (server, mut manager) = run_async_blocking(async move {
        if ztunnel_mode != WorkloadMode::Direct {
            // we need a client ztunnel
            manager.deploy_ztunnel("LOCAL").await.unwrap();
        }
        if ztunnel_mode == WorkloadMode::HBONE {
            // we need a server ztunnel
            manager.deploy_ztunnel("REMOTE").await.unwrap();
        }

        let server = manager
            .workload_builder("server", "REMOTE")
            .register()
            .await
            .unwrap();
        (server, manager)
    });
    server
        .run_ready(move |ready| async move {
            let echo = tcp::TestServer::new(echo_mode, 8080).await;
            ready.set_ready();
            echo.run().await;
            Ok(())
        })
        .unwrap();
    let echo_addr = SocketAddr::new(manager.resolver().resolve("server").unwrap(), 8080);
    let (tx, rx) = std::sync::mpsc::sync_channel::<usize>(0);
    let (ack_tx, ack_rx) = std::sync::mpsc::sync_channel::<Result<(), io::Error>>(0);

    let client_mode = match echo_mode {
        Mode::ReadWrite => Mode::ReadWrite,
        Mode::ReadDoubleWrite => Mode::ReadDoubleWrite,
        Mode::Write => Mode::Read,
        Mode::Read => Mode::Write,
        Mode::Forward(_) => todo!("not implemented for benchmark"),
        Mode::ForwardProxyProtocol => todo!("not implemented for benchmark"),
    };
    let clients: Vec<_> = (0..clients)
        .map(|id| {
            spawn_client(
                id,
                &mut manager,
                ztunnel_mode,
                traffic_mode,
                echo_addr,
                client_mode,
            )
        })
        .collect();
    thread::spawn(move || {
        while let Ok(size) = rx.recv() {
            // Send request to all clients
            for c in &clients {
                c.tx.send(size).unwrap()
            }
            // Then wait for all completions -- this must be done in a separate loop to allow parallel processing.
            for c in &clients {
                if let Err(e) = c.ack.recv().unwrap() {
                    // Failed
                    ack_tx.send(Err(e)).unwrap();
                    return;
                }
            }
            // Success
            ack_tx.send(Ok(())).unwrap();
        }
    });
    Ok((manager, tx, ack_rx))
}

fn spawn_client(
    i: usize,
    manager: &mut WorkloadManager,
    ztunnel_mode: WorkloadMode,
    traffic_mode: TestTrafficMode,
    echo_addr: SocketAddr,
    client_mode: Mode,
) -> TestClient {
    let client = run_async_blocking(async move {
        let name = format!("client-{i}");
        let mut builder = manager.workload_builder(&name, "LOCAL");
        if ztunnel_mode == WorkloadMode::HBONE {
            builder = builder.egress_gateway(echo_addr.ip());
        }
        builder.register().await.unwrap()
    });

    let (tx, rx) = std::sync::mpsc::sync_channel::<usize>(0);
    let (ack_tx, ack_rx) = std::sync::mpsc::sync_channel::<Result<(), io::Error>>(0);
    if traffic_mode == TestTrafficMode::Request {
        client
            .run_ready(move |ready| async move {
                let mut conn = TcpStream::connect(echo_addr).await.unwrap();
                conn.set_nodelay(true).unwrap();
                info!("setup complete");

                // warmup: send 1 byte so we ensure we have the full connection setup.
                tcp::run_client(&mut conn, 1, client_mode).await.unwrap();
                info!("warmup complete");
                ready.set_ready();

                // Accept requests and process them
                while let Ok(size) = rx.recv() {
                    // Send `size` bytes.
                    let res = tcp::run_client(&mut conn, size, client_mode).await;
                    // Report we are done.
                    ack_tx.send(res).unwrap();
                }
                Ok(())
            })
            .unwrap();
    } else {
        client
            .run_ready(move |ready| async move {
                ready.set_ready();
                // Accept requests and process them
                while let Ok(size) = rx.recv() {
                    // Open connection
                    let mut conn = TcpStream::connect(echo_addr).await.unwrap();
                    conn.set_nodelay(true).unwrap();
                    // Send `size` bytes.
                    let res = tcp::run_client(&mut conn, size, client_mode).await;
                    // Report we are done.
                    ack_tx.send(res).unwrap();
                }
                Ok(())
            })
            .unwrap();
    }

    TestClient { tx, ack: ack_rx }
}

struct TestClient {
    tx: SyncSender<usize>,
    ack: Receiver<Result<(), Error>>,
}

pub fn throughput(c: &mut Criterion) {
    const THROUGHPUT_SEND_SIZE: usize = GB;
    fn run_throughput<T: Measurement>(
        c: &mut BenchmarkGroup<T>,
        name: &str,
        mode: WorkloadMode,
        clients: usize,
    ) {
        let (_manager, tx, ack) =
            initialize_environment(mode, TestTrafficMode::Request, Mode::Read, clients).unwrap();
        let size = THROUGHPUT_SEND_SIZE / clients;
        c.bench_function(name, |b| {
            b.iter(|| {
                tx.send(size).unwrap();
                ack.recv().unwrap().unwrap();
            })
        });
    }

    let mut c = c.benchmark_group("throughput");

    // Measure in bits, not bytes, to match tools like iperf
    c.throughput(Throughput::Elements((THROUGHPUT_SEND_SIZE * 8) as u64));
    // Test takes a while, so reduce how many iterations we run
    c.sample_size(10);
    c.sampling_mode(SamplingMode::Flat);
    c.measurement_time(Duration::from_secs(5));
    // Send request in various modes.
    // Each test will use a pre-existing connection and send 1GB for multiple iterations
    for clients in [1, 2, 8] {
        run_throughput(
            &mut c,
            &format!("direct{clients}"),
            WorkloadMode::Direct,
            clients,
        );
        run_throughput(
            &mut c,
            &format!("tcp{clients}"),
            WorkloadMode::TcpClient,
            clients,
        );
        run_throughput(
            &mut c,
            &format!("hbone{clients}"),
            WorkloadMode::HBONE,
            clients,
        );
    }
}

pub fn latency(c: &mut Criterion) {
    const LATENCY_SEND_SIZE: usize = KB;
    fn run_latency<T: Measurement>(c: &mut BenchmarkGroup<T>, name: &str, mode: WorkloadMode) {
        let (_manager, tx, ack) =
            initialize_environment(mode, TestTrafficMode::Request, Mode::Read, 1).unwrap();
        c.bench_function(name, |b| {
            b.iter(|| {
                tx.send(LATENCY_SEND_SIZE).unwrap();
                ack.recv().unwrap().unwrap();
            })
        });
    }

    let mut c = c.benchmark_group("latency");

    // Measure in RPS
    c.throughput(Throughput::Elements(1));
    // Test takes a while, so reduce how many iterations we run
    // Send request in various modes.
    // Each test will use a pre-existing connection and send 1GB for multiple iterations
    run_latency(&mut c, "direct", WorkloadMode::Direct);
    run_latency(&mut c, "tcp", WorkloadMode::TcpClient);
    run_latency(&mut c, "hbone", WorkloadMode::HBONE);
}

pub fn connections(c: &mut Criterion) {
    fn run_connections<T: Measurement>(c: &mut BenchmarkGroup<T>, name: &str, mode: WorkloadMode) {
        let (_manager, tx, ack) =
            initialize_environment(mode, TestTrafficMode::Connection, Mode::ReadWrite, 1).unwrap();
        c.bench_function(name, |b| {
            b.iter(|| {
                tx.send(1).unwrap();
                ack.recv().unwrap().unwrap();
            })
        });
    }

    let mut c = c.benchmark_group("connections");

    // Measure in connections/s
    c.throughput(Throughput::Elements(1));
    // Send request in various modes.
    // Each test will use a pre-existing connection and send 1GB for multiple iterations
    run_connections(&mut c, "direct", WorkloadMode::Direct);
    run_connections(&mut c, "tcp", WorkloadMode::TcpClient);
    run_connections(&mut c, "hbone", WorkloadMode::HBONE);
}

pub fn rbac(c: &mut Criterion) {
    let policies = create_test_policies();
    let mut state = ProxyState::new(None);
    let workload = Arc::new(test_default_workload());
    let names = policies.iter().map(|p| p.name.to_string()).collect();
    for p in policies {
        state.policies.update(p).unwrap();
    }
    state.workloads.insert(workload.clone());
    state
        .sandboxes
        .update(XdsResource {
            name: "workload:benchmark".into(),
            resource: XdsSandbox {
                uid: "workload:benchmark".into(),
                attester: Some(Attester {
                    workload_uid: workload.uid.to_string(),
                }),
                policy_refs: std::collections::HashMap::from([(
                    TRAFFIC_POLICY_TYPE.to_string(),
                    PolicyReference {
                        resource_names: names,
                    },
                )]),
                ..Default::default()
            },
        })
        .unwrap();
    let sandbox = state.sandboxes.get(&"workload:benchmark".into());

    let mut registry = Registry::default();
    let metrics = Arc::new(crate::proxy::Metrics::new(&mut registry));
    let mock_proxy_state = DemandProxyState::new(
        Arc::new(RwLock::new(state)),
        None,
        ResolverConfig::default(),
        ResolverOpts::default(),
        metrics,
    );
    let rc = ProxyRbacContext {
        conn: rbac::Connection {
            src: "127.0.0.1:12345".parse().unwrap(),
            dst: "127.0.0.2:12345".parse().unwrap(),
            src_identity: None,
            dst_network: "".into(),
            direction: rbac::Direction::Outbound,
        },
        workload,
        sandbox,
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    c.bench_function("rbac", |b| {
        b.to_async(&rt).iter(|| async {
            let _ = mock_proxy_state.assert_rbac(&rc).await;
        })
    });
}

pub fn metrics(c: &mut Criterion) {
    let mut registry = Registry::default();
    let metrics = proxy::Metrics::new(metrics::sub_registry(&mut registry));

    let mut c = c.benchmark_group("metrics");
    c.bench_function("write", |b| {
        b.iter(|| {
            let co = proxy::ConnectionOpen {
                reporter: Default::default(),
                source: Some(Arc::new(test_helpers::test_default_workload())),
                derived_source: None,
                destination: None,
                destination_service: None,
                connection_security_policy: Default::default(),
            };
            let tl = proxy::CommonTrafficLabels::from(co);
            metrics.connection_opens.get_or_create(&tl).inc();
        })
    });
    c.bench_function("encode", |b| {
        b.iter(|| {
            let mut buf = String::new();
            prometheus_client::encoding::text::encode(&mut buf, &registry).unwrap();
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .with_profiler(PProfProfiler::new(100, Output::Protobuf))
        .warm_up_time(Duration::from_millis(1));
    targets = connections
}

criterion_main!(benches);
