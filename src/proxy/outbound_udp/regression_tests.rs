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
use crate::proxy::h2::H2Stream;
use crate::proxy::h2::client::{WorkloadKey, spawn_connection};
use crate::test_helpers::helpers::test_proxy_metrics;
use tracing::instrument::WithSubscriber;

#[derive(Clone, Default)]
struct CapturedAccessLog(Arc<std::sync::Mutex<Vec<u8>>>);

impl io::Write for CapturedAccessLog {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl CapturedAccessLog {
    fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync + 'static {
        let writer = self.clone();
        tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_writer(move || writer.clone())
            .finish()
    }

    fn events(&self) -> Vec<serde_json::Value> {
        let data = self.0.lock().unwrap();
        std::str::from_utf8(&data)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|event| event["fields"]["message"] == "UDP session complete")
            .collect()
    }
}

#[tokio::test]
async fn access_log_counts_udp_payloads_and_emits_once_after_peer_close() {
    let capture = CapturedAccessLog::default();
    let (stream, mut peer) = h2_pair(65_535).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let source = client.local_addr().unwrap();
    let response = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let (tx, rx) = datagram_channel_with_limits(8, 1024);
    // Two datagrams in one batch, including a zero-length UDP datagram.
    tx.try_send(Bytes::from_static(b"hello")).unwrap();
    tx.try_send(Bytes::new()).unwrap();
    let (reader, writer) = stream.split_into_buffered_reader();
    let relay = tokio::spawn(
        async move {
            let mut log = test_session_log(source);
            log.gateway = Some("192.0.2.2:15008".parse().unwrap());
            relay_datagrams(
                reader,
                writer,
                response,
                rx,
                test_proxy_metrics(),
                Duration::from_secs(2),
                &mut log,
            )
            .await
            .unwrap();
        }
        .with_subscriber(capture.subscriber()),
    );
    let mut decoder = capsule::Decoder::default();
    let mut uploaded = Vec::new();
    while uploaded.len() < 2 {
        let chunk = tokio::time::timeout(Duration::from_secs(2), peer.recv.data())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        peer.recv
            .flow_control()
            .release_capacity(chunk.len())
            .unwrap();
        uploaded.extend(decoder.push(&chunk).unwrap());
    }
    assert_eq!(uploaded, [Bytes::from_static(b"hello"), Bytes::new()]);
    let mut replies = BytesMut::new();
    capsule::encode_datagram_into(&vec![1; 65_527], &mut replies).unwrap();
    capsule::encode_datagram_into(b"reply", &mut replies).unwrap();
    capsule::encode_datagram_into(b"", &mut replies).unwrap();
    peer.send.send_data(replies.freeze(), false).unwrap();
    assert_eq!(receive(&client).await, b"reply");
    assert_eq!(receive(&client).await, b"");
    assert!(
        capture.events().is_empty(),
        "no per-packet or session-start event"
    );
    peer.send.send_data(Bytes::new(), true).unwrap();
    tokio::time::timeout(Duration::from_secs(2), relay)
        .await
        .unwrap()
        .unwrap();
    let events = capture.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["target"], "access");
    assert_eq!(events[0]["level"], "INFO");
    let fields = &events[0]["fields"];
    assert_eq!(fields["protocol"], "udp");
    assert_eq!(fields["src.addr"], source.to_string());
    assert_eq!(fields["dst.addr"], "192.0.2.1:9000");
    assert_eq!(fields["gateway.addr"], "192.0.2.2:15008");
    assert_eq!(fields["packets_sent"], 2);
    assert_eq!(fields["bytes_sent"], 5);
    assert_eq!(fields["packets_recv"], 2);
    assert_eq!(fields["bytes_recv"], 5);
    assert!(fields["duration_ms"].is_u64());
    assert_eq!(fields["end_reason"], "peer_closed");
}

#[tokio::test]
async fn cancelled_session_logs_once_without_counting_partial_upload() {
    let capture = CapturedAccessLog::default();
    let (stream, mut peer) = h2_pair(16).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let source = client.local_addr().unwrap();
    let response = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let (tx, rx) = datagram_channel_with_limits(8, 1024);
    tx.try_send(Bytes::from(vec![42; 128])).unwrap();
    let (reader, writer) = stream.split_into_buffered_reader();
    async {
        let mut relay = Box::pin(async move {
            let mut log = test_session_log(source);
            relay_datagrams(
                reader,
                writer,
                response,
                rx,
                test_proxy_metrics(),
                Duration::from_secs(5),
                &mut log,
            )
            .await
            .unwrap();
        });
        let exercise = async {
            let first = tokio::time::timeout(Duration::from_secs(2), peer.recv.data())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(first.len(), 16);
            peer.send
                .send_data(capsule::encode_datagram(b"reply").unwrap(), false)
                .unwrap();
            assert_eq!(receive(&client).await, b"reply");
        };
        tokio::select! {
            _ = &mut relay => panic!("blocked upload unexpectedly finished"),
            _ = exercise => {},
        }
        assert!(capture.events().is_empty());
        // Cancel the entire owning future while its upload is flow-control blocked.
        // Drop under this scoped subscriber: WithSubscriber only scopes polling, not
        // tokio task destruction (production uses the process-wide access subscriber).
        drop(relay);
    }
    .with_subscriber(capture.subscriber())
    .await;
    let events = capture.events();
    assert_eq!(events.len(), 1);
    let fields = &events[0]["fields"];
    assert_eq!(fields["end_reason"], "cancelled");
    assert_eq!(fields["packets_sent"], 0);
    assert_eq!(fields["bytes_sent"], 0);
    assert_eq!(fields["packets_recv"], 1);
    assert_eq!(fields["bytes_recv"], 5);
}

#[tokio::test]
async fn idle_session_logs_once_with_zero_counters() {
    let capture = CapturedAccessLog::default();
    let (stream, _peer) = h2_pair(65_535).await;
    let (_tx, rx) = datagram_channel_with_limits(1, 1);
    let response = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let (reader, writer) = stream.split_into_buffered_reader();
    async {
        let mut log = test_session_log("127.0.0.1:12345".parse().unwrap());
        relay_datagrams(
            reader,
            writer,
            response,
            rx,
            test_proxy_metrics(),
            Duration::from_millis(20),
            &mut log,
        )
        .await
        .unwrap();
    }
    .with_subscriber(capture.subscriber())
    .await;
    let events = capture.events();
    assert_eq!(events.len(), 1);
    let fields = &events[0]["fields"];
    assert_eq!(fields["end_reason"], "idle_timeout");
    assert_eq!(fields["gateway.addr"], "unknown");
    assert_eq!(fields["packets_sent"], 0);
    assert_eq!(fields["bytes_sent"], 0);
    assert_eq!(fields["packets_recv"], 0);
    assert_eq!(fields["bytes_recv"], 0);
    assert!(fields["duration_ms"].as_u64().unwrap() >= 20);
}

#[tokio::test]
async fn establishment_failure_logs_once_before_a_gateway_is_selected() {
    let capture = CapturedAccessLog::default();
    // The fixture deliberately has no source workload, so route establishment fails.
    let (outbound, client, _rx, _trigger, _registry) =
        dispatcher_fixture(Duration::from_secs(1)).await;
    let pool = WorkloadHBONEPool::new(
        outbound.pi.cfg.clone(),
        outbound.pi.socket_factory.clone(),
        outbound.pi.local_workload_information.clone(),
    );
    let (_tx, rx) = datagram_channel_with_limits(1, 1);
    async {
        let mut log = test_session_log(client.local_addr().unwrap());
        let error = run_session(
            outbound.pi,
            pool,
            outbound.socket,
            outbound.response_sockets,
            log.key,
            rx,
            &mut log,
        )
        .await
        .unwrap_err();
        log.error = Some(error.to_string());
    }
    .with_subscriber(capture.subscriber())
    .await;
    let events = capture.events();
    assert_eq!(events.len(), 1);
    let fields = &events[0]["fields"];
    assert_eq!(fields["end_reason"], "establishment_error");
    assert_eq!(fields["gateway.addr"], "unknown");
    assert!(!fields["error"].as_str().unwrap().is_empty());
    assert_eq!(fields["packets_sent"], 0);
    assert_eq!(fields["packets_recv"], 0);
}

fn test_session_log(source: SocketAddr) -> SessionLog {
    SessionLog::new(
        FlowKey {
            source,
            destination: "192.0.2.1:9000".parse().unwrap(),
        },
        42,
    )
}

async fn relay_for_test<R, W>(
    reader: R,
    writer: W,
    socket: Arc<UdpSocket>,
    source: SocketAddr,
    datagrams: DatagramReceiver,
    metrics: Arc<crate::proxy::Metrics>,
    idle_timeout: Duration,
) -> Result<(), Error>
where
    R: ResizeBufRead + Unpin,
    W: AsyncWriteBuf + Unpin,
{
    let mut log = test_session_log(source);
    relay_datagrams(
        reader,
        writer,
        socket,
        datagrams,
        metrics,
        idle_timeout,
        &mut log,
    )
    .await
}

struct Peer {
    recv: h2::RecvStream,
    send: h2::SendStream<Bytes>,
    driver: tokio::task::JoinHandle<()>,
    _client_drain: watch::Sender<bool>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

async fn h2_pair(window: u32) -> (H2Stream, Peer) {
    let (client_io, server_io) = tokio::io::duplex(65_536);
    let (stream_tx, stream_rx) = tokio::sync::oneshot::channel();
    let driver = tokio::spawn(async move {
        let mut connection = h2::server::Builder::new()
            .initial_window_size(window)
            .enable_connect_protocol()
            .handshake::<_, Bytes>(server_io)
            .await
            .unwrap();
        let (request, mut response) = connection.accept().await.unwrap().unwrap();
        assert_eq!(
            request
                .extensions()
                .get::<h2::ext::Protocol>()
                .unwrap()
                .as_str(),
            "connect-udp"
        );
        let send = response
            .send_response(http::Response::new(()), false)
            .unwrap();
        assert!(stream_tx.send((request.into_body(), send)).is_ok());
        while connection.accept().await.is_some() {}
    });
    let (client_drain, drain_rx) = watch::channel(false);
    let mut client = spawn_connection(
        Arc::new(crate::config::parse_config().unwrap()),
        client_io,
        drain_rx,
        WorkloadKey {
            src_id: crate::identity::Identity::default(),
            dst_id: vec![crate::identity::Identity::default()],
            src: "127.0.0.1".parse().unwrap(),
            dst: "127.0.0.1:15008".parse().unwrap(),
        },
    )
    .await
    .unwrap();
    let mut request = http::Request::builder()
        .method("CONNECT")
        .uri("https://localhost/.well-known/masque/udp/127.0.0.1/9000/")
        .body(())
        .unwrap();
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static("connect-udp"));
    let (stream, _) = client.send_request(request).await.unwrap();
    let (recv, send) = stream_rx.await.unwrap();
    (
        stream,
        Peer {
            recv,
            send,
            driver,
            _client_drain: client_drain,
        },
    )
}

async fn receive(socket: &UdpSocket) -> Vec<u8> {
    let mut payload = vec![0; 65_536];
    let read = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut payload))
        .await
        .expect("UDP response timed out")
        .unwrap();
    payload.truncate(read);
    payload
}

#[tokio::test]
async fn stalled_h2_upload_delivers_responses_and_resumes_without_corrupting_capsules() {
    let (stream, mut peer) = h2_pair(16).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let response = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let (tx, rx) = datagram_channel_with_limits(8, 1024);
    let payload = Bytes::from(vec![42; 128]);
    tx.try_send(payload.clone()).unwrap();
    let (reader, writer) = stream.split_into_buffered_reader();
    let relay = tokio::spawn(relay_for_test(
        reader,
        writer,
        response,
        client.local_addr().unwrap(),
        rx,
        test_proxy_metrics(),
        Duration::from_secs(5),
    ));

    let first = tokio::time::timeout(Duration::from_secs(2), peer.recv.data())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first.len(), 16);
    // Keep the upload window exhausted until the application receives its response.
    peer.send
        .send_data(capsule::encode_datagram(b"reply").unwrap(), false)
        .unwrap();
    assert_eq!(receive(&client).await, b"reply");

    tx.try_send(Bytes::from_static(b"second")).unwrap();
    let expected = [
        capsule::encode_datagram(&payload).unwrap(),
        capsule::encode_datagram(b"second").unwrap(),
    ]
    .concat();
    let mut wire = first.to_vec();
    peer.recv
        .flow_control()
        .release_capacity(first.len())
        .unwrap();
    while wire.len() < expected.len() {
        let chunk = tokio::time::timeout(Duration::from_secs(2), peer.recv.data())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        peer.recv
            .flow_control()
            .release_capacity(chunk.len())
            .unwrap();
        wire.extend_from_slice(&chunk);
    }
    assert_eq!(wire, expected);
    peer.send.send_data(Bytes::new(), true).unwrap();
    tokio::time::timeout(Duration::from_secs(2), relay)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn closed_input_preserves_delayed_and_valid_responses_after_oversized_datagram() {
    let (stream, mut peer) = h2_pair(65_535).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let response = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let (tx, rx) = datagram_channel_with_limits(8, 1024);
    drop(tx);
    let mut registry = prometheus_client::registry::Registry::default();
    let metrics = Arc::new(crate::proxy::Metrics::new(&mut registry));
    let (reader, writer) = stream.split_into_buffered_reader();
    let relay = tokio::spawn(relay_for_test(
        reader,
        writer,
        response,
        client.local_addr().unwrap(),
        rx,
        metrics,
        Duration::from_secs(5),
    ));
    tokio::task::yield_now().await;
    assert!(!relay.is_finished());

    let mut wire = BytesMut::new();
    capsule::encode_datagram_into(&vec![1; 65_527], &mut wire).unwrap();
    capsule::encode_datagram_into(b"valid-after", &mut wire).unwrap();
    peer.send.send_data(wire.freeze(), false).unwrap();
    assert_eq!(receive(&client).await, b"valid-after");
    assert!(!relay.is_finished());
    peer.send
        .send_data(capsule::encode_datagram(b"still-open").unwrap(), true)
        .unwrap();
    assert_eq!(receive(&client).await, b"still-open");
    tokio::time::timeout(Duration::from_secs(2), relay)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let mut output = String::new();
    prometheus_client::encoding::text::encode(&mut output, &registry).unwrap();
    assert!(output.contains(
        "udp_datagrams_dropped_total{direction=\"outbound\",reason=\"oversized_datagram\"} 1"
    ));
}

#[tokio::test]
async fn closed_input_eventually_expires_without_responses() {
    let (stream, _peer) = h2_pair(65_535).await;
    let (tx, rx) = datagram_channel_with_limits(1, 1);
    drop(tx);
    let response = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let (reader, writer) = stream.split_into_buffered_reader();
    tokio::time::timeout(
        Duration::from_secs(2),
        relay_for_test(
            reader,
            writer,
            response,
            "127.0.0.1:12345".parse().unwrap(),
            rx,
            test_proxy_metrics(),
            Duration::from_millis(20),
        ),
    )
    .await
    .expect("closed input kept the stream alive forever")
    .unwrap();
}

// Seed one existing flow to exercise the real UDP dispatcher and drain wrapper without requiring
// a TLS gateway or Linux TPROXY privileges. The original-destination option alone is unprivileged.
async fn dispatcher_fixture(
    deadline: Duration,
) -> (
    OutboundUdp,
    UdpSocket,
    DatagramReceiver,
    crate::drain::DrainTrigger,
    prometheus_client::registry::Registry,
) {
    let listener = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    #[cfg(target_os = "linux")]
    nix::sys::socket::setsockopt(
        &*listener,
        nix::sys::socket::sockopt::Ipv4OrigDstAddr,
        &true,
    )
    .unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (tx, rx) = datagram_channel_with_limits(8, 1024);
    let mut sessions = SessionTable::new(8);
    sessions
        .insert(
            FlowKey {
                source: client.local_addr().unwrap(),
                destination: listener.local_addr().unwrap(),
            },
            tx,
        )
        .unwrap();
    let (trigger, drain) = crate::drain::new();
    let state = crate::test_helpers::new_proxy_state(&[], &[], &[]);
    let local = Arc::new(crate::proxy::LocalWorkloadInformation::new(
        Arc::new(crate::state::WorkloadInfo {
            name: "source".into(),
            namespace: "default".into(),
            service_account: "default".into(),
        }),
        state.clone(),
        crate::identity::mock::new_secret_manager(Duration::from_secs(10)),
    ));
    let mut registry = prometheus_client::registry::Registry::default();
    let metrics = Arc::new(crate::proxy::Metrics::new(&mut registry));
    let pi = ProxyInputs::new(
        Arc::new(crate::config::Config {
            outbound_udp_addr: "127.0.0.1:0".parse().unwrap(),
            self_termination_deadline: deadline,
            ..crate::config::parse_config().unwrap()
        }),
        crate::proxy::connection_manager::ConnectionManager::default(),
        state,
        metrics,
        Arc::new(crate::proxy::DefaultSocketFactory::default()),
        None,
        local,
        false,
        None,
        None,
        None,
    );
    (
        OutboundUdp {
            response_sockets: Arc::default(),
            pi,
            drain,
            socket: listener,
            sessions,
            drain_started: Some(Arc::new(tokio::sync::Notify::new())),
        },
        client,
        rx,
        trigger,
        registry,
    )
}

#[tokio::test]
async fn graceful_drain_dispatches_existing_flows_rejects_new_flows_and_obeys_deadline() {
    let (proxy, client, mut rx, trigger, registry) =
        dispatcher_fixture(Duration::from_secs(60)).await;
    let destination = proxy.socket.local_addr().unwrap();
    let started = proxy.drain_started.clone().unwrap();
    let running = tokio::spawn(proxy.run());
    client.send_to(b"before", destination).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap()
            .payload,
        "before"
    );
    let draining = tokio::spawn(trigger.start_drain_and_wait(crate::drain::DrainMode::Graceful));
    tokio::time::timeout(Duration::from_secs(2), started.notified())
        .await
        .expect("dispatcher did not start draining");
    assert!(!draining.is_finished());
    client.send_to(b"during", destination).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap()
            .payload,
        "during"
    );
    let newcomer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    newcomer.send_to(b"new-flow", destination).await.unwrap();
    let output = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let mut output = String::new();
            prometheus_client::encoding::text::encode(&mut output, &registry).unwrap();
            if output.contains(
                "udp_datagrams_dropped_total{direction=\"outbound\",reason=\"draining\"} 1",
            ) {
                break output;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("new flow was not rejected during drain");
    assert!(!draining.is_finished());
    // Advance only after socket I/O has completed, so virtual time cannot race kernel readiness.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(60)).await;
    tokio::time::timeout(Duration::from_secs(2), draining)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), running)
        .await
        .unwrap()
        .unwrap();
    assert!(rx.recv().await.is_none());
    assert!(!output.contains("udp_sessions_total{direction=\"outbound\"} 1"));
}

#[tokio::test]
async fn immediate_drain_does_not_wait_for_the_graceful_deadline() {
    let (proxy, _client, mut rx, trigger, _) = dispatcher_fixture(Duration::from_secs(60)).await;
    let running = tokio::spawn(proxy.run());
    tokio::time::timeout(
        Duration::from_secs(2),
        trigger.start_drain_and_wait(crate::drain::DrainMode::Immediate),
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(2), running)
        .await
        .unwrap()
        .unwrap();
    assert!(rx.recv().await.is_none());
}

#[tokio::test]
async fn downstream_activity_does_not_extend_a_blocked_batch_deadline() {
    let capture = CapturedAccessLog::default();
    let (stream, mut peer) = h2_pair(16).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let response = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let (tx, rx) = datagram_channel_with_limits(8, 1024);
    tx.try_send(Bytes::from(vec![42; 128])).unwrap();
    let (reader, writer) = stream.split_into_buffered_reader();
    let mut relay = tokio::spawn(
        relay_for_test(
            reader,
            writer,
            response,
            client.local_addr().unwrap(),
            rx,
            test_proxy_metrics(),
            Duration::from_millis(300),
        )
        .with_subscriber(capture.subscriber()),
    );
    // No capacity is released: the batch must time out even as responses continue arriving.
    let first = tokio::time::timeout(Duration::from_secs(2), peer.recv.data())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first.len(), 16);
    let mut delivered = 0;
    let result = {
        let responses = async {
            loop {
                peer.send
                    .send_data(capsule::encode_datagram(b"reply").unwrap(), false)
                    .unwrap();
                assert_eq!(receive(&client).await, b"reply");
                delivered += 1;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        tokio::select! {
            biased;
            result = &mut relay => result.unwrap(),
            _ = responses => unreachable!(),
            _ = tokio::time::sleep(Duration::from_secs(2)) => panic!("responses kept a blocked upload alive"),
        }
    };
    assert!(delivered > 1);
    assert!(matches!(result, Err(Error::Io(error)) if error.kind() == io::ErrorKind::TimedOut));
    let events = capture.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["fields"]["end_reason"], "hbone_write_timeout");
    assert_eq!(events[0]["fields"]["packets_sent"], 0);
    assert!(events[0]["fields"]["packets_recv"].as_u64().unwrap() > 1);
}
