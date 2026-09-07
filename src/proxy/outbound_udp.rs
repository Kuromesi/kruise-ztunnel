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

use std::collections::HashMap;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use tokio::net::UdpSocket;
use tokio::sync::{Semaphore, mpsc, watch};
use tracing::{Instrument, error, info};

use crate::copy::{AsyncWriteBuf, BufferedSplitter, ResizeBufRead};
use crate::drain::{DrainWatcher, run_with_drain};
use crate::proxy::h2::capsule;
use crate::proxy::metrics::{UdpDirection, UdpDropReason};
use crate::proxy::outbound::OutboundConnection;
use crate::proxy::{Error, ProxyInputs, TraceParent, pool::WorkloadHBONEPool};

// How much of a queued batch is coalesced into a single H2 DATA write. A single UDP datagram may
// exceed this limit, but subsequent datagrams are left for the next write. Not configurable: this
// is a write-batching detail, not a resource bound, and Envoy exposes no equivalent.
const MAX_CAPSULE_BATCH_BYTES: usize = 16_384;
#[cfg(target_os = "linux")]
const UDP_RECEIVE_BUFFER_BYTES: usize = 4 * 1024 * 1024;
const SESSION_ESTABLISH_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FlowKey {
    source: SocketAddr,
    destination: SocketAddr,
}

struct CapsuleBatch {
    bytes: Bytes,
    datagrams: u64,
    payload_bytes: u64,
}

#[derive(Default)]
struct DatagramTotals {
    packets: u64,
    bytes: u64,
}

/// One access event per admitted flow, including establishment failures and cancellation.
/// Counts describe complete upload batches accepted by HBONE and successful UDP replies;
/// they are UDP payload bytes, not capsule/TLS overhead or remote-delivery acknowledgements.
/// Only the two relay futures update their own direction, so no per-packet synchronization
/// or log formatting is needed. Keep this guard outside the cancellable session future.
struct SessionLog {
    key: FlowKey,
    id: u64,
    started: tokio::time::Instant,
    gateway: Option<SocketAddr>,
    sent: DatagramTotals,
    received: DatagramTotals,
    end_reason: &'static str,
    error: Option<String>,
}

impl SessionLog {
    fn new(key: FlowKey, id: u64) -> Self {
        Self {
            key,
            id,
            started: tokio::time::Instant::now(),
            gateway: None,
            sent: DatagramTotals::default(),
            received: DatagramTotals::default(),
            end_reason: "cancelled",
            error: None,
        }
    }
}

impl Drop for SessionLog {
    fn drop(&mut self) {
        let gateway = self.gateway.map(|address| address.to_string());
        info!(
            target: "access",
            parent: None,
            protocol = "udp",
            direction = "outbound",
            session_id = self.id,
            src.addr = %self.key.source,
            dst.addr = %self.key.destination,
            gateway.addr = gateway.as_deref().unwrap_or("unknown"),
            packets_sent = self.sent.packets,
            bytes_sent = self.sent.bytes,
            packets_recv = self.received.packets,
            bytes_recv = self.received.bytes,
            duration_ms = self.started.elapsed().as_millis() as u64,
            end_reason = if std::thread::panicking() { "panic" } else { self.end_reason },
            error = self.error.as_deref(),
            "UDP session complete"
        );
    }
}

struct SessionEntry {
    id: u64,
    sender: DatagramSender,
}

struct SessionTable {
    entries: HashMap<FlowKey, SessionEntry>,
    max_sessions: usize,
    next_id: u64,
}

impl SessionTable {
    fn new(max_sessions: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_sessions,
            next_id: 0,
        }
    }

    fn insert(&mut self, key: FlowKey, sender: DatagramSender) -> Option<u64> {
        if self.entries.len() >= self.max_sessions {
            return None;
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.entries.insert(key, SessionEntry { id, sender });
        Some(id)
    }

    fn complete(&mut self, key: FlowKey, id: u64) {
        if self.entries.get(&key).is_some_and(|entry| entry.id == id) {
            self.entries.remove(&key);
        }
    }

    fn get(&self, key: &FlowKey) -> Option<(u64, DatagramSender)> {
        self.entries
            .get(key)
            .map(|entry| (entry.id, entry.sender.clone()))
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Clone)]
pub(super) struct DatagramSender {
    sender: mpsc::Sender<QueuedDatagram>,
    byte_capacity: Arc<Semaphore>,
    max_bytes: u32,
}

pub(super) struct DatagramReceiver {
    receiver: mpsc::Receiver<QueuedDatagram>,
    drop_metrics: Option<(Arc<crate::proxy::Metrics>, UdpDirection)>,
}

#[derive(Debug)]
pub(super) struct QueuedDatagram {
    pub(super) payload: Bytes,
    _byte_capacity: tokio::sync::OwnedSemaphorePermit,
}

#[derive(Debug)]
pub(super) enum DatagramTrySendError {
    Full,
    Closed(Bytes),
}

impl DatagramSender {
    pub(super) fn try_send(&self, payload: Bytes) -> Result<(), DatagramTrySendError> {
        let permits = payload.len().max(1).min(self.max_bytes as usize) as u32;
        let permit = self
            .byte_capacity
            .clone()
            .try_acquire_many_owned(permits)
            .map_err(|_| DatagramTrySendError::Full)?;
        let queued = QueuedDatagram {
            payload,
            _byte_capacity: permit,
        };
        self.sender.try_send(queued).map_err(|error| match error {
            mpsc::error::TrySendError::Full(queued) => {
                drop(queued);
                DatagramTrySendError::Full
            }
            mpsc::error::TrySendError::Closed(queued) => {
                DatagramTrySendError::Closed(queued.payload)
            }
        })
    }
}

impl DatagramReceiver {
    pub(super) async fn recv(&mut self) -> Option<QueuedDatagram> {
        self.receiver.recv().await
    }

    fn try_recv(&mut self) -> Result<QueuedDatagram, mpsc::error::TryRecvError> {
        self.receiver.try_recv()
    }

    pub(super) fn track_drops(
        &mut self,
        metrics: Arc<crate::proxy::Metrics>,
        direction: UdpDirection,
    ) {
        self.drop_metrics = Some((metrics, direction));
    }

    fn record_pending_drops(&mut self, reason: UdpDropReason) {
        let Some((metrics, direction)) = self.drop_metrics.take() else {
            return;
        };
        let count = self.receiver.len() as u64;
        if count > 0 {
            metrics.udp.record_drop(direction, reason, count);
        }
    }
}

impl Drop for DatagramReceiver {
    fn drop(&mut self) {
        self.record_pending_drops(UdpDropReason::session_end);
    }
}

pub(super) fn datagram_channel_with_limits(
    max_datagrams: usize,
    max_bytes: usize,
) -> (DatagramSender, DatagramReceiver) {
    let max_datagrams = max_datagrams.max(1);
    let max_bytes = max_bytes.max(1).min(u32::MAX as usize) as u32;
    let (sender, receiver) = mpsc::channel(max_datagrams);
    let byte_capacity = Arc::new(Semaphore::new(max_bytes as usize));
    (
        DatagramSender {
            sender,
            byte_capacity,
            max_bytes,
        },
        DatagramReceiver {
            receiver,
            drop_metrics: None,
        },
    )
}

pub(super) fn kernel_overflow_delta(previous: u32, current: u32) -> u64 {
    current.wrapping_sub(previous) as u64
}

struct ResponseSocketEntry {
    socket: Arc<UdpSocket>,
    users: usize,
}

/// Scoped to one OutboundUdp (and therefore one socket factory/network namespace).
/// Sharing by original destination avoids thousands of identical UDP binds, which make
/// Linux's TPROXY socket lookup scan a long chain for every client datagram.
#[derive(Default)]
struct ResponseSocketPool {
    entries: Mutex<HashMap<SocketAddr, ResponseSocketEntry>>,
}

impl ResponseSocketPool {
    fn acquire(
        self: &Arc<Self>,
        destination: SocketAddr,
        create: impl FnOnce() -> io::Result<Arc<UdpSocket>>,
    ) -> io::Result<ResponseSocketLease> {
        // Socket creation is synchronous. Serialize it with removal so concurrent sessions
        // never create duplicate binds; no lock is held across an await or a datagram send.
        let mut entries = self.entries.lock().unwrap();
        let entry = match entries.entry(destination) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => entry.insert(ResponseSocketEntry {
                socket: create()?,
                users: 0,
            }),
        };
        entry.users += 1;
        Ok(ResponseSocketLease {
            pool: self.clone(),
            destination,
            socket: Some(entry.socket.clone()),
        })
    }
}

/// Hold through the entire relay, including cancellation. The relay's socket clone must
/// be dropped before this lease so the last release closes the socket while holding the lock.
struct ResponseSocketLease {
    pool: Arc<ResponseSocketPool>,
    destination: SocketAddr,
    socket: Option<Arc<UdpSocket>>,
}

impl Drop for ResponseSocketLease {
    fn drop(&mut self) {
        let mut entries = self.pool.entries.lock().unwrap();
        let entry = entries.get_mut(&self.destination).unwrap();
        entry.users -= 1;
        self.socket.take();
        if entry.users == 0 {
            entries.remove(&self.destination);
        }
    }
}

pub(super) struct OutboundUdp {
    pi: Arc<ProxyInputs>,
    drain: DrainWatcher,
    socket: Arc<UdpSocket>,
    sessions: SessionTable,
    response_sockets: Arc<ResponseSocketPool>,
    #[cfg(test)]
    drain_started: Option<Arc<tokio::sync::Notify>>,
}

impl OutboundUdp {
    pub(super) async fn new(pi: Arc<ProxyInputs>, drain: DrainWatcher) -> Result<Self, Error> {
        let socket = pi
            .socket_factory
            .udp_bind(pi.cfg.outbound_udp_addr)
            .map_err(|e| Error::Bind(pi.cfg.outbound_udp_addr, e))?;
        enable_original_destination(&socket)?;
        let receive_buffer_bytes = socket_receive_buffer_size(&socket)?;
        pi.metrics
            .udp
            .set_socket_receive_buffer(UdpDirection::outbound, receive_buffer_bytes);
        info!(
            address = %socket.local_addr()?,
            component = "outbound-udp",
            receive_buffer_bytes,
            "experimental CONNECT-UDP listener established"
        );
        let sessions = SessionTable::new(pi.cfg.udp_max_sessions);
        Ok(Self {
            pi,
            drain,
            socket: Arc::new(socket),
            sessions,
            response_sockets: Arc::default(),
            #[cfg(test)]
            drain_started: None,
        })
    }

    pub(super) async fn run(self) {
        let pool = WorkloadHBONEPool::new(
            self.pi.cfg.clone(),
            self.pi.socket_factory.clone(),
            self.pi.local_workload_information.clone(),
        );
        let pi = self.pi.clone();
        let drain = self.drain.clone();
        let accept = async move |sub_drain: DrainWatcher, force_shutdown: watch::Receiver<()>| {
            // Unlike TCP accept, the UDP dispatcher also serves existing sessions. Keep it
            // alive through graceful drain; it observes sub_drain and the hard deadline itself.
            tokio::spawn(
                self.accept(pool, sub_drain, force_shutdown)
                    .in_current_span(),
            )
            .await
        };
        run_with_drain(
            "outbound-udp".to_string(),
            drain,
            pi.cfg.self_termination_deadline,
            accept,
        )
        .await
    }

    /// Receives redirected datagrams and spawns a session per flow.
    ///
    /// During graceful drain, keep dispatching existing flows but refuse new sessions. Both this
    /// task and every session hold a drain watcher and observe the force-shutdown deadline.
    async fn accept(
        self,
        pool: WorkloadHBONEPool,
        drain: DrainWatcher,
        mut force_shutdown: watch::Receiver<()>,
    ) {
        let mut sessions = self.sessions;
        let (completed_tx, mut completed_rx) = mpsc::unbounded_channel();
        let mut receive_batch = ReceiveBatch::new();
        let mut overflow_counter = 0;
        let mut draining = false;
        loop {
            if draining && sessions.entries.is_empty() {
                return;
            }
            tokio::select! {
                biased;
                _ = force_shutdown.changed() => return,
                _ = drain.clone().wait_for_drain(), if !draining => {
                    draining = true;
                    #[cfg(test)]
                    if let Some(started) = &self.drain_started {
                        started.notify_one();
                    }
                }
                completed = completed_rx.recv() => {
                    if let Some((key, id)) = completed {
                        sessions.complete(key, id);
                    }
                }
                received = recv_original_destinations(&self.socket, &mut receive_batch) => {
                    let mut received = match received {
                        Ok(v) => v,
                        Err(err) => {
                            error!(component = "outbound-udp", %err, "failed to receive UDP datagrams");
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            continue;
                        }
                    };
                    if received.truncated > 0 {
                        self.pi.metrics.udp.record_drop(
                            UdpDirection::outbound,
                            UdpDropReason::truncated,
                            received.truncated,
                        );
                    }
                    if received.missing_original_destination > 0 {
                        self.pi.metrics.udp.record_drop(
                            UdpDirection::outbound,
                            UdpDropReason::missing_original_destination,
                            received.missing_original_destination,
                        );
                    }
                    if let Some(current) = received.overflow_counter {
                        let dropped = kernel_overflow_delta(overflow_counter, current);
                        overflow_counter = current;
                        if dropped > 0 {
                            self.pi.metrics.udp.record_drop(
                                UdpDirection::outbound,
                                UdpDropReason::kernel_rx_queue,
                                dropped,
                            );
                        }
                    }
                    let received_bytes = received
                        .datagrams
                        .iter()
                        .map(|datagram| datagram.payload.len() as u64)
                        .sum();
                    self.pi.metrics.udp.record_received(
                        UdpDirection::outbound,
                        received.datagrams.len() as u64,
                        received_bytes,
                    );
                    for datagram in received.datagrams.drain(..) {
                        let key = FlowKey {
                            source: crate::socket::to_canonical(datagram.source),
                            destination: crate::socket::to_canonical(datagram.destination),
                        };
                        if is_illegal_call(
                            key.destination,
                            self.pi.cfg.outbound_udp_addr.port(),
                        ) {
                            self.pi.metrics.udp.record_drop(
                                UdpDirection::outbound,
                                UdpDropReason::self_redirect,
                                1,
                            );
                            continue;
                        }
                        let mut payload = datagram.payload;
                        if let Some((id, sender)) = sessions.get(&key) {
                            match sender.try_send(payload) {
                                Ok(()) => continue,
                                Err(DatagramTrySendError::Full) => {
                                    self.pi.metrics.udp.record_drop(
                                        UdpDirection::outbound,
                                        UdpDropReason::session_queue,
                                        1,
                                    );
                                    continue;
                                }
                                Err(DatagramTrySendError::Closed(returned)) => {
                                    sessions.complete(key, id);
                                    payload = returned;
                                }
                            }
                        }

                        if draining {
                            self.pi.metrics.udp.record_drop(
                                UdpDirection::outbound,
                                UdpDropReason::draining,
                                1,
                            );
                            continue;
                        }
                        let (tx, rx) = datagram_channel_with_limits(
                            self.pi.cfg.udp_max_buffered_datagrams,
                            self.pi.cfg.udp_max_buffered_bytes,
                        );
                        let Some(id) = sessions.insert(key, tx.clone()) else {
                            self.pi.metrics.udp.record_drop(
                                UdpDirection::outbound,
                                UdpDropReason::session_limit,
                                1,
                            );
                            continue;
                        };
                        let mut session_log = SessionLog::new(key, id);
                        if tx.try_send(payload).is_err() {
                            session_log.end_reason = "session_queue_full";
                            self.pi.metrics.udp.record_drop(
                                UdpDirection::outbound,
                                UdpDropReason::session_queue,
                                1,
                            );
                            sessions.complete(key, id);
                            continue;
                        }
                        let socket = self.socket.clone();
                        let response_sockets = self.response_sockets.clone();
                        let pi = self.pi.clone();
                        let session_pool = pool.clone();
                        let completed_tx = completed_tx.clone();
                        // Holding this until the session ends is what lets the drain wait for it.
                        let drain = drain.clone();
                        let mut force_shutdown = force_shutdown.clone();
                        tokio::spawn(async move {
                            // Since this task is spawned, make sure we are guaranteed to terminate
                            tokio::select! {
                                _ = force_shutdown.changed() => {
                                    session_log.end_reason = "force_shutdown";
                                }
                                result = run_session(pi, session_pool, socket, response_sockets, key, rx, &mut session_log) => {
                                    if let Err(err) = result {
                                        session_log.error = Some(err.to_string());
                                    }
                                }
                            }
                            drop(session_log);
                            drop(drain);
                            let _ = completed_tx.send((key, id));
                        });
                    }
                    receive_batch.recycle(received.datagrams);
                }
            }
        }
    }
}

/// Rejects datagrams a client addressed to this listener over loopback, which would otherwise make
/// us open a session to ourselves.
///
/// The loopback gate is the load-bearing part. Only the listener's IP can be compared away, and it
/// is wildcard-bound (`config.rs`), so a comparison against `cfg.outbound_udp_addr` as a whole
/// collapses into a bare port match and drops traffic to a remote host on the same port. Note that
/// the inpod redirect rules only exclude 127.0.0.1/32, so the rest of 127.0.0.0/8 does reach us.
///
/// This deliberately does not consult `cfg.illegal_ports`: that set has no protocol dimension and
/// its other members (15001/15006/15008) are TCP listeners, so matching them here would be
/// meaningless. A destination on the pod's own IP is likewise not our problem — the inbound side
/// rejects it.
///
/// `destination` is canonicalized by the caller, so IPv4-mapped loopback is covered.
fn is_illegal_call(destination: SocketAddr, listener_port: u16) -> bool {
    destination.ip().is_loopback() && destination.port() == listener_port
}

async fn run_session(
    pi: Arc<ProxyInputs>,
    pool: WorkloadHBONEPool,
    socket: Arc<UdpSocket>,
    response_sockets: Arc<ResponseSocketPool>,
    key: FlowKey,
    mut datagrams: DatagramReceiver,
    session_log: &mut SessionLog,
) -> Result<(), Error> {
    let _session = pi.metrics.udp.session_opened(UdpDirection::outbound);
    datagrams.track_drops(pi.metrics.clone(), UdpDirection::outbound);
    let mut outbound = OutboundConnection {
        pi: pi.clone(),
        id: TraceParent::new(),
        pool,
        hbone_port: pi.cfg.inbound_addr.port(),
    };
    let stream = tokio::time::timeout(
        SESSION_ESTABLISH_TIMEOUT,
        outbound.connect_udp(key.source, key.destination, &mut session_log.gateway),
    )
    .await;
    let stream = match stream {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            session_log.end_reason = "establishment_error";
            datagrams.record_pending_drops(UdpDropReason::session_establishment);
            return Err(error);
        }
        Err(_) => {
            session_log.end_reason = "establishment_timeout";
            datagrams.record_pending_drops(UdpDropReason::session_establishment);
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "CONNECT-UDP session establishment timed out",
            )));
        }
    };
    let response_socket = response_sockets
        .acquire(key.destination, || {
            response_socket(key.destination, pi.socket_factory.as_ref(), socket)
        })
        .inspect_err(|_| {
            session_log.end_reason = "response_socket_error";
        })?;
    let (reader, writer) = stream.split_into_buffered_reader();
    relay_datagrams(
        reader,
        writer,
        response_socket.socket.as_ref().unwrap().clone(),
        datagrams,
        pi.metrics.clone(),
        pi.cfg.udp_session_idle_timeout,
        session_log,
    )
    .await
}

/// Keep both directions polled even when one writer is blocked. Each future owns its pending
/// bytes for its entire lifetime, so selecting activity in the other direction cannot cancel a
/// partially written capsule. Any error or deadline terminates the whole stream.
async fn relay_datagrams<R, W>(
    mut reader: R,
    mut writer: W,
    response_socket: Arc<UdpSocket>,
    mut datagrams: DatagramReceiver,
    metrics: Arc<crate::proxy::Metrics>,
    idle_timeout: Duration,
    session_log: &mut SessionLog,
) -> Result<(), Error>
where
    R: ResizeBufRead + Unpin,
    W: AsyncWriteBuf + Unpin,
{
    let source = session_log.key.source;
    let (activity, mut last_activity) = watch::channel(tokio::time::Instant::now());
    let mut in_flight_datagrams = 0;
    let mut upload_reason = "capsule_encode_error";
    let mut download_reason = "hbone_read_error";
    let (end_reason, result) = {
        let upload = async {
            loop {
                upload_reason = "capsule_encode_error";
                let Some(batch) = next_capsule_batch(&mut datagrams).await? else {
                    break;
                };
                in_flight_datagrams = batch.datagrams;
                let encoded_bytes = batch.bytes.len() as u64;
                activity.send_replace(tokio::time::Instant::now());
                // Bound the total time for this batch, independently of downstream activity.
                upload_reason = "hbone_write_timeout";
                let written =
                    tokio::time::timeout(idle_timeout, write_all_buf(&mut writer, batch.bytes))
                        .await
                        .map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::TimedOut,
                                "CONNECT-UDP stream write stalled",
                            )
                        })?;
                upload_reason = "hbone_write_error";
                written?;
                session_log.sent.packets += batch.datagrams;
                session_log.sent.bytes += batch.payload_bytes;
                metrics.udp.record_capsule_batch(
                    UdpDirection::outbound,
                    in_flight_datagrams,
                    encoded_bytes,
                );
                in_flight_datagrams = 0;
                activity.send_replace(tokio::time::Instant::now());
            }
            // Closing the input queue does not imply that all responses have arrived. Keep the
            // stream open for its reader until idle timeout, peer close, or forced shutdown.
            std::future::pending::<Result<(), Error>>().await
        };
        let download = async {
            let mut decoder = capsule::Decoder::default();
            loop {
                download_reason = "hbone_read_error";
                let read = poll_fn(|cx| Pin::new(&mut reader).poll_bytes(cx)).await?;
                if read.is_empty() {
                    download_reason = "peer_closed";
                    return Ok::<(), Error>(());
                }
                download_reason = "capsule_decode_error";
                let payloads = decoder.push(&read)?;
                let dropped_oversized = decoder.take_dropped_oversized();
                if dropped_oversized > 0 {
                    metrics.udp.record_drop(
                        UdpDirection::outbound,
                        UdpDropReason::oversized_datagram,
                        dropped_oversized,
                    );
                }
                for payload in payloads {
                    activity.send_replace(tokio::time::Instant::now());
                    download_reason = "response_send_error";
                    if send_response(&response_socket, source, &payload, &metrics).await? {
                        session_log.received.packets += 1;
                        session_log.received.bytes += payload.len() as u64;
                    }
                }
            }
        };
        let idle = async {
            loop {
                let deadline = *last_activity.borrow_and_update() + idle_timeout;
                if tokio::time::timeout_at(deadline, last_activity.changed())
                    .await
                    .is_err()
                {
                    return;
                }
            }
        };
        tokio::select! {
            result = upload => (upload_reason, result),
            result = download => (download_reason, result),
            _ = idle => ("idle_timeout", Ok(())),
        }
    };
    session_log.end_reason = end_reason;
    if in_flight_datagrams > 0 {
        metrics.udp.record_drop(
            UdpDirection::outbound,
            UdpDropReason::hbone_write,
            in_flight_datagrams,
        );
    }
    result
}

async fn send_response(
    socket: &UdpSocket,
    source: SocketAddr,
    payload: &[u8],
    metrics: &crate::proxy::Metrics,
) -> io::Result<bool> {
    // The capsule format supports the IPv6 maximum, but IPv4 cannot carry as much payload.
    let max_payload = if source.is_ipv4() { 65_507 } else { 65_527 };
    if payload.len() > max_payload {
        metrics
            .udp
            .record_drop(UdpDirection::outbound, UdpDropReason::oversized_datagram, 1);
        return Ok(false);
    }
    match socket.send_to(payload, source).await {
        Ok(_) => {
            metrics
                .udp
                .record_sent(UdpDirection::outbound, 1, payload.len() as u64);
            return Ok(true);
        }
        Err(error) => {
            metrics
                .udp
                .record_drop(UdpDirection::outbound, UdpDropReason::response_send, 1);
            // Datagram-specific size/buffer errors do not make the socket unusable. Keep other
            // responses and the tunnel alive, as Envoy's UDP downstream send path does.
            if !matches!(error.raw_os_error(), Some(libc::EMSGSIZE | libc::ENOBUFS))
                && !matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                )
            {
                return Err(error);
            }
        }
    }
    Ok(false)
}

async fn next_capsule_batch(datagrams: &mut DatagramReceiver) -> io::Result<Option<CapsuleBatch>> {
    let Some(first) = datagrams.recv().await else {
        return Ok(None);
    };
    let mut batch = BytesMut::with_capacity(
        first
            .payload
            .len()
            .saturating_add(10)
            .min(MAX_CAPSULE_BATCH_BYTES),
    );
    capsule::encode_datagram_into(&first.payload, &mut batch)?;
    let mut datagram_count = 1;
    let mut payload_bytes = first.payload.len() as u64;

    while batch.len() < MAX_CAPSULE_BATCH_BYTES {
        let payload = match datagrams.try_recv() {
            Ok(payload) => payload,
            Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                break;
            }
        };
        capsule::encode_datagram_into(&payload.payload, &mut batch)?;
        datagram_count += 1;
        payload_bytes += payload.payload.len() as u64;
    }
    Ok(Some(CapsuleBatch {
        bytes: batch.freeze(),
        datagrams: datagram_count,
        payload_bytes,
    }))
}

async fn write_all_buf<W>(writer: &mut W, mut buf: Bytes) -> io::Result<()>
where
    W: AsyncWriteBuf + Unpin,
{
    while !buf.is_empty() {
        let written = poll_fn(|cx| Pin::new(&mut *writer).poll_write_buf(cx, buf.clone())).await?;
        if written == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        buf.advance(written);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn enable_original_destination(socket: &UdpSocket) -> io::Result<()> {
    use nix::sys::socket::{setsockopt, sockopt};

    let socket_ref = socket2::SockRef::from(socket);
    socket_ref.set_ip_transparent_v4(true)?;
    setsockopt(socket, sockopt::Ipv4OrigDstAddr, &true).map_err(io::Error::from)?;
    setsockopt(socket, sockopt::RxqOvfl, &1).map_err(io::Error::from)?;
    setsockopt(socket, sockopt::RcvBuf, &UDP_RECEIVE_BUFFER_BYTES).map_err(io::Error::from)?;
    if socket.local_addr()?.is_ipv6() {
        socket_ref.set_ip_transparent_v6(true)?;
        setsockopt(socket, sockopt::Ipv6OrigDstAddr, &true).map_err(io::Error::from)?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(super) fn enable_original_destination(_socket: &UdpSocket) -> io::Result<()> {
    Ok(())
}

pub(super) fn socket_receive_buffer_size(socket: &UdpSocket) -> io::Result<usize> {
    socket2::SockRef::from(socket).recv_buffer_size()
}

/// Binds a socket that replies to the client with the flow's original destination as the source.
///
/// The socket must come from `socket_factory`, not from `socket2::Socket::new`: in in-pod mode the
/// factory is what enters the workload's network namespace, and it only stays there for the
/// duration of the call. `run_session` runs on a task spawned long after `OutboundUdp::new`
/// returned, so a directly created socket would land in ztunnel's own namespace and send the
/// response into the wrong pod. The factory also owns the mark, as it does for TCP.
#[cfg(target_os = "linux")]
pub(super) fn response_socket(
    destination: SocketAddr,
    socket_factory: &(dyn crate::proxy::SocketFactory + Send + Sync),
    _listener: Arc<UdpSocket>,
) -> io::Result<Arc<UdpSocket>> {
    use socket2::SockAddr;

    let socket = match destination {
        SocketAddr::V4(_) => {
            let socket = socket_factory.new_udp_v4()?;
            socket.set_ip_transparent_v4(true)?;
            socket
        }
        SocketAddr::V6(_) => {
            let socket = socket_factory.new_udp_v6()?;
            socket.set_ip_transparent_v6(true)?;
            socket
        }
    };
    socket.set_reuse_address(true)?;
    socket.bind(&SockAddr::from(destination))?;
    socket.set_nonblocking(true)?;
    Ok(Arc::new(UdpSocket::from_std(socket.into())?))
}

#[cfg(not(target_os = "linux"))]
pub(super) fn response_socket(
    _destination: SocketAddr,
    _socket_factory: &(dyn crate::proxy::SocketFactory + Send + Sync),
    listener: Arc<UdpSocket>,
) -> io::Result<Arc<UdpSocket>> {
    Ok(listener)
}

pub(super) struct ReceivedDatagram {
    pub(super) payload: Bytes,
    pub(super) source: SocketAddr,
    pub(super) destination: SocketAddr,
}

pub(super) struct ReceivedDatagrams {
    pub(super) datagrams: Vec<ReceivedDatagram>,
    pub(super) overflow_counter: Option<u32>,
    pub(super) truncated: u64,
    pub(super) missing_original_destination: u64,
}

impl ReceivedDatagrams {
    fn empty(datagrams: Vec<ReceivedDatagram>) -> Self {
        Self {
            datagrams,
            overflow_counter: None,
            truncated: 0,
            missing_original_destination: 0,
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) use linux_receive::ReceiveBatch;

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub(super) mod linux_receive {
    use std::io;
    use std::mem::{self, size_of};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    use std::os::fd::RawFd;
    use std::ptr;

    use bytes::Bytes;

    use super::{ReceivedDatagram, ReceivedDatagrams};

    const DATAGRAMS_PER_SYSCALL: usize = 16;
    const MAX_DATAGRAMS_PER_READY: usize = 256;
    const MAX_DATAGRAM_SIZE: usize = 65_536;

    pub(in crate::proxy) struct ReceiveBatch {
        payloads: Vec<Box<[u8]>>,
        iovecs: Vec<libc::iovec>,
        addresses: Vec<libc::sockaddr_storage>,
        controls: Vec<Box<[u8]>>,
        messages: Vec<libc::mmsghdr>,
        output: Vec<ReceivedDatagram>,
    }

    // SAFETY: The raw pointers stored in iovecs/messages always target heap allocations owned by
    // the same ReceiveBatch. Those allocations remain stable when the struct moves between Tokio
    // worker threads, and the pointers are reset immediately before every synchronous recvmmsg.
    unsafe impl Send for ReceiveBatch {}

    impl ReceiveBatch {
        pub(in crate::proxy) fn new() -> Self {
            let control_size =
                nix::cmsg_space!(libc::sockaddr_in, libc::sockaddr_in6, u32).capacity();
            Self {
                payloads: (0..DATAGRAMS_PER_SYSCALL)
                    .map(|_| vec![0; MAX_DATAGRAM_SIZE].into_boxed_slice())
                    .collect(),
                // SAFETY: All-zero is a valid initial state for these libc receive structures.
                iovecs: (0..DATAGRAMS_PER_SYSCALL)
                    .map(|_| unsafe { mem::zeroed() })
                    .collect(),
                // SAFETY: sockaddr_storage is plain data and is initialized by recvmmsg.
                addresses: (0..DATAGRAMS_PER_SYSCALL)
                    .map(|_| unsafe { mem::zeroed() })
                    .collect(),
                controls: (0..DATAGRAMS_PER_SYSCALL)
                    .map(|_| vec![0; control_size].into_boxed_slice())
                    .collect(),
                // SAFETY: Each header is fully populated before recvmmsg reads it.
                messages: (0..DATAGRAMS_PER_SYSCALL)
                    .map(|_| unsafe { mem::zeroed() })
                    .collect(),
                output: Vec::with_capacity(MAX_DATAGRAMS_PER_READY),
            }
        }

        pub(in crate::proxy) fn recycle(&mut self, mut datagrams: Vec<ReceivedDatagram>) {
            datagrams.clear();
            self.output = datagrams;
        }

        pub(super) fn recv_nonblocking(&mut self, fd: RawFd) -> io::Result<ReceivedDatagrams> {
            let mut output = mem::take(&mut self.output);
            output.clear();
            let mut received = ReceivedDatagrams::empty(output);
            let mut packets_processed = 0;

            loop {
                match self.recv_once(fd) {
                    Ok(0) if received.datagrams.is_empty() => {
                        self.output = received.datagrams;
                        return Err(io::ErrorKind::WouldBlock.into());
                    }
                    Ok(0) => return Ok(received),
                    Ok(count) => {
                        packets_processed += count;
                        for index in 0..count {
                            self.decode_message(index, &mut received);
                        }
                        if packets_processed >= MAX_DATAGRAMS_PER_READY {
                            return Ok(received);
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if received.datagrams.is_empty()
                            && received.truncated == 0
                            && received.missing_original_destination == 0
                        {
                            self.output = received.datagrams;
                            return Err(error);
                        }
                        return Ok(received);
                    }
                    Err(error) => {
                        if received.datagrams.is_empty()
                            && received.truncated == 0
                            && received.missing_original_destination == 0
                        {
                            self.output = received.datagrams;
                            return Err(error);
                        }
                        return Ok(received);
                    }
                }
            }
        }

        fn recv_once(&mut self, fd: RawFd) -> io::Result<usize> {
            for index in 0..DATAGRAMS_PER_SYSCALL {
                self.iovecs[index] = libc::iovec {
                    iov_base: self.payloads[index].as_mut_ptr().cast(),
                    iov_len: self.payloads[index].len(),
                };
                self.addresses[index] = unsafe { mem::zeroed() };
                self.controls[index].fill(0);
                self.messages[index] = unsafe { mem::zeroed() };
                let header = &mut self.messages[index].msg_hdr;
                header.msg_name = ptr::from_mut(&mut self.addresses[index]).cast();
                header.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                header.msg_iov = ptr::from_mut(&mut self.iovecs[index]);
                header.msg_iovlen = 1 as _;
                header.msg_control = self.controls[index].as_mut_ptr().cast();
                header.msg_controllen = self.controls[index].len() as _;
                header.msg_flags = 0;
            }

            // SAFETY: All message headers point to live, writable buffers owned by self for the
            // duration of this call, and the vector has DATAGRAMS_PER_SYSCALL elements.
            let result = unsafe {
                libc::recvmmsg(
                    fd,
                    self.messages.as_mut_ptr(),
                    DATAGRAMS_PER_SYSCALL as u32,
                    libc::MSG_DONTWAIT,
                    ptr::null_mut(),
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(result as usize)
        }

        fn decode_message(&self, index: usize, received: &mut ReceivedDatagrams) {
            let message = &self.messages[index];
            if message.msg_hdr.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
                || message.msg_len as usize > self.payloads[index].len()
            {
                received.truncated += 1;
                return;
            }

            let Ok(source) =
                raw_socket_address(&self.addresses[index], message.msg_hdr.msg_namelen)
            else {
                received.missing_original_destination += 1;
                return;
            };
            let (destination, overflow_counter) = control_messages(&message.msg_hdr);
            if let Some(counter) = overflow_counter {
                received.overflow_counter = Some(counter);
            }
            let Some(destination) = destination else {
                received.missing_original_destination += 1;
                return;
            };
            received.datagrams.push(ReceivedDatagram {
                payload: Bytes::copy_from_slice(&self.payloads[index][..message.msg_len as usize]),
                source,
                destination,
            });
        }
    }

    fn raw_socket_address(
        storage: &libc::sockaddr_storage,
        length: libc::socklen_t,
    ) -> io::Result<SocketAddr> {
        match storage.ss_family as libc::c_int {
            libc::AF_INET if length as usize >= size_of::<libc::sockaddr_in>() => {
                // SAFETY: The address family and kernel-provided length identify sockaddr_in.
                let address = unsafe {
                    ptr::read_unaligned(ptr::from_ref(storage).cast::<libc::sockaddr_in>())
                };
                Ok(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
                    u16::from_be(address.sin_port),
                )))
            }
            libc::AF_INET6 if length as usize >= size_of::<libc::sockaddr_in6>() => {
                // SAFETY: The address family and kernel-provided length identify sockaddr_in6.
                let address = unsafe {
                    ptr::read_unaligned(ptr::from_ref(storage).cast::<libc::sockaddr_in6>())
                };
                Ok(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(address.sin6_addr.s6_addr),
                    u16::from_be(address.sin6_port),
                    address.sin6_flowinfo,
                    address.sin6_scope_id,
                )))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported UDP source address family",
            )),
        }
    }

    fn control_messages(header: &libc::msghdr) -> (Option<SocketAddr>, Option<u32>) {
        let mut destination = None;
        let mut overflow_counter = None;
        // SAFETY: CMSG_LEN only performs the libc alignment calculation for these fixed sizes.
        let sockaddr_in_len =
            unsafe { libc::CMSG_LEN(size_of::<libc::sockaddr_in>() as u32) as usize };
        let sockaddr_in6_len =
            unsafe { libc::CMSG_LEN(size_of::<libc::sockaddr_in6>() as u32) as usize };
        let overflow_len = unsafe { libc::CMSG_LEN(size_of::<u32>() as u32) as usize };
        // SAFETY: header and its control buffer were initialized by recvmmsg and remain live while
        // this function walks the kernel-provided cmsghdr chain.
        let mut control = unsafe { libc::CMSG_FIRSTHDR(ptr::from_ref(header)) };
        while !control.is_null() {
            // SAFETY: CMSG_FIRSTHDR/CMSG_NXTHDR only return headers within msg_control.
            let control_ref = unsafe { &*control };
            let data = unsafe { libc::CMSG_DATA(control) };
            match (control_ref.cmsg_level, control_ref.cmsg_type) {
                (libc::IPPROTO_IP, libc::IP_ORIGDSTADDR)
                    if control_ref.cmsg_len >= sockaddr_in_len =>
                {
                    // SAFETY: cmsg_len proves the payload contains sockaddr_in.
                    let address = unsafe { ptr::read_unaligned(data.cast::<libc::sockaddr_in>()) };
                    destination = Some(SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
                        u16::from_be(address.sin_port),
                    )));
                }
                (libc::IPPROTO_IPV6, libc::IPV6_ORIGDSTADDR)
                    if control_ref.cmsg_len >= sockaddr_in6_len =>
                {
                    // SAFETY: cmsg_len proves the payload contains sockaddr_in6.
                    let address = unsafe { ptr::read_unaligned(data.cast::<libc::sockaddr_in6>()) };
                    destination = Some(SocketAddr::V6(SocketAddrV6::new(
                        Ipv6Addr::from(address.sin6_addr.s6_addr),
                        u16::from_be(address.sin6_port),
                        address.sin6_flowinfo,
                        address.sin6_scope_id,
                    )));
                }
                (libc::SOL_SOCKET, libc::SO_RXQ_OVFL) if control_ref.cmsg_len >= overflow_len => {
                    // SAFETY: cmsg_len proves the payload contains u32.
                    overflow_counter = Some(unsafe { ptr::read_unaligned(data.cast::<u32>()) });
                }
                _ => {}
            }
            control = unsafe { libc::CMSG_NXTHDR(ptr::from_ref(header), control) };
        }
        (destination, overflow_counter)
    }
}

#[cfg(target_os = "linux")]
pub(super) async fn recv_original_destinations(
    socket: &UdpSocket,
    receive_batch: &mut ReceiveBatch,
) -> io::Result<ReceivedDatagrams> {
    use std::os::fd::AsRawFd;
    use tokio::io::Interest;

    socket
        .async_io(Interest::READABLE, || {
            receive_batch.recv_nonblocking(socket.as_raw_fd())
        })
        .await
}

#[cfg(not(target_os = "linux"))]
pub(super) struct ReceiveBatch {
    payload: Vec<u8>,
    output: Vec<ReceivedDatagram>,
}

#[cfg(not(target_os = "linux"))]
impl ReceiveBatch {
    pub(super) fn new() -> Self {
        Self {
            payload: vec![0; 65_536],
            output: Vec::with_capacity(1),
        }
    }

    pub(super) fn recycle(&mut self, mut datagrams: Vec<ReceivedDatagram>) {
        datagrams.clear();
        self.output = datagrams;
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) async fn recv_original_destinations(
    socket: &UdpSocket,
    receive_batch: &mut ReceiveBatch,
) -> io::Result<ReceivedDatagrams> {
    let (bytes, source) = socket.recv_from(&mut receive_batch.payload).await?;
    let mut datagrams = std::mem::take(&mut receive_batch.output);
    datagrams.push(ReceivedDatagram {
        payload: Bytes::copy_from_slice(&receive_batch.payload[..bytes]),
        source,
        destination: socket.local_addr()?,
    });
    Ok(ReceivedDatagrams::empty(datagrams))
}

#[cfg(test)]
mod tests {
    fn pooled_test_socket() -> std::io::Result<std::sync::Arc<tokio::net::UdpSocket>> {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        socket.set_nonblocking(true)?;
        Ok(std::sync::Arc::new(tokio::net::UdpSocket::from_std(
            socket,
        )?))
    }

    #[tokio::test]
    async fn response_socket_pool_shares_replies_and_releases_last_user() {
        let pool = std::sync::Arc::new(super::ResponseSocketPool::default());
        let destination = "192.0.2.1:9000".parse().unwrap();
        let first = pool.acquire(destination, pooled_test_socket).unwrap();
        let second = pool
            .acquire(destination, || panic!("duplicate bind"))
            .unwrap();
        let weak = std::sync::Arc::downgrade(first.socket.as_ref().unwrap());
        assert!(std::sync::Arc::ptr_eq(
            first.socket.as_ref().unwrap(),
            second.socket.as_ref().unwrap()
        ));
        let source = first.socket.as_ref().unwrap().local_addr().unwrap();
        let client_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        first
            .socket
            .as_ref()
            .unwrap()
            .send_to(b"a", client_a.local_addr().unwrap())
            .await
            .unwrap();
        drop(first);
        second
            .socket
            .as_ref()
            .unwrap()
            .send_to(b"b", client_b.local_addr().unwrap())
            .await
            .unwrap();
        for (client, expected) in [(client_a, b'a'), (client_b, b'b')] {
            let mut buf = [0; 8];
            let (len, peer) = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                client.recv_from(&mut buf),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!((len, buf[0], peer), (1, expected, source));
        }
        assert_eq!(pool.entries.lock().unwrap().len(), 1);
        drop(second);
        assert!(pool.entries.lock().unwrap().is_empty());
        assert!(weak.upgrade().is_none());
        let reopened = pool.acquire(destination, pooled_test_socket).unwrap();
        drop(reopened);
        assert!(pool.entries.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn response_socket_pool_isolates_destinations_and_factories() {
        let pool = std::sync::Arc::new(super::ResponseSocketPool::default());
        let other_pool = std::sync::Arc::new(super::ResponseSocketPool::default());
        let a = "192.0.2.1:9000".parse().unwrap();
        assert!(
            pool.acquire(a, || Err(std::io::Error::other("bind failed")))
                .is_err()
        );
        assert!(pool.entries.lock().unwrap().is_empty());
        let leases = [
            pool.acquire(a, pooled_test_socket).unwrap(),
            pool.acquire("192.0.2.1:9001".parse().unwrap(), pooled_test_socket)
                .unwrap(),
            pool.acquire("192.0.2.2:9000".parse().unwrap(), pooled_test_socket)
                .unwrap(),
            pool.acquire("[2001:db8::1]:9000".parse().unwrap(), pooled_test_socket)
                .unwrap(),
            other_pool.acquire(a, pooled_test_socket).unwrap(),
        ];
        for (i, lease) in leases.iter().enumerate() {
            for other in &leases[i + 1..] {
                assert!(!std::sync::Arc::ptr_eq(
                    lease.socket.as_ref().unwrap(),
                    other.socket.as_ref().unwrap()
                ));
            }
        }
        drop(leases);
        assert!(pool.entries.lock().unwrap().is_empty());
        assert!(other_pool.entries.lock().unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn response_socket_pool_concurrent_creation_and_cancellation() {
        let pool = std::sync::Arc::new(super::ResponseSocketPool::default());
        let creates = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(17));
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let (pool, creates, barrier) = (pool.clone(), creates.clone(), barrier.clone());
            tasks.push(tokio::spawn(async move {
                let _lease = pool
                    .acquire("192.0.2.1:9000".parse().unwrap(), || {
                        creates.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        pooled_test_socket()
                    })
                    .unwrap();
                barrier.wait().await;
                std::future::pending::<()>().await;
            }));
        }
        barrier.wait().await;
        assert_eq!(creates.load(std::sync::atomic::Ordering::SeqCst), 1);
        let weak = std::sync::Arc::downgrade(
            &pool.entries.lock().unwrap().values().next().unwrap().socket,
        );
        for task in tasks {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        }
        assert!(pool.entries.lock().unwrap().is_empty());
        assert!(weak.upgrade().is_none());
    }

    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use bytes::{Bytes, BytesMut};

    struct ChunkedWriter {
        max_write: usize,
        output: BytesMut,
    }

    impl crate::copy::AsyncWriteBuf for ChunkedWriter {
        fn poll_write_buf(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: Bytes,
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            let written = this.max_write.min(buf.len());
            this.output.extend_from_slice(&buf[..written]);
            Poll::Ready(Ok(written))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn retries_partial_h2_writes_without_losing_bytes() {
        let mut writer = ChunkedWriter {
            max_write: 3,
            output: BytesMut::new(),
        };

        super::write_all_buf(&mut writer, Bytes::from_static(b"0123456789"))
            .await
            .unwrap();

        assert_eq!(writer.output.as_ref(), b"0123456789");
    }

    #[tokio::test]
    async fn coalesces_ready_datagrams_without_losing_capsule_boundaries() {
        let (tx, mut rx) = super::datagram_channel_with_limits(4, 1_024);
        tx.try_send(Bytes::from_static(b"one")).unwrap();
        tx.try_send(Bytes::from_static(b"two")).unwrap();
        tx.try_send(Bytes::from_static(b"three")).unwrap();

        let batch = super::next_capsule_batch(&mut rx).await.unwrap().unwrap();
        let mut decoder = crate::proxy::h2::capsule::Decoder::default();

        assert_eq!(batch.datagrams, 3);
        assert_eq!(
            decoder.push(&batch.bytes).unwrap(),
            vec![
                Bytes::from_static(b"one"),
                Bytes::from_static(b"two"),
                Bytes::from_static(b"three"),
            ]
        );
    }

    #[tokio::test]
    async fn oversized_datagram_does_not_drain_the_next_batch() {
        let (tx, mut rx) = super::datagram_channel_with_limits(2, 32_768);
        let oversized = Bytes::from(vec![0x5a; super::MAX_CAPSULE_BATCH_BYTES]);
        tx.try_send(oversized.clone()).unwrap();
        tx.try_send(Bytes::from_static(b"next")).unwrap();

        let batch = super::next_capsule_batch(&mut rx).await.unwrap().unwrap();
        let mut decoder = crate::proxy::h2::capsule::Decoder::default();

        assert_eq!(batch.datagrams, 1);
        assert_eq!(decoder.push(&batch.bytes).unwrap(), vec![oversized]);
        assert_eq!(rx.try_recv().unwrap().payload, Bytes::from_static(b"next"));
    }

    #[tokio::test]
    async fn byte_bounded_queue_accepts_small_bursts_beyond_eight_datagrams() {
        let (tx, mut rx) = super::datagram_channel_with_limits(1_024, 16_384);

        for value in 0..32u8 {
            tx.try_send(Bytes::from(vec![value; 64])).unwrap();
        }

        for value in 0..32u8 {
            assert_eq!(
                rx.recv().await.unwrap().payload,
                Bytes::from(vec![value; 64])
            );
        }
    }

    /// The byte bound, not the datagram bound, is what limits a burst of MTU-sized datagrams.
    /// Deliberately passes its own limits rather than reading the config default, so that retuning
    /// the default does not silently change what this asserts.
    #[tokio::test]
    async fn queue_absorbs_a_burst_up_to_the_byte_limit() {
        let (tx, mut rx) = super::datagram_channel_with_limits(1_024, 16 * 1_024);

        for value in 0..16u8 {
            tx.try_send(Bytes::from(vec![value; 1_024])).unwrap();
        }
        // The datagram bound is nowhere near reached, so this can only be the byte bound.
        assert!(matches!(
            tx.try_send(Bytes::from_static(b"over")),
            Err(super::DatagramTrySendError::Full)
        ));

        for value in 0..16u8 {
            assert_eq!(
                rx.recv().await.unwrap().payload,
                Bytes::from(vec![value; 1_024])
            );
        }
    }

    #[tokio::test]
    async fn byte_bounded_queue_releases_capacity_after_receive() {
        let (tx, mut rx) = super::datagram_channel_with_limits(1_024, 100);
        tx.try_send(Bytes::from(vec![1; 60])).unwrap();

        let rejected = tx.try_send(Bytes::from(vec![2; 41])).unwrap_err();
        assert!(matches!(rejected, super::DatagramTrySendError::Full));

        let first = rx.recv().await.unwrap();
        assert_eq!(first.payload.len(), 60);
        drop(first);
        tx.try_send(Bytes::from(vec![2; 41])).unwrap();
    }

    #[tokio::test]
    async fn byte_bounded_queue_allows_one_oversized_datagram_when_empty() {
        let (tx, mut rx) = super::datagram_channel_with_limits(1_024, 100);
        tx.try_send(Bytes::from(vec![1; 101])).unwrap();
        assert!(matches!(
            tx.try_send(Bytes::from_static(b"next")),
            Err(super::DatagramTrySendError::Full)
        ));

        let oversized = rx.recv().await.unwrap();
        assert_eq!(oversized.payload.len(), 101);
        drop(oversized);
        tx.try_send(Bytes::from_static(b"next")).unwrap();
    }

    #[test]
    fn receiver_drop_records_all_queued_datagrams() {
        let mut registry = prometheus_client::registry::Registry::default();
        let metrics = Arc::new(crate::proxy::Metrics::new(&mut registry));
        let (tx, mut rx) = super::datagram_channel_with_limits(8, 1_024);
        tx.try_send(Bytes::from_static(b"one")).unwrap();
        tx.try_send(Bytes::from_static(b"two")).unwrap();
        rx.track_drops(metrics, crate::proxy::metrics::UdpDirection::outbound);

        drop(rx);
        let mut output = String::new();
        prometheus_client::encoding::text::encode(&mut output, &registry).unwrap();

        assert!(output.contains(
            "udp_datagrams_dropped_total{direction=\"outbound\",reason=\"session_end\"} 2"
        ));
    }

    #[test]
    fn kernel_overflow_delta_handles_counter_wraparound() {
        assert_eq!(super::kernel_overflow_delta(10, 15), 5);
        assert_eq!(super::kernel_overflow_delta(u32::MAX - 2, 1), 4);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn recvmmsg_reads_multiple_datagrams_with_original_destination() {
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        super::enable_original_destination(&receiver).unwrap();
        let destination = receiver.local_addr().unwrap();
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        for value in 0..4u8 {
            sender.send_to(&[value; 32], destination).await.unwrap();
        }

        let mut receive_batch = super::ReceiveBatch::new();
        let received = super::recv_original_destinations(&receiver, &mut receive_batch)
            .await
            .unwrap();

        assert_eq!(received.datagrams.len(), 4);
        assert_eq!(received.truncated, 0);
        assert_eq!(received.missing_original_destination, 0);
        for (index, datagram) in received.datagrams.iter().enumerate() {
            assert_eq!(datagram.payload, Bytes::from(vec![index as u8; 32]));
            assert_eq!(datagram.destination, destination);
            assert_eq!(datagram.source, sender.local_addr().unwrap());
        }
    }

    #[test]
    fn rejects_new_flow_when_session_limit_is_reached() {
        let first = super::FlowKey {
            source: "127.0.0.1:10001".parse::<SocketAddr>().unwrap(),
            destination: "127.0.0.2:9000".parse::<SocketAddr>().unwrap(),
        };
        let second = super::FlowKey {
            source: "127.0.0.1:10002".parse::<SocketAddr>().unwrap(),
            destination: "127.0.0.2:9000".parse::<SocketAddr>().unwrap(),
        };
        let (first_tx, _first_rx) = super::datagram_channel_with_limits(1, 1);
        let (second_tx, _second_rx) = super::datagram_channel_with_limits(1, 1);
        let mut sessions = super::SessionTable::new(1);

        assert!(sessions.insert(first, first_tx).is_some());
        assert!(sessions.insert(second, second_tx).is_none());
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn stale_completion_does_not_remove_replacement_session() {
        let key = super::FlowKey {
            source: "127.0.0.1:10001".parse::<SocketAddr>().unwrap(),
            destination: "127.0.0.2:9000".parse::<SocketAddr>().unwrap(),
        };
        let mut sessions = super::SessionTable::new(1);
        let (first_tx, _first_rx) = super::datagram_channel_with_limits(1, 1);
        let first_id = sessions.insert(key, first_tx).unwrap();
        sessions.complete(key, first_id);

        let (replacement_tx, _replacement_rx) = super::datagram_channel_with_limits(1, 1);
        let replacement_id = sessions.insert(key, replacement_tx).unwrap();
        sessions.complete(key, first_id);
        assert_eq!(sessions.len(), 1);

        sessions.complete(key, replacement_id);
        assert_eq!(sessions.len(), 0);
    }

    /// The response socket binds transparently to the flow's original destination and replies into
    /// the pod, so it only works when it lives in the workload's network namespace. Binding in
    /// ztunnel's own namespace still succeeds (IP_TRANSPARENT permits foreign addresses), so assert
    /// on delivery rather than on the bind.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn response_socket_is_bound_in_the_workload_netns() {
        use crate::inpod::netns::InpodNetns;

        if !crate::test_helpers::can_run_privilged_test() {
            eprintln!("This test requires root; skipping");
            return;
        }
        // Isolate the namespace we are called in, so a socket that escapes the workload netns
        // cannot reach the machine's real loopback.
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();

        let cfg = crate::config::Config {
            packet_mark: Some(123),
            ..crate::config::parse_config().unwrap()
        };
        let inpod_cfg = crate::inpod::config::InPodConfig::new(&cfg).unwrap();
        let netns = InpodNetns::new(
            Arc::new(InpodNetns::current().unwrap()),
            crate::inpod::test_helpers::new_netns(),
        )
        .unwrap();
        let socket_factory = inpod_cfg.socket_factory(netns);

        // Stands in for the captured pod client: this address only exists inside the workload netns.
        let client = socket_factory
            .udp_bind("127.0.0.1:0".parse().unwrap())
            .unwrap();
        let client_addr = client.local_addr().unwrap();
        let original_destination: SocketAddr = "127.0.0.2:9000".parse().unwrap();

        // Only the non-Linux fallback returns the listener, so any socket will do here.
        let listener = Arc::new(
            socket_factory
                .udp_bind("127.0.0.1:0".parse().unwrap())
                .unwrap(),
        );
        let response =
            super::response_socket(original_destination, socket_factory.as_ref(), listener)
                .unwrap();
        // The factory owns the mark too, the same way it does for new_tcp_v4.
        assert_eq!(
            socket2::SockRef::from(&*response).mark().unwrap(),
            cfg.packet_mark.unwrap()
        );
        response.send_to(b"reply", client_addr).await.unwrap();

        let mut buf = [0u8; 16];
        let (read, from) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut buf),
        )
        .await
        .expect("response never reached the workload netns")
        .unwrap();
        assert_eq!(&buf[..read], b"reply");
        assert_eq!(from, original_destination);
    }

    #[test]
    fn rejects_only_the_listener_port_reached_over_loopback() {
        let illegal_call = |addr: &str| super::is_illegal_call(addr.parse().unwrap(), 15002);

        assert!(illegal_call("127.0.0.1:15002"));
        // The inpod redirect rules only exclude 127.0.0.1/32, so the rest of 127.0.0.0/8 reaches us.
        assert!(illegal_call("127.0.0.2:15002"));
        assert!(illegal_call("[::1]:15002"));

        // A remote host that happens to serve on our listener port must still be proxied.
        assert!(!illegal_call("203.0.113.7:15002"));
        // Same for the pod's own address: the inbound side rejects it, we must not black-hole it.
        assert!(!illegal_call("10.244.0.8:15002"));
        assert!(!illegal_call("127.0.0.1:9000"));
    }
}

#[cfg(test)]
mod regression_tests;
