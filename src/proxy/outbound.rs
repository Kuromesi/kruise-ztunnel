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

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::TryFutureExt;
use hyper::header::FORWARDED;
use std::time::Instant;

use tokio::net::TcpStream;
use tokio::sync::watch;

use tracing::{Instrument, debug, error, info, info_span, trace_span};

use crate::extensions::extensions::{EgressPolicies, EgressPolicy, EgressPolicyAction};
use crate::extensions::sni::SniAction;
use crate::identity::Identity;
use crate::proxy::connection_manager::{ConnectionAttributes, ConnectionContext};
use crate::rbac::{Connection, Direction};
use crate::sandbox::discovery::Sandbox;
use crate::sandbox::sandbox;

use crate::proxy::metrics::Reporter;
use crate::proxy::{
    BAGGAGE_HEADER, Error, HboneAddress, ProxyInputs, TLS_HEADER, TRACEPARENT_HEADER, TraceParent,
    WORKLOAD_NAME_HEADER, WORKLOAD_NAMESPACE_HEADER, util,
};
use crate::proxy::{ConnectionOpen, ConnectionResultBuilder, DerivedWorkload, metrics};

use crate::baggage::{self, Baggage};
use crate::drain::DrainWatcher;
use crate::drain::run_with_drain;
use crate::proxy::h2::{H2Stream, client::WorkloadKey};
use crate::state::ProxyRbacContext;
use crate::state::workload::OutboundProtocol;
use crate::state::workload::Workload;
use crate::tls::sniff;
use crate::{assertions, copy, proxy, socket};

pub struct Outbound {
    pi: Arc<ProxyInputs>,
    drain: DrainWatcher,
    listener: socket::Listener,
}

impl Outbound {
    pub(super) async fn new(pi: Arc<ProxyInputs>, drain: DrainWatcher) -> Result<Outbound, Error> {
        let mut listener = pi
            .socket_factory
            .tcp_bind(pi.cfg.outbound_addr)
            .map_err(|e| Error::Bind(pi.cfg.outbound_addr, e))?;
        let transparent = super::maybe_set_transparent(&pi, &listener)?;
        listener.set_socket_options(Some(pi.cfg.socket_config));

        info!(
            address=%listener.local_addr(),
            component="outbound",
            transparent,
            "listener established",
        );
        Ok(Outbound {
            pi,
            listener,
            drain,
        })
    }

    pub(super) fn address(&self) -> SocketAddr {
        self.listener.local_addr()
    }

    pub(super) async fn run(self) {
        let pool = proxy::pool::WorkloadHBONEPool::new(
            self.pi.cfg.clone(),
            self.pi.socket_factory.clone(),
            self.pi.local_workload_information.clone(),
        );
        let pi = self.pi.clone();
        let accept = async move |drain: DrainWatcher, force_shutdown: watch::Receiver<()>| {
            loop {
                // Asynchronously wait for an inbound socket.
                let socket = self.listener.accept().await;
                let start = Instant::now();
                let drain = drain.clone();
                let mut force_shutdown = force_shutdown.clone();
                match socket {
                    Ok((stream, _remote)) => {
                        let socket_labels = metrics::SocketLabels {
                            reporter: Reporter::source,
                        };
                        self.pi.metrics.record_socket_open(&socket_labels);

                        let mut oc = OutboundConnection {
                            pi: self.pi.clone(),
                            id: TraceParent::new(),
                            pool: pool.clone(),
                        };
                        let span = info_span!("outbound", id=%oc.id);
                        let metrics_for_socket_close = self.pi.metrics.clone();
                        let serve_outbound_connection = async move {
                            let _socket_guard = metrics::SocketCloseGuard::new(
                                metrics_for_socket_close,
                                Reporter::source,
                            );
                            debug!(component="outbound", "connection started");
                            // Since this task is spawned, make sure we are guaranteed to terminate
                            tokio::select! {
                                _ = force_shutdown.changed() => {
                                    debug!(component="outbound", "connection forcefully terminated");
                                }
                                _ = oc.proxy(stream) => {}
                            }
                            // Mark we are done with the connection, so drain can complete
                            drop(drain);
                            debug!(component="outbound", dur=?start.elapsed(), "connection completed");
                        }.instrument(span);

                        assertions::size_between_ref(1000, 2250, &serve_outbound_connection);
                        tokio::spawn(serve_outbound_connection);
                    }
                    Err(e) => {
                        if util::is_runtime_shutdown(&e) {
                            return;
                        }
                        error!("Failed TCP handshake {}", e);
                    }
                }
            }
        };

        run_with_drain(
            "outbound".to_string(),
            self.drain,
            pi.cfg.self_termination_deadline,
            accept,
        )
        .await
    }
}

pub(super) struct OutboundConnection {
    pub(super) pi: Arc<ProxyInputs>,
    pub(super) id: TraceParent,
    pub(super) pool: proxy::pool::WorkloadHBONEPool,
}

impl OutboundConnection {
    async fn proxy(&mut self, source_stream: TcpStream) {
        let source_addr =
            socket::to_canonical(source_stream.peer_addr().expect("must receive peer addr"));
        let dst_addr = socket::orig_dst_addr_or_default(&source_stream);
        self.proxy_to(source_stream, source_addr, dst_addr).await;
    }

    pub async fn proxy_to(
        &mut self,
        source_stream: TcpStream,
        source_addr: SocketAddr,
        dest_addr: SocketAddr,
    ) {
        let start = Instant::now();

        // First find the source workload of this traffic. If we don't know where the request is from
        // we will reject it.
        let build = self
            .pi
            .local_workload_information
            .get_workload()
            .and_then(|source| {
                // Select once before routing; policy, headers and pooling use this snapshot.
                let sandbox = self.pi.state.fetch_sandbox(&source);
                self.build_request(source, sandbox, dest_addr)
            });
        let mut req = match Box::pin(build).await {
            Ok(req) => Box::new(req),
            Err(err) => {
                metrics::log_early_deny(source_addr, dest_addr, Reporter::source, err);
                return;
            }
        };

        let rbac_ctx = ProxyRbacContext {
            conn: Connection {
                src: source_addr,
                dst: dest_addr,
                src_identity: Some(req.source.identity()),
                dst_network: req
                    .actual_destination_workload
                    .clone()
                    .map(|x| x.network.clone())
                    .unwrap_or("".into()),
                direction: Direction::Outbound,
            },
            workload: req.source.clone(),
            sandbox: req.sandbox.clone(),
        };
        let conn = ConnectionAttributes::Outbound(proxy::connection_manager::OutboundAttributes {
            actual_dst: req.actual_destination,
            protocol: req.protocol,
        });

        // TODO: should we use the original address or the actual address? Both seems nice!
        let mut conn_guard = match self
            .pi
            .connection_manager
            .assert_rbac(
                &self.pi.state,
                ConnectionContext {
                    rbac_ctx,
                    attributes: conn,
                },
            )
            .await
        {
            Ok(guard) => guard,
            Err(err) => {
                metrics::log_early_deny(source_addr, dest_addr, Reporter::source, err);
                return;
            }
        };

        let metrics = self.pi.metrics.clone();
        let hbone_target = req.hbone_target_destination.clone();
        let connection_result_builder = Box::new(ConnectionResultBuilder::new(
            source_addr,
            req.actual_destination,
            hbone_target,
            start,
            Self::conn_metrics_from_request(&req),
            metrics,
        ));

        let drain_watch = conn_guard.watcher();
        let proxy_future = async {
            match req.protocol {
                OutboundProtocol::HBONE => {
                    self.proxy_to_hbone(
                        source_stream,
                        source_addr,
                        &mut req,
                        connection_result_builder,
                    )
                    .await
                }
                OutboundProtocol::TCP => {
                    self.proxy_to_tcp(source_stream, &req, connection_result_builder)
                        .await
                }
            }
        };

        tokio::select! {
            _ = proxy_future => {
                conn_guard.release();
            }
            _ = drain_watch.wait_for_drain() => {
                debug!("outbound connection terminated due to policy change");
            }
        }
    }

    async fn proxy_to_hbone(
        &mut self,
        mut stream: TcpStream,
        remote_addr: SocketAddr,
        req: &mut Request,
        connection_stats_builder: Box<ConnectionResultBuilder>,
    ) {
        let connection_stats = Box::new(connection_stats_builder.build());
        let res = (async {
            let mut sniffed_data = Bytes::new();
            if let Some(HboneAddress::SocketAddr(_)) = &req.hbone_target_destination {
                let sniffing = &self.pi.cfg.tls_sniffing;
                let sniffed = Box::pin(sniff::sniff(
                    &mut stream,
                    sniffing.timeout,
                    sniffing.max_bytes,
                ))
                .await;
                self.pi.metrics.record_tls_sniff(&sniffed);
                let sniffed = sniffed?;
                if !sniffing.fail_open && sniffed.outcome.is_failure() {
                    return Err(Error::TlsSniffFailed(sniffed.outcome.as_str()));
                }
                req.tls.sni = sniffed.sni;
                sniffed_data = sniffed.data;
            }
            req.evaluate_sni_policy()?;

            let (mut upgraded, _) = Box::pin(self.send_hbone_request(remote_addr, req)).await?;
            upgraded
                .write_sniffed(sniffed_data, &connection_stats)
                .await?;
            copy::copy_bidirectional(copy::TcpStreamSplitter(stream), upgraded, &connection_stats)
                .await
        })
        .await;
        connection_stats.record(res);
    }

    async fn create_hbone_request(
        &self,
        remote_addr: SocketAddr,
        req: &Request,
    ) -> http::Request<()> {
        let mut builder = http::Request::builder()
            .uri(
                req.hbone_target_destination
                    .as_ref()
                    .expect("HBONE must have target")
                    .to_string(),
            )
            .method(hyper::Method::CONNECT)
            .version(hyper::Version::HTTP_2)
            .header(BAGGAGE_HEADER, baggage(req))
            .header(FORWARDED, build_forwarded(remote_addr))
            .header(TRACEPARENT_HEADER, self.id.header())
            // Identify the source pod, rather than its owning deployment.
            // This context also applies when sandbox mode is disabled.
            .header(WORKLOAD_NAME_HEADER, req.source.name.as_str())
            .header(WORKLOAD_NAMESPACE_HEADER, req.source.namespace.as_str());

        if let Some(tls) = req.tls.header_value() {
            builder = builder.header(TLS_HEADER, tls);
        }
        if let Some(sandbox) = &req.sandbox {
            builder = builder.header(sandbox::SANDBOX_ID_HEADER, sandbox.uid.as_str());
        }
        if let Some(sandbox_manager) = &self.pi.sandbox_manager {
            if let Some(token) = sandbox_manager.get_or_load_token().await {
                builder = builder.header(sandbox::SANDBOX_TOKEN_HEADER, token.as_str());
            }
            if let Some(encoded_labels) = &req.source.encoded_labels {
                builder = builder.header(sandbox::SANDBOX_LABELS_HEADER, encoded_labels.as_str());
            }
        }

        builder
            .body(())
            .expect("builder with known status code should not fail")
    }

    /// returns upgraded stream and peer's baggage
    async fn send_hbone_request(
        &mut self,
        remote_addr: SocketAddr,
        req: &Request,
    ) -> Result<(H2Stream, Option<Baggage>), Error> {
        let request = self.create_hbone_request(remote_addr, req).await;
        let pool_key = Box::new(WorkloadKey {
            src_id: req.source.identity(),
            dst_id: req.upstream_sans.clone(),
            sandbox_id: req.sandbox.as_ref().map(|sandbox| sandbox.uid.clone()),
            src: remote_addr.ip(),
            dst: req.actual_destination,
        });
        let (upgraded, baggage) = Box::pin(self.pool.send_request_pooled(&pool_key, request))
            .instrument(trace_span!("outbound connect"))
            .await?;
        Ok((upgraded, baggage))
    }

    async fn proxy_to_tcp(
        &mut self,
        stream: TcpStream,
        req: &Request,
        connection_stats_builder: Box<ConnectionResultBuilder>,
    ) {
        let connection_stats = Box::new(connection_stats_builder.build());

        let res = (async {
            let outbound = super::freebind_connect(
                None, // No need to spoof source IP on outbound
                req.actual_destination,
                self.pi.socket_factory.as_ref(),
            )
            .await?;

            // Proxying data between downstream and upstream
            copy::copy_bidirectional(
                copy::TcpStreamSplitter(stream),
                copy::TcpStreamSplitter(outbound),
                &connection_stats,
            )
            .await
        })
        .await;
        connection_stats.record(res);
    }

    fn conn_metrics_from_request(req: &Request) -> ConnectionOpen {
        let (derived_source, security_policy) = match req.protocol {
            OutboundProtocol::HBONE => (
                Some(DerivedWorkload {
                    // We are going to do mTLS, so report our identity
                    identity: Some(req.source.as_ref().identity()),
                    ..Default::default()
                }),
                metrics::SecurityPolicy::mutual_tls,
            ),
            OutboundProtocol::TCP => (None, metrics::SecurityPolicy::unknown),
        };
        ConnectionOpen {
            reporter: Reporter::source,
            derived_source,
            source: Some(req.source.clone()),
            destination: req.actual_destination_workload.clone(),
            connection_security_policy: security_policy,
            destination_service: None,
        }
    }

    // build_request computes all information about the request we should send
    async fn build_request(
        &self,
        source_workload: Arc<Workload>,
        sandbox: Option<Arc<Sandbox>>,
        target: SocketAddr,
    ) -> Result<Request, Error> {
        if self.pi.cfg.illegal_ports.contains(&target.port())
            && (target.ip().is_loopback() || source_workload.workload_ips.contains(&target.ip()))
        {
            return Err(Error::SelfCall);
        }

        if let Some(result) = self
            .apply_egress_policy(&source_workload, &sandbox, &target)
            .await
        {
            return result;
        }

        debug!("built request as passthrough");
        Ok(Request {
            protocol: OutboundProtocol::TCP,
            source: source_workload,
            sandbox,
            tls: TlsMetadata::default(),
            hbone_target_destination: None,
            actual_destination_workload: None,
            actual_destination: target,
            upstream_sans: vec![],
        })
    }

    async fn apply_egress_policy(
        &self,
        source_workload: &Arc<Workload>,
        sandbox: &Option<Arc<Sandbox>>,
        target: &SocketAddr,
    ) -> Option<Result<Request, Error>> {
        let matched = match_source_egress_policy(source_workload, sandbox.as_deref(), target)
            .map(|policy| (policy.policy, policy.gateway.clone()));
        let (action, gateway) = matched?;
        match action {
            EgressPolicyAction::Passthrough => {
                debug!("egress policy matched passthrough for target {target}");
                None
            }
            EgressPolicyAction::Deny => Some(Err(Error::EgressPolicyDenied(*target))),
            EgressPolicyAction::Gateway => {
                debug!("egress policy matched gateway action for target {target}");
                let gw_address = match gateway.as_ref() {
                    Some(gw) => gw,
                    None => return Some(Err(Error::EgressPolicyGatewayMissing(*target))),
                };
                let waypoint = match self
                    .pi
                    .state
                    .fetch_waypoint(gw_address, source_workload, *target)
                    .await
                {
                    Ok(w) => w,
                    Err(e) => return Some(Err(e)),
                };
                let actual_destination = waypoint.workload_socket_addr();
                let upstream_sans = waypoint.workload_and_services_san();
                Some(Ok(Request {
                    protocol: OutboundProtocol::HBONE,
                    source: source_workload.clone(),
                    sandbox: sandbox.clone(),
                    tls: TlsMetadata::default(),
                    hbone_target_destination: Some(HboneAddress::SocketAddr(*target)),
                    actual_destination_workload: Some(waypoint.workload),
                    actual_destination,
                    upstream_sans,
                }))
            }
        }
    }
}

fn build_forwarded(remote_addr: SocketAddr) -> String {
    format!("for=\"{remote_addr}\"")
}

fn baggage(r: &Request) -> String {
    baggage::baggage_header_val(&r.source.baggage(), &r.source.workload_type)
}

#[derive(Debug)]
struct Request {
    protocol: OutboundProtocol,
    // Source workload sending the request
    source: Arc<Workload>,
    // Selected before routing; shared by egress policy, CONNECT headers and the pool key.
    sandbox: Option<Arc<Sandbox>>,
    // Optional ClientHello metadata for this CONNECT stream; never part of the pool key.
    tls: TlsMetadata,
    // The selected egress gateway workload, if any.
    actual_destination_workload: Option<Arc<Workload>>,
    // The address of the next hop, such as a workload or egress gateway.
    // When using HBONE, the `hbone_target_destination` is the inner :authority and `actual_destination` is the TCP destination.
    actual_destination: SocketAddr,
    // If using HBONE, the inner (:authority) of the HBONE request.
    hbone_target_destination: Option<HboneAddress>,

    // The identity we will assert for the next hop; this may not be the same as actual_destination_workload
    // in the case of proxies along the path.
    upstream_sans: Vec<Identity>,
}

#[derive(Debug, Default)]
struct TlsMetadata {
    sni: Option<String>,
    action: Option<SniAction>,
}

impl TlsMetadata {
    /// `action=<terminate|passthrough>;sni=<name>`, omitting unknown fields.
    fn header_value(&self) -> Option<String> {
        let fields = [
            self.action
                .and_then(SniAction::header_value)
                .map(|action| format!("action={action}")),
            self.sni.as_ref().map(|sni| format!("sni={sni}")),
        ];
        let value = fields.into_iter().flatten().collect::<Vec<_>>().join(";");
        (!value.is_empty()).then_some(value)
    }
}

impl Request {
    fn evaluate_sni_policy(&mut self) -> Result<(), Error> {
        let policy = self.sandbox.as_ref().and_then(|s| s.sni_policy.as_ref());
        let (Some(sni), Some(policy)) = (&self.tls.sni, policy) else {
            self.tls.action = None;
            return Ok(());
        };
        let action = policy.evaluate(sni);
        if action == Some(SniAction::Deny) {
            return Err(Error::SniPolicyDenied(sni.clone()));
        }
        self.tls.action = action;
        Ok(())
    }
}

fn match_source_egress_policy<'a>(
    source_workload: &'a Workload,
    sandbox: Option<&'a Sandbox>,
    target: &SocketAddr,
) -> Option<&'a EgressPolicy> {
    // A selected Sandbox owns routing, including absent routes and no-match passthrough.
    let policies = match sandbox {
        Some(sandbox) => sandbox.egress_routing.as_ref(),
        None => source_workload.egress_policies.as_ref(),
    }?;
    match_egress_policy(policies, source_workload.namespace.as_ref(), target)
}

/// Find the first egress policy that applies to a connection from
/// `source_namespace` going to `target`. Returns `None` when no policy passes
/// all of the namespace / CIDR / port filters.
///
/// Match rules (an empty list means "match anything"):
/// - `policy.namespaces` is empty OR contains `source_namespace`
/// - `policy.match_cidrs` is empty OR some CIDR contains `target.ip()`
/// - `policy.match_ports` is empty OR some port equals `target.port()`
///
/// First-match-wins: iteration order in `policies.policies` is the priority
/// order, and later policies are not consulted once a candidate is found.
pub(crate) fn match_egress_policy<'a>(
    policies: &'a EgressPolicies,
    source_namespace: &str,
    target: &SocketAddr,
) -> Option<&'a EgressPolicy> {
    policies.policies.iter().find(|policy| {
        let ns_ok = policy.namespaces.is_empty() || policy.namespaces.contains(source_namespace);
        if !ns_ok {
            return false;
        }
        let cidr_ok = policy.match_cidrs.is_empty()
            || policy
                .match_cidrs
                .iter()
                .any(|cidr| cidr.contains(&target.ip()));
        if !cidr_ok {
            return false;
        }
        policy.match_ports.is_empty() || policy.match_ports.iter().any(|p| *p == target.port())
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::time::Duration;

    use bytes::Bytes;

    use super::*;
    use crate::config::Config;
    use crate::proxy::connection_manager::ConnectionManager;
    use crate::proxy::{LocalWorkloadInformation, pool::WorkloadHBONEPool};
    use crate::state::WorkloadInfo;
    use crate::test_helpers::helpers::{initialize_telemetry, test_proxy_metrics};
    use crate::test_helpers::new_proxy_state;
    use crate::xds::istio::workload::NetworkAddress as XdsNetworkAddress;
    use crate::xds::istio::workload::Port;
    use crate::xds::istio::workload::Service as XdsService;
    use crate::xds::istio::workload::TunnelProtocol as XdsProtocol;
    use crate::xds::istio::workload::Workload as XdsWorkload;
    use crate::xds::istio::workload::address::Type as XdsAddressType;
    use crate::{identity, xds};

    fn outbound_with_resources(xds: Vec<XdsAddressType>) -> OutboundConnection {
        let cfg = Arc::new(Config {
            local_node: Some("local-node".to_string()),
            ..crate::config::parse_config().unwrap()
        });
        let source = XdsWorkload {
            uid: "cluster1//v1/Pod/ns/source-workload".to_string(),
            name: "source-workload".to_string(),
            namespace: "ns".to_string(),
            addresses: vec![
                Bytes::copy_from_slice(&[127, 0, 0, 1]),
                Bytes::copy_from_slice("::1".parse::<Ipv6Addr>().unwrap().octets().as_slice()),
            ],
            node: "local-node".to_string(),
            ..Default::default()
        };
        let mut workloads = vec![source];
        let mut services = vec![];
        for x in xds {
            match x {
                XdsAddressType::Workload(wl) => workloads.push(wl),
                XdsAddressType::Service(svc) => services.push(svc),
            };
        }
        let state = new_proxy_state(&workloads, &services, &[]);

        let sock_fact = std::sync::Arc::new(crate::proxy::DefaultSocketFactory::default());

        let wi = WorkloadInfo {
            name: "source-workload".to_string(),
            namespace: "ns".to_string(),
            service_account: "default".to_string(),
        };
        let local_workload_information = Arc::new(LocalWorkloadInformation::new(
            Arc::new(wi.clone()),
            state.clone(),
            identity::mock::new_secret_manager(Duration::from_secs(10)),
        ));
        OutboundConnection {
            pi: Arc::new(ProxyInputs {
                state: state.clone(),
                cfg: cfg.clone(),
                metrics: test_proxy_metrics(),
                socket_factory: sock_fact.clone(),
                local_workload_information: local_workload_information.clone(),
                connection_manager: ConnectionManager::default(),
                resolver: None,
                disable_inbound_freebind: false,
                crl_manager: None,
                sandbox_manager: None,
                firewall_metrics: None,
            }),
            id: TraceParent::new(),
            pool: WorkloadHBONEPool::new(
                cfg.clone(),
                sock_fact,
                local_workload_information.clone(),
            ),
        }
    }

    #[tokio::test]
    async fn routing_uses_source_policy_for_known_and_unknown_destinations() {
        use crate::state::workload::{
            GatewayAddress, NamespacedHostname, gatewayaddress::Destination,
        };
        let outbound = outbound_with_resources(vec![
            XdsAddressType::Workload(XdsWorkload {
                uid: "destination".into(),
                addresses: vec![Bytes::from_static(&[127, 0, 0, 2])],
                tunnel_protocol: XdsProtocol::Hbone.into(),
                waypoint: Some(xds::istio::workload::GatewayAddress {
                    destination: Some(xds::istio::workload::gateway_address::Destination::Address(
                        XdsNetworkAddress {
                            network: "remote".into(),
                            address: vec![127, 0, 0, 99],
                        },
                    )),
                    hbone_mtls_port: 15008,
                }),
                ..Default::default()
            }),
            XdsAddressType::Service(XdsService {
                hostname: "target.ns".into(),
                namespace: "ns".into(),
                addresses: vec![XdsNetworkAddress {
                    network: "".into(),
                    address: vec![127, 0, 0, 3],
                }],
                ports: vec![Port {
                    service_port: 80,
                    target_port: 8080,
                }],
                waypoint: Some(xds::istio::workload::GatewayAddress {
                    destination: Some(xds::istio::workload::gateway_address::Destination::Address(
                        XdsNetworkAddress {
                            network: "".into(),
                            address: vec![127, 0, 0, 99],
                        },
                    )),
                    hbone_mtls_port: 15008,
                }),
                ..Default::default()
            }),
            XdsAddressType::Workload(XdsWorkload {
                uid: "egress-gateway".into(),
                namespace: "ns".into(),
                hostname: "egress.ns".into(),
                addresses: vec![Bytes::from_static(&[127, 0, 0, 10])],
                ..Default::default()
            }),
        ]);
        let source = outbound
            .pi
            .local_workload_information
            .get_workload()
            .await
            .unwrap();
        for target in ["127.0.0.2:80", "127.0.0.3:80", "203.0.113.1:80"] {
            let target: SocketAddr = target.parse().unwrap();
            let direct = outbound
                .build_request(source.clone(), None, target)
                .await
                .unwrap();
            assert_eq!(direct.protocol, OutboundProtocol::TCP);
            assert_eq!(direct.actual_destination, target);
            assert!(direct.actual_destination_workload.is_none());
            assert!(direct.hbone_target_destination.is_none());

            for action in [
                EgressPolicyAction::Passthrough,
                EgressPolicyAction::Deny,
                EgressPolicyAction::Gateway,
            ] {
                let source = Arc::new(Workload {
                    egress_policies: Some(EgressPolicies {
                        policies: vec![EgressPolicy {
                            namespaces: Default::default(),
                            match_cidrs: vec![],
                            match_ports: vec![],
                            policy: action,
                            gateway: Some(GatewayAddress {
                                destination: Destination::Hostname(NamespacedHostname {
                                    namespace: "ns".into(),
                                    hostname: "egress.ns".into(),
                                }),
                                hbone_mtls_port: 15008,
                            }),
                        }],
                    }),
                    ..(*source).clone()
                });
                let result = outbound.build_request(source, None, target).await;
                match action {
                    EgressPolicyAction::Deny => {
                        assert!(matches!(result, Err(Error::EgressPolicyDenied(_))))
                    }
                    EgressPolicyAction::Passthrough => {
                        let request = result.unwrap();
                        assert_eq!(request.protocol, OutboundProtocol::TCP);
                        assert_eq!(request.actual_destination, target);
                    }
                    EgressPolicyAction::Gateway => {
                        let request = result.unwrap();
                        assert_eq!(request.protocol, OutboundProtocol::HBONE);
                        assert_eq!(
                            request.actual_destination,
                            "127.0.0.10:15008".parse().unwrap()
                        );
                        assert_eq!(
                            request.hbone_target_destination.unwrap().to_string(),
                            target.to_string()
                        );
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn direct_routing_rejects_local_proxy_ports() {
        let outbound = outbound_with_resources(vec![]);
        let source = Arc::new(Workload {
            workload_ips: vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
            ..crate::test_helpers::test_default_workload()
        });
        for port in [15001, 15006, 15008] {
            for ip in ["127.0.0.1", "::1", "192.0.2.1", "2001:db8::1"] {
                let target = SocketAddr::new(ip.parse().unwrap(), port);
                assert!(matches!(
                    outbound.build_request(source.clone(), None, target).await,
                    Err(Error::SelfCall)
                ));
            }
            let target = SocketAddr::new("192.0.2.2".parse().unwrap(), port);
            assert!(
                outbound
                    .build_request(source.clone(), None, target)
                    .await
                    .is_ok()
            );
        }
        assert!(
            outbound
                .build_request(source, None, "192.0.2.1:8080".parse().unwrap())
                .await
                .is_ok()
        );
    }

    #[test]
    fn build_forwarded() {
        assert_eq!(
            super::build_forwarded("127.0.0.1:80".parse().unwrap()),
            r#"for="127.0.0.1:80""#,
        );
        assert_eq!(
            super::build_forwarded("[::1]:80".parse().unwrap()),
            r#"for="[::1]:80""#,
        );
    }

    #[tokio::test]
    async fn hbone_request_carries_workload_headers() {
        initialize_telemetry();

        // Create a test config with a specific network
        let cfg = Arc::new(Config {
            network: "test-network".into(),
            local_node: Some("local-node".to_string()),
            ..crate::config::parse_config().unwrap()
        });

        // Create a source workload and add it to state
        let source = XdsWorkload {
            uid: "cluster1//v1/Pod/ns/source-workload".to_string(),
            name: "source-workload".to_string(),
            namespace: "ns".to_string(),
            workload_name: "source-deployment".to_string(),
            addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 1])],
            node: "local-node".to_string(),
            ..Default::default()
        };

        let state = new_proxy_state(&[source], &[], &[]);
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory::default());

        let wi = WorkloadInfo {
            name: "source-workload".to_string(),
            namespace: "ns".to_string(),
            service_account: "default".to_string(),
        };
        let local_workload_information = Arc::new(LocalWorkloadInformation::new(
            Arc::new(wi.clone()),
            state.clone(),
            identity::mock::new_secret_manager(Duration::from_secs(10)),
        ));

        let outbound = OutboundConnection {
            pi: Arc::new(ProxyInputs {
                state: state.clone(),
                cfg: cfg.clone(),
                metrics: test_proxy_metrics(),
                socket_factory: sock_fact.clone(),
                local_workload_information: local_workload_information.clone(),
                connection_manager: ConnectionManager::default(),
                resolver: None,
                disable_inbound_freebind: false,
                crl_manager: None,
                sandbox_manager: None,
                firewall_metrics: None,
            }),
            id: TraceParent::new(),
            pool: WorkloadHBONEPool::new(
                cfg.clone(),
                sock_fact,
                local_workload_information.clone(),
            ),
        };

        // Get the source workload from state
        let source_workload = outbound
            .pi
            .local_workload_information
            .get_workload()
            .await
            .unwrap();

        // Create a minimal test request with required fields
        let mut req = Request {
            protocol: OutboundProtocol::HBONE,
            source: source_workload,
            sandbox: None,
            tls: TlsMetadata::default(),
            hbone_target_destination: Some(HboneAddress::SocketAddr(
                "10.0.0.1:8080".parse().unwrap(),
            )),
            actual_destination_workload: None,
            actual_destination: "10.0.0.1:8080".parse().unwrap(),
            upstream_sans: vec![],
        };

        let remote_addr = "127.0.0.1:12345".parse().unwrap();

        let request = outbound.create_hbone_request(remote_addr, &req).await;
        assert_eq!(request.headers()[WORKLOAD_NAME_HEADER], "source-workload");
        assert_eq!(request.headers()[WORKLOAD_NAMESPACE_HEADER], "ns");
        assert!(!request.headers().contains_key(TLS_HEADER));
        use crate::extensions::sni::{SniRule, SniTrafficPolicy};
        let policy = SniTrafficPolicy {
            rules: vec![
                SniRule {
                    sni: vec!["first.example".into()],
                    action: SniAction::TlsTermination,
                },
                SniRule {
                    sni: vec!["blocked.example".into()],
                    action: SniAction::Deny,
                },
            ],
        };
        // Without a Sandbox there is no policy: only the observed SNI is reported.
        req.tls.sni = Some("blocked.example".into());
        req.evaluate_sni_policy().unwrap();
        let request = outbound.create_hbone_request(remote_addr, &req).await;
        assert_eq!(request.headers()[TLS_HEADER], "sni=blocked.example");

        let mut sandbox: Sandbox = crate::xds::agentio::sandbox::Sandbox {
            uid: "sandbox-a".into(),
            ..Default::default()
        }
        .try_into()
        .unwrap();
        sandbox.sni_policy = Some(policy);
        req.sandbox = Some(Arc::new(sandbox));
        for (sni, action) in [
            ("first.example", "terminate"),
            ("second.example", "passthrough"),
        ] {
            req.tls.sni = Some(sni.to_owned());
            req.evaluate_sni_policy().unwrap();
            let request = outbound.create_hbone_request(remote_addr, &req).await;
            assert_eq!(
                request.headers()[TLS_HEADER],
                format!("action={action};sni={sni}")
            );
        }
        req.tls.sni = None;
        req.evaluate_sni_policy().unwrap();
        let request = outbound.create_hbone_request(remote_addr, &req).await;
        assert!(!request.headers().contains_key(TLS_HEADER));

        req.tls.sni = Some("blocked.example".into());
        assert!(matches!(
            req.evaluate_sni_policy(),
            Err(Error::SniPolicyDenied(_))
        ));
    }

    mod match_egress_policy_tests {
        use super::super::{match_egress_policy, match_source_egress_policy};
        use crate::extensions::extensions::{EgressPolicies, EgressPolicy, EgressPolicyAction};
        use crate::test_helpers::test_default_workload;
        use ipnet::IpNet;
        use std::collections::HashSet;
        use std::net::SocketAddr;

        fn target(addr: &str) -> SocketAddr {
            addr.parse().expect("valid SocketAddr")
        }

        fn cidr(s: &str) -> IpNet {
            s.parse().expect("valid CIDR")
        }

        fn ns(items: &[&str]) -> HashSet<String> {
            items.iter().map(|s| s.to_string()).collect()
        }

        fn policy_passthrough() -> EgressPolicy {
            EgressPolicy {
                namespaces: HashSet::new(),
                match_cidrs: vec![],
                match_ports: vec![],
                policy: EgressPolicyAction::Passthrough,
                gateway: None,
            }
        }

        fn wrap(policies: Vec<EgressPolicy>) -> EgressPolicies {
            EgressPolicies { policies }
        }

        #[test]
        fn workload_policy_applies_without_a_sandbox() {
            let mut workload = test_default_workload();
            workload.namespace = "ns-a".into();
            workload.egress_policies = Some(wrap(vec![EgressPolicy {
                policy: EgressPolicyAction::Deny,
                ..policy_passthrough()
            }]));

            let got = match_source_egress_policy(&workload, None, &target("10.0.0.1:443"))
                .expect("inline workload policy should match");
            assert_eq!(got.policy, EgressPolicyAction::Deny);

            workload.egress_policies = None;
            assert!(match_source_egress_policy(&workload, None, &target("10.0.0.1:443")).is_none());
        }

        #[test]
        fn selected_sandbox_does_not_fall_back_to_workload_policy() {
            let mut workload = test_default_workload();
            workload.egress_policies = Some(wrap(vec![EgressPolicy {
                policy: EgressPolicyAction::Deny,
                ..policy_passthrough()
            }]));
            for routing in [
                None,
                Some(wrap(vec![])),
                Some(wrap(vec![EgressPolicy {
                    match_ports: vec![80],
                    ..policy_passthrough()
                }])),
            ] {
                let sandbox = crate::sandbox::discovery::Sandbox {
                    uid: "sandbox-a".into(),
                    workload_uid: Some(workload.uid.clone()),
                    egress_routing: routing,
                    traffic_policy: Default::default(),
                    traffic_policy_refs: Vec::new(),
                    sni_policy: None,
                };
                assert!(
                    match_source_egress_policy(&workload, Some(&sandbox), &target("10.0.0.1:443"))
                        .is_none()
                );
            }
        }

        #[test]
        fn empty_policy_list_returns_none() {
            // Defensive baseline: callers wrap this in `if let Some(policies)`, but
            // an empty `policies` field must also short-circuit to None.
            let ep = wrap(vec![]);
            assert!(match_egress_policy(&ep, "ns1", &target("10.0.0.1:80")).is_none());
        }

        #[test]
        fn fully_unconstrained_policy_matches_anything() {
            let ep = wrap(vec![policy_passthrough()]);
            let got =
                match_egress_policy(&ep, "any-ns", &target("1.2.3.4:9999")).expect("should match");
            assert_eq!(got.policy, EgressPolicyAction::Passthrough);
        }

        #[test]
        fn namespace_filter_admits_listed_source() {
            let ep = wrap(vec![EgressPolicy {
                namespaces: ns(&["ns-a", "ns-b"]),
                ..policy_passthrough()
            }]);
            assert!(match_egress_policy(&ep, "ns-a", &target("10.0.0.1:80")).is_some());
            assert!(match_egress_policy(&ep, "ns-b", &target("10.0.0.1:80")).is_some());
        }

        #[test]
        fn namespace_filter_rejects_unlisted_source() {
            let ep = wrap(vec![EgressPolicy {
                namespaces: ns(&["ns-a"]),
                ..policy_passthrough()
            }]);
            assert!(match_egress_policy(&ep, "ns-other", &target("10.0.0.1:80")).is_none());
        }

        #[test]
        fn cidr_filter_admits_target_inside_any_range() {
            let ep = wrap(vec![EgressPolicy {
                match_cidrs: vec![cidr("10.0.0.0/8"), cidr("192.168.1.0/24")],
                ..policy_passthrough()
            }]);
            assert!(match_egress_policy(&ep, "ns", &target("10.255.255.1:80")).is_some());
            assert!(match_egress_policy(&ep, "ns", &target("192.168.1.42:80")).is_some());
        }

        #[test]
        fn cidr_filter_rejects_target_outside_all_ranges() {
            let ep = wrap(vec![EgressPolicy {
                match_cidrs: vec![cidr("10.0.0.0/8")],
                ..policy_passthrough()
            }]);
            assert!(match_egress_policy(&ep, "ns", &target("172.16.0.1:80")).is_none());
        }

        #[test]
        fn port_filter_admits_target_with_matching_port() {
            let ep = wrap(vec![EgressPolicy {
                match_ports: vec![80, 443, 8080],
                ..policy_passthrough()
            }]);
            assert!(match_egress_policy(&ep, "ns", &target("10.0.0.1:443")).is_some());
            assert!(match_egress_policy(&ep, "ns", &target("10.0.0.1:8080")).is_some());
        }

        #[test]
        fn port_filter_rejects_target_with_non_matching_port() {
            let ep = wrap(vec![EgressPolicy {
                match_ports: vec![80, 443],
                ..policy_passthrough()
            }]);
            assert!(match_egress_policy(&ep, "ns", &target("10.0.0.1:22")).is_none());
        }

        #[test]
        fn combined_filters_require_all_to_pass() {
            // ns-a + 10.0.0.0/24 + port 80 — only the exact triple matches.
            let ep = wrap(vec![EgressPolicy {
                namespaces: ns(&["ns-a"]),
                match_cidrs: vec![cidr("10.0.0.0/24")],
                match_ports: vec![80],
                ..policy_passthrough()
            }]);
            assert!(match_egress_policy(&ep, "ns-a", &target("10.0.0.5:80")).is_some());
            // wrong namespace
            assert!(match_egress_policy(&ep, "ns-b", &target("10.0.0.5:80")).is_none());
            // wrong CIDR
            assert!(match_egress_policy(&ep, "ns-a", &target("11.0.0.5:80")).is_none());
            // wrong port
            assert!(match_egress_policy(&ep, "ns-a", &target("10.0.0.5:81")).is_none());
        }

        #[test]
        fn first_match_wins_skips_later_policies() {
            // A passthrough policy ahead of a deny policy must shadow the deny —
            // proves order-priority semantics that the caller relies on for
            // "allow-list before deny-all" configs.
            let allow_first = EgressPolicy {
                match_cidrs: vec![cidr("10.0.0.0/24")],
                policy: EgressPolicyAction::Passthrough,
                ..policy_passthrough()
            };
            let deny_all = EgressPolicy {
                policy: EgressPolicyAction::Deny,
                ..policy_passthrough()
            };
            let ep = wrap(vec![allow_first, deny_all]);
            let got = match_egress_policy(&ep, "ns", &target("10.0.0.5:80"))
                .expect("first policy should match");
            assert_eq!(got.policy, EgressPolicyAction::Passthrough);
        }

        #[test]
        fn non_matching_policy_falls_through_to_next() {
            // The first policy filters out by CIDR; the second has no filters
            // and should be returned.
            let strict_first = EgressPolicy {
                match_cidrs: vec![cidr("10.0.0.0/24")],
                policy: EgressPolicyAction::Deny,
                ..policy_passthrough()
            };
            let catchall = EgressPolicy {
                policy: EgressPolicyAction::Gateway,
                ..policy_passthrough()
            };
            let ep = wrap(vec![strict_first, catchall]);
            let got = match_egress_policy(&ep, "ns", &target("172.16.0.1:80"))
                .expect("catchall should match");
            assert_eq!(got.policy, EgressPolicyAction::Gateway);
        }

        #[test]
        fn ipv6_target_matches_ipv6_cidr() {
            // CIDR matching has to work for IPv6 too — production traffic on
            // dual-stack hosts will hit this branch.
            let ep = wrap(vec![EgressPolicy {
                match_cidrs: vec![cidr("fd00::/8")],
                ..policy_passthrough()
            }]);
            assert!(match_egress_policy(&ep, "ns", &target("[fd00::1]:80")).is_some());
            assert!(match_egress_policy(&ep, "ns", &target("[2001:db8::1]:80")).is_none());
        }

        #[test]
        fn returned_reference_preserves_action_and_gateway() {
            // The caller dispatches on `policy.policy` and reads `policy.gateway`
            // for the Gateway branch — verify we don't accidentally lose them.
            let ep = wrap(vec![EgressPolicy {
                policy: EgressPolicyAction::Gateway,
                gateway: None, // gateway resolution is the caller's responsibility
                ..policy_passthrough()
            }]);
            let got = match_egress_policy(&ep, "ns", &target("10.0.0.1:80")).expect("match");
            assert_eq!(got.policy, EgressPolicyAction::Gateway);
            assert!(got.gateway.is_none());
        }
    }

    #[tokio::test]
    async fn hbone_uses_discovered_sandbox_routing_and_independent_token() {
        use crate::sandbox::discovery::tests::Fixture;
        use crate::state::DemandProxyState;
        let fixture = Fixture::new();
        let cfg = Arc::new(crate::test_helpers::test_config());
        let state = DemandProxyState::new(
            fixture.state.clone(),
            None,
            Default::default(),
            Default::default(),
            test_proxy_metrics(),
        );
        let wi = WorkloadInfo::new("pod".into(), "ns".into(), "default".into());
        let mut manager = sandbox::SandboxManager::default();
        let local = Arc::new(LocalWorkloadInformation::new(
            Arc::new(wi),
            state.clone(),
            identity::mock::new_secret_manager(Duration::from_secs(10)),
        ));
        let socket_factory = Arc::new(crate::proxy::DefaultSocketFactory::default());
        let token_dir = tempfile::tempdir().unwrap();
        // The producer's token filename is independent of the xDS Sandbox ID.
        std::fs::write(token_dir.path().join("producer-key.token"), "correct-token").unwrap();
        manager
            .run(token_dir.path().into(), cfg.sandbox_watcher_debounce_ms)
            .await;
        tokio::time::timeout(Duration::from_secs(3), async {
            while manager.list_sandbox_tokens().len() != 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let manager = Arc::new(manager);
        let outbound = OutboundConnection {
            pi: Arc::new(ProxyInputs {
                state: state.clone(),
                cfg: cfg.clone(),
                metrics: test_proxy_metrics(),
                socket_factory: socket_factory.clone(),
                local_workload_information: local.clone(),
                connection_manager: ConnectionManager::default(),
                resolver: None,
                disable_inbound_freebind: false,
                crl_manager: None,
                sandbox_manager: Some(manager.clone()),
                firewall_metrics: None,
            }),
            id: TraceParent::new(),
            pool: WorkloadHBONEPool::new(cfg.clone(), socket_factory, local),
        };
        // The same Workload can route through different policies once its Sandbox is selected.
        use crate::xds::agentio::sandbox::{
            EgressRouting, Sandbox as XdsSandbox, egress_routing, sandbox::Attester,
        };
        fixture
            .state
            .write()
            .unwrap()
            .workloads
            .insert(Arc::new(Workload {
                uid: "egress-gateway".into(),
                hostname: "egress.ns".into(),
                workload_ips: vec!["127.0.0.10".parse().unwrap()],
                ..(*fixture.workload).clone()
            }));
        let mut routes = EgressRouting {
            routes: vec![egress_routing::Route {
                match_cidrs: vec!["10.0.0.0/8".into()],
                match_ports: vec!["443".into()],
                action: egress_routing::Action::Gateway.into(),
                gateway: Some(egress_routing::GatewayAddress {
                    service: "egress.ns".into(),
                    port: 15008,
                }),
            }],
        };
        let publish_routing = |id: &str, routing: EgressRouting| {
            fixture
                .state
                .write()
                .unwrap()
                .sandboxes
                .update(xds::XdsResource {
                    name: id.into(),
                    resource: XdsSandbox {
                        uid: id.into(),
                        attester: Some(Attester {
                            workload_uid: fixture.workload.uid.to_string(),
                        }),
                        egress_routing: Some(routing),
                        ..Default::default()
                    },
                })
                .unwrap();
        };
        publish_routing("sandbox-a", routes.clone());
        publish_routing(
            "sandbox-b",
            EgressRouting {
                routes: vec![egress_routing::Route::default()],
            },
        );
        let sandboxes = fixture
            .state
            .read()
            .unwrap()
            .sandboxes
            .get_by_workload(&fixture.workload.uid);
        let target: SocketAddr = "10.0.0.1:443".parse().unwrap();
        let workload = Arc::new(Workload {
            egress_policies: Some(EgressPolicies {
                policies: vec![EgressPolicy {
                    namespaces: Default::default(),
                    match_cidrs: vec![],
                    match_ports: vec![],
                    policy: EgressPolicyAction::Deny,
                    gateway: None,
                }],
            }),
            ..(*fixture.workload).clone()
        });
        assert!(matches!(
            outbound.build_request(workload.clone(), None, target).await,
            Err(Error::EgressPolicyDenied(_))
        ));
        for selected in &sandboxes {
            let request = outbound
                .build_request(workload.clone(), Some(selected.clone()), target)
                .await
                .unwrap();
            assert!(Arc::ptr_eq(request.sandbox.as_ref().unwrap(), selected));
            if selected.uid == "sandbox-a" {
                assert_eq!(request.protocol, OutboundProtocol::HBONE);
                assert_eq!(
                    request.actual_destination,
                    "127.0.0.10:15008".parse().unwrap()
                );
                assert_eq!(
                    request
                        .hbone_target_destination
                        .as_ref()
                        .unwrap()
                        .to_string(),
                    target.to_string()
                );
                let hbone = outbound.create_hbone_request(target, &request).await;
                assert_eq!(hbone.headers()[sandbox::SANDBOX_ID_HEADER], "sandbox-a");
            } else {
                assert_eq!(request.protocol, OutboundProtocol::TCP);
                assert_eq!(request.actual_destination, target);
            }
        }
        // A selected but unavailable gateway fails the request without direct fallback.
        routes.routes[0].gateway.as_mut().unwrap().service = "missing.ns".into();
        publish_routing("sandbox-a", routes);
        let selected = state.fetch_sandbox(&fixture.workload);
        assert!(matches!(
            outbound
                .build_request(fixture.workload.clone(), selected, target)
                .await,
            Err(Error::UnknownWaypoint(_))
        ));
        fixture
            .state
            .write()
            .unwrap()
            .sandboxes
            .remove(&"sandbox-a".into());
        fixture
            .state
            .write()
            .unwrap()
            .sandboxes
            .remove(&"sandbox-b".into());

        let mut request = Request {
            protocol: OutboundProtocol::HBONE,
            source: fixture.workload.clone(),
            sandbox: None,
            tls: TlsMetadata::default(),
            hbone_target_destination: Some(HboneAddress::SocketAddr(
                "10.0.0.1:443".parse().unwrap(),
            )),
            actual_destination_workload: None,
            actual_destination: "10.0.0.1:443".parse().unwrap(),
            upstream_sans: vec![],
        };
        let source = "127.0.0.1:12345".parse().unwrap();
        let before = outbound.create_hbone_request(source, &request).await;
        assert!(!before.headers().contains_key(sandbox::SANDBOX_ID_HEADER));
        assert_eq!(
            before.headers()[sandbox::SANDBOX_TOKEN_HEADER],
            "Y29ycmVjdC10b2tlbg=="
        );
        fixture.publish("sandbox-a");
        request.sandbox = state.fetch_sandbox(&request.source);
        let discovered = outbound.create_hbone_request(source, &request).await;
        assert_eq!(
            discovered.headers()[sandbox::SANDBOX_ID_HEADER],
            "sandbox-a"
        );
        let captured_a = state.fetch_sandbox(&request.source).unwrap();
        request.sandbox = Some(captured_a.clone());
        let hbone = outbound.create_hbone_request(source, &request).await;
        assert_eq!(hbone.headers()[sandbox::SANDBOX_ID_HEADER], "sandbox-a");
        assert_eq!(
            hbone.headers()[sandbox::SANDBOX_TOKEN_HEADER],
            "Y29ycmVjdC10b2tlbg=="
        );
        fixture.publish("sandbox-b");
        assert_eq!(
            state
                .fetch_sandbox(&request.source)
                .map(|sandbox| sandbox.uid.clone())
                .unwrap(),
            captured_a.uid
        );
        // Each request carries its selected identity while token loading stays independent.
        for id in ["sandbox-a", "sandbox-b"] {
            request.sandbox = fixture
                .state
                .read()
                .unwrap()
                .sandboxes
                .get_by_workload(&request.source.uid)
                .into_iter()
                .find(|sandbox| sandbox.uid == id);
            let hbone = outbound.create_hbone_request(source, &request).await;
            assert_eq!(hbone.headers()[sandbox::SANDBOX_ID_HEADER], id);
            assert_eq!(
                hbone.headers()[sandbox::SANDBOX_TOKEN_HEADER],
                "Y29ycmVjdC10b2tlbg=="
            );
        }
        let foreign = Arc::new(Workload {
            uid: "foreign".into(),
            ..(*fixture.workload).clone()
        });
        fixture
            .state
            .write()
            .unwrap()
            .workloads
            .insert(foreign.clone());
        request.source = foreign;
        request.sandbox = state.fetch_sandbox(&request.source);
        let foreign_request = outbound.create_hbone_request(source, &request).await;
        assert!(
            !foreign_request
                .headers()
                .contains_key(sandbox::SANDBOX_ID_HEADER)
        );
        assert!(state.fetch_sandbox(&request.source).is_none());
        request.source = fixture.workload.clone();
        request.sandbox = Some(captured_a.clone());
        fixture
            .state
            .write()
            .unwrap()
            .sandboxes
            .remove(&"sandbox-a".into());
        // An already-started connection keeps its captured label after a Sandbox update.
        let captured = outbound.create_hbone_request(source, &request).await;
        assert_eq!(captured.headers()[sandbox::SANDBOX_ID_HEADER], "sandbox-a");
        let current = state.fetch_sandbox(&request.source).unwrap();
        assert_eq!(current.uid, "sandbox-b");
        request.sandbox = Some(current);
        let next = outbound.create_hbone_request(source, &request).await;
        assert_eq!(next.headers()[sandbox::SANDBOX_ID_HEADER], "sandbox-b");
        fixture
            .state
            .write()
            .unwrap()
            .sandboxes
            .remove(&"sandbox-b".into());
        // Removing the last binding leaves new connections without a Sandbox label.
        assert!(state.fetch_sandbox(&request.source).is_none());
        request.sandbox = state.fetch_sandbox(&request.source);
        let unlabeled = outbound.create_hbone_request(source, &request).await;
        assert!(!unlabeled.headers().contains_key(sandbox::SANDBOX_ID_HEADER));
    }

    #[tokio::test]
    async fn sandbox_policy_updates_recheck_tcp_without_lifecycle_drain() {
        use crate::sandbox::discovery::tests::Fixture;
        use crate::state::DemandProxyState;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let fixture = Fixture::new();
        fixture.publish("sandbox-a");
        let cfg = Arc::new(crate::test_helpers::test_config());
        let state = DemandProxyState::new(
            fixture.state.clone(),
            None,
            Default::default(),
            Default::default(),
            test_proxy_metrics(),
        );
        let local = Arc::new(LocalWorkloadInformation::new(
            Arc::new(WorkloadInfo::new(
                "pod".into(),
                "ns".into(),
                "default".into(),
            )),
            state.clone(),
            identity::mock::new_secret_manager(Duration::from_secs(10)),
        ));
        let sockets = Arc::new(crate::proxy::DefaultSocketFactory::default());
        let connection_manager = ConnectionManager::default();
        let (stop, watch) = crate::drain::new();
        let watcher = tokio::spawn(
            crate::proxy::connection_manager::PolicyWatcher::new(
                state.clone(),
                watch,
                connection_manager.clone(),
            )
            .run(),
        );
        use crate::xds::agentio::sandbox::{Sandbox, SandboxState, sandbox::Attester};
        use crate::xds::agentio::security::{TrafficPolicy, traffic_policy};
        use crate::xds::{Handler, ProxyStateUpdater, XdsResource, XdsUpdate};
        let updater = ProxyStateUpdater::new_no_fetch(fixture.state.clone());
        let publish = |resource: Sandbox| {
            updater
                .handle(Box::new(&mut std::iter::once(XdsUpdate::Update(
                    XdsResource {
                        name: resource.uid.clone().into(),
                        resource,
                    },
                ))))
                .unwrap();
        };
        let mut outbound = OutboundConnection {
            pi: Arc::new(ProxyInputs {
                state,
                cfg: cfg.clone(),
                metrics: test_proxy_metrics(),
                socket_factory: sockets.clone(),
                local_workload_information: local.clone(),
                connection_manager: connection_manager.clone(),
                resolver: None,
                disable_inbound_freebind: false,
                crl_manager: None,
                sandbox_manager: None,
                firewall_metrics: None,
            }),
            id: TraceParent::new(),
            pool: WorkloadHBONEPool::new(cfg.clone(), sockets, local),
        };
        let inputs = outbound.pi.clone();
        let pool = outbound.pool.clone();
        tokio::time::timeout(Duration::from_secs(5), async {
            let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let destination = upstream.local_addr().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (source, source_addr) = listener.accept().await.unwrap();
            let forwarding = tokio::spawn(async move {
                outbound.proxy_to(source, source_addr, destination).await;
            });
            let (mut server, _) = upstream.accept().await.unwrap();
            client.write_all(b"ok").await.unwrap();
            let mut received = [0; 2];
            server.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, b"ok");
            assert_eq!(connection_manager.connections().len(), 1);
            for lifecycle in [
                Some(SandboxState::Paused),
                Some(SandboxState::Stopped),
                None,
            ] {
                if let Some(lifecycle) = lifecycle {
                    publish(Sandbox {
                        uid: "sandbox-a".into(),
                        state: lifecycle.into(),
                        attester: Some(Attester {
                            workload_uid: fixture.workload.uid.to_string(),
                        }),
                        ..Default::default()
                    });
                } else {
                    updater
                        .handle(Box::new(&mut std::iter::once(
                            XdsUpdate::<Sandbox>::Remove("sandbox-a".into()),
                        )))
                        .unwrap();
                }
                // The existing stream still forwards in both directions.
                client.write_all(b"ok").await.unwrap();
                server.read_exact(&mut received).await.unwrap();
                assert_eq!(&received, b"ok");
                server.write_all(b"ok").await.unwrap();
                client.read_exact(&mut received).await.unwrap();
                assert_eq!(&received, b"ok");

                // A new unlabelled connection is also admitted normally.
                let mut next_client = TcpStream::connect(listener.local_addr().unwrap())
                    .await
                    .unwrap();
                let (source, source_addr) = listener.accept().await.unwrap();
                let mut next = OutboundConnection {
                    pi: inputs.clone(),
                    id: TraceParent::new(),
                    pool: pool.clone(),
                };
                let next_forwarding = tokio::spawn(async move {
                    next.proxy_to(source, source_addr, destination).await;
                });
                let (mut next_server, _) = upstream.accept().await.unwrap();
                next_client.write_all(b"ok").await.unwrap();
                next_server.read_exact(&mut received).await.unwrap();
                assert_eq!(&received, b"ok");
                drop(next_client);
                drop(next_server);
                next_forwarding.await.unwrap();
            }
            // An accepted xDS policy update rechecks and closes the existing TCP stream.
            publish(Sandbox {
                uid: "sandbox-a".into(),
                attester: Some(Attester {
                    workload_uid: fixture.workload.uid.to_string(),
                }),
                traffic_policy: Some(TrafficPolicy {
                    egress: Some(traffic_policy::RuleSet {
                        rules: vec![traffic_policy::Rule {
                            action: traffic_policy::Action::Deny.into(),
                            r#match: Some(traffic_policy::Match::default()),
                        }],
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            });
            assert_eq!(client.read(&mut received).await.unwrap(), 0);
            assert_eq!(server.read(&mut received).await.unwrap(), 0);
            forwarding.await.unwrap();

            let mut denied_client = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (denied_source, denied_addr) = listener.accept().await.unwrap();
            let mut denied = OutboundConnection {
                pi: inputs.clone(),
                id: TraceParent::new(),
                pool: pool.clone(),
            };
            denied
                .proxy_to(denied_source, denied_addr, destination)
                .await;
            assert_eq!(denied_client.read(&mut received).await.unwrap(), 0);
            assert!(connection_manager.connections().is_empty());
        })
        .await
        .unwrap();
        stop.start_drain_and_wait(crate::drain::DrainMode::Immediate)
            .await;
        watcher.await.unwrap();
    }
}
