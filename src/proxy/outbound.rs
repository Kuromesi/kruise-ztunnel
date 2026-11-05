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

use hyper::header::FORWARDED;
use std::time::Instant;

use tokio::net::TcpStream;
use tokio::sync::watch;

use tracing::{Instrument, debug, error, info, info_span, trace_span};

use crate::extensions::extensions::{EgressPolicies, EgressPolicy, EgressPolicyAction};
use crate::identity::Identity;
use crate::proxy::connection_manager::{ConnectionAttributes, ConnectionContext};
use crate::rbac::{Connection, Direction};
use crate::sandbox::metadata::SANDBOX_METADATA_HEADER;
use crate::sandbox::sandbox::{self, SandboxContext};

use crate::proxy::metrics::Reporter;
use crate::proxy::{
    BAGGAGE_HEADER, DESTINATION_DNS_CANDIDATES_HEADER, Error, HboneAddress, ProxyInputs,
    TRACEPARENT_HEADER, TraceParent, util,
};
use crate::proxy::{ConnectionOpen, ConnectionResultBuilder, DerivedWorkload, metrics};

use crate::baggage::{self, Baggage};
use crate::drain::DrainWatcher;
use crate::drain::run_with_drain;
use crate::proxy::h2::{H2Stream, client::WorkloadKey};
use crate::state::ProxyRbacContext;
use crate::state::workload::OutboundProtocol;
use crate::state::workload::Workload;
use crate::{assertions, copy, proxy, socket};

pub struct Outbound {
    pi: Arc<ProxyInputs>,
    drain: DrainWatcher,
    listener: socket::Listener,
}

const MAX_DESTINATION_DNS_CANDIDATES_HEADER_BYTES: usize = 8192;

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
    pub(super) async fn connect_udp(
        &mut self,
        source_addr: SocketAddr,
        dest_addr: SocketAddr,
        gateway: &mut Option<SocketAddr>,
    ) -> Result<H2Stream, Error> {
        let source = self.pi.local_workload_information.get_workload().await?;
        let sandbox = self.pi.sandbox_for_connection()?;
        let req = self.build_request(source, sandbox, dest_addr).await?;
        if req.protocol != OutboundProtocol::HBONE {
            return Err(Error::UnsupportedFeature(
                "CONNECT-UDP PoC requires an HBONE gateway route".to_string(),
            ));
        }
        // Record the selected peer before opening the stream so failed or cancelled
        // handshakes still identify the attempted gateway in the UDP session log.
        *gateway = Some(req.actual_destination);
        let request = self.create_connect_udp_request(source_addr, &req).await?;

        let pool_key = WorkloadKey {
            src_id: req.source.identity(),
            dst_id: req.upstream_sans.clone(),
            sandbox_id: req
                .sandbox_context
                .sandbox
                .as_ref()
                .map(|sandbox| sandbox.uid.clone()),
            src: source_addr.ip(),
            dst: req.actual_destination,
        };
        let (stream, _) = self
            .pool
            .send_request_pooled(&pool_key, request)
            .instrument(trace_span!("outbound connect-udp"))
            .await?;
        Ok(stream)
    }

    async fn create_connect_udp_request(
        &self,
        source_addr: SocketAddr,
        req: &Request,
    ) -> Result<http::Request<()>, Error> {
        let path = connect_udp_masque_path(req.hbone_target_destination.as_ref())?;
        // Reuse the current HBONE source and Sandbox headers for UDP as well.
        let mut request = self.create_hbone_request(source_addr, req)?;
        *request.uri_mut() = format!("https://{}{path}", req.actual_destination)
            .parse()
            .expect("CONNECT-UDP request uses validated addresses");
        request
            .headers_mut()
            .insert("capsule-protocol", http::HeaderValue::from_static("?1"));
        request
            .extensions_mut()
            .insert(h2::ext::Protocol::from_static("connect-udp"));
        Ok(request)
    }

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
        let build = async {
            let source = self.pi.local_workload_information.get_workload().await?;
            // Select once before routing; policy, headers and pooling use this snapshot.
            let sandbox = self.pi.sandbox_for_connection()?;
            self.build_request(source, sandbox, dest_addr).await
        };
        let req = match Box::pin(build).await {
            Ok(req) => Box::new(req),
            Err(err) => {
                metrics::log_early_deny(source_addr, dest_addr, Reporter::source, err);
                return;
            }
        };

        let rbac_ctx = ProxyRbacContext {
            conn: Connection {
                destination_fqdns: req.destination_fqdns.clone(),
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
            sandbox: req.sandbox_context.sandbox.clone(),
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
                    self.proxy_to_hbone(source_stream, source_addr, &req, connection_result_builder)
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
        stream: TcpStream,
        remote_addr: SocketAddr,
        req: &Request,
        connection_stats_builder: Box<ConnectionResultBuilder>,
    ) {
        let connection_stats = Box::new(connection_stats_builder.build());
        let res = (async {
            let (upgraded, _) = Box::pin(self.send_hbone_request(remote_addr, req)).await?;
            copy::copy_bidirectional(copy::TcpStreamSplitter(stream), upgraded, &connection_stats)
                .await
        })
        .await;
        connection_stats.record(res);
    }

    fn create_hbone_request(
        &self,
        remote_addr: SocketAddr,
        req: &Request,
    ) -> Result<http::Request<()>, Error> {
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
            .header(TRACEPARENT_HEADER, self.id.header());

        if let Some(sandbox) = &req.sandbox_context.sandbox {
            builder = builder.header(sandbox::SANDBOX_ID_HEADER, sandbox.uid.as_str());
        }
        if let Some(header) = &req.sandbox_context.metadata {
            builder = builder.header(SANDBOX_METADATA_HEADER, header.clone());
        }
        if !req.destination_fqdns.is_empty() {
            let mut serializer = sfv::ListSerializer::new();
            for name in &req.destination_fqdns {
                let _ = serializer.bare_item(
                    sfv::StringRef::from_str(name).expect("DNS presentation names are ASCII"),
                );
            }
            let value = serializer.finish().expect("nonempty DNS candidate list");
            if value.len() > MAX_DESTINATION_DNS_CANDIDATES_HEADER_BYTES {
                return Err(Error::DestinationDnsCandidatesHeaderTooLarge(value.len()));
            }
            let mut header =
                http::HeaderValue::from_str(&value).expect("Structured Fields are ASCII");
            header.set_sensitive(true);
            builder = builder.header(DESTINATION_DNS_CANDIDATES_HEADER, header);
        }

        Ok(builder
            .body(())
            .expect("builder with known status code should not fail"))
    }

    /// returns upgraded stream and peer's baggage
    async fn send_hbone_request(
        &mut self,
        remote_addr: SocketAddr,
        req: &Request,
    ) -> Result<(H2Stream, Option<Baggage>), Error> {
        let request = self.create_hbone_request(remote_addr, req)?;
        let pool_key = Box::new(WorkloadKey {
            src_id: req.source.identity(),
            dst_id: req.upstream_sans.clone(),
            sandbox_id: req
                .sandbox_context
                .sandbox
                .as_ref()
                .map(|sandbox| sandbox.uid.clone()),
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
        context: SandboxContext,
        target: SocketAddr,
    ) -> Result<Request, Error> {
        if self.pi.cfg.illegal_ports.contains(&target.port())
            && (target.ip().is_loopback() || source_workload.workload_ips.contains(&target.ip()))
        {
            return Err(Error::SelfCall);
        }

        let destination_fqdns = self
            .pi
            .local_workload_information
            .dns_bindings
            .as_ref()
            .map(|bindings| bindings.lookup(target.ip(), tokio::time::Instant::now()))
            .unwrap_or_default();
        if let Some(result) = self
            .apply_egress_policy(&source_workload, &context, &target, &destination_fqdns)
            .await
        {
            return result;
        }

        debug!("built request as passthrough");
        Ok(Request {
            destination_fqdns,
            protocol: OutboundProtocol::TCP,
            source: source_workload,
            sandbox_context: context,
            hbone_target_destination: None,
            actual_destination_workload: None,
            actual_destination: target,
            upstream_sans: vec![],
        })
    }

    async fn apply_egress_policy(
        &self,
        source_workload: &Arc<Workload>,
        context: &SandboxContext,
        target: &SocketAddr,
        destination_fqdns: &[crate::strng::Strng],
    ) -> Option<Result<Request, Error>> {
        let matched = match_source_egress_policy(source_workload, target)
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
                    destination_fqdns: destination_fqdns.to_vec(),
                    protocol: OutboundProtocol::HBONE,
                    source: source_workload.clone(),
                    sandbox_context: context.clone(),
                    hbone_target_destination: Some(HboneAddress::SocketAddr(*target)),
                    actual_destination_workload: Some(waypoint.workload),
                    actual_destination,
                    upstream_sans,
                }))
            }
        }
    }
}

fn connect_udp_masque_path(
    hbone_target_destination: Option<&HboneAddress>,
) -> Result<String, Error> {
    match hbone_target_destination {
        Some(HboneAddress::SocketAddr(SocketAddr::V4(target))) if target.port() != 0 => Ok(
            format!("/.well-known/masque/udp/{}/{}/", target.ip(), target.port(),),
        ),
        _ => Err(Error::UnsupportedFeature(
            "CONNECT-UDP egress policy requires a numeric IPv4 target".to_string(),
        )),
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
    // Shared admission snapshot for local policy and HBONE metadata, before gateway routing.
    destination_fqdns: Vec<crate::strng::Strng>,
    protocol: OutboundProtocol,
    // Source workload sending the request
    source: Arc<Workload>,
    // Selected before routing; shared by egress policy, CONNECT headers and the pool key.
    sandbox_context: SandboxContext,
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

fn match_source_egress_policy<'a>(
    source_workload: &'a Workload,
    target: &SocketAddr,
) -> Option<&'a EgressPolicy> {
    // Routing is always selected from the source Workload, including Sandbox traffic.
    let policies = source_workload.egress_policies.as_ref()?;
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
    use crate::sandbox::discovery::Sandbox;
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
        let mut local_workload_information = LocalWorkloadInformation::new(
            Arc::new(wi.clone()),
            state.clone(),
            identity::mock::new_secret_manager(Duration::from_secs(10)),
        );
        local_workload_information.dns_bindings = Some(Arc::new(Default::default()));
        let local_workload_information = Arc::new(local_workload_information);
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
                sandbox_management_tls: None,
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
                .build_request(source.clone(), Default::default(), target)
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
                let result = outbound
                    .build_request(source, Default::default(), target)
                    .await;
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
                    outbound
                        .build_request(source.clone(), Default::default(), target)
                        .await,
                    Err(Error::SelfCall)
                ));
            }
            let target = SocketAddr::new("192.0.2.2".parse().unwrap(), port);
            assert!(
                outbound
                    .build_request(source.clone(), Default::default(), target)
                    .await
                    .is_ok()
            );
        }
        assert!(
            outbound
                .build_request(
                    source,
                    Default::default(),
                    "192.0.2.1:8080".parse().unwrap()
                )
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

    #[test]
    fn connect_udp_masque_path_uses_egress_policy_ipv4_target_without_service() {
        let target = HboneAddress::SocketAddr("10.0.0.8:9000".parse().unwrap());

        let path = connect_udp_masque_path(Some(&target)).unwrap();

        assert_eq!(path, "/.well-known/masque/udp/10.0.0.8/9000/");
    }

    #[test]
    fn connect_udp_masque_path_rejects_unsupported_numeric_targets() {
        let ipv6 = HboneAddress::SocketAddr("[2001:db8::1]:9000".parse().unwrap());
        let zero_port = HboneAddress::SocketAddr("10.0.0.8:0".parse().unwrap());

        for target in [None, Some(&ipv6), Some(&zero_port)] {
            assert!(matches!(
                connect_udp_masque_path(target),
                Err(Error::UnsupportedFeature(_))
            ));
        }
    }

    #[tokio::test]
    async fn shared_dns_bindings_are_isolated_per_workload() {
        use crate::dns::resolver::Answer;
        use hickory_proto::rr::{Name, RData, Record, rdata::A};

        let seed = outbound_with_resources(vec![]);
        let mut config = crate::test_helpers::test_config();
        config.proxy_mode = crate::config::ProxyMode::Shared;
        config.enable_dns_name_tracking = true;
        let (_drain, watch) = crate::drain::new();
        let factory = crate::proxyfactory::ProxyFactory::new(
            Arc::new(config),
            seed.pi.state.clone(),
            seed.pi.local_workload_information.full_cert_manager.clone(),
            test_proxy_metrics(),
            Some(crate::dns::Metrics::new(
                &mut prometheus_client::registry::Registry::default(),
            )),
            watch,
            None,
        )
        .unwrap();
        let mut proxies = Vec::new();
        for pod in ["pod-a", "pod-b"] {
            proxies.push(
                factory
                    .new_proxies_from_factory(
                        None,
                        Some(pod),
                        WorkloadInfo::new(pod.into(), "ns".into(), "default".into()),
                        seed.pi.socket_factory.clone(),
                    )
                    .await
                    .unwrap(),
            );
        }
        let bindings: Vec<_> = proxies
            .iter()
            .map(|proxy| {
                assert!(proxy.dns_proxy.is_some());
                proxy
                    .proxy
                    .as_ref()
                    .unwrap()
                    .outbound
                    .pi
                    .local_workload_information
                    .dns_bindings
                    .as_ref()
                    .unwrap()
            })
            .collect();
        assert!(!Arc::ptr_eq(bindings[0], bindings[1]));
        let ip = "203.0.113.7".parse().unwrap();
        let now = tokio::time::Instant::now();
        for (binding, name) in bindings.iter().zip(["a.example.com", "b.example.com"]) {
            let name = Name::from_ascii(name).unwrap();
            binding.observe(
                &name,
                &Answer::new(
                    vec![Record::from_rdata(name.clone(), 60, RData::A(A(ip)))],
                    false,
                ),
                now,
            );
        }
        assert_eq!(bindings[0].lookup(ip.into(), now), ["a.example.com"]);
        assert_eq!(bindings[1].lookup(ip.into(), now), ["b.example.com"]);
    }

    #[tokio::test]
    async fn hbone_dns_header_uses_original_destination_snapshot() {
        use crate::dns::resolver::Answer;
        use crate::state::workload::{GatewayAddress, NetworkAddress, gatewayaddress::Destination};
        use hickory_proto::rr::{Name, RData, Record, rdata::A};

        let outbound = outbound_with_resources(vec![XdsAddressType::Workload(XdsWorkload {
            uid: "egress-gateway".into(),
            namespace: "ns".into(),
            addresses: vec![Bytes::from_static(&[127, 0, 0, 10])],
            ..Default::default()
        })]);
        let source = outbound
            .pi
            .local_workload_information
            .get_workload()
            .await
            .unwrap();
        let source = Arc::new(Workload {
            egress_policies: Some(EgressPolicies {
                policies: vec![EgressPolicy {
                    namespaces: Default::default(),
                    match_cidrs: vec![],
                    match_ports: vec![],
                    policy: EgressPolicyAction::Gateway,
                    gateway: Some(GatewayAddress {
                        destination: Destination::Address(NetworkAddress {
                            network: "".into(),
                            address: "127.0.0.10".parse().unwrap(),
                        }),
                        hbone_mtls_port: 15008,
                    }),
                }],
            }),
            ..(*source).clone()
        });
        let bindings = outbound
            .pi
            .local_workload_information
            .dns_bindings
            .as_ref()
            .unwrap();
        let target: SocketAddr = "203.0.113.7:443".parse().unwrap();
        for (host, ip) in [
            ("B.Example.COM.", "203.0.113.7"),
            ("a.example.com", "203.0.113.7"),
            ("gateway.example.com", "127.0.0.10"),
        ] {
            let name = Name::from_ascii(host).unwrap();
            bindings.observe(
                &name,
                &Answer::new(
                    vec![Record::from_rdata(
                        name.clone(),
                        10,
                        RData::A(A(ip.parse().unwrap())),
                    )],
                    false,
                ),
                tokio::time::Instant::now(),
            );
        }
        let mut req = outbound
            .build_request(source.clone(), Default::default(), target)
            .await
            .unwrap();
        assert_eq!(req.actual_destination, "127.0.0.10:15008".parse().unwrap());
        assert_eq!(req.destination_fqdns, ["a.example.com", "b.example.com"]);
        // Expiration after admission must not change either local evidence or wire metadata.
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(11)).await;
        tokio::time::resume();
        assert!(
            bindings
                .lookup(target.ip(), tokio::time::Instant::now())
                .is_empty()
        );
        let remote = "127.0.0.1:12345".parse().unwrap();
        let request = outbound.create_hbone_request(remote, &req).unwrap();
        assert_eq!(
            request.headers()[DESTINATION_DNS_CANDIDATES_HEADER],
            r#""a.example.com", "b.example.com""#
        );
        assert!(request.headers()[DESTINATION_DNS_CANDIDATES_HEADER].is_sensitive());
        let udp = outbound
            .create_connect_udp_request(remote, &req)
            .await
            .unwrap();
        assert_eq!(
            udp.headers()[DESTINATION_DNS_CANDIDATES_HEADER],
            request.headers()[DESTINATION_DNS_CANDIDATES_HEADER]
        );

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let (headers_tx, headers_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (request, mut response) = connection.accept().await.unwrap().unwrap();
            headers_tx.send(request.headers().clone()).unwrap();
            response
                .send_response(http::Response::new(()), true)
                .unwrap();
            while let Some(stream) = connection.accept().await {
                stream.unwrap();
            }
        });
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(connection);
        let (response, _) = client.send_request(request, true).unwrap();
        assert_eq!(response.await.unwrap().status(), http::StatusCode::OK);
        let received = headers_rx.await.unwrap();
        assert_eq!(
            received["x-agentio-destination-dns-candidates"],
            r#""a.example.com", "b.example.com""#
        );
        assert!(!received.contains_key("x-agentio-destination-dns-names"));
        let received_names: sfv::List =
            sfv::Parser::new(received[DESTINATION_DNS_CANDIDATES_HEADER].as_bytes())
                .parse()
                .unwrap();
        assert_eq!(
            received_names,
            vec![
                sfv::Item::new(sfv::StringRef::constant("a.example.com")).into(),
                sfv::Item::new(sfv::StringRef::constant("b.example.com")).into(),
            ]
        );
        server.abort();
        driver.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        assert!(driver.await.unwrap_err().is_cancelled());
        drop(client);

        let fresh = outbound
            .build_request(source, Default::default(), target)
            .await
            .unwrap();
        assert!(
            !outbound
                .create_hbone_request(remote, &fresh)
                .unwrap()
                .headers()
                .contains_key(DESTINATION_DNS_CANDIDATES_HEADER)
        );
        req.destination_fqdns = (0..1000)
            .map(|i| crate::strng::format!("{i}.example.com"))
            .collect();
        assert!(matches!(
            outbound.create_hbone_request(remote, &req),
            Err(Error::DestinationDnsCandidatesHeaderTooLarge(_))
        ));
        assert!(matches!(
            outbound.create_connect_udp_request(remote, &req).await,
            Err(Error::DestinationDnsCandidatesHeaderTooLarge(_))
        ));
    }

    #[tokio::test]
    async fn hbone_request_carries_sandbox_id_without_sni() {
        const TEST_SANDBOX_TOKEN: &str =
            r#"{"accessToken":"opaque-token","sandboxClientId":"client+/="}"#;
        const TEST_SANDBOX_METADATA: &str =
            "agent-identity.access-token=opaque-token,agent-identity.sandbox-client-id=client+/=";
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

        let id: crate::strng::Strng = "sandbox-a".into();
        let sandbox = crate::xds::agentio::sandbox::Sandbox {
            uid: id.to_string(),
            attester: Some(crate::xds::agentio::sandbox::sandbox::Attester {
                workload_uid: source.uid.clone(),
            }),
            ..Default::default()
        };
        let state = new_proxy_state(&[source], &[], &[sandbox]);
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

        let mut outbound = OutboundConnection {
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
                sandbox_management_tls: None,
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
            destination_fqdns: vec![],
            protocol: OutboundProtocol::HBONE,
            source: source_workload,
            sandbox_context: SandboxContext::default(),
            hbone_target_destination: Some(HboneAddress::SocketAddr(
                "10.0.0.1:8080".parse().unwrap(),
            )),
            actual_destination_workload: None,
            actual_destination: "10.0.0.1:8080".parse().unwrap(),
            upstream_sans: vec![],
        };

        let remote_addr = "127.0.0.1:12345".parse().unwrap();

        let request = outbound.create_hbone_request(remote_addr, &req).unwrap();
        assert!(!request.headers().contains_key("x-agentio-sni"));
        let udp = outbound
            .create_connect_udp_request(remote_addr, &req)
            .await
            .unwrap();
        assert_eq!(udp.method(), hyper::Method::CONNECT);
        assert_eq!(udp.version(), hyper::Version::HTTP_2);
        assert_eq!(
            udp.uri(),
            "https://10.0.0.1:8080/.well-known/masque/udp/10.0.0.1/8080/"
        );
        assert_eq!(udp.headers()["capsule-protocol"], "?1");
        assert_eq!(udp.headers()[FORWARDED], r#"for="127.0.0.1:12345""#);
        assert_eq!(
            udp.extensions()
                .get::<h2::ext::Protocol>()
                .unwrap()
                .as_str(),
            "connect-udp"
        );
        assert!(!udp.headers().contains_key("x-agentio-sni"));
        assert!(!udp.headers().contains_key("x-agentio-tls"));
        let sandbox: Sandbox = crate::xds::agentio::sandbox::Sandbox {
            uid: "sandbox-a".into(),
            ..Default::default()
        }
        .try_into()
        .unwrap();
        let sandbox = Arc::new(sandbox);
        for sandbox in [None, Some(sandbox.clone())] {
            req.sandbox_context = SandboxContext {
                sandbox,
                ..Default::default()
            };
            let request = outbound.create_hbone_request(remote_addr, &req).unwrap();
            assert!(!request.headers().contains_key("x-agentio-sni"));
            assert!(!request.headers().contains_key("x-agentio-tls"));
            assert_eq!(
                request
                    .headers()
                    .get(sandbox::SANDBOX_ID_HEADER)
                    .map(|v| v.to_str().unwrap()),
                req.sandbox_context.sandbox.as_ref().map(|s| s.uid.as_str())
            );
            assert!(!request.headers().contains_key("x-agentio-sandbox-uid"));
        }
        let directory = tempfile::tempdir().unwrap();
        let token_dir = directory.path().join("tokens");
        std::fs::create_dir_all(&token_dir).unwrap();
        std::fs::write(token_dir.join("sandbox.token"), TEST_SANDBOX_TOKEN).unwrap();
        let mut manager = sandbox::SandboxManager::new(state.clone(), Arc::new(wi));
        manager = manager
            .with_registration(directory.path().join("state"))
            .unwrap();
        manager.token = Some(
            crate::sandbox::token::FileSandboxToken::start(token_dir.clone(), 10)
                .await
                .unwrap(),
        );
        let manager = Arc::new(manager);
        Arc::get_mut(&mut outbound.pi).unwrap().sandbox_manager = Some(manager.clone());
        let unprepared = outbound.pi.sandbox_for_connection().unwrap();
        assert!(unprepared.sandbox.is_none());
        assert!(unprepared.metadata.is_none());
        manager.prepare(&id).await.unwrap();
        let context = outbound.pi.sandbox_for_connection().unwrap();
        assert!(directory.path().join("state/sandbox.json").is_file());
        req.sandbox_context = context;
        // HBONE construction uses the captured context, without reading the file again.
        std::fs::remove_file(token_dir.join("sandbox.token")).unwrap();
        let request = outbound.create_hbone_request(remote_addr, &req).unwrap();
        assert_eq!(request.headers()[sandbox::SANDBOX_ID_HEADER], id.as_str());
        assert_eq!(
            request.headers()[SANDBOX_METADATA_HEADER],
            TEST_SANDBOX_METADATA
        );
        assert!(request.headers()[SANDBOX_METADATA_HEADER].is_sensitive());
        assert!(!request.headers().contains_key("x-agentio-sandbox-uid"));
        assert!(!request.headers().contains_key("x-agentio-sandbox-token"));
        let udp = outbound
            .create_connect_udp_request(remote_addr, &req)
            .await
            .unwrap();
        assert_eq!(udp.headers()[sandbox::SANDBOX_ID_HEADER], id.as_str());
        assert_eq!(
            udp.headers()[SANDBOX_METADATA_HEADER],
            TEST_SANDBOX_METADATA
        );
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

            let got = match_source_egress_policy(&workload, &target("10.0.0.1:443"))
                .expect("inline workload policy should match");
            assert_eq!(got.policy, EgressPolicyAction::Deny);

            workload.egress_policies = None;
            assert!(match_source_egress_policy(&workload, &target("10.0.0.1:443")).is_none());
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
    async fn sidecar_dns_learning_and_policy_updates_recheck_tcp() {
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
        let mut local = LocalWorkloadInformation::new(
            Arc::new(WorkloadInfo::new(
                "pod".into(),
                "ns".into(),
                "default".into(),
            )),
            state.clone(),
            identity::mock::new_secret_manager(Duration::from_secs(10)),
        );
        local.dns_bindings = Some(Arc::new(Default::default()));
        let local = Arc::new(local);
        let sockets = Arc::new(crate::proxy::DefaultSocketFactory::default());
        let connection_manager = ConnectionManager::default();
        let (stop, watch) = crate::drain::new();
        let watcher = tokio::spawn(
            crate::proxy::connection_manager::PolicyWatcher::new(
                state.clone(),
                watch.clone(),
                connection_manager.clone(),
            )
            .run(),
        );
        use crate::xds::agentio::sandbox::{Sandbox, sandbox::Attester};
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
        let allow_fqdn = TrafficPolicy {
            egress: Some(traffic_policy::RuleSet {
                rules: vec![traffic_policy::Rule {
                    action: traffic_policy::Action::Allow.into(),
                    r#match: Some(traffic_policy::Match {
                        destination_fqdns: vec!["api.example.com".into()],
                        ..Default::default()
                    }),
                }],
            }),
            ..Default::default()
        };
        publish(Sandbox {
            uid: "sandbox-a".into(),
            attester: Some(Attester {
                workload_uid: fixture.workload.uid.to_string(),
            }),
            traffic_policy: Some(allow_fqdn.clone()),
            ..Default::default()
        });
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
                sandbox_management_tls: None,
                firewall_metrics: None,
            }),
            id: TraceParent::new(),
            pool: WorkloadHBONEPool::new(cfg.clone(), sockets, local),
        };
        let inputs = outbound.pi.clone();
        let pool = outbound.pool.clone();
        struct TestForwarder(crate::dns::forwarder::Forwarder);
        #[async_trait::async_trait]
        impl crate::dns::Forwarder for TestForwarder {
            fn search_domains(
                &self,
                _: &crate::state::workload::Workload,
            ) -> Vec<hickory_proto::rr::Name> {
                vec![]
            }
            async fn forward(
                &self,
                _: Option<&crate::state::workload::Workload>,
                request: &hickory_server::server::Request,
            ) -> Result<crate::dns::resolver::Answer, hickory_server::zone_handler::LookupError>
            {
                crate::dns::resolver::Resolver::lookup(&self.0, request).await
            }
        }
        let upstream_dns = crate::test_helpers::dns::run_dns(std::collections::HashMap::from([(
            crate::test_helpers::dns::n("api.example.com."),
            vec!["127.0.0.1".parse().unwrap()],
        )]))
        .await
        .unwrap();
        let dns = crate::dns::Server::new(
            "cluster.local".into(),
            crate::config::Address::Localhost(false, 0),
            inputs.state.clone(),
            Arc::new(TestForwarder(
                crate::dns::forwarder::Forwarder::new(
                    upstream_dns.resolver_config(),
                    inputs.socket_factory.clone(),
                    Default::default(),
                )
                .unwrap(),
            )),
            Arc::new(crate::dns::Metrics::new(
                &mut prometheus_client::registry::Registry::default(),
            )),
            watch,
            inputs.socket_factory.as_ref(),
            inputs.local_workload_information.as_fetcher(),
            None,
            true,
        )
        .await
        .unwrap();
        let dns_addr = dns.udp_address();
        let dns_task = tokio::spawn(dns.run());
        for _ in 0..2 {
            let response =
                crate::test_helpers::app::dns_request(dns_addr, "api.example.com.", true, false)
                    .await;
            assert_eq!(response.answers.len(), 1);
        }
        assert_eq!(
            inputs
                .local_workload_information
                .dns_bindings
                .as_ref()
                .unwrap()
                .lookup("127.0.0.1".parse().unwrap(), tokio::time::Instant::now()),
            ["api.example.com"]
        );
        tokio::time::timeout(Duration::from_secs(15), async {
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
            // Replaying the same Sandbox resource leaves established traffic intact.
            publish(Sandbox {
                uid: "sandbox-a".into(),
                attester: Some(Attester {
                    workload_uid: fixture.workload.uid.to_string(),
                }),
                traffic_policy: Some(allow_fqdn.clone()),
                ..Default::default()
            });
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
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(6)).await;
            tokio::time::resume();
            assert!(
                inputs
                    .local_workload_information
                    .dns_bindings
                    .as_ref()
                    .unwrap()
                    .lookup(destination.ip(), tokio::time::Instant::now())
                    .is_empty()
            );
            let established = connection_manager.connections().pop().unwrap();
            assert!(
                inputs
                    .state
                    .assert_rbac(&established.rbac_ctx)
                    .await
                    .is_ok()
            );
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
        dns_task.await.unwrap();
    }
}
