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

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use futures_util::TryFutureExt;
use hyper::header::FORWARDED;
use std::time::Instant;

use tokio::net::TcpStream;
use tokio::sync::watch;

use tracing::{Instrument, debug, error, info, info_span, trace_span};

use crate::extensions::extensions::{EgressPolicies, EgressPolicy, EgressPolicyAction};
use crate::identity::Identity;
use crate::proxy::connection_manager::{ConnectionAttributes, ConnectionContext};
use crate::rbac::{Connection, Direction};
use crate::sandbox::discovery::Sandbox;
use crate::sandbox::sandbox;
use crate::strng::Strng;

use crate::proxy::metrics::Reporter;
use crate::proxy::{
    BAGGAGE_HEADER, Error, HboneAddress, ProxyInputs, TRACEPARENT_HEADER, TraceParent,
    WORKLOAD_NAME_HEADER, WORKLOAD_NAMESPACE_HEADER, X_FORWARDED_NETWORK_HEADER, util,
};
use crate::proxy::{ConnectionOpen, ConnectionResultBuilder, DerivedWorkload, metrics};

use crate::baggage::{self, Baggage};
use crate::drain::DrainWatcher;
use crate::drain::run_with_drain;
use crate::proxy::h2::{H2Stream, client::WorkloadKey};
use crate::state::service::{LoadBalancerMode, Service, ServiceDescription};
use crate::state::workload::OutboundProtocol;
use crate::state::workload::{InboundProtocol, NetworkAddress, Workload, address::Address};
use crate::state::{ProxyRbacContext, ServiceResolutionMode, Upstream};
use crate::tls::identity_from_connection;
use crate::xds::kruise::networking::extensions::v1::MeshInternalTrafficPolicy::MeshInternalPassthrough;
use crate::{assertions, copy, proxy, socket};

use super::h2::TokioH2Stream;

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
                            hbone_port: self.pi.cfg.inbound_addr.port(),
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
    pub(super) hbone_port: u16,
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

        let illegal_call =
            dest_addr.ip().is_loopback() && self.pi.cfg.illegal_ports.contains(&dest_addr.port());
        if illegal_call {
            metrics::log_early_deny(source_addr, dest_addr, Reporter::source, Error::SelfCall);
            return;
        }
        // First find the source workload of this traffic. If we don't know where the request is from
        // we will reject it.
        let build = self
            .pi
            .local_workload_information
            .get_workload()
            .and_then(|source| {
                // Select once before routing; policy, headers and pooling use this snapshot.
                let sandbox = self
                    .pi
                    .sandbox_manager
                    .as_ref()
                    .and_then(|manager| manager.fetch_attested_sandbox(&source));
                self.build_request(source, sandbox, source_addr.ip(), dest_addr)
            });
        let req = match Box::pin(build).await {
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
                OutboundProtocol::DOUBLEHBONE => {
                    // We box this since its not a common path and it would make the future really big.
                    Box::pin(self.proxy_to_double_hbone(
                        source_stream,
                        source_addr,
                        &req,
                        connection_result_builder,
                    ))
                    .await
                }
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

    async fn proxy_to_double_hbone(
        &mut self,
        stream: TcpStream,
        remote_addr: SocketAddr,
        req: &Request,
        mut connection_stats_builder: Box<ConnectionResultBuilder>,
    ) {
        // async move block allows use of ? operator
        let res = (async move {
            // Create the outer HBONE stream
            let (upgraded, _) = Box::pin(self.send_hbone_request(remote_addr, req)).await?;
            // Wrap upgraded to implement tokio's Async{Write,Read}
            let upgraded = TokioH2Stream::new(upgraded);

            // For the inner one, we do it manually to avoid connection pooling.
            // Otherwise, we would only ever reach one workload in the remote cluster.
            // We also need to abort tasks the right way to get graceful terminations.
            let wl_key = WorkloadKey {
                src_id: req.source.identity(),
                dst_id: req.final_sans.clone(),
                sandbox_id: req.sandbox.as_ref().map(|sandbox| sandbox.uid.clone()),
                src: remote_addr.ip(),
                dst: req.actual_destination,
            };

            // Fetch certs and establish inner TLS connection.
            let cert = self
                .pi
                .local_workload_information
                .fetch_certificate()
                .await?;
            let connector = cert.outbound_connector(wl_key.dst_id.clone())?;
            let tls_stream = connector.connect(upgraded).await?;
            let (_, ssl) = tls_stream.get_ref();
            let peer_identity = identity_from_connection(ssl);

            // Spawn inner CONNECT tunnel
            let (drain_tx, drain_rx) = tokio::sync::watch::channel(false);
            let mut sender = super::h2::client::spawn_connection(
                self.pi.cfg.clone(),
                tls_stream,
                drain_rx,
                wl_key,
            )
            .await?;
            let origin_network = &self.pi.cfg.network;
            let http_request = self
                .create_hbone_request(remote_addr, req, Some(origin_network))
                .await;
            let (inner_upgraded, baggage) = sender.send_request(http_request).await?;

            // Proxy
            let derived_workload = baggage.map(|baggage| DerivedWorkload {
                workload_name: baggage.workload_name,
                app: baggage.service_name,
                namespace: baggage.namespace,
                identity: peer_identity,
                cluster_id: baggage.cluster_id,
                region: baggage.region,
                zone: baggage.zone,
                revision: baggage.revision,
            });
            Result::<_, Error>::Ok((derived_workload, drain_tx, inner_upgraded))
        })
        .await;

        match res {
            Err(e) => {
                let connection_stats = connection_stats_builder.build();
                connection_stats.record(Err(e));
            }
            Ok((derived_workload, drain_tx, inner_upgraded)) => {
                if let Some(derived_workload) = derived_workload {
                    *connection_stats_builder =
                        connection_stats_builder.with_derived_destination(&derived_workload);
                }

                let connection_stats = connection_stats_builder.build();
                let res = copy::copy_bidirectional(
                    copy::TcpStreamSplitter(stream),
                    inner_upgraded,
                    &connection_stats,
                )
                .await;
                let _ = drain_tx.send(true);

                connection_stats.record(res);
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

    async fn create_hbone_request(
        &self,
        remote_addr: SocketAddr,
        req: &Request,
        origin_network: Option<&Strng>,
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
            .header(
                FORWARDED,
                build_forwarded(remote_addr, &req.intended_destination_service),
            )
            .header(TRACEPARENT_HEADER, self.id.header())
            // Identify the source pod, rather than its owning deployment.
            // This context also applies when sandbox mode is disabled.
            .header(WORKLOAD_NAME_HEADER, req.source.name.as_str())
            .header(WORKLOAD_NAMESPACE_HEADER, req.source.namespace.as_str());

        // Add x-istio-origin-network header for inner CONNECT requests in double HBONE
        if let Some(network) = origin_network {
            builder = builder.header(X_FORWARDED_NETWORK_HEADER, network.as_str());
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
        // This is the single cluster/single-HBONE codepath (and also the outer tunnel
        // for double HBONE). We don't need the x-istio-origin-network header here because:
        // - For single HBONE: both source and destination are in the same network
        // - For double HBONE outer: the gateway doesn't need origin network info
        let request = self.create_hbone_request(remote_addr, req, None).await;
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
            OutboundProtocol::HBONE | OutboundProtocol::DOUBLEHBONE => (
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
            destination_service: req.intended_destination_service.clone(),
        }
    }

    // This function is called when the select next hop is on a different network,
    // so we expect the upstream workload to have a network gatewy configured.
    //
    // When we use a gateway to reach to a workload on a remote network we have to
    // use double HBONE (HBONE incapsulated inside HBONE). The gateway will
    // terminate the outer HBONE tunnel and forward the inner HBONE to the actual
    // destination as a opaque stream of bytes and the actual destination will
    // interpret it as an HBONE connection.
    //
    // If the upstream workload does not have an E/W gateway this function returns
    // an error indicating that it could not find a valid destination.
    //
    // A note about double HBONE, in double HBONE both inner and outer HBONE use
    // destination service name as HBONE target URI.
    //
    // Having target URI in the outer HBONE tunnel allows E/W gateway to figure out
    // where to route the data next witout the need to terminate inner HBONE tunnel.
    // In other words, it could forward inner HBONE as if it's an opaque stream of
    // bytes without trying to interpret it.
    //
    // NOTE: when connecting through an E/W gateway, regardless of whether there is
    // a waypoint or not, we always use service hostname and the service port. It's
    // somewhat different from how regular HBONE works, so I'm calling it out here.
    async fn build_request_through_gateway(
        &self,
        source: Arc<Workload>,
        sandbox: Option<Arc<Sandbox>>,
        // next hop on the remote network that we picked as our destination.
        // It may be a local view of a Waypoint workload on remote network or
        // a local view of the service workload (when waypoint is not
        // configured).
        upstream: Upstream,
        // This is a target service we wanted to reach in the first place.
        //
        // NOTE: Crossing network boundaries is only supported for services
        // at the moment, so we should always have a service we could use.
        service: &Service,
        target: SocketAddr,
    ) -> Result<Request, Error> {
        if let Some(gateway) = &upstream.workload.network_gateway {
            let gateway_upstream = self
                .pi
                .state
                .fetch_network_gateway(gateway, &source, target)
                .await?;
            let hbone_target_destination = Some(HboneAddress::SvcHostname(
                service.hostname.clone(),
                target.port(),
            ));

            debug!("built request to a destination on another network through an E/W gateway");
            Ok(Request {
                protocol: OutboundProtocol::DOUBLEHBONE,
                source,
                sandbox,
                hbone_target_destination,
                actual_destination_workload: Some(gateway_upstream.workload.clone()),
                intended_destination_service: Some(ServiceDescription::from(service)),
                actual_destination: gateway_upstream.workload_socket_addr().ok_or(
                    Error::NoValidDestination(Box::new((*gateway_upstream.workload).clone())),
                )?,
                // The outer tunnel of double HBONE is terminated by the E/W
                // gateway and so for the credentials of the next hop
                // (upstream_sans) we use gateway credentials.
                upstream_sans: gateway_upstream.workload_and_services_san(),
                // The inner HBONE tunnel is terminated by either the server
                // we want to reach or a Waypoint in front of it, depending on
                // the configuration. So for the final destination credentials
                // (final_sans) we use the upstream workload credentials.
                final_sans: upstream.service_sans(),
            })
        } else {
            // Do not try to send cross-network traffic without network gateway.
            Err(Error::NoValidDestination(Box::new(
                (*upstream.workload).clone(),
            )))
        }
    }

    // build_request computes all information about the request we should send
    // TODO: Do we want a single lock for source and upstream...?
    async fn build_request(
        &self,
        source_workload: Arc<Workload>,
        sandbox: Option<Arc<Sandbox>>,
        downstream: IpAddr,
        target: SocketAddr,
    ) -> Result<Request, Error> {
        let state = &self.pi.state;

        if source_workload.mesh_internal_traffic_policy == MeshInternalPassthrough {
            if let Some(result) = self
                .apply_egress_policy(&source_workload, &sandbox, &target)
                .await
            {
                return result;
            }

            debug!("built request as passthrough;");
            return Ok(Request {
                protocol: OutboundProtocol::TCP,
                source: source_workload,
                sandbox,
                hbone_target_destination: None,
                actual_destination_workload: None,
                intended_destination_service: None,
                actual_destination: target,
                upstream_sans: vec![],
                final_sans: vec![],
            });
        }

        // If this is to-service traffic check for a service waypoint
        // Capture result of whether this is svc addressed
        let service = if let Some(Address::Service(target_service)) = state
            .fetch_address(&NetworkAddress {
                network: self.pi.cfg.network.clone(),
                address: target.ip(),
            })
            .await
        {
            // if we have a waypoint for this svc, use it; otherwise route traffic normally
            if let Some(waypoint) = state
                .fetch_service_waypoint(&target_service, &source_workload, target)
                .await?
            {
                if waypoint.workload.network != source_workload.network {
                    debug!("picked a waypoint on remote network");
                    return self
                        .build_request_through_gateway(
                            source_workload.clone(),
                            sandbox,
                            waypoint,
                            &target_service,
                            target,
                        )
                        .await;
                }

                let upstream_sans = waypoint.workload_and_services_san();
                let actual_destination =
                    waypoint
                        .workload_socket_addr()
                        .ok_or(Error::NoValidDestination(Box::new(
                            (*waypoint.workload).clone(),
                        )))?;
                debug!("built request to service waypoint proxy");
                return Ok(Request {
                    protocol: OutboundProtocol::HBONE,
                    source: source_workload,
                    sandbox,
                    hbone_target_destination: Some(HboneAddress::SocketAddr(target)),
                    actual_destination_workload: Some(waypoint.workload),
                    intended_destination_service: Some(ServiceDescription::from(&*target_service)),
                    actual_destination,
                    upstream_sans,
                    final_sans: vec![],
                });
            }
            // this was service addressed but we did not find a waypoint
            Some(target_service)
        } else {
            // this wasn't service addressed
            None
        };

        let Some(us) = state
            .fetch_upstream(
                source_workload.network.clone(),
                &source_workload,
                target,
                ServiceResolutionMode::Standard,
            )
            .await?
        else {
            if let Some(service) = service
                && service.
                load_balancer.
                as_ref().
                // If we are not a passthrough service, we should have an upstream
                map(|lb| lb.mode != LoadBalancerMode::Passthrough).
                // If the service had no lb, we should have an upstream
                unwrap_or(true)
            {
                return Err(Error::NoHealthyUpstream(target));
            }

            if let Some(result) = self
                .apply_egress_policy(&source_workload, &sandbox, &target)
                .await
            {
                return result;
            }

            debug!("built request as passthrough; no upstream found");
            return Ok(Request {
                protocol: OutboundProtocol::TCP,
                source: source_workload,
                sandbox,
                hbone_target_destination: None,
                actual_destination_workload: None,
                intended_destination_service: None,
                actual_destination: target,
                upstream_sans: vec![],
                final_sans: vec![],
            });
        };

        // Check whether we are using an E/W gateway and sending cross network traffic
        if us.workload.network != source_workload.network {
            // Workloads on remote network must be service addressed, so if we got here
            // and we don't have a service for the original target address then it's a
            // bug either in ztunnel itself or in istiod.
            //
            // For a double HBONE protocol implementation we have to know the
            // destination service and if there is no service for the target it's a bug.
            //
            // This situation "should never happen" because for workloads fetch_upstream
            // above only checks the workloads on the same network as this ztunnel
            // instance and therefore it should not be able to find a workload on a
            // different network.
            debug_assert!(
                service.is_some(),
                "workload on remote network is not service addressed"
            );
            debug!("picked a workload on remote network");
            let service = service.as_ref().ok_or(Error::NoService(target))?;
            return self
                .build_request_through_gateway(
                    source_workload.clone(),
                    sandbox,
                    us,
                    service,
                    target,
                )
                .await;
        }

        // We are not using a network gateway and there is no workload address.
        let from_waypoint = proxy::check_from_waypoint(
            state,
            &us.workload,
            Some(&source_workload.identity()),
            &downstream,
        )
        .await;

        // Check if we need to go through a workload addressed waypoint.
        // Don't traverse waypoint twice if the source is sandwich-outbound.
        // Don't traverse waypoint if traffic was addressed to a service (handled before)
        if !from_waypoint && service.is_none() {
            // For case upstream server has enabled waypoint
            let waypoint = state
                .fetch_workload_waypoint(&us.workload, &source_workload, target)
                .await?;
            if let Some(waypoint) = waypoint {
                let actual_destination =
                    waypoint
                        .workload_socket_addr()
                        .ok_or(Error::NoValidDestination(Box::new(
                            (*waypoint.workload).clone(),
                        )))?;
                let upstream_sans = waypoint.workload_and_services_san();
                debug!("built request to workload waypoint proxy");
                return Ok(Request {
                    // Always use HBONE here
                    protocol: OutboundProtocol::HBONE,
                    source: source_workload,
                    sandbox,
                    // Use the original VIP, not translated
                    hbone_target_destination: Some(HboneAddress::SocketAddr(target)),
                    actual_destination_workload: Some(waypoint.workload),
                    intended_destination_service: us.destination_service.clone(),
                    actual_destination,
                    upstream_sans,
                    final_sans: vec![],
                });
            }
            // Workload doesn't have a waypoint; send directly
        }

        let selected_workload_ip = us
            .selected_workload_ip
            .ok_or(Error::NoValidDestination(Box::new((*us.workload).clone())))?;

        // only change the port if we're sending HBONE
        let actual_destination = match us.workload.protocol {
            InboundProtocol::HBONE => SocketAddr::from((selected_workload_ip, self.hbone_port)),
            InboundProtocol::TCP => us
                .workload_socket_addr()
                .ok_or(Error::NoValidDestination(Box::new((*us.workload).clone())))?,
        };
        let hbone_target_destination = match us.workload.protocol {
            InboundProtocol::HBONE => Some(HboneAddress::SocketAddr(
                us.workload_socket_addr()
                    .ok_or(Error::NoValidDestination(Box::new((*us.workload).clone())))?,
            )),
            InboundProtocol::TCP => None,
        };

        // For case no waypoint for both side and direct to remote node proxy
        let (upstream_sans, final_sans) = (us.workload_and_services_san(), vec![]);
        debug!("built request to workload");
        Ok(Request {
            protocol: OutboundProtocol::from(us.workload.protocol),
            source: source_workload,
            sandbox,
            hbone_target_destination,
            actual_destination_workload: Some(us.workload.clone()),
            intended_destination_service: us.destination_service.clone(),
            actual_destination,
            upstream_sans,
            final_sans,
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
                let actual_destination = match waypoint.workload_socket_addr() {
                    Some(addr) => addr,
                    None => {
                        return Some(Err(Error::NoValidDestination(Box::new(
                            (*waypoint.workload).clone(),
                        ))));
                    }
                };
                let upstream_sans = waypoint.workload_and_services_san();
                Some(Ok(Request {
                    protocol: OutboundProtocol::HBONE,
                    source: source_workload.clone(),
                    sandbox: sandbox.clone(),
                    hbone_target_destination: Some(HboneAddress::SocketAddr(*target)),
                    actual_destination_workload: Some(waypoint.workload),
                    intended_destination_service: None,
                    actual_destination,
                    upstream_sans,
                    final_sans: vec![],
                }))
            }
        }
    }
}

fn build_forwarded(remote_addr: SocketAddr, server: &Option<ServiceDescription>) -> String {
    match server {
        None => {
            format!("for=\"{remote_addr}\"")
        }
        Some(svc) => {
            format!("for=\"{remote_addr}\";host={}", svc.hostname)
        }
    }
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
    // The actual destination workload we are targeting. When proxying through a waypoint, this is the waypoint,
    // not the original.
    // May be unset in case of passthrough.
    actual_destination_workload: Option<Arc<Workload>>,
    // The intended destination service for the request. When proxying through a waypoint, this is *not* the waypoint
    // service, but rather the original intended service.
    // May be unset in case of non-service traffic
    intended_destination_service: Option<ServiceDescription>,
    // The address we should actually request to. This is the "next hop" address; could be a waypoint, network gateway,
    // etc.
    // When using HBONE, the `hbone_target_destination` is the inner :authority and `actual_destination` is the TCP destination.
    actual_destination: SocketAddr,
    // If using HBONE, the inner (:authority) of the HBONE request.
    hbone_target_destination: Option<HboneAddress>,

    // The identity we will assert for the next hop; this may not be the same as actual_destination_workload
    // in the case of proxies along the path.
    upstream_sans: Vec<Identity>,

    // The identity of workload that will ultimately process this request.
    // This field only matters if we need to know both the identity of the next hop, as well as the
    // final hop (currently, this is only double HBONE).
    final_sans: Vec<Identity>,
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
    use crate::xds::istio::workload::Workload as XdsWorkload;
    use crate::xds::istio::workload::address::Type as XdsAddressType;
    use crate::xds::istio::workload::{IpFamilies, Port};
    use crate::xds::istio::workload::{LoadBalancing, TunnelProtocol as XdsProtocol};
    use crate::xds::istio::workload::{
        NamespacedHostname as XdsNamespacedHostname, NetworkAddress as XdsNetworkAddress, PortList,
    };
    use crate::xds::istio::workload::{NetworkMode, Service as XdsService};
    use crate::{identity, xds};

    async fn run_build_request(
        from: &str,
        to: &str,
        xds: XdsAddressType,
        expect: Option<ExpectedRequest<'_>>,
    ) {
        run_build_request_multi(from, to, vec![xds], expect).await;
    }

    async fn run_build_request_multi(
        from: &str,
        to: &str,
        xds: Vec<XdsAddressType>,
        expect: Option<ExpectedRequest<'_>>,
    ) -> Option<Request> {
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
        let waypoint = XdsWorkload {
            uid: "cluster1//v1/Pod/ns/waypoint-workload".to_string(),
            name: "waypoint-workload".to_string(),
            namespace: "ns".to_string(),
            addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 10])],
            node: "local-node".to_string(),
            service_account: "waypoint-sa".to_string(),
            ..Default::default()
        };
        let waypoint_dual = XdsWorkload {
            uid: "cluster1//v1/Pod/ns/waypoint-workload-dual".to_string(),
            name: "waypoint-workload-dual".to_string(),
            namespace: "ns".to_string(),
            addresses: vec![
                Bytes::copy_from_slice(&[127, 0, 0, 11]),
                Bytes::copy_from_slice("ff06::c5".parse::<Ipv6Addr>().unwrap().octets().as_slice()),
            ],
            node: "local-node".to_string(),
            service_account: "waypoint-sa".to_string(),
            ..Default::default()
        };
        let mut workloads = vec![source, waypoint, waypoint_dual];
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
            hbone_port: cfg.inbound_addr.port(),
        };

        let local = outbound
            .pi
            .local_workload_information
            .get_workload()
            .await
            .unwrap();
        let req = outbound
            .build_request(local, None, from.parse().unwrap(), to.parse().unwrap())
            .await
            .ok();
        if let Some(ref r) = req {
            assert_eq!(
                expect,
                Some(ExpectedRequest {
                    protocol: r.protocol,
                    hbone_destination: &r
                        .hbone_target_destination
                        .as_ref()
                        .map(|s| s.to_string())
                        .unwrap_or_default(),
                    destination: &r.actual_destination.to_string(),
                })
            );
        } else {
            assert_eq!(expect, None);
        }
        req
    }

    #[tokio::test]
    async fn build_request_unknown_dest() {
        run_build_request(
            "127.0.0.1",
            "1.2.3.4:80",
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/default/my-pod".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                ..Default::default()
            }),
            Some(ExpectedRequest {
                protocol: OutboundProtocol::TCP,
                hbone_destination: "",
                destination: "1.2.3.4:80",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_wrong_network() {
        run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            vec![
                XdsAddressType::Service(XdsService {
                    hostname: "example.com".to_string(),
                    addresses: vec![XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![127, 0, 0, 3],
                    }],
                    ports: vec![Port {
                        service_port: 80,
                        target_port: 8080,
                    }],
                    ..Default::default()
                }),
                XdsAddressType::Workload(XdsWorkload {
                    uid: "cluster1//v1/Pod/default/remote-pod".to_string(),
                    addresses: vec![Bytes::copy_from_slice(&[10, 0, 0, 2])],
                    network: "remote".to_string(),
                    services: std::collections::HashMap::from([(
                        "/example.com".to_string(),
                        PortList {
                            ports: vec![Port {
                                service_port: 80,
                                target_port: 8080,
                            }],
                        },
                    )]),
                    ..Default::default()
                }),
            ],
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_double_hbone() {
        // example.com service has a workload on remote network.
        // E/W gateway is addressed by an IP.
        run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            vec![
                XdsAddressType::Service(XdsService {
                    hostname: "example.com".to_string(),
                    addresses: vec![XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![127, 0, 0, 3],
                    }],
                    ports: vec![Port {
                        service_port: 80,
                        target_port: 8080,
                    }],
                    ..Default::default()
                }),
                XdsAddressType::Workload(XdsWorkload {
                    uid: "cluster1//v1/Pod/default/remote-pod".to_string(),
                    addresses: vec![],
                    network: "remote".to_string(),
                    network_gateway: Some(xds::istio::workload::GatewayAddress {
                        destination: Some(
                            xds::istio::workload::gateway_address::Destination::Address(
                                XdsNetworkAddress {
                                    network: "remote".to_string(),
                                    address: vec![10, 22, 1, 1],
                                },
                            ),
                        ),
                        hbone_mtls_port: 15009,
                    }),
                    services: std::collections::HashMap::from([(
                        "/example.com".to_string(),
                        PortList {
                            ports: vec![Port {
                                service_port: 80,
                                target_port: 8080,
                            }],
                        },
                    )]),
                    ..Default::default()
                }),
                XdsAddressType::Workload(XdsWorkload {
                    uid: "cluster1//v1/Pod/default/ew-gtw".to_string(),
                    addresses: vec![Bytes::copy_from_slice(&[10, 22, 1, 1])],
                    network: "remote".to_string(),
                    ..Default::default()
                }),
            ],
            Some(ExpectedRequest {
                protocol: OutboundProtocol::DOUBLEHBONE,
                hbone_destination: "example.com:80",
                destination: "10.22.1.1:15009",
            }),
        )
        .await;
        // example.com service has a workload on remote network.
        // E/W gateway is addressed by a hostname.
        run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            vec![
                XdsAddressType::Service(XdsService {
                    hostname: "example.com".to_string(),
                    addresses: vec![XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![127, 0, 0, 3],
                    }],
                    ports: vec![Port {
                        service_port: 80,
                        target_port: 8080,
                    }],
                    ..Default::default()
                }),
                XdsAddressType::Service(XdsService {
                    hostname: "ew-gtw".to_string(),
                    addresses: vec![XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![127, 0, 0, 4],
                    }],
                    ports: vec![Port {
                        service_port: 15009,
                        target_port: 15009,
                    }],
                    ..Default::default()
                }),
                XdsAddressType::Workload(XdsWorkload {
                    uid: "cluster1//v1/Pod/default/remote-pod".to_string(),
                    addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 6])],
                    network: "remote".to_string(),
                    network_gateway: Some(xds::istio::workload::GatewayAddress {
                        hbone_mtls_port: 15009,
                        destination: Some(
                            xds::istio::workload::gateway_address::Destination::Hostname(
                                XdsNamespacedHostname {
                                    namespace: Default::default(),
                                    hostname: "ew-gtw".into(),
                                },
                            ),
                        ),
                    }),
                    services: std::collections::HashMap::from([(
                        "/example.com".to_string(),
                        PortList {
                            ports: vec![Port {
                                service_port: 80,
                                target_port: 8080,
                            }],
                        },
                    )]),
                    ..Default::default()
                }),
                XdsAddressType::Workload(XdsWorkload {
                    uid: "cluster1//v1/Pod/default/ew-gtw".to_string(),
                    addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 5])],
                    network: "remote".to_string(),
                    services: std::collections::HashMap::from([(
                        "/ew-gtw".to_string(),
                        PortList {
                            ports: vec![Port {
                                service_port: 15009,
                                target_port: 15008,
                            }],
                        },
                    )]),
                    ..Default::default()
                }),
            ],
            Some(ExpectedRequest {
                protocol: OutboundProtocol::DOUBLEHBONE,
                hbone_destination: "example.com:80",
                destination: "127.0.0.5:15008",
            }),
        )
        .await;
        // example.com service has a waypoint and waypoint workload is on remote network.
        // E/W gateway is addressed by an IP.
        run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            vec![
                XdsAddressType::Service(XdsService {
                    hostname: "example.com".to_string(),
                    addresses: vec![XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![127, 0, 0, 3],
                    }],
                    ports: vec![Port {
                        service_port: 80,
                        target_port: 8080,
                    }],
                    waypoint: Some(xds::istio::workload::GatewayAddress {
                        destination: Some(
                            xds::istio::workload::gateway_address::Destination::Hostname(
                                XdsNamespacedHostname {
                                    namespace: Default::default(),
                                    hostname: "waypoint.com".into(),
                                },
                            ),
                        ),
                        hbone_mtls_port: 15008,
                    }),
                    ..Default::default()
                }),
                XdsAddressType::Service(XdsService {
                    hostname: "waypoint.com".to_string(),
                    addresses: vec![XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![127, 0, 0, 4],
                    }],
                    ports: vec![Port {
                        service_port: 15008,
                        target_port: 15008,
                    }],
                    ..Default::default()
                }),
                XdsAddressType::Workload(XdsWorkload {
                    uid: "Kubernetes//Pod/default/remote-waypoint-pod".to_string(),
                    addresses: vec![],
                    network: "remote".to_string(),
                    network_gateway: Some(xds::istio::workload::GatewayAddress {
                        destination: Some(
                            xds::istio::workload::gateway_address::Destination::Address(
                                XdsNetworkAddress {
                                    network: "remote".to_string(),
                                    address: vec![10, 22, 1, 1],
                                },
                            ),
                        ),
                        hbone_mtls_port: 15009,
                    }),
                    services: std::collections::HashMap::from([(
                        "/waypoint.com".to_string(),
                        PortList {
                            ports: vec![Port {
                                service_port: 15008,
                                target_port: 15008,
                            }],
                        },
                    )]),
                    ..Default::default()
                }),
                XdsAddressType::Workload(XdsWorkload {
                    uid: "Kubernetes//Pod/default/remote-ew-gtw".to_string(),
                    addresses: vec![Bytes::copy_from_slice(&[10, 22, 1, 1])],
                    network: "remote".to_string(),
                    ..Default::default()
                }),
            ],
            Some(ExpectedRequest {
                protocol: OutboundProtocol::DOUBLEHBONE,
                hbone_destination: "example.com:80",
                destination: "10.22.1.1:15009",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_failover_to_remote() {
        // Similar to the double HBONE test that we already have, but it sets up a scenario when
        // load balancing logic will pick a workload on a remote cluster when local workloads are
        // unhealthy, thus showing the expected failover behavior.
        let service = XdsAddressType::Service(XdsService {
            hostname: "example.com".to_string(),
            addresses: vec![XdsNetworkAddress {
                network: "".to_string(),
                address: vec![127, 0, 0, 3],
            }],
            ports: vec![Port {
                service_port: 80,
                target_port: 8080,
            }],
            // Prefer routing to workloads on the same network, but when nothing is healthy locally
            // allow failing over to remote networks.
            load_balancing: Some(xds::istio::workload::LoadBalancing {
                routing_preference: vec![
                    xds::istio::workload::load_balancing::Scope::Network.into(),
                ],
                mode: xds::istio::workload::load_balancing::Mode::Failover.into(),
                ..Default::default()
            }),
            ..Default::default()
        });
        let ew_gateway = XdsAddressType::Workload(XdsWorkload {
            uid: "Kubernetes//Pod/default/remote-ew-gtw".to_string(),
            addresses: vec![Bytes::copy_from_slice(&[10, 22, 1, 1])],
            network: "remote".to_string(),
            ..Default::default()
        });
        let remote_workload = XdsAddressType::Workload(XdsWorkload {
            uid: "Kubernetes//Pod/default/remote-example.com-pod".to_string(),
            addresses: vec![],
            network: "remote".to_string(),
            network_gateway: Some(xds::istio::workload::GatewayAddress {
                destination: Some(xds::istio::workload::gateway_address::Destination::Address(
                    XdsNetworkAddress {
                        network: "remote".to_string(),
                        address: vec![10, 22, 1, 1],
                    },
                )),
                hbone_mtls_port: 15009,
            }),
            services: std::collections::HashMap::from([(
                "/example.com".to_string(),
                PortList {
                    ports: vec![Port {
                        service_port: 80,
                        target_port: 8080,
                    }],
                },
            )]),
            ..Default::default()
        });
        let healthy_local_workload = XdsAddressType::Workload(XdsWorkload {
            uid: "Kubernetes//Pod/default/local-example.com-pod".to_string(),
            addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
            network: "".to_string(),
            tunnel_protocol: xds::istio::workload::TunnelProtocol::Hbone.into(),
            services: std::collections::HashMap::from([(
                "/example.com".to_string(),
                PortList {
                    ports: vec![Port {
                        service_port: 80,
                        target_port: 8080,
                    }],
                },
            )]),
            status: xds::istio::workload::WorkloadStatus::Healthy.into(),
            ..Default::default()
        });
        let unhealthy_local_workload = XdsAddressType::Workload(XdsWorkload {
            uid: "Kubernetes//Pod/default/local-example.com-pod".to_string(),
            addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
            network: "".to_string(),
            tunnel_protocol: xds::istio::workload::TunnelProtocol::Hbone.into(),
            services: std::collections::HashMap::from([(
                "/example.com".to_string(),
                PortList {
                    ports: vec![Port {
                        service_port: 80,
                        target_port: 8080,
                    }],
                },
            )]),
            status: xds::istio::workload::WorkloadStatus::Unhealthy.into(),
            ..Default::default()
        });

        run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            vec![
                service.clone(),
                ew_gateway.clone(),
                remote_workload.clone(),
                healthy_local_workload.clone(),
            ],
            Some(ExpectedRequest {
                protocol: OutboundProtocol::HBONE,
                hbone_destination: "127.0.0.2:8080",
                destination: "127.0.0.2:15008",
            }),
        )
        .await;

        run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            vec![
                service.clone(),
                ew_gateway.clone(),
                remote_workload.clone(),
                unhealthy_local_workload.clone(),
            ],
            Some(ExpectedRequest {
                protocol: OutboundProtocol::DOUBLEHBONE,
                hbone_destination: "example.com:80",
                destination: "10.22.1.1:15009",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_known_dest_remote_node_tcp() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/ns/test-tcp".to_string(),
                name: "test-tcp".to_string(),
                namespace: "ns".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                tunnel_protocol: XdsProtocol::None as i32,
                node: "remote-node".to_string(),
                ..Default::default()
            }),
            Some(ExpectedRequest {
                protocol: OutboundProtocol::TCP,
                hbone_destination: "",
                destination: "127.0.0.2:80",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_known_dest_remote_node_hbone() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/ns/test-tcp".to_string(),
                name: "test-tcp".to_string(),
                namespace: "ns".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                tunnel_protocol: XdsProtocol::Hbone as i32,
                node: "remote-node".to_string(),
                ..Default::default()
            }),
            Some(ExpectedRequest {
                protocol: OutboundProtocol::HBONE,
                hbone_destination: "127.0.0.2:80",
                destination: "127.0.0.2:15008",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_known_dest_local_node_tcp() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/ns/test-tcp".to_string(),
                name: "test-tcp".to_string(),
                namespace: "ns".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                tunnel_protocol: XdsProtocol::None as i32,
                node: "local-node".to_string(),
                ..Default::default()
            }),
            Some(ExpectedRequest {
                protocol: OutboundProtocol::TCP,
                hbone_destination: "",
                destination: "127.0.0.2:80",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_known_dest_local_node_hbone() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/ns/test-tcp".to_string(),
                name: "test-tcp".to_string(),
                namespace: "ns".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                tunnel_protocol: XdsProtocol::Hbone as i32,
                node: "local-node".to_string(),
                ..Default::default()
            }),
            Some(ExpectedRequest {
                protocol: OutboundProtocol::HBONE,
                hbone_destination: "127.0.0.2:80",
                destination: "127.0.0.2:15008",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_source_waypoint() {
        run_build_request(
            "127.0.0.2",
            "127.0.0.1:80",
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/default/my-pod".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                waypoint: Some(xds::istio::workload::GatewayAddress {
                    destination: Some(xds::istio::workload::gateway_address::Destination::Address(
                        XdsNetworkAddress {
                            network: "".to_string(),
                            address: [127, 0, 0, 10].to_vec(),
                        },
                    )),
                    hbone_mtls_port: 15008,
                }),
                ..Default::default()
            }),
            // Even though source has a waypoint, we don't use it
            Some(ExpectedRequest {
                protocol: OutboundProtocol::TCP,
                hbone_destination: "",
                destination: "127.0.0.1:80",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_destination_waypoint() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/default/my-pod".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                waypoint: Some(xds::istio::workload::GatewayAddress {
                    destination: Some(xds::istio::workload::gateway_address::Destination::Address(
                        XdsNetworkAddress {
                            network: "".to_string(),
                            address: [127, 0, 0, 10].to_vec(),
                        },
                    )),
                    hbone_mtls_port: 15008,
                }),
                ..Default::default()
            }),
            // Should use the waypoint
            Some(ExpectedRequest {
                protocol: OutboundProtocol::HBONE,
                hbone_destination: "127.0.0.2:80",
                destination: "127.0.0.10:15008",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_destination_waypoint_mismatch_ip() {
        run_build_request(
            "127.0.0.1",
            "[ff06::c3]:80",
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/default/my-pod".to_string(),
                addresses: vec![
                    Bytes::copy_from_slice(&[127, 0, 0, 2]),
                    Bytes::copy_from_slice(
                        "ff06::c3".parse::<Ipv6Addr>().unwrap().octets().as_slice(),
                    ),
                ],
                waypoint: Some(xds::istio::workload::GatewayAddress {
                    destination: Some(xds::istio::workload::gateway_address::Destination::Address(
                        XdsNetworkAddress {
                            network: "".to_string(),
                            address: [127, 0, 0, 11].to_vec(),
                        },
                    )),
                    hbone_mtls_port: 15008,
                }),
                ..Default::default()
            }),
            // Should use the waypoint
            Some(ExpectedRequest {
                protocol: OutboundProtocol::HBONE,
                hbone_destination: "[ff06::c3]:80",
                destination: "127.0.0.11:15008",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_destination_svc_waypoint() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.3:80",
            XdsAddressType::Service(XdsService {
                addresses: vec![XdsNetworkAddress {
                    network: "".to_string(),
                    address: vec![127, 0, 0, 3],
                }],
                ports: vec![Port {
                    service_port: 80,
                    target_port: 8080,
                }],
                waypoint: Some(xds::istio::workload::GatewayAddress {
                    destination: Some(xds::istio::workload::gateway_address::Destination::Address(
                        XdsNetworkAddress {
                            network: "".to_string(),
                            address: [127, 0, 0, 10].to_vec(),
                        },
                    )),
                    hbone_mtls_port: 15008,
                }),
                ..Default::default()
            }),
            // Should use the waypoint
            Some(ExpectedRequest {
                protocol: OutboundProtocol::HBONE,
                hbone_destination: "127.0.0.3:80",
                destination: "127.0.0.10:15008",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_empty_service() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.3:80",
            XdsAddressType::Service(XdsService {
                addresses: vec![XdsNetworkAddress {
                    network: "".to_string(),
                    address: vec![127, 0, 0, 3],
                }],
                ports: vec![Port {
                    service_port: 80,
                    target_port: 8080,
                }],
                ..Default::default()
            }),
            // Should use the waypoint
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_target_port() {
        run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            vec![
                XdsAddressType::Service(XdsService {
                    hostname: "example.com".to_string(),
                    addresses: vec![XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![127, 0, 0, 3],
                    }],
                    ports: vec![
                        Port {
                            service_port: 80,
                            target_port: 0, // named port
                        },
                        Port {
                            service_port: 8080,
                            target_port: 0, // named port
                        },
                    ],
                    ..Default::default()
                }),
                XdsAddressType::Workload(XdsWorkload {
                    uid: "cluster1//v1/Pod/default/matching-pod".to_string(),
                    addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                    services: std::collections::HashMap::from([(
                        "/example.com".to_string(),
                        PortList {
                            ports: vec![Port {
                                service_port: 80,
                                target_port: 1234,
                            }],
                        },
                    )]),
                    ..Default::default()
                }),
                // This pod does not have a port 80 defined at all
                XdsAddressType::Workload(XdsWorkload {
                    uid: "cluster1//v1/Pod/default/unmatching-pod".to_string(),
                    addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 4])],
                    services: std::collections::HashMap::from([(
                        "/example.com".to_string(),
                        PortList {
                            ports: vec![Port {
                                service_port: 8080,
                                target_port: 9999,
                            }],
                        },
                    )]),
                    ..Default::default()
                }),
            ],
            Some(ExpectedRequest {
                protocol: OutboundProtocol::TCP,
                hbone_destination: "",
                destination: "127.0.0.2:1234",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_host_network() {
        let xds = vec![
            // Normal service
            XdsAddressType::Service(XdsService {
                hostname: "example.com".to_string(),
                addresses: vec![XdsNetworkAddress {
                    network: "".to_string(),
                    address: vec![127, 0, 0, 3],
                }],
                ports: vec![Port {
                    service_port: 80,
                    target_port: 80,
                }],
                ..Default::default()
            }),
            // Workload is host network, so it's going to have the same IP as another workload
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/default/pod1".to_string(),
                name: "pod1".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                services: std::collections::HashMap::from([(
                    "/example.com".to_string(),
                    PortList {
                        ports: vec![Port {
                            service_port: 80,
                            target_port: 80,
                        }],
                    },
                )]),
                network_mode: NetworkMode::HostNetwork as i32,
                ..Default::default()
            }),
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/default/pod2".to_string(),
                name: "pod2".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                network_mode: NetworkMode::HostNetwork as i32,
                ..Default::default()
            }),
        ];
        let res = run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            xds.clone(),
            // Traffic to the service should go to the pod in the service
            Some(ExpectedRequest {
                destination: "127.0.0.2:80",
                protocol: OutboundProtocol::TCP,
                hbone_destination: "",
            }),
        )
        .await
        .expect("must resolve");
        // Ensure it actually went to pod1, not the other pod with the same IP
        assert_eq!(
            res.actual_destination_workload.expect("found a dest").name,
            "pod1"
        );

        // Traffic to the node directly. We should forward the request, but as passthrough, rather than
        // associating it with a random pod.
        let res = run_build_request_multi(
            "127.0.0.1",
            "127.0.0.2:80",
            xds.clone(),
            // Traffic to the service should go to the pod in the service
            Some(ExpectedRequest {
                destination: "127.0.0.2:80",
                protocol: OutboundProtocol::TCP,
                hbone_destination: "",
            }),
        )
        .await
        .expect("must resolve");
        // Ensure it actually went to pod1, not the other pod with the same IP
        assert_eq!(res.actual_destination_workload, None);
    }

    #[tokio::test]
    async fn multiple_address_workload() {
        let workload = XdsAddressType::Workload(XdsWorkload {
            uid: "cluster1//v1/Pod/ns/test-tcp".to_string(),
            name: "test-tcp".to_string(),
            namespace: "ns".to_string(),
            addresses: vec![
                Bytes::copy_from_slice(&[127, 0, 0, 2]),
                Bytes::copy_from_slice("ff06::c3".parse::<Ipv6Addr>().unwrap().octets().as_slice()),
            ],
            tunnel_protocol: XdsProtocol::None as i32,
            node: "remote-node".to_string(),
            ..Default::default()
        });
        // v4 goes go v4
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            workload.clone(),
            Some(ExpectedRequest {
                protocol: OutboundProtocol::TCP,
                hbone_destination: "",
                destination: "127.0.0.2:80",
            }),
        )
        .await;
        // v6 goes go v6
        run_build_request(
            "127.0.0.1",
            "[ff06::c3]:80",
            workload.clone(),
            Some(ExpectedRequest {
                protocol: OutboundProtocol::TCP,
                hbone_destination: "",
                destination: "[ff06::c3]:80",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn service_ip_families() {
        initialize_telemetry();
        let workload = XdsAddressType::Workload(XdsWorkload {
            uid: "cluster1//v1/Pod/default/dual".to_string(),
            addresses: vec![
                Bytes::copy_from_slice(&[127, 0, 0, 2]),
                Bytes::copy_from_slice("ff06::c3".parse::<Ipv6Addr>().unwrap().octets().as_slice()),
            ],
            tunnel_protocol: 1,
            services: std::collections::HashMap::from([(
                "/example.com".to_string(),
                PortList { ports: vec![] },
            )]),
            ..Default::default()
        });
        let svc = |f: IpFamilies| {
            let mut s = XdsService {
                hostname: "example.com".to_string(),
                addresses: vec![
                    XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![127, 0, 0, 3],
                    },
                    XdsNetworkAddress {
                        network: "".to_string(),
                        address: "::3".parse::<Ipv6Addr>().unwrap().octets().into(),
                    },
                ],
                ports: vec![Port {
                    service_port: 80,
                    target_port: 80,
                }],
                ..Default::default()
            };
            s.set_ip_families(f);
            XdsAddressType::Service(s)
        };
        // V6 only should always use V6 IP
        run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            vec![svc(IpFamilies::Ipv6Only), workload.clone()],
            Some(ExpectedRequest {
                protocol: OutboundProtocol::HBONE,
                hbone_destination: "[ff06::c3]:80",
                destination: "[ff06::c3]:15008",
            }),
        )
        .await;
        // V4 only should always use V4 IP
        run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            vec![svc(IpFamilies::Ipv4Only), workload.clone()],
            Some(ExpectedRequest {
                protocol: OutboundProtocol::HBONE,
                hbone_destination: "127.0.0.2:80",
                destination: "127.0.0.2:15008",
            }),
        )
        .await;
        // Dual stack should always prefer the original family (here ipv4)
        run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            vec![svc(IpFamilies::Dual), workload.clone()],
            Some(ExpectedRequest {
                protocol: OutboundProtocol::HBONE,
                hbone_destination: "127.0.0.2:80",
                destination: "127.0.0.2:15008",
            }),
        )
        .await;
        // Dual stack should always prefer the original family (here ipv6)
        run_build_request_multi(
            "::1",
            "[::3]:80",
            vec![svc(IpFamilies::Dual), workload.clone()],
            Some(ExpectedRequest {
                protocol: OutboundProtocol::HBONE,
                hbone_destination: "[ff06::c3]:80",
                destination: "[ff06::c3]:15008",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_passthrough_svc() {
        run_build_request(
            "127.0.0.1",
            "1.2.3.4:80",
            XdsAddressType::Service(XdsService {
                hostname: "example.com".to_string(),
                waypoint: None,
                load_balancing: Some(LoadBalancing {
                    mode: xds::istio::workload::load_balancing::Mode::Passthrough.into(),
                    ..Default::default()
                }),
                addresses: vec![
                    XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![1, 2, 3, 4],
                    },
                    XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![1, 5, 6, 7],
                    },
                ],
                ports: vec![Port {
                    service_port: 80,
                    target_port: 80,
                }],
                ..Default::default()
            }),
            Some(ExpectedRequest {
                protocol: OutboundProtocol::TCP,
                hbone_destination: "",
                destination: "1.2.3.4:80",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_passthrough_svc_with_waypoint() {
        run_build_request(
            "127.0.0.1",
            "1.2.3.4:80",
            XdsAddressType::Service(XdsService {
                hostname: "example.com".to_string(),
                waypoint: Some(xds::istio::workload::GatewayAddress {
                    destination: Some(xds::istio::workload::gateway_address::Destination::Address(
                        XdsNetworkAddress {
                            network: "".to_string(),
                            address: [127, 0, 0, 10].to_vec(),
                        },
                    )),
                    hbone_mtls_port: 15008,
                }),
                load_balancing: Some(LoadBalancing {
                    mode: xds::istio::workload::load_balancing::Mode::Passthrough.into(),
                    ..Default::default()
                }),
                addresses: vec![
                    XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![1, 2, 3, 4],
                    },
                    XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![1, 5, 6, 7],
                    },
                ],
                ports: vec![Port {
                    service_port: 80,
                    target_port: 80,
                }],
                ..Default::default()
            }),
            Some(ExpectedRequest {
                protocol: OutboundProtocol::HBONE,
                destination: "127.0.0.10:15008",
                hbone_destination: "1.2.3.4:80",
            }),
        )
        .await;
    }

    #[test]
    fn build_forwarded() {
        assert_eq!(
            super::build_forwarded("127.0.0.1:80".parse().unwrap(), &None),
            r#"for="127.0.0.1:80""#,
        );
        assert_eq!(
            super::build_forwarded("[::1]:80".parse().unwrap(), &None),
            r#"for="[::1]:80""#,
        );
        assert_eq!(
            super::build_forwarded(
                "127.0.0.1:80".parse().unwrap(),
                &Some(ServiceDescription {
                    hostname: "example.com".into(),
                    name: Default::default(),
                    namespace: Default::default(),
                }),
            ),
            r#"for="127.0.0.1:80";host=example.com"#,
        );
    }

    #[tokio::test]
    async fn test_x_forwarded_network_header() {
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
            hbone_port: cfg.inbound_addr.port(),
        };

        // Get the source workload from state
        let source_workload = outbound
            .pi
            .local_workload_information
            .get_workload()
            .await
            .unwrap();

        // Create a minimal test request with required fields
        let req = Request {
            protocol: OutboundProtocol::HBONE,
            source: source_workload,
            sandbox: None,
            hbone_target_destination: Some(HboneAddress::SocketAddr(
                "10.0.0.1:8080".parse().unwrap(),
            )),
            actual_destination_workload: None,
            intended_destination_service: None,
            actual_destination: "10.0.0.1:8080".parse().unwrap(),
            upstream_sans: vec![],
            final_sans: vec![],
        };

        let remote_addr = "127.0.0.1:12345".parse().unwrap();

        // Test the single HBONE case - header should NOT be added when origin_network is None
        let http_request_no_header = outbound.create_hbone_request(remote_addr, &req, None).await;
        assert!(
            http_request_no_header
                .headers()
                .get(X_FORWARDED_NETWORK_HEADER)
                .is_none(),
            "x-istio-origin-network header should not be present when origin_network is None (single HBONE)"
        );

        // Test the double HBONE inner request case - header should be added when network is specified
        let network = crate::strng::Strng::from("test-network");
        let http_request_with_header = outbound
            .create_hbone_request(remote_addr, &req, Some(&network))
            .await;
        assert_eq!(
            http_request_with_header
                .headers()
                .get(X_FORWARDED_NETWORK_HEADER)
                .unwrap(),
            "test-network",
            "x-istio-origin-network header should contain the network name for double HBONE inner request"
        );
        // Both CONNECT forms carry pod identity without a sandbox manager.
        // The pod name must win over the owning deployment's workload_name.
        for request in [&http_request_no_header, &http_request_with_header] {
            assert_eq!(request.headers()[WORKLOAD_NAME_HEADER], "source-workload");
            assert_eq!(request.headers()[WORKLOAD_NAMESPACE_HEADER], "ns");
        }
    }

    #[derive(PartialEq, Debug)]
    struct ExpectedRequest<'a> {
        protocol: OutboundProtocol,
        hbone_destination: &'a str,
        destination: &'a str,
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
        let mut manager = sandbox::SandboxManager::new(state.clone());
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
            hbone_port: cfg.inbound_addr.port(),
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
        for mode in [Default::default(), MeshInternalPassthrough] {
            let workload = Arc::new(Workload {
                mesh_internal_traffic_policy: mode,
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
                outbound
                    .build_request(workload.clone(), None, target.ip(), target)
                    .await,
                Err(Error::EgressPolicyDenied(_))
            ));
            for selected in &sandboxes {
                let request = outbound
                    .build_request(
                        workload.clone(),
                        Some(selected.clone()),
                        target.ip(),
                        target,
                    )
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
                    let hbone = outbound.create_hbone_request(target, &request, None).await;
                    assert_eq!(hbone.headers()[sandbox::SANDBOX_ID_HEADER], "sandbox-a");
                } else {
                    assert_eq!(request.protocol, OutboundProtocol::TCP);
                    assert_eq!(request.actual_destination, target);
                }
            }
        }
        // A selected but unavailable gateway fails the request without direct fallback.
        routes.routes[0].gateway.as_mut().unwrap().service = "missing.ns".into();
        publish_routing("sandbox-a", routes);
        let selected = manager.fetch_attested_sandbox(&fixture.workload);
        assert!(matches!(
            outbound
                .build_request(fixture.workload.clone(), selected, target.ip(), target)
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
            hbone_target_destination: Some(HboneAddress::SocketAddr(
                "10.0.0.1:443".parse().unwrap(),
            )),
            actual_destination_workload: None,
            intended_destination_service: None,
            actual_destination: "10.0.0.1:443".parse().unwrap(),
            upstream_sans: vec![],
            final_sans: vec![],
        };
        let source = "127.0.0.1:12345".parse().unwrap();
        let before = outbound.create_hbone_request(source, &request, None).await;
        assert!(!before.headers().contains_key(sandbox::SANDBOX_ID_HEADER));
        assert_eq!(
            before.headers()[sandbox::SANDBOX_TOKEN_HEADER],
            "Y29ycmVjdC10b2tlbg=="
        );
        fixture.publish("sandbox-a");
        request.sandbox = manager.fetch_attested_sandbox(&request.source);
        let discovered = outbound.create_hbone_request(source, &request, None).await;
        assert_eq!(
            discovered.headers()[sandbox::SANDBOX_ID_HEADER],
            "sandbox-a"
        );
        let captured_a = manager.fetch_attested_sandbox(&request.source).unwrap();
        request.sandbox = Some(captured_a.clone());
        for network in [None, Some(&cfg.network)] {
            let hbone = outbound
                .create_hbone_request(source, &request, network)
                .await;
            assert_eq!(hbone.headers()[sandbox::SANDBOX_ID_HEADER], "sandbox-a");
            assert_eq!(
                hbone.headers()[sandbox::SANDBOX_TOKEN_HEADER],
                "Y29ycmVjdC10b2tlbg=="
            );
        }
        fixture.publish("sandbox-b");
        assert_eq!(
            manager
                .fetch_attested_sandbox(&request.source)
                .map(|sandbox| sandbox.uid.clone())
                .unwrap(),
            captured_a.uid
        );
        // Each request carries its selected identity while token loading stays independent.
        for id in ["sandbox-a", "sandbox-b"] {
            for network in [None, Some(&cfg.network)] {
                request.sandbox = fixture
                    .state
                    .read()
                    .unwrap()
                    .sandboxes
                    .get_by_workload(&request.source.uid)
                    .into_iter()
                    .find(|sandbox| sandbox.uid == id);
                let hbone = outbound
                    .create_hbone_request(source, &request, network)
                    .await;
                assert_eq!(hbone.headers()[sandbox::SANDBOX_ID_HEADER], id);
                assert_eq!(
                    hbone.headers()[sandbox::SANDBOX_TOKEN_HEADER],
                    "Y29ycmVjdC10b2tlbg=="
                );
            }
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
        request.sandbox = manager.fetch_attested_sandbox(&request.source);
        let foreign_request = outbound.create_hbone_request(source, &request, None).await;
        assert!(
            !foreign_request
                .headers()
                .contains_key(sandbox::SANDBOX_ID_HEADER)
        );
        assert!(manager.fetch_attested_sandbox(&request.source).is_none());
        request.source = fixture.workload.clone();
        request.sandbox = Some(captured_a.clone());
        fixture
            .state
            .write()
            .unwrap()
            .sandboxes
            .remove(&"sandbox-a".into());
        // An already-started connection keeps its captured label, including the
        // inner CONNECT created after a Sandbox update. No revalidation blocks it.
        let inner = outbound
            .create_hbone_request(source, &request, Some(&cfg.network))
            .await;
        assert_eq!(inner.headers()[sandbox::SANDBOX_ID_HEADER], "sandbox-a");
        let current = manager.fetch_attested_sandbox(&request.source).unwrap();
        assert_eq!(current.uid, "sandbox-b");
        request.sandbox = Some(current);
        let next = outbound.create_hbone_request(source, &request, None).await;
        assert_eq!(next.headers()[sandbox::SANDBOX_ID_HEADER], "sandbox-b");
        fixture
            .state
            .write()
            .unwrap()
            .sandboxes
            .remove(&"sandbox-b".into());
        // Removing the last binding leaves new connections without a Sandbox label.
        assert!(manager.fetch_attested_sandbox(&request.source).is_none());
        request.sandbox = manager.fetch_attested_sandbox(&request.source);
        let unlabeled = outbound.create_hbone_request(source, &request, None).await;
        assert!(!unlabeled.headers().contains_key(sandbox::SANDBOX_ID_HEADER));
    }

    #[tokio::test]
    async fn sandbox_policy_updates_recheck_tcp_without_lifecycle_drain() {
        use crate::sandbox::discovery::tests::Fixture;
        use crate::state::DemandProxyState;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let fixture = Fixture::new();
        fixture
            .state
            .write()
            .unwrap()
            .workloads
            .insert(Arc::new(Workload {
                mesh_internal_traffic_policy: MeshInternalPassthrough,
                ..(*fixture.workload).clone()
            }));
        fixture.publish("sandbox-a");
        let manager = Arc::new(fixture.manager);
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
                sandbox_manager: Some(manager.clone()),
                firewall_metrics: None,
            }),
            id: TraceParent::new(),
            pool: WorkloadHBONEPool::new(cfg.clone(), sockets, local),
            hbone_port: cfg.inbound_addr.port(),
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
                    hbone_port: cfg.inbound_addr.port(),
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
                hbone_port: cfg.inbound_addr.port(),
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
