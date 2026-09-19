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

use crate::proxy::Error;

use crate::state::DemandProxyState;
use crate::state::ProxyRbacContext;
use serde::{Serialize, Serializer};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt::Formatter;
use std::net::SocketAddr;

use crate::drain;
use crate::drain::{DrainTrigger, DrainWatcher};
use crate::state::workload::{InboundProtocol, OutboundProtocol};
use std::sync::Arc;
use std::sync::RwLock;
use tracing::{debug, error, info, warn};

struct ConnectionDrain {
    // TODO: this should almost certainly be changed to a type which has counted references exposed.
    // tokio::sync::watch can be subscribed without taking a write lock and exposes references
    // and also a receiver_count method
    tx: DrainTrigger,
    rx: DrainWatcher,
    count: usize,
}

impl ConnectionDrain {
    fn new() -> Self {
        let (tx, rx) = drain::new();
        ConnectionDrain { tx, rx, count: 1 }
    }

    /// drain drops the internal reference to rx and then signals drain on the tx
    // always inline, this is for convenience so that we don't forget to drop the rx but there's really no reason it needs to grow the stack
    #[inline(always)]
    async fn drain(self) {
        drop(self.rx); // very important, drain cannot complete if there are outstand rx
        self.tx
            .start_drain_and_wait(drain::DrainMode::Immediate)
            .await;
    }
}

#[derive(Clone)]
pub struct ConnectionManager {
    drains: Arc<RwLock<HashMap<ConnectionContext, ConnectionDrain>>>,
}

impl std::fmt::Debug for ConnectionManager {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionManager").finish()
    }
}

impl Default for ConnectionManager {
    fn default() -> Self {
        ConnectionManager {
            drains: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

pub struct ConnectionGuard {
    cm: ConnectionManager,
    conn: ConnectionContext,
    watch: Option<DrainWatcher>,
}

// For reasons that I don't fully understand, this uses an obscene amount of stack space when written as a normal function,
// amounting to ~1kb overhead per connection.
// Inlining it removes this entirely, and the macro ensures we do it consistently across the various areas we use it.
#[macro_export]
macro_rules! handle_connection {
    ($connguard:expr, $future:expr) => {{
        let watch = $connguard.watcher();
        tokio::select! {
            res = $future => {
                $connguard.release();
                res
            }
            _signaled = watch.wait_for_drain() => Err(Error::AuthorizationPolicyLateRejection)
        }
    }};
}

impl ConnectionGuard {
    pub fn watcher(&mut self) -> drain::DrainWatcher {
        self.watch.take().expect("watch cannot be taken twice")
    }
    pub fn release(self) {
        self.cm.release(&self.conn);
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if self.watch.is_some() {
            debug!("rbac context {:?} auto-dropped", &self.conn);
            self.cm.release(&self.conn)
        }
    }
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboundAttributes {
    pub actual_dst: SocketAddr,
    pub protocol: OutboundProtocol,
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionDump {
    pub src: SocketAddr,
    pub original_dst: Option<String>,
    pub actual_dst: SocketAddr,
    pub protocol: InboundProtocol,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InboundAttributes {
    pub dest_service: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, serde::Serialize)]
pub enum ConnectionAttributes {
    Inbound(InboundAttributes),
    Outbound(OutboundAttributes),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, serde::Serialize)]
pub struct ConnectionContext {
    #[serde(flatten)]
    pub rbac_ctx: ProxyRbacContext,
    pub attributes: ConnectionAttributes,
}

impl ConnectionManager {
    pub async fn assert_rbac(
        &self,
        state: &DemandProxyState,
        ctx: ConnectionContext,
    ) -> Result<ConnectionGuard, Error> {
        // Register before our initial assert. This prevents a race if policy changes between assert() and
        // track()
        let Some(watch) = self.register(&ctx) else {
            warn!("failed to track {ctx:?}");
            debug_assert!(false, "failed to track {ctx:?}");
            return Err(Error::ConnectionTrackingFailed);
        };

        if let Err(err) = state.assert_rbac(&ctx.rbac_ctx).await {
            self.release(&ctx);
            return Err(Error::AuthorizationPolicyRejection(err));
        }
        Ok(ConnectionGuard {
            cm: self.clone(),
            conn: ctx,
            watch: Some(watch),
        })
    }
    // register a connection with the connection manager
    // this must be done before a connection can be tracked
    // allows policy to be asserted against the connection
    // even no tasks have a receiver channel yet
    fn register(&self, c: &ConnectionContext) -> Option<DrainWatcher> {
        match self.drains.write().expect("mutex").entry(c.clone()) {
            Entry::Occupied(mut cd) => {
                cd.get_mut().count += 1;
                let rx = cd.get().rx.clone();
                Some(rx)
            }
            Entry::Vacant(entry) => {
                let drain = ConnectionDrain::new();
                let rx = drain.rx.clone();
                entry.insert(drain);
                Some(rx)
            }
        }
    }

    // releases tracking on a connection
    // uses a counter to determine if there are other tracked connections or not so it may retain the tx/rx channels when necessary
    pub fn release(&self, c: &ConnectionContext) {
        let mut drains = self.drains.write().expect("mutex");
        if let Some((k, mut v)) = drains.remove_entry(c)
            && v.count > 1
        {
            // something else is tracking this connection, decrement count but retain
            v.count -= 1;
            drains.insert(k, v);
        }
    }

    // signal all connections listening to this channel to take action (typically terminate traffic)
    async fn close(&self, c: &ConnectionContext) {
        let drain = { self.drains.write().expect("mutex").remove(c) };
        if let Some(cd) = drain {
            cd.drain().await;
        } else {
            // this is bad, possibly drain called twice
            error!("requested drain on a Connection which wasn't initialized");
        }
    }

    //  get a list of all connections being tracked
    pub fn connections(&self) -> Vec<ConnectionContext> {
        // potentially large copy under read lock, could require optimization
        self.drains.read().expect("mutex").keys().cloned().collect()
    }
}

#[derive(serde::Serialize)]
struct ConnectionManagerDump {
    inbound: Vec<ConnectionDump>,
    outbound: Vec<ConnectionDump>,
}

impl Serialize for ConnectionManager {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let inbound: Vec<_> = self
            .drains
            .read()
            .expect("mutex")
            .keys()
            .cloned()
            .filter_map(|c| {
                let ConnectionAttributes::Inbound(inbound_conn) = &c.attributes else {
                    return None;
                };
                Some(ConnectionDump {
                    src: c.rbac_ctx.conn.src,
                    original_dst: inbound_conn.dest_service.clone(),
                    actual_dst: c.rbac_ctx.conn.dst,
                    protocol: if c.rbac_ctx.conn.src_identity.is_some() {
                        InboundProtocol::HBONE
                    } else {
                        InboundProtocol::TCP
                    },
                })
            })
            .collect();
        let outbound: Vec<_> = self
            .drains
            .read()
            .expect("mutex")
            .keys()
            .cloned()
            .filter_map(|c| {
                let ConnectionAttributes::Outbound(outbound_conn) = &c.attributes else {
                    return None;
                };
                Some(ConnectionDump {
                    src: c.rbac_ctx.conn.src,
                    original_dst: Some(outbound_conn.actual_dst.to_string()),
                    actual_dst: c.rbac_ctx.conn.dst,
                    protocol: if c.rbac_ctx.conn.src_identity.is_some() {
                        InboundProtocol::HBONE
                    } else {
                        InboundProtocol::TCP
                    },
                })
            })
            .collect();
        let dump = ConnectionManagerDump { inbound, outbound };
        dump.serialize(serializer)
    }
}

pub struct PolicyWatcher {
    state: DemandProxyState,
    stop: DrainWatcher,
    connection_manager: ConnectionManager,
}

impl PolicyWatcher {
    pub fn new(
        state: DemandProxyState,
        stop: DrainWatcher,
        connection_manager: ConnectionManager,
    ) -> Self {
        PolicyWatcher {
            state,
            stop,
            connection_manager,
        }
    }

    pub async fn run(self) {
        let mut policies_changed = self.state.read().policies.subscribe();
        loop {
            tokio::select! {
                _ = self.stop.clone().wait_for_drain() => {
                    break;
                }
                _ = policies_changed.changed() => {
                    let connections = self.connection_manager.connections();
                    for conn in connections {
                        if self.state.assert_rbac(&conn.rbac_ctx).await.is_err() {
                            self.connection_manager.close(&conn).await;
                            info!("connection {:?} closed because it's no longer allowed after a policy update", conn);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::drain;
    use crate::drain::DrainWatcher;
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use prometheus_client::registry::Registry;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::{Arc, RwLock};
    use std::time::Duration;

    use crate::rbac::Connection;
    use crate::state::{DemandProxyState, ProxyState};
    use crate::test_helpers::test_default_workload;
    use crate::xds::agentio::security::{TrafficPolicy, traffic_policy};
    use crate::xds::{Handler, ProxyStateUpdater, XdsResource, XdsUpdate};

    use super::{
        ConnectionAttributes, ConnectionContext, ConnectionGuard, ConnectionManager,
        InboundAttributes, PolicyWatcher,
    };

    #[tokio::test]
    async fn test_connection_manager_close() {
        // setup a new ConnectionManager
        let cm = ConnectionManager::default();
        // ensure drains is empty
        assert_eq!(cm.drains.read().unwrap().len(), 0);
        assert_eq!(cm.connections().len(), 0);

        let register = |cm: &ConnectionManager, c: &ConnectionContext| {
            let cm = cm.clone();
            let c = c.clone();

            let watch = cm.register(&c).unwrap();
            ConnectionGuard {
                cm,
                conn: c,
                watch: Some(watch),
            }
        };

        // track a new connection
        let rbac_ctx1 = ConnectionContext {
            rbac_ctx: crate::state::ProxyRbacContext {
                sandbox: None,
                conn: Connection {
                    src_identity: None,
                    src: std::net::SocketAddr::new(
                        std::net::Ipv4Addr::new(192, 168, 0, 1).into(),
                        80,
                    ),
                    dst_network: "".into(),
                    dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(192, 168, 0, 2),
                        8080,
                    )),
                    direction: crate::rbac::Direction::Inbound,
                },
                workload: Arc::new(test_default_workload()),
            },
            attributes: ConnectionAttributes::Inbound(InboundAttributes { dest_service: None }),
        };

        // ensure drains contains exactly 1 item
        let mut close1 = register(&cm, &rbac_ctx1);
        assert_eq!(cm.drains.read().unwrap().len(), 1);
        assert_eq!(cm.connections().len(), 1);
        assert_eq!(cm.connections(), vec!(rbac_ctx1.clone()));

        // setup a second track on the same connection
        let mut another_close1 = register(&cm, &rbac_ctx1);

        // ensure drains contains exactly 1 item
        assert_eq!(cm.drains.read().unwrap().len(), 1);
        assert_eq!(cm.connections().len(), 1);
        assert_eq!(cm.connections(), vec!(rbac_ctx1.clone()));

        // track a second connection
        let rbac_ctx2 = ConnectionContext {
            rbac_ctx: crate::state::ProxyRbacContext {
                sandbox: None,
                conn: Connection {
                    src_identity: None,
                    src: std::net::SocketAddr::new(
                        std::net::Ipv4Addr::new(192, 168, 0, 3).into(),
                        80,
                    ),
                    dst_network: "".into(),
                    dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(192, 168, 0, 2),
                        8080,
                    )),
                    direction: crate::rbac::Direction::Inbound,
                },
                workload: Arc::new(test_default_workload()),
            },
            attributes: ConnectionAttributes::Inbound(InboundAttributes { dest_service: None }),
        };

        let mut close2 = register(&cm, &rbac_ctx2);
        // ensure drains contains exactly 2 items
        assert_eq!(cm.drains.read().unwrap().len(), 2);
        assert_eq!(cm.connections().len(), 2);
        let mut connections = cm.connections();
        // ordering cannot be guaranteed without sorting
        connections.sort_by(|a, b| a.rbac_ctx.conn.cmp(&b.rbac_ctx.conn));
        assert_eq!(connections, vec![rbac_ctx1.clone(), rbac_ctx2.clone()]);

        // spawn tasks to assert that we close in a timely manner for rbac_ctx1
        tokio::spawn(assert_close(close1.watch.take().unwrap()));
        tokio::spawn(assert_close(another_close1.watch.take().unwrap()));
        // close rbac_ctx1
        cm.close(&rbac_ctx1).await;
        // ensure drains contains exactly 1 item
        assert_eq!(cm.drains.read().unwrap().len(), 1);
        assert_eq!(cm.connections().len(), 1);
        assert_eq!(cm.connections(), vec!(rbac_ctx2.clone()));

        // spawn a task to assert that we close in a timely manner for rbac_ctx2
        tokio::spawn(assert_close(close2.watch.take().unwrap()));
        // close rbac_ctx2
        cm.close(&rbac_ctx2).await;
        // assert that drains is empty again
        assert_eq!(cm.drains.read().unwrap().len(), 0);
        assert_eq!(cm.connections().len(), 0);
    }

    #[tokio::test]
    async fn test_connection_manager_release() {
        // setup a new ConnectionManager
        let cm = ConnectionManager::default();
        // ensure drains is empty
        assert_eq!(cm.drains.read().unwrap().len(), 0);
        assert_eq!(cm.connections().len(), 0);

        let register = |cm: &ConnectionManager, c: &ConnectionContext| {
            let cm = cm.clone();
            let c = c.clone();

            let watch = cm.register(&c).unwrap();
            ConnectionGuard {
                cm,
                conn: c,
                watch: Some(watch),
            }
        };

        // create a new connection
        let conn1 = ConnectionContext {
            rbac_ctx: crate::state::ProxyRbacContext {
                sandbox: None,
                conn: Connection {
                    src_identity: None,
                    src: std::net::SocketAddr::new(
                        std::net::Ipv4Addr::new(192, 168, 0, 1).into(),
                        80,
                    ),
                    dst_network: "".into(),
                    dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(192, 168, 0, 2),
                        8080,
                    )),
                    direction: crate::rbac::Direction::Inbound,
                },
                workload: Arc::new(test_default_workload()),
            },
            attributes: ConnectionAttributes::Inbound(InboundAttributes { dest_service: None }),
        };

        // create a second connection
        let conn2 = ConnectionContext {
            rbac_ctx: crate::state::ProxyRbacContext {
                sandbox: None,
                conn: Connection {
                    src_identity: None,
                    src: std::net::SocketAddr::new(
                        std::net::Ipv4Addr::new(192, 168, 0, 3).into(),
                        80,
                    ),
                    dst_network: "".into(),
                    dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(192, 168, 0, 2),
                        8080,
                    )),
                    direction: crate::rbac::Direction::Inbound,
                },
                workload: Arc::new(test_default_workload()),
            },
            attributes: ConnectionAttributes::Inbound(InboundAttributes { dest_service: None }),
        };
        let another_conn1 = conn1.clone();

        let close1 = register(&cm, &conn1);
        let another_close1 = register(&cm, &another_conn1);

        // ensure drains contains exactly 1 item
        assert_eq!(cm.drains.read().unwrap().len(), 1);
        assert_eq!(cm.connections().len(), 1);
        assert_eq!(cm.connections(), vec!(conn1.clone()));

        // release conn1's clone
        drop(another_close1);
        // ensure drains still contains exactly 1 item
        assert_eq!(cm.drains.read().unwrap().len(), 1);
        assert_eq!(cm.connections().len(), 1);
        assert_eq!(cm.connections(), vec!(conn1.clone()));

        let close2 = register(&cm, &conn2);
        // ensure drains contains exactly 2 items
        assert_eq!(cm.drains.read().unwrap().len(), 2);
        assert_eq!(cm.connections().len(), 2);
        let mut connections = cm.connections();
        // ordering cannot be guaranteed without sorting
        connections.sort_by(|a, b| a.rbac_ctx.conn.cmp(&b.rbac_ctx.conn));
        assert_eq!(connections, vec![conn1.clone(), conn2.clone()]);

        // release conn1
        drop(close1);
        // ensure drains contains exactly 1 item
        assert_eq!(cm.drains.read().unwrap().len(), 1);
        assert_eq!(cm.connections().len(), 1);
        assert_eq!(cm.connections(), vec!(conn2.clone()));

        // clone conn2 and track it
        let another_conn2 = conn2.clone();
        let another_close2 = register(&cm, &another_conn2);
        // release tracking on conn2
        drop(close2);
        // ensure drains still contains exactly 1 item
        assert_eq!(cm.drains.read().unwrap().len(), 1);
        assert_eq!(cm.connections().len(), 1);
        assert_eq!(cm.connections(), vec!(another_conn2.clone()));

        // release tracking on conn2's clone
        drop(another_close2);
        // ensure drains contains exactly 0 items
        assert_eq!(cm.drains.read().unwrap().len(), 0);
        assert_eq!(cm.connections().len(), 0);
    }

    #[tokio::test]
    async fn test_policy_watcher_lifecycle() {
        let policy_name = "trafficPolicies/test";
        let state = Arc::new(RwLock::new(ProxyState::new(None)));
        let workload = Arc::new(crate::state::workload::Workload {
            uid: "workload".into(),
            ..test_default_workload()
        });
        state.write().unwrap().workloads.insert(workload.clone());
        let updater = ProxyStateUpdater::new_no_fetch(state.clone());
        updater
            .handle(Box::new(&mut std::iter::once(XdsUpdate::Update(
                XdsResource {
                    name: "sandbox".into(),
                    resource: crate::xds::agentio::sandbox::Sandbox {
                        uid: "sandbox".into(),
                        attester: Some(crate::xds::agentio::sandbox::sandbox::Attester {
                            workload_uid: workload.uid.to_string(),
                        }),
                        ..Default::default()
                    },
                },
            ))))
            .unwrap();
        {
            let mut current = state.write().unwrap();
            let mut bound = (*workload).clone();
            bound.traffic_policy_refs = Some(vec![policy_name.into()]);
            current.workloads.insert(Arc::new(bound));
        }
        let publish = |rules| {
            updater
                .handle(Box::new(&mut std::iter::once(XdsUpdate::Update(
                    XdsResource {
                        name: policy_name.into(),
                        resource: TrafficPolicy {
                            ingress: Some(traffic_policy::RuleSet { rules }),
                            egress: None,
                        },
                    },
                ))))
                .unwrap();
        };
        publish(vec![traffic_policy::Rule {
            action: traffic_policy::Action::Allow.into(),
            r#match: Some(traffic_policy::Match::default()),
        }]);
        let mut registry = Registry::default();
        let metrics = Arc::new(crate::proxy::Metrics::new(&mut registry));
        let dstate = DemandProxyState::new(
            state.clone(),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
            metrics,
        );
        let connection_manager = ConnectionManager::default();
        let (tx, stop) = drain::new();
        let watcher = PolicyWatcher::new(dstate.clone(), stop, connection_manager.clone());
        // Start the subscription before publishing the policy change.
        let mut watching = Box::pin(watcher.run());
        assert!(futures_util::poll!(&mut watching).is_pending());
        let watcher_task = tokio::spawn(watching);

        let conn = ConnectionContext {
            rbac_ctx: crate::state::ProxyRbacContext {
                sandbox: None,
                conn: Connection {
                    src_identity: None,
                    src: "192.168.0.1:80".parse().unwrap(),
                    dst_network: "".into(),
                    dst: "192.168.0.2:8080".parse().unwrap(),
                    direction: crate::rbac::Direction::Inbound,
                },
                workload,
            },
            attributes: ConnectionAttributes::Inbound(InboundAttributes { dest_service: None }),
        };
        let mut connection = connection_manager.assert_rbac(&dstate, conn).await.unwrap();
        let close = connection.watch.take().unwrap();

        // An explicitly empty ingress denies the previously allowed connection.
        publish(vec![]);
        assert_close(close).await;
        drop(connection);
        tx.start_drain_and_wait(drain::DrainMode::Immediate).await;
        tokio::time::timeout(Duration::from_secs(1), watcher_task)
            .await
            .unwrap()
            .unwrap();
    }

    // small helper to assert that the Watches are working in a timely manner
    async fn assert_close(c: DrainWatcher) {
        let result = tokio::time::timeout(Duration::from_secs(1), c.wait_for_drain()).await;
        assert!(result.is_ok())
    }
}
