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

use std::collections::{BTreeMap, HashMap};
use std::error::Error as StdErr;
use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use tracing::Level;

use tokio::sync::mpsc;
#[cfg(any(test, feature = "testing"))]
use tracing::error;
use tracing::{debug, info, instrument, trace, warn};

pub use client::*;
pub use metrics::*;
pub use types::*;
use xds::istio::workload::Address as XdsAddress;
use xds::istio::workload::PortList;
use xds::istio::workload::Service as XdsService;
use xds::istio::workload::Workload as XdsWorkload;
use xds::istio::workload::address::Type as XdsType;

use crate::cert_fetcher::{CertFetcher, NoCertFetcher};
use crate::config::ConfigSource;
use crate::sandbox::discovery::Sandbox;
use crate::sandbox::traffic_policy::TrafficPolicy;
use crate::state::ProxyState;
use crate::state::service::{Endpoint, Service, ServiceStore};
use crate::state::workload::{NamespacedHostname, Workload};
use crate::strng;
use crate::strng::Strng;
use crate::{tls, xds};

use self::service::discovery::v3::DeltaDiscoveryRequest;

mod client;
pub mod metrics;
mod types;

struct DisplayStatus<'a>(&'a tonic::Status);

impl fmt::Display for DisplayStatus<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let s = &self.0;
        write!(f, "status: {:?}, message: {:?}", s.code(), s.message())?;

        if s.message().to_string().contains("authentication failure") {
            write!(
                f,
                " (hint: check the control plane logs for more information)"
            )?;
        }
        if !s.details().is_empty()
            && let Ok(st) = std::str::from_utf8(s.details())
        {
            write!(f, ", details: {st}")?;
        }
        if let Some(src) = s.source().and_then(|s| s.source()) {
            write!(f, ", source: {src}")?;
            // Error is not public to explicitly match on, so do a fuzzy match
            if format!("{src}").contains("Temporary failure in name resolution") {
                write!(f, " (hint: is the DNS server reachable?)")?;
            }
        }
        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("gRPC error {}", DisplayStatus(.0))]
    GrpcStatus(#[from] tonic::Status),
    #[error("gRPC connection error connecting to {}: {}", .0, DisplayStatus(.1))]
    Connection(String, #[source] tonic::Status),
    /// Attempted to send on a MPSC channel which has been canceled
    #[error(transparent)]
    RequestFailure(#[from] Box<mpsc::error::SendError<DeltaDiscoveryRequest>>),
    #[error("failed to send on demand resource")]
    OnDemandSend(),
    #[error("TLS Error: {0}")]
    TLSError(#[from] tls::Error),
}

/// Updates the [ProxyState] from XDS.
/// All state updates code goes in ProxyStateUpdateMutator, that takes state as a parameter.
/// this guarantees that the state is always locked when it is updated.
#[derive(Clone)]
pub struct ProxyStateUpdateMutator {
    cert_fetcher: Arc<dyn CertFetcher>,
}

#[derive(Clone)]
pub struct ProxyStateUpdater {
    state: Arc<RwLock<ProxyState>>,
    updater: ProxyStateUpdateMutator,
}

impl ProxyStateUpdater {
    /// Creates a new updater for the given stores. Will prefetch certs when workloads are updated.
    pub fn new(state: Arc<RwLock<ProxyState>>, cert_fetcher: Arc<dyn CertFetcher>) -> Self {
        Self {
            state,
            updater: ProxyStateUpdateMutator { cert_fetcher },
        }
    }
    /// Creates a new updater that does not prefetch workload certs.
    pub fn new_no_fetch(state: Arc<RwLock<ProxyState>>) -> Self {
        Self {
            state,
            updater: ProxyStateUpdateMutator::new_no_fetch(),
        }
    }
}

impl ProxyStateUpdateMutator {
    /// Creates a new updater that does not prefetch workload certs.
    pub fn new_no_fetch() -> Self {
        ProxyStateUpdateMutator {
            cert_fetcher: Arc::new(NoCertFetcher()),
        }
    }

    #[instrument(
        level = Level::TRACE,
        name="insert_workload",
        skip_all,
        fields(uid=%w.uid),
    )]
    pub fn insert_workload(&self, state: &mut ProxyState, w: XdsWorkload) -> anyhow::Result<()> {
        debug!("handling insert");

        // Clone services, so we can pass full ownership of the rest of XdsWorkload to build our Workload
        // object, which doesn't include Services.
        // In theory, I think we could avoid this if Workload::try_from returning the services.
        // let services = w.services.clone();
        // Convert the workload.
        let (workload, services): (Workload, HashMap<String, PortList>) = w.try_into()?;
        let workload = Arc::new(workload);

        // First, remove the entry entirely to make sure things are cleaned up properly.
        self.remove_workload_for_insert(state, &workload.uid);

        // Prefetch the cert for the workload.
        self.cert_fetcher.prefetch_cert(&workload);

        // Lock and upstate the stores.
        state.workloads.insert(workload.clone());
        insert_service_endpoints(&workload, &services, &mut state.services)?;

        Ok(())
    }

    pub fn remove(&self, state: &mut ProxyState, xds_name: &Strng) {
        self.remove_internal(state, xds_name, false);
    }

    fn remove_workload_for_insert(&self, state: &mut ProxyState, xds_name: &Strng) {
        self.remove_internal(state, xds_name, true);
    }

    #[instrument(
        level = Level::TRACE,
        name="remove",
        skip_all,
        fields(name=%xds_name, for_workload_insert=%for_workload_insert),
    )]
    fn remove_internal(&self, state: &mut ProxyState, xds_name: &Strng, for_workload_insert: bool) {
        // remove workload by UID; if xds_name is a service then this will no-op
        if let Some(prev) = state.workloads.remove(&strng::new(xds_name)) {
            // Also remove service endpoints for the workload.
            state.services.remove_endpoint(&prev);

            // This is a real removal (not a removal before insertion), and nothing else references the cert
            // Clear it out
            if !for_workload_insert
                && state
                    .workloads
                    .was_last_identity_on_node(&prev.node, &prev.identity())
            {
                self.cert_fetcher.clear_cert(&prev.identity());
            }
            // We removed a workload, no reason to attempt to remove a service with the same name
            return;
        }
        if for_workload_insert {
            // This is a workload, don't attempt to remove as a service
            return;
        }

        let Ok(name) = NamespacedHostname::from_str(xds_name) else {
            // we don't have namespace/hostname xds primary key for service
            warn!(
                "tried to remove service but it did not have the expected namespace/hostname format"
            );
            return;
        };

        if name.hostname.contains('/') {
            // avoid trying to delete obvious workload UIDs as a service,
            // which can result in noisy logs when new workloads are added
            // (we remove then add workloads on initial update)
            //
            // we can make this assumption because namespaces and hostnames cannot have `/` in them
            trace!("not a service, not attempting to delete as such",);
            return;
        }
        if !state.services.remove(&name) {
            warn!("tried to remove service, but it was not found");
        }
    }

    pub fn insert_address(&self, state: &mut ProxyState, a: XdsAddress) -> anyhow::Result<()> {
        match a.r#type {
            Some(XdsType::Workload(w)) => self.insert_workload(state, w),
            Some(XdsType::Service(s)) => self.insert_service(state, s),
            _ => Err(anyhow::anyhow!("unknown address type")),
        }
    }

    #[instrument(
        level = Level::TRACE,
        name="insert_service",
        skip_all,
        fields(name=%service.name),
    )]
    pub fn insert_service(
        &self,
        state: &mut ProxyState,
        service: XdsService,
    ) -> anyhow::Result<()> {
        debug!("handling insert");
        let mut service = Service::try_from(&service)?;

        // If the service already exists, add existing endpoints into the new service.
        if let Some(prev) = state
            .services
            .get_by_namespaced_host(&service.namespaced_hostname())
        {
            for ep in prev.endpoints.iter() {
                if service.should_include_endpoint(ep.status) {
                    service
                        .endpoints
                        .insert(ep.workload_uid.clone(), ep.clone());
                }
            }
        }

        state.services.insert(service);
        Ok(())
    }
}

impl Handler<XdsWorkload> for ProxyStateUpdater {
    fn handle(
        &self,
        updates: Box<&mut dyn Iterator<Item = XdsUpdate<XdsWorkload>>>,
    ) -> Result<(), Vec<RejectedConfig>> {
        // use deepsize::DeepSizeOf;
        let mut state = self.state.write().unwrap();
        let handle = |res: XdsUpdate<XdsWorkload>| {
            match res {
                XdsUpdate::Update(w) => self.updater.insert_workload(&mut state, w.resource)?,
                XdsUpdate::Remove(name) => {
                    debug!("handling delete {}", name);
                    self.updater.remove(&mut state, &strng::new(name))
                }
            }
            Ok(())
        };
        handle_single_resource(updates, handle)
    }
}

impl Handler<XdsAddress> for ProxyStateUpdater {
    fn handle(
        &self,
        updates: Box<&mut dyn Iterator<Item = XdsUpdate<XdsAddress>>>,
    ) -> Result<(), Vec<RejectedConfig>> {
        let mut state = self.state.write().unwrap();
        let handle = |res: XdsUpdate<XdsAddress>| {
            match res {
                XdsUpdate::Update(w) => self.updater.insert_address(&mut state, w.resource)?,
                XdsUpdate::Remove(name) => {
                    debug!("handling delete {}", name);
                    self.updater.remove(&mut state, &strng::new(name))
                }
            }
            Ok(())
        };
        handle_single_resource(updates, handle)
    }
}

impl Handler<agentio::sandbox::Sandbox> for ProxyStateUpdater {
    fn no_on_demand(&self) -> bool {
        // Sandbox resources use pushes even when Workload discovery is on-demand.
        true
    }

    fn handle(
        &self,
        updates: Box<&mut dyn Iterator<Item = XdsUpdate<agentio::sandbox::Sandbox>>>,
    ) -> Result<(), Vec<RejectedConfig>> {
        let mut state = self.state.write().unwrap();
        let mut changed = false;
        let result = handle_single_resource(updates, |update| {
            changed |= match update {
                XdsUpdate::Update(resource) => state.sandboxes.update(resource)?,
                XdsUpdate::Remove(name) => state.sandboxes.remove(&name),
            };
            Ok(())
        });
        // Notify once for accepted policy/binding changes, including partial batches.
        if changed {
            state.policies.send();
        }
        result
    }
}

impl Handler<agentio::security::TrafficPolicy> for ProxyStateUpdater {
    fn no_on_demand(&self) -> bool {
        true
    }

    fn handle(
        &self,
        updates: Box<&mut dyn Iterator<Item = XdsUpdate<agentio::security::TrafficPolicy>>>,
    ) -> Result<(), Vec<RejectedConfig>> {
        let mut state = self.state.write().unwrap();
        let mut changed = false;
        let result = handle_single_resource(updates, |update| {
            changed |= match update {
                XdsUpdate::Update(resource) => state.policies.update(resource)?,
                XdsUpdate::Remove(name) => state.policies.remove(&name),
            };
            Ok(())
        });
        // Re-evaluate TCP connections and non-TCP firewalls against the shared store.
        if changed {
            state.policies.send();
        }
        result
    }
}

fn insert_service_endpoints(
    workload: &Workload,
    services: &HashMap<String, PortList>,
    services_state: &mut ServiceStore,
) -> anyhow::Result<()> {
    for (namespaced_host, ports) in services {
        // Parse the namespaced hostname for the service.
        let namespaced_host = NamespacedHostname::from_str(namespaced_host)?;
        services_state.insert_endpoint(
            namespaced_host,
            Endpoint {
                workload_uid: workload.uid.clone(),
                port: ports.into(),
                status: workload.status,
            },
        )
    }
    Ok(())
}

/// LocalClient serves as a local file reader alternative for XDS. This is intended for testing.
pub struct LocalClient {
    pub cfg: ConfigSource,
    pub state: Arc<RwLock<ProxyState>>,
    pub cert_fetcher: Arc<dyn CertFetcher>,
    pub local_node: Option<Strng>,
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalWorkload {
    #[serde(flatten)]
    pub workload: Workload,
    pub services: HashMap<String, HashMap<u16, u16>>,
}

#[derive(Default, Debug, PartialEq, Eq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalConfig {
    #[serde(default)]
    pub workloads: Vec<LocalWorkload>,
    #[serde(default)]
    pub services: Vec<Service>,
    #[serde(default)]
    pub sandboxes: Vec<Sandbox>,
    #[serde(default)]
    pub policies: BTreeMap<String, TrafficPolicy>,
}

impl LocalClient {
    #[instrument(skip_all, name = "local_client")]
    pub async fn run(self) -> Result<(), anyhow::Error> {
        // Load initial state
        match &self.cfg {
            #[cfg(any(test, feature = "testing"))]
            ConfigSource::Dynamic(rx) => {
                let mut rx = rx.lock().await;
                let r = rx
                    .recv()
                    .await
                    .ok_or(anyhow::anyhow!("did not get initial config"))?;
                self.load_config(r)?;
                rx.ack().await?;
            }
            f => {
                let r: LocalConfig = serde_yaml::from_str(&f.read_to_string().await?)?;
                self.load_config(r)?;
            }
        };
        #[cfg(any(test, feature = "testing"))]
        if let ConfigSource::Dynamic(ref rx) = self.cfg {
            let rx = rx.clone();
            tokio::spawn(async move {
                // Mutex is just for borrow checker; we know we are the only user and can hold the lock forever.
                let mut rx = rx.lock().await;
                while let Some(req) = rx.recv().await {
                    if let Err(e) = self.load_config(req) {
                        error!("failed to load dynamic config update: {e:?}");
                    }
                    if let Err(e) = rx.ack().await {
                        error!("failed to ack: {}", e);
                    }
                }
            });
        };
        Ok(())
    }

    fn load_config(&self, r: LocalConfig) -> anyhow::Result<()> {
        debug!(
            "load local config: {}",
            serde_yaml::to_string(&r).unwrap_or_default()
        );
        let mut next = ProxyState::new(self.local_node.clone());
        let num_workloads = r.workloads.len();
        let num_sandboxes = r.sandboxes.len();
        let num_policies = r.policies.len();
        for (name, policy) in r.policies {
            policy.validate()?;
            next.policies.insert(name.into(), policy)?;
        }
        for sandbox in r.sandboxes {
            sandbox.validate()?;
            anyhow::ensure!(
                next.sandboxes.get(&sandbox.uid).is_none(),
                "duplicate Sandbox uid: {}",
                sandbox.uid
            );
            next.sandboxes.insert(sandbox);
        }
        for wl in r.workloads {
            trace!("inserting local workload {}", &wl.workload.uid);
            self.cert_fetcher.prefetch_cert(&wl.workload);
            let w = Arc::new(wl.workload);
            next.workloads.insert(w.clone());

            let services: HashMap<String, PortList> = wl
                .services
                .into_iter()
                .map(|(k, v)| (k, PortList::from(v)))
                .collect();

            insert_service_endpoints(&w, &services, &mut next.services)?;
        }
        for svc in r.services {
            next.services.insert(svc);
        }
        let mut state = self.state.write().unwrap();
        state.workloads = next.workloads;
        state.services = next.services;
        state.sandboxes = next.sandboxes;
        state.policies.replace(next.policies);
        state.policies.send();
        info!(%num_workloads, %num_sandboxes, %num_policies, "local config initialized");
        Ok(())
    }
}

#[cfg(test)]
mod local_tests;
