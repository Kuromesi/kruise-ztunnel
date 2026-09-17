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

use crate::config as zconfig;
use crate::drain::DrainWatcher;
use crate::readiness;
use crate::state::DemandProxyState;
use metrics::Metrics;
use std::future::Future;
use std::sync::Arc;
use std::thread;
use tokio::sync::mpsc;
use workloadmanager::WorkloadProxyManager;

use crate::proxyfactory::ProxyFactory;

use self::config::InPodConfig;

pub mod admin;
mod config;
pub mod metrics;
pub mod netns;
pub mod packet;
mod protocol;
mod statemanager;
mod workloadmanager;

#[cfg(any(test, feature = "testing"))]
pub mod test_helpers;

pub mod istio {
    pub mod zds {
        tonic::include_proto!("istio.workload.zds");
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("error creating proxy {0}: {1}")]
    ProxyError(String, crate::proxy::Error),
    #[error("error receiving message: {0}")]
    ReceiveMessageError(String),
    #[error("error sending ack: {0}")]
    SendAckError(String),
    #[error("error sending nack: {0}")]
    SendNackError(String),
    #[error("protocol error: {0}")]
    ProtocolError(String),
    #[error("announce error: {0}")]
    AnnounceError(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub struct WorkloadUid(String);

impl std::fmt::Display for WorkloadUid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl WorkloadUid {
    pub fn new(uid: String) -> Self {
        Self(uid)
    }
    pub fn into_string(self) -> String {
        self.0
    }
}

#[derive(Debug)]
pub struct WorkloadData {
    netns: std::os::fd::OwnedFd,
    workload_uid: WorkloadUid,
    workload_info: Option<istio::zds::WorkloadInfo>,
}

#[derive(Debug)]
pub enum WorkloadMessage {
    AddWorkload(WorkloadData),
    KeepWorkload(WorkloadUid),
    WorkloadSnapshotSent,
    DelWorkload(WorkloadUid),
}

pub fn init_and_new(
    metrics: Arc<Metrics>,
    admin_server: &mut crate::admin::Service,
    cfg: &zconfig::Config,
    proxy_gen: ProxyFactory,
    ready: readiness::Ready,
    state: DemandProxyState,
    drain_rx: DrainWatcher,
    fw_metrics: crate::firewall::metrics::Metrics,
) -> anyhow::Result<WorkloadProxyManager> {
    // verify that we have the permissions for the syscalls we need
    WorkloadProxyManager::verify_syscalls()?;

    let admin_handler: Arc<admin::WorkloadManagerAdminHandler> = Default::default();
    admin_server.add_handler(admin_handler.clone());
    let inpod_config = crate::inpod::InPodConfig::new(cfg)?;

    // Set up firewall coordinator channel (only if firewall rules are enabled and nsenter is available)
    let fw_tx = if cfg.enable_firewall_rules {
        let nsenter_ok = std::process::Command::new("/usr/bin/nsenter")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !nsenter_ok {
            tracing::error!(
                "ENABLE_FIREWALL_RULES is true but nsenter not available at /usr/bin/nsenter"
            );
            None
        } else {
            match crate::firewall::detect_backend(cfg.firewall_backend, false) {
                Ok(backend_kind) => {
                    let (tx, rx) = mpsc::unbounded_channel();
                    let proxy_mark = cfg.packet_mark.unwrap_or(1337);
                    let coordinator = crate::firewall::InpodFirewallController::new(
                        state,
                        backend_kind,
                        rx,
                        proxy_mark,
                        cfg.dns_proxy,
                        fw_metrics,
                    );
                    let fw_drain = drain_rx.clone();
                    spawn_firewall_runtime(async move {
                        coordinator.run(fw_drain).await;
                    })
                    .map_err(|e| anyhow::anyhow!("failed to start firewall runtime: {e}"))?;
                    Some(tx)
                }
                Err(e) => {
                    tracing::warn!(
                        "No firewall backend available for inpod mode: {}, firewall rules will not be enforced",
                        e
                    );
                    None
                }
            }
        }
    } else {
        None
    };

    let state_mgr = statemanager::WorkloadProxyManagerState::new(
        proxy_gen,
        inpod_config,
        metrics,
        admin_handler,
        fw_tx,
    );

    Ok(WorkloadProxyManager::new(
        cfg.inpod_uds.clone(),
        state_mgr,
        ready,
    )?)
}

fn spawn_firewall_runtime<F>(future: F) -> std::io::Result<thread::JoinHandle<()>>
where
    F: Future<Output = ()> + Send + 'static,
{
    thread::Builder::new()
        .name("ztunnel-fw".to_string())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("firewall runtime builds");
            runtime.block_on(future);
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn firewall_runtime_runs_task_on_dedicated_thread() {
        let (tx, rx) = tokio::sync::oneshot::channel();

        let handle = spawn_firewall_runtime(async move {
            let name = std::thread::current()
                .name()
                .map(str::to_string)
                .unwrap_or_default();
            tx.send(name).unwrap();
        })
        .unwrap();

        let thread_name = rx.await.unwrap();
        handle.join().unwrap();

        assert_eq!(thread_name, "ztunnel-fw");
    }
}
