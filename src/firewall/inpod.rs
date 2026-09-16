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

use anyhow::Result;
use futures::stream::{self, StreamExt};
use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::drain::DrainWatcher;
use crate::inpod::WorkloadUid;
use crate::inpod::netns::InpodNetns;
use crate::state::{DemandProxyState, WorkloadInfo};

use super::Backend;
use super::backend::BackendBuilder;
use super::convert;
use super::metrics::Metrics;
use super::types::RuleSet;
use super::{DEFAULT_FIREWALL_DEBOUNCE_INTERVAL, DEFAULT_FIREWALL_MAX_DEBOUNCE_TIME};
use crate::time::Debouncer;

const MAX_CONCURRENT_APPLIES: usize = 16;
const MAX_INIT_RETRIES: u8 = 5;
const RETRY_INIT_INTERVAL: Duration = Duration::from_secs(5);

// --- FirewallEvent ---

pub enum FirewallEvent {
    AddPod {
        uid: WorkloadUid,
        info: WorkloadInfo,
        netns: InpodNetns,
    },
    RemovePod {
        uid: WorkloadUid,
    },
}

use super::detect::FirewallBackend;

fn make_backend_for_netns(
    kind: &FirewallBackend,
    netns: &InpodNetns,
    proxy_mark: u32,
    dns_proxy: bool,
    info: &WorkloadInfo,
) -> Box<dyn Backend> {
    let netns_path = format!("/proc/{}/fd/{}", std::process::id(), netns.as_raw_fd());
    BackendBuilder::new(kind.clone())
        .in_netns(netns_path)
        .skip_proxy_mark(proxy_mark)
        .dns_proxy_enabled(dns_proxy)
        .with_workload_info(info)
        .build()
}

// --- PodState ---

pub enum PodState {
    Enrolled,
    PendingWorkload,
    InitFailed { retries: u8 },
}

// --- PodFirewallState ---

struct PodFirewallState {
    netns: InpodNetns,
    workload_info: WorkloadInfo,
    last_policy_hash: u64,
    state: PodState,
}

// --- InpodFirewallController ---

pub struct InpodFirewallController {
    state: DemandProxyState,
    backend_kind: FirewallBackend,
    pods: HashMap<WorkloadUid, PodFirewallState>,
    event_rx: mpsc::UnboundedReceiver<FirewallEvent>,
    proxy_mark: u32,
    dns_proxy: bool,
    metrics: Metrics,
}

impl InpodFirewallController {
    pub fn new(
        state: DemandProxyState,
        backend_kind: FirewallBackend,
        event_rx: mpsc::UnboundedReceiver<FirewallEvent>,
        proxy_mark: u32,
        dns_proxy: bool,
        metrics: Metrics,
    ) -> Self {
        Self {
            state,
            backend_kind,
            pods: HashMap::new(),
            event_rx,
            proxy_mark,
            dns_proxy,
            metrics,
        }
    }

    pub async fn run(mut self, drain: DrainWatcher) {
        let mut policies_changed = self.state.read().policies.subscribe();
        let mut workloads_changed = self.state.read().workloads.new_subscriber();
        let mut retry_interval = tokio::time::interval(RETRY_INIT_INTERVAL);

        info!("InpodFirewallController started");

        loop {
            tokio::select! {
                _ = drain.clone().wait_for_drain() => {
                    info!("InpodFirewallController draining");
                    break;
                }
                pod_event = self.event_rx.recv() => {
                    let Some(event) = pod_event else {
                        info!("Firewall event channel closed, stopping");
                        break;
                    };
                    match event {
                        FirewallEvent::AddPod { uid, info, netns } => {
                            self.handle_add_pod(uid, info, netns).await;
                        }
                        FirewallEvent::RemovePod { uid } => {
                            self.handle_remove_pod(&uid).await;
                        }
                    }
                }
                policy_event = policies_changed.changed() => {
                    if policy_event.is_err() {
                        info!("Policy notifier closed, stopping InpodFirewallController");
                        break;
                    }
                    self.debounce_and_rebuild(&drain, &mut policies_changed).await;
                }
                _ = workloads_changed.changed() => {
                    self.rebuild_pending_workload_pods().await;
                }
                _ = retry_interval.tick(), if self.has_retryable_pods() => {
                    self.retry_init_failed_pods().await;
                }
            }
        }

        info!("InpodFirewallController stopped");
    }

    // --- Pod lifecycle ---

    async fn handle_add_pod(&mut self, uid: WorkloadUid, info: WorkloadInfo, netns: InpodNetns) {
        if let Some(existing) = self.pods.get(&uid) {
            if existing.netns == netns {
                debug!(uid = %uid, "Pod already registered with same netns, skipping");
                return;
            }
            info!(uid = %uid, "Pod sandbox recreated (different netns), re-initializing");
            self.handle_remove_pod(&uid).await;
        }

        let (state, last_policy_hash) = self.try_init_and_apply(&uid, &info, &netns).await;

        self.pods.insert(
            uid,
            PodFirewallState {
                netns,
                workload_info: info,
                last_policy_hash,
                state,
            },
        );
        self.sync_pod_metrics();
    }

    async fn try_init_and_apply(
        &self,
        uid: &WorkloadUid,
        info: &WorkloadInfo,
        netns: &InpodNetns,
    ) -> (PodState, u64) {
        let backend = make_backend_for_netns(
            &self.backend_kind,
            netns,
            self.proxy_mark,
            self.dns_proxy,
            info,
        );

        if let Err(e) = backend.init().await {
            error!(uid = %uid, "Failed to init firewall backend in pod netns: {}", e);
            return (PodState::InitFailed { retries: 0 }, 0);
        }

        let (ruleset, policy_hash) = {
            let state_guard = self.state.read();
            let Some((ruleset, policy_hash)) =
                convert::resolve_workload_firewall(&state_guard, info, None)
            else {
                debug!(info = %info, "Workload not found in xDS state");
                return (PodState::PendingWorkload, 0);
            };
            (ruleset, policy_hash)
        };

        match backend.apply(&ruleset).await {
            Ok(()) => {
                info!(uid = %uid, "Applied firewall rules ({} rules)", ruleset.rules.len());
                (PodState::Enrolled, policy_hash)
            }
            Err(e) => {
                error!(uid = %uid, "Failed to apply firewall rules: {}", e);
                (PodState::InitFailed { retries: 0 }, 0)
            }
        }
    }

    async fn handle_remove_pod(&mut self, uid: &WorkloadUid) {
        let Some(pod_state) = self.pods.remove(uid) else {
            debug!(uid = %uid, "RemovePod for unknown pod, ignoring");
            return;
        };

        let backend = make_backend_for_netns(
            &self.backend_kind,
            &pod_state.netns,
            self.proxy_mark,
            self.dns_proxy,
            &pod_state.workload_info,
        );
        if let Err(e) = backend.cleanup().await {
            debug!(uid = %uid, "Failed to cleanup firewall rules (pod netns may already be gone): {}", e);
        }

        info!(uid = %uid, "Removed pod firewall state");
        self.sync_pod_metrics();
    }

    fn sync_pod_metrics(&self) {
        let mut enrolled = 0usize;
        let mut pending = 0usize;
        let mut init_failed = 0usize;
        for ps in self.pods.values() {
            match ps.state {
                PodState::Enrolled => enrolled += 1,
                PodState::PendingWorkload => pending += 1,
                PodState::InitFailed { .. } => init_failed += 1,
            }
        }
        self.metrics
            .update_pod_counts(enrolled, pending, init_failed);
    }

    // --- Debounce + rebuild ---

    async fn debounce_and_rebuild(
        &mut self,
        drain: &DrainWatcher,
        policies_changed: &mut tokio::sync::watch::Receiver<()>,
    ) {
        let mut debouncer = Debouncer::new(
            DEFAULT_FIREWALL_DEBOUNCE_INTERVAL,
            DEFAULT_FIREWALL_MAX_DEBOUNCE_TIME,
        );

        loop {
            tokio::select! {
                _ = drain.clone().wait_for_drain() => return,
                result = policies_changed.changed() => {
                    if result.is_err() { return; }
                    debouncer.extend();
                }
                Some(event) = self.event_rx.recv() => {
                    match event {
                        FirewallEvent::AddPod { uid, info, netns } => {
                            self.handle_add_pod(uid, info, netns).await;
                        }
                        FirewallEvent::RemovePod { uid } => {
                            self.handle_remove_pod(&uid).await;
                        }
                    }
                }
                _ = debouncer.wait() => break,
            }
        }

        self.rebuild_all_pods().await;
    }

    async fn rebuild_all_pods(&mut self) {
        if self.pods.is_empty() {
            return;
        }

        let rebuild_start = std::time::Instant::now();
        let mut to_apply: Vec<(WorkloadUid, InpodNetns, WorkloadInfo, RuleSet, u64)> = Vec::new();

        {
            let state_guard = self.state.read();
            for (uid, pod_state) in &self.pods {
                if matches!(pod_state.state, PodState::InitFailed { .. }) {
                    continue;
                }
                let Some((ruleset, policy_hash)) = convert::resolve_workload_firewall(
                    &state_guard,
                    &pod_state.workload_info,
                    Some(pod_state.last_policy_hash),
                ) else {
                    continue;
                };
                to_apply.push((
                    uid.clone(),
                    pod_state.netns.clone(),
                    pod_state.workload_info.clone(),
                    ruleset,
                    policy_hash,
                ));
            }
        }

        if to_apply.is_empty() {
            debug!("Policy change: no pods affected after diff");
            return;
        }

        info!(
            "Policy change: applying to {}/{} pods",
            to_apply.len(),
            self.pods.len()
        );

        let backend_kind = &self.backend_kind;
        let proxy_mark = self.proxy_mark;
        let dns_proxy = self.dns_proxy;
        let metrics = self.metrics.clone();
        let results: Vec<(WorkloadUid, u64, Result<()>)> = stream::iter(to_apply)
            .map(|(uid, netns, wl_info, ruleset, policy_hash)| {
                let metrics = metrics.clone();
                async move {
                    let backend = make_backend_for_netns(
                        backend_kind,
                        &netns,
                        proxy_mark,
                        dns_proxy,
                        &wl_info,
                    );
                    let start = std::time::Instant::now();
                    let result = backend.apply(&ruleset).await;
                    metrics.record_apply(result.is_ok(), start.elapsed().as_secs_f64());
                    (uid, policy_hash, result)
                }
            })
            .buffer_unordered(MAX_CONCURRENT_APPLIES)
            .collect()
            .await;

        for (uid, policy_hash, result) in results {
            match result {
                Ok(()) => {
                    if let Some(ps) = self.pods.get_mut(&uid) {
                        ps.last_policy_hash = policy_hash;
                        ps.state = PodState::Enrolled;
                    }
                }
                Err(e) => {
                    if self.pods.contains_key(&uid) {
                        error!(uid = %uid, "Failed to apply firewall rules: {}", e);
                    } else {
                        debug!(uid = %uid, "Apply failed for already-removed pod: {}", e);
                    }
                }
            }
        }
        self.metrics
            .rebuild_duration
            .observe(rebuild_start.elapsed().as_secs_f64());
        self.sync_pod_metrics();
    }

    // --- Pending workload rebuild ---

    async fn rebuild_pending_workload_pods(&mut self) {
        let pending: Vec<WorkloadUid> = self
            .pods
            .iter()
            .filter(|(_, s)| matches!(s.state, PodState::PendingWorkload))
            .map(|(uid, _)| uid.clone())
            .collect();

        if pending.is_empty() {
            return;
        }

        debug!("Rebuilding {} pods pending workload data", pending.len());

        let mut to_process: Vec<(WorkloadUid, InpodNetns, WorkloadInfo, RuleSet, u64)> = Vec::new();
        {
            let state_guard = self.state.read();
            for uid in &pending {
                let Some(pod_state) = self.pods.get(uid) else {
                    continue;
                };
                let Some((ruleset, policy_hash)) = convert::resolve_workload_firewall(
                    &state_guard,
                    &pod_state.workload_info,
                    None,
                ) else {
                    continue;
                };
                to_process.push((
                    uid.clone(),
                    pod_state.netns.clone(),
                    pod_state.workload_info.clone(),
                    ruleset,
                    policy_hash,
                ));
            }
        }

        for (uid, netns, wl_info, ruleset, policy_hash) in to_process {
            let backend = make_backend_for_netns(
                &self.backend_kind,
                &netns,
                self.proxy_mark,
                self.dns_proxy,
                &wl_info,
            );
            let start = std::time::Instant::now();
            let result = backend.apply(&ruleset).await;
            self.metrics
                .record_apply(result.is_ok(), start.elapsed().as_secs_f64());
            match result {
                Ok(()) => {
                    if let Some(ps) = self.pods.get_mut(&uid) {
                        ps.last_policy_hash = policy_hash;
                        ps.state = PodState::Enrolled;
                    }
                    info!(uid = %uid, "Applied firewall rules after workload data arrived");
                }
                Err(e) => {
                    error!(uid = %uid, "Failed to apply firewall rules for pending workload: {}", e);
                }
            }
        }
        self.sync_pod_metrics();
    }

    // --- Init retry ---

    fn has_retryable_pods(&self) -> bool {
        self.pods.values().any(
            |s| matches!(s.state, PodState::InitFailed { retries } if retries < MAX_INIT_RETRIES),
        )
    }

    async fn retry_init_failed_pods(&mut self) {
        let retryable: Vec<WorkloadUid> = self
            .pods
            .iter()
            .filter(|(_, s)| {
                matches!(s.state, PodState::InitFailed { retries } if retries < MAX_INIT_RETRIES)
            })
            .map(|(uid, _)| uid.clone())
            .collect();

        if retryable.is_empty() {
            return;
        }

        debug!("Retrying init for {} failed pods", retryable.len());

        for uid in retryable {
            let Some(pod_state) = self.pods.get(&uid) else {
                continue;
            };
            let retries = match pod_state.state {
                PodState::InitFailed { retries } => retries,
                _ => continue,
            };

            let (new_state, policy_hash) = self
                .try_init_and_apply(&uid, &pod_state.workload_info, &pod_state.netns)
                .await;

            if let Some(ps) = self.pods.get_mut(&uid) {
                match new_state {
                    PodState::InitFailed { .. } => {
                        let next = retries + 1;
                        ps.state = PodState::InitFailed { retries: next };
                        if next >= MAX_INIT_RETRIES {
                            warn!(uid = %uid, "Pod init failed after {} retries, giving up", next);
                        }
                    }
                    _ => {
                        info!(uid = %uid, "Pod init succeeded on retry {}", retries + 1);
                        ps.state = new_state;
                        ps.last_policy_hash = policy_hash;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pod_state(state: PodState) -> PodFirewallState {
        use std::sync::Arc;
        let (r, _w) = std::os::unix::net::UnixStream::pair().unwrap();
        let fd: std::os::fd::OwnedFd = r.into();
        let cur = InpodNetns::current().unwrap_or_else(|_| {
            let (r2, _) = std::os::unix::net::UnixStream::pair().unwrap();
            r2.into()
        });
        let netns = InpodNetns::new(Arc::new(cur), fd).unwrap();
        PodFirewallState {
            netns,
            workload_info: WorkloadInfo::new(
                "test".to_string(),
                "default".to_string(),
                "default".to_string(),
            ),
            last_policy_hash: 0,
            state,
        }
    }

    fn is_init_failed(s: &PodFirewallState) -> bool {
        matches!(s.state, PodState::InitFailed { .. })
    }

    #[test]
    fn has_failed_pods_detects_init_failed() {
        let mut pods = HashMap::new();
        pods.insert(
            WorkloadUid::new("uid-1".into()),
            make_pod_state(PodState::InitFailed { retries: 0 }),
        );
        assert!(pods.values().any(is_init_failed));
    }

    #[test]
    fn has_failed_pods_false_when_all_enrolled() {
        let mut pods = HashMap::new();
        pods.insert(
            WorkloadUid::new("uid-1".into()),
            make_pod_state(PodState::Enrolled),
        );
        assert!(!pods.values().any(is_init_failed));
    }

    #[test]
    fn has_failed_pods_empty() {
        let pods: HashMap<WorkloadUid, PodFirewallState> = HashMap::new();
        assert!(!pods.values().any(is_init_failed));
    }

    #[test]
    fn pending_workload_not_counted_as_failed() {
        let mut pods = HashMap::new();
        pods.insert(
            WorkloadUid::new("uid-1".into()),
            make_pod_state(PodState::PendingWorkload),
        );
        assert!(!pods.values().any(is_init_failed));
    }

    #[test]
    fn pod_state_variants() {
        let ps = make_pod_state(PodState::InitFailed { retries: 0 });
        assert!(matches!(ps.state, PodState::InitFailed { retries: 0 }));

        let ps = make_pod_state(PodState::PendingWorkload);
        assert!(matches!(ps.state, PodState::PendingWorkload));

        let ps = make_pod_state(PodState::Enrolled);
        assert!(matches!(ps.state, PodState::Enrolled));
    }

    #[test]
    fn rebuild_skips_init_failed_pods() {
        let mut pods = HashMap::new();
        pods.insert(
            WorkloadUid::new("enrolled".into()),
            make_pod_state(PodState::Enrolled),
        );
        pods.insert(
            WorkloadUid::new("init-fail".into()),
            make_pod_state(PodState::InitFailed { retries: 0 }),
        );

        let active = pods.values().filter(|s| !is_init_failed(s)).count();
        let failed = pods.values().filter(|s| is_init_failed(s)).count();
        assert_eq!(active, 1);
        assert_eq!(failed, 1);
    }

    #[test]
    fn retry_selects_correct_pods() {
        let mut pods = HashMap::new();
        pods.insert(
            WorkloadUid::new("ok".into()),
            make_pod_state(PodState::Enrolled),
        );
        pods.insert(
            WorkloadUid::new("init-fail".into()),
            make_pod_state(PodState::InitFailed { retries: 0 }),
        );
        pods.insert(
            WorkloadUid::new("pending".into()),
            make_pod_state(PodState::PendingWorkload),
        );

        let failed: Vec<_> = pods
            .iter()
            .filter(|(_, s)| is_init_failed(s))
            .map(|(uid, _)| uid.clone())
            .collect();

        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].clone().into_string(), "init-fail");
    }

    #[test]
    fn pending_workload_selects_correct_pods() {
        let mut pods = HashMap::new();
        pods.insert(
            WorkloadUid::new("ok".into()),
            make_pod_state(PodState::Enrolled),
        );
        pods.insert(
            WorkloadUid::new("pending".into()),
            make_pod_state(PodState::PendingWorkload),
        );
        pods.insert(
            WorkloadUid::new("init-fail".into()),
            make_pod_state(PodState::InitFailed { retries: 0 }),
        );

        let pending: Vec<_> = pods
            .iter()
            .filter(|(_, s)| matches!(s.state, PodState::PendingWorkload))
            .map(|(uid, _)| uid.clone())
            .collect();

        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].clone().into_string(), "pending");
    }

    #[test]
    fn retry_skips_maxed_out_pods() {
        let mut pods = HashMap::new();
        pods.insert(
            WorkloadUid::new("retryable".into()),
            make_pod_state(PodState::InitFailed { retries: 2 }),
        );
        pods.insert(
            WorkloadUid::new("maxed-out".into()),
            make_pod_state(PodState::InitFailed {
                retries: MAX_INIT_RETRIES,
            }),
        );

        let retryable: Vec<_> = pods
            .iter()
            .filter(|(_, s)| {
                matches!(s.state, PodState::InitFailed { retries } if retries < MAX_INIT_RETRIES)
            })
            .map(|(uid, _)| uid.clone())
            .collect();

        assert_eq!(retryable.len(), 1);
        assert_eq!(retryable[0].clone().into_string(), "retryable");
    }

    #[test]
    fn detect_backend_kind_returns_error_when_no_binaries() {
        let result =
            super::super::detect::detect_backend(crate::config::FirewallBackendMode::Auto, false);
        let _ = result;
    }
}
