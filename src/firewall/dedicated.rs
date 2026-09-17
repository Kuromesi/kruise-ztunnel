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

use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{error, info};

use crate::drain::DrainWatcher;
use crate::state::{DemandProxyState, WorkloadInfo};
use crate::time::Debouncer;

use super::backend::{Backend, BackendBuilder};
use super::convert;
use super::detect::FirewallBackend;
use super::metrics::Metrics;

use super::{DEFAULT_FIREWALL_DEBOUNCE_INTERVAL, DEFAULT_FIREWALL_MAX_DEBOUNCE_TIME};

pub struct FirewallController {
    state: DemandProxyState,
    stop: DrainWatcher,
    backend: Box<dyn Backend>,
    workload_info: Arc<WorkloadInfo>,
    debounce_interval: Duration,
    max_debounce_time: Duration,
    metrics: Metrics,
}

impl FirewallController {
    pub fn new(
        state: DemandProxyState,
        stop: DrainWatcher,
        detected: FirewallBackend,
        workload_info: Arc<WorkloadInfo>,
        metrics: Metrics,
    ) -> Self {
        Self::new_with_debounce(
            state,
            stop,
            detected,
            workload_info,
            DEFAULT_FIREWALL_DEBOUNCE_INTERVAL,
            DEFAULT_FIREWALL_MAX_DEBOUNCE_TIME,
            metrics,
        )
    }

    pub fn new_with_debounce(
        state: DemandProxyState,
        stop: DrainWatcher,
        detected: FirewallBackend,
        workload_info: Arc<WorkloadInfo>,
        debounce_interval: Duration,
        max_debounce_time: Duration,
        metrics: Metrics,
    ) -> Self {
        let backend = BackendBuilder::new(detected)
            .with_workload_info(&workload_info)
            .build();
        Self {
            state,
            stop,
            backend,
            workload_info,
            debounce_interval,
            max_debounce_time,
            metrics,
        }
    }

    fn resolve_and_build(
        &self,
        applied_hash: Option<u64>,
    ) -> Option<(crate::firewall::RuleSet, u64)> {
        let state = self.state.read();
        convert::resolve_workload_firewall(&state, &self.workload_info, applied_hash)
    }

    async fn drain_cleanup(&self) {
        info!("Firewall controller draining, cleaning up rules");
        if let Err(e) = self.backend.cleanup().await {
            error!("Failed to cleanup firewall rules: {}", e);
        }
    }

    pub async fn run(self) {
        if let Err(e) = self.backend.init().await {
            error!("Failed to initialize firewall backend: {}", e);
            return;
        }

        // Subscribe before the initial apply so updates during it are not lost.
        let mut policies_changed = self.state.read().policies.subscribe();
        let mut last_policy_hash = None;
        if let Some((ruleset, policy_hash)) = self.resolve_and_build(last_policy_hash) {
            let start = Instant::now();
            let result = self.backend.apply(&ruleset).await;
            self.metrics
                .record_apply(result.is_ok(), start.elapsed().as_secs_f64());
            match result {
                Ok(()) => last_policy_hash = Some(policy_hash),
                Err(e) => error!("Failed to apply initial firewall rules: {}", e),
            }
        }

        loop {
            tokio::select! {
                _ = self.stop.clone().wait_for_drain() => {
                    self.drain_cleanup().await;
                    break;
                }
                result = policies_changed.changed() => {
                    if result.is_err() {
                        info!("Policy notifier closed, stopping firewall controller");
                        break;
                    }
                    match wait_for_policy_debounce(
                        &self.stop,
                        &mut policies_changed,
                        self.debounce_interval,
                        self.max_debounce_time,
                    )
                    .await
                    {
                        DebounceResult::Ready => {}
                        DebounceResult::Draining => {
                            self.drain_cleanup().await;
                            break;
                        }
                        DebounceResult::Closed => {
                            info!("Policy notifier closed, stopping firewall controller");
                            break;
                        }
                    }
                    let rebuild_start = Instant::now();
                    let Some((ruleset, policy_hash)) = self.resolve_and_build(last_policy_hash) else {
                        continue;
                    };
                    info!("Firewall policies changed, applying {} rules", ruleset.rules.len());
                    let start = Instant::now();
                    let result = self.backend.apply(&ruleset).await;
                    self.metrics
                        .record_apply(result.is_ok(), start.elapsed().as_secs_f64());
                    self.metrics
                        .rebuild_duration
                        .observe(rebuild_start.elapsed().as_secs_f64());
                    match result {
                        Ok(()) => last_policy_hash = Some(policy_hash),
                        Err(e) => error!("Failed to apply firewall rules: {}", e),
                    }
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum DebounceResult {
    Ready,
    Draining,
    Closed,
}

pub(super) async fn wait_for_policy_debounce(
    stop: &DrainWatcher,
    policies_changed: &mut tokio::sync::watch::Receiver<()>,
    debounce_interval: Duration,
    max_debounce_time: Duration,
) -> DebounceResult {
    let mut debouncer = Debouncer::new(debounce_interval, max_debounce_time);

    loop {
        tokio::select! {
            _ = stop.clone().wait_for_drain() => {
                return DebounceResult::Draining;
            }
            result = policies_changed.changed() => {
                if result.is_err() {
                    return DebounceResult::Closed;
                }
                debouncer.extend();
            }
            _ = debouncer.wait() => {
                return DebounceResult::Ready;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drain;
    use tokio::sync::watch;

    #[tokio::test(start_paused = true)]
    async fn debounce_waits_for_quiet_interval_after_last_change() {
        let (_drain_tx, drain_rx) = drain::new();
        let (tx, mut rx) = watch::channel(());

        let wait = tokio::spawn(async move {
            wait_for_policy_debounce(
                &drain_rx,
                &mut rx,
                Duration::from_millis(100),
                Duration::from_secs(1),
            )
            .await
        });

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(99)).await;
        assert!(!wait.is_finished());

        tx.send_replace(());
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(99)).await;
        assert!(!wait.is_finished());

        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(wait.await.unwrap(), DebounceResult::Ready);
    }

    #[tokio::test(start_paused = true)]
    async fn debounce_never_waits_past_max_time() {
        let (_drain_tx, drain_rx) = drain::new();
        let (tx, mut rx) = watch::channel(());

        let wait = tokio::spawn(async move {
            wait_for_policy_debounce(
                &drain_rx,
                &mut rx,
                Duration::from_millis(100),
                Duration::from_millis(250),
            )
            .await
        });

        for _ in 0..3 {
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_millis(80)).await;
            tx.send_replace(());
        }

        tokio::task::yield_now().await;
        assert!(!wait.is_finished());

        tokio::time::advance(Duration::from_millis(10)).await;
        assert_eq!(wait.await.unwrap(), DebounceResult::Ready);
    }
}
