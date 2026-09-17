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

//! Firewall backend trait definition

pub mod ipt;
pub mod nft;

use async_trait::async_trait;
use tokio::process::Command;

pub use ipt::IptBackend;
pub use nft::NftBackend;

use super::detect::FirewallBackend;
use super::types::RuleSet;
use crate::state::WorkloadInfo;

/// Build a `Command` that optionally enters a network namespace via nsenter.
pub(super) fn make_nsenter_cmd(netns_path: &Option<String>, program: &str) -> Command {
    match netns_path {
        Some(path) => {
            let mut cmd = Command::new("/usr/bin/nsenter");
            cmd.arg(format!("--net={}", path)).arg("--").arg(program);
            cmd
        }
        None => Command::new(program),
    }
}

/// Format workload identity as "namespace/name" for structured logging.
pub(super) fn format_workload_label(name: &Option<String>, namespace: &Option<String>) -> String {
    match (name, namespace) {
        (Some(name), Some(ns)) => format!("{}/{}", ns, name),
        _ => String::new(),
    }
}

/// Firewall backend trait
///
/// Implementations of this trait handle the actual application of firewall rules
/// to the system (e.g., iptables, nftables).
#[async_trait]
pub trait Backend: Send + Sync {
    /// One-time setup (e.g. create chains, jump rules).
    /// Called once before the first apply. Default is no-op.
    async fn init(&self) -> anyhow::Result<()> {
        Ok(())
    }

    /// Atomically replace all ztunnel-managed rules
    async fn apply(&self, ruleset: &RuleSet) -> anyhow::Result<()>;

    /// Clean up all ztunnel-managed rules (shutdown / drain).
    async fn cleanup(&self) -> anyhow::Result<()>;
}

/// Builder for constructing a firewall backend from detection result.
pub struct BackendBuilder {
    detected: FirewallBackend,
    netns_path: Option<String>,
    proxy_mark: Option<u32>,
    dns_proxy: bool,
    workload_info: Option<WorkloadInfo>,
}

impl BackendBuilder {
    pub fn new(detected: FirewallBackend) -> Self {
        Self {
            detected,
            netns_path: None,
            proxy_mark: None,
            dns_proxy: false,
            workload_info: None,
        }
    }

    pub fn in_netns(mut self, path: impl Into<String>) -> Self {
        self.netns_path = Some(path.into());
        self
    }

    pub fn skip_proxy_mark(mut self, mark: u32) -> Self {
        self.proxy_mark = Some(mark);
        self
    }

    pub fn dns_proxy_enabled(mut self, enabled: bool) -> Self {
        self.dns_proxy = enabled;
        self
    }

    pub fn with_workload_info(mut self, info: &WorkloadInfo) -> Self {
        self.workload_info = Some(info.clone());
        self
    }

    pub fn build(self) -> Box<dyn Backend> {
        match self.detected {
            FirewallBackend::Nftables => {
                let mut b = NftBackend::new();
                if let Some(path) = self.netns_path {
                    b = b.in_netns(path);
                }
                if let Some(mark) = self.proxy_mark {
                    b = b.skip_mark(mark);
                }
                if let Some(ref info) = self.workload_info {
                    b = b.with_workload_info(&info.name, &info.namespace);
                }
                Box::new(b)
            }
            FirewallBackend::Iptables {
                iptables_bin,
                restore_bin,
            } => {
                let mut b = IptBackend::new().with_binaries(iptables_bin, restore_bin);
                if let Some(path) = self.netns_path {
                    b = b.in_netns(path);
                }
                if let Some(mark) = self.proxy_mark {
                    b = b.skip_mark(mark);
                }
                b = b.dns_proxy(self.dns_proxy);
                if let Some(ref info) = self.workload_info {
                    b = b.with_workload_info(&info.name, &info.namespace);
                }
                Box::new(b)
            }
        }
    }
}
