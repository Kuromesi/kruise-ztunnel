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

use std::hash::{Hash, Hasher};

use crate::sandbox::traffic_policy::firewall_rulesets;
use crate::state::{ProxyState, WorkloadInfo};

use super::types::RuleSet;

/// Resolve the same first attested Sandbox used by the proxy.
/// An absent Sandbox or empty policy chain clears firewall rules.
/// Returns None when the Workload is missing or the applied policy hash is unchanged.
pub fn resolve_workload_firewall(
    state: &ProxyState,
    info: &WorkloadInfo,
    applied_hash: Option<u64>,
) -> Option<(RuleSet, u64)> {
    let wl = state.workloads.find_by_info(info)?;
    if let Some(sandbox) = state.sandboxes.get_by_workload(&wl.uid).first() {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        sandbox.uid.hash(&mut hasher);
        for policy in sandbox.traffic_policies(&state.policies) {
            policy.hash(&mut hasher);
        }
        let hash = hasher.finish();
        if applied_hash == Some(hash) {
            return None;
        }
        return Some((
            firewall_rulesets(sandbox.traffic_policies(&state.policies)),
            hash,
        ));
    }
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    wl.uid.hash(&mut hasher);
    let hash = hasher.finish();
    if applied_hash == Some(hash) {
        return None;
    }
    Some((RuleSet::default(), hash))
}
