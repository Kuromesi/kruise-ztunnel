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

use crate::rbac::firewall_rulesets;
use crate::state::{ProxyState, WorkloadInfo};

use super::types::RuleSet;

/// Resolve native Workload policies and the selected Sandbox's inline gate.
/// Returns None when the Workload is missing or the applied policy hash is unchanged.
pub fn resolve_workload_firewall(
    state: &ProxyState,
    info: &WorkloadInfo,
    applied_hash: Option<u64>,
) -> Option<(RuleSet, u64)> {
    let workload = state.workloads.find_by_info(info)?;
    let sandbox = state
        .sandboxes
        .get_by_workload(&workload.uid)
        .first()
        .cloned();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    workload.uid.hash(&mut hasher);
    for policy in workload.traffic_policies(&state.policies) {
        policy.hash(&mut hasher);
    }
    sandbox
        .as_ref()
        .map(|sandbox| (&sandbox.uid, &sandbox.traffic_policy))
        .hash(&mut hasher);
    let hash = hasher.finish();
    if applied_hash == Some(hash) {
        return None;
    }
    let mut rules = firewall_rulesets(workload.traffic_policies(&state.policies));
    if let Some(inline) = sandbox
        .as_ref()
        .and_then(|sandbox| sandbox.traffic_policy.as_ref())
    {
        rules.inline_rules = firewall_rulesets(std::iter::once(("inline", Some(inline)))).rules;
    }
    Some((rules, hash))
}
