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

//! Cached Sandbox resources and their attester Workload bindings.

use std::collections::HashMap;
use std::sync::Arc;

use tracing::warn;

use super::traffic_policy::TrafficPolicy;
use crate::extensions::extensions::EgressPolicies;
use crate::strng::Strng;
use crate::xds::XdsResource;
use crate::xds::agentio::sandbox::Sandbox as XdsSandbox;

#[cfg(test)]
pub(crate) mod tests;

fn validate_id(id: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !id.is_empty() && id.len() <= 512 && id != "*" && id.bytes().all(|b| b.is_ascii_graphic()),
        "Sandbox uid must be a nonempty printable ASCII identifier, at most 512 bytes, other than '*'"
    );
    Ok(())
}

/// Sandbox information used by the proxy, independent of the xDS wire format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sandbox {
    pub uid: Strng,
    pub workload_uid: Option<Strng>,
    pub egress_routing: Option<EgressPolicies>,
    pub traffic_policies: Vec<TrafficPolicy>,
}

impl TryFrom<XdsSandbox> for Sandbox {
    type Error = anyhow::Error;

    fn try_from(resource: XdsSandbox) -> Result<Self, Self::Error> {
        validate_id(&resource.uid)?;
        let workload_uid = match resource.attester {
            Some(attester) => {
                anyhow::ensure!(
                    !attester.workload_uid.is_empty(),
                    "empty attester workload UID"
                );
                Some(attester.workload_uid.into())
            }
            None => None,
        };
        Ok(Self {
            uid: resource.uid.into(),
            workload_uid,
            egress_routing: resource
                .egress_routing
                .map(EgressPolicies::try_from)
                .transpose()?,
            traffic_policies: resource
                .traffic_policies
                .into_iter()
                .map(TrafficPolicy::try_from)
                .collect::<anyhow::Result<_>>()?,
        })
    }
}

#[derive(Debug, Default)]
pub struct SandboxStore {
    // Accepted internal snapshots, atomically replaced by valid updates.
    resources: HashMap<Strng, Arc<Sandbox>>,
    // Sandbox IDs for each attester Workload UID, in binding arrival order.
    by_workload: HashMap<Strng, Vec<Strng>>,
}

impl SandboxStore {
    pub fn update(&mut self, update: XdsResource<XdsSandbox>) -> anyhow::Result<()> {
        let validation = (|| {
            anyhow::ensure!(
                update.resource.uid == update.name,
                "resource name differs from Sandbox uid"
            );
            Sandbox::try_from(update.resource)
        })();
        let sandbox = match validation {
            Ok(sandbox) => Arc::new(sandbox),
            Err(error) => {
                warn!(
                    sandbox_id = %update.name,
                    %error,
                    "ignoring invalid Sandbox update; retaining last accepted resource"
                );
                return Err(error);
            }
        };
        let previous = self.resources.insert(update.name.clone(), sandbox.clone());
        let previous_workload = previous.as_ref().and_then(|s| s.workload_uid.as_deref());
        let workload = sandbox.workload_uid.as_deref();
        // Keep the selection order stable when only the resource contents change.
        if previous_workload != workload {
            if let Some(uid) = previous_workload {
                self.remove_workload_binding(uid, &update.name);
            }
            if let Some(uid) = workload {
                self.by_workload
                    .entry(uid.into())
                    .or_default()
                    .push(update.name);
            }
        }
        Ok(())
    }

    pub fn remove(&mut self, name: &Strng) {
        if let Some(previous) = self.resources.remove(name)
            && let Some(workload_uid) = &previous.workload_uid
        {
            self.remove_workload_binding(workload_uid, name);
        }
    }

    fn remove_workload_binding(&mut self, workload_uid: &str, sandbox_id: &Strng) {
        if let Some(sandboxes) = self.by_workload.get_mut(workload_uid) {
            sandboxes.retain(|id| id != sandbox_id);
            if sandboxes.is_empty() {
                self.by_workload.remove(workload_uid);
            }
        }
    }

    pub fn get(&self, id: &Strng) -> Option<Arc<Sandbox>> {
        self.resources.get(id).cloned()
    }

    /// Return the Sandboxes bound to a Workload in binding arrival order.
    pub fn get_by_workload(&self, workload_uid: &Strng) -> Vec<Arc<Sandbox>> {
        self.by_workload
            .get(workload_uid)
            .into_iter()
            .flatten()
            .filter_map(|id| self.resources.get(id).cloned())
            .collect()
    }
}
