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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tracing::warn;

use crate::extensions::extensions::EgressPolicies;
use crate::extensions::sni::{SNI_POLICY_TYPE_URL, SniTrafficPolicy};
use crate::rbac::{TrafficPolicy, TrafficPolicyStore};
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Sandbox {
    pub uid: Strng,
    pub workload_uid: Option<Strng>,
    pub egress_routing: Option<EgressPolicies>,
    pub traffic_policy: Option<TrafficPolicy>,
    #[serde(default)]
    pub traffic_policy_refs: Vec<Strng>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni_policy: Option<SniTrafficPolicy>,
}

impl TryFrom<XdsSandbox> for Sandbox {
    type Error = anyhow::Error;

    fn try_from(resource: XdsSandbox) -> Result<Self, Self::Error> {
        let workload_uid = resource
            .attester
            .map(|attester| attester.workload_uid.into());
        let mut sni_policy: Option<SniTrafficPolicy> = None;
        for extension in resource.extensions {
            anyhow::ensure!(
                extension.type_url == SNI_POLICY_TYPE_URL,
                "unsupported Sandbox extension type: {}",
                extension.type_url
            );
            let policy = SniTrafficPolicy::decode(&extension.value)?;
            sni_policy
                .get_or_insert_with(Default::default)
                .rules
                .extend(policy.rules);
        }
        let mut traffic_policy_refs = Vec::new();
        for (type_url, reference) in resource.policy_refs {
            if reference.resource_names.is_empty() {
                continue;
            }
            anyhow::ensure!(
                type_url == crate::xds::TRAFFIC_POLICY_TYPE,
                "unsupported policy reference type: {type_url}"
            );
            traffic_policy_refs.extend(reference.resource_names.into_iter().map(Strng::from));
        }
        let sandbox = Self {
            sni_policy,
            traffic_policy_refs,
            uid: resource.uid.into(),
            workload_uid,
            egress_routing: resource
                .egress_routing
                .map(EgressPolicies::try_from)
                .transpose()?,
            traffic_policy: resource
                .traffic_policy
                .map(TrafficPolicy::try_from)
                .transpose()?,
        };
        sandbox.validate()?;
        Ok(sandbox)
    }
}

impl Sandbox {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        validate_id(&self.uid)?;
        anyhow::ensure!(
            self.workload_uid.as_ref().is_none_or(|uid| !uid.is_empty()),
            "empty attester workload UID"
        );
        let mut seen = HashSet::new();
        for name in &self.traffic_policy_refs {
            anyhow::ensure!(
                !name.is_empty() && name != "*" && seen.insert(name),
                "invalid or duplicate TrafficPolicy reference: {name}"
            );
        }
        if let Some(policy) = &self.traffic_policy {
            policy.validate()?;
        }
        if let Some(policy) = &self.sni_policy {
            policy.validate()?;
        }
        if let Some(routing) = &self.egress_routing {
            for route in &routing.policies {
                route.validate_route()?;
            }
        }
        Ok(())
    }

    pub fn traffic_policies<'a>(
        &'a self,
        store: &'a TrafficPolicyStore,
    ) -> impl Iterator<Item = (&'a str, Option<&'a TrafficPolicy>)> + Clone {
        self.traffic_policy
            .iter()
            .map(|policy| ("inline", Some(policy)))
            .chain(
                self.traffic_policy_refs
                    .iter()
                    .map(move |name| (name.as_str(), store.get(name))),
            )
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
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Arc<Sandbox>> {
        self.resources.values()
    }

    pub fn update(&mut self, update: XdsResource<XdsSandbox>) -> anyhow::Result<bool> {
        let validation = (|| {
            anyhow::ensure!(
                update.resource.uid == update.name,
                "resource name differs from Sandbox uid"
            );
            Sandbox::try_from(update.resource)
        })();
        let sandbox = match validation {
            Ok(sandbox) => sandbox,
            Err(error) => {
                warn!(
                    sandbox_id = %update.name,
                    %error,
                    "ignoring invalid Sandbox update; retaining last accepted resource"
                );
                return Err(error);
            }
        };
        Ok(self.insert(sandbox))
    }

    pub(crate) fn insert(&mut self, sandbox: Sandbox) -> bool {
        let sandbox = Arc::new(sandbox);
        let previous = self.resources.insert(sandbox.uid.clone(), sandbox.clone());
        let previous_workload = previous.as_ref().and_then(|s| s.workload_uid.as_deref());
        let workload = sandbox.workload_uid.as_deref();
        let policy_changed = previous.as_ref().is_none_or(|old| {
            old.workload_uid != sandbox.workload_uid
                || old.traffic_policy != sandbox.traffic_policy
                || old.traffic_policy_refs != sandbox.traffic_policy_refs
        });
        // Keep the selection order stable when only the resource contents change.
        if previous_workload != workload {
            if let Some(uid) = previous_workload {
                self.remove_workload_binding(uid, &sandbox.uid);
            }
            if let Some(uid) = workload {
                self.by_workload
                    .entry(uid.into())
                    .or_default()
                    .push(sandbox.uid.clone());
            }
        }
        policy_changed
    }

    pub fn remove(&mut self, name: &Strng) -> bool {
        let Some(previous) = self.resources.remove(name) else {
            return false;
        };
        if let Some(workload_uid) = &previous.workload_uid {
            self.remove_workload_binding(workload_uid, name);
        }
        true
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
