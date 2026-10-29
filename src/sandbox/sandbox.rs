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

use std::fs::{self, File};
use std::io::{ErrorKind, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{Mutex as AsyncMutex, watch};

use crate::sandbox::discovery::{Sandbox, validate_id};
use crate::state::{DemandProxyState, WorkloadInfo};
use crate::strng::{self, Strng};
use crate::xds::SANDBOX_TYPE;

use super::token::FileSandboxToken;

pub mod rpc {
    tonic::include_proto!("agentio.network.v1");
}

pub(crate) const READY_TIMEOUT: Duration = Duration::from_secs(30);
const REGISTRATION_FILE: &str = "sandbox.json";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid Sandbox identity: {0}")]
    InvalidIdentity(#[source] anyhow::Error),
    #[error("Sandbox registration I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid Sandbox registration JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("a different Sandbox is already registered")]
    AlreadyRegistered,
    #[error("Sandbox is bound to a different Workload")]
    WorkloadMismatch,
    #[error("Sandbox configuration is not ready")]
    NotReady,
    #[error("Sandbox token is not loaded or is empty")]
    TokenNotReady,
    #[error("Sandbox token loading failed: {0}")]
    TokenLoad(#[source] anyhow::Error),
    #[error("local Workload is not available")]
    UnknownWorkload,
    #[error("policy update channel closed: {0}")]
    UpdateChannelClosed(#[from] watch::error::RecvError),
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Registration {
    sandbox_id: String,
}

#[cfg(test)]
#[path = "sandbox/registration_tests.rs"]
mod registration_tests;

pub static SANDBOX_ID_HEADER: &str = "x-agentio-sandbox-id";
pub static SANDBOX_LABELS_HEADER: &str = "x-agentio-sandbox-labels";

/// Manages one workload proxy's Sandbox identity, token and policy readiness.
pub struct SandboxManager {
    state: DemandProxyState,
    workload: Arc<WorkloadInfo>,
    pub(crate) token: Option<FileSandboxToken>,
    // Only identity is persisted. Readiness is checked against the current xDS snapshot.
    directory: Option<PathBuf>,
    id: watch::Sender<Option<Strng>>,
    registration_lock: Mutex<()>,
    fetch_lock: AsyncMutex<()>,
}

impl SandboxManager {
    pub fn new(state: DemandProxyState, workload: Arc<WorkloadInfo>) -> Self {
        Self {
            state,
            workload,
            token: None,
            directory: None,
            id: watch::channel(None).0,
            registration_lock: Mutex::new(()),
            fetch_lock: AsyncMutex::new(()),
        }
    }

    pub fn with_registration(mut self, directory: PathBuf) -> Result<Self, Error> {
        fs::create_dir_all(&directory)?;
        let id = match fs::read_to_string(directory.join(REGISTRATION_FILE)) {
            Ok(contents) => {
                let registration: Registration = serde_json::from_str(&contents)?;
                validate_id(&registration.sandbox_id).map_err(Error::InvalidIdentity)?;
                Some(strng::new(&registration.sandbox_id))
            }
            Err(e) if e.kind() == ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        self.directory = Some(directory);
        self.id.send_replace(id);
        Ok(self)
    }

    pub(crate) fn check_registration(&self, id: &str) -> Result<(), Error> {
        validate_id(id).map_err(Error::InvalidIdentity)?;
        if let Some(current) = self.id.borrow().as_ref()
            && current.as_str() != id
        {
            return Err(Error::AlreadyRegistered);
        }
        Ok(())
    }

    // Called after readiness checks in spawn_blocking: once committing, cancellation
    // must not interrupt rename and publication to the running process.
    pub(crate) fn register(&self, id: &str) -> Result<(), Error> {
        let _guard = self.registration_lock.lock().unwrap();
        // Another Prepare may have committed while this request waited for readiness.
        self.check_registration(id)?;
        if self.id.borrow().is_some() {
            return Ok(());
        }
        let directory = self.directory.as_ref().expect("registration configured");
        let temporary = directory.join("sandbox.json.tmp");
        let mut file = File::create(&temporary)?;
        serde_json::to_writer_pretty(
            &mut file,
            &Registration {
                sandbox_id: id.into(),
            },
        )?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(temporary, directory.join(REGISTRATION_FILE))?;
        File::open(directory)?.sync_all()?;
        self.id.send_replace(Some(strng::new(id)));
        Ok(())
    }

    pub(crate) async fn registered_id(&self) -> Strng {
        let mut ids = self.id.subscribe();
        ids.wait_for(Option::is_some)
            .await
            .expect("SandboxManager owns the sender")
            .as_ref()
            .unwrap()
            .clone()
    }

    /// Demand the Sandbox and confirm its binding to this proxy before returning.
    /// Registration remains separate so failed or cancelled waits do not persist an ID.
    pub(crate) async fn wait_for_sandbox(&self, id: &Strng) -> Result<Arc<Sandbox>, Error> {
        tokio::time::timeout(READY_TIMEOUT, async {
            // Start Sandbox demand before waiting for local Workload discovery.
            self.fetch_sandbox(id).await?;
            self.state
                .wait_for_workload(&self.workload, READY_TIMEOUT)
                .await
                .ok_or(Error::UnknownWorkload)?;
            // Use the current snapshot after waiting, including on restart recovery.
            self.get_sandbox(id)
        })
        .await
        .map_err(|_| Error::NotReady)?
    }

    async fn fetch_sandbox(&self, id: &Strng) -> Result<Arc<Sandbox>, Error> {
        let current = || {
            self.state
                .read()
                .sandboxes
                .get(id)
                .filter(|s| s.workload_uid.is_some())
        };
        if let Some(sandbox) = current() {
            return Ok(sandbox);
        }
        // Coalesce RPC and background restoration for this registration.
        let _fetch = self.fetch_lock.lock().await;
        let mut changes = self.state.read().policies.subscribe();
        if let Some(sandbox) = current() {
            return Ok(sandbox);
        }
        // A demand notification is only a wakeup, never proof of readiness.
        // Missing/rejected resources remain blocked until an accepted update arrives.
        let demand = self.state.fetch_on_demand(SANDBOX_TYPE, id.clone());
        tokio::pin!(demand);
        let mut responded = false;
        loop {
            if let Some(sandbox) = current() {
                return Ok(sandbox);
            }
            tokio::select! {
                _ = &mut demand, if !responded => responded = true,
                result = changes.changed() => {
                    result?;
                }
            }
        }
    }

    /// Check local state only. Preparation and recovery own demand and waiting.
    pub fn ready_sandbox(&self) -> Result<Arc<Sandbox>, Error> {
        let id = self.id.borrow();
        let id = id.as_ref().ok_or(Error::NotReady)?;
        self.get_sandbox(id)
    }

    fn get_sandbox(&self, id: &Strng) -> Result<Arc<Sandbox>, Error> {
        let state = self.state.read();
        let workload = state
            .workloads
            .find_by_info(&self.workload)
            .ok_or(Error::NotReady)?;
        state
            .sandboxes
            .get_for_workload(id, &workload.uid)
            .map_err(|_| Error::WorkloadMismatch)?
            .ok_or(Error::NotReady)
    }
}
