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
use std::time::Duration;

use futures_util::StreamExt;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Code, Request, Response, Status};
use tracing::{error, info, warn};

use crate::drain::{DrainMode, DrainWatcher};
use crate::sandbox::sandbox::Error;
use crate::sandbox::sandbox::rpc::sandbox_network_server::{SandboxNetwork, SandboxNetworkServer};
use crate::sandbox::sandbox::rpc::{PrepareSandboxRequest, PrepareSandboxResponse};
use crate::strng;

use super::ProxyInputs;

#[cfg(test)]
mod tests;

pub(super) struct Server {
    listener: TcpListener,
    pi: Arc<ProxyInputs>,
    drain: DrainWatcher,
}

impl Server {
    pub(super) fn new(pi: Arc<ProxyInputs>, drain: DrainWatcher) -> Result<Self, super::Error> {
        let address = pi.cfg.sandbox_prepare_addr;
        let listener = pi
            .socket_factory
            .tcp_bind(address)
            .map_err(|error| super::Error::Bind(address, error))?;
        info!(address = %listener.local_addr(), component = "sandbox", "listener established");
        Ok(Self {
            listener: listener.inner(),
            pi,
            drain,
        })
    }

    pub(super) async fn run(self) {
        let deadline = self.pi.cfg.self_termination_deadline;
        let tls = self.pi.sandbox_management_tls.clone();
        let service = Service { pi: self.pi };
        let recovery = service.clone().recover();
        let (shutdown, stopped) = oneshot::channel::<()>();
        let server = async move {
            let shutdown = async move {
                let _ = stopped.await;
            };
            let service = SandboxNetworkServer::new(service);
            if let Some(tls) = tls {
                let incoming = tls_listener::TlsListener::new(tls.acceptor.clone(), self.listener)
                    .filter_map(|result| async {
                        match result {
                            Ok((stream, _)) => Some(Ok::<_, std::io::Error>(stream)),
                            Err(tls_listener::Error::ListenerError(error)) => Some(Err(error)),
                            Err(error) => {
                                warn!(%error, "Sandbox management TLS connection rejected");
                                None
                            }
                        }
                    });
                tonic::transport::Server::builder()
                    .serve_with_incoming_shutdown(service, incoming, shutdown)
                    .await
            } else {
                tonic::transport::Server::builder()
                    .serve_with_incoming_shutdown(
                        service,
                        TcpListenerStream::new(self.listener),
                        shutdown,
                    )
                    .await
            }
        };
        let drain = self.drain.wait_for_drain();
        tokio::pin!(server, recovery, drain);
        let mut recovered = false;
        loop {
            tokio::select! {
                result = &mut server => {
                    if let Err(error) = result {
                        error!(%error, "Sandbox preparation RPC failed");
                    }
                    return;
                }
                _ = &mut recovery, if !recovered => recovered = true,
                blocker = &mut drain => {
                    // Pod removal cancels pending requests; process shutdown may drain them.
                    drop(shutdown);
                    if blocker.mode() == DrainMode::Graceful {
                        match tokio::time::timeout(deadline, &mut server).await {
                            Ok(Ok(())) => {},
                            Ok(Err(error)) => warn!(%error, "Sandbox preparation RPC drain failed"),
                            Err(_) => warn!("Sandbox preparation RPC drain timed out"),
                        }
                    }
                    return;
                }
            }
        }
    }
}

#[derive(Clone)]
struct Service {
    pi: Arc<ProxyInputs>,
}

impl Service {
    async fn recover(self) {
        // Only confirmed registrations survive a restart or caller disconnect.
        let manager = self
            .pi
            .sandbox_manager
            .as_ref()
            .expect("preparation configured");
        let id = manager.registered_id().await;
        loop {
            match manager.wait_for_sandbox(&id).await {
                Ok(_) => {
                    info!("registered Sandbox configuration restored");
                    return;
                }
                Err(error) => {
                    warn!(%error, "Sandbox restoration pending; traffic uses Workload policies");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }
}

#[tonic::async_trait]
impl SandboxNetwork for Service {
    async fn prepare_sandbox(
        &self,
        request: Request<PrepareSandboxRequest>,
    ) -> Result<Response<PrepareSandboxResponse>, Status> {
        if let Some(tls) = &self.pi.sandbox_management_tls {
            tls.authorize(&request)?;
        }
        let id = strng::new(&request.into_inner().sandbox_id);
        let manager = self
            .pi
            .sandbox_manager
            .clone()
            .expect("preparation configured");
        manager.check_registration(&id)?;
        manager.wait_for_sandbox(&id).await?;
        if let Some(token) = &manager.token {
            token.require_ready().await?;
        }
        tokio::task::spawn_blocking(move || manager.register(&id))
            .await
            .map_err(|e| Status::internal(format!("registration task failed: {e}")))??;
        Ok(Response::new(PrepareSandboxResponse {}))
    }
}

// Translate Sandbox manager errors only at the RPC boundary.
impl From<Error> for Status {
    fn from(error: Error) -> Self {
        let code = match &error {
            Error::InvalidIdentity(_) => Code::InvalidArgument,
            Error::AlreadyRegistered | Error::WorkloadMismatch | Error::TokenNotReady => {
                Code::FailedPrecondition
            }
            Error::NotReady => Code::DeadlineExceeded,
            Error::UnknownWorkload | Error::UpdateChannelClosed(_) => Code::Unavailable,
            Error::Io(_) | Error::Json(_) | Error::TokenLoad(_) => Code::Internal,
        };
        Status::new(code, error.to_string())
    }
}
