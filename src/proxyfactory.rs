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

use crate::config;
use crate::identity::SecretManager;
use crate::sandbox::sandbox::SandboxManager;
use crate::sandbox::token::FileSandboxToken;
use crate::state::{DemandProxyState, WorkloadInfo};
use crate::tls;
use std::sync::Arc;
use tracing::error;

use crate::dns;
use crate::drain::DrainWatcher;

use crate::firewall::metrics::Metrics as FirewallMetrics;
use crate::proxy::connection_manager::ConnectionManager;
use crate::proxy::{DefaultSocketFactory, Proxy, inbound::Inbound};
use crate::proxy::{Error, LocalWorkloadInformation, Metrics};

// Proxy factory creates ztunnel proxies using a socket factory.
// this allows us to create our proxies the same way in regular mode and in inpod mode.
pub struct ProxyFactory {
    config: Arc<config::Config>,
    state: DemandProxyState,
    cert_manager: Arc<SecretManager>,
    proxy_metrics: Arc<Metrics>,
    dns_metrics: Option<Arc<dns::Metrics>>,
    drain: DrainWatcher,
    crl_manager: Option<Arc<tls::crl::CrlManager>>,
    sandbox_management_tls: Option<Arc<tls::management::ManagementTls>>,
    firewall_metrics: Option<FirewallMetrics>,
}

impl ProxyFactory {
    pub fn new(
        config: Arc<config::Config>,
        state: DemandProxyState,
        cert_manager: Arc<SecretManager>,
        proxy_metrics: Arc<Metrics>,
        dns_metrics: Option<dns::Metrics>,
        drain: DrainWatcher,
        firewall_metrics: Option<FirewallMetrics>,
    ) -> std::io::Result<Self> {
        let sandbox_management_tls = if config.sandbox_management_tls_enabled {
            Some(Arc::new(
                tls::management::ManagementTls::load(
                    &config.sandbox_management_tls_dir,
                    &config.sandbox_management_allowed_identities,
                )
                .map_err(std::io::Error::other)?,
            ))
        } else {
            None
        };
        let dns_metrics = match dns_metrics {
            Some(metrics) => Some(Arc::new(metrics)),
            None => {
                if config.dns_proxy {
                    error!("dns proxy configured but no dns metrics provided")
                }
                None
            }
        };

        // Initialize CRL manager if crl_path is set
        let crl_manager = if let Some(crl_path) = &config.crl_path {
            match tls::crl::CrlManager::new(crl_path.clone()) {
                Ok(manager) => {
                    let manager_arc = Arc::new(manager);

                    if let Err(e) = manager_arc.start_file_watcher() {
                        tracing::warn!(
                            "crl file watcher could not be started: {}. \
                            crl validation will continue with current file, but \
                            crl updates will require restarting ztunnel.",
                            e
                        );
                    }

                    Some(manager_arc)
                }
                Err(e) => {
                    tracing::warn!(
                        path = ?crl_path,
                        error = %e,
                        "failed to initialize crl manager"
                    );
                    None
                }
            }
        } else {
            None
        };

        Ok(ProxyFactory {
            config,
            state,
            cert_manager,
            proxy_metrics,
            dns_metrics,
            drain,
            crl_manager,
            sandbox_management_tls,
            firewall_metrics,
        })
    }

    pub async fn new_proxies_for_dedicated(
        &self,
        proxy_workload_info: WorkloadInfo,
    ) -> Result<ProxyResult, Error> {
        let base = crate::proxy::DefaultSocketFactory(self.config.socket_config);
        let factory: Arc<dyn crate::proxy::SocketFactory + Send + Sync> =
            if let Some(mark) = self.config.packet_mark {
                Arc::new(crate::proxy::MarkSocketFactory { inner: base, mark })
            } else {
                Arc::new(base)
            };
        self.new_proxies_from_factory(None, None, proxy_workload_info, factory)
            .await
    }

    pub async fn new_proxies_from_factory(
        &self,
        proxy_drain: Option<DrainWatcher>,
        workload_uid: Option<&str>,
        proxy_workload_info: WorkloadInfo,
        socket_factory: Arc<dyn crate::proxy::SocketFactory + Send + Sync>,
    ) -> Result<ProxyResult, Error> {
        let mut result: ProxyResult = Default::default();
        let drain = proxy_drain.unwrap_or_else(|| self.drain.clone());

        #[cfg(any(test, feature = "testing"))]
        let mut resolver = None;

        let local_workload_information = Arc::new(LocalWorkloadInformation::new(
            Arc::new(proxy_workload_info),
            self.state.clone(),
            self.cert_manager.clone(),
        ));

        // Optionally create the DNS proxy.
        if self.config.dns_proxy {
            let server = dns::Server::new(
                self.config.cluster_domain.clone(),
                self.config.dns_proxy_addr,
                self.state.clone(),
                dns::forwarder_for_mode(
                    self.config.proxy_mode,
                    self.config.cluster_domain.clone(),
                    socket_factory.clone(),
                )?,
                self.dns_metrics.clone().unwrap(),
                drain.clone(),
                socket_factory.as_ref(),
                local_workload_information.as_fetcher(),
                self.config.prefered_service_namespace.clone(),
                self.config.ipv6_enabled,
            )
            .await?;
            #[cfg(any(test, feature = "testing"))]
            {
                resolver = Some(server.resolver());
            }
            result.dns_proxy = Some(server);
        }

        // Optionally create the HBONE proxy.
        if self.config.proxy {
            let sandbox_manager = if self.config.enable_sandbox_manager {
                if let Some(uid) = workload_uid
                    && std::path::Path::new(uid).file_name() != Some(std::ffi::OsStr::new(uid))
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "workload UID must be a single directory name",
                    )
                    .into());
                }
                let mut state_directory = self.config.sandbox_state_dir.clone();
                if let Some(uid) = workload_uid {
                    state_directory.push(uid);
                }
                let mut manager = SandboxManager::new(
                    self.state.clone(),
                    local_workload_information.workload_info(),
                )
                .with_registration(state_directory)?;
                if self.config.sandbox_token_enabled {
                    let mut token_directory =
                        std::path::PathBuf::from(&self.config.sandbox_token_path);
                    if let Some(uid) = workload_uid {
                        token_directory.push(uid);
                    }
                    manager.token = Some(
                        FileSandboxToken::start(
                            token_directory,
                            self.config.sandbox_watcher_debounce_ms,
                        )
                        .await?,
                    );
                }
                Some(Arc::new(manager))
            } else {
                None
            };
            let cm = ConnectionManager::default();
            let pi = crate::proxy::ProxyInputs::new(
                self.config.clone(),
                cm.clone(),
                self.state.clone(),
                self.proxy_metrics.clone(),
                socket_factory.clone(),
                #[cfg(any(test, feature = "testing"))]
                resolver,
                local_workload_information,
                false,
                self.crl_manager.clone(),
                sandbox_manager,
                self.sandbox_management_tls.clone(),
                self.firewall_metrics.clone(),
            );
            result.connection_manager = Some(cm);
            result.proxy = Some(Proxy::from_inputs(pi, drain).await?);
        }

        Ok(result)
    }

    /// Creates an inbound listener specifically for ztunnel's own internal endpoints (metrics).
    /// This allows ztunnel to act as its own workload, enforcing policies on traffic directed to itself.
    /// This is distinct from the main inbound listener which handles traffic for other workloads proxied by ztunnel.
    pub async fn create_ztunnel_self_proxy_listener(
        &self,
    ) -> Result<Option<crate::proxy::inbound::Inbound>, Error> {
        if self.config.proxy_mode != config::ProxyMode::Shared {
            return Ok(None);
        }

        if let (Some(ztunnel_identity), Some(ztunnel_workload)) =
            (&self.config.ztunnel_identity, &self.config.ztunnel_workload)
        {
            tracing::info!(
                "creating ztunnel self-proxy listener with identity: {:?}",
                ztunnel_identity
            );

            let local_workload_information = Arc::new(LocalWorkloadInformation::new(
                Arc::new(ztunnel_workload.clone()),
                self.state.clone(),
                self.cert_manager.clone(),
            ));

            let socket_factory = Arc::new(DefaultSocketFactory(self.config.socket_config));

            let cm = ConnectionManager::default();

            let pi = crate::proxy::ProxyInputs::new(
                self.config.clone(),
                cm.clone(),
                self.state.clone(),
                self.proxy_metrics.clone(),
                socket_factory,
                #[cfg(any(test, feature = "testing"))]
                None,
                local_workload_information,
                true,
                self.crl_manager.clone(),
                None,
                None,
                None,
            );

            let inbound = Inbound::new(pi, self.drain.clone()).await?;
            Ok(Some(inbound))
        } else {
            Ok(None)
        }
    }
}

#[derive(Default)]
pub struct ProxyResult {
    pub proxy: Option<Proxy>,
    pub dns_proxy: Option<dns::Server>,
    pub connection_manager: Option<ConnectionManager>,
}
