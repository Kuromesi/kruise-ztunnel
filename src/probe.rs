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

use bytes::Bytes;
use http::header;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpSocket;
use tonic_health::pb::HealthCheckRequest;
use tonic_health::pb::health_client::HealthClient;
use tower::service_fn;
use tracing::{debug, error, info};

use crate::config::Config;
use crate::socket;
use once_cell::sync::Lazy;
use regex::Regex;

const LINGER_TIMEOUT: Duration = Duration::from_secs(1);

fn default_timeout_seconds() -> i32 {
    1
}

/// Prober defines a health check configuration, mirroring the Kubernetes Probe specification.
/// It supports one of three mechanisms: HTTP GET, TCP Socket, or gRPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Prober {
    pub http_get: Option<HTTPGetAction>,
    pub tcp_socket: Option<TCPSocketAction>,
    pub grpc: Option<GRPCAction>,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: i32,
}

/// Helper type to handle JSON fields that can be either an integer port or a named port string.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IntOrString {
    Int(u16),
    String(String),
}

impl IntOrString {
    /// Converts the enum to a numeric port value.
    pub fn int_value(&self) -> u16 {
        match self {
            IntOrString::Int(i) => *i,
            IntOrString::String(s) => s.parse().unwrap_or(0),
        }
    }
}

/// Represents the URI scheme for HTTP probes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum URIScheme {
    Http,
    Https,
}

/// Custom HTTP header to be sent with the probe request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HTTPHeader {
    pub name: String,
    pub value: String,
}

/// Action to perform an HTTP GET request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HTTPGetAction {
    pub path: String,
    pub port: IntOrString,
    pub host: Option<String>,
    pub scheme: Option<URIScheme>,
    pub http_headers: Option<Vec<HTTPHeader>>,
}

/// Action to perform a TCP connection check.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TCPSocketAction {
    pub port: IntOrString,
    pub host: Option<String>,
}

/// Action to perform a gRPC health check (standard health protocol).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GRPCAction {
    pub port: i32,
    pub service: Option<String>,
}

/// Regex to ensure probe paths follow the expected format: /app-health/{id}/{livez|readyz|startupz}
static APP_PROBER_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^/app-health/[^/]+/(livez|readyz|startupz)$").expect("Invalid regex")
});

/// Validates that the prober configuration is well-formed according to Kubernetes requirements.
pub fn validate_app_kube_prober(path: &str, prober: &Prober) -> Result<(), String> {
    debug!("Validating app kube prober for path: {}", path);

    // 1. Validate path format
    if !APP_PROBER_PATTERN.is_match(path) {
        let error_msg = format!(
            "invalid path, must be in form of regex pattern {}",
            APP_PROBER_PATTERN.as_str()
        );
        error!("Validation failed for {}: {}", path, error_msg);
        return Err(error_msg);
    }

    // 2. Ensure exactly one action type is defined
    let mut count = 0;
    if prober.http_get.is_some() {
        count += 1;
    }
    if prober.tcp_socket.is_some() {
        count += 1;
    }
    if prober.grpc.is_some() {
        count += 1;
    }

    if count != 1 {
        let error_msg =
            "invalid prober type, must be one of type httpGet, tcpSocket or gRPC".to_string();
        error!("Validation failed for {}: {}", path, error_msg);
        return Err(error_msg);
    }

    // 3. Port validation (ensure port is a numeric type for this implementation)
    if let Some(http_get) = &prober.http_get {
        if matches!(http_get.port, IntOrString::String(_)) {
            return Err(format!(
                "invalid prober config for {}, port must be int",
                path
            ));
        }
    }

    if let Some(tcp_socket) = &prober.tcp_socket {
        if matches!(tcp_socket.port, IntOrString::String(_)) {
            return Err(format!(
                "invalid prober config for {}, port must be int",
                path
            ));
        }
    }

    Ok(())
}

/// The Server holds the configuration and clients required to execute health probes.
#[derive(Clone, Debug)]
pub struct Server {
    /// Mapping of URL paths to their specific probe configurations.
    pub app_kube_probers: HashMap<String, Prober>,
    /// Pre-initialized HTTP clients for paths that use HTTP GET probes.
    pub app_probe_clients: HashMap<String, reqwest::Client>,
    /// The port this probe server is listening on (used for Host header rewriting).
    pub status_port: u16,
    /// The target IP where the probes should be sent (usually the local Pod IP).
    pub app_probers_destination: String,

    pub local_addr: IpAddr,
}

impl Server {
    /// Creates a new Server instance based on the provided configuration.
    pub fn new(config: Arc<Config>) -> Result<Self, String> {
        info!("Initializing probe server with configuration");

        let app_kube_probers = config
            .kube_app_probes
            .clone()
            .ok_or_else(|| "No kube app probes found, not enabling kube app probes.".to_string())?;

        let mut app_probe_clients = HashMap::new();

        let local_addr = socket::to_self_addr(
            config
                .pod_ip
                .parse::<IpAddr>()
                .expect("should not fail to parse pod ip"),
        );

        for (path, prober) in &app_kube_probers {
            if prober.http_get.is_some() {
                validate_app_kube_prober(path, prober)?;

                // Define a custom redirect policy:
                // 1. Follow up to 10 redirects.
                // 2. Stop if the hostname changes (security boundary).
                let custom_redirect_policy = reqwest::redirect::Policy::custom(|attempt| {
                    if attempt.previous().len() >= 10 {
                        return attempt.error("stopped after 10 redirects");
                    }
                    let initial_url = &attempt.previous()[0];
                    if attempt.url().host_str() != initial_url.host_str() {
                        return attempt.stop();
                    }
                    attempt.follow()
                });

                let client = reqwest::Client::builder()
                    .local_address(local_addr)
                    .danger_accept_invalid_certs(true) // Probes often use self-signed certs
                    .pool_max_idle_per_host(if config.probe_keepalive_connections {
                        10
                    } else {
                        0
                    })
                    .timeout(Duration::from_secs(prober.timeout_seconds as u64))
                    .redirect(custom_redirect_policy)
                    .build()
                    .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

                app_probe_clients.insert(path.clone(), client);
            }
        }

        Ok(Server {
            app_kube_probers,
            app_probe_clients,
            status_port: config.stats_addr.port(),
            app_probers_destination: config.pod_ip.clone(),
            local_addr,
        })
    }

    /// Main entry point to handle an incoming probe request from Kubernetes.
    pub async fn handle_app_probe(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let path = req.uri().path();
        let normalized_path = if !path.starts_with('/') {
            format!("/{}", path)
        } else {
            path.to_string()
        };

        // Identify which probe configuration matches this path
        let prober = match self.app_kube_probers.get(&normalized_path) {
            Some(p) => p,
            None => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from(format!(
                        "app prober config does not exist for {}",
                        normalized_path
                    ))))
                    .unwrap());
            }
        };

        // Dispatch to the specific handler based on probe type
        if let Some(http_get) = &prober.http_get {
            Ok(self
                .handle_app_probe_http_get(req, http_get, &normalized_path)
                .await)
        } else if let Some(tcp_socket) = &prober.tcp_socket {
            Ok(self.handle_app_probe_tcp_socket(tcp_socket, prober).await)
        } else if let Some(grpc) = &prober.grpc {
            Ok(self.handle_app_probe_grpc(req, grpc, prober).await)
        } else {
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::new()))
                .unwrap())
        }
    }

    /// Executes an HTTP GET probe by forwarding the request to the target application.
    async fn handle_app_probe_http_get(
        &self,
        req: Request<Incoming>,
        http_get: &HTTPGetAction,
        path: &str,
    ) -> Response<Full<Bytes>> {
        let real_port = http_get.port.int_value();
        let prober_path = if http_get.path.starts_with('/') {
            http_get.path.clone()
        } else {
            format!("/{}", http_get.path)
        };

        let scheme = match http_get.scheme.as_ref().unwrap_or(&URIScheme::Http) {
            URIScheme::Https => "https",
            URIScheme::Http => "http",
        };

        let url = format!(
            "{}://{}:{}{}",
            scheme, self.app_probers_destination, real_port, prober_path
        );
        debug!("forwarding probe request to {url}");
        let http_client = match self.app_probe_clients.get(path) {
            Some(client) => client,
            None => {
                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::new(Bytes::new()))
                    .unwrap();
            }
        };

        // Header Logic:
        // We need to rewrite the Host header. If the incoming request points to the status port,
        // we swap it for the actual application port.
        let incoming_host = req
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        debug!("incoming Host header: {incoming_host}");

        let mut final_host = incoming_host.clone();
        if !final_host.is_empty() {
            if let Some(pos) = final_host.rfind(':') {
                if &final_host[pos + 1..] == self.status_port.to_string() {
                    final_host = format!("{}:{}", &final_host[..pos], real_port);
                }
            }
        }

        // If the Host header is empty, fall back to the actual application address.
        // Sending an empty Host header violates HTTP/1.1 and many servers reject it with 400.
        if final_host.is_empty() || final_host == "<none>" {
            final_host = format!("{}:{}", self.app_probers_destination, real_port);
            debug!("Host header was empty, falling back to {final_host}");
        }

        // Forward existing headers to the application
        let mut forwarded_headers = header::HeaderMap::new();
        for (name, value) in req.headers().iter() {
            if name == header::HOST {
                continue;
            }
            forwarded_headers.insert(name.clone(), value.clone());
        }

        debug!("forwarding headers: {:?}", forwarded_headers);

        // Execute the probe
        let resp = match http_client
            .get(&url)
            .headers(forwarded_headers)
            .header(header::HOST, final_host)
            .send()
            .await
        {
            Ok(res) => {
                let status = res.status();
                debug!("backend responded with status {}", status);
                res
            }
            Err(e) => {
                error!("HTTP probe failed for {}: {}", url, e);
                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::new(Bytes::new()))
                    .unwrap();
            }
        };

        // Kubernetes considers 200-399 as success for HTTP probes
        let raw_status = resp.status().as_u16();
        let final_status = if (300..400).contains(&raw_status) {
            StatusCode::OK
        } else {
            StatusCode::from_u16(raw_status).unwrap_or(StatusCode::OK)
        };

        let body_bytes = resp.bytes().await.unwrap_or_default();
        Response::builder()
            .status(final_status)
            .body(Full::new(body_bytes))
            .unwrap()
    }

    /// Executes a TCP Socket probe by attempting to open a connection to the target port.
    async fn handle_app_probe_tcp_socket(
        &self,
        tcp_socket: &TCPSocketAction,
        prober: &Prober,
    ) -> Response<Full<Bytes>> {
        let addr = SocketAddr::new(
            self.app_probers_destination.parse::<IpAddr>().unwrap(),
            tcp_socket.port.int_value() as u16,
        );

        let connect_timeout = Duration::from_secs(prober.timeout_seconds as u64);
        match tokio::time::timeout(connect_timeout, create_prober_socket(addr, self.local_addr))
            .await
        {
            Ok(Ok(_)) => Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::new()))
                .unwrap(),
            _ => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::new()))
                .unwrap(),
        }
    }

    /// Executes a gRPC health check probe.
    async fn handle_app_probe_grpc(
        &self,
        req: Request<Incoming>,
        grpc_config: &GRPCAction,
        prober: &Prober,
    ) -> Response<Full<Bytes>> {
        let addr = format!(
            "http://{}:{}",
            self.app_probers_destination, grpc_config.port
        );
        let timeout = Duration::from_secs(prober.timeout_seconds as u64);

        let user_agent = req
            .headers()
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("kube-probe/rust");

        let local_ip_copy = self.local_addr;
        let host = self.app_probers_destination.clone();
        let port = grpc_config.port;
        let connector = service_fn(move |_: tonic::codegen::http::Uri| {
            let local_ip = local_ip_copy;
            let host = host.clone();
            let port = port;
            async move {
                let dst_addr = format!("{}:{}", host, port).parse::<SocketAddr>().unwrap();
                let stream = create_prober_socket(dst_addr, local_ip).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        });

        // Setup the gRPC channel
        let endpoint = match tonic::transport::Endpoint::from_shared(addr.clone()) {
            Ok(e) => e.connect_timeout(timeout).user_agent(user_agent).unwrap(),
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::new(Bytes::new()))
                    .unwrap();
            }
        };

        let channel = match endpoint.connect_with_connector(connector).await {
            Ok(c) => c,
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::new(Bytes::new()))
                    .unwrap();
            }
        };

        let service_name = grpc_config.service.clone().unwrap_or_default();

        // Perform the gRPC Health Check call in a spawned task
        let result = tokio::spawn(async move {
            let mut client = HealthClient::new(channel);
            client
                .check(HealthCheckRequest {
                    service: service_name,
                })
                .await
        })
        .await;

        match result {
            Ok(Ok(resp)) => {
                let status_code = resp.into_inner().status;
                let serving_status =
                    tonic_health::pb::health_check_response::ServingStatus::Serving as i32;

                if status_code == serving_status {
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::new()))
                        .unwrap()
                } else {
                    // Status is NOT_SERVING or other
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Full::new(Bytes::new()))
                        .unwrap()
                }
            }
            _ => {
                // RPC error or Task join error
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::new(Bytes::new()))
                    .unwrap()
            }
        }
    }
}

async fn create_prober_socket(
    target: SocketAddr,
    local_ip: IpAddr,
) -> std::io::Result<tokio::net::TcpStream> {
    let socket = if target.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };

    // tokio::net::TcpSocket::set_linger is deprecated (SO_LINGER blocks the
    // task on drop); reach through socket2 to set the same option directly.
    socket2::SockRef::from(&socket).set_linger(Some(LINGER_TIMEOUT))?;
    socket.bind(SocketAddr::new(local_ip, 0))?;
    socket.connect(target).await
}
