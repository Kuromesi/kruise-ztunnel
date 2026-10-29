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

//! TLS and client authorization for Sandbox management RPCs.

use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tonic::transport::server::Connected;
use tonic::{Request, Status};
use x509_parser::extensions::GeneralName;

type ConnectionInfo =
    <tokio_rustls::server::TlsStream<tokio::net::TcpStream> as Connected>::ConnectInfo;

pub(crate) struct ManagementTls {
    pub(crate) acceptor: tokio_rustls::TlsAcceptor,
    allowed_identities: HashSet<String>,
}

impl ManagementTls {
    /// Loaded once by ProxyFactory and shared by all per-Pod listeners.
    pub(crate) fn load(directory: &Path, identities: &[String]) -> anyhow::Result<Self> {
        let cert_path = directory.join("tls.crt");
        let key_path = directory.join("tls.key");
        let ca_path = directory.join("ca.crt");
        let certs = rustls_pemfile::certs(&mut BufReader::new(
            File::open(&cert_path).with_context(|| format!("open {}", cert_path.display()))?,
        ))
        .collect::<Result<Vec<_>, _>>()
        .context("read Sandbox management certificate chain")?;
        let key = rustls_pemfile::private_key(&mut BufReader::new(
            File::open(&key_path).with_context(|| format!("open {}", key_path.display()))?,
        ))
        .context("read Sandbox management private key")?
        .context("Sandbox management tls.key contains no private key")?;
        let mut roots = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut BufReader::new(
            File::open(&ca_path).with_context(|| format!("open {}", ca_path.display()))?,
        )) {
            roots
                .add(cert.context("read Sandbox management client CA")?)
                .context("invalid Sandbox management client CA")?;
        }
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), super::lib::provider())
                .build()
                .context("configure Sandbox management client verification")?;
        let mut config = ServerConfig::builder_with_provider(super::lib::provider())
            .with_protocol_versions(super::tls_versions())?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .context("configure Sandbox management server certificate")?;
        config.alpn_protocols = vec![b"h2".to_vec()];
        Ok(Self {
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
            allowed_identities: identities.iter().cloned().collect(),
        })
    }

    /// Only TLS connection metadata supplies identity; request headers are not trusted.
    pub(crate) fn authorize<T>(&self, request: &Request<T>) -> Result<(), Status> {
        let certs = request
            .extensions()
            .get::<ConnectionInfo>()
            .and_then(|info| info.peer_certs())
            .ok_or_else(|| Status::unauthenticated("management client certificate required"))?;
        let leaf = certs
            .first()
            .ok_or_else(|| Status::unauthenticated("management client certificate required"))?;
        self.authorize_certificate(leaf)
    }

    fn authorize_certificate(&self, leaf: &[u8]) -> Result<(), Status> {
        let (_, cert) = x509_parser::parse_x509_certificate(leaf)
            .map_err(|_| Status::unauthenticated("invalid management client certificate"))?;
        let sans = cert
            .subject_alternative_name()
            .map_err(|_| Status::unauthenticated("invalid management client SAN"))?;
        let allowed = sans.is_some_and(|sans| {
            sans.value.general_names.iter().any(|name| match name {
                GeneralName::URI(id) | GeneralName::DNSName(id) => {
                    self.allowed_identities.contains(*id)
                }
                _ => false,
            })
        });
        if !allowed {
            return Err(Status::permission_denied(
                "management client identity is not allowed",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rustls::ClientConfig;

    // Use the same configured crypto provider as production, including non-default backends.
    pub(crate) fn client_config(root: &[u8], credentials: Option<(&str, &str)>) -> ClientConfig {
        let mut roots = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut &*root) {
            roots.add(cert.unwrap()).unwrap();
        }
        let builder = ClientConfig::builder_with_provider(super::super::lib::provider())
            .with_protocol_versions(super::super::tls_versions())
            .unwrap()
            .with_root_certificates(roots);
        let mut config = if let Some((key, cert)) = credentials {
            builder
                .with_client_auth_cert(
                    rustls_pemfile::certs(&mut cert.as_bytes())
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap(),
                    rustls_pemfile::private_key(&mut key.as_bytes())
                        .unwrap()
                        .unwrap(),
                )
                .unwrap()
        } else {
            builder.with_no_client_auth()
        };
        config.alpn_protocols = vec![b"h2".to_vec()];
        config
    }

    #[test]
    fn sandbox_management_tls_load_rejects_invalid_material() {
        use crate::tls::mock::{TEST_PKEY, TEST_ROOT, TEST_WORKLOAD_CERT};
        let dir = tempfile::tempdir().unwrap();
        let identities = vec!["manager.example".into()];
        let valid = [
            ("tls.crt", TEST_WORKLOAD_CERT),
            ("tls.key", TEST_PKEY),
            ("ca.crt", TEST_ROOT),
        ];
        for (name, data) in valid {
            std::fs::write(dir.path().join(name), data).unwrap();
        }
        assert!(ManagementTls::load(dir.path(), &identities).is_ok());
        for (name, data) in valid {
            std::fs::remove_file(dir.path().join(name)).unwrap();
            assert!(
                ManagementTls::load(dir.path(), &identities).is_err(),
                "missing {name}"
            );
            std::fs::write(dir.path().join(name), "not PEM").unwrap();
            assert!(
                ManagementTls::load(dir.path(), &identities).is_err(),
                "malformed {name}"
            );
            std::fs::write(dir.path().join(name), data).unwrap();
        }
        std::fs::write(
            dir.path().join("tls.key"),
            rcgen::KeyPair::generate().unwrap().serialize_pem(),
        )
        .unwrap();
        assert!(
            ManagementTls::load(dir.path(), &identities).is_err(),
            "mismatched private key"
        );
    }

    #[test]
    fn sandbox_management_identity_uses_exact_sans_not_cn() {
        use crate::tls::mock::{TEST_PKEY, TEST_ROOT, TEST_WORKLOAD_CERT};
        let dir = tempfile::tempdir().unwrap();
        for (name, data) in [
            ("tls.crt", TEST_WORKLOAD_CERT),
            ("tls.key", TEST_PKEY),
            ("ca.crt", TEST_ROOT),
        ] {
            std::fs::write(dir.path().join(name), data).unwrap();
        }
        let tls = ManagementTls::load(dir.path(), &["manager.example".into()]).unwrap();
        for (names, allowed) in [
            (vec!["manager.example"], true),
            (vec!["gateway.example"], false),
            (vec!["*.example"], false),
            (vec![], false),
        ] {
            let mut params = rcgen::CertificateParams::new(
                names.into_iter().map(String::from).collect::<Vec<_>>(),
            )
            .unwrap();
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "manager.example");
            let cert = params
                .self_signed(&rcgen::KeyPair::generate().unwrap())
                .unwrap();
            assert_eq!(tls.authorize_certificate(cert.der()).is_ok(), allowed);
        }
        assert_eq!(
            tls.authorize(&Request::new(())).unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
    }
}
