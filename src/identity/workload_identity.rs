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

use super::Error;
use crate::strng::Strng;
use x509_parser::prelude::*;

pub const WORKLOAD_IDENTITY_OID: &str = "1.3.6.1.4.1.57874.5.1";

/// Runtime instance reference verified by the CA.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WorkloadIdentity {
    pub registry: Strng,
    pub uid: Strng,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<Strng>,
}

impl WorkloadIdentity {
    pub fn validate(&self) -> Result<(), Error> {
        if self.registry.is_empty() || self.uid.is_empty() {
            return Err(Error::WorkloadIdentity(
                "registry and uid are required".into(),
            ));
        }
        Ok(())
    }

    pub fn from_certificate(der: &[u8]) -> Result<Option<Self>, Error> {
        let invalid = || Error::WorkloadIdentity("invalid workload identity extension".into());
        let (_, cert) = X509Certificate::from_der(der).map_err(|_| invalid())?;
        let mut extensions = cert
            .extensions()
            .iter()
            .filter(|e| e.oid.to_id_string() == WORKLOAD_IDENTITY_OID);
        let Some(extension) = extensions.next() else {
            return Ok(None);
        };
        if extensions.next().is_some() {
            return Err(invalid());
        }
        if !extension.value.trim_ascii_start().starts_with(b"{") {
            return Err(invalid());
        }
        let identity: Self = serde_json::from_slice(extension.value).map_err(|_| invalid())?;
        identity.validate()?;
        Ok(Some(identity))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_workload_identity_extension() {
        use rcgen::{CertificateParams, CustomExtension, KeyPair};
        let cert = |values: Vec<Vec<u8>>| {
            let mut params = CertificateParams::default();
            for value in values {
                params
                    .custom_extensions
                    .push(CustomExtension::from_oid_content(
                        &[1, 3, 6, 1, 4, 1, 57874, 5, 1],
                        value,
                    ));
            }
            params.self_signed(&KeyPair::generate().unwrap()).unwrap()
        };
        // Shared JSON fixtures with the Go issuer's TestWorkloadIdentityJSON.
        let valid = br#"{"registry":"r","uid":"u"}"#.to_vec();
        assert_eq!(
            WorkloadIdentity::from_certificate(cert(vec![]).der()).unwrap(),
            None
        );
        assert_eq!(
            WorkloadIdentity::from_certificate(cert(vec![valid.clone()]).der()).unwrap(),
            Some(WorkloadIdentity {
                registry: "r".into(),
                uid: "u".into(),
                role: None
            }),
        );
        let identity = WorkloadIdentity::from_certificate(
            cert(vec![
                br#"{"registry":"r","uid":"u","role":"ext-proc"}"#.to_vec(),
            ])
            .der(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(identity.role.as_deref(), Some("ext-proc"));
        for role in [
            "sandbox-attester",
            "egress-gateway",
            "ext-proc",
            "future-role",
        ] {
            let payload = serde_json::to_vec(&serde_json::json!({
                "registry": "r", "uid": "u", "role": role,
                "future": {"field": true}
            }))
            .unwrap();
            let identity = WorkloadIdentity::from_certificate(cert(vec![payload]).der())
                .unwrap()
                .unwrap();
            assert_eq!(identity.role.as_deref(), Some(role));
        }
        for payload in [
            b"".as_slice(),
            br#"{}"#,
            br#"null"#,
            br#"["r","u",null]"#,
            br#"{"registry":"r"}"#,
            br#"{"uid":"u"}"#,
            br#"{"registry":"","uid":"u"}"#,
            br#"{"registry":"r","uid":""}"#,
            br#"{"registry":"r","uid":42}"#,
            br#"{"registry":"r","uid":"u","role":42}"#,
            br#"{"registry":"r","uid":"u","uid":"v"}"#,
            br#"{"registry":"r","uid":"u"} trailing"#,
            b"\x30\x06\x0c\x01r\x0c\x01u",
        ] {
            assert!(
                WorkloadIdentity::from_certificate(cert(vec![payload.to_vec()]).der()).is_err()
            );
        }
        assert!(
            WorkloadIdentity::from_certificate(cert(vec![valid.clone(), valid]).der()).is_err()
        );
    }
}
