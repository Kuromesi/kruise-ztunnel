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

use crate::state::workload::GatewayAddress;
use crate::state::workload::{NamespacedHostname, gatewayaddress};
use crate::strng::Strng;
use crate::xds::agentio::sandbox::{EgressRouting, egress_routing};
use crate::xds::istio::workload::Extension as XdsWorkloadExtension;
use crate::xds::kruise::networking::extensions::v1 as proto;
use crate::xds::kruise::networking::extensions::v1::{
    EgressPolicies as ProtoEgressPolicies, WorkloadMetadata,
};
use ipnet::IpNet;
use prost::Message;
use std::collections::HashSet;
use tracing::debug;

const WORKLOAD_METADATA_TYPE_URL: &str =
    "type.googleapis.com/kruise.networking.extensions.v1.WorkloadMetadata";
const DEFAULT_EGRESS_POLICIES_TYPE_URL: &str =
    "type.googleapis.com/kruise.networking.extensions.v1.EgressPolicies";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum EgressPolicyAction {
    Passthrough,
    Deny,
    Gateway,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EgressPolicyError {
    #[error("unknown egress policy action: {0}")]
    UnknownAction(i32),
    #[error("invalid egress policy CIDR: {0}")]
    InvalidCidr(String),
    #[error("invalid egress policy port: {0}")]
    InvalidPort(String),
    #[error("invalid egress gateway service: {0}")]
    InvalidGatewayService(String),
    #[error("invalid egress gateway port: {0}")]
    InvalidGatewayPort(u32),
    #[error("gateway action requires a gateway")]
    MissingGateway,
    #[error("passthrough action must not specify a gateway")]
    UnexpectedGateway,
    #[error("failed to decode egress policies: {0}")]
    Decode(String),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EgressPolicy {
    #[serde(default)]
    pub namespaces: HashSet<String>,
    #[serde(default)]
    pub match_cidrs: Vec<IpNet>,
    #[serde(default)]
    pub match_ports: Vec<u16>,
    pub policy: EgressPolicyAction,
    pub gateway: Option<GatewayAddress>,
}

impl std::hash::Hash for EgressPolicy {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        for ns in &self.namespaces {
            ns.hash(state);
        }
        self.match_cidrs.len().hash(state);
        for cidr in &self.match_cidrs {
            cidr.hash(state);
        }
        self.match_ports.len().hash(state);
        for port in &self.match_ports {
            port.hash(state);
        }
        self.policy.hash(state);
        self.gateway.hash(state);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EgressPolicies {
    #[serde(default)]
    pub policies: Vec<EgressPolicy>,
}

impl std::hash::Hash for EgressPolicies {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.policies.len().hash(state);
        for policy in &self.policies {
            policy.hash(state);
        }
    }
}

#[derive(Debug, Clone)]
pub enum WorkloadExtension {
    WorkloadMetadata(WorkloadMetadata),
    EgressPolicies(EgressPolicies),
    Raw(RawExtension),
}

#[derive(Debug, Clone)]
pub struct RawExtension {
    pub name: String,
    pub config_type_url: Option<String>,
    pub config_raw: Option<Vec<u8>>,
}

impl TryFrom<XdsWorkloadExtension> for WorkloadExtension {
    type Error = EgressPolicyError;

    fn try_from(value: XdsWorkloadExtension) -> Result<Self, Self::Error> {
        if let Some(any) = &value.config {
            match any.type_url.as_str() {
                WORKLOAD_METADATA_TYPE_URL => {
                    if let Ok(metadata) = WorkloadMetadata::decode(&*any.value) {
                        debug!("Decoded workload metadata extension: {:?}", metadata);
                        return Ok(WorkloadExtension::WorkloadMetadata(metadata));
                    }
                }
                DEFAULT_EGRESS_POLICIES_TYPE_URL => {
                    let policies = ProtoEgressPolicies::decode(&*any.value)
                        .map_err(|err| EgressPolicyError::Decode(err.to_string()))?;
                    debug!("Decoded egress policies extension: {:?}", policies);
                    return Ok(WorkloadExtension::EgressPolicies(EgressPolicies::try_from(
                        policies,
                    )?));
                }
                _ => {}
            }
        }
        Ok(WorkloadExtension::Raw(RawExtension::from(value)))
    }
}

impl WorkloadMetadata {
    /// Encode label map as a base64 of `k1=v1,k2=k2,...`.
    /// Keys are sorted so the output is deterministic across processes - the
    /// downstream gateway uses this string as a cache key, so two workloads
    /// with identical labels must produce identical encodings.
    pub fn encode_labels(&self) -> String {
        let mut pairs: Vec<_> = self.labels.iter().collect();
        pairs.sort_by_key(|&(k, _)| k);
        let encoded: String = pairs
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(",");
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            encoded.as_bytes(),
        )
    }
}

impl From<XdsWorkloadExtension> for RawExtension {
    fn from(ext: XdsWorkloadExtension) -> Self {
        let (config_type_url, config_raw) = match ext.config {
            Some(any) => (Some(any.type_url), Some(any.value)),
            None => (None, None),
        };

        RawExtension {
            name: ext.name,
            config_type_url,
            config_raw,
        }
    }
}

impl TryFrom<i32> for EgressPolicyAction {
    type Error = EgressPolicyError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(EgressPolicyAction::Passthrough),
            1 => Ok(EgressPolicyAction::Deny),
            2 => Ok(EgressPolicyAction::Gateway),
            other => Err(EgressPolicyError::UnknownAction(other)),
        }
    }
}

impl TryFrom<proto::EgressPolicy> for EgressPolicy {
    type Error = EgressPolicyError;

    fn try_from(value: proto::EgressPolicy) -> Result<Self, Self::Error> {
        let policy = EgressPolicyAction::try_from(value.policy)?;
        let match_cidrs = parse_cidrs(value.match_cidrs)?;
        let match_ports = parse_ports(value.match_ports)?;
        let gateway = value
            .gateway
            .as_ref()
            .map(|gateway| parse_gateway_address(&gateway.service, gateway.port))
            .transpose()?;
        if policy == EgressPolicyAction::Gateway && gateway.is_none() {
            return Err(EgressPolicyError::MissingGateway);
        }

        Ok(EgressPolicy {
            namespaces: value.namespaces.into_iter().collect(),
            match_cidrs,
            match_ports,
            policy,
            gateway,
        })
    }
}

impl TryFrom<proto::EgressPolicies> for EgressPolicies {
    type Error = EgressPolicyError;

    fn try_from(value: proto::EgressPolicies) -> Result<Self, Self::Error> {
        Ok(EgressPolicies {
            policies: value
                .egress_policies
                .into_iter()
                .map(EgressPolicy::try_from)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl TryFrom<egress_routing::Route> for EgressPolicy {
    type Error = EgressPolicyError;

    fn try_from(value: egress_routing::Route) -> Result<Self, Self::Error> {
        // Sandbox GATEWAY is 1; the legacy Workload action with that value is DENY.
        let policy = match egress_routing::Action::try_from(value.action) {
            Ok(egress_routing::Action::Passthrough) => EgressPolicyAction::Passthrough,
            Ok(egress_routing::Action::Gateway) => EgressPolicyAction::Gateway,
            Err(_) => return Err(EgressPolicyError::UnknownAction(value.action)),
        };
        let match_cidrs = parse_cidrs(value.match_cidrs)?;
        let match_ports = parse_ports(value.match_ports)?;
        let gateway = value
            .gateway
            .as_ref()
            .map(|gateway| parse_gateway_address(&gateway.service, gateway.port))
            .transpose()?;
        let route = Self {
            namespaces: HashSet::new(),
            match_cidrs,
            match_ports,
            policy,
            gateway,
        };
        route.validate_route()?;
        Ok(route)
    }
}

impl EgressPolicy {
    pub(crate) fn validate_route(&self) -> Result<(), EgressPolicyError> {
        if self.match_ports.contains(&0) {
            return Err(EgressPolicyError::InvalidPort("0".into()));
        }
        if let Some(gateway) = &self.gateway
            && gateway.hbone_mtls_port == 0
        {
            return Err(EgressPolicyError::InvalidGatewayPort(0));
        }
        match (self.policy, self.gateway.is_some()) {
            (EgressPolicyAction::Gateway, false) => return Err(EgressPolicyError::MissingGateway),
            (EgressPolicyAction::Passthrough, true) => {
                return Err(EgressPolicyError::UnexpectedGateway);
            }
            _ => {}
        }
        Ok(())
    }
}

impl TryFrom<EgressRouting> for EgressPolicies {
    type Error = EgressPolicyError;

    fn try_from(value: EgressRouting) -> Result<Self, Self::Error> {
        Ok(Self {
            policies: value
                .routes
                .into_iter()
                .map(EgressPolicy::try_from)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

fn parse_cidrs(cidrs: Vec<String>) -> Result<Vec<IpNet>, EgressPolicyError> {
    cidrs
        .into_iter()
        .map(|cidr| {
            cidr.parse::<IpNet>()
                .map_err(|_| EgressPolicyError::InvalidCidr(cidr))
        })
        .collect()
}

fn parse_ports(ports: Vec<String>) -> Result<Vec<u16>, EgressPolicyError> {
    ports
        .into_iter()
        .map(|port| {
            port.parse::<u16>()
                .map_err(|_| EgressPolicyError::InvalidPort(port))
        })
        .collect()
}

/// Convert gateway fields shared by both wire formats into the internal type.
/// The service field is expected as a FQDN like `name.namespace.svc.cluster.local`;
/// the second dot-separated segment is taken as the namespace. Invalid service
/// names and out-of-range ports reject the containing resource.
/// Port `0` is normalized to the HBONE MTLS default (15008).
fn parse_gateway_address(svc: &str, port: u32) -> Result<GatewayAddress, EgressPolicyError> {
    let mut segments = svc.split('.');
    let service = segments.next().unwrap_or_default();
    let namespace = segments.next().unwrap_or_default();
    if service.is_empty() || namespace.is_empty() {
        return Err(EgressPolicyError::InvalidGatewayService(svc.into()));
    }
    let port = match port {
        0 => 15008,
        p => u16::try_from(p).map_err(|_| EgressPolicyError::InvalidGatewayPort(p))?,
    };
    Ok(GatewayAddress {
        destination: gatewayaddress::Destination::Hostname(NamespacedHostname {
            namespace: Strng::from(namespace),
            hostname: Strng::from(svc),
        }),
        hbone_mtls_port: port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xds::kruise::networking::extensions::v1 as ext_proto;
    use prost_types::Any;
    use std::collections::HashMap;

    #[test]
    fn extension_type_urls_match_control_plane_proto_package() {
        const PREFIX: &str = "type.googleapis.com/kruise.networking.extensions.v1.";

        assert_eq!(
            WORKLOAD_METADATA_TYPE_URL,
            format!("{PREFIX}WorkloadMetadata")
        );
        assert_eq!(
            DEFAULT_EGRESS_POLICIES_TYPE_URL,
            format!("{PREFIX}EgressPolicies")
        );
    }

    // ---- helpers --------------------------------------------------------

    fn any_of<M: Message>(type_url: &str, msg: &M) -> Any {
        // Build a google.protobuf.Any payload for a known proto message; used
        // to drive the type_url dispatch in TryFrom<XdsWorkloadExtension>.
        let mut buf = Vec::with_capacity(msg.encoded_len());
        msg.encode(&mut buf).expect("encode");
        Any {
            type_url: type_url.to_string(),
            value: buf,
        }
    }

    fn workload_ext(name: &str, any: Option<Any>) -> XdsWorkloadExtension {
        XdsWorkloadExtension {
            name: name.to_string(),
            config: any,
        }
    }

    // ---- EgressPolicyAction --------------------------------------------

    #[test]
    fn egress_action_from_known_values() {
        assert_eq!(
            EgressPolicyAction::try_from(0).unwrap(),
            EgressPolicyAction::Passthrough
        );
        assert_eq!(
            EgressPolicyAction::try_from(1).unwrap(),
            EgressPolicyAction::Deny
        );
        assert_eq!(
            EgressPolicyAction::try_from(2).unwrap(),
            EgressPolicyAction::Gateway
        );
    }

    #[test]
    fn egress_action_unknown_is_rejected() {
        assert!(EgressPolicyAction::try_from(99).is_err());
        assert!(EgressPolicyAction::try_from(-1).is_err());
    }

    // ---- parse_gateway_address --------------------------------------

    #[test]
    fn gateway_extracts_namespace_from_fqdn() {
        let gw = ext_proto::GatewayAddress {
            service: "egress.istio-system.svc.cluster.local".to_string(),
            port: 8443,
        };
        let out = parse_gateway_address(&gw.service, gw.port).expect("should parse");
        match out.destination {
            gatewayaddress::Destination::Hostname(h) => {
                assert_eq!(h.namespace.as_str(), "istio-system");
                assert_eq!(h.hostname.as_str(), "egress.istio-system.svc.cluster.local");
            }
            _ => panic!("expected Hostname destination"),
        }
        assert_eq!(out.hbone_mtls_port, 8443);
    }

    #[test]
    fn gateway_port_zero_defaults_to_hbone_mtls() {
        // port=0 is the proto3 default; treat it as "use the HBONE mtls port".
        let gw = ext_proto::GatewayAddress {
            service: "egress.istio-system".to_string(),
            port: 0,
        };
        let out = parse_gateway_address(&gw.service, gw.port).expect("should parse");
        assert_eq!(out.hbone_mtls_port, 15008);
    }

    #[test]
    fn gateway_without_dot_is_rejected() {
        let gw = ext_proto::GatewayAddress {
            service: "no-dots-here".to_string(),
            port: 0,
        };
        assert!(parse_gateway_address(&gw.service, gw.port).is_err());
    }

    #[test]
    fn gateway_trailing_dot_is_rejected() {
        let gw = ext_proto::GatewayAddress {
            service: "foo.".to_string(),
            port: 1234,
        };
        assert!(parse_gateway_address(&gw.service, gw.port).is_err());
    }

    // ---- EgressPolicy::try_from ----------------------------------------

    #[test]
    fn egress_policy_from_proto_accepts_valid_fields() {
        let pp = ext_proto::EgressPolicy {
            namespaces: vec!["ns-a".into(), "ns-b".into(), "ns-a".into()],
            match_cidrs: vec!["10.0.0.0/8".into(), "2001:db8::/32".into()],
            match_ports: vec!["80".into(), "443".into()],
            policy: 2, // Gateway
            gateway: Some(ext_proto::GatewayAddress {
                service: "gw.istio-system".to_string(),
                port: 0,
            }),
        };
        let p = EgressPolicy::try_from(pp).unwrap();
        // namespaces deduplicated via HashSet
        assert_eq!(p.namespaces.len(), 2);
        assert!(p.namespaces.contains("ns-a"));
        assert!(p.namespaces.contains("ns-b"));
        assert_eq!(p.match_cidrs.len(), 2);
        assert_eq!(p.match_ports, vec![80, 443]);
        assert_eq!(p.policy, EgressPolicyAction::Gateway);
        assert!(p.gateway.is_some());
    }

    #[test]
    fn egress_policy_from_proto_rejects_invalid_cidr() {
        let pp = ext_proto::EgressPolicy {
            match_cidrs: vec!["not-a-cidr".into()],
            ..Default::default()
        };
        assert!(EgressPolicy::try_from(pp).is_err());
    }

    #[test]
    fn egress_policy_from_proto_rejects_invalid_port() {
        let pp = ext_proto::EgressPolicy {
            match_ports: vec!["65536".into()],
            ..Default::default()
        };
        assert!(EgressPolicy::try_from(pp).is_err());
    }

    #[test]
    fn egress_policy_from_proto_rejects_invalid_gateway() {
        let pp = ext_proto::EgressPolicy {
            policy: 2,
            gateway: Some(ext_proto::GatewayAddress {
                service: "no-namespace".to_string(),
                port: 0,
            }),
            ..Default::default()
        };
        assert!(EgressPolicy::try_from(pp).is_err());
    }

    #[test]
    fn egress_policies_from_proto_preserves_order() {
        let pp = ext_proto::EgressPolicies {
            egress_policies: vec![
                ext_proto::EgressPolicy {
                    namespaces: vec!["a".into()],
                    policy: 0,
                    ..Default::default()
                },
                ext_proto::EgressPolicy {
                    namespaces: vec!["b".into()],
                    policy: 1,
                    ..Default::default()
                },
            ],
        };
        let p = EgressPolicies::try_from(pp).unwrap();
        assert_eq!(p.policies.len(), 2);
        assert_eq!(p.policies[0].policy, EgressPolicyAction::Passthrough);
        assert_eq!(p.policies[1].policy, EgressPolicyAction::Deny);
    }

    #[test]
    fn egress_policies_from_proto_rejects_any_invalid_policy() {
        let pp = ext_proto::EgressPolicies {
            egress_policies: vec![
                ext_proto::EgressPolicy {
                    policy: 1,
                    ..Default::default()
                },
                ext_proto::EgressPolicy {
                    match_ports: vec!["invalid".into()],
                    ..Default::default()
                },
            ],
        };
        assert!(EgressPolicies::try_from(pp).is_err());
    }

    #[test]
    fn sandbox_egress_routing_reuses_workload_policy_types() {
        let routing = EgressPolicies::try_from(EgressRouting {
            routes: vec![
                egress_routing::Route {
                    action: egress_routing::Action::Gateway.into(),
                    match_cidrs: vec!["10.0.0.0/8".into(), "2001:db8::/32".into()],
                    match_ports: vec!["80".into(), "443".into()],
                    gateway: Some(egress_routing::GatewayAddress {
                        service: "egress.ns.svc.cluster.local".into(),
                        port: 0,
                    }),
                },
                egress_routing::Route::default(),
            ],
        })
        .unwrap();
        let legacy = EgressPolicy::try_from(ext_proto::EgressPolicy {
            policy: 2,
            match_cidrs: vec!["10.0.0.0/8".into(), "2001:db8::/32".into()],
            match_ports: vec!["80".into(), "443".into()],
            gateway: Some(ext_proto::GatewayAddress {
                service: "egress.ns.svc.cluster.local".into(),
                port: 0,
            }),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(routing.policies[0], legacy);
        assert_eq!(routing.policies[1].policy, EgressPolicyAction::Passthrough);
    }

    #[test]
    fn invalid_sandbox_egress_routes_are_rejected() {
        use egress_routing::{Action, GatewayAddress, Route};
        for route in [
            Route {
                action: 2,
                ..Default::default()
            },
            Route {
                action: Action::Gateway.into(),
                ..Default::default()
            },
            Route {
                match_cidrs: vec!["invalid".into()],
                ..Default::default()
            },
            Route {
                match_ports: vec!["0".into()],
                ..Default::default()
            },
            Route {
                match_ports: vec!["65536".into()],
                ..Default::default()
            },
            Route {
                gateway: Some(GatewayAddress {
                    service: "egress.ns".into(),
                    port: 15008,
                }),
                ..Default::default()
            },
            Route {
                action: Action::Gateway.into(),
                gateway: Some(GatewayAddress {
                    service: "invalid".into(),
                    port: 15008,
                }),
                ..Default::default()
            },
            Route {
                action: Action::Gateway.into(),
                gateway: Some(GatewayAddress {
                    service: "egress.ns".into(),
                    port: 65536,
                }),
                ..Default::default()
            },
        ] {
            assert!(
                EgressPolicies::try_from(EgressRouting {
                    routes: vec![Route::default(), route],
                })
                .is_err()
            );
        }
    }

    // ---- WorkloadMetadata::encode_labels -------------------------------

    #[test]
    fn encode_labels_empty_input() {
        let m = WorkloadMetadata {
            labels: HashMap::new(),
            ..Default::default()
        };
        // Base64 of empty bytes is empty string.
        assert_eq!(m.encode_labels(), "");
    }

    #[test]
    fn encode_labels_single_kv() {
        let mut labels = HashMap::new();
        labels.insert("app".to_string(), "v1".to_string());
        let m = WorkloadMetadata {
            labels,
            ..Default::default()
        };
        // base64("app=v1") == "YXBwPXYx"
        assert_eq!(m.encode_labels(), "YXBwPXYx");
    }

    #[test]
    fn encode_labels_is_deterministic_regardless_of_insert_order() {
        // Insertion order differs but key-sort makes the output identical.
        let mut a = HashMap::new();
        a.insert("b".to_string(), "2".to_string());
        a.insert("a".to_string(), "1".to_string());

        let mut b = HashMap::new();
        b.insert("a".to_string(), "1".to_string());
        b.insert("b".to_string(), "2".to_string());

        let ma = WorkloadMetadata {
            labels: a,
            ..Default::default()
        };
        let mb = WorkloadMetadata {
            labels: b,
            ..Default::default()
        };
        assert_eq!(ma.encode_labels(), mb.encode_labels());
        // base64("a=1,b=2") == "YT0xLGI9Mg=="
        assert_eq!(ma.encode_labels(), "YT0xLGI9Mg==");
    }

    // ---- XdsWorkloadExtension -> WorkloadExtension ----------------------------

    #[test]
    fn workload_extension_metadata() {
        let mut labels = HashMap::new();
        labels.insert("env".to_string(), "prod".to_string());
        let meta = WorkloadMetadata {
            labels,
            ..Default::default()
        };
        let any = any_of(WORKLOAD_METADATA_TYPE_URL, &meta);
        let ext = workload_ext("meta-ext", Some(any));

        match WorkloadExtension::try_from(ext).unwrap() {
            WorkloadExtension::WorkloadMetadata(m) => {
                assert_eq!(m.labels.get("env"), Some(&"prod".to_string()));
            }
            other => panic!("expected WorkloadMetadata, got {:?}", other),
        }
    }

    #[test]
    fn workload_extension_egress_policies() {
        let policies = ext_proto::EgressPolicies {
            egress_policies: vec![ext_proto::EgressPolicy {
                policy: 1,
                ..Default::default()
            }],
        };
        let any = any_of(DEFAULT_EGRESS_POLICIES_TYPE_URL, &policies);
        let ext = workload_ext("eg-ext", Some(any));

        match WorkloadExtension::try_from(ext).unwrap() {
            WorkloadExtension::EgressPolicies(p) => {
                assert_eq!(p.policies.len(), 1);
                assert_eq!(p.policies[0].policy, EgressPolicyAction::Deny);
            }
            other => panic!("expected EgressPolicies, got {:?}", other),
        }
    }

    #[test]
    fn workload_extension_unknown_type_url_falls_back_to_raw() {
        let any = Any {
            type_url: "type.googleapis.com/unknown.Thing".to_string(),
            value: vec![1, 2, 3],
        };
        let ext = workload_ext("unk", Some(any));

        match WorkloadExtension::try_from(ext).unwrap() {
            WorkloadExtension::Raw(r) => {
                assert_eq!(r.name, "unk");
                assert_eq!(
                    r.config_type_url.as_deref(),
                    Some("type.googleapis.com/unknown.Thing")
                );
                assert_eq!(r.config_raw.as_deref(), Some(&[1u8, 2, 3][..]));
            }
            other => panic!("expected Raw, got {:?}", other),
        }
    }

    #[test]
    fn workload_extension_metadata_with_corrupt_bytes_falls_back_to_raw() {
        // Right type_url, wrong bytes -> decode fails, we keep payload as Raw
        // so an operator can still inspect the malformed config.
        let any = Any {
            type_url: WORKLOAD_METADATA_TYPE_URL.to_string(),
            value: vec![0xff, 0xff, 0xff, 0xff],
        };
        let ext = workload_ext("bad-meta", Some(any));
        assert!(matches!(
            WorkloadExtension::try_from(ext).unwrap(),
            WorkloadExtension::Raw(_)
        ));
    }

    #[test]
    fn workload_extension_without_config_is_raw_with_none_fields() {
        let ext = workload_ext("nocfg", None);
        match WorkloadExtension::try_from(ext).unwrap() {
            WorkloadExtension::Raw(r) => {
                assert_eq!(r.name, "nocfg");
                assert!(r.config_type_url.is_none());
                assert!(r.config_raw.is_none());
            }
            other => panic!("expected Raw, got {:?}", other),
        }
    }
}
