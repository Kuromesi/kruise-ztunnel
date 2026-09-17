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

use super::*;
use crate::proxy::AuthorizationRejectionError;
use crate::rbac::{Connection, Direction};
use crate::state::{DemandProxyState, ProxyRbacContext};

const CONFIG: &str = include_str!("../../examples/sandbox.yaml");
const POLICY: &str = "namespaces/default/trafficPolicies/local-egress";

fn client(cfg: ConfigSource) -> LocalClient {
    LocalClient {
        cfg,
        state: Arc::new(RwLock::new(ProxyState::new(None))),
        cert_fetcher: Arc::new(NoCertFetcher()),
        local_node: None,
    }
}

fn proxy_state(client: &LocalClient) -> DemandProxyState {
    DemandProxyState::new(
        client.state.clone(),
        None,
        Default::default(),
        Default::default(),
        crate::test_helpers::helpers::test_proxy_metrics(),
    )
}

fn context(client: &LocalClient, port: u16) -> ProxyRbacContext {
    ProxyRbacContext {
        conn: Connection {
            src: "127.0.0.1:1234".parse().unwrap(),
            dst: std::net::SocketAddr::from(([192, 0, 2, 1], port)),
            src_identity: None,
            dst_network: strng::EMPTY,
            direction: Direction::Outbound,
        },
        workload: client
            .state
            .read()
            .unwrap()
            .workloads
            .find_uid(&"cluster1//v1/Pod/default/local".into())
            .unwrap(),
        sandbox: None,
    }
}

#[tokio::test]
async fn local_file_loads_sandbox_inline_and_shared_policies() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), CONFIG).unwrap();
    let client = client(ConfigSource::File(file.path().into()));
    LocalClient {
        cfg: client.cfg.clone(),
        state: client.state.clone(),
        cert_fetcher: client.cert_fetcher.clone(),
        local_node: client.local_node.clone(),
    }
    .run()
    .await
    .unwrap();
    let state = proxy_state(&client);
    let ctx = context(&client, 8080);
    let sandbox = state.fetch_sandbox(&ctx.workload).unwrap();
    assert_eq!(sandbox.uid.as_str(), "workload:local");
    assert_eq!(sandbox.traffic_policy_refs, vec![Strng::from(POLICY)]);
    assert_eq!(state.assert_rbac(&ctx).await, Ok(()));
    assert_eq!(state.assert_rbac(&context(&client, 8081)).await, Ok(()));
    assert_eq!(
        state.assert_rbac(&context(&client, 9999)).await,
        Err(AuthorizationRejectionError::ExplicitlyDenied(
            POLICY.into(),
            "rule-0".into()
        )),
    );
    let mut inbound = context(&client, 9999);
    inbound.conn.direction = Direction::Inbound;
    assert_eq!(state.assert_rbac(&inbound).await, Ok(()));
}

#[tokio::test]
async fn local_reload_replaces_resources_and_keeps_policy_subscribers() {
    let client = client(ConfigSource::Static(CONFIG.into()));
    let mut changes = client.state.read().unwrap().policies.subscribe();
    LocalClient {
        cfg: client.cfg.clone(),
        state: client.state.clone(),
        cert_fetcher: client.cert_fetcher.clone(),
        local_node: client.local_node.clone(),
    }
    .run()
    .await
    .unwrap();
    assert!(changes.has_changed().unwrap());
    changes.borrow_and_update();
    let state = proxy_state(&client);
    let ctx = context(&client, 8081);
    let mut yaml: serde_yaml::Value = serde_yaml::from_str(CONFIG).unwrap();
    yaml["policies"][POLICY]["egress"]["rules"][1]["action"] = "Deny".into();
    let mut config: LocalConfig = serde_yaml::from_value(yaml).unwrap();
    client.load_config(config.clone()).unwrap();
    assert!(changes.has_changed().unwrap());
    changes.borrow_and_update();
    assert_eq!(
        state.assert_rbac(&ctx).await,
        Err(AuthorizationRejectionError::ExplicitlyDenied(
            POLICY.into(),
            "rule-1".into()
        ))
    );
    // Inline ALLOW remains terminal ahead of a shared DENY.
    assert_eq!(state.assert_rbac(&context(&client, 8080)).await, Ok(()));

    config.policies.clear();
    client.load_config(config.clone()).unwrap();
    assert!(changes.has_changed().unwrap());
    changes.borrow_and_update();
    assert!(
        client
            .state
            .read()
            .unwrap()
            .policies
            .get(&POLICY.into())
            .is_none()
    );
    assert_eq!(
        state.assert_rbac(&ctx).await,
        Err(AuthorizationRejectionError::ExplicitlyDenied(
            POLICY.into(),
            "policy-unavailable".into()
        ))
    );
    assert_eq!(state.assert_rbac(&context(&client, 8080)).await, Ok(()));

    config.sandboxes.clear();
    client.load_config(config).unwrap();
    assert!(changes.has_changed().unwrap());
    changes.borrow_and_update();
    assert!(
        client
            .state
            .read()
            .unwrap()
            .sandboxes
            .get_by_workload(&ctx.workload.uid)
            .is_empty()
    );
    assert_eq!(state.assert_rbac(&ctx).await, Ok(()));
    client.load_config(LocalConfig::default()).unwrap();
    assert!(changes.has_changed().unwrap());
    assert!(
        client
            .state
            .read()
            .unwrap()
            .workloads
            .find_uid(&ctx.workload.uid)
            .is_none()
    );
}

#[test]
fn invalid_local_resources_preserve_the_previous_snapshot() {
    let client = client(ConfigSource::Static(CONFIG.into()));
    let config: LocalConfig = serde_yaml::from_str(CONFIG).unwrap();
    client.load_config(config.clone()).unwrap();
    let changes = client.state.read().unwrap().policies.subscribe();
    let before = serde_json::to_value(&*client.state.read().unwrap()).unwrap();
    for (name, change) in [
        (
            "zero inline port",
            (|c: &mut serde_yaml::Value| {
                c["sandboxes"][0]["trafficPolicy"]["egress"]["rules"][0]["ports"][0]["range"]["start"] =
                    0.into();
            }) as fn(&mut serde_yaml::Value),
        ),
        ("reversed shared port range", |c| {
            c["policies"][POLICY]["egress"]["rules"][0]["ports"][0]["range"]["end"] = 1.into();
        }),
        ("ICMP port constraint", |c| {
            c["policies"][POLICY]["egress"]["rules"][0]["ports"][0]["protocol"] = "ICMP".into();
        }),
        ("empty Sandbox uid", |c| {
            c["sandboxes"][0]["uid"] = "".into()
        }),
        ("empty Workload uid", |c| {
            c["sandboxes"][0]["workloadUid"] = "".into()
        }),
        ("duplicate policy reference", |c| {
            c["sandboxes"][0]["trafficPolicyRefs"]
                .as_sequence_mut()
                .unwrap()
                .push(POLICY.into());
        }),
        ("wildcard policy reference", |c| {
            c["sandboxes"][0]["trafficPolicyRefs"][0] = "*".into()
        }),
        ("duplicate Sandbox", |c| {
            let sandbox = c["sandboxes"][0].clone();
            c["sandboxes"].as_sequence_mut().unwrap().push(sandbox);
        }),
        ("empty policy name", |c| {
            let policy = c["policies"][POLICY].clone();
            c["policies"]
                .as_mapping_mut()
                .unwrap()
                .insert("".into(), policy);
        }),
        ("missing gateway", |c| {
            c["sandboxes"][0]["egressRouting"] =
                serde_yaml::from_str("policies: [{policy: Gateway}]").unwrap();
        }),
    ] {
        let mut invalid: serde_yaml::Value = serde_yaml::from_str(CONFIG).unwrap();
        change(&mut invalid);
        let invalid = serde_yaml::from_value(invalid).unwrap();
        assert!(client.load_config(invalid).is_err(), "{name}");
        assert_eq!(
            serde_json::to_value(&*client.state.read().unwrap()).unwrap(),
            before
        );
        assert!(!changes.has_changed().unwrap());
    }
}

#[test]
fn local_resource_yaml_round_trips_and_rejects_unknown_fields() {
    let mut config: LocalConfig = serde_yaml::from_str(CONFIG).unwrap();
    config.sandboxes[0].egress_routing = Some(
        serde_yaml::from_str(
            r#"
policies:
- policy: Gateway
  gateway:
    destination: default/egress.default.svc.cluster.local
    hboneMtlsPort: 15008
"#,
        )
        .unwrap(),
    );
    config.sandboxes[0].validate().unwrap();
    let yaml = serde_yaml::to_string(&config).unwrap();
    assert!(yaml.contains("action: Deny"));
    assert!(yaml.contains("protocol: TCP"));
    assert!(yaml.contains("policy: Gateway"));
    assert_eq!(serde_yaml::from_str::<LocalConfig>(&yaml).unwrap(), config);
    for invalid in [
        CONFIG.replace("action: Allow", "acton: Allow"),
        CONFIG.replace("action: Allow", "action: UNKNOWN"),
        CONFIG.replace("protocol: TCP", "protocol: UNKNOWN"),
        CONFIG.replace("end: 9999", "end: 65536"),
        CONFIG.replace("ports:", "portt:"),
        CONFIG.replace("trafficPolicyRefs:", "policyRefs:"),
        CONFIG.replace(
            "- action: Allow",
            "- action: Allow\n        sourceIps: [invalid-cidr]",
        ),
        "policies: [{name: legacy, action: Allow}]".into(),
    ] {
        assert!(serde_yaml::from_str::<LocalConfig>(&invalid).is_err());
    }
    serde_yaml::from_str::<LocalConfig>(include_str!("../../examples/localhost.yaml")).unwrap();
}
