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

//! iptables backend integration tests
//!
//! These tests require root privileges and a real Linux environment.
//! Run with: `sudo cargo test --test firewall_ipt_integration -- --ignored`

use std::ops::RangeInclusive;
use ztunnel::firewall::Backend;
use ztunnel::firewall::backend::ipt::IptBackend;
use ztunnel::firewall::types::{
    Direction, FirewallMatch, FirewallProtocol, FirewallRule, PortGroup, RuleAction, RuleSet,
};

async fn list_filter_chain(chain: &str) -> String {
    let output = tokio::process::Command::new("iptables")
        .args(["-t", "filter", "-S", chain])
        .output()
        .await
        .unwrap_or_else(|e| panic!("Failed to list {} rules: {}", chain, e));

    assert!(
        output.status.success(),
        "Failed to list {} rules: {}",
        chain,
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Helper to create a test rule with a single clause containing one match.
fn make_rule(
    name: &str,
    direction: Direction,
    match_source: Vec<&str>,
    match_dest: Vec<&str>,
    match_dports: Vec<RangeInclusive<u16>>,
    action: RuleAction,
    priority: i32,
) -> FirewallRule {
    let port_groups = if match_dports.is_empty() {
        vec![PortGroup {
            protocol: FirewallProtocol::NonTcp,
            ports: vec![],
        }]
    } else {
        vec![PortGroup {
            protocol: FirewallProtocol::NonTcp,
            ports: match_dports,
        }]
    };
    let source_ips = match_source
        .into_iter()
        .map(|s| s.parse().unwrap())
        .collect();
    let dest_ips = match_dest.into_iter().map(|s| s.parse().unwrap()).collect();
    FirewallRule {
        name: name.into(),
        action,
        direction,
        priority,
        clauses: vec![vec![FirewallMatch {
            source_ips,
            dest_ips,
            port_groups,
        }]],
    }
}

/// Test full lifecycle: init → apply → verify → cleanup
#[tokio::test]
#[ignore] // Requires root privileges
async fn test_full_lifecycle() {
    // 1. Initialize chains
    let backend = IptBackend::new();
    backend
        .init()
        .await
        .expect("Failed to initialize firewall chains");

    // 2. Apply ruleset
    let ruleset = RuleSet {
        rules: vec![
            make_rule(
                "deny-ssh",
                Direction::Inbound,
                vec![],
                vec![],
                vec![22..=22],
                RuleAction::Deny,
                10,
            ),
            make_rule(
                "allow-http",
                Direction::Outbound,
                vec![],
                vec![],
                vec![80..=80, 443..=443],
                RuleAction::Allow,
                5,
            ),
        ],
        ..Default::default()
    };

    backend
        .apply(&ruleset)
        .await
        .expect("Failed to apply ruleset");

    // 3. Verify rules exist
    let stdout = list_filter_chain("ISTIO_FW_FILTER_IN").await;
    assert!(
        stdout.contains("-p udp -m udp --dport 22 -j REJECT")
            && stdout.contains("-p sctp -m sctp --dport 22 -j REJECT"),
        "SSH deny rule should exist in ISTIO_FW_FILTER_IN"
    );

    let stdout = list_filter_chain("ISTIO_FW_FILTER_OUT").await;
    assert!(
        stdout.contains("-p udp -m multiport --dports 80,443 -j ACCEPT")
            && stdout.contains("-p sctp -m multiport --dports 80,443 -j ACCEPT"),
        "HTTP allow rule should exist in ISTIO_FW_FILTER_OUT"
    );

    // 4. Cleanup
    backend
        .cleanup()
        .await
        .expect("Failed to cleanup firewall chains");

    // 5. Verify chains are empty
    let stdout = list_filter_chain("ISTIO_FW_FILTER_IN").await;
    assert!(
        !stdout.contains("--dport 22"),
        "Rules should be cleared after cleanup"
    );
}

/// Test idempotent apply: apply twice, verify no rule duplication
#[tokio::test]
#[ignore] // Requires root privileges
async fn test_idempotent_apply() {
    let backend = IptBackend::new();
    backend
        .init()
        .await
        .expect("Failed to initialize firewall chains");

    let ruleset = RuleSet {
        rules: vec![make_rule(
            "deny-internal",
            Direction::Inbound,
            vec!["10.0.0.0/8"],
            vec![],
            vec![80..=80],
            RuleAction::Deny,
            0,
        )],
        ..Default::default()
    };

    // Apply first time
    backend
        .apply(&ruleset)
        .await
        .expect("Failed to apply ruleset (first time)");

    // Apply second time (should be idempotent)
    backend
        .apply(&ruleset)
        .await
        .expect("Failed to apply ruleset (second time)");

    // Verify the UDP/SCTP-expanded REJECT rules are not duplicated.
    let stdout = list_filter_chain("ISTIO_FW_FILTER_IN").await;
    let reject_count = stdout.matches("-j REJECT").count();

    assert_eq!(
        reject_count, 2,
        "Should have exactly two REJECT rules (udp + sctp), not duplicated"
    );

    backend
        .cleanup()
        .await
        .expect("Failed to cleanup firewall chains");
}

/// Test priority ordering: verify rules are applied in priority order
#[tokio::test]
#[ignore] // Requires root privileges
async fn test_priority_ordering() {
    let backend = IptBackend::new();
    backend
        .init()
        .await
        .expect("Failed to initialize firewall chains");

    let ruleset = RuleSet {
        rules: vec![
            make_rule(
                "low-priority",
                Direction::Inbound,
                vec!["10.0.0.0/8"],
                vec![],
                vec![80..=80],
                RuleAction::Deny,
                10,
            ),
            make_rule(
                "high-priority",
                Direction::Inbound,
                vec!["192.168.0.0/16"],
                vec![],
                vec![443..=443],
                RuleAction::Deny,
                5,
            ),
        ],
        ..Default::default()
    };

    backend
        .apply(&ruleset)
        .await
        .expect("Failed to apply ruleset");

    // Verify rules are in correct order
    let stdout = list_filter_chain("ISTIO_FW_FILTER_IN").await;

    // high-priority (192.168.0.0/16) should appear before low-priority (10.0.0.0/8)
    let high_pos = stdout
        .find("192.168.0.0/16")
        .expect("high-priority rule should exist");
    let low_pos = stdout
        .find("10.0.0.0/8")
        .expect("low-priority rule should exist");

    assert!(
        high_pos < low_pos,
        "High priority rule (priority=5) should appear before low priority rule (priority=10)"
    );

    backend
        .cleanup()
        .await
        .expect("Failed to cleanup firewall chains");
}

/// Test multi-CIDR expansion: verify cartesian product generates correct number of rules
#[tokio::test]
#[ignore] // Requires root privileges
async fn test_multi_cidr_expansion() {
    let backend = IptBackend::new();
    backend
        .init()
        .await
        .expect("Failed to initialize firewall chains");

    let ruleset = RuleSet {
        rules: vec![make_rule(
            "deny-multi",
            Direction::Outbound,
            vec!["10.0.0.0/8", "172.16.0.0/12"],
            vec!["192.168.1.0/24", "192.168.2.0/24"],
            vec![443..=443],
            RuleAction::Deny,
            0,
        )],
        ..Default::default()
    };

    backend
        .apply(&ruleset)
        .await
        .expect("Failed to apply ruleset");

    // Verify 8 rules exist (2 sources × 2 destinations × udp/sctp)
    let stdout = list_filter_chain("ISTIO_FW_FILTER_OUT").await;
    let reject_count = stdout.matches("-j REJECT").count();

    assert_eq!(
        reject_count, 8,
        "Should have 8 REJECT rules (2 sources × 2 destinations × udp/sctp)"
    );

    backend
        .cleanup()
        .await
        .expect("Failed to cleanup firewall chains");
}
