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

//! iptables backend implementation
//!
//! Uses `*filter` table with dedicated chains:
//! - ISTIO_FW_FILTER_IN: inbound policy rules (hook INPUT)
//! - ISTIO_FW_FILTER_OUT: outbound policy rules (hook OUTPUT)
//!
//! TCP rules are handled by ztunnel user-space proxy (L4/L7 RBAC).
//! Only non-TCP protocols (UDP, ICMP, etc.) are translated to netfilter rules.
//!
//! Deny action uses REJECT (sends ICMP port unreachable / TCP RST).
//! Allow action uses ACCEPT.
//!
//! Infrastructure rules (always first):
//! - conntrack bypass: ESTABLISHED,RELATED connections accepted
//! - loopback bypass: lo interface traffic accepted
//!
//! Apply uses `iptables-restore --noflush` with explicit `-F` to flush
//! only ISTIO_FW_* chains, preserving hijack module chains.

use anyhow::Context;
use async_trait::async_trait;
use tracing::{debug, info, warn};

use super::super::types::{
    Direction, FirewallMatch, FirewallProtocol, FirewallRule, PortGroup, RuleAction, RuleSet,
};
use super::Backend;

/// A fully expanded single iptables match (result of clause cartesian expansion).
struct FlatMatch {
    source: Option<ipnet::IpNet>,
    dest: Option<ipnet::IpNet>,
    proto_str: String,
    port_suffix: String,
}

/// iptables backend implementation
pub struct IptBackend {
    iptables_bin: String,
    restore_bin: String,
    netns_path: Option<String>,
    proxy_mark: Option<u32>,
    dns_proxy: bool,
    workload_name: Option<String>,
    workload_namespace: Option<String>,
}

impl Default for IptBackend {
    fn default() -> Self {
        Self {
            iptables_bin: "iptables".to_string(),
            restore_bin: "iptables-restore".to_string(),
            netns_path: None,
            proxy_mark: None,
            dns_proxy: false,
            workload_name: None,
            workload_namespace: None,
        }
    }
}

impl IptBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_binaries(
        mut self,
        iptables_bin: impl Into<String>,
        restore_bin: impl Into<String>,
    ) -> Self {
        self.iptables_bin = iptables_bin.into();
        self.restore_bin = restore_bin.into();
        self
    }

    pub fn in_netns(mut self, netns_path: impl Into<String>) -> Self {
        self.netns_path = Some(netns_path.into());
        self
    }

    pub fn skip_mark(mut self, proxy_mark: u32) -> Self {
        self.proxy_mark = Some(proxy_mark);
        self
    }

    pub fn dns_proxy(mut self, enabled: bool) -> Self {
        self.dns_proxy = enabled;
        self
    }

    pub fn with_workload_info(
        mut self,
        name: impl Into<String>,
        namespace: impl Into<String>,
    ) -> Self {
        self.workload_name = Some(name.into());
        self.workload_namespace = Some(namespace.into());
        self
    }

    fn workload_label(&self) -> String {
        super::format_workload_label(&self.workload_name, &self.workload_namespace)
    }

    fn make_cmd(&self, program: &str) -> tokio::process::Command {
        super::make_nsenter_cmd(&self.netns_path, program)
    }

    /// Render RuleSet to iptables-restore format.
    ///
    /// All rules go into the `*filter` table using INPUT (inbound) and OUTPUT (outbound) hooks.
    pub fn render_ruleset(&self, ruleset: &RuleSet) -> String {
        let mut lines = vec!["*filter".to_string()];

        if !ruleset.inline_rules.is_empty() {
            for chain in ["ISTIO_FW_INLINE_IN", "ISTIO_FW_INLINE_OUT"] {
                lines.push(format!(":{chain} - [0:0]"));
            }
            for chain in ["ISTIO_FW_INLINE_IN", "ISTIO_FW_INLINE_OUT"] {
                lines.push(format!("-F {chain}"));
            }
        }
        lines.push("-F ISTIO_FW_FILTER_IN".into());
        lines.push("-F ISTIO_FW_FILTER_OUT".into());

        lines.push(
            "-A ISTIO_FW_FILTER_IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
                .to_string(),
        );
        lines.push(
            "-A ISTIO_FW_FILTER_OUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
                .to_string(),
        );
        lines.push("-A ISTIO_FW_FILTER_IN -i lo -j ACCEPT".to_string());
        lines.push("-A ISTIO_FW_FILTER_OUT -o lo -j ACCEPT".to_string());
        if let Some(mark) = self.proxy_mark {
            lines.push(format!(
                "-A ISTIO_FW_FILTER_OUT -m mark --mark {} -j RETURN",
                mark
            ));
            if self.dns_proxy {
                // In inpod mode with DNS proxy enabled, nat/OUTPUT REDIRECTs DNS
                // (UDP:53) to local port 15053. After REDIRECT, the packet's dst is
                // rewritten, so normal `-d <kube-dns>` rules won't match. Bypass
                // redirected DNS using conntrack original destination port matching.
                lines.push(
                    "-A ISTIO_FW_FILTER_OUT -p udp -m conntrack --ctorigdstport 53 --ctdir ORIGINAL -j ACCEPT"
                        .to_string(),
                );
            }
        } else {
            lines.push("-A ISTIO_FW_FILTER_OUT -m owner --uid-owner 1337 -j RETURN".to_string());
            lines.push("-A ISTIO_FW_FILTER_OUT -m owner --gid-owner 1337 -j RETURN".to_string());
        }

        if !ruleset.inline_rules.is_empty() {
            lines.push("-A ISTIO_FW_FILTER_IN ! -p tcp -j ISTIO_FW_INLINE_IN".into());
            lines.push("-A ISTIO_FW_FILTER_OUT ! -p tcp -j ISTIO_FW_INLINE_OUT".into());
            let mut inline = ruleset.inline_rules.iter().collect::<Vec<_>>();
            inline.sort_by_key(|rule| rule.priority);
            for rule in inline {
                let chain = match rule.direction {
                    Direction::Inbound => "ISTIO_FW_INLINE_IN",
                    Direction::Outbound => "ISTIO_FW_INLINE_OUT",
                };
                let action = match rule.action {
                    RuleAction::Allow => "RETURN",
                    RuleAction::Deny => "REJECT",
                };
                lines.extend(Self::render_rule_in_chain(rule, chain, action));
            }
        }

        let mut sorted_rules = ruleset.rules.clone();
        // Stable sorting preserves namespace/name order and rule declaration order.
        sorted_rules.sort_by_key(|rule| rule.priority);

        for rule in &sorted_rules {
            lines.extend(Self::render_rule(rule));
        }

        if ruleset.policy_attached {
            lines.push("-A ISTIO_FW_FILTER_IN ! -p tcp -j REJECT".to_string());
            lines.push("-A ISTIO_FW_FILTER_OUT ! -p tcp -j REJECT".to_string());
        }

        lines.push("COMMIT".to_string());

        lines.join("\n")
    }

    /// Render port ranges into one or more iptables --dport / multiport suffixes.
    /// iptables multiport supports max 15 entries (each range counts as 2).
    fn render_port_suffixes(ports: &[std::ops::RangeInclusive<u16>]) -> Vec<String> {
        if ports.is_empty() {
            return vec![String::new()];
        }
        if ports.len() == 1 {
            let range = &ports[0];
            if range.start() == range.end() {
                return vec![format!("--dport {}", range.start())];
            } else {
                return vec![format!("--dport {}:{}", range.start(), range.end())];
            }
        }

        let mut suffixes = Vec::new();
        let mut chunk = Vec::new();
        let mut chunk_weight = 0usize;

        for range in ports {
            let (port, weight) = if range.start() == range.end() {
                (range.start().to_string(), 1usize)
            } else {
                (format!("{}:{}", range.start(), range.end()), 2usize)
            };

            if !chunk.is_empty() && chunk_weight + weight > 15 {
                suffixes.push(Self::format_port_suffix(&chunk));
                chunk.clear();
                chunk_weight = 0;
            }

            chunk.push(port);
            chunk_weight += weight;
        }

        if !chunk.is_empty() {
            suffixes.push(Self::format_port_suffix(&chunk));
        }

        suffixes
    }

    fn format_port_suffix(ports: &[String]) -> String {
        if ports.len() == 1 {
            format!("--dport {}", ports[0])
        } else {
            format!("-m multiport --dports {}", ports.join(","))
        }
    }

    /// Render a single FirewallRule into one or more iptables rule lines.
    ///
    /// The rule's `clauses` (AND'd) are expanded via cartesian product.
    /// Within each clause, OR'd matches are also expanded (one iptables rule per combination).
    fn render_rule(rule: &FirewallRule) -> Vec<String> {
        let chain = match rule.direction {
            Direction::Inbound => "ISTIO_FW_FILTER_IN",
            Direction::Outbound => "ISTIO_FW_FILTER_OUT",
        };

        let action_str = match rule.action {
            RuleAction::Allow => "ACCEPT",
            RuleAction::Deny => "REJECT",
        };

        Self::render_rule_in_chain(rule, chain, action_str)
    }

    fn render_rule_in_chain(rule: &FirewallRule, chain: &str, action_str: &str) -> Vec<String> {
        // Flatten clauses into a list of flat match combinations via cartesian product.
        // Each FlatMatch is one concrete (src, dst, proto, port) tuple.
        let flat_matches = Self::flatten_clauses(&rule.clauses);

        let mut lines = Vec::new();
        let mut ipv6_skipped = 0usize;
        for flat in flat_matches {
            if flat.source.is_some_and(|s| s.network().is_ipv6()) {
                ipv6_skipped += 1;
                continue;
            }
            if flat.dest.is_some_and(|d| d.network().is_ipv6()) {
                ipv6_skipped += 1;
                continue;
            }

            let mut parts = vec![format!("-A {}", chain)];
            if let Some(cidr) = flat.source {
                parts.push(format!("-s {}", cidr));
            }
            if let Some(cidr) = flat.dest {
                parts.push(format!("-d {}", cidr));
            }
            parts.push(flat.proto_str);
            if !flat.port_suffix.is_empty() {
                parts.push(flat.port_suffix);
            }
            parts.push(format!("-j {}", action_str));
            lines.push(parts.join(" "));
        }

        if ipv6_skipped > 0 && lines.is_empty() {
            warn!(
                "FirewallRule '{}' produced no iptables rules (all {} match(es) were IPv6, iptables is IPv4 only)",
                rule.name, ipv6_skipped
            );
        }

        debug!(
            "Rendered FirewallRule '{}' (direction={:?}, priority={}, action={:?}) -> {} iptables rules",
            rule.name,
            rule.direction,
            rule.priority,
            rule.action,
            lines.len()
        );

        lines
    }

    /// Expand the clause structure into a flat list of match combinations.
    ///
    /// Clauses are AND'd → cartesian product across clauses.
    /// Within a clause, matches are OR'd → each generates independent rules.
    ///
    /// Unlike the nft backend (which keeps multiple IPs as Vec and renders them
    /// as nftables sets), iptables only supports one value per field per rule,
    /// so this function fully expands src × dst × port into scalar FlatMatch entries.
    ///
    /// Example:
    ///   clause A: [{src: [10.0.0.1, 10.0.0.2]}]
    ///   clause B: [{port: tcp/80}]
    ///
    ///   init:      [{}]
    ///   × clause A → [{src:10.0.0.1}, {src:10.0.0.2}]        (IPs expanded)
    ///   × clause B → [{src:10.0.0.1, port:tcp/80}, {src:10.0.0.2, port:tcp/80}]
    ///
    /// INVARIANT: Istio's control plane guarantees that different clauses operate
    /// on different dimensions (one clause for source IPs, another for ports, etc.).
    /// If two clauses both specify the same dimension, the later clause's value
    /// replaces the earlier one — acceptable because the control plane never
    /// generates such overlap.
    fn flatten_clauses(clauses: &[Vec<FirewallMatch>]) -> Vec<FlatMatch> {
        // Start with one empty combination
        let mut combinations: Vec<FlatMatch> = vec![FlatMatch {
            source: None,
            dest: None,
            proto_str: "! -p tcp".to_string(),
            port_suffix: String::new(),
        }];

        for clause in clauses {
            let mut expanded = Vec::new();
            for existing in &combinations {
                for fw_match in clause {
                    // Expand source IPs
                    let sources: Vec<Option<ipnet::IpNet>> = if fw_match.source_ips.is_empty() {
                        vec![existing.source]
                    } else {
                        fw_match.source_ips.iter().map(|ip| Some(*ip)).collect()
                    };

                    // Expand dest IPs
                    let dests: Vec<Option<ipnet::IpNet>> = if fw_match.dest_ips.is_empty() {
                        vec![existing.dest]
                    } else {
                        fw_match.dest_ips.iter().map(|ip| Some(*ip)).collect()
                    };

                    // Expand port groups into (proto_str, port_suffix) pairs.
                    // If this match has no port restriction (NonTcp with empty ports),
                    // preserve the existing proto from previous clauses rather than
                    // overwriting it — the AND semantics require all clause conditions
                    // to hold simultaneously.
                    let is_no_port_restriction = fw_match.port_groups.is_empty()
                        || (fw_match.port_groups.len() == 1
                            && fw_match.port_groups[0].protocol == FirewallProtocol::NonTcp
                            && fw_match.port_groups[0].ports.is_empty());

                    let proto_ports = if is_no_port_restriction {
                        vec![(existing.proto_str.clone(), existing.port_suffix.clone())]
                    } else {
                        Self::expand_port_groups(&fw_match.port_groups)
                    };

                    for src in &sources {
                        for dst in &dests {
                            for (proto_str, port_suffix) in &proto_ports {
                                expanded.push(FlatMatch {
                                    source: *src,
                                    dest: *dst,
                                    proto_str: proto_str.clone(),
                                    port_suffix: port_suffix.clone(),
                                });
                            }
                        }
                    }
                }
            }
            combinations = expanded;
        }

        combinations
    }

    /// Expand port_groups into (protocol_flag, port_suffix) pairs for iptables.
    fn expand_port_groups(port_groups: &[PortGroup]) -> Vec<(String, String)> {
        let mut result = Vec::new();

        for group in port_groups {
            match group.protocol {
                FirewallProtocol::NonTcp => {
                    if group.ports.is_empty() {
                        result.push(("! -p tcp".to_string(), String::new()));
                    } else {
                        let suffixes = Self::render_port_suffixes(&group.ports);
                        for s in &suffixes {
                            result.push(("-p udp".to_string(), s.clone()));
                        }
                        for s in &suffixes {
                            result.push(("-p sctp".to_string(), s.clone()));
                        }
                    }
                }
                FirewallProtocol::Udp => {
                    let suffixes = Self::render_port_suffixes(&group.ports);
                    for s in suffixes {
                        result.push(("-p udp".to_string(), s));
                    }
                }
                FirewallProtocol::Sctp => {
                    let suffixes = Self::render_port_suffixes(&group.ports);
                    for s in suffixes {
                        result.push(("-p sctp".to_string(), s));
                    }
                }
                FirewallProtocol::Icmp => {
                    result.push(("-p icmp".to_string(), String::new()));
                }
            }
        }

        result
    }

    async fn do_init(&self) -> anyhow::Result<()> {
        for (chain, hook_chain) in [
            ("ISTIO_FW_FILTER_IN", "INPUT"),
            ("ISTIO_FW_FILTER_OUT", "OUTPUT"),
        ] {
            let output = self
                .make_cmd(&self.iptables_bin)
                .args(["-t", "filter", "-N", chain])
                .output()
                .await
                .context(format!("Failed to create {} chain", chain))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("Chain already exists") {
                    anyhow::bail!("Failed to create {} chain: {}", chain, stderr);
                }
            }

            let check = self
                .make_cmd(&self.iptables_bin)
                .args(["-t", "filter", "-C", hook_chain, "-j", chain])
                .output()
                .await
                .context(format!("Failed to check {} jump rule", chain))?;
            if !check.status.success() {
                let output = self
                    .make_cmd(&self.iptables_bin)
                    .args(["-t", "filter", "-I", hook_chain, "1", "-j", chain])
                    .output()
                    .await
                    .context(format!("Failed to insert {} jump rule", chain))?;
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    anyhow::bail!("Failed to insert {} jump rule: {}", chain, stderr);
                }
            }
        }

        info!("Initialized firewall chains and jump rules");
        Ok(())
    }
}

#[async_trait]
impl Backend for IptBackend {
    async fn init(&self) -> anyhow::Result<()> {
        self.do_init().await
    }

    async fn apply(&self, ruleset: &RuleSet) -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt;

        let script = self.render_ruleset(ruleset);
        debug!(workload = %self.workload_label(), "Applying iptables ruleset:\n{}", script);

        let mut child = self
            .make_cmd(&self.restore_bin)
            .arg("--noflush")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context("Failed to spawn iptables-restore")?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(script.as_bytes())
                .await
                .context("Failed to write to iptables-restore stdin")?;
            drop(stdin);
        }

        let output =
            tokio::time::timeout(std::time::Duration::from_secs(30), child.wait_with_output())
                .await
                .context("iptables-restore timed out")?
                .context("Failed to wait for iptables-restore")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("iptables-restore failed: {}", stderr);
        }

        info!(
            workload = %self.workload_label(),
            "Successfully applied {} firewall rules",
            ruleset.rules.len()
        );
        Ok(())
    }

    async fn cleanup(&self) -> anyhow::Result<()> {
        for chain in ["ISTIO_FW_FILTER_IN", "ISTIO_FW_FILTER_OUT"] {
            let output = self
                .make_cmd(&self.iptables_bin)
                .args(["-t", "filter", "-F", chain])
                .output()
                .await
                .context(format!("Failed to flush {} chain", chain))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!("Failed to flush {} chain: {}", chain, stderr);
            }
        }

        info!(workload = %self.workload_label(), "Cleaned up firewall rules");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// Compare rendered output against golden file
    fn assert_golden(actual: &str, golden_name: &str) {
        let golden_path = format!(
            "src/firewall/backend/testdata/{}.iptables-restore",
            golden_name
        );
        let expected = std::fs::read_to_string(&golden_path)
            .unwrap_or_else(|e| panic!("Failed to read golden file {}: {}", golden_path, e));

        // Trim trailing whitespace for comparison
        let actual_trimmed = actual.trim_end();
        let expected_trimmed = expected.trim_end();

        assert_eq!(
            actual_trimmed, expected_trimmed,
            "\nRendered output doesn't match golden file '{}'\n\
             To update golden file, run:\n\
             cargo test golden_files -- --nocapture 2>&1 | grep -A 1000 'UPDATE GOLDEN' > {}\n",
            golden_path, golden_path
        );
    }

    fn make_rule(
        name: &str,
        direction: Direction,
        match_source: Vec<&str>,
        match_dest: Vec<&str>,
        protocol: FirewallProtocol,
        match_dports: Vec<std::ops::RangeInclusive<u16>>,
        action: RuleAction,
    ) -> FirewallRule {
        let source_ips: Vec<ipnet::IpNet> = match_source
            .into_iter()
            .map(|s| ipnet::IpNet::from_str(s).unwrap())
            .collect();
        let dest_ips: Vec<ipnet::IpNet> = match_dest
            .into_iter()
            .map(|s| ipnet::IpNet::from_str(s).unwrap())
            .collect();
        FirewallRule {
            name: name.into(),
            action,
            direction,
            priority: 0,
            clauses: vec![vec![FirewallMatch {
                source_ips,
                dest_ips,
                port_groups: vec![PortGroup {
                    protocol,
                    ports: match_dports,
                }],
            }]],
        }
    }

    // ========== Golden file tests ==========

    #[test]
    fn test_golden_empty_ruleset() {
        let ruleset = RuleSet {
            rules: vec![],
            ..Default::default()
        };
        let rendered = IptBackend::new().render_ruleset(&ruleset);
        assert_golden(&rendered, "empty_ruleset");
    }

    #[test]
    fn test_golden_single_inbound_deny() {
        let ruleset = RuleSet {
            rules: vec![make_rule(
                "deny-inbound",
                Direction::Inbound,
                vec!["10.0.0.0/8"],
                vec![],
                FirewallProtocol::NonTcp,
                vec![80..=80],
                RuleAction::Deny,
            )],
            ..Default::default()
        };
        let rendered = IptBackend::new().render_ruleset(&ruleset);
        assert_golden(&rendered, "single_inbound_deny");
    }

    #[test]
    fn test_golden_multi_cidr_cartesian() {
        let ruleset = RuleSet {
            rules: vec![make_rule(
                "multi-cidr-test",
                Direction::Inbound,
                vec!["10.0.0.0/8", "172.16.0.0/12"],
                vec!["192.168.1.0/24", "192.168.2.0/24"],
                FirewallProtocol::NonTcp,
                vec![443..=443],
                RuleAction::Deny,
            )],
            ..Default::default()
        };
        let rendered = IptBackend::new().render_ruleset(&ruleset);
        assert_golden(&rendered, "multi_cidr_cartesian");
    }

    #[test]
    fn test_golden_priority_ordering() {
        let mut rule1 = make_rule(
            "low-priority",
            Direction::Inbound,
            vec!["10.0.0.0/8"],
            vec![],
            FirewallProtocol::NonTcp,
            vec![80..=80],
            RuleAction::Deny,
        );
        rule1.priority = 10;

        let mut rule2 = make_rule(
            "high-priority",
            Direction::Inbound,
            vec!["192.168.0.0/16"],
            vec![],
            FirewallProtocol::NonTcp,
            vec![443..=443],
            RuleAction::Deny,
        );
        rule2.priority = 5;

        let mut rule3 = make_rule(
            "outbound-allow",
            Direction::Outbound,
            vec![],
            vec!["172.16.0.0/12"],
            FirewallProtocol::NonTcp,
            vec![8080..=8080],
            RuleAction::Allow,
        );
        rule3.priority = 20;

        let ruleset = RuleSet {
            rules: vec![rule1, rule2, rule3],
            ..Default::default()
        };
        let rendered = IptBackend::new().render_ruleset(&ruleset);
        assert_golden(&rendered, "priority_ordering");
    }

    #[test]
    fn test_golden_port_range_and_multiport() {
        let ruleset = RuleSet {
            rules: vec![
                make_rule(
                    "port-range-rule",
                    Direction::Inbound,
                    vec![],
                    vec![],
                    FirewallProtocol::NonTcp,
                    vec![8000..=8080],
                    RuleAction::Deny,
                ),
                make_rule(
                    "multi-port-rule",
                    Direction::Outbound,
                    vec![],
                    vec![],
                    FirewallProtocol::NonTcp,
                    vec![80..=80, 443..=443, 9000..=9100],
                    RuleAction::Allow,
                ),
            ],
            ..Default::default()
        };
        let rendered = IptBackend::new().render_ruleset(&ruleset);
        assert_golden(&rendered, "port_range_and_multiport");
    }

    #[test]
    fn test_golden_dedicated_default_deny() {
        let ruleset = RuleSet {
            rules: vec![make_rule(
                "allow-dns-out",
                Direction::Outbound,
                vec![],
                vec!["8.8.8.0/24"],
                FirewallProtocol::NonTcp,
                vec![53..=53],
                RuleAction::Allow,
            )],
            inline_rules: Vec::new(),
            policy_attached: true,
        };
        let rendered = IptBackend::new().render_ruleset(&ruleset);
        assert_golden(&rendered, "dedicated_default_deny");
    }

    #[test]
    fn test_golden_icmp() {
        let rule = FirewallRule {
            name: "icmp-in".into(),
            action: RuleAction::Deny,
            direction: Direction::Inbound,
            priority: 0,
            clauses: vec![vec![FirewallMatch {
                source_ips: vec!["10.0.0.0/8".parse().unwrap()],
                dest_ips: vec![],
                port_groups: vec![PortGroup {
                    protocol: FirewallProtocol::Icmp,
                    ports: vec![],
                }],
            }]],
        };
        let rendered = IptBackend::new().render_ruleset(&RuleSet {
            rules: vec![rule],
            ..Default::default()
        });
        assert_golden(&rendered, "icmp");
    }

    #[test]
    fn test_golden_ipv6_skipped() {
        let rule = FirewallRule {
            name: "ipv6-skipped".into(),
            action: RuleAction::Deny,
            direction: Direction::Inbound,
            priority: 0,
            clauses: vec![vec![FirewallMatch {
                source_ips: vec!["fd00::/8".parse().unwrap()],
                dest_ips: vec![],
                port_groups: vec![PortGroup {
                    protocol: FirewallProtocol::Udp,
                    ports: vec![53..=53],
                }],
            }]],
        };
        let rendered = IptBackend::new().render_ruleset(&RuleSet {
            rules: vec![rule],
            ..Default::default()
        });
        assert_golden(&rendered, "ipv6_skipped");
    }

    #[test]
    fn test_golden_multi_clause_cartesian() {
        // Two AND'd clauses: source clause (2 OR'd IPs) × port clause (2 OR'd ports)
        // Should expand to 2 sources × 2 ports × 2 protocols (udp+sctp) = 8 rules
        let rule = FirewallRule {
            name: "multi-clause".into(),
            action: RuleAction::Deny,
            direction: Direction::Inbound,
            priority: 0,
            clauses: vec![
                // Clause 0: 2 OR'd source matches
                vec![
                    FirewallMatch {
                        source_ips: vec!["10.0.0.0/8".parse().unwrap()],
                        dest_ips: vec![],
                        port_groups: vec![PortGroup {
                            protocol: FirewallProtocol::NonTcp,
                            ports: vec![],
                        }],
                    },
                    FirewallMatch {
                        source_ips: vec!["172.16.0.0/12".parse().unwrap()],
                        dest_ips: vec![],
                        port_groups: vec![PortGroup {
                            protocol: FirewallProtocol::NonTcp,
                            ports: vec![],
                        }],
                    },
                ],
                // Clause 1: 2 OR'd port matches
                vec![
                    FirewallMatch {
                        source_ips: vec![],
                        dest_ips: vec![],
                        port_groups: vec![PortGroup {
                            protocol: FirewallProtocol::NonTcp,
                            ports: vec![53..=53],
                        }],
                    },
                    FirewallMatch {
                        source_ips: vec![],
                        dest_ips: vec![],
                        port_groups: vec![PortGroup {
                            protocol: FirewallProtocol::NonTcp,
                            ports: vec![80..=80],
                        }],
                    },
                ],
            ],
        };

        let ruleset = RuleSet {
            rules: vec![rule],
            ..Default::default()
        };
        let rendered = IptBackend::new().render_ruleset(&ruleset);
        assert_golden(&rendered, "multi_clause_cartesian");
    }

    #[test]
    fn test_golden_multi_clause_source_and_port() {
        // Clause 0: source IPs (no port restriction)
        // Clause 1: port restriction (no source IPs)
        // Verifies that source-only clause does NOT overwrite port from previous clause.
        // This is the bug that caused DNS (UDP:53) to be blocked — the source clause
        // would overwrite the port clause's `--dport 53` with bare `! -p tcp`.
        let rule = FirewallRule {
            name: "src-and-port".into(),
            action: RuleAction::Allow,
            direction: Direction::Inbound,
            priority: 0,
            clauses: vec![
                // Clause 0: port 53 (NonTcp)
                vec![FirewallMatch {
                    source_ips: vec![],
                    dest_ips: vec![],
                    port_groups: vec![PortGroup {
                        protocol: FirewallProtocol::NonTcp,
                        ports: vec![53..=53],
                    }],
                }],
                // Clause 1: 2 OR'd sources, no port restriction
                vec![
                    FirewallMatch {
                        source_ips: vec!["10.0.0.0/8".parse().unwrap()],
                        dest_ips: vec![],
                        port_groups: vec![PortGroup {
                            protocol: FirewallProtocol::NonTcp,
                            ports: vec![],
                        }],
                    },
                    FirewallMatch {
                        source_ips: vec!["172.16.0.0/12".parse().unwrap()],
                        dest_ips: vec![],
                        port_groups: vec![PortGroup {
                            protocol: FirewallProtocol::NonTcp,
                            ports: vec![],
                        }],
                    },
                ],
            ],
        };

        let ruleset = RuleSet {
            rules: vec![rule],
            ..Default::default()
        };
        let rendered = IptBackend::new().render_ruleset(&ruleset);
        assert_golden(&rendered, "multi_clause_source_and_port");
    }

    // ========== Inpod mode golden file tests ==========

    fn inpod_backend() -> IptBackend {
        IptBackend::new().skip_mark(1337).dns_proxy(true)
    }

    #[test]
    fn test_golden_inpod_empty_ruleset() {
        let ruleset = RuleSet::default();
        let rendered = inpod_backend().render_ruleset(&ruleset);
        assert_golden(&rendered, "inpod_empty_ruleset");
    }

    #[test]
    fn test_golden_inpod_single_inbound_deny() {
        let ruleset = RuleSet {
            rules: vec![make_rule(
                "test",
                Direction::Inbound,
                vec!["10.0.0.0/8"],
                vec![],
                FirewallProtocol::NonTcp,
                vec![80..=80],
                RuleAction::Deny,
            )],
            inline_rules: Vec::new(),
            policy_attached: true,
        };
        let rendered = inpod_backend().render_ruleset(&ruleset);
        assert_golden(&rendered, "inpod_single_inbound_deny");
    }

    #[test]
    fn test_golden_inpod_mixed_rules() {
        let ruleset = RuleSet {
            rules: vec![
                make_rule(
                    "deny-dns-in",
                    Direction::Inbound,
                    vec!["10.0.0.0/8"],
                    vec![],
                    FirewallProtocol::NonTcp,
                    vec![53..=53],
                    RuleAction::Deny,
                ),
                make_rule(
                    "allow-dns-out",
                    Direction::Outbound,
                    vec![],
                    vec!["8.8.8.0/24"],
                    FirewallProtocol::NonTcp,
                    vec![53..=53],
                    RuleAction::Allow,
                ),
            ],
            inline_rules: Vec::new(),
            policy_attached: true,
        };
        let rendered = inpod_backend().render_ruleset(&ruleset);
        assert_golden(&rendered, "inpod_mixed_rules");
    }

    // ========== Individual rule rendering tests ==========

    #[test]
    fn test_render_single_cidr() {
        let rule = make_rule(
            "test",
            Direction::Inbound,
            vec!["10.0.0.0/8"],
            vec![],
            FirewallProtocol::NonTcp,
            vec![80..=80],
            RuleAction::Deny,
        );

        let lines = IptBackend::render_rule(&rule);
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            "-A ISTIO_FW_FILTER_IN -s 10.0.0.0/8 -p udp --dport 80 -j REJECT"
        );
        assert_eq!(
            lines[1],
            "-A ISTIO_FW_FILTER_IN -s 10.0.0.0/8 -p sctp --dport 80 -j REJECT"
        );
    }

    #[test]
    fn test_render_multi_cidr_source() {
        let rule = make_rule(
            "test",
            Direction::Inbound,
            vec!["10.0.0.0/8", "172.16.0.0/12"],
            vec![],
            FirewallProtocol::NonTcp,
            vec![80..=80],
            RuleAction::Deny,
        );

        let lines = IptBackend::render_rule(&rule);
        assert_eq!(lines.len(), 4);
        assert_eq!(
            lines[0],
            "-A ISTIO_FW_FILTER_IN -s 10.0.0.0/8 -p udp --dport 80 -j REJECT"
        );
        assert_eq!(
            lines[1],
            "-A ISTIO_FW_FILTER_IN -s 10.0.0.0/8 -p sctp --dport 80 -j REJECT"
        );
        assert_eq!(
            lines[2],
            "-A ISTIO_FW_FILTER_IN -s 172.16.0.0/12 -p udp --dport 80 -j REJECT"
        );
        assert_eq!(
            lines[3],
            "-A ISTIO_FW_FILTER_IN -s 172.16.0.0/12 -p sctp --dport 80 -j REJECT"
        );
    }

    #[test]
    fn test_render_multi_cidr_cartesian() {
        let rule = make_rule(
            "test",
            Direction::Outbound,
            vec!["10.0.0.0/8", "192.168.0.0/16"],
            vec!["8.8.8.0/24", "1.1.1.0/24"],
            FirewallProtocol::NonTcp,
            vec![443..=443],
            RuleAction::Deny,
        );

        let lines = IptBackend::render_rule(&rule);
        // 2 sources × 2 destinations × 2 protocols (udp, sctp) = 8 rules
        assert_eq!(lines.len(), 8);
        assert!(lines[0].contains("-s 10.0.0.0/8 -d 8.8.8.0/24 -p udp"));
        assert!(lines[1].contains("-s 10.0.0.0/8 -d 8.8.8.0/24 -p sctp"));
        assert!(lines[2].contains("-s 10.0.0.0/8 -d 1.1.1.0/24 -p udp"));
        assert!(lines[3].contains("-s 10.0.0.0/8 -d 1.1.1.0/24 -p sctp"));
        assert!(lines[4].contains("-s 192.168.0.0/16 -d 8.8.8.0/24 -p udp"));
        assert!(lines[5].contains("-s 192.168.0.0/16 -d 8.8.8.0/24 -p sctp"));
        assert!(lines[6].contains("-s 192.168.0.0/16 -d 1.1.1.0/24 -p udp"));
        assert!(lines[7].contains("-s 192.168.0.0/16 -d 1.1.1.0/24 -p sctp"));
        assert!(lines[0].contains("-j REJECT"));
    }

    #[test]
    fn test_render_port_range() {
        let rule = make_rule(
            "test",
            Direction::Inbound,
            vec![],
            vec![],
            FirewallProtocol::NonTcp,
            vec![8000..=8080],
            RuleAction::Deny,
        );

        let lines = IptBackend::render_rule(&rule);
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            "-A ISTIO_FW_FILTER_IN -p udp --dport 8000:8080 -j REJECT"
        );
        assert_eq!(
            lines[1],
            "-A ISTIO_FW_FILTER_IN -p sctp --dport 8000:8080 -j REJECT"
        );
    }

    #[test]
    fn test_render_multiport() {
        let rule = make_rule(
            "test",
            Direction::Outbound,
            vec![],
            vec![],
            FirewallProtocol::NonTcp,
            vec![80..=80, 443..=443, 8000..=8080],
            RuleAction::Deny,
        );

        let lines = IptBackend::render_rule(&rule);
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            "-A ISTIO_FW_FILTER_OUT -p udp -m multiport --dports 80,443,8000:8080 -j REJECT"
        );
        assert_eq!(
            lines[1],
            "-A ISTIO_FW_FILTER_OUT -p sctp -m multiport --dports 80,443,8000:8080 -j REJECT"
        );
    }

    #[test]
    fn test_render_multiport_chunks_ranges_by_entry_weight() {
        let rule = make_rule(
            "test",
            Direction::Outbound,
            vec![],
            vec![],
            FirewallProtocol::NonTcp,
            vec![
                1..=2,
                3..=4,
                5..=6,
                7..=8,
                9..=10,
                11..=12,
                13..=14,
                15..=16,
            ],
            RuleAction::Deny,
        );

        let lines = IptBackend::render_rule(&rule);
        assert_eq!(lines.len(), 4);
        assert_eq!(
            lines[0],
            "-A ISTIO_FW_FILTER_OUT -p udp -m multiport --dports 1:2,3:4,5:6,7:8,9:10,11:12,13:14 -j REJECT"
        );
        assert_eq!(
            lines[1],
            "-A ISTIO_FW_FILTER_OUT -p udp --dport 15:16 -j REJECT"
        );
        assert_eq!(
            lines[2],
            "-A ISTIO_FW_FILTER_OUT -p sctp -m multiport --dports 1:2,3:4,5:6,7:8,9:10,11:12,13:14 -j REJECT"
        );
        assert_eq!(
            lines[3],
            "-A ISTIO_FW_FILTER_OUT -p sctp --dport 15:16 -j REJECT"
        );
    }

    #[test]
    fn test_render_no_match() {
        let rule = make_rule(
            "test",
            Direction::Inbound,
            vec![],
            vec![],
            FirewallProtocol::NonTcp,
            vec![],
            RuleAction::Allow,
        );

        let lines = IptBackend::render_rule(&rule);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], "-A ISTIO_FW_FILTER_IN ! -p tcp -j ACCEPT");
    }

    #[test]
    fn test_render_full_ruleset() {
        let ruleset = RuleSet {
            rules: vec![
                make_rule(
                    "test",
                    Direction::Inbound,
                    vec!["10.0.0.0/8"],
                    vec![],
                    FirewallProtocol::NonTcp,
                    vec![80..=80, 443..=443],
                    RuleAction::Deny,
                ),
                make_rule(
                    "test",
                    Direction::Outbound,
                    vec![],
                    vec!["192.168.1.0/24"],
                    FirewallProtocol::NonTcp,
                    vec![8080..=8080],
                    RuleAction::Deny,
                ),
            ],
            ..Default::default()
        };

        let script = IptBackend::new().render_ruleset(&ruleset);

        assert!(script.starts_with("*filter"));
        assert!(script.contains("-F ISTIO_FW_FILTER_IN"));
        assert!(script.contains("-F ISTIO_FW_FILTER_OUT"));

        // Verify infrastructure rules
        assert!(script.contains(
            "-A ISTIO_FW_FILTER_IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        ));
        assert!(script.contains("-A ISTIO_FW_FILTER_IN -i lo -j ACCEPT"));
        assert!(script.contains(
            "-A ISTIO_FW_FILTER_OUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        ));
        assert!(script.contains("-A ISTIO_FW_FILTER_OUT -o lo -j ACCEPT"));

        // Verify policy rules (protocol=None with ports → expanded to udp + sctp)
        assert!(script.contains(
            "-A ISTIO_FW_FILTER_IN -s 10.0.0.0/8 -p udp -m multiport --dports 80,443 -j REJECT"
        ));
        assert!(script.contains(
            "-A ISTIO_FW_FILTER_IN -s 10.0.0.0/8 -p sctp -m multiport --dports 80,443 -j REJECT"
        ));
        // REJECT is used in filter table
        assert!(
            script
                .contains("-A ISTIO_FW_FILTER_OUT -d 192.168.1.0/24 -p udp --dport 8080 -j REJECT")
        );
        assert!(
            script.contains(
                "-A ISTIO_FW_FILTER_OUT -d 192.168.1.0/24 -p sctp --dport 8080 -j REJECT"
            )
        );

        // Verify COMMIT
        assert!(script.ends_with("COMMIT"));
    }

    #[test]
    fn test_render_ruleset_priority_ordering() {
        let mut rule1 = make_rule(
            "low-priority",
            Direction::Inbound,
            vec!["10.0.0.0/8"],
            vec![],
            FirewallProtocol::NonTcp,
            vec![80..=80],
            RuleAction::Deny,
        );
        rule1.priority = 10;

        let mut rule2 = make_rule(
            "high-priority",
            Direction::Inbound,
            vec!["192.168.0.0/16"],
            vec![],
            FirewallProtocol::NonTcp,
            vec![443..=443],
            RuleAction::Deny,
        );
        rule2.priority = 5;

        let ruleset = RuleSet {
            rules: vec![rule1, rule2],
            ..Default::default()
        };

        let script = IptBackend::new().render_ruleset(&ruleset);

        // high-priority (priority=5) should come before low-priority (priority=10)
        let high_pos = script.find("-s 192.168.0.0/16").unwrap();
        let low_pos = script.find("-s 10.0.0.0/8").unwrap();
        assert!(high_pos < low_pos, "Higher priority rule should come first");
    }

    #[test]
    fn test_udp_explicit_protocol() {
        let rule = FirewallRule {
            name: "test".into(),
            action: RuleAction::Deny,
            direction: Direction::Inbound,
            priority: 0,
            clauses: vec![vec![FirewallMatch {
                source_ips: vec!["10.0.0.0/8".parse().unwrap()],
                dest_ips: vec![],
                port_groups: vec![PortGroup {
                    protocol: FirewallProtocol::Udp,
                    ports: vec![53..=53],
                }],
            }]],
        };

        let lines = IptBackend::render_rule(&rule);
        assert_eq!(lines.len(), 1);
        assert_eq!(
            lines[0],
            "-A ISTIO_FW_FILTER_IN -s 10.0.0.0/8 -p udp --dport 53 -j REJECT"
        );
    }

    #[test]
    fn test_outbound_dest_no_conntrack_in_dedicated_mode() {
        // Dedicated mode (no proxy_mark) should NOT generate conntrack rules
        let rule = FirewallRule {
            name: "dns-service".into(),
            action: RuleAction::Allow,
            direction: Direction::Outbound,
            priority: 0,
            clauses: vec![vec![FirewallMatch {
                source_ips: vec![],
                dest_ips: vec!["192.168.0.10/32".parse().unwrap()],
                port_groups: vec![PortGroup {
                    protocol: FirewallProtocol::Udp,
                    ports: vec![53..=53],
                }],
            }]],
        };

        let lines = IptBackend::render_rule(&rule);
        assert_eq!(lines.len(), 1);
        assert_eq!(
            lines[0],
            "-A ISTIO_FW_FILTER_OUT -d 192.168.0.10/32 -p udp --dport 53 -j ACCEPT"
        );
        assert!(!lines[0].contains("conntrack"));
    }

    #[test]
    fn test_inpod_dns_bypass_in_ruleset() {
        // Inpod mode (proxy_mark set) should include DNS conntrack bypass
        let ruleset = RuleSet::default();
        let rendered = inpod_backend().render_ruleset(&ruleset);
        assert!(
            rendered.contains("-p udp -m conntrack --ctorigdstport 53 --ctdir ORIGINAL -j ACCEPT"),
            "Inpod mode should include DNS conntrack bypass rule"
        );

        // Dedicated mode should NOT include it
        let rendered = IptBackend::new().render_ruleset(&ruleset);
        assert!(
            !rendered.contains("ctorigdstport"),
            "Dedicated mode should not include DNS conntrack bypass"
        );
    }

    #[test]
    fn test_render_sctp_with_ports() {
        let rule = FirewallRule {
            name: "test".into(),
            action: RuleAction::Deny,
            direction: Direction::Inbound,
            priority: 0,
            clauses: vec![vec![FirewallMatch {
                source_ips: vec!["10.0.0.0/8".parse().unwrap()],
                dest_ips: vec![],
                port_groups: vec![PortGroup {
                    protocol: FirewallProtocol::Sctp,
                    ports: vec![36412..=36412],
                }],
            }]],
        };

        let lines = IptBackend::render_rule(&rule);
        assert_eq!(lines.len(), 1);
        assert_eq!(
            lines[0],
            "-A ISTIO_FW_FILTER_IN -s 10.0.0.0/8 -p sctp --dport 36412 -j REJECT"
        );
    }

    #[test]
    fn test_render_icmp_no_ports() {
        let rule = FirewallRule {
            name: "test".into(),
            action: RuleAction::Deny,
            direction: Direction::Inbound,
            priority: 0,
            clauses: vec![vec![FirewallMatch {
                source_ips: vec!["10.0.0.0/8".parse().unwrap()],
                dest_ips: vec![],
                port_groups: vec![PortGroup {
                    protocol: FirewallProtocol::Icmp,
                    ports: vec![],
                }],
            }]],
        };

        let lines = IptBackend::render_rule(&rule);
        assert_eq!(lines.len(), 1);
        assert_eq!(
            lines[0],
            "-A ISTIO_FW_FILTER_IN -s 10.0.0.0/8 -p icmp -j REJECT"
        );
    }

    #[test]
    fn test_mixed_protocols_in_port_groups() {
        let rule = FirewallRule {
            name: "test".into(),
            action: RuleAction::Deny,
            direction: Direction::Inbound,
            priority: 0,
            clauses: vec![vec![FirewallMatch {
                source_ips: vec!["10.0.0.0/8".parse().unwrap()],
                dest_ips: vec![],
                port_groups: vec![
                    PortGroup {
                        protocol: FirewallProtocol::Udp,
                        ports: vec![53..=53],
                    },
                    PortGroup {
                        protocol: FirewallProtocol::Sctp,
                        ports: vec![443..=443],
                    },
                ],
            }]],
        };

        let lines = IptBackend::render_rule(&rule);
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            "-A ISTIO_FW_FILTER_IN -s 10.0.0.0/8 -p udp --dport 53 -j REJECT"
        );
        assert_eq!(
            lines[1],
            "-A ISTIO_FW_FILTER_IN -s 10.0.0.0/8 -p sctp --dport 443 -j REJECT"
        );
    }

    mod proptest_tests {
        use super::*;
        use proptest::prelude::*;

        fn arb_protocol() -> impl Strategy<Value = FirewallProtocol> {
            prop_oneof![
                Just(FirewallProtocol::NonTcp),
                Just(FirewallProtocol::Udp),
                Just(FirewallProtocol::Sctp),
                Just(FirewallProtocol::Icmp),
            ]
        }

        fn arb_direction() -> impl Strategy<Value = Direction> {
            prop_oneof![Just(Direction::Inbound), Just(Direction::Outbound),]
        }

        fn arb_action() -> impl Strategy<Value = RuleAction> {
            prop_oneof![Just(RuleAction::Allow), Just(RuleAction::Deny),]
        }

        fn arb_port_range() -> impl Strategy<Value = std::ops::RangeInclusive<u16>> {
            (1u16..=65534u16).prop_flat_map(|lo| (lo..=65535u16).prop_map(move |hi| lo..=hi))
        }

        fn arb_ipv4_cidr() -> impl Strategy<Value = ipnet::IpNet> {
            (any::<[u8; 4]>(), 0u8..=32u8).prop_map(|(octets, prefix)| {
                let addr = std::net::Ipv4Addr::from(octets);
                ipnet::Ipv4Net::new(addr, prefix)
                    .unwrap_or(ipnet::Ipv4Net::new(addr, 32).unwrap())
                    .trunc()
                    .into()
            })
        }

        fn arb_port_group() -> impl Strategy<Value = PortGroup> {
            (
                arb_protocol(),
                prop::collection::vec(arb_port_range(), 0..4),
            )
                .prop_map(|(protocol, ports)| {
                    let ports = if protocol == FirewallProtocol::Icmp {
                        vec![]
                    } else {
                        ports
                    };
                    PortGroup { protocol, ports }
                })
        }

        fn arb_firewall_match() -> impl Strategy<Value = FirewallMatch> {
            (
                prop::collection::vec(arb_ipv4_cidr(), 0..3),
                prop::collection::vec(arb_ipv4_cidr(), 0..3),
                prop::collection::vec(arb_port_group(), 1..3),
            )
                .prop_map(|(source_ips, dest_ips, port_groups)| FirewallMatch {
                    source_ips,
                    dest_ips,
                    port_groups,
                })
        }

        fn arb_firewall_rule() -> impl Strategy<Value = FirewallRule> {
            (
                "[a-z]{3,10}",
                arb_direction(),
                arb_action(),
                -100i32..100i32,
                prop::collection::vec(prop::collection::vec(arb_firewall_match(), 1..3), 1..3),
            )
                .prop_map(|(name, direction, action, priority, clauses)| {
                    FirewallRule {
                        name: name.into(),
                        action,
                        direction,
                        priority,
                        clauses,
                    }
                })
        }

        fn arb_ruleset() -> impl Strategy<Value = RuleSet> {
            (
                prop::collection::vec(arb_firewall_rule(), 0..5),
                any::<bool>(),
            )
                .prop_map(|(rules, policy_attached)| RuleSet {
                    rules,
                    policy_attached,
                    inline_rules: Vec::new(),
                })
        }

        proptest! {
            #[test]
            fn render_ruleset_never_panics(ruleset in arb_ruleset()) {
                let _ = IptBackend::new().render_ruleset(&ruleset);
            }

            #[test]
            fn render_ruleset_structure_valid(ruleset in arb_ruleset()) {
                let output = IptBackend::new().render_ruleset(&ruleset);
                prop_assert!(output.starts_with("*filter"), "must start with *filter");
                prop_assert!(output.ends_with("COMMIT"), "must end with COMMIT");
                prop_assert!(output.contains("-F ISTIO_FW_FILTER_IN"));
                prop_assert!(output.contains("-F ISTIO_FW_FILTER_OUT"));
            }

            #[test]
            fn policy_attached_adds_default_deny(ruleset in arb_ruleset()) {
                let output = IptBackend::new().render_ruleset(&ruleset);
                if ruleset.policy_attached {
                    prop_assert!(
                        output.contains("! -p tcp -j REJECT"),
                        "policy_attached=true must have default deny"
                    );
                }
                // When policy_attached=false and no rules, there should be no default deny
                let empty = RuleSet { rules: vec![], ..Default::default() };
                let empty_output = IptBackend::new().render_ruleset(&empty);
                prop_assert!(
                    !empty_output.contains("! -p tcp -j REJECT"),
                    "empty ruleset with policy_attached=false must not have default deny"
                );
            }

            #[test]
            fn inbound_rules_in_input_chain(rule in arb_firewall_rule()) {
                let ruleset = RuleSet { rules: vec![rule.clone()], ..Default::default() };
                let output = IptBackend::new().render_ruleset(&ruleset);
                let chain = match rule.direction {
                    Direction::Inbound => "ISTIO_FW_FILTER_IN",
                    Direction::Outbound => "ISTIO_FW_FILTER_OUT",
                };
                let wrong_chain = match rule.direction {
                    Direction::Inbound => "ISTIO_FW_FILTER_OUT",
                    Direction::Outbound => "ISTIO_FW_FILTER_IN",
                };
                // Skip infrastructure lines that exist in both chains
                for line in output.lines() {
                    if line.contains("conntrack") || line.contains(" lo ") || line.contains("owner") || line.contains("-F ") || line.contains("mark") {
                        continue;
                    }
                    if line.starts_with(&format!("-A {}", chain)) {
                        // expected
                    } else if line.starts_with(&format!("-A {}", wrong_chain)) {
                        prop_assert!(false, "rule appeared in wrong chain: {}", line);
                    }
                }
            }

            #[test]
            fn rule_names_appear_in_inpod_output(ruleset in arb_ruleset()) {
                let output = IptBackend::new().skip_mark(1337).dns_proxy(true).render_ruleset(&ruleset);
                prop_assert!(output.contains("-m mark --mark 1337"), "inpod must have mark bypass");
            }
        }
    }
}
