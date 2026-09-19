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

// nftables backend implementation for ztunnel firewall module
//
// This module implements the Backend trait for nftables, generating nft scripts
// that define a dedicated `ztunnel` table with policy chains (type filter).
//
// Key design decisions:
// - Uses `type filter` chains for policy rules (priority -150)
// - TCP rules are skipped (handled by ztunnel user-space proxy L4/L7 RBAC)
// - Protocol::None adds `meta l4proto != tcp` to only match non-TCP traffic
// - Conntrack bypass and loopback bypass as first rules in policy chains
// - Idempotent table replacement using `add table` + `delete table` pattern
// - nftables native set support for multi-CIDR matching within the same family
// - Mixed IPv4/IPv6 rules are cartesian-expanded per family (cross-family
//   pairs are dropped since an IPv4 packet cannot match an IPv6 address)

use std::net::IpAddr;
use std::process::Stdio;

use crate::firewall::Backend;
use crate::firewall::types::{
    Direction, FirewallMatch, FirewallProtocol, FirewallRule, PortGroup, RuleAction, RuleSet,
};
use anyhow::{Context, Result};
use ipnet::IpNet;
use tracing::{debug, info, warn};

/// Group a slice of IpNet by address family: (ipv4_cidrs, ipv6_cidrs)
fn group_by_family(cidrs: &[IpNet]) -> (Vec<&IpNet>, Vec<&IpNet>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for c in cidrs {
        match c.network() {
            IpAddr::V4(_) => v4.push(c),
            IpAddr::V6(_) => v6.push(c),
        }
    }
    (v4, v6)
}

/// Escape `"` and `\` inside an nft comment string, and strip control
/// characters (newlines, etc.) that could break out of the comment.
fn escape_comment(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

/// CIDRs exceeding this count use a named set (with interval tree lookup)
/// instead of an anonymous inline set (linear scan). Also avoids potential
/// netlink message size limits for very large inline sets.
const NAMED_SET_THRESHOLD: usize = 128;

/// A flattened match after clause cartesian expansion (for nft).
/// Unlike iptables FlatMatch, nft keeps Vecs (rendered as sets).
struct NftFlatMatch {
    source_ips: Vec<IpNet>,
    dest_ips: Vec<IpNet>,
    port_groups: Vec<PortGroup>,
}

/// A named nftables set to be declared at the table level.
struct NamedSet {
    name: String,
    is_v4: bool,
    elements: Vec<String>,
}

/// Output of rendering a single FirewallRule.
struct RenderedRule {
    sets: Vec<NamedSet>,
    lines: Vec<String>,
}

#[derive(Default)]
pub struct NftBackend {
    netns_path: Option<String>,
    proxy_mark: Option<u32>,
    workload_name: Option<String>,
    workload_namespace: Option<String>,
}

impl NftBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn in_netns(mut self, netns_path: impl Into<String>) -> Self {
        self.netns_path = Some(netns_path.into());
        self
    }

    pub fn skip_mark(mut self, proxy_mark: u32) -> Self {
        self.proxy_mark = Some(proxy_mark);
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

    /// Render a complete ruleset as an nft script
    pub fn render_ruleset(&self, ruleset: &RuleSet) -> String {
        let mut set_counter: usize = 0;

        // Separate rules by direction
        let mut inbound_rules: Vec<_> = ruleset
            .rules
            .iter()
            .filter(|r| r.direction == Direction::Inbound)
            .collect();
        let mut outbound_rules: Vec<_> = ruleset
            .rules
            .iter()
            .filter(|r| r.direction == Direction::Outbound)
            .collect();

        // Sort by priority (lower value = higher priority = executed first)
        // Stable sorting preserves namespace/name order and rule declaration order.
        inbound_rules.sort_by_key(|rule| rule.priority);
        outbound_rules.sort_by_key(|rule| rule.priority);

        // Render all rules first (collecting named sets)
        let mut all_sets: Vec<NamedSet> = Vec::new();
        let mut inbound_lines: Vec<String> = Vec::new();
        let mut outbound_lines: Vec<String> = Vec::new();

        for rule in inbound_rules {
            let rendered = Self::render_rule(rule, &mut set_counter);
            all_sets.extend(rendered.sets);
            inbound_lines.extend(rendered.lines);
        }
        for rule in outbound_rules {
            let rendered = Self::render_rule(rule, &mut set_counter);
            all_sets.extend(rendered.sets);
            outbound_lines.extend(rendered.lines);
        }

        let mut inline_input = Vec::new();
        let mut inline_output = Vec::new();
        let mut inline = ruleset.inline_rules.iter().collect::<Vec<_>>();
        inline.sort_by_key(|rule| rule.priority);
        for rule in inline {
            let action = match rule.action {
                RuleAction::Allow => "return",
                RuleAction::Deny => "reject",
            };
            let rendered = Self::render_rule_with_action(rule, &mut set_counter, action);
            all_sets.extend(rendered.sets);
            match rule.direction {
                Direction::Inbound => inline_input.extend(rendered.lines),
                Direction::Outbound => inline_output.extend(rendered.lines),
            }
        }

        // Build the nft script
        let mut script = String::new();

        // Idempotent table creation pattern
        script.push_str("add table inet ztunnel\n");
        script.push_str("delete table inet ztunnel\n");
        script.push_str("table inet ztunnel {\n");

        // Emit named set declarations (before chains)
        for set in &all_sets {
            let type_str = if set.is_v4 { "ipv4_addr" } else { "ipv6_addr" };
            script.push_str(&format!("  set {} {{\n", set.name));
            script.push_str(&format!("    type {}\n", type_str));
            script.push_str("    flags interval\n");
            script.push_str(&format!(
                "    elements = {{ {} }}\n",
                set.elements.join(", ")
            ));
            script.push_str("  }\n");
        }

        if !ruleset.inline_rules.is_empty() {
            for (name, lines) in [
                ("zt_inline_input", &inline_input),
                ("zt_inline_output", &inline_output),
            ] {
                script.push_str(&format!("  chain {name} {{\n"));
                for line in lines {
                    script.push_str(&format!("    {line}\n"));
                }
                script.push_str("  }\n");
            }
        }

        // Policy chains (type filter, priority -150)
        script.push_str("  chain zt_policy_input {\n");
        script.push_str("    type filter hook input priority -150; policy accept;\n");
        script.push_str("    ct state established,related accept\n");
        script.push_str("    iif lo accept\n");

        if !ruleset.inline_rules.is_empty() {
            script.push_str("    meta l4proto != tcp jump zt_inline_input\n");
        }
        for line in &inbound_lines {
            script.push_str(&format!("    {}\n", line));
        }

        if ruleset.policy_attached {
            script.push_str("    meta l4proto != tcp reject\n");
        }

        script.push_str("  }\n");

        script.push_str("  chain zt_policy_output {\n");
        script.push_str("    type filter hook output priority -150; policy accept;\n");
        script.push_str("    ct state established,related accept\n");
        script.push_str("    oif lo accept\n");
        if let Some(mark) = self.proxy_mark {
            script.push_str(&format!("    meta mark {} return\n", mark));
        } else {
            script.push_str("    meta skuid 1337 return\n");
            script.push_str("    meta skgid 1337 return\n");
        }

        if !ruleset.inline_rules.is_empty() {
            script.push_str("    meta l4proto != tcp jump zt_inline_output\n");
        }
        for line in &outbound_lines {
            script.push_str(&format!("    {}\n", line));
        }

        if ruleset.policy_attached {
            script.push_str("    meta l4proto != tcp reject\n");
        }

        script.push_str("  }\n");

        script.push_str("}\n");

        script
    }

    /// Render a single firewall rule into one or more nft rule strings.
    ///
    /// nftables' `ip` and `ip6` families cannot be mixed inside a single set,
    /// so when `match_source` / `match_dest` contain both v4 and v6 CIDRs we
    /// emit one nft rule per (src_family, dst_family) same-family pair -- the
    /// cross-family combinations are meaningless (an IPv4 packet can never
    /// have an IPv6 address) and must be dropped, matching the cartesian
    /// expansion semantics of the iptables backend.
    fn render_rule(rule: &FirewallRule, set_counter: &mut usize) -> RenderedRule {
        let action_str = match rule.action {
            RuleAction::Allow => "accept",
            RuleAction::Deny => "reject",
        };
        Self::render_rule_with_action(rule, set_counter, action_str)
    }

    fn render_rule_with_action(
        rule: &FirewallRule,
        set_counter: &mut usize,
        action_str: &str,
    ) -> RenderedRule {
        let comment = format!("comment \"{}\"", escape_comment(&rule.name));

        // Expand clauses via cartesian product (same semantics as iptables),
        // but nftables can use sets for multiple IPs within a single flat match.
        let flat_matches = Self::flatten_clauses(&rule.clauses);

        let mut sets = Vec::new();
        let mut lines = Vec::new();
        for flat in flat_matches {
            let src_cidrs = &flat.source_ips;
            let dst_cidrs = &flat.dest_ips;

            // Group by family for source
            let src_groups: Vec<(bool, Vec<&IpNet>)> = if src_cidrs.is_empty() {
                vec![(true, vec![])]
            } else {
                let (v4, v6) = group_by_family(src_cidrs);
                let mut f = Vec::new();
                if !v4.is_empty() {
                    f.push((true, v4));
                }
                if !v6.is_empty() {
                    f.push((false, v6));
                }
                f
            };

            let dst_groups: Vec<(bool, Vec<&IpNet>)> = if dst_cidrs.is_empty() {
                vec![(true, vec![])]
            } else {
                let (v4, v6) = group_by_family(dst_cidrs);
                let mut f = Vec::new();
                if !v4.is_empty() {
                    f.push((true, v4));
                }
                if !v6.is_empty() {
                    f.push((false, v6));
                }
                f
            };

            for (src_is_v4, src_v) in &src_groups {
                for (dst_is_v4, dst_v) in &dst_groups {
                    if !src_v.is_empty() && !dst_v.is_empty() && src_is_v4 != dst_is_v4 {
                        continue;
                    }

                    let effective_is_v4 = if !src_v.is_empty() {
                        Some(*src_is_v4)
                    } else if !dst_v.is_empty() {
                        Some(*dst_is_v4)
                    } else {
                        None
                    };

                    let mut parts = Vec::new();

                    if let Some(part) =
                        Self::render_ip_match(src_v, "saddr", *src_is_v4, set_counter, &mut sets)
                    {
                        parts.push(part);
                    }

                    if let Some(part) =
                        Self::render_ip_match(dst_v, "daddr", *dst_is_v4, set_counter, &mut sets)
                    {
                        parts.push(part);
                    }

                    for group in &flat.port_groups {
                        let mut rule_parts = parts.clone();
                        Self::render_port_group(&mut rule_parts, group, effective_is_v4);
                        rule_parts.push(action_str.to_string());
                        rule_parts.push(comment.clone());
                        lines.push(rule_parts.join(" "));
                    }
                }
            }
        }

        debug!(
            "Rendered FirewallRule '{}' (direction={:?}, priority={}, action={:?}) -> {} nft rules",
            rule.name,
            rule.direction,
            rule.priority,
            rule.action,
            lines.len()
        );

        RenderedRule { sets, lines }
    }

    /// Render an IP match expression for source or destination CIDRs.
    /// Uses a named set when the CIDR count exceeds NAMED_SET_THRESHOLD.
    fn render_ip_match(
        cidrs: &[&IpNet],
        direction: &str,
        is_v4: bool,
        set_counter: &mut usize,
        sets: &mut Vec<NamedSet>,
    ) -> Option<String> {
        if cidrs.is_empty() {
            return None;
        }
        let prefix = if is_v4 { "ip" } else { "ip6" };
        if cidrs.len() == 1 {
            Some(format!("{} {} {}", prefix, direction, cidrs[0]))
        } else if cidrs.len() > NAMED_SET_THRESHOLD {
            let family_tag = if is_v4 { "v4" } else { "v6" };
            let name = format!("zt_{}_{}", *set_counter, family_tag);
            *set_counter += 1;
            sets.push(NamedSet {
                name: name.clone(),
                is_v4,
                elements: cidrs.iter().map(|c| c.to_string()).collect(),
            });
            Some(format!("{} {} @{}", prefix, direction, name))
        } else {
            let joined: Vec<String> = cidrs.iter().map(|c| c.to_string()).collect();
            Some(format!(
                "{} {} {{ {} }}",
                prefix,
                direction,
                joined.join(", ")
            ))
        }
    }

    /// Expand clauses (AND'd) × matches (OR'd) into flat combinations.
    /// Each NftFlatMatch represents one nft rule's match criteria.
    ///
    /// Unlike the ipt backend (which fully expands src × dst × port into scalar
    /// entries), nftables supports sets natively, so multiple IPs stay as Vec
    /// inside a single NftFlatMatch and are rendered as `{ ip1, ip2 }`.
    ///
    /// Example:
    ///   clause A: [{src: [10.0.0.1, 10.0.0.2]}]
    ///   clause B: [{port: tcp/80}]
    ///
    ///   init:      [{}]
    ///   × clause A → [{src:[10.0.0.1, 10.0.0.2]}]            (IPs kept as set)
    ///   × clause B → [{src:[10.0.0.1, 10.0.0.2], port:tcp/80}]
    ///
    /// INVARIANT: Istio's control plane guarantees that different clauses operate
    /// on different dimensions (one clause for source IPs, another for ports, etc.).
    /// If two clauses both specify the same dimension, the later clause's value
    /// replaces the earlier one — acceptable because the control plane never
    /// generates such overlap.
    fn flatten_clauses(clauses: &[Vec<FirewallMatch>]) -> Vec<NftFlatMatch> {
        let default_pg = PortGroup {
            protocol: FirewallProtocol::NonTcp,
            ports: vec![],
        };

        let mut combinations: Vec<NftFlatMatch> = vec![NftFlatMatch {
            source_ips: vec![],
            dest_ips: vec![],
            port_groups: vec![default_pg.clone()],
        }];

        for clause in clauses {
            let mut expanded = Vec::new();
            for existing in &combinations {
                for fw_match in clause {
                    let source_ips = if fw_match.source_ips.is_empty() {
                        existing.source_ips.clone()
                    } else {
                        fw_match.source_ips.clone()
                    };

                    let dest_ips = if fw_match.dest_ips.is_empty() {
                        existing.dest_ips.clone()
                    } else {
                        fw_match.dest_ips.clone()
                    };

                    let is_no_port_restriction = fw_match.port_groups.is_empty()
                        || (fw_match.port_groups.len() == 1
                            && fw_match.port_groups[0].protocol == FirewallProtocol::NonTcp
                            && fw_match.port_groups[0].ports.is_empty());

                    let port_groups = if is_no_port_restriction {
                        existing.port_groups.clone()
                    } else {
                        fw_match.port_groups.clone()
                    };

                    expanded.push(NftFlatMatch {
                        source_ips,
                        dest_ips,
                        port_groups,
                    });
                }
            }
            combinations = expanded;
        }

        combinations
    }

    /// Render a single PortGroup into nft match expressions appended to `parts`.
    fn render_port_group(
        parts: &mut Vec<String>,
        group: &PortGroup,
        effective_is_v4: Option<bool>,
    ) {
        match group.protocol {
            FirewallProtocol::NonTcp => {
                if group.ports.is_empty() {
                    parts.push("meta l4proto != tcp".to_string());
                } else {
                    parts.push("meta l4proto { udp, sctp }".to_string());
                    parts.push(Self::format_nft_ports("th", &group.ports));
                }
            }
            FirewallProtocol::Udp => {
                if group.ports.is_empty() {
                    parts.push("meta l4proto udp".to_string());
                } else {
                    parts.push(Self::format_nft_ports("udp", &group.ports));
                }
            }
            FirewallProtocol::Sctp => {
                if group.ports.is_empty() {
                    parts.push("meta l4proto sctp".to_string());
                } else {
                    parts.push(Self::format_nft_ports("sctp", &group.ports));
                }
            }
            FirewallProtocol::Icmp => {
                parts.push(match effective_is_v4 {
                    Some(true) => "ip protocol icmp".to_string(),
                    Some(false) => "meta l4proto ipv6-icmp".to_string(),
                    None => "meta l4proto { icmp, ipv6-icmp }".to_string(),
                });
            }
        }
    }

    /// Format port ranges as nft dport expression: `<proto> dport <port_expr>`
    fn format_nft_ports(proto_or_th: &str, ports: &[std::ops::RangeInclusive<u16>]) -> String {
        if ports.len() == 1 {
            let port = &ports[0];
            if port.start() == port.end() {
                format!("{} dport {}", proto_or_th, port.start())
            } else {
                format!("{} dport {}-{}", proto_or_th, port.start(), port.end())
            }
        } else {
            let port_strs: Vec<String> = ports
                .iter()
                .map(|p| {
                    if p.start() == p.end() {
                        p.start().to_string()
                    } else {
                        format!("{}-{}", p.start(), p.end())
                    }
                })
                .collect();
            format!("{} dport {{ {} }}", proto_or_th, port_strs.join(", "))
        }
    }
}

#[async_trait::async_trait]
impl Backend for NftBackend {
    async fn apply(&self, ruleset: &RuleSet) -> Result<()> {
        let script = self.render_ruleset(ruleset);

        debug!(workload = %self.workload_label(),"Applying nftables ruleset:\n{}", script);

        let mut child = self
            .make_cmd("nft")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn nft")?;

        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            stdin
                .write_all(script.as_bytes())
                .await
                .context("Failed to write to nft stdin")?;
        }

        let output =
            tokio::time::timeout(std::time::Duration::from_secs(30), child.wait_with_output())
                .await
                .context("nft apply timed out")?
                .context("Failed to wait for nft")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("nft apply failed: {}", stderr);
        }

        info!(workload = %self.workload_label(),"Applied {} nftables rules", ruleset.rules.len());

        Ok(())
    }

    async fn cleanup(&self) -> Result<()> {
        // Flush policy chains (keep chains themselves)
        let commands = vec![
            vec!["flush", "chain", "inet", "ztunnel", "zt_policy_input"],
            vec!["flush", "chain", "inet", "ztunnel", "zt_policy_output"],
        ];

        for args in commands {
            let output = self
                .make_cmd("nft")
                .args(&args)
                .output()
                .await
                .context("Failed to execute nft flush")?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("No such file or directory") {
                    warn!("nft cleanup warning: {}", stderr);
                }
            }
        }

        info!(workload = %self.workload_label(),"Cleaned up nftables policy chains");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::types::{
        Direction, FirewallProtocol, FirewallRule, PortGroup, RuleAction, RuleSet,
    };
    use ipnet::IpNet;
    use std::ops::RangeInclusive;
    use std::str::FromStr;

    fn make_rule(
        name: &str,
        direction: Direction,
        match_source: Vec<&str>,
        match_dest: Vec<&str>,
        protocol: FirewallProtocol,
        match_dports: Vec<RangeInclusive<u16>>,
        action: RuleAction,
    ) -> FirewallRule {
        FirewallRule {
            name: name.into(),
            action,
            direction,
            priority: 0,
            clauses: vec![vec![FirewallMatch {
                source_ips: match_source
                    .iter()
                    .map(|s| IpNet::from_str(s).unwrap())
                    .collect(),
                dest_ips: match_dest
                    .iter()
                    .map(|s| IpNet::from_str(s).unwrap())
                    .collect(),
                port_groups: vec![PortGroup {
                    protocol,
                    ports: match_dports,
                }],
            }]],
        }
    }

    fn assert_golden(actual: &str, golden_name: &str) {
        let expected =
            std::fs::read_to_string(format!("src/firewall/backend/testdata/{}.nft", golden_name))
                .unwrap_or_else(|e| panic!("failed to read nft golden {}: {}", golden_name, e));
        assert_eq!(actual.trim(), expected.trim());
    }

    #[test]
    fn test_render_single_rule() {
        // Use UDP protocol (TCP rules are skipped)
        let rule = make_rule(
            "test-rule",
            Direction::Inbound,
            vec!["10.0.0.0/8"],
            vec![],
            FirewallProtocol::Udp,
            vec![80..=80],
            RuleAction::Deny,
        );

        let ruleset = RuleSet {
            rules: vec![rule],
            ..Default::default()
        };

        let script = NftBackend::new().render_ruleset(&ruleset);

        assert!(script.contains("table inet ztunnel"));
        assert!(script.contains("chain zt_policy_input"));
        assert!(script.contains("type filter hook input priority -150"));
        assert!(script.contains("ct state established,related accept"));
        assert!(script.contains("iif lo accept"));
        assert!(script.contains("ip saddr 10.0.0.0/8 udp dport 80 reject"));
        assert!(script.contains("comment \"test-rule\""));
    }

    #[test]
    fn test_render_multi_cidr() {
        // Use UDP protocol (TCP rules are skipped)
        let rule = make_rule(
            "multi-cidr",
            Direction::Inbound,
            vec!["10.0.0.0/8", "172.16.0.0/12"],
            vec!["192.168.1.0/24"],
            FirewallProtocol::Udp,
            vec![443..=443],
            RuleAction::Deny,
        );

        let ruleset = RuleSet {
            rules: vec![rule],
            ..Default::default()
        };

        let script = NftBackend::new().render_ruleset(&ruleset);

        // nftables uses sets for multi-CIDR
        assert!(script.contains("ip saddr { 10.0.0.0/8, 172.16.0.0/12 }"));
        assert!(script.contains("ip daddr 192.168.1.0/24"));
        assert!(script.contains("udp dport 443 reject"));
    }

    #[test]
    fn test_render_port_range() {
        // Use UDP protocol (TCP rules are skipped)
        let rule = make_rule(
            "port-range",
            Direction::Outbound,
            vec![],
            vec![],
            FirewallProtocol::Udp,
            vec![8000..=9000],
            RuleAction::Allow,
        );

        let ruleset = RuleSet {
            rules: vec![rule],
            ..Default::default()
        };

        let script = NftBackend::new().render_ruleset(&ruleset);

        assert!(script.contains("chain zt_policy_output"));
        assert!(script.contains("type filter hook output priority -150"));
        assert!(script.contains("ct state established,related accept"));
        assert!(script.contains("oif lo accept"));
        assert!(script.contains("udp dport 8000-9000 accept"));
    }

    #[test]
    fn test_render_multi_port_non_tcp() {
        // NonTcp with multiple ports uses `meta l4proto { udp, sctp }` + `th dport`
        let rule = make_rule(
            "multi-port",
            Direction::Inbound,
            vec![],
            vec![],
            FirewallProtocol::NonTcp,
            vec![80..=80, 443..=443, 8080..=8080],
            RuleAction::Deny,
        );

        let lines = NftBackend::render_rule(&rule, &mut 0).lines;
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("meta l4proto { udp, sctp }"));
        assert!(lines[0].contains("th dport { 80, 443, 8080 }"));
    }

    #[test]
    fn test_render_multi_port_udp() {
        // UDP multi-port should still render
        let rule = make_rule(
            "multi-port-udp",
            Direction::Inbound,
            vec![],
            vec![],
            FirewallProtocol::Udp,
            vec![80..=80, 443..=443, 8080..=8080],
            RuleAction::Deny,
        );

        let ruleset = RuleSet {
            rules: vec![rule],
            ..Default::default()
        };

        let script = NftBackend::new().render_ruleset(&ruleset);

        assert!(script.contains("udp dport { 80, 443, 8080 } reject"));
    }

    // Golden file tests
    #[test]
    fn test_golden_empty_ruleset() {
        let ruleset = RuleSet {
            rules: vec![],
            ..Default::default()
        };
        let script = NftBackend::new().render_ruleset(&ruleset);
        assert_golden(&script, "empty_ruleset");
    }

    #[test]
    fn test_golden_single_inbound_deny() {
        let rule = make_rule(
            "deny-inbound",
            Direction::Inbound,
            vec!["10.0.0.0/8"],
            vec![],
            FirewallProtocol::NonTcp,
            vec![80..=80],
            RuleAction::Deny,
        );

        let ruleset = RuleSet {
            rules: vec![rule],
            ..Default::default()
        };

        let script = NftBackend::new().render_ruleset(&ruleset);
        assert_golden(&script, "single_inbound_deny");
    }

    #[test]
    fn test_golden_multi_cidr_cartesian() {
        let rule = make_rule(
            "multi-cidr-test",
            Direction::Inbound,
            vec!["10.0.0.0/8", "172.16.0.0/12"],
            vec!["192.168.1.0/24", "192.168.2.0/24"],
            FirewallProtocol::NonTcp,
            vec![443..=443],
            RuleAction::Deny,
        );

        let ruleset = RuleSet {
            rules: vec![rule],
            ..Default::default()
        };

        let script = NftBackend::new().render_ruleset(&ruleset);
        assert_golden(&script, "multi_cidr_cartesian");
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

        let script = NftBackend::new().render_ruleset(&ruleset);
        assert_golden(&script, "priority_ordering");
    }

    #[test]
    fn test_golden_port_range_and_multiport() {
        let rule1 = make_rule(
            "port-range-rule",
            Direction::Inbound,
            vec![],
            vec![],
            FirewallProtocol::NonTcp,
            vec![8000..=8080],
            RuleAction::Deny,
        );

        let rule2 = make_rule(
            "multi-port-rule",
            Direction::Outbound,
            vec![],
            vec![],
            FirewallProtocol::NonTcp,
            vec![80..=80, 443..=443, 9000..=9100],
            RuleAction::Allow,
        );

        let ruleset = RuleSet {
            rules: vec![rule1, rule2],
            ..Default::default()
        };

        let script = NftBackend::new().render_ruleset(&ruleset);
        assert_golden(&script, "port_range_and_multiport");
    }

    #[test]
    fn test_golden_multi_clause_cartesian() {
        let rule = FirewallRule {
            name: "multi-clause".into(),
            action: RuleAction::Deny,
            direction: Direction::Inbound,
            priority: 0,
            clauses: vec![
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
        let script = NftBackend::new().render_ruleset(&RuleSet {
            rules: vec![rule],
            ..Default::default()
        });
        assert_golden(&script, "multi_clause_cartesian");
    }

    #[test]
    fn test_golden_multi_clause_source_and_port() {
        let rule = FirewallRule {
            name: "src-and-port".into(),
            action: RuleAction::Allow,
            direction: Direction::Inbound,
            priority: 0,
            clauses: vec![
                vec![FirewallMatch {
                    source_ips: vec![],
                    dest_ips: vec![],
                    port_groups: vec![PortGroup {
                        protocol: FirewallProtocol::NonTcp,
                        ports: vec![53..=53],
                    }],
                }],
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
        let script = NftBackend::new().render_ruleset(&RuleSet {
            rules: vec![rule],
            ..Default::default()
        });
        assert_golden(&script, "multi_clause_source_and_port");
    }

    #[test]
    fn test_golden_dedicated_default_deny() {
        let rule = make_rule(
            "allow-dns-out",
            Direction::Outbound,
            vec![],
            vec!["8.8.8.0/24"],
            FirewallProtocol::NonTcp,
            vec![53..=53],
            RuleAction::Allow,
        );
        let script = NftBackend::new().render_ruleset(&RuleSet {
            rules: vec![rule],
            inline_rules: Vec::new(),
            policy_attached: true,
        });
        assert_golden(&script, "dedicated_default_deny");
    }

    #[test]
    fn test_golden_icmp() {
        let rule = make_rule(
            "icmp-in",
            Direction::Inbound,
            vec!["10.0.0.0/8"],
            vec![],
            FirewallProtocol::Icmp,
            vec![],
            RuleAction::Deny,
        );
        let script = NftBackend::new().render_ruleset(&RuleSet {
            rules: vec![rule],
            ..Default::default()
        });
        assert_golden(&script, "icmp");
    }

    #[test]
    fn test_golden_mixed_ipv4_ipv6() {
        let rule = make_rule(
            "mixed-family",
            Direction::Inbound,
            vec!["10.0.0.0/8", "fd00::/8"],
            vec!["192.168.1.0/24", "2001:db8::/32"],
            FirewallProtocol::NonTcp,
            vec![443..=443],
            RuleAction::Deny,
        );
        let script = NftBackend::new().render_ruleset(&RuleSet {
            rules: vec![rule],
            ..Default::default()
        });
        assert_golden(&script, "mixed_ipv4_ipv6");
    }

    // ========== Inpod mode golden file tests ==========

    fn inpod_backend() -> NftBackend {
        NftBackend::new().skip_mark(1337)
    }

    #[test]
    fn test_golden_inpod_empty_ruleset() {
        let ruleset = RuleSet::default();
        let script = inpod_backend().render_ruleset(&ruleset);
        assert_golden(&script, "inpod_empty_ruleset");
    }

    #[test]
    fn test_golden_inpod_single_inbound_deny() {
        let rule = make_rule(
            "test",
            Direction::Inbound,
            vec!["10.0.0.0/8"],
            vec![],
            FirewallProtocol::NonTcp,
            vec![80..=80],
            RuleAction::Deny,
        );
        let ruleset = RuleSet {
            rules: vec![rule],
            inline_rules: Vec::new(),
            policy_attached: true,
        };
        let script = inpod_backend().render_ruleset(&ruleset);
        assert_golden(&script, "inpod_single_inbound_deny");
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
        let script = inpod_backend().render_ruleset(&ruleset);
        assert_golden(&script, "inpod_mixed_rules");
    }

    // ========== IPv6 tests ==========

    #[test]
    fn test_render_ipv6_source() {
        // Use UDP (TCP rules are skipped)
        let rule = make_rule(
            "ipv6-rule",
            Direction::Inbound,
            vec!["fd00::/8"],
            vec![],
            FirewallProtocol::Udp,
            vec![80..=80],
            RuleAction::Deny,
        );

        let lines = NftBackend::render_rule(&rule, &mut 0).lines;
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("ip6 saddr fd00::/8"));
        assert!(lines[0].contains("udp dport 80 reject"));
    }

    #[test]
    fn test_render_ipv6_multi_cidr() {
        // Use protocol=None to test meta l4proto filter
        let rule = make_rule(
            "ipv6-multi",
            Direction::Inbound,
            vec!["fd00::/8", "2001:db8::/32"],
            vec!["2001:db8:1::/48"],
            FirewallProtocol::NonTcp,
            vec![443..=443],
            RuleAction::Deny,
        );

        let lines = NftBackend::render_rule(&rule, &mut 0).lines;
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("ip6 saddr { fd00::/8, 2001:db8::/32 }"));
        assert!(lines[0].contains("ip6 daddr 2001:db8:1::/48"));
        assert!(lines[0].contains("meta l4proto { udp, sctp }"));
    }

    #[test]
    fn test_render_mixed_v4_v6_source() {
        // Mixed v4+v6 sources, no dest: should emit 2 rules (one per family)
        // Use protocol=None to test meta l4proto filter
        let rule = make_rule(
            "mixed-src",
            Direction::Inbound,
            vec!["10.0.0.0/8", "fd00::/8"],
            vec![],
            FirewallProtocol::NonTcp,
            vec![80..=80],
            RuleAction::Deny,
        );

        let lines = NftBackend::render_rule(&rule, &mut 0).lines;
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("ip saddr 10.0.0.0/8"));
        assert!(lines[1].contains("ip6 saddr fd00::/8"));
        // Both should have meta l4proto { udp, sctp } (ports present)
        assert!(lines[0].contains("meta l4proto { udp, sctp }"));
        assert!(lines[1].contains("meta l4proto { udp, sctp }"));
    }

    #[test]
    fn test_render_mixed_v4_v6_cartesian() {
        // Mixed v4+v6 in both source and dest: cross-family pairs skipped.
        // Valid pairs: (v4,v4), (v6,v6) -> 2 rules
        // Use protocol=None to test meta l4proto filter
        let rule = make_rule(
            "mixed-cartesian",
            Direction::Inbound,
            vec!["10.0.0.0/8", "fd00::/8"],
            vec!["192.168.1.0/24", "2001:db8::/32"],
            FirewallProtocol::NonTcp,
            vec![443..=443],
            RuleAction::Deny,
        );

        let lines = NftBackend::render_rule(&rule, &mut 0).lines;
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("ip saddr 10.0.0.0/8"));
        assert!(lines[0].contains("ip daddr 192.168.1.0/24"));
        assert!(lines[1].contains("ip6 saddr fd00::/8"));
        assert!(lines[1].contains("ip6 daddr 2001:db8::/32"));
    }

    #[test]
    fn test_render_mixed_v4_source_v6_dest_dropped() {
        // v4-only source + v6-only dest: cross-family pair is skipped, 0 rules
        let rule = make_rule(
            "cross-family-empty",
            Direction::Inbound,
            vec!["10.0.0.0/8"],
            vec!["fd00::/8"],
            FirewallProtocol::Udp,
            vec![80..=80],
            RuleAction::Deny,
        );

        let lines = NftBackend::render_rule(&rule, &mut 0).lines;
        assert!(
            lines.is_empty(),
            "cross-family pairs should produce no rules"
        );
    }

    // ========== SCTP and ICMP protocol tests ==========

    #[test]
    fn test_render_sctp_with_ports() {
        let rule = make_rule(
            "sctp-rule",
            Direction::Inbound,
            vec!["10.0.0.0/8"],
            vec![],
            FirewallProtocol::Sctp,
            vec![36412..=36412],
            RuleAction::Deny,
        );

        let lines = NftBackend::render_rule(&rule, &mut 0).lines;
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("ip saddr 10.0.0.0/8"));
        assert!(lines[0].contains("sctp dport 36412"));
        assert!(lines[0].contains("reject"));
    }

    #[test]
    fn test_render_icmp_no_ports() {
        let rule = make_rule(
            "icmp-rule",
            Direction::Inbound,
            vec!["10.0.0.0/8"],
            vec![],
            FirewallProtocol::Icmp,
            vec![],
            RuleAction::Deny,
        );

        let lines = NftBackend::render_rule(&rule, &mut 0).lines;
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("ip saddr 10.0.0.0/8"));
        assert!(lines[0].contains("ip protocol icmp"));
        assert!(lines[0].contains("reject"));
    }

    #[test]
    fn test_render_icmp_with_ports_ignored() {
        // ICMP doesn't have ports, so ports should be ignored with a warning
        let rule = make_rule(
            "icmp-with-ports",
            Direction::Inbound,
            vec!["10.0.0.0/8"],
            vec![],
            FirewallProtocol::Icmp,
            vec![80..=80],
            RuleAction::Deny,
        );

        let lines = NftBackend::render_rule(&rule, &mut 0).lines;
        // Should still generate 1 rule, but without port matching
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("ip saddr 10.0.0.0/8"));
        assert!(lines[0].contains("ip protocol icmp"));
        // Should NOT contain port matching
        assert!(!lines[0].contains("dport"));
        assert!(lines[0].contains("reject"));
    }

    // ========== ICMP IPv6 family tests ==========

    #[test]
    fn test_render_icmpv6_with_ipv6_source() {
        let rule = make_rule(
            "icmpv6-rule",
            Direction::Inbound,
            vec!["fd00::/8"],
            vec![],
            FirewallProtocol::Icmp,
            vec![],
            RuleAction::Deny,
        );

        let lines = NftBackend::render_rule(&rule, &mut 0).lines;
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("ip6 saddr fd00::/8"));
        assert!(lines[0].contains("meta l4proto ipv6-icmp"));
        assert!(!lines[0].contains("ip protocol icmp"));
        assert!(lines[0].contains("reject"));
    }

    #[test]
    fn test_render_icmp_no_cidrs_matches_both_families() {
        let rule = make_rule(
            "icmp-both",
            Direction::Inbound,
            vec![],
            vec![],
            FirewallProtocol::Icmp,
            vec![],
            RuleAction::Deny,
        );

        let lines = NftBackend::render_rule(&rule, &mut 0).lines;
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("meta l4proto { icmp, ipv6-icmp }"));
        assert!(lines[0].contains("reject"));
    }

    #[test]
    fn test_render_icmp_mixed_cidrs_per_family() {
        let rule = make_rule(
            "icmp-mixed",
            Direction::Inbound,
            vec!["10.0.0.0/8", "fd00::/8"],
            vec![],
            FirewallProtocol::Icmp,
            vec![],
            RuleAction::Deny,
        );

        let lines = NftBackend::render_rule(&rule, &mut 0).lines;
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("ip saddr 10.0.0.0/8"));
        assert!(lines[0].contains("ip protocol icmp"));
        assert!(lines[1].contains("ip6 saddr fd00::/8"));
        assert!(lines[1].contains("meta l4proto ipv6-icmp"));
    }

    // ========== Comment escaping tests ==========

    #[test]
    fn test_comment_escapes_quotes_and_backslash() {
        // Use UDP (TCP rules are skipped)
        let rule = make_rule(
            r#"rule "with" \quotes"#,
            Direction::Inbound,
            vec![],
            vec![],
            FirewallProtocol::Udp,
            vec![80..=80],
            RuleAction::Deny,
        );

        let lines = NftBackend::render_rule(&rule, &mut 0).lines;
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains(r#"comment "rule \"with\" \\quotes""#),
            "actual: {}",
            lines[0]
        );
    }

    #[test]
    fn test_escape_comment_helper() {
        assert_eq!(escape_comment("plain"), "plain");
        assert_eq!(escape_comment(r#"has "quote""#), r#"has \"quote\""#);
        assert_eq!(escape_comment(r"back\slash"), r"back\\slash");
        assert_eq!(escape_comment(r#"both \"x""#), r#"both \\\"x\""#);
    }

    // ========== TCP skip and protocol=None tests ==========

    #[test]
    fn test_tcp_excluded_by_type_system() {
        // TCP cannot be expressed in FirewallProtocol — compile-time guarantee.
        // This test verifies that a UDP rule renders correctly.
        let udp_rule = make_rule(
            "udp-rule",
            Direction::Inbound,
            vec!["10.0.0.0/8"],
            vec![],
            FirewallProtocol::Udp,
            vec![53..=53],
            RuleAction::Deny,
        );

        let lines = NftBackend::render_rule(&udp_rule, &mut 0).lines;
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("ip saddr 10.0.0.0/8 udp dport 53 reject"));
    }

    #[test]
    fn test_protocol_none_adds_l4proto_filter() {
        // Protocol=None should add `meta l4proto != tcp` to exclude TCP
        let rule = make_rule(
            "any-proto",
            Direction::Inbound,
            vec!["10.0.0.0/8"],
            vec![],
            FirewallProtocol::NonTcp,
            vec![53..=53],
            RuleAction::Deny,
        );

        let lines = NftBackend::render_rule(&rule, &mut 0).lines;
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("meta l4proto { udp, sctp }"));
        assert!(lines[0].contains("th dport 53 reject"));
    }

    #[test]
    fn test_protocol_none_no_ports() {
        // Protocol=None with no port match should still add meta l4proto filter
        let rule = make_rule(
            "any-proto-no-port",
            Direction::Inbound,
            vec!["10.0.0.0/8"],
            vec![],
            FirewallProtocol::NonTcp,
            vec![],
            RuleAction::Deny,
        );

        let lines = NftBackend::render_rule(&rule, &mut 0).lines;
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("meta l4proto != tcp"));
        assert!(lines[0].contains("ip saddr 10.0.0.0/8"));
    }

    // ========== Named set tests ==========

    #[test]
    fn test_golden_named_set_basic() {
        let cidrs: Vec<IpNet> = (0..NAMED_SET_THRESHOLD as u32 + 2)
            .map(|i| format!("10.0.{}.0/24", i).parse().unwrap())
            .collect();

        let rule = FirewallRule {
            name: "named-set-rule".into(),
            action: RuleAction::Deny,
            direction: Direction::Inbound,
            priority: 100,
            clauses: vec![vec![FirewallMatch {
                source_ips: cidrs,
                dest_ips: vec!["192.168.1.0/24".parse().unwrap()],
                port_groups: vec![PortGroup {
                    protocol: FirewallProtocol::Udp,
                    ports: vec![53..=53],
                }],
            }]],
        };

        let script = NftBackend::new().render_ruleset(&RuleSet {
            rules: vec![rule],
            inline_rules: Vec::new(),
            policy_attached: true,
        });

        assert_golden(&script, "named_set_basic");
    }

    #[test]
    fn test_golden_named_set_multi_rule() {
        let src_cidrs: Vec<IpNet> = (0..NAMED_SET_THRESHOLD as u32 + 2)
            .map(|i| format!("10.0.{}.0/24", i).parse().unwrap())
            .collect();
        let dst_cidrs: Vec<IpNet> = (0..NAMED_SET_THRESHOLD as u32 + 2)
            .map(|i| format!("2001:db8:{:x}::/48", i).parse().unwrap())
            .collect();

        let rule1 = FirewallRule {
            name: "inbound-large-src".into(),
            action: RuleAction::Deny,
            direction: Direction::Inbound,
            priority: 10,
            clauses: vec![vec![FirewallMatch {
                source_ips: src_cidrs,
                dest_ips: vec![],
                port_groups: vec![PortGroup {
                    protocol: FirewallProtocol::NonTcp,
                    ports: vec![],
                }],
            }]],
        };

        let rule2 = FirewallRule {
            name: "outbound-large-dst-v6".into(),
            action: RuleAction::Allow,
            direction: Direction::Outbound,
            priority: 20,
            clauses: vec![vec![FirewallMatch {
                source_ips: vec![],
                dest_ips: dst_cidrs,
                port_groups: vec![PortGroup {
                    protocol: FirewallProtocol::Udp,
                    ports: vec![443..=443],
                }],
            }]],
        };

        let script = NftBackend::new().render_ruleset(&RuleSet {
            rules: vec![rule1, rule2],
            inline_rules: Vec::new(),
            policy_attached: true,
        });

        assert_golden(&script, "named_set_multi_rule");
    }

    #[test]
    fn test_golden_named_set_mixed() {
        // Rule 1: source exceeds threshold (named set), dest is small (anonymous set)
        let large_src: Vec<IpNet> = (0..NAMED_SET_THRESHOLD as u32 + 2)
            .map(|i| format!("10.0.{}.0/24", i).parse().unwrap())
            .collect();

        let rule1 = FirewallRule {
            name: "mixed-large-src".into(),
            action: RuleAction::Deny,
            direction: Direction::Inbound,
            priority: 10,
            clauses: vec![vec![FirewallMatch {
                source_ips: large_src,
                dest_ips: vec![
                    "192.168.1.0/24".parse().unwrap(),
                    "192.168.2.0/24".parse().unwrap(),
                ],
                port_groups: vec![PortGroup {
                    protocol: FirewallProtocol::Udp,
                    ports: vec![53..=53],
                }],
            }]],
        };

        // Rule 2: all small (anonymous sets only, no named set)
        let rule2 = FirewallRule {
            name: "small-anon-only".into(),
            action: RuleAction::Allow,
            direction: Direction::Outbound,
            priority: 100,
            clauses: vec![vec![FirewallMatch {
                source_ips: vec![],
                dest_ips: vec![
                    "8.8.8.0/24".parse().unwrap(),
                    "8.8.4.0/24".parse().unwrap(),
                    "1.1.1.0/24".parse().unwrap(),
                ],
                port_groups: vec![PortGroup {
                    protocol: FirewallProtocol::Udp,
                    ports: vec![53..=53],
                }],
            }]],
        };

        // Rule 3: dest exceeds threshold (named set), no source
        let large_dst: Vec<IpNet> = (0..NAMED_SET_THRESHOLD as u32 + 2)
            .map(|i| {
                format!("172.{}.{}.0/24", 16 + i / 256, i % 256)
                    .parse()
                    .unwrap()
            })
            .collect();

        let rule3 = FirewallRule {
            name: "mixed-large-dst".into(),
            action: RuleAction::Deny,
            direction: Direction::Outbound,
            priority: 50,
            clauses: vec![vec![FirewallMatch {
                source_ips: vec![],
                dest_ips: large_dst,
                port_groups: vec![PortGroup {
                    protocol: FirewallProtocol::NonTcp,
                    ports: vec![],
                }],
            }]],
        };

        let script = NftBackend::new().render_ruleset(&RuleSet {
            rules: vec![rule1, rule2, rule3],
            inline_rules: Vec::new(),
            policy_attached: true,
        });

        assert_golden(&script, "named_set_mixed");
    }

    #[test]
    fn test_named_set_source_v4() {
        let cidrs: Vec<&str> = (0..130u32)
            .map(|i| Box::leak(format!("10.{}.{}.0/24", i / 256, i % 256).into_boxed_str()) as &str)
            .collect();
        let rule = FirewallRule {
            name: "large-src".into(),
            action: RuleAction::Deny,
            direction: Direction::Inbound,
            priority: 0,
            clauses: vec![vec![FirewallMatch {
                source_ips: cidrs.iter().map(|s| s.parse().unwrap()).collect(),
                dest_ips: vec![],
                port_groups: vec![PortGroup {
                    protocol: FirewallProtocol::NonTcp,
                    ports: vec![],
                }],
            }]],
        };

        let script = NftBackend::new().render_ruleset(&RuleSet {
            rules: vec![rule],
            ..Default::default()
        });

        assert!(script.contains("set zt_0_v4 {"));
        assert!(script.contains("type ipv4_addr"));
        assert!(script.contains("flags interval"));
        assert!(script.contains("ip saddr @zt_0_v4"));
        assert!(script.contains("10.0.0.0/24"));
        assert!(script.contains("10.0.129.0/24"));
    }

    #[test]
    fn test_named_set_threshold_boundary() {
        // Exactly NAMED_SET_THRESHOLD → anonymous set (no named set)
        let cidrs: Vec<IpNet> = (0..NAMED_SET_THRESHOLD as u32)
            .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256).parse().unwrap())
            .collect();
        let rule = FirewallRule {
            name: "boundary".into(),
            action: RuleAction::Deny,
            direction: Direction::Inbound,
            priority: 0,
            clauses: vec![vec![FirewallMatch {
                source_ips: cidrs,
                dest_ips: vec![],
                port_groups: vec![PortGroup {
                    protocol: FirewallProtocol::NonTcp,
                    ports: vec![],
                }],
            }]],
        };

        let script = NftBackend::new().render_ruleset(&RuleSet {
            rules: vec![rule],
            ..Default::default()
        });

        assert!(
            !script.contains("set zt_"),
            "at threshold should use anonymous set"
        );
        assert!(script.contains("ip saddr {"));
    }

    #[test]
    fn test_named_set_multiple_rules_unique_names() {
        let make_large_rule = |name: &str, direction: Direction| -> FirewallRule {
            let cidrs: Vec<IpNet> = (0..130u32)
                .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256).parse().unwrap())
                .collect();
            FirewallRule {
                name: name.into(),
                action: RuleAction::Deny,
                direction,
                priority: 0,
                clauses: vec![vec![FirewallMatch {
                    source_ips: cidrs,
                    dest_ips: vec![],
                    port_groups: vec![PortGroup {
                        protocol: FirewallProtocol::NonTcp,
                        ports: vec![],
                    }],
                }]],
            }
        };

        let script = NftBackend::new().render_ruleset(&RuleSet {
            rules: vec![
                make_large_rule("rule-a", Direction::Inbound),
                make_large_rule("rule-b", Direction::Outbound),
            ],
            ..Default::default()
        });

        assert!(script.contains("set zt_0_v4 {"));
        assert!(script.contains("set zt_1_v4 {"));
        assert!(script.contains("ip saddr @zt_0_v4"));
        assert!(script.contains("ip saddr @zt_1_v4"));
    }

    #[test]
    fn test_named_set_dest_v6() {
        let cidrs: Vec<IpNet> = (0..130u32)
            .map(|i| format!("2001:db8:{:x}::/48", i).parse().unwrap())
            .collect();
        let rule = FirewallRule {
            name: "large-dst-v6".into(),
            action: RuleAction::Deny,
            direction: Direction::Inbound,
            priority: 0,
            clauses: vec![vec![FirewallMatch {
                source_ips: vec![],
                dest_ips: cidrs,
                port_groups: vec![PortGroup {
                    protocol: FirewallProtocol::NonTcp,
                    ports: vec![],
                }],
            }]],
        };

        let script = NftBackend::new().render_ruleset(&RuleSet {
            rules: vec![rule],
            ..Default::default()
        });

        assert!(script.contains("set zt_0_v6 {"));
        assert!(script.contains("type ipv6_addr"));
        assert!(script.contains("flags interval"));
        assert!(script.contains("ip6 daddr @zt_0_v6"));
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

        fn arb_port_range() -> impl Strategy<Value = RangeInclusive<u16>> {
            (1u16..=65534u16).prop_flat_map(|lo| (lo..=65535u16).prop_map(move |hi| lo..=hi))
        }

        fn arb_ipv4_cidr() -> impl Strategy<Value = IpNet> {
            (any::<[u8; 4]>(), 0u8..=32u8).prop_map(|(octets, prefix)| {
                let addr = std::net::Ipv4Addr::from(octets);
                ipnet::Ipv4Net::new(addr, prefix)
                    .unwrap_or(ipnet::Ipv4Net::new(addr, 32).unwrap())
                    .trunc()
                    .into()
            })
        }

        fn arb_ipv6_cidr() -> impl Strategy<Value = IpNet> {
            (any::<[u8; 16]>(), 0u8..=128u8).prop_map(|(octets, prefix)| {
                let addr = std::net::Ipv6Addr::from(octets);
                ipnet::Ipv6Net::new(addr, prefix)
                    .unwrap_or(ipnet::Ipv6Net::new(addr, 128).unwrap())
                    .trunc()
                    .into()
            })
        }

        fn arb_cidr() -> impl Strategy<Value = IpNet> {
            prop_oneof![arb_ipv4_cidr(), arb_ipv6_cidr(),]
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
                prop::collection::vec(arb_cidr(), 0..3),
                prop::collection::vec(arb_cidr(), 0..3),
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
                let _ = NftBackend::new().render_ruleset(&ruleset);
            }

            #[test]
            fn render_ruleset_structure_valid(ruleset in arb_ruleset()) {
                let output = NftBackend::new().render_ruleset(&ruleset);
                prop_assert!(output.contains("add table inet ztunnel"), "must contain add table");
                prop_assert!(output.contains("delete table inet ztunnel"), "must contain delete table");
                prop_assert!(output.contains("chain zt_policy_input"), "must contain input chain");
                prop_assert!(output.contains("chain zt_policy_output"), "must contain output chain");
            }

            #[test]
            fn policy_attached_adds_default_deny(ruleset in arb_ruleset()) {
                let output = NftBackend::new().render_ruleset(&ruleset);
                if ruleset.policy_attached {
                    prop_assert!(
                        output.contains("meta l4proto != tcp reject"),
                        "policy_attached=true must have default deny"
                    );
                }
                let empty = RuleSet { rules: vec![], ..Default::default() };
                let empty_output = NftBackend::new().render_ruleset(&empty);
                prop_assert!(
                    !empty_output.contains("meta l4proto != tcp reject"),
                    "empty ruleset with policy_attached=false must not have default deny"
                );
            }

            #[test]
            fn rule_names_preserved_as_comments(rule in arb_firewall_rule()) {
                let ruleset = RuleSet { rules: vec![rule.clone()], ..Default::default() };
                let output = NftBackend::new().render_ruleset(&ruleset);
                let lines = NftBackend::render_rule(&rule, &mut 0).lines;
                // Cross-family filtering can drop all matches, producing no rule lines
                if lines.is_empty() {
                    return Ok(());
                }
                let name_str: &str = rule.name.as_ref();
                let escaped: String = name_str.chars()
                    .filter(|c| !c.is_control())
                    .map(|c| match c { '"' => '\'', '\\' => '/', _ => c })
                    .collect();
                prop_assert!(
                    output.contains(&escaped),
                    "rule name '{}' (escaped: '{}') must appear in output",
                    name_str, escaped
                );
            }

            #[test]
            fn inbound_rules_in_input_chain(rule in arb_firewall_rule()) {
                let lines = NftBackend::render_rule(&rule, &mut 0).lines;
                let expected_chain = match rule.direction {
                    Direction::Inbound => "zt_policy_input",
                    Direction::Outbound => "zt_policy_output",
                };
                for line in &lines {
                    prop_assert!(
                        !line.contains("zt_policy_") || line.contains(expected_chain),
                        "rule in wrong chain: {}", line
                    );
                }
            }

            #[test]
            fn inpod_mode_has_mark_bypass(ruleset in arb_ruleset()) {
                let output = NftBackend::new().skip_mark(1337).render_ruleset(&ruleset);
                prop_assert!(output.contains("meta mark 1337 return"), "inpod must have mark bypass");
                prop_assert!(!output.contains("meta skuid"), "inpod must not have uid bypass");
            }
        }
    }
}
