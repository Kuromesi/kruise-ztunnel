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

//! Firewall rule types and data structures
//!
//! The structure mirrors Istio's RBAC rule model:
//! - A FirewallRule has multiple clauses (AND'd)
//! - Each clause has multiple matches (OR'd)
//! - Each match specifies L3/L4 fields to match against
//!
//! Backends (iptables, nftables) are responsible for expanding this structure
//! into their native format. nftables can use sets for OR'd values within a
//! dimension; iptables expands into one rule per combination.

use ipnet::IpNet;
use std::ops::RangeInclusive;

use crate::strng::Strng;

/// Rule action - what to do with matching traffic
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    /// Allow the traffic (maps to netfilter ACCEPT)
    Allow,
    /// Actively deny the traffic (maps to netfilter REJECT: TCP RST / ICMP unreachable)
    Deny,
}

/// Traffic direction - determines which chain the rule applies to
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Inbound traffic (iptables INPUT / nft hook input)
    Inbound,
    /// Outbound traffic (iptables OUTPUT / nft hook output)
    Outbound,
}

/// Protocols the firewall handles. TCP is excluded — handled by userspace proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FirewallProtocol {
    /// Match all non-TCP protocols. Backends render as:
    /// - iptables: `! -p tcp` (no ports) or expand to udp+sctp (with ports)
    /// - nftables: `meta l4proto != tcp` or `meta l4proto { udp, sctp }`
    NonTcp,
    /// UDP protocol
    Udp,
    /// SCTP protocol
    Sctp,
    /// ICMP protocol (no ports)
    Icmp,
}

/// A set of destination port ranges scoped to a single protocol.
#[derive(Debug, Clone, PartialEq)]
pub struct PortGroup {
    pub protocol: FirewallProtocol,
    /// Destination port ranges. Empty means "any port" for this protocol.
    /// ICMP always has empty ports (ICMP has no port concept).
    pub ports: Vec<RangeInclusive<u16>>,
}

/// A single L3/L4 match condition within a clause.
/// All fields are AND'd: traffic must match source AND dest AND port_groups.
/// Empty fields mean "match any" for that dimension.
#[derive(Debug, Clone, PartialEq)]
pub struct FirewallMatch {
    /// Source IP match (empty = any source)
    pub source_ips: Vec<IpNet>,
    /// Destination IP match (empty = any destination)
    pub dest_ips: Vec<IpNet>,
    /// Protocol and port match groups.
    /// Empty Vec = match all non-TCP traffic.
    pub port_groups: Vec<PortGroup>,
}

/// A firewall rule — preserves the clause/match structure from RBAC.
///
/// Structure: `clauses` are AND'd. Within each clause, matches are OR'd.
/// Semantics: rule fires when ALL clauses have at least one match that passes.
///
/// Backends expand this structure into native rules:
/// - nftables uses sets for OR'd values (compact)
/// - iptables expands into cartesian product of combinations
#[derive(Debug, Clone, PartialEq)]
pub struct FirewallRule {
    /// Rule name (for debugging)
    pub name: Strng,
    /// Action: Allow / Deny
    pub action: RuleAction,
    /// Direction: Inbound / Outbound
    pub direction: Direction,
    /// Priority (lower value = higher priority, executed first)
    pub priority: i32,
    /// AND'd clauses. Each clause is a Vec of OR'd FirewallMatch.
    /// Empty outer Vec = unconditional match (matches everything).
    pub clauses: Vec<Vec<FirewallMatch>>,
}

/// Complete rule set (passed to Backend)
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RuleSet {
    /// Sandbox gate evaluated before the Workload rules. ALLOW returns to the
    /// Workload stage; DENY terminates evaluation. Defaults are explicit rules.
    pub inline_rules: Vec<FirewallRule>,
    /// Rules in policy evaluation order, preserving declaration order within
    /// each policy. Backends must preserve this order when priorities are equal.
    pub rules: Vec<FirewallRule>,
    /// When true, unmatched non-TCP traffic is rejected (trailing REJECT rule).
    /// Set when any TrafficPolicy match the workload.
    pub policy_attached: bool,
}
