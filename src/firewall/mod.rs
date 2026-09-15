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

//! Firewall module - translates AuthorizationPolicy to netfilter rules

use std::time::Duration;

pub mod backend;
pub mod convert;
pub mod dedicated;
pub mod detect;
#[cfg(target_os = "linux")]
pub mod inpod;
pub mod metrics;
pub mod types;

pub const DEFAULT_FIREWALL_DEBOUNCE_INTERVAL: Duration = Duration::from_millis(100);
pub const DEFAULT_FIREWALL_MAX_DEBOUNCE_TIME: Duration = Duration::from_secs(1);

pub use backend::{Backend, BackendBuilder, IptBackend, NftBackend};
pub use convert::{
    build_firewall_ruleset, collect_workload_policies, hash_policies, resolve_workload_firewall,
};
pub use dedicated::FirewallController;
pub use detect::{FirewallBackend, detect_backend};
#[cfg(target_os = "linux")]
pub use inpod::{FirewallEvent, InpodFirewallController};
pub use types::{
    Direction, FirewallMatch, FirewallProtocol, FirewallRule, PortGroup, RuleAction, RuleSet,
};
