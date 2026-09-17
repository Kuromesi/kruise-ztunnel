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

use std::process::Command;
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub(super) struct IptablesVariant {
    pub binary: String,
    pub restore_binary: String,
    pub existing_rules: bool,
}

/// Result of backend detection — pure data, no construction logic.
#[derive(Debug, Clone)]
pub enum FirewallBackend {
    Nftables,
    Iptables {
        iptables_bin: String,
        restore_bin: String,
    },
}

/// Probe an iptables binary variant for availability and kernel support.
///
/// Steps:
/// 1. Run `<bin>-save` to check binary existence and exit status
/// 2. Test kernel support with `-L -t filter` (read-only, no rule insertion)
/// 3. Check whether this netns already has rules for this variant
///    (`<bin>-save` output >= 3 lines implies at least one rule exists)
fn probe_iptables(bin: &str) -> Option<IptablesVariant> {
    let save_bin = format!("{bin}-save");
    let restore_bin = format!("{bin}-restore");

    let save_output = match Command::new(&save_bin).output() {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            debug!("{save_bin} exited with error: {stderr}");
            return None;
        }
        Err(e) => {
            debug!("{save_bin} not available: {e}");
            return None;
        }
    };

    match Command::new(bin)
        .args(["-t", "filter", "-L", "-n"])
        .output()
    {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            debug!("{bin}: kernel module not loaded or not supported: {stderr}");
            return None;
        }
        Err(e) => {
            debug!("{bin}: cannot execute: {e}");
            return None;
        }
    }

    let save_str = String::from_utf8_lossy(&save_output.stdout);
    let existing_rules =
        save_str.contains("ISTIO_FW_FILTER_IN") || save_str.contains("ISTIO_FW_FILTER_OUT");

    debug!(
        binary = bin,
        existing_rules, "iptables variant probed successfully"
    );

    Some(IptablesVariant {
        binary: bin.to_string(),
        restore_binary: restore_bin,
        existing_rules,
    })
}

/// Check whether the native `nft` binary is available and the kernel supports it.
fn probe_nft() -> bool {
    match Command::new("nft").args(["list", "tables"]).output() {
        Ok(o) if o.status.success() => true,
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            debug!("nft exists but unusable: {stderr}");
            false
        }
        Err(e) => {
            debug!("nft not available: {e}");
            false
        }
    }
}

/// Find the best usable iptables variant.
///
/// Priority:
/// 1. `iptables-legacy` **if** it already has rules — avoids mixing legacy/nft
/// 2. `iptables-nft` — preferred modern variant
/// 3. `iptables` — fallback (symlinked to one of the above on most distros)
fn choose_iptables_variant(
    legacy: Option<IptablesVariant>,
    nft: Option<IptablesVariant>,
    plain: Option<IptablesVariant>,
) -> Option<IptablesVariant> {
    if let Some(ref v) = legacy {
        if v.existing_rules {
            info!("Using iptables-legacy (existing rules detected)");
            return legacy;
        }
    }

    if let Some(v) = nft {
        info!("Using iptables-nft");
        return Some(v);
    }

    if let Some(v) = plain {
        info!("Using iptables (plain)");
        return Some(v);
    }

    // Legacy was found but had no existing rules and no other variant worked.
    if legacy.is_some() {
        info!("Using iptables-legacy (only available variant)");
    }
    legacy
}

fn detect_iptables() -> Option<IptablesVariant> {
    choose_iptables_variant(
        probe_iptables("iptables-legacy"),
        probe_iptables("iptables-nft"),
        probe_iptables("iptables"),
    )
}

/// Detect the best available firewall backend.
///
/// - `mode`: Auto prefers nft, Iptables forces iptables-only.
/// - `check_existing_rules`: when true (dedicated mode), existing iptables rules
///   in the current netns force iptables to avoid mixing backends. When false
///   (inpod mode), this check is skipped because rules live in per-pod netns.
pub fn detect_backend(
    mode: crate::config::FirewallBackendMode,
    dedicated_mode: bool,
) -> anyhow::Result<FirewallBackend> {
    use crate::config::FirewallBackendMode;

    let ipt = detect_iptables();
    let nft_ok = mode == FirewallBackendMode::Auto && probe_nft();

    if dedicated_mode {
        if let Some(ref v) = ipt {
            if v.existing_rules {
                warn!(
                    "Existing iptables rules detected ({}), using iptables backend instead of nft",
                    v.binary
                );
                return Ok(FirewallBackend::Iptables {
                    iptables_bin: v.binary.clone(),
                    restore_bin: v.restore_binary.clone(),
                });
            }
        }
    }

    if nft_ok {
        info!("Firewall backend: native nftables");
        return Ok(FirewallBackend::Nftables);
    }

    if let Some(v) = ipt {
        info!("Firewall backend: iptables ({})", v.binary);
        return Ok(FirewallBackend::Iptables {
            iptables_bin: v.binary,
            restore_bin: v.restore_binary,
        });
    }

    anyhow::bail!("no usable firewall backend: neither iptables nor nft found with kernel support")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn variant(binary: &str, existing_rules: bool) -> IptablesVariant {
        IptablesVariant {
            binary: binary.to_string(),
            restore_binary: format!("{binary}-restore"),
            existing_rules,
        }
    }

    #[test]
    fn choose_iptables_prefers_legacy_with_existing_rules() {
        let selected = choose_iptables_variant(
            Some(variant("iptables-legacy", true)),
            Some(variant("iptables-nft", false)),
            Some(variant("iptables", false)),
        )
        .unwrap();

        assert_eq!(selected.binary, "iptables-legacy");
    }

    #[test]
    fn choose_iptables_prefers_nft_when_legacy_has_no_existing_rules() {
        let selected = choose_iptables_variant(
            Some(variant("iptables-legacy", false)),
            Some(variant("iptables-nft", false)),
            Some(variant("iptables", false)),
        )
        .unwrap();

        assert_eq!(selected.binary, "iptables-nft");
    }

    #[test]
    fn choose_iptables_falls_back_to_plain_then_legacy() {
        let selected = choose_iptables_variant(
            Some(variant("iptables-legacy", false)),
            None,
            Some(variant("iptables", false)),
        )
        .unwrap();
        assert_eq!(selected.binary, "iptables");

        let selected =
            choose_iptables_variant(Some(variant("iptables-legacy", false)), None, None).unwrap();
        assert_eq!(selected.binary, "iptables-legacy");
    }
}
