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

use prost::Message;

use crate::xds::kruise::networking::extensions::v1 as proto;

pub(crate) const SNI_POLICY_TYPE_URL: &str =
    "type.googleapis.com/kruise.networking.extensions.v1.SniTrafficPolicy";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SniAction {
    TlsTermination,
    Passthrough,
    Deny,
}

impl SniAction {
    /// Denials are enforced locally before opening a CONNECT stream.
    pub(crate) fn header_value(self) -> Option<&'static str> {
        match self {
            Self::TlsTermination => Some("terminate"),
            Self::Passthrough => Some("passthrough"),
            Self::Deny => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SniRule {
    pub sni: Vec<String>,
    pub action: SniAction,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SniTrafficPolicy {
    #[serde(default)]
    pub rules: Vec<SniRule>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SniPolicyError {
    #[error("failed to decode SNI policy: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("unknown or unspecified SNI action: {0}")]
    InvalidAction(i32),
    #[error("invalid SNI pattern: {0}")]
    InvalidPattern(String),
}

impl SniTrafficPolicy {
    pub(crate) fn decode(data: &[u8]) -> Result<Self, SniPolicyError> {
        let policy = proto::SniTrafficPolicy::decode(data)?;
        let rules = policy
            .rules
            .into_iter()
            .map(|rule| {
                let action = match proto::SniAction::try_from(rule.action) {
                    Ok(proto::SniAction::TlsTermination) => SniAction::TlsTermination,
                    Ok(proto::SniAction::Passthrough) => SniAction::Passthrough,
                    Ok(proto::SniAction::Deny) => SniAction::Deny,
                    _ => return Err(SniPolicyError::InvalidAction(rule.action)),
                };
                Ok(SniRule {
                    sni: rule.r#match.unwrap_or_default().sni,
                    action,
                })
            })
            .collect::<Result<_, _>>()?;
        let policy = Self { rules };
        policy.validate()?;
        Ok(policy)
    }

    pub(crate) fn validate(&self) -> Result<(), SniPolicyError> {
        for pattern in self.rules.iter().flat_map(|rule| &rule.sni) {
            let name = pattern.strip_suffix('.').unwrap_or(pattern);
            if name == "*" {
                continue;
            }
            let name = name.strip_prefix("*.").unwrap_or(name);
            if name.is_empty()
                || name.len() > 253
                || !name.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && label.as_bytes()[0].is_ascii_alphanumeric()
                        && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
            {
                return Err(SniPolicyError::InvalidPattern(pattern.clone()));
            }
        }
        Ok(())
    }

    /// A complete policy with no matching rule passes TLS through. Missing SNI is
    /// not a decision: callers retain gateway fallback for incomplete sniffing.
    pub(crate) fn evaluate(&self, sni: &str) -> Option<SniAction> {
        let name = sni.strip_suffix('.').unwrap_or(sni);
        if name.is_empty() {
            return None;
        }
        Some(
            self.rules
                .iter()
                .find(|rule| {
                    rule.sni.iter().any(|pattern| {
                        let pattern = pattern.strip_suffix('.').unwrap_or(pattern);
                        pattern == "*"
                            || pattern.eq_ignore_ascii_case(name)
                            || pattern.strip_prefix('*').is_some_and(|suffix| {
                                name.len() > suffix.len()
                                    && name
                                        .get(name.len() - suffix.len()..)
                                        .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
                            })
                    })
                })
                .map_or(SniAction::Passthrough, |rule| rule.action),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_match_normalization_and_fallback() {
        let policy = SniTrafficPolicy {
            rules: vec![
                SniRule {
                    sni: vec!["skip.example.com".into()],
                    action: SniAction::Passthrough,
                },
                SniRule {
                    sni: vec!["*.Example.COM.".into()],
                    action: SniAction::TlsTermination,
                },
                SniRule {
                    sni: vec!["*".into()],
                    action: SniAction::Deny,
                },
            ],
        };
        policy.validate().unwrap();
        for (name, action) in [
            ("SKIP.EXAMPLE.COM.", SniAction::Passthrough),
            ("www.example.com", SniAction::TlsTermination),
            ("a.b.example.com", SniAction::TlsTermination),
            ("example.com", SniAction::Deny),
            ("badexample.com", SniAction::Deny),
            ("example.com.evil", SniAction::Deny),
        ] {
            assert_eq!(policy.evaluate(name), Some(action), "{name}");
        }
        assert_eq!(policy.evaluate(""), None);
        assert_eq!(
            SniTrafficPolicy::default().evaluate("example.com"),
            Some(SniAction::Passthrough)
        );
    }

    #[test]
    fn xds_extensions_preserve_order_and_reject_invalid_rules() {
        use crate::sandbox::discovery::Sandbox;
        use crate::xds::agentio::sandbox::Sandbox as XdsSandbox;

        let extension = |pattern: &str, action: i32| prost_types::Any {
            type_url: SNI_POLICY_TYPE_URL.into(),
            value: proto::SniTrafficPolicy {
                rules: vec![proto::SniRule {
                    r#match: Some(proto::SniMatch {
                        sni: vec![pattern.into()],
                    }),
                    action,
                }],
            }
            .encode_to_vec(),
        };
        let sandbox = |extensions| XdsSandbox {
            uid: "sandbox-a".into(),
            extensions,
            ..Default::default()
        };
        let extensions = vec![
            extension("skip.example.com", proto::SniAction::Passthrough.into()),
            extension("*", proto::SniAction::TlsTermination.into()),
        ];
        let policy = Sandbox::try_from(sandbox(extensions))
            .unwrap()
            .sni_policy
            .unwrap();
        assert_eq!(policy.rules.len(), 2);
        assert_eq!(
            policy.evaluate("skip.example.com"),
            Some(SniAction::Passthrough)
        );
        assert_eq!(
            policy.evaluate("another.example"),
            Some(SniAction::TlsTermination)
        );

        for invalid in [
            extension("*", 0),
            extension("*", 123),
            extension("bad*pattern.com", proto::SniAction::Passthrough.into()),
            prost_types::Any {
                type_url: SNI_POLICY_TYPE_URL.into(),
                value: vec![0xff],
            },
        ] {
            assert!(Sandbox::try_from(sandbox(vec![invalid])).is_err());
        }
    }
}
