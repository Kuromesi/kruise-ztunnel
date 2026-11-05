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

use std::collections::BTreeMap;

use http::HeaderValue;

pub(crate) const SANDBOX_METADATA_HEADER: &str = "x-agentio-sandbox-metadata";

/// Contributions use fixed, namespaced keys and Structured Fields String values.
#[derive(Default)]
pub(crate) struct SandboxMetadata {
    entries: BTreeMap<&'static str, sfv::String>,
}

impl SandboxMetadata {
    pub(crate) fn insert(&mut self, key: &'static str, value: &str) -> Result<(), sfv::Error> {
        self.entries
            .insert(key, sfv::StringRef::from_str(value)?.to_owned());
        Ok(())
    }

    pub(crate) fn extend(&mut self, other: &Self) {
        self.entries.extend(
            other
                .entries
                .iter()
                .map(|(&key, value)| (key, value.clone())),
        );
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn to_header_value(&self) -> Option<HeaderValue> {
        let mut serializer = sfv::DictSerializer::new();
        for (key, value) in &self.entries {
            let _ = serializer.bare_item(
                sfv::KeyRef::from_str(key).expect("fixed metadata keys are valid SF keys"),
                value,
            );
        }
        let value = serializer.finish()?;
        let mut header = HeaderValue::from_str(&value).expect("Structured Fields are ASCII");
        header.set_sensitive(true);
        Some(header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contributions_merge_as_structured_dictionary_without_duplicate_keys() {
        let mut metadata = SandboxMetadata::default();
        assert!(metadata.to_header_value().is_none());
        metadata.insert("runtime.name", "runtime,one").unwrap();
        let mut identity = SandboxMetadata::default();
        identity
            .insert("agent-identity.access-token", "eyJ.test.signature")
            .unwrap();
        identity
            .insert("agent-identity.sandbox-client-id", "client+/=")
            .unwrap();
        metadata.extend(&identity);
        metadata.insert("runtime.name", "runtime,two").unwrap();
        let header = metadata.to_header_value().unwrap();
        assert_eq!(
            header.to_str().unwrap(),
            r#"agent-identity.access-token="eyJ.test.signature", agent-identity.sandbox-client-id="client+/=", runtime.name="runtime,two""#
        );
        assert!(header.is_sensitive());
    }

    #[test]
    fn structured_dictionary_round_trip_preserves_delimiters_and_escapes() {
        let mut metadata = SandboxMetadata::default();
        let value = "a,b;c% d=+/\"\\";
        metadata.insert("test.value", value).unwrap();
        let header = metadata.to_header_value().unwrap();
        let parsed: sfv::Dictionary = sfv::Parser::new(header.as_bytes()).parse().unwrap();
        let sfv::ListEntry::Item(item) = &parsed["test.value"] else {
            panic!("expected a String Item");
        };
        assert!(item.params.is_empty());
        assert_eq!(item.bare_item.as_string().unwrap().as_str(), value);
    }

    #[test]
    fn rejects_non_ascii_and_control_characters_before_header_construction() {
        let mut metadata = SandboxMetadata::default();
        for value in ["中", "x\r", "x\n", "x\t", "x\0", "x\u{7f}"] {
            assert!(metadata.insert("test.value", value).is_err());
            assert!(metadata.to_header_value().is_none());
        }
    }
}
