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
use std::fmt::Write;

use http::HeaderValue;

pub(crate) const SANDBOX_METADATA_HEADER: &str = "x-agentio-sandbox-metadata";

/// Contributions use fixed, namespaced keys; values are encoded at insertion.
#[derive(Default)]
pub(crate) struct SandboxMetadata {
    entries: BTreeMap<&'static str, String>,
}

impl SandboxMetadata {
    pub(crate) fn insert(&mut self, key: &'static str, value: &str) {
        self.entries.insert(key, encode_metadata_value(value));
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
        if self.is_empty() {
            return None;
        }
        let value = self
            .entries
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(",");
        let mut header =
            HeaderValue::from_str(&value).expect("static keys and encoded ASCII values");
        header.set_sensitive(true);
        Some(header)
    }
}

fn encode_metadata_value(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        // W3C baggage value characters, with '%' reserved for percent-encoding.
        if byte != b'%'
            && matches!(byte, 0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e)
        {
            encoded.push(char::from(byte));
        } else {
            write!(&mut encoded, "%{byte:02X}").unwrap();
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contributions_merge_without_double_encoding_or_duplicate_keys() {
        let mut metadata = SandboxMetadata::default();
        assert!(metadata.to_header_value().is_none());
        metadata.insert("runtime.name", "runtime,one");
        let mut identity = SandboxMetadata::default();
        identity.insert("agent-identity.access-token", "eyJ.test.signature");
        identity.insert("agent-identity.sandbox-client-id", "client+/=");
        metadata.extend(&identity);
        metadata.insert("runtime.name", "runtime,two");
        let header = metadata.to_header_value().unwrap();
        assert_eq!(
            header.to_str().unwrap(),
            "agent-identity.access-token=eyJ.test.signature,agent-identity.sandbox-client-id=client+/=,runtime.name=runtime%2Ctwo"
        );
        assert!(header.is_sensitive());
    }

    #[test]
    fn percent_encodes_baggage_delimiters_and_utf8() {
        let mut metadata = SandboxMetadata::default();
        metadata.insert("test.value", "a,b;c% d=+/\"\\\r\n中");
        assert_eq!(
            metadata.to_header_value().unwrap().to_str().unwrap(),
            "test.value=a%2Cb%3Bc%25%20d=+/%22%5C%0D%0A%E4%B8%AD"
        );
    }
}
