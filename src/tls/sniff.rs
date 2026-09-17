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

use std::io;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use rustls::server::Acceptor;
use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) struct Sniffed {
    pub sni: Option<String>,
    pub data: Bytes,
    pub outcome: Outcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    SniFound,
    SniNotFound,
    NotTls,
    ParseError,
    Timeout,
    TooLarge,
}

impl Outcome {
    pub(crate) fn is_failure(self) -> bool {
        matches!(self, Self::ParseError | Self::Timeout | Self::TooLarge)
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::SniFound => "sni_found",
            Self::SniNotFound => "sni_not_found",
            Self::NotTls => "not_tls",
            Self::ParseError => "parse_error",
            Self::Timeout => "timeout",
            Self::TooLarge => "too_large",
        }
    }
}

/// Collect optional metadata without completing a handshake or sending TLS alerts.
/// Every consumed byte is returned, including on timeout, invalid TLS or the size limit.
/// Socket errors and EOF still terminate the connection.
pub(crate) async fn sniff(
    stream: &mut (impl AsyncRead + Unpin),
    timeout: Duration,
    max_bytes: usize,
) -> io::Result<Sniffed> {
    // Keep the data outside the timed future so cancellation cannot discard consumed bytes.
    let mut data = BytesMut::new();
    let (sni, outcome) = tokio::time::timeout(timeout, async {
        let mut acceptor = Acceptor::default();
        let mut buf = vec![0; max_bytes.min(4096)];
        while data.len() < max_bytes {
            let limit = buf.len().min(max_bytes - data.len());
            let n = stream.read(&mut buf[..limit]).await?;
            if n == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            data.extend_from_slice(&buf[..n]);
            // A ClientHello starts with a TLS handshake record. Reject plaintext promptly.
            if data[0] != 0x16 {
                return Ok((None, Outcome::NotTls));
            }

            let mut remaining = &buf[..n];
            while !remaining.is_empty() {
                match acceptor.read_tls(&mut remaining) {
                    Ok(0) | Err(_) => return Ok((None, Outcome::ParseError)),
                    Ok(_) => {}
                }
                match acceptor.accept() {
                    Ok(Some(accepted)) => {
                        let sni = accepted.client_hello().server_name().map(str::to_owned);
                        let outcome = if sni.is_some() {
                            Outcome::SniFound
                        } else {
                            Outcome::SniNotFound
                        };
                        return Ok((sni, outcome));
                    }
                    Ok(None) => {}
                    // Deliberately drop the alert: this proxy only observes the handshake.
                    Err((_error, _alert)) => return Ok((None, Outcome::ParseError)),
                }
            }
        }
        Ok((None, Outcome::TooLarge))
    })
    .await
    .unwrap_or(Ok((None, Outcome::Timeout)))?;

    Ok(Sniffed {
        sni,
        data: data.freeze(),
        outcome,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn client_hello(name: &str) -> Vec<u8> {
        let config = rustls::ClientConfig::builder_with_provider(crate::tls::provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let mut client =
            rustls::ClientConnection::new(config.into(), name.to_owned().try_into().unwrap())
                .unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        hello
    }

    #[tokio::test]
    async fn segmented_client_hello_preserves_bytes() {
        for (name, split_records) in [
            ("example.com", false),
            ("other.example", true),
            ("127.0.0.1", false), // IP literals omit the SNI extension.
        ] {
            let mut hello = client_hello(name);
            if split_records {
                assert_eq!(
                    u16::from_be_bytes([hello[3], hello[4]]) as usize,
                    hello.len() - 5
                );
                let mut records = Vec::new();
                for fragment in hello[5..].chunks(31) {
                    records.extend_from_slice(&hello[..3]);
                    records.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
                    records.extend_from_slice(fragment);
                }
                hello = records;
            }
            hello.extend_from_slice(b"following application bytes");
            let expected = hello.clone();
            // Tiny capacity forces reads to span both TCP chunks and TLS record boundaries.
            let (mut client, mut server) = tokio::io::duplex(7);
            let writer = tokio::spawn(async move { client.write_all(&hello).await.unwrap() });
            let result = sniff(&mut server, Duration::from_secs(1), 64 * 1024)
                .await
                .unwrap();
            let expected_sni = (name != "127.0.0.1").then_some(name);
            assert_eq!(result.sni.as_deref(), expected_sni);
            assert!(!result.outcome.is_failure());
            assert_eq!(
                result.outcome,
                if expected_sni.is_some() {
                    Outcome::SniFound
                } else {
                    Outcome::SniNotFound
                }
            );
            let mut replay = result.data.to_vec();
            server.read_to_end(&mut replay).await.unwrap();
            writer.await.unwrap();
            assert_eq!(replay, expected);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn fallback_retains_data_and_never_sends_alerts() {
        let mut registry = prometheus_client::registry::Registry::default();
        let metrics = crate::proxy::Metrics::new(crate::metrics::sub_registry(&mut registry));
        for (input, max_bytes, outcome) in [
            (&b"GET / HTTP/1.1\r\n"[..], 1024, Outcome::NotTls),
            (&b"\x16\x03\x01"[..], 1024, Outcome::Timeout),
            (
                &b"\x16\x03\x01\0\x04\xff\0\0\0"[..],
                1024,
                Outcome::ParseError,
            ),
            (&b"\x16\x03\x01"[..], 2, Outcome::TooLarge),
        ] {
            let (mut client, mut server) = tokio::io::duplex(128);
            client.write_all(input).await.unwrap();
            let result = sniff(&mut server, Duration::from_millis(10), max_bytes).await;
            metrics.record_tls_sniff(&result);
            let result = result.unwrap();
            assert_eq!(result.outcome, outcome);
            assert_eq!(result.outcome.is_failure(), outcome != Outcome::NotTls);
            assert!(result.sni.is_none());
            assert!(result.data.len() <= max_bytes);
            client.shutdown().await.unwrap();
            let mut replay = result.data.to_vec();
            server.read_to_end(&mut replay).await.unwrap();
            assert_eq!(replay, input);
            drop(server);
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert!(response.is_empty());
        }
        let closed = sniff(&mut &b""[..], Duration::from_secs(1), 1024).await;
        assert_eq!(
            closed.as_ref().err().unwrap().kind(),
            io::ErrorKind::UnexpectedEof
        );
        metrics.record_tls_sniff(&closed);
        let mut encoded = String::new();
        prometheus_client::encoding::text::encode(&mut encoded, &registry).unwrap();
        for outcome in ["not_tls", "timeout", "parse_error", "too_large", "closed"] {
            assert!(
                encoded.contains(&format!(
                    "istio_tls_sniff_results_total{{result=\"{outcome}\"}} 1"
                )),
                "{encoded}"
            );
        }
    }
}
