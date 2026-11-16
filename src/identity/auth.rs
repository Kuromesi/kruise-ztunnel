// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthSource {
    // JWT authentication source which contains the token file path and the cluster id.
    Token(PathBuf, String),
    // JWT authentication source which contains a static token file.
    // Note that this token is not refreshed, so its lifetime ought to be longer than ztunnel's
    StaticToken(String, String),
    None,
}

impl AuthSource {
    /// Freeze the credential used to open ADS so its cache identity matches the sent JWT.
    pub(crate) async fn snapshot(&self) -> anyhow::Result<(Self, Option<crate::strng::Strng>)> {
        let auth = match self {
            Self::Token(path, cluster_id) => Self::StaticToken(
                String::from_utf8(load_token(path).await?)?,
                cluster_id.clone(),
            ),
            other => other.clone(),
        };
        let pod_uid = match &auth {
            Self::StaticToken(token, _) => pod_uid(token)?,
            _ => None,
        };
        Ok((auth, pod_uid))
    }

    pub async fn insert_headers(&self, request: &mut http::HeaderMap) -> anyhow::Result<()> {
        const AUTHORIZATION: &str = "authorization";
        const CLUSTER: &str = "clusterid";
        match self {
            AuthSource::Token(path, cluster_id) => {
                let token = load_token(path).await.map(|mut t| {
                    let mut bearer: Vec<u8> = b"Bearer ".to_vec();
                    bearer.append(&mut t);
                    bearer
                })?;
                request.insert(AUTHORIZATION, token.try_into()?);
                request.insert(CLUSTER, cluster_id.try_into()?);
            }
            AuthSource::StaticToken(token, cluster_id) => {
                let token = {
                    let mut bearer: Vec<u8> = b"Bearer ".to_vec();
                    bearer.extend_from_slice(token.as_bytes());
                    bearer
                };
                request.insert(AUTHORIZATION, token.try_into()?);
                request.insert(CLUSTER, cluster_id.try_into()?);
            }
            AuthSource::None => {}
        }
        Ok(())
    }
}

fn pod_uid(token: &str) -> anyhow::Result<Option<crate::strng::Strng>> {
    use base64::Engine;

    let segments: Vec<_> = token.split('.').collect();
    if segments.len() != 3 {
        return Ok(None);
    }
    // This only partitions local caches. The control plane still authenticates the JWT.
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segments[1])
        .map_err(|_| anyhow::anyhow!("invalid workload JWT payload encoding"))?;
    #[derive(serde::Deserialize)]
    struct Claims {
        #[serde(rename = "kubernetes.io")]
        kubernetes: Option<Kubernetes>,
    }
    #[derive(serde::Deserialize)]
    struct Kubernetes {
        pod: Option<Pod>,
    }
    #[derive(serde::Deserialize)]
    struct Pod {
        uid: crate::strng::Strng,
    }
    let claims: Claims = serde_json::from_slice(&payload)
        .map_err(|_| anyhow::anyhow!("invalid workload JWT claims"))?;
    Ok(claims.kubernetes.and_then(|k| k.pod).map(|p| p.uid))
}

async fn load_token(path: &PathBuf) -> io::Result<Vec<u8>> {
    let t = tokio::fs::read(path).await?;

    if t.is_empty() {
        return Err(io::Error::other("token file exists, but was empty"));
    }
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn jwt(uid: &str, sequence: u32) -> String {
        let claims = serde_json::json!({"kubernetes.io": {"pod": {"uid": uid}}, "jti": sequence});
        format!(
            "header.{}.signature",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string())
        )
    }

    #[tokio::test]
    async fn snapshots_follow_projected_token_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("token");
        let original = jwt("pod-a", 1);
        std::fs::write(&path, &original).unwrap();
        let source = AuthSource::Token(path.clone(), "cluster".into());
        let (first, uid) = source.snapshot().await.unwrap();
        assert_eq!(uid.as_deref(), Some("pod-a"));
        for (id, sequence) in [("pod-a", 2), ("pod-b", 3)] {
            let next = directory.path().join("next");
            std::fs::write(&next, jwt(id, sequence)).unwrap();
            std::fs::rename(next, &path).unwrap();
            let (_, uid) = source.snapshot().await.unwrap();
            assert_eq!(uid.as_deref(), Some(id));
        }
        let mut headers = http::HeaderMap::new();
        first.insert_headers(&mut headers).await.unwrap();
        assert_eq!(headers["authorization"], format!("Bearer {original}"));
    }

    #[test]
    fn optional_pod_binding_does_not_expose_credentials_in_errors() {
        assert_eq!(pod_uid("opaque-token").unwrap(), None);
        assert_eq!(pod_uid("header.e30.signature").unwrap(), None);
        let credential = "header.secret-credential.signature";
        let error = pod_uid(credential).unwrap_err().to_string();
        assert!(!error.contains("secret-credential"));
    }
}
