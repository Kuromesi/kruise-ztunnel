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

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::metadata::SandboxMetadata;
use super::sandbox::Error;
use crate::watcher::watcher::{AsyncFileWatcher, FileStore};

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct AgentIdentityToken {
    access_token: String,
    sandbox_client_id: String,
}

/// Parse and encode once per file update, keeping credential contents out of errors.
fn sandbox_token_transform(s: String) -> anyhow::Result<SandboxMetadata> {
    if s.is_empty() {
        return Ok(SandboxMetadata::default());
    }
    let token: AgentIdentityToken = serde_json::from_str(&s).map_err(|error| {
        anyhow::anyhow!(
            "invalid sandbox token JSON at line {}, column {}; expected accessToken and sandboxClientId strings",
            error.line(), error.column(),
        )
    })?;
    anyhow::ensure!(
        !token.access_token.is_empty(),
        "sandbox token accessToken must not be empty"
    );
    anyhow::ensure!(
        !token.sandbox_client_id.is_empty(),
        "sandbox token sandboxClientId must not be empty"
    );
    let mut metadata = SandboxMetadata::default();
    metadata.insert("agent-identity.access-token", &token.access_token);
    metadata.insert("agent-identity.sandbox-client-id", &token.sandbox_client_id);
    Ok(metadata)
}

/// Derive the [`FileStore`] key from a token file path.
/// Returns the file stem (filename without extension) as an opaque cache key.
/// The producer chooses the filename independently of the xDS Sandbox ID.
fn sandbox_token_key(path: &Path) -> Option<String> {
    path.file_stem().map(|s| s.to_string_lossy().to_string())
}

pub(crate) struct FileSandboxToken {
    store: Arc<FileStore<String, SandboxMetadata>>,
    watcher_task: tokio::task::JoinHandle<()>,
}

impl FileSandboxToken {
    pub(crate) async fn start(token_dir: PathBuf, debounce_ms: u64) -> Result<Self, Error> {
        fs::create_dir_all(&token_dir).map_err(|error| Error::TokenLoad(error.into()))?;
        let store = Arc::new(FileStore::new(
            token_dir,
            sandbox_token_transform,
            sandbox_token_key,
        ));
        let watcher_task = AsyncFileWatcher::new(store.clone())
            .with_debounce_ms(debounce_ms)
            .start()
            .await
            .map_err(Error::TokenLoad)?;
        tracing::info!("sandbox token watcher started");
        Ok(Self {
            store,
            watcher_task,
        })
    }

    pub(crate) async fn require_ready(&self) -> Result<(), Error> {
        self.store
            .get_or_load()
            .await
            .map_err(Error::TokenLoad)?
            .filter(|token| !token.is_empty())
            .ok_or(Error::TokenNotReady)?;
        Ok(())
    }

    pub(crate) async fn fill_metadata(&self, metadata: &mut SandboxMetadata) {
        if let Some(token) = self.get_or_load().await {
            metadata.extend(&token);
        }
    }

    /// Return a cached token, or read a file if the watcher has not loaded one yet.
    pub(crate) async fn get_or_load(&self) -> Option<Arc<SandboxMetadata>> {
        match self.store.get_or_load().await {
            Ok(token) => token,
            Err(err) => {
                tracing::debug!(error = %err, "sandbox token read-through unavailable");
                // The watcher may have populated the cache while the read failed.
                self.store.first()
            }
        }
    }
}

impl Drop for FileSandboxToken {
    fn drop(&mut self) {
        self.watcher_task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const TOKEN: &str = r#"{"accessToken":"eyJ.test.signature","sandboxClientId":"client+/="}"#;
    const METADATA: &str =
        "agent-identity.access-token=eyJ.test.signature,agent-identity.sandbox-client-id=client+/=";

    fn unwatched_token(token_dir: PathBuf) -> FileSandboxToken {
        FileSandboxToken {
            store: Arc::new(FileStore::new(
                token_dir,
                sandbox_token_transform,
                sandbox_token_key,
            )),
            // Read-through tests deliberately exclude background cache invalidation.
            watcher_task: tokio::spawn(async {}),
        }
    }

    #[tokio::test]
    async fn token_directory_is_created_before_the_producer_writes() {
        let directory = tempfile::tempdir().unwrap();
        let tokens = directory.path().join("tokens");
        let token = FileSandboxToken::start(tokens.clone(), 10).await.unwrap();
        assert!(tokens.is_dir());
        assert!(matches!(
            token.require_ready().await,
            Err(Error::TokenNotReady)
        ));
        fs::write(tokens.join("sandbox.token"), TOKEN).unwrap();
        token.require_ready().await.unwrap();
    }

    #[tokio::test]
    async fn dropping_token_stops_its_watcher_without_affecting_another() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let a = FileSandboxToken::start(first.path().into(), 10)
            .await
            .unwrap();
        let b = FileSandboxToken::start(second.path().into(), 10)
            .await
            .unwrap();
        let watcher_a = a.watcher_task.abort_handle();
        let watcher_b = b.watcher_task.abort_handle();
        let store_a = Arc::downgrade(&a.store);
        drop(a);
        tokio::time::timeout(Duration::from_secs(5), async {
            while !watcher_a.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(store_a.upgrade().is_none());
        assert!(!watcher_b.is_finished());
        fs::write(second.path().join("sandbox.token"), TOKEN).unwrap();
        assert_eq!(
            b.get_or_load()
                .await
                .unwrap()
                .to_header_value()
                .unwrap()
                .to_str()
                .unwrap(),
            METADATA
        );
    }

    #[tokio::test]
    async fn read_through_loads_a_new_file_and_reuses_the_cache() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("tokens");
        let mgr = unwatched_token(directory.clone());
        assert!(mgr.get_or_load().await.is_none());

        // Keep recursive discovery and filename keys independent of metadata encoding.
        std::fs::create_dir_all(directory.join("nested")).unwrap();
        let path = directory.join("nested/sandbox");
        let raw = TOKEN.to_string();
        std::fs::write(&path, &raw).unwrap();
        let token = mgr.get_or_load().await.unwrap();
        assert_eq!(
            token.to_header_value(),
            sandbox_token_transform(raw).unwrap().to_header_value()
        );
        assert!(Arc::ptr_eq(
            &mgr.store.get(&"sandbox".to_string()).unwrap(),
            &token
        ));

        std::fs::remove_file(path).unwrap();
        assert!(Arc::ptr_eq(&mgr.get_or_load().await.unwrap(), &token));
    }

    #[tokio::test]
    async fn read_through_preserves_empty_file_contents() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = unwatched_token(dir.path().to_path_buf());
        std::fs::write(dir.path().join("sandbox.token"), "").unwrap();
        assert!(mgr.get_or_load().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn read_through_preserves_multiple_tokens_by_key() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = unwatched_token(dir.path().to_path_buf());
        let second = r#"{"accessToken":"second","sandboxClientId":"other"}"#;
        std::fs::write(dir.path().join("first.token"), TOKEN).unwrap();
        std::fs::write(dir.path().join("second.token"), second).unwrap();
        mgr.require_ready().await.unwrap();
        assert_eq!(mgr.store.values().len(), 2);
        assert_eq!(
            mgr.store
                .get(&"first".into())
                .unwrap()
                .to_header_value()
                .unwrap()
                .to_str()
                .unwrap(),
            METADATA
        );
        assert_eq!(
            mgr.store.get(&"second".into()).unwrap().to_header_value(),
            sandbox_token_transform(second.into())
                .unwrap()
                .to_header_value()
        );
    }

    #[test]
    fn token_transform_extracts_only_identity_metadata() {
        let raw = r#"{"accessToken":"eyJ.test.signature","sandboxClientId":"client+/=","requestId":"unused","accessTokenExpiration":"unused","refreshToken":"must-not-forward"}"#;
        let header = sandbox_token_transform(raw.into())
            .unwrap()
            .to_header_value()
            .unwrap();
        assert_eq!(header.to_str().unwrap(), METADATA);
        assert!(header.is_sensitive());
    }

    #[tokio::test]
    async fn fills_identity_fields_alongside_other_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let source = unwatched_token(directory.path().into());
        std::fs::write(directory.path().join("sandbox.token"), TOKEN).unwrap();
        let mut metadata = SandboxMetadata::default();
        metadata.insert("runtime.name", "test,runtime");
        source.fill_metadata(&mut metadata).await;
        assert_eq!(
            metadata.to_header_value().unwrap().to_str().unwrap(),
            format!("{METADATA},runtime.name=test%2Cruntime")
        );
    }

    #[test]
    fn token_transform_rejects_invalid_fields_without_disclosing_credentials() {
        for raw in [
            r#""secret-token""#,
            r#"{"accessToken":"secret-token"}"#,
            r#"{"sandboxClientId":"client"}"#,
            r#"{"accessToken":"secret-token","sandboxClientId":[]}"#,
            r#"{"accessToken":"","sandboxClientId":"client"}"#,
            r#"{"accessToken":"secret-token","sandboxClientId":""}"#,
            r#"{"accessToken":"secret-token","accessToken":"duplicate","sandboxClientId":"client"}"#,
            "not-json-secret-token",
        ] {
            let error = sandbox_token_transform(raw.into()).err().unwrap();
            assert!(!format!("{error:#}").contains("secret-token"));
        }
    }

    #[test]
    fn token_transform_handles_empty_input() {
        assert!(sandbox_token_transform(String::new()).unwrap().is_empty());
    }

    #[test]
    fn token_key_extracts_file_stem() {
        let key = sandbox_token_key(&PathBuf::from("/var/opt/sandbox/sb-123.token"));
        assert_eq!(key, Some("sb-123".to_string()));
    }

    #[test]
    fn token_key_extracts_stem_for_file_without_extension() {
        let key = sandbox_token_key(&PathBuf::from("/var/opt/sandbox/sb-456"));
        assert_eq!(key, Some("sb-456".to_string()));
    }

    #[test]
    fn token_key_handles_k8s_atomic_mount_dotfile() {
        // K8s atomic writes create directory entries like `..data` (symlink to
        // a timestamped dir). Path::file_stem treats the leading dot as the
        // "beginning" of the name and splits at the next dot, so `..data`
        // stems to ".". This is acceptable: "." is not a valid sandbox id, so
        // lookups for the symlink entry return None.
        let key = sandbox_token_key(&PathBuf::from("/var/opt/sandbox/..data"));
        assert_eq!(key, Some(".".to_string()));
    }

    #[test]
    fn token_key_returns_none_for_root_path() {
        // A path without a file component has no token key.
        assert_eq!(sandbox_token_key(&PathBuf::from("/")), None);
    }

    #[test]
    fn token_key_strips_only_final_extension() {
        // Path like `foo.tar.gz` stems to `foo.tar`; this is fine because
        // sandbox token files are named `<id>.token`, not double-extensioned.
        let key = sandbox_token_key(&PathBuf::from("foo.tar.gz"));
        assert_eq!(key, Some("foo.tar".to_string()));
    }
}
