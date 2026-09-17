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

use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::discovery::Sandbox;
use crate::state::DemandProxyState;
use crate::state::workload::Workload;

use base64::Engine;

use crate::watcher::watcher::{AsyncFileWatcher, FileStore};

pub static SANDBOX_TOKEN_HEADER: &str = "x-agentio-sandbox-token";
pub static SANDBOX_ID_HEADER: &str = "x-agentio-sandbox-id";
pub static SANDBOX_LABELS_HEADER: &str = "x-agentio-sandbox-labels";

/// Transform a raw token file content into the value stored in [`FileStore`].
/// Wraps the bytes in standard base64 so downstream consumers can ship them
/// in HTTP headers (`x-agentio-sandbox-token`) without worrying about binary or
/// CRLF content.
pub(crate) fn sandbox_token_transform(s: String) -> anyhow::Result<String> {
    Ok(base64::engine::general_purpose::STANDARD.encode(s))
}

/// Derive the [`FileStore`] key from a token file path.
/// Returns the file stem (filename without extension) as an opaque cache key.
/// The producer chooses the filename independently of the xDS Sandbox ID.
pub(crate) fn sandbox_token_key(path: &Path) -> Option<String> {
    path.file_stem().map(|s| s.to_string_lossy().to_string())
}

/// Looks up Sandbox traffic metadata and watches the local token directory.
pub struct SandboxManager {
    store: Option<Arc<FileStore<String, String>>>,
    watcher_task: Option<tokio::task::JoinHandle<()>>,
    state: DemandProxyState,
}

impl SandboxManager {
    pub fn new(state: DemandProxyState) -> Self {
        SandboxManager {
            store: None,
            watcher_task: None,
            state,
        }
    }

    /// Return the local Workload's first discovered Sandbox.
    /// Per-connection selection among multiple Sandboxes can be added here later.
    /// TODO: Support multiple Sandboxes per Workload, and select the correct one for each connection.
    pub fn fetch_attested_sandbox(&self, workload: &Workload) -> Option<Arc<Sandbox>> {
        self.state
            .read()
            .sandboxes
            .get_by_workload(&workload.uid)
            .first()
            .cloned()
    }

    pub async fn run(&mut self, token_dir: PathBuf, debounce_ms: u64) {
        tracing::info!(
            debounce_ms,
            "sandbox mode enabled - starting directory watcher for {:?}",
            token_dir,
        );

        let store = Arc::new(FileStore::new(
            token_dir,
            sandbox_token_transform,
            sandbox_token_key,
        ));

        let watcher = AsyncFileWatcher::new(store.clone()).with_debounce_ms(debounce_ms);

        match watcher.start().await {
            Ok(handle) => {
                tracing::info!("sandbox token watcher started");
                if let Some(previous) = self.watcher_task.replace(handle) {
                    previous.abort();
                }
                self.store = Some(store);
            }
            Err(e) => {
                // Keep the previous watcher, if any, when replacement cannot start.
                tracing::error!("failed to start sandbox token watcher: {}", e);
            }
        }
    }

    pub fn list_sandbox_tokens(&self) -> Vec<Arc<String>> {
        self.store.as_ref().map_or(vec![], |s| s.values())
    }

    /// Return a cached token, or read a file if the watcher has not loaded one yet.
    /// An absent token is not cached, so the next lookup can observe its creation.
    pub async fn get_or_load_token(&self) -> Option<Arc<String>> {
        let store = self.store.as_ref()?;
        let result = store.get_or_load().await;
        match result {
            Ok(token) => token,
            Err(err) => {
                tracing::debug!(error = %err, "sandbox token read-through unavailable");
                // The watcher may have populated the cache while the read failed.
                store.first()
            }
        }
    }

    pub fn get_sandbox_token(&self, token_key: String) -> Option<Arc<String>> {
        match self.store {
            None => None,
            Some(ref store) => store.get(&token_key),
        }
    }
}

impl Drop for SandboxManager {
    fn drop(&mut self) {
        if let Some(task) = &self.watcher_task {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn unwatched_manager(token_dir: PathBuf) -> SandboxManager {
        SandboxManager {
            store: Some(Arc::new(FileStore::new(
                token_dir,
                sandbox_token_transform,
                sandbox_token_key,
            ))),
            watcher_task: None,
            state: crate::test_helpers::new_proxy_state(&[], &[], &[]),
        }
    }

    #[tokio::test]
    async fn replacing_and_dropping_manager_stops_watchers() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let mut manager = SandboxManager::new(crate::test_helpers::new_proxy_state(&[], &[], &[]));
        manager.run(first.path().into(), 10).await;
        let previous = manager.watcher_task.as_ref().unwrap().abort_handle();
        let previous_store = Arc::downgrade(manager.store.as_ref().unwrap());
        manager.run(second.path().into(), 10).await;
        let current = manager.watcher_task.as_ref().unwrap().abort_handle();
        let current_store = Arc::downgrade(manager.store.as_ref().unwrap());
        drop(manager);
        tokio::time::timeout(Duration::from_secs(5), async {
            while !previous.is_finished() || !current.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(previous_store.upgrade().is_none());
        assert!(current_store.upgrade().is_none());
    }

    #[tokio::test]
    async fn read_through_loads_a_new_file_and_reuses_the_cache() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("tokens");
        let mgr = unwatched_manager(directory.clone());
        assert!(mgr.get_or_load_token().await.is_none());

        // Preserve the watcher's recursive discovery and opaque-content contract.
        std::fs::create_dir_all(directory.join("nested")).unwrap();
        let path = directory.join("nested/sandbox");
        let raw = "opaque-token".repeat(7000);
        std::fs::write(&path, &raw).unwrap();
        let token = mgr.get_or_load_token().await.unwrap();
        assert_eq!(*token, sandbox_token_transform(raw).unwrap());
        assert_eq!(
            mgr.get_sandbox_token("sandbox".to_string()),
            Some(token.clone())
        );

        std::fs::remove_file(path).unwrap();
        assert_eq!(mgr.get_or_load_token().await, Some(token));
    }

    #[tokio::test]
    async fn read_through_preserves_empty_file_contents() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = unwatched_manager(dir.path().to_path_buf());
        std::fs::write(dir.path().join("sandbox.token"), "").unwrap();
        assert_eq!(mgr.get_or_load_token().await, Some(Arc::new(String::new())));
    }

    #[tokio::test]
    async fn read_through_does_not_require_a_single_file() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = unwatched_manager(dir.path().to_path_buf());
        std::fs::write(dir.path().join("first.token"), "first").unwrap();
        std::fs::write(dir.path().join("second.token"), "second").unwrap();
        let token = mgr.get_or_load_token().await.unwrap();
        assert!(
            ["first", "second"]
                .into_iter()
                .map(|raw| sandbox_token_transform(raw.to_string()).unwrap())
                .any(|encoded| encoded == *token)
        );
    }

    #[test]
    fn token_transform_base64_encodes_bytes() {
        // "hello" -> "aGVsbG8=" (standard alphabet, with padding)
        let got = sandbox_token_transform("hello".to_string()).expect("transform");
        assert_eq!(got, "aGVsbG8=");
    }

    #[test]
    fn token_transform_handles_empty_input() {
        // Empty input must produce empty output (not error); K8s briefly writes
        // empty files during atomic remount.
        let got = sandbox_token_transform(String::new()).expect("transform");
        assert_eq!(got, "");
    }

    #[test]
    fn token_transform_preserves_binary_content_via_base64() {
        // Round-trip through base64 to make sure non-ASCII bytes survive.
        let raw = "tok\nwith\rweird\x00bytes";
        let encoded = sandbox_token_transform(raw.to_string()).expect("transform");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .expect("decode");
        assert_eq!(decoded.as_slice(), raw.as_bytes());
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

    #[test]
    fn manager_new_returns_empty_state() {
        let mgr = SandboxManager::new(crate::test_helpers::new_proxy_state(&[], &[], &[]));
        assert!(mgr.list_sandbox_tokens().is_empty());
        assert!(mgr.get_sandbox_token("any-id".to_string()).is_none());
    }

    #[test]
    fn manager_lookups_before_run_are_safe() {
        // Calling lookup methods before `run()` must not panic and must return
        // empty/None - this is the failure mode we want when the watcher fails
        // to start (e.g. directory missing in an unprivileged sandbox).
        let mgr = SandboxManager::new(crate::test_helpers::new_proxy_state(&[], &[], &[]));
        let tokens = mgr.list_sandbox_tokens();
        let token = mgr.get_sandbox_token("anything".to_string());
        assert!(tokens.is_empty());
        assert!(token.is_none());
    }

    #[test]
    fn header_constants_have_expected_values() {
        // These header names are part of the on-the-wire contract with the
        // egress gateway; changing them is a breaking change.
        assert_eq!(SANDBOX_TOKEN_HEADER, "x-agentio-sandbox-token");
        assert_eq!(SANDBOX_ID_HEADER, "x-agentio-sandbox-id");
        assert_eq!(SANDBOX_LABELS_HEADER, "x-agentio-sandbox-labels");
    }
}
