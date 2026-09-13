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

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine;

use crate::watcher::watcher::{AsyncFileWatcher, FileStore};

pub static SANDBOX_TOKEN_HEADER: &str = "x-agentio-sandbox-token";
pub static SANDBOX_ID_HEADER: &str = "x-agentio-sandbox-id";
pub static SANDBOX_LABELS_HEADER: &str = "x-agentio-sandbox-labels";

// Runtime-issued token files are normally a few KiB. Bound a cache-miss read
// even if a file is accidentally replaced by a large file or grows mid-read.
const MAX_TOKEN_FILE_SIZE: u64 = 64 * 1024;

#[derive(serde::Deserialize)]
struct SandboxTokenFile {
    #[serde(rename = "accessToken")]
    access_token: String,
}

/// Validate a runtime-issued token file and encode its original JSON bytes.
/// Watcher updates and read-through use the same validation,
/// so a partial write cannot publish an unusable credential into the cache.
pub(crate) fn sandbox_token_transform(s: String) -> anyhow::Result<String> {
    anyhow::ensure!(
        s.len() as u64 <= MAX_TOKEN_FILE_SIZE,
        "sandbox token file exceeds size limit"
    );
    let token: SandboxTokenFile = serde_json::from_str(&s).map_err(|_| {
        // Do not include serde's unexpected value in logs: it can be a credential.
        anyhow::anyhow!("sandbox token file must contain a string accessToken")
    })?;
    anyhow::ensure!(
        !token.access_token.is_empty(),
        "sandbox accessToken is empty"
    );
    Ok(base64::engine::general_purpose::STANDARD.encode(s))
}

/// Read the runtime's single-token directory without waiting for future writes.
/// The manager has no active sandbox key, so ambiguous directories cannot
/// safely identify the current sandbox.
fn read_sandbox_token(directory: &Path) -> io::Result<Option<(PathBuf, String)>> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    let mut candidate = None;
    for entry in entries {
        let path = entry?.path();
        if path.extension().is_none_or(|ext| ext != "token") {
            continue;
        }
        if candidate.replace(path).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "multiple sandbox token files",
            ));
        }
    }
    let Some(path) = candidate else {
        return Ok(None);
    };
    let path = path.canonicalize()?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A misplaced FIFO must not occupy a blocking-pool thread indefinitely.
        // O_NONBLOCK does not change regular-file reads.
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(&path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sandbox token is not a regular file",
        ));
    }
    let mut content = String::new();
    file.take(MAX_TOKEN_FILE_SIZE + 1)
        .read_to_string(&mut content)?;
    if content.len() as u64 > MAX_TOKEN_FILE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sandbox token file exceeds size limit",
        ));
    }
    Ok(Some((path, content)))
}

/// Derive the [`FileStore`] key from a token file path.
/// Returns the file stem (filename without extension); K8s atomic-write mounts
/// create files like `<sandbox-id>.token`, so the stem matches the sandbox id
/// the proxy uses to look the token up.
pub(crate) fn sandbox_token_key(path: &PathBuf) -> Option<String> {
    path.file_stem().map(|s| s.to_string_lossy().to_string())
}

/// Manages sandbox tokens by watching all files in the token directory.
#[derive(Default)]
pub struct SandboxManager {
    store: Option<Arc<FileStore<String, String>>>,
    token_dir: Option<PathBuf>,
    _watcher_handle: Option<tokio::task::JoinHandle<()>>,
}

impl SandboxManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn run(&mut self, token_dir: PathBuf, debounce_ms: u64) {
        tracing::info!(
            debounce_ms,
            "sandbox mode enabled - starting directory watcher for {:?}",
            token_dir,
        );

        let store = Arc::new(FileStore::new(sandbox_token_transform, sandbox_token_key));
        self.token_dir = Some(token_dir.clone());

        let watcher = AsyncFileWatcher::new(store.clone(), token_dir).with_debounce_ms(debounce_ms);

        match watcher.start().await {
            Ok(handle) => {
                tracing::info!("sandbox token watcher started");
                self._watcher_handle = Some(handle);
                self.store = Some(store);
            }
            Err(e) => {
                tracing::error!("failed to start sandbox token watcher: {}", e);
            }
        }
    }

    pub fn list_sandbox_tokens(&self) -> Vec<Arc<String>> {
        self.store.as_ref().map_or(vec![], |s| s.values())
    }

    /// Return a cached token, or make one attempt to load it from disk.
    /// Missing tokens are not cached, so the next lookup can observe a new file.
    pub async fn get_or_load_token(&self) -> Option<Arc<String>> {
        if let Some(token) = self.store.as_ref().and_then(|store| store.first()) {
            return Some(token);
        }
        let token_dir = self.token_dir.clone()?;
        let result = if let Some(store) = &self.store {
            store
                .get_or_load(move || read_sandbox_token(&token_dir))
                .await
        } else {
            // If the watcher could not start, read on each lookup without
            // caching: no watcher would invalidate a credential on rotation.
            tokio::task::spawn_blocking(move || -> anyhow::Result<Option<Arc<String>>> {
                read_sandbox_token(&token_dir)?
                    .map(|(_, content)| sandbox_token_transform(content).map(Arc::new))
                    .transpose()
            })
            .await
            .unwrap_or_else(|err| Err(err.into()))
        };
        match result {
            Ok(token) => token,
            Err(err) => {
                tracing::debug!(directory = ?self.token_dir, error = %err, "sandbox token read-through unavailable");
                // A watcher update can become visible while the read fails.
                self.store.as_ref().and_then(|store| store.first())
            }
        }
    }

    pub fn get_sandbox_token(&self, sandbox_id: String) -> Option<Arc<String>> {
        self.store.as_ref().and_then(|store| store.get(&sandbox_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unwatched_manager(path: PathBuf) -> SandboxManager {
        SandboxManager {
            store: Some(Arc::new(FileStore::new(
                sandbox_token_transform,
                sandbox_token_key,
            ))),
            token_dir: Some(path),
            _watcher_handle: None,
        }
    }

    #[tokio::test]
    async fn read_through_loads_token_after_a_miss_without_watcher() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = unwatched_manager(dir.path().to_path_buf());
        assert!(mgr.get_or_load_token().await.is_none());
        let raw = r#"{"accessToken":"test-only-placeholder"}"#;
        std::fs::write(dir.path().join("sandbox.token"), raw).unwrap();
        let token = mgr.get_or_load_token().await.unwrap();
        assert_eq!(*token, sandbox_token_transform(raw.to_string()).unwrap());
        assert!(mgr.get_sandbox_token("sandbox".to_string()).is_some());
        // Cache hit must not touch the filesystem.
        std::fs::remove_file(dir.path().join("sandbox.token")).unwrap();
        assert_eq!(mgr.get_or_load_token().await, Some(token));
    }

    #[tokio::test]
    async fn read_through_tolerates_missing_directory_and_partial_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-created-yet");
        let mgr = unwatched_manager(path.clone());
        assert!(mgr.get_or_load_token().await.is_none());
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("sandbox.token"), r#"{"accessToken":""}"#).unwrap();
        assert!(mgr.get_or_load_token().await.is_none());
        std::fs::write(path.join("sandbox.token"), "{").unwrap();
        assert!(mgr.get_or_load_token().await.is_none());
        std::fs::write(
            path.join("sandbox.token"),
            r#"{"accessToken":"test-token"}"#,
        )
        .unwrap();
        assert!(mgr.get_or_load_token().await.is_some());
    }

    #[test]
    fn token_transform_base64_encodes_original_json() {
        let raw = r#"{"accessToken":"test-token","requestId":"test-request"}"#;
        let got = sandbox_token_transform(raw.to_string()).expect("transform");
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(got)
                .unwrap(),
            raw.as_bytes()
        );
    }

    #[test]
    fn token_transform_rejects_incomplete_credentials_without_disclosing_content() {
        for raw in [
            "",
            "{",
            "{}",
            r#"{"accessToken":""}"#,
            r#"{"accessToken":123}"#,
            "\"sensitive-placeholder\"",
        ] {
            let err = sandbox_token_transform(raw.to_string()).unwrap_err();
            assert!(!err.to_string().contains("sensitive-placeholder"));
        }
    }

    #[test]
    fn token_transform_preserves_json_escaping_via_base64() {
        let raw = r#"{"accessToken":"tok\nwith\rweird\u0000bytes"}"#;
        let encoded = sandbox_token_transform(raw.to_string()).expect("transform");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .expect("decode");
        assert_eq!(decoded.as_slice(), raw.as_bytes());
    }

    #[tokio::test]
    async fn read_through_rejects_ambiguous_oversized_and_nonregular_files() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = unwatched_manager(dir.path().to_path_buf());
        let first = dir.path().join("first.token");
        let second = dir.path().join("second.token");
        let raw = r#"{"accessToken":"test-token"}"#;
        std::fs::write(&first, raw).unwrap();
        std::fs::write(&second, raw).unwrap();
        assert!(mgr.get_or_load_token().await.is_none());
        std::fs::remove_file(&second).unwrap();
        std::fs::write(&first, "x".repeat(MAX_TOKEN_FILE_SIZE as usize + 1)).unwrap();
        assert!(mgr.get_or_load_token().await.is_none());
        std::fs::remove_file(&first).unwrap();
        std::fs::create_dir(&first).unwrap();
        assert!(mgr.get_or_load_token().await.is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn read_through_does_not_wait_for_a_fifo_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fifo.token");
        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRUSR).unwrap();
        let mgr = unwatched_manager(dir.path().to_path_buf());
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), mgr.get_or_load_token())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn failed_watcher_does_not_cache_credentials_without_invalidation() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("not-created-yet");
        let mut mgr = SandboxManager::new();
        mgr.run(directory.clone(), 100).await;
        assert!(mgr.store.is_none());
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("sandbox.token");
        std::fs::write(&path, r#"{"accessToken":"first-test-token"}"#).unwrap();
        let first = mgr.get_or_load_token().await.unwrap();
        std::fs::write(&path, r#"{"accessToken":"second-test-token"}"#).unwrap();
        let second = mgr.get_or_load_token().await.unwrap();
        assert_ne!(first, second);
        std::fs::remove_file(&path).unwrap();
        assert!(mgr.get_or_load_token().await.is_none());
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
        // No file component means no sandbox id; the watcher will skip the
        // event entirely (see FileStore::handle_change).
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
        let mgr = SandboxManager::new();
        assert!(mgr.list_sandbox_tokens().is_empty());
        assert!(mgr.get_sandbox_token("any-id".to_string()).is_none());
    }

    #[test]
    fn manager_lookups_before_run_are_safe() {
        // Calling lookup methods before `run()` must not panic and must return
        // empty/None - this is the failure mode we want when the watcher fails
        // to start (e.g. directory missing in an unprivileged sandbox).
        let mgr = SandboxManager::new();
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
