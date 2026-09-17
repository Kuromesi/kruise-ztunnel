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

use anyhow::Context;
use arc_swap::ArcSwap;
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, info, warn};

// Recover from missed notifications, including a native watch lost after a directory replacement.
const RESCAN_INTERVAL: Duration = Duration::from_secs(30);

/// A directory snapshot with lock-free reads and serialized refreshes.
pub struct FileStore<K, V> {
    path: PathBuf,
    transform: fn(String) -> anyhow::Result<V>,
    key_func: fn(&Path) -> Option<K>,
    snapshot: ArcSwap<BTreeMap<K, Arc<V>>>,
    refresh_lock: Mutex<()>,
}

impl<K, V> FileStore<K, V>
where
    K: Ord + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    pub fn new(
        path: impl Into<PathBuf>,
        transform: fn(String) -> anyhow::Result<V>,
        key_func: fn(&Path) -> Option<K>,
    ) -> Self {
        Self {
            path: path.into(),
            transform,
            key_func,
            snapshot: ArcSwap::from_pointee(BTreeMap::new()),
            refresh_lock: Mutex::new(()),
        }
    }

    /// Select by key order so rescanning unchanged files does not switch values.
    pub fn first(&self) -> Option<Arc<V>> {
        self.snapshot
            .load()
            .first_key_value()
            .map(|(_, value)| value.clone())
    }

    pub fn get(&self, key: &K) -> Option<Arc<V>> {
        self.snapshot.load().get(key).cloned()
    }

    pub fn values(&self) -> Vec<Arc<V>> {
        self.snapshot.load().values().cloned().collect()
    }

    /// Retry an empty snapshot on demand, using the same refresh path as the watcher.
    pub async fn get_or_load(self: &Arc<Self>) -> anyhow::Result<Option<Arc<V>>> {
        if let Some(value) = self.first() {
            return Ok(Some(value));
        }
        let _guard = self.refresh_lock.lock().await;
        if let Some(value) = self.first() {
            return Ok(Some(value));
        }
        self.load().await?;
        Ok(self.first())
    }

    async fn refresh(self: &Arc<Self>) -> anyhow::Result<()> {
        let _guard = self.refresh_lock.lock().await;
        self.load().await
    }

    /// Called with refresh_lock held through scanning and publication.
    async fn load(self: &Arc<Self>) -> anyhow::Result<()> {
        let store = self.clone();
        let snapshot = tokio::task::spawn_blocking(move || store.scan())
            .await
            .context("directory scan task failed")??;
        // Publish outside spawn_blocking: a cancelled refresh must not publish late.
        self.snapshot.store(Arc::new(snapshot));
        Ok(())
    }

    fn scan(&self) -> anyhow::Result<BTreeMap<K, Arc<V>>> {
        let mut snapshot = BTreeMap::new();
        for entry in walkdir::WalkDir::new(&self.path).sort_by_file_name() {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error)
                    if error
                        .io_error()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
                {
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            let Some(key) = (self.key_func)(path) else {
                continue;
            };
            let content = match std::fs::read_to_string(path) {
                Ok(content) => content,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(error).with_context(|| format!("reading {}", path.display()));
                }
            };
            let value = (self.transform)(content)
                .with_context(|| format!("transforming {}", path.display()))?;
            // Duplicate keys use the first path in sorted traversal order.
            match snapshot.entry(key) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(Arc::new(value));
                }
                std::collections::btree_map::Entry::Occupied(_) => {
                    warn!(path = %path.display(), "ignoring duplicate file key");
                }
            }
        }
        Ok(snapshot)
    }
}

/// File events invalidate the directory snapshot; they are never applied as deltas.
pub struct AsyncFileWatcher<K, V> {
    store: Arc<FileStore<K, V>>,
    debounce: Duration,
}

impl<K, V> AsyncFileWatcher<K, V>
where
    K: Ord + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    pub fn new(store: Arc<FileStore<K, V>>) -> Self {
        Self {
            store,
            debounce: Duration::from_millis(500),
        }
    }

    pub fn with_debounce_ms(mut self, ms: u64) -> Self {
        self.debounce = Duration::from_millis(ms);
        self
    }

    /// Install the watch before the initial scan. The caller owns task cancellation.
    pub async fn start(self) -> anyhow::Result<tokio::task::JoinHandle<()>> {
        anyhow::ensure!(
            !self.debounce.is_zero(),
            "watcher debounce must be positive"
        );
        // A full channel already represents a pending refresh, so coalescing is safe.
        let (tx, rx) = mpsc::channel(1);
        let mut watcher = RecommendedWatcher::new(
            move |result: notify::Result<notify::Event>| {
                match result {
                    Ok(event)
                        if !event.need_rescan() && matches!(event.kind, EventKind::Access(_)) =>
                    {
                        return;
                    }
                    Err(error) => warn!(%error, "file watch error, requesting rescan"),
                    _ => {}
                }
                let _ = tx.try_send(());
            },
            Config::default(),
        )
        .context("failed to create file watcher")?;
        watcher
            .watch(&self.store.path, RecursiveMode::Recursive)
            .context("failed to watch directory")?;

        if let Err(error) = self.store.refresh().await {
            warn!(%error, "initial directory scan failed, will retry");
        }
        info!(path = %self.store.path.display(), "watching directory");
        Ok(tokio::spawn(async move {
            let _watcher = watcher;
            self.run(rx, RESCAN_INTERVAL).await;
        }))
    }

    async fn run(self, mut changes: mpsc::Receiver<()>, rescan_interval: Duration) {
        let mut rescan = tokio::time::interval_at(
            tokio::time::Instant::now() + rescan_interval,
            rescan_interval,
        );
        rescan.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                Some(()) = changes.recv() => {
                    // Bound batching latency even if changes keep arriving.
                    tokio::time::sleep(self.debounce).await;
                    let _ = changes.try_recv();
                }
                _ = rescan.tick() => {}
            }
            match self.store.refresh().await {
                Ok(()) => debug!(path = %self.store.path.display(), "directory snapshot refreshed"),
                Err(error) => warn!(%error, "directory scan failed, keeping previous snapshot"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex as StdMutex, OnceLock};
    use tokio::time::timeout;

    fn key(path: &Path) -> Option<String> {
        path.file_stem()
            .map(|name| name.to_string_lossy().into_owned())
    }

    fn store(path: &Path) -> Arc<FileStore<String, String>> {
        Arc::new(FileStore::new(path, Ok, key))
    }

    async fn wait_for(store: &FileStore<String, String>, value: Option<&str>) {
        timeout(Duration::from_secs(5), async {
            while store.first().as_deref().map(String::as_str) != value {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("directory snapshot converges");
    }

    #[tokio::test]
    async fn refresh_reconciles_duplicate_keys_and_directory_removal() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("a-old");
        let new = dir.path().join("b-new");
        std::fs::create_dir(&old).unwrap();
        std::fs::create_dir(&new).unwrap();
        std::fs::write(old.join("token"), "old").unwrap();
        std::fs::write(new.join("token"), "new").unwrap();
        let store = store(dir.path());
        store.refresh().await.unwrap();
        assert_eq!(store.first().as_deref().map(String::as_str), Some("old"));
        std::fs::remove_dir_all(old).unwrap();
        store.refresh().await.unwrap();
        assert_eq!(store.first().as_deref().map(String::as_str), Some("new"));
        std::fs::remove_dir_all(new).unwrap();
        store.refresh().await.unwrap();
        assert!(store.first().is_none());
    }

    #[tokio::test]
    async fn failed_scan_preserves_complete_snapshot_and_retries() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        std::fs::write(dir.path().join("a"), "first").unwrap();
        std::fs::write(dir.path().join("b"), "second").unwrap();
        store.refresh().await.unwrap();
        let snapshot = store.snapshot.load_full();
        std::fs::remove_file(dir.path().join("a")).unwrap();
        std::fs::write(dir.path().join("b"), [0xff]).unwrap();
        assert!(store.refresh().await.is_err());
        assert!(Arc::ptr_eq(&snapshot, &store.snapshot.load_full()));
        std::fs::write(dir.path().join("b"), "updated").unwrap();
        store.refresh().await.unwrap();
        assert_eq!(store.values().len(), 1);
        assert_eq!(
            store.first().as_deref().map(String::as_str),
            Some("updated")
        );
    }

    #[tokio::test]
    async fn rescans_select_a_stable_first_key_and_cache_hits_skip_io() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        std::fs::write(dir.path().join("b"), "second").unwrap();
        std::fs::write(dir.path().join("a"), "first").unwrap();
        for _ in 0..3 {
            store.refresh().await.unwrap();
            assert_eq!(store.first().as_deref().map(String::as_str), Some("first"));
        }
        let cached = store.first().unwrap();
        std::fs::remove_dir_all(dir.path()).unwrap();
        assert!(Arc::ptr_eq(
            &cached,
            &store.get_or_load().await.unwrap().unwrap()
        ));
    }

    struct ScanGate {
        started: tokio::sync::Notify,
        resume: StdMutex<std::sync::mpsc::Receiver<()>>,
    }
    static SCAN_GATE: OnceLock<ScanGate> = OnceLock::new();

    fn pause_old_content(content: String) -> anyhow::Result<String> {
        if content == "old" {
            let gate = SCAN_GATE.get().unwrap();
            gate.started.notify_one();
            gate.resume
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))?;
        }
        Ok(content)
    }

    #[tokio::test]
    async fn scans_are_serialized_and_cancelled_scans_cannot_publish() {
        let (resume, receiver) = std::sync::mpsc::channel();
        assert!(
            SCAN_GATE
                .set(ScanGate {
                    started: tokio::sync::Notify::new(),
                    resume: StdMutex::new(receiver),
                })
                .is_ok()
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        let store = Arc::new(FileStore::new(dir.path(), pause_old_content, key));
        std::fs::write(&path, "old").unwrap();
        let initial = tokio::spawn({
            let store = store.clone();
            async move { store.refresh().await }
        });
        timeout(
            Duration::from_secs(5),
            SCAN_GATE.get().unwrap().started.notified(),
        )
        .await
        .unwrap();
        std::fs::write(&path, "new").unwrap();
        // An event refresh must wait for the entire initial scan, not only publication.
        assert!(
            timeout(Duration::from_millis(20), store.refresh())
                .await
                .is_err()
        );
        resume.send(()).unwrap();
        initial.await.unwrap().unwrap();
        store.refresh().await.unwrap();
        assert_eq!(store.first().as_deref().map(String::as_str), Some("new"));

        std::fs::write(&path, "old").unwrap();
        let cancelled = tokio::spawn({
            let store = store.clone();
            async move { store.refresh().await }
        });
        timeout(
            Duration::from_secs(5),
            SCAN_GATE.get().unwrap().started.notified(),
        )
        .await
        .unwrap();
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());
        std::fs::remove_file(&path).unwrap();
        store.refresh().await.unwrap();
        resume.send(()).unwrap();
        // The abandoned blocking scan may finish, but cannot restore the deleted value.
        timeout(Duration::from_secs(5), async {
            while Arc::strong_count(&store) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(store.first().is_none());
    }

    #[tokio::test]
    async fn watcher_reconciles_directory_moves_and_atomic_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let watched = dir.path().join("watched");
        let staged = dir.path().join("staged");
        std::fs::create_dir(&watched).unwrap();
        std::fs::create_dir(&staged).unwrap();
        std::fs::write(staged.join("token"), "first").unwrap();
        let store = store(&watched);
        let task = AsyncFileWatcher::new(store.clone())
            .with_debounce_ms(10)
            .start()
            .await
            .unwrap();
        let nested = watched.join("nested");
        std::fs::rename(&staged, &nested).unwrap();
        wait_for(&store, Some("first")).await;
        std::fs::write(dir.path().join("replacement"), "second").unwrap();
        std::fs::rename(dir.path().join("replacement"), nested.join("token")).unwrap();
        wait_for(&store, Some("second")).await;
        std::fs::rename(&nested, &staged).unwrap();
        wait_for(&store, None).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn periodic_scan_recovers_without_notifications() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        let store = store(dir.path());
        std::fs::write(&path, "old").unwrap();
        store.refresh().await.unwrap();
        // No OS watcher or event sends: only the recovery timer can update the cache.
        let (_sender, receiver) = mpsc::channel(1);
        let watcher = AsyncFileWatcher::new(store.clone());
        let task = tokio::spawn(watcher.run(receiver, Duration::from_millis(20)));
        std::fs::write(&path, "new").unwrap();
        wait_for(&store, Some("new")).await;
        std::fs::remove_file(path).unwrap();
        wait_for(&store, None).await;
        task.abort();
        let _ = task.await;
    }
}
