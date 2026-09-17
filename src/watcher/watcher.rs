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

use arc_swap::ArcSwap;
use notify_debouncer_full::{DebounceEventResult, Debouncer, FileIdMap, new_debouncer_opt};
use std::sync::{Arc, RwLock};
use std::{fs, path::PathBuf, time::Duration};

use std::{
    collections::{HashMap, HashSet},
    hash::{DefaultHasher, Hash, Hasher},
};

use anyhow::Context;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Tracks a file's content hash and transformed value.
#[derive(Clone)]
pub struct FileTracker<V> {
    pub path: PathBuf,
    pub hash: u64,
    pub transformed: Arc<V>,
}

/// Thread-safe store that holds transformed file contents.
pub struct FileStore<K, V> {
    pub transform: fn(String) -> anyhow::Result<V>,
    pub key_func: fn(&PathBuf) -> Option<K>,
    pub store: ArcSwap<HashMap<K, FileTracker<V>>>,
    write_lock: tokio::sync::Mutex<()>,
}

impl<K, V> FileStore<K, V>
where
    K: Hash + Eq + Clone + Send + Sync + std::fmt::Debug + 'static,
    V: Clone + Send + Sync + 'static,
{
    pub fn new(
        transform: fn(String) -> anyhow::Result<V>,
        key_func: fn(&PathBuf) -> Option<K>,
    ) -> Self {
        Self {
            transform,
            key_func,
            store: ArcSwap::new(Arc::new(HashMap::new())),
            write_lock: tokio::sync::Mutex::new(()),
        }
    }
    /// Handles file change events: reads, transforms, and updates the store.
    pub async fn handle_change(&self, path: &PathBuf) -> anyhow::Result<()> {
        // Canonicalize early so we deduplicate across symlinks.
        let canonical = match path.canonicalize() {
            Ok(p) => p,
            Err(_) => {
                debug!("Path no longer exists, removing: {:?}", path);
                self.handle_remove(path).await;
                return Ok(());
            }
        };

        let key = match (self.key_func)(&canonical) {
            Some(k) => k,
            None => return Ok(()),
        };

        // Read file content.
        let content = match tokio::fs::read_to_string(&canonical).await {
            Ok(c) => c,
            Err(e) => {
                debug!("Failed to read {:?}: {}", canonical, e);
                self.handle_remove(&canonical).await;
                return Ok(());
            }
        };

        // Transform content to value.
        let value = match (self.transform)(content.clone()) {
            Ok(v) => v,
            Err(e) => {
                // Keep old value on transient parse errors (e.g., K8s mid-write).
                warn!(
                    "Transform error for {:?}: {}, keeping old value",
                    canonical, e
                );
                return Ok(());
            }
        };

        // Compute hash.
        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        let hash = hasher.finish();

        // Update store.
        {
            let _guard = self.write_lock.lock().await;
            let current_map = self.store.load();

            if let Some(tracker) = current_map.get(&key) {
                if tracker.hash == hash {
                    debug!("File unchanged: {:?}", canonical);
                    return Ok(());
                }
            }

            let mut new_map = (**current_map).clone();
            new_map.insert(
                key.clone(),
                FileTracker {
                    path: canonical,
                    hash,
                    transformed: Arc::new(value),
                },
            );
            self.store.store(Arc::new(new_map));
            info!("Updated store (hash={})", hash);
        }

        Ok(())
    }

    /// Return a cached value, or make one blocking read attempt on an empty store.
    /// Never overwrite a store update that happened while the read was in flight.
    /// An absent file is not cached, so the next caller can observe its creation.
    pub async fn get_or_load<F>(&self, load: F) -> anyhow::Result<Option<Arc<V>>>
    where
        F: FnOnce() -> std::io::Result<Option<(PathBuf, String)>> + Send + 'static,
    {
        let snapshot = self.store.load_full();
        if let Some(tracker) = snapshot.values().next() {
            return Ok(Some(tracker.transformed.clone()));
        }

        let loaded = tokio::task::spawn_blocking(load)
            .await
            .context("file read task failed")??;
        let Some((path, content)) = loaded else {
            return Ok(self.first());
        };
        let Some(key) = (self.key_func)(&path) else {
            return Ok(self.first());
        };
        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        let hash = hasher.finish();
        let transformed = Arc::new((self.transform)(content)?);

        let _guard = self.write_lock.lock().await;
        let current = self.store.load();
        if !Arc::ptr_eq(&snapshot, &current) {
            return Ok(current.values().next().map(|v| v.transformed.clone()));
        }
        self.store.store(Arc::new(HashMap::from([(
            key,
            FileTracker {
                path,
                hash,
                transformed: transformed.clone(),
            },
        )])));
        Ok(Some(transformed))
    }

    /// Return the first value in the store's unspecified iteration order.
    pub fn first(&self) -> Option<Arc<V>> {
        self.store
            .load()
            .values()
            .next()
            .map(|v| v.transformed.clone())
    }

    /// Removes a file entry from the store.
    pub async fn handle_remove(&self, path: &PathBuf) {
        let Some(key) = (self.key_func)(path) else {
            return;
        };

        let _guard = self.write_lock.lock().await;
        let current_map = self.store.load();
        let mut new_map = (**current_map).clone();
        let removed = new_map.remove(&key).is_some();
        // Publish even when the key was not cached: a concurrent read-through
        // may have read this file before its deletion and must not restore it.
        self.store.store(Arc::new(new_map));
        if removed {
            info!("Removed {:?} from store (key={:?})", path, key);
        }
    }

    pub fn get(&self, key: &K) -> Option<Arc<V>> {
        self.store
            .load()
            .get(key)
            .map(|tracker| tracker.transformed.clone())
    }

    pub fn values(&self) -> Vec<Arc<V>> {
        self.store
            .load()
            .values()
            .map(|tracker| tracker.transformed.clone())
            .collect()
    }

    pub fn keys(&self) -> Vec<K> {
        self.store.load().keys().cloned().collect()
    }

    pub fn values_owned(&self) -> Vec<V>
    where
        V: Clone,
    {
        self.store
            .load()
            .values()
            .map(|tracker| (*tracker.transformed).clone())
            .collect()
    }
}

/// Asynchronous file watcher that monitors a directory and updates the store.
pub struct AsyncFileWatcher<K, V>
where
    K: Hash + Eq + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    store: Arc<FileStore<K, V>>,
    watch_path: PathBuf,
    debounce_ms: u64,
}

impl<K, V> AsyncFileWatcher<K, V>
where
    K: Hash + Eq + Clone + Send + Sync + std::fmt::Debug + 'static,
    V: Clone + Send + Sync + 'static,
{
    pub fn new(store: Arc<FileStore<K, V>>, path: impl Into<PathBuf>) -> Self {
        Self {
            store,
            watch_path: path.into(),
            debounce_ms: 500,
        }
    }

    /// Set the debounce interval in milliseconds.
    /// Higher values batch more events but increase update latency.
    pub fn with_debounce_ms(mut self, ms: u64) -> Self {
        self.debounce_ms = ms;
        self
    }

    pub fn store(&self) -> Arc<FileStore<K, V>> {
        self.store.clone()
    }

    /// Starts the watcher: sets up notify first, then scans existing files.
    pub async fn start(self) -> anyhow::Result<tokio::task::JoinHandle<()>> {
        // Channel: size 256 to tolerate bursts.
        let (tx, mut rx) = mpsc::channel::<Event>(256);

        // Create watcher *before* scanning so we don't miss early events.
        let watch_path = self.watch_path.clone();
        let mut watcher = RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                if let Ok(event) = res {
                    debug!(
                        kind = ?event.kind,
                        paths = ?event.paths,
                        "Notify event"
                    );
                    if tx.try_send(event).is_err() {
                        warn!("Event channel full, dropping event");
                    }
                }
            },
            Config::default(),
        )
        .context("failed to create file watcher")?;

        watcher
            .watch(&watch_path, RecursiveMode::Recursive)
            .context("failed to watch path")?;

        info!("Watching directory: {:?}", watch_path);

        // Spawn the event processing loop (debounce + process).
        let store = self.store.clone();
        let debounce_interval = Duration::from_millis(self.debounce_ms);

        let handle = tokio::spawn(async move {
            let _keep_alive = watcher; // keep watcher alive for the lifetime of this task

            let mut pending: HashSet<PathBuf> = HashSet::new();
            let mut tick = tokio::time::interval(debounce_interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    biased;
                    // Collect incoming events into the pending set.
                    Some(event) = rx.recv() => {
                        for path in event.paths {
                            match event.kind {
                                EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {
                                    pending.insert(path);
                                }
                                _ => {}
                            }
                        }
                    }

                    // Debounce tick: flush pending paths.
                    _ = tick.tick() => {
                        if pending.is_empty() {
                            continue;
                        }

                        let paths: Vec<_> = pending.drain().collect();
                        debug!("Debounce tick: processing {} paths", paths.len());

                        for path in &paths {
                            if path.is_file() {
                                // Best-effort: log errors but don't abort the loop.
                                if let Err(e) = store.handle_change(path).await {
                                    warn!("Failed to handle change: {}", e);
                                }
                            } else {
                                // Likely removed or a broken symlink.
                                store.handle_remove(path).await;
                            }
                        }
                    }
                }
            }
        });

        // Initial scan *after* watcher is running, so early events are captured.
        // This also runs concurrently — the watcher thread will process events
        // while we scan.
        let store_scan = self.store.clone();
        let path_scan = self.watch_path.clone();
        tokio::spawn(async move {
            info!("Initial scan of {:?}", path_scan);
            match tokio::task::spawn_blocking(move || {
                let mut files = Vec::new();
                let walker = walkdir::WalkDir::new(&path_scan);
                for entry in walker.into_iter().filter_map(|e| e.ok()) {
                    if entry.file_type().is_file() {
                        files.push(entry.path().to_path_buf());
                    }
                }
                files
            })
            .await
            {
                Ok(file_paths) => {
                    info!("Found {} files in initial scan", file_paths.len());
                    for path in &file_paths {
                        if let Err(e) = store_scan.handle_change(path).await {
                            warn!("Initial scan failed for {:?}: {}", path, e);
                        }
                    }
                }
                Err(e) => {
                    warn!("Initial scan task panicked: {}", e);
                }
            }
            info!("Initial scan completed");
        });

        Ok(handle)
    }
}

pub struct FileWatcher<V> {
    path: PathBuf,
    debouncer: RwLock<Option<Debouncer<RecommendedWatcher, FileIdMap>>>,
    pub transform: fn(String) -> anyhow::Result<V>,
    transformed: ArcSwap<Option<V>>,
}

impl<V> FileWatcher<V>
where
    V: Clone + Send + Sync + 'static,
{
    pub fn new(path: PathBuf, transform: fn(String) -> anyhow::Result<V>) -> Self {
        Self {
            path,
            debouncer: RwLock::new(None),
            transform,
            transformed: ArcSwap::new(Arc::new(None)),
        }
    }

    fn load(&self) -> anyhow::Result<()> {
        let content = fs::read_to_string(&self.path)?;
        let transformed = (self.transform)(content)?;

        self.transformed.store(Arc::new(Some(transformed)));
        Ok(())
    }

    pub fn read(&self) -> Arc<Option<V>> {
        self.transformed.load().clone()
    }

    pub fn run(self: &Arc<Self>) -> anyhow::Result<()> {
        debug!(
            path = ?self.path,
            debounce_secs = 2,
            "starting file watcher"
        );

        let watcher: Arc<FileWatcher<V>> = self.clone();
        // create debouncer with 2-second timeout
        // this collapses multiple events (CREATE/CHMOD/RENAME/REMOVE) into a single reload
        let mut debouncer = new_debouncer_opt(
            Duration::from_secs(2),
            None,
            move |result: DebounceEventResult| match result {
                Ok(events) => {
                    if !events.is_empty() {
                        debug!(event_count = events.len(), "directory events detected");

                        debug!("directory changed, reloading");
                        match watcher.load() {
                            Ok(()) => {
                                debug!("file reloaded successfully after file change");
                            }
                            Err(e) => debug!(error = %e, "failed to reload file"),
                        }
                    }
                }
                Err(errors) => {
                    for error in errors {
                        debug!(error = ?error, "watcher error");
                    }
                }
            },
            FileIdMap::new(),
            notify::Config::default(),
        )?;

        // start watching the directory
        debouncer.watch(self.path.clone(), RecursiveMode::NonRecursive)?;

        {
            let mut guard = self.debouncer.write().unwrap();
            *guard = Some(debouncer);
        }

        debug!("file watcher started successfully");
        Ok(())
    }
}

#[cfg(test)]
mod read_through_tests {
    use super::*;

    fn store() -> Arc<FileStore<String, String>> {
        Arc::new(FileStore::new(Ok, |path| {
            path.file_stem().map(|s| s.to_string_lossy().into_owned())
        }))
    }

    #[tokio::test]
    async fn cache_hit_skips_loader() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "cached").unwrap();
        let store = store();
        store.handle_change(&path).await.unwrap();
        assert_eq!(
            store
                .get_or_load(|| panic!("cache hit must not read files"))
                .await
                .unwrap(),
            Some(Arc::new("cached".to_string()))
        );
    }

    #[tokio::test]
    async fn stale_read_does_not_overwrite_watcher_update() {
        concurrent_update(false).await;
    }

    #[tokio::test]
    async fn stale_read_does_not_restore_a_removed_token() {
        concurrent_update(true).await;
    }

    #[tokio::test]
    async fn stale_read_does_not_cache_a_file_removed_before_its_first_publication() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "stale").unwrap();
        let store = store();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let reader = {
            let store = store.clone();
            let path = path.clone();
            tokio::spawn(async move {
                store
                    .get_or_load(move || {
                        let content = std::fs::read_to_string(&path)?;
                        started_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                        Ok(Some((path, content)))
                    })
                    .await
                    .unwrap()
            })
        };
        started_rx.await.unwrap();
        std::fs::remove_file(&path).unwrap();
        store.handle_remove(&path).await;
        release_tx.send(()).unwrap();
        assert!(reader.await.unwrap().is_none());
        assert!(store.first().is_none());
    }

    async fn concurrent_update(remove: bool) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        let store = store();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let reader = {
            let store = store.clone();
            let path = path.clone();
            tokio::spawn(async move {
                store
                    .get_or_load(move || {
                        started_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                        Ok(Some((path, "stale".to_string())))
                    })
                    .await
                    .unwrap()
            })
        };
        started_rx.await.unwrap();
        std::fs::write(&path, "newer").unwrap();
        store.handle_change(&path).await.unwrap();
        if remove {
            std::fs::remove_file(&path).unwrap();
            store.handle_remove(&path).await;
        }
        release_tx.send(()).unwrap();
        let expected = (!remove).then(|| Arc::new("newer".to_string()));
        assert_eq!(reader.await.unwrap(), expected);
        assert_eq!(store.first(), expected);
    }
}
