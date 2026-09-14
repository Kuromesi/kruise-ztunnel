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

use std::convert::Infallible;
use std::future::Future;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::TryFutureExt;
use http_body_util::Full;
use hyper::{Request, Response};
use tokio::net::{UnixListener, UnixStream};
use tracing::{info, warn};

use crate::drain::DrainWatcher;
use crate::hyper_util::http1_server;

struct SocketCleanup {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        // Never unlink a replacement created by another process.
        if let Ok(metadata) = std::fs::symlink_metadata(&self.path) {
            if metadata.dev() == self.dev && metadata.ino() == self.ino {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}

// This transport is private to the admin API. TCP admin, readiness and metrics
// continue to use the existing hyper_util::Server.
pub(super) struct UnixServer<S> {
    name: String,
    listener: UnixListener,
    cleanup: SocketCleanup,
    drain_rx: DrainWatcher,
    state: S,
}

impl<S> UnixServer<S> {
    /// Bind only a filesystem socket. The parent directory must be private to the
    /// sidecar; do not share it with application containers.
    pub(super) async fn bind(
        name: &str,
        path: &Path,
        drain_rx: DrainWatcher,
        state: S,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(path.is_absolute(), "Unix socket path must be absolute");
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("socket has no parent"))?;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                anyhow::ensure!(
                    metadata.file_type().is_socket(),
                    "refusing to replace non-socket {}",
                    path.display()
                );
                match tokio::time::timeout(Duration::from_secs(1), UnixStream::connect(path))
                    .await?
                {
                    Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                        std::fs::remove_file(path)?;
                    }
                    Err(e) => return Err(e.into()),
                    Ok(_) => anyhow::bail!("Unix socket {} is already in use", path.display()),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let listener = UnixListener::bind(path)?;
        let metadata = std::fs::symlink_metadata(path)?;
        let cleanup = SocketCleanup {
            path: path.to_path_buf(),
            dev: metadata.dev(),
            ino: metadata.ino(),
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            name: name.to_string(),
            listener,
            cleanup,
            drain_rx,
            state,
        })
    }

    pub(super) fn state_mut(&mut self) -> &mut S {
        &mut self.state
    }

    pub(super) fn spawn<F, R>(self, f: F)
    where
        S: Send + Sync + 'static,
        F: Fn(Arc<S>, Request<hyper::body::Incoming>) -> R + Send + Sync + 'static,
        R: Future<Output = Result<Response<Full<Bytes>>, anyhow::Error>> + Send + Sync + 'static,
    {
        let address = self.cleanup.path.display().to_string();
        let drain = self.drain_rx;
        let state = Arc::new(self.state);
        let f = Arc::new(f);
        info!(
            %address,
            component=self.name,
            "listener established",
        );
        let bind = self.listener;
        let cleanup = self.cleanup;
        let drain_stream = drain.clone();
        let drain_connections = drain;
        let name = self.name;
        tokio::spawn(async move {
            let drained = drain_stream.wait_for_drain();
            tokio::pin!(drained);
            loop {
                let socket = tokio::select! {
                    biased;
                    _ = &mut drained => break,
                    accepted = bind.accept() => match accepted {
                        Ok((socket, _)) => socket,
                        Err(err) => {
                            warn!(component = name, %err, "listener accept failed");
                            break;
                        }
                    },
                };
                let drain = drain_connections.clone();
                let f = f.clone();
                let state = state.clone();
                tokio::spawn(async move {
                    let serve = http1_server()
                        .half_close(true)
                        .header_read_timeout(Duration::from_secs(2))
                        .max_buf_size(8 * 1024)
                        .serve_connection(
                            hyper_util::rt::TokioIo::new(socket),
                            hyper::service::service_fn(move |req| {
                                let state = state.clone();

                                // Failures would abort the whole connection; we just want to return an HTTP error
                                f(state, req).or_else(|err| async move {
                                    Ok::<Response<Full<Bytes>>, Infallible>(
                                        Response::builder()
                                            .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                                            .body(err.to_string().into())
                                            .expect(
                                                "builder with known status code should not fail",
                                            ),
                                    )
                                })
                            }),
                        );
                    // Wait for drain to signal or connection serving to complete
                    match futures_util::future::select(Box::pin(drain.wait_for_drain()), serve)
                        .await
                    {
                        // We got a shutdown request. Start graceful shutdown and wait for the pending requests to complete.
                        futures_util::future::Either::Left((_shutdown, mut serve)) => {
                            let drain = std::pin::Pin::new(&mut serve);
                            drain.graceful_shutdown();
                            serve.await
                        }
                        // Serving finished, just return the result.
                        futures_util::future::Either::Right((serve, _shutdown)) => serve,
                    }
                });
            }
            drop(bind);
            drop(cleanup);
            info!(
                %address,
                component=name,
                "listener drained",
            );
        });
    }
}

#[cfg(test)]
mod unix_socket_tests {
    use super::*;

    #[tokio::test]
    async fn socket_permissions_cleanup_and_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private/admin.sock");
        let (_trigger, drain) = crate::drain::new();
        let server = UnixServer::bind("test", &path, drain.clone(), ())
            .await
            .unwrap();
        assert_eq!(
            std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            UnixServer::bind("test", &path, drain.clone(), ())
                .await
                .is_err()
        );
        assert!(UnixStream::connect(&path).await.is_ok());
        drop(server);
        assert!(!path.exists());
        // Simulate the file left after a process exits without cleanup.
        drop(UnixListener::bind(&path).unwrap());
        let restarted = UnixServer::bind("test", &path, drain, ()).await.unwrap();
        assert!(UnixStream::connect(&path).await.is_ok());
        drop(restarted);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn preserves_files_symlinks_and_replacements() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("admin.sock");
        let (_trigger, drain) = crate::drain::new();
        std::fs::write(&path, "keep").unwrap();
        assert!(
            UnixServer::bind("test", &path, drain.clone(), ())
                .await
                .is_err()
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "keep");
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(dir.path().join("missing"), &path).unwrap();
        assert!(
            UnixServer::bind("test", &path, drain.clone(), ())
                .await
                .is_err()
        );
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        std::fs::remove_file(&path).unwrap();
        let server = UnixServer::bind("test", &path, drain, ()).await.unwrap();
        std::fs::remove_file(&path).unwrap();
        let replacement = UnixListener::bind(&path).unwrap();
        drop(server);
        assert!(path.exists());
        drop(replacement);
    }
}
