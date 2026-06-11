// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axum::extract::MatchedPath;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use serde::Serialize;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone)]
pub struct AccessLogModel(pub String);

#[derive(Serialize)]
struct AccessLogEntry {
    ts: String,
    trace_id: String,
    method: String,
    path: String,
    model: String,
    status: u16,
    duration_ms: f64,
}

// ---------------------------------------------------------------------------
// ReopenableWriter
// ---------------------------------------------------------------------------

pub struct ReopenableWriter {
    path: PathBuf,
    inner: parking_lot::Mutex<BufWriter<File>>,
}

impl ReopenableWriter {
    pub fn new(path: &Path) -> io::Result<Self> {
        let file = File::options().create(true).append(true).open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            inner: parking_lot::Mutex::new(BufWriter::new(file)),
        })
    }

    pub fn reopen(&self) -> io::Result<()> {
        let new_file = File::options()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let mut guard = self.inner.lock();
        guard.flush()?;
        *guard = BufWriter::new(new_file);
        Ok(())
    }

    fn write_batch(&self, entries: &[AccessLogEntry]) -> io::Result<()> {
        let mut guard = self.inner.lock();
        for entry in entries {
            if let Ok(line) = serde_json::to_vec(entry) {
                guard.write_all(&line)?;
                guard.write_all(b"\n")?;
            }
        }
        guard.flush()
    }
}

pub struct ReopenableWriterGuard<'a>(parking_lot::MutexGuard<'a, BufWriter<File>>);

impl<'a> io::Write for ReopenableWriterGuard<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<'a> MakeWriter<'a> for ReopenableWriter {
    type Writer = ReopenableWriterGuard<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        ReopenableWriterGuard(self.inner.lock())
    }
}

/// Wrapper for use with `tracing_subscriber::fmt().with_writer(...)`,
/// which requires a `'static + MakeWriter` value.
///
/// Each `make_writer` call opens the file (via `File::try_clone` on the current fd),
/// so tracing holds its own fd and does not interfere with `BufWriter`-based
/// access-log writes or `reopen()`.
#[derive(Clone)]
pub struct SharedReopenableWriter(pub std::sync::Arc<ReopenableWriter>);

pub struct TracingFileWriter(File);

impl io::Write for TracingFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<'a> MakeWriter<'a> for SharedReopenableWriter {
    type Writer = TracingFileWriter;

    fn make_writer(&'a self) -> Self::Writer {
        let guard = self.0.inner.lock();
        let file = guard
            .get_ref()
            .try_clone()
            .expect("failed to clone log file fd");
        TracingFileWriter(file)
    }
}

// ---------------------------------------------------------------------------
// AccessLogWriter
// ---------------------------------------------------------------------------

static ACCESS_LOG_DROPPED: AtomicU64 = AtomicU64::new(0);
static ACCESS_LOG_IO_ERRORS: AtomicU64 = AtomicU64::new(0);

pub struct AccessLogWriter {
    tx: Option<flume::Sender<AccessLogEntry>>,
    thread_handle: Option<std::thread::JoinHandle<()>>,
    writer: std::sync::Arc<ReopenableWriter>,
    pub trace_id_header: String,
}

impl AccessLogWriter {
    pub fn new(path: &Path, trace_id_header: String) -> io::Result<Self> {
        let writer = std::sync::Arc::new(ReopenableWriter::new(path)?);
        let (tx, rx) = flume::bounded::<AccessLogEntry>(8192);

        let w = writer.clone();
        let handle = std::thread::Builder::new()
            .name("access-log-writer".into())
            .spawn(move || writer_loop(rx, &w))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(Self {
            tx: Some(tx),
            thread_handle: Some(handle),
            writer,
            trace_id_header,
        })
    }

    pub fn reopen(&self) -> io::Result<()> {
        self.writer.reopen()
    }

    fn send(&self, entry: AccessLogEntry) {
        let Some(ref tx) = self.tx else { return };
        match tx.try_send(entry) {
            Ok(()) => {}
            Err(flume::TrySendError::Full(_)) => {
                let prev = ACCESS_LOG_DROPPED.fetch_add(1, Ordering::Relaxed);
                if prev % 1000 == 0 {
                    tracing::warn!(
                        total_dropped = prev + 1,
                        "access log channel full, dropping entry"
                    );
                }
            }
            Err(flume::TrySendError::Disconnected(_)) => {}
        }
    }

    pub fn shutdown(self) {
        drop(self);
    }
}

impl Drop for AccessLogWriter {
    fn drop(&mut self) {
        self.tx.take();
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}

fn writer_loop(rx: flume::Receiver<AccessLogEntry>, writer: &ReopenableWriter) {
    let mut buf = Vec::with_capacity(256);

    loop {
        let deadline = Instant::now() + Duration::from_millis(200);
        while buf.len() < 256 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match rx.recv_timeout(remaining) {
                Ok(entry) => buf.push(entry),
                Err(flume::RecvTimeoutError::Timeout) => break,
                Err(flume::RecvTimeoutError::Disconnected) => {
                    buf.extend(rx.try_iter());
                    if !buf.is_empty() {
                        let _ = writer.write_batch(&buf);
                    }
                    return;
                }
            }
        }

        if !buf.is_empty() {
            if let Err(e) = writer.write_batch(&buf) {
                let prev = ACCESS_LOG_IO_ERRORS.fetch_add(buf.len() as u64, Ordering::Relaxed);
                if prev % 1000 == 0 {
                    tracing::warn!(error = %e, "access log write error");
                }
            }
            buf.clear();
        }
    }
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

pub async fn access_log_middleware(
    axum::extract::State(writer): axum::extract::State<Option<std::sync::Arc<AccessLogWriter>>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let Some(ref writer) = writer else {
        return next.run(req).await;
    };

    let trace_id = req
        .headers()
        .get(writer.trace_id_header.as_str())
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_owned();
    let method = req.method().to_string();
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| "unknown".to_owned());

    let start = Instant::now();
    let response = next.run(req).await;
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    let status = response.status().as_u16();
    let model = response
        .extensions()
        .get::<AccessLogModel>()
        .map(|m| m.0.as_str())
        .unwrap_or("-")
        .to_owned();

    let ts = chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, false);

    writer.send(AccessLogEntry {
        ts,
        trace_id,
        method,
        path,
        model,
        status,
        duration_ms,
    });

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn reopenable_writer_write_batch_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        let writer = ReopenableWriter::new(&path).unwrap();

        let entries = vec![AccessLogEntry {
            ts: "2026-01-01T00:00:00.000Z".into(),
            trace_id: "t1".into(),
            method: "GET".into(),
            path: "/health".into(),
            model: "-".into(),
            status: 200,
            duration_ms: 0.1,
        }];
        writer.write_batch(&entries).unwrap();

        let rotated = dir.path().join("test.log.1");
        std::fs::rename(&path, &rotated).unwrap();
        writer.reopen().unwrap();

        let entries2 = vec![AccessLogEntry {
            ts: "2026-01-01T00:00:01.000Z".into(),
            trace_id: "t2".into(),
            method: "POST".into(),
            path: "/query".into(),
            model: "llama".into(),
            status: 200,
            duration_ms: 1.0,
        }];
        writer.write_batch(&entries2).unwrap();

        let mut old_content = String::new();
        File::open(&rotated)
            .unwrap()
            .read_to_string(&mut old_content)
            .unwrap();
        assert!(old_content.contains("\"trace_id\":\"t1\""));
        assert!(!old_content.contains("\"trace_id\":\"t2\""));

        let mut new_content = String::new();
        File::open(&path)
            .unwrap()
            .read_to_string(&mut new_content)
            .unwrap();
        assert!(new_content.contains("\"trace_id\":\"t2\""));
        assert!(!new_content.contains("\"trace_id\":\"t1\""));
    }

    #[test]
    fn access_log_writer_shutdown_drains() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.log");
        let writer = AccessLogWriter::new(&path, "x-trace-id".into()).unwrap();

        for i in 0..5 {
            writer.send(AccessLogEntry {
                ts: format!("2026-01-01T00:00:0{i}.000Z"),
                trace_id: format!("req-{i}"),
                method: "GET".into(),
                path: "/health".into(),
                model: "-".into(),
                status: 200,
                duration_ms: 0.1,
            });
        }

        writer.shutdown();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 5);
        assert!(content.contains("\"trace_id\":\"req-0\""));
        assert!(content.contains("\"trace_id\":\"req-4\""));
    }
}
