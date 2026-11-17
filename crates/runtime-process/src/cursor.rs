//! Cursor-paged process log: per-process seq-chunk ring buffer.
//!
//! Every chunk of process output is stored with a monotonically increasing
//! sequence number, its stream (stdout/stderr), the text, the raw byte
//! length (before UTF-8 decode) and a timestamp. Readers page with `after`
//! (last observed seq) and get back `next_after` plus
//! `oldest_sequence`, `cursor_lost` and `truncated` metadata.
//!
//! [`CursorLog`] wraps [`ProcessLog`] in a tokio [`Mutex`] plus a [`Notify`]
//! so [`CursorLog::read_after`] can block until newer chunks arrive instead
//! of polling.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use tokio::sync::{Mutex, Notify};

/// Default ring buffer size: 4 MB of raw (pre-UTF-8-decode) bytes.
pub const DEFAULT_RING_BUFFER_BYTES: usize = 4_000_000;

/// Output stream a chunk belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamId {
    Stdout,
    Stderr,
}

/// One numbered chunk of process output.
#[derive(Debug, Clone)]
pub struct Chunk {
    pub seq: u64,
    pub stream: StreamId,
    pub text: String,
    pub raw_len: usize, // byte length before UTF-8 decode
    pub at: DateTime<Utc>,
}

/// Result of a cursor-paged read.
#[derive(Debug, Clone)]
pub struct ReadPage {
    pub chunks: Vec<Chunk>,
    pub oldest_sequence: u64,
    pub cursor_lost: bool,   // `after` predates the oldest retained chunk
    pub next_after: Option<u64>,
    pub truncated: bool,     // page stopped because `limit_bytes` was exceeded
}

/// Per-process seq-chunk ring buffer.
///
/// Chunks are appended with monotonically increasing sequences starting at 1.
/// When total raw bytes exceed `max_bytes` (default 4 MB) the oldest chunks
/// are dropped, keeping the buffer bounded.
#[derive(Debug, Clone)]
pub struct ProcessLog {
    pub chunks: VecDeque<Chunk>,
    pub next_seq: u64,
    pub raw_bytes: usize,
    max_bytes: usize,
}

impl ProcessLog {
    pub fn new() -> Self {
        Self::with_max_bytes(DEFAULT_RING_BUFFER_BYTES)
    }

    pub fn with_max_bytes(max_bytes: usize) -> Self {
        Self {
            chunks: VecDeque::new(),
            next_seq: 1,
            raw_bytes: 0,
            max_bytes,
        }
    }

    /// Append `text` on `stream` and return the assigned sequence number.
    pub fn push(&mut self, stream: StreamId, text: String) -> u64 {
        let raw_len = text.len();
        let seq = self.next_seq;
        self.next_seq += 1;
        self.chunks.push_back(Chunk {
            seq,
            stream,
            text,
            raw_len,
            at: Utc::now(),
        });
        self.raw_bytes += raw_len;
        self.trim();
        seq
    }

    /// Drop the oldest chunks while raw bytes exceed the limit.
    fn trim(&mut self) {
        while self.raw_bytes > self.max_bytes {
            let Some(chunk) = self.chunks.pop_front() else {
                break;
            };
            self.raw_bytes = self.raw_bytes.saturating_sub(chunk.raw_len);
        }
    }

    /// Sequence of the oldest retained chunk, or `next_seq` when empty.
    pub fn oldest_sequence(&self) -> u64 {
        self.chunks
            .front()
            .map(|chunk| chunk.seq)
            .unwrap_or(self.next_seq)
    }

    /// Read chunks with `seq > after`, bounded by `limit_bytes` raw bytes.
    ///
    /// # Cursor-paging semantics
    ///
    /// * `cursor_lost` is set when `after > 0` and `after < oldest - 1`
    ///   (the cursor predates the oldest retained chunk, e.g. after ring
    ///   buffer trim).
    /// * Chunks are included while the running raw-byte total stays within
    ///   `limit_bytes`; the first chunk that would exceed it stops the page
    ///   and sets `truncated = true`.
    /// * `next_after` is the last included seq, or `after` unchanged when the
    ///   page is empty.
    pub fn read_after(&mut self, after: u64, limit_bytes: usize) -> ReadPage {
        let oldest = self.oldest_sequence();
        let cursor_lost = after > 0 && after < oldest.saturating_sub(1);

        let mut chunks = Vec::new();
        let mut bytes = 0usize;
        let mut truncated = false;
        // Empty pages keep the cursor unchanged so callers can retry.
        let mut next_after = if after > 0 { Some(after) } else { None };

        for chunk in self.chunks.iter() {
            if chunk.seq <= after {
                continue;
            }
            if bytes + chunk.raw_len > limit_bytes && !chunks.is_empty() {
                truncated = true;
                break;
            }
            bytes += chunk.raw_len;
            next_after = Some(chunk.seq);
            chunks.push(chunk.clone());
        }

        ReadPage {
            chunks,
            oldest_sequence: oldest,
            cursor_lost,
            next_after,
            truncated,
        }
    }
}

impl Default for ProcessLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Tokio-aware process log.
///
/// [`ProcessLog`] behind a tokio [`Mutex`] plus a [`Notify`]. [`push`](Self::push)
/// appends and wakes waiters; [`read_after`](Self::read_after) blocks until a
/// chunk with `seq > after` exists or `wait_ms` elapses.
#[derive(Clone)]
pub struct CursorLog {
    inner: Arc<Mutex<ProcessLog>>,
    notify: Arc<Notify>,
}

impl CursorLog {
    pub fn new() -> Self {
        Self::with_max_bytes(DEFAULT_RING_BUFFER_BYTES)
    }

    pub fn with_max_bytes(max_bytes: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ProcessLog::with_max_bytes(max_bytes))),
            notify: Arc::new(Notify::new()),
        }
    }

    /// Append output and wake any waiters. Returns the assigned seq.
    pub async fn push(&self, stream: StreamId, text: String) -> u64 {
        let mut inner = self.inner.lock().await;
        let seq = inner.push(stream, text);
        drop(inner);
        self.notify.notify_waiters();
        seq
    }

    /// Read chunks with `seq > after`.
    ///
    /// Waits until such a chunk exists or `wait_ms` milliseconds elapse
    /// (`0` returns immediately without waiting). Returns the page for the
    /// current buffer contents.
    pub async fn read_after(
        &self,
        after: u64,
        limit_bytes: usize,
        wait_ms: u64,
    ) -> ReadPage {
        let deadline = if wait_ms == 0 {
            None
        } else {
            Some(Instant::now() + Duration::from_millis(wait_ms))
        };

        loop {
            // Fast path: newer data already present.
            {
                let mut inner = self.inner.lock().await;
                if inner.chunks.iter().any(|chunk| chunk.seq > after) {
                    return inner.read_after(after, limit_bytes);
                }
            }

            let Some(deadline) = deadline else {
                let mut inner = self.inner.lock().await;
                return inner.read_after(after, limit_bytes);
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return self.inner.lock().await.read_after(after, limit_bytes);
            }

            tokio::select! {
                _ = self.notify.notified() => {}
                _ = tokio::time::sleep(remaining) => {
                    let mut inner = self.inner.lock().await;
                    return inner.read_after(after, limit_bytes);
                }
            }
        }
    }

    pub fn inner(&self) -> Arc<Mutex<ProcessLog>> {
        Arc::clone(&self.inner)
    }
}

impl Default for CursorLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Process registry with cursor logs and garbage collection.
///
/// Tracks one [`CursorLog`] per process id. Exited processes are garbage
/// collected when either:
/// * they exited longer than `ttl` ago, or
/// * there are more than `max_processes` total: the oldest exited ones go first.
#[derive(Clone, Default)]
pub struct ProcessRegistry {
    logs: HashMap<String, Arc<CursorLog>>,
    exited_at: HashMap<String, DateTime<Utc>>,
}

impl ProcessRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a process, creating its log on first sight.
    pub fn register(&mut self, id: &str) -> Arc<CursorLog> {
        if let Some(log) = self.logs.get(id) {
            return Arc::clone(log);
        }
        let log = Arc::new(CursorLog::new());
        self.logs.insert(id.to_string(), Arc::clone(&log));
        log
    }

    pub fn get(&self, id: &str) -> Option<Arc<CursorLog>> {
        self.logs.get(id).map(Arc::clone)
    }

    /// Mark `id` as exited at `at`, making it eligible for GC.
    pub fn record_exit(&mut self, id: &str, at: DateTime<Utc>) {
        self.exited_at.insert(id.to_string(), at);
    }

    pub fn len(&self) -> usize {
        self.logs.len()
    }

    /// Run garbage collection as of `now`.
    pub fn gc(&mut self, now: DateTime<Utc>, ttl: Duration, max_processes: usize) {
        // 1. TTL: drop processes exited longer ago than `ttl`.
        let expired: Vec<String> = self
            .exited_at
            .iter()
            .filter(|(_, at)| {
                now.signed_duration_since(**at).num_seconds() > ttl.as_secs() as i64
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in &expired {
            self.logs.remove(id);
            self.exited_at.remove(id);
        }

        // 2. Count: drop oldest exited processes beyond the limit.
        if self.logs.len() > max_processes {
            let mut exited: Vec<(DateTime<Utc>, String)> = self
                .exited_at
                .iter()
                .map(|(id, at)| (*at, id.clone()))
                .collect();
            exited.sort_by_key(|(at, _)| *at);
            let to_drop = self.logs.len() - max_processes;
            for (_, id) in exited.iter().take(to_drop) {
                self.logs.remove(id);
                self.exited_at.remove(id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_assigns_monotonic_seqs() {
        let mut log = ProcessLog::new();
        let s1 = log.push(StreamId::Stdout, "one".into());
        let s2 = log.push(StreamId::Stderr, "two".into());
        let s3 = log.push(StreamId::Stdout, "three".into());
        assert_eq!((s1, s2, s3), (1, 2, 3));
        assert_eq!(log.next_seq, 4);
        assert_eq!(log.raw_bytes, 3 + 3 + 5);
        assert_eq!(
            log.chunks.iter().map(|c| c.stream).collect::<Vec<_>>(),
            vec![StreamId::Stdout, StreamId::Stderr, StreamId::Stdout]
        );
    }

    #[test]
    fn raw_len_is_byte_length() {
        let mut log = ProcessLog::new();
        log.push(StreamId::Stdout, "héllo".into()); // 5 chars, 6 UTF-8 bytes
        assert_eq!(log.chunks.front().unwrap().raw_len, 6);
    }

    #[test]
    fn read_after_returns_newer_chunks() {
        let mut log = ProcessLog::new();
        for i in 1..=5 {
            log.push(StreamId::Stdout, format!("chunk {i}"));
        }
        let page = log.read_after(2, 10_000);
        assert_eq!(page.chunks.len(), 3);
        assert_eq!(
            page.chunks.iter().map(|c| c.seq).collect::<Vec<_>>(),
            vec![3, 4, 5]
        );
        assert_eq!(page.next_after, Some(5));
        assert!(!page.truncated);
        assert!(!page.cursor_lost);
        assert_eq!(page.oldest_sequence, 1);
        // Chunks preserve seq/stream/at; text is the payload.
        assert!(!page.chunks.iter().any(|c| c.at == DateTime::from_timestamp(0, 0).unwrap()));
    }

    #[test]
    fn read_after_cursor_lost() {
        // Force trim so the oldest retained seq advances past 1.
        let mut log = ProcessLog::with_max_bytes(20);
        for i in 1..=4 {
            log.push(StreamId::Stdout, "1234567890".into()); // raw_len 10 each
        }
        assert_eq!(log.oldest_sequence(), 3); // chunks [3, 4] retained
        assert!(!log.read_after(0, 10_000).cursor_lost); // after == 0 never lost
        assert!(!log.read_after(2, 10_000).cursor_lost); // 2 < 2 is false
        assert!(log.read_after(1, 10_000).cursor_lost);  // 1 < 2
    }

    #[test]
    fn read_after_cursor_lost_after_trim() {
        let mut log = ProcessLog::with_max_bytes(10);
        for i in 1..=5 {
            log.push(StreamId::Stdout, "12345".into()); // raw_len 5 each
        }
        let oldest = log.oldest_sequence();
        assert!(oldest > 1, "oldest should have advanced past trimmed chunks");
        let page = log.read_after(1, 10_000);
        assert!(page.cursor_lost, "cursor 1 predates oldest {oldest}");
        assert_eq!(page.oldest_sequence, oldest);
    }

    #[test]
    fn read_after_truncation() {
        let mut log = ProcessLog::new();
        for _ in 1..=5 {
            log.push(StreamId::Stdout, "aaaa".into()); // 4 bytes each
        }
        // Limit 7 fits exactly one chunk; the second would exceed it.
        let page = log.read_after(0, 7);
        assert_eq!(page.chunks.len(), 1);
        assert_eq!(page.next_after, Some(1));
        assert!(page.truncated);
    }

    #[test]
    fn read_after_oversized_single_chunk() {
        // A chunk bigger than the limit is still returned whole (chunks are
        // atomic); nothing else was cut.
        let mut log = ProcessLog::new();
        log.push(StreamId::Stdout, "aaaa".into());
        let page = log.read_after(0, 2);
        assert_eq!(page.chunks.len(), 1);
        assert!(!page.truncated);
    }

    #[test]
    fn read_after_empty_keeps_cursor() {
        let mut log = ProcessLog::new();
        for i in 1..=3 {
            log.push(StreamId::Stdout, "c".into());
        }
        let page = log.read_after(3, 10_000);
        assert!(page.chunks.is_empty());
        assert_eq!(page.next_after, Some(3)); // unchanged
        assert!(!page.truncated);
        // Empty log: no cursor to preserve.
        let mut empty = ProcessLog::new();
        let page = empty.read_after(0, 10_000);
        assert_eq!(page.next_after, None);
    }

    #[test]
    fn ring_buffer_trims_oldest_chunks() {
        let mut log = ProcessLog::with_max_bytes(10);
        log.push(StreamId::Stdout, "aaaa".into()); // 4 bytes
        log.push(StreamId::Stdout, "bbbb".into()); // 8 bytes
        log.push(StreamId::Stdout, "cccc".into()); // 12 > 10 -> trim "aaaa"
        assert_eq!(log.raw_bytes, 8);
        assert_eq!(log.chunks.len(), 2);
        assert_eq!(log.chunks.front().unwrap().seq, 2);
        assert_eq!(log.oldest_sequence(), 2);
    }

    #[test]
    fn ring_buffer_trim_respects_default_4mb() {
        let mut log = ProcessLog::new();
        let big = "x".repeat(3_000_000);
        log.push(StreamId::Stdout, big.clone());
        log.push(StreamId::Stdout, big); // 6 MB > 4 MB -> first chunk trimmed
        assert_eq!(log.chunks.len(), 1);
        assert_eq!(log.raw_bytes, 3_000_000);
        assert_eq!(log.oldest_sequence(), 2);
    }

    #[test]
    fn oldest_sequence_empty_equals_next_seq() {
        let mut log = ProcessLog::new();
        assert_eq!(log.oldest_sequence(), 1);
    }

    #[tokio::test]
    async fn cursor_log_waits_for_new_data() {
        let log = CursorLog::new();
        let clone = log.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            clone.push(StreamId::Stdout, "hello".into()).await;
        });
        let page = log.read_after(0, 10_000, 500).await;
        assert_eq!(page.chunks.len(), 1);
        assert_eq!(page.chunks[0].text, "hello");
        assert_eq!(page.next_after, Some(1));
    }

    #[tokio::test]
    async fn cursor_log_returns_immediately_when_data_present() {
        let log = CursorLog::new();
        log.push(StreamId::Stdout, "hi".into()).await;
        let page = log.read_after(0, 10_000, 0).await;
        assert_eq!(page.chunks.len(), 1);
    }

    #[tokio::test]
    async fn cursor_log_times_out() {
        let log = CursorLog::new();
        let page = log.read_after(0, 10_000, 20).await;
        assert!(page.chunks.is_empty());
        assert_eq!(page.next_after, None);
    }

    #[tokio::test]
    async fn cursor_log_wait_is_bounded_by_deadline() {
        let log = CursorLog::new();
        let start = Instant::now();
        let page = log.read_after(0, 10_000, 100).await;
        let elapsed = start.elapsed();
        assert!(page.chunks.is_empty());
        assert!(elapsed >= Duration::from_millis(100));
        assert!(elapsed < Duration::from_millis(500));
    }

    #[test]
    fn registry_register_returns_same_log() {
        let mut reg = ProcessRegistry::new();
        let a = reg.register("p1");
        let b = reg.register("p1");
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn registry_gc_ttl() {
        let mut reg = ProcessRegistry::new();
        let now = Utc::now();
        reg.register("old");
        reg.record_exit("old", now - chrono::Duration::hours(2));
        reg.register("fresh");
        reg.record_exit("fresh", now - chrono::Duration::minutes(30));
        reg.gc(
            now,
            chrono::Duration::hours(1).to_std().unwrap(),
            50,
        );
        assert!(reg.get("old").is_none());
        assert!(reg.get("fresh").is_some());
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn registry_gc_max_processes() {
        let mut reg = ProcessRegistry::new();
        let now = Utc::now();
        for i in 0..60 {
            reg.register(&format!("p{i}"));
            // p0 exited longest ago, p59 most recently.
            reg.record_exit(
                &format!("p{i}"),
                now - chrono::Duration::minutes((59 - i) as i64),
            );
        }
        reg.gc(
            now,
            chrono::Duration::hours(1).to_std().unwrap(),
            50,
        );
        assert_eq!(reg.len(), 50);
        assert!(reg.get("p0").is_none());   // oldest exited dropped first
        assert!(reg.get("p9").is_none());
        assert!(reg.get("p59").is_some()); // newest exited retained
        // Never-exited processes are not eligible for count-based GC.
        reg.register("running");
        assert_eq!(reg.len(), 51);
    }
}
