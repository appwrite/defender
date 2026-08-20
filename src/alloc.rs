//! Process allocator helpers.
//!
//! On Linux the binary uses jemalloc so that dropping a compiled [`crate::engine::Engine`]
//! actually returns pages to the OS. glibc `malloc` commonly keeps the old
//! arenas mapped, which is what a CVD hot-reload looks like as a permanent RSS
//! step-up (old engine + new engine, then “stuck” at ~1.5×).

#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// Enable jemalloc’s background purge thread. Safe to call more than once.
pub fn init() {
    #[cfg(target_os = "linux")]
    {
        if let Err(e) = tikv_jemalloc_ctl::background_thread::write(true) {
            tracing::debug!(error = ?e, "jemalloc background_thread not enabled");
        }
    }
}

/// Return unused heap pages to the OS.
///
/// Call after compiling an engine (scratch buffers from unpack/AC construction)
/// and again after swapping so the previous engine’s pages can be unmapped.
pub fn reclaim_unused_pages() {
    #[cfg(target_os = "linux")]
    {
        let _ = tikv_jemalloc_ctl::epoch::advance();
        // `MALLCTL_ARENAS_ALL` is `u32::MAX`: purge every arena, including the
        // tokio blocking-pool thread that compiled the engine.
        let rc = unsafe { tikv_jemalloc_ctl::raw::write(b"arena.4294967295.purge\0", ()) };
        if let Err(e) = rc {
            tracing::debug!(error = ?e, "jemalloc arena purge failed");
        }
    }
}

/// Current resident set in bytes (`VmRSS`), if `/proc` is available.
pub fn rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb.saturating_mul(1024));
        }
    }
    None
}

/// Format a byte count for logs (`123.4 MiB`).
pub fn format_bytes(n: u64) -> String {
    const MIB: f64 = 1024.0 * 1024.0;
    if n >= 1024 * 1024 {
        format!("{:.1} MiB", n as f64 / MIB)
    } else if n >= 1024 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_bytes_scales() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(2048), "2.0 KiB");
        assert_eq!(format_bytes(2 * 1024 * 1024), "2.0 MiB");
    }

    #[test]
    fn reclaim_does_not_panic() {
        reclaim_unused_pages();
        let _ = rss_bytes();
    }
}
