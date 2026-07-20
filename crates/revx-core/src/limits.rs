use std::sync::OnceLock;

const DEFAULT_RSS_KB: u64 = 8 * 1024;

pub fn env_rss_kb() -> u64 {
    std::env::var("REVX_RSS_KB")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .or_else(|| {
            std::env::var("REVX_RSS_MB")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .map(|mb| mb.saturating_mul(1024))
        })
        .filter(|v| *v >= 64)
        .unwrap_or(DEFAULT_RSS_KB)
}

pub fn micro_mode() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        std::env::var_os("REVX_MICRO").is_some() || env_rss_kb() <= 1024
    })
}

pub fn lean_mode() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        if std::env::var_os("REVX_FULL_MEM").is_some() {
            return false;
        }
        if std::env::var_os("REVX_LEAN").is_some() || micro_mode() {
            return true;
        }
        env_rss_kb() <= 32 * 1024
    })
}

pub fn lean_symbol_cap() -> usize {
    if micro_mode() {
        0
    } else if lean_mode() {
        256
    } else {
        usize::MAX
    }
}

pub fn lean_import_export_cap() -> usize {
    if micro_mode() {
        0
    } else if lean_mode() {
        256
    } else {
        usize::MAX
    }
}

pub fn lean_string_limits() -> (usize, usize, usize) {
    if micro_mode() {
        (0, 0, 0)
    } else if lean_mode() {
        (8, 512, 16 * 1024)
    } else {
        (usize::MAX, usize::MAX, usize::MAX)
    }
}
