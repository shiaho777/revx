use std::sync::OnceLock;

const DEFAULT_RSS_KB: u64 = 8 * 1024;

pub fn parse_rss_kb(raw_kb: Option<&str>, raw_mb: Option<&str>) -> Option<u64> {
    raw_kb
        .and_then(|v| v.parse::<u64>().ok())
        .or_else(|| {
            raw_mb
                .and_then(|v| v.parse::<u64>().ok())
                .map(|mb| mb.saturating_mul(1024))
        })
        .filter(|v| *v >= 64)
}

pub fn env_rss_kb() -> u64 {
    env_rss_kb_parsed().unwrap_or(DEFAULT_RSS_KB)
}

fn env_rss_kb_parsed() -> Option<u64> {
    parse_rss_kb(
        std::env::var("REVX_RSS_KB").ok().as_deref(),
        std::env::var("REVX_RSS_MB").ok().as_deref(),
    )
}

pub fn rss_limit_relaxed() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        env_rss_kb_parsed()
            .map(|kb| kb > DEFAULT_RSS_KB)
            .unwrap_or(false)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AnalysisCaps {
    pub global_references: Option<usize>,
    pub cfg_blocks: Option<usize>,
    pub cfg_instructions: Option<usize>,
    pub shared_string_map: Option<usize>,
    pub data_ref_scan_insts: Option<usize>,
}

pub const ENV_MAX_GLOBAL_REFERENCES: &str = "REVX_MAX_GLOBAL_REFERENCES";
pub const ENV_MAX_CFG_BLOCKS: &str = "REVX_MAX_CFG_BLOCKS";
pub const ENV_MAX_CFG_INSTRUCTIONS: &str = "REVX_MAX_CFG_INSTRUCTIONS";
pub const ENV_MAX_SHARED_STRING_MAP: &str = "REVX_MAX_SHARED_STRING_MAP";
pub const ENV_MAX_DATA_REF_SCAN_INSTS: &str = "REVX_MAX_DATA_REF_SCAN_INSTS";

pub fn resolve_analysis_caps(
    global_references: Option<&str>,
    cfg_blocks: Option<&str>,
    cfg_instructions: Option<&str>,
    shared_string_map: Option<&str>,
    data_ref_scan_insts: Option<&str>,
) -> AnalysisCaps {
    fn parse(raw: Option<&str>) -> Option<usize> {
        raw.and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v >= 1)
    }
    AnalysisCaps {
        global_references: parse(global_references),
        cfg_blocks: parse(cfg_blocks),
        cfg_instructions: parse(cfg_instructions),
        shared_string_map: parse(shared_string_map),
        data_ref_scan_insts: parse(data_ref_scan_insts),
    }
}

pub fn analysis_caps() -> AnalysisCaps {
    static CAPS: OnceLock<AnalysisCaps> = OnceLock::new();
    *CAPS.get_or_init(|| {
        resolve_analysis_caps(
            std::env::var(ENV_MAX_GLOBAL_REFERENCES).ok().as_deref(),
            std::env::var(ENV_MAX_CFG_BLOCKS).ok().as_deref(),
            std::env::var(ENV_MAX_CFG_INSTRUCTIONS).ok().as_deref(),
            std::env::var(ENV_MAX_SHARED_STRING_MAP).ok().as_deref(),
            std::env::var(ENV_MAX_DATA_REF_SCAN_INSTS).ok().as_deref(),
        )
    })
}

pub fn micro_mode() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("REVX_MICRO").is_some() || env_rss_kb() <= 1024)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rss_kb_prefers_kb_and_filters_small() {
        assert_eq!(parse_rss_kb(Some("128"), Some("512")), Some(128));
        assert_eq!(parse_rss_kb(None, Some("512")), Some(512 * 1024));
        assert_eq!(parse_rss_kb(Some("16"), Some("512")), None);
        assert_eq!(parse_rss_kb(Some("32"), None), None);
        assert_eq!(parse_rss_kb(Some("abc"), Some("zzz")), None);
        assert_eq!(parse_rss_kb(None, None), None);
    }

    #[test]
    fn rss_relaxed_requires_above_default() {
        let relaxed = |kb: Option<u64>| kb.map(|v| v > DEFAULT_RSS_KB).unwrap_or(false);
        assert!(!relaxed(None));
        assert!(!relaxed(Some(DEFAULT_RSS_KB)));
        assert!(relaxed(Some(DEFAULT_RSS_KB + 1)));
    }

    #[test]
    fn resolve_analysis_caps_parses_and_rejects_invalid() {
        let caps = resolve_analysis_caps(Some("4096"), Some("0"), Some("x"), None, Some("128"));
        assert_eq!(caps.global_references, Some(4096));
        assert_eq!(caps.cfg_blocks, None);
        assert_eq!(caps.cfg_instructions, None);
        assert_eq!(caps.shared_string_map, None);
        assert_eq!(caps.data_ref_scan_insts, Some(128));
        assert_eq!(
            resolve_analysis_caps(None, None, None, None, None),
            AnalysisCaps::default()
        );
    }
}
