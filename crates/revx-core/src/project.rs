use crate::model::ProjectConfig;
use std::path::{Path, PathBuf};

pub fn find_workspace_root(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(current) = dir {
        if current.join(".revx").exists() {
            return Some(current.to_path_buf());
        }
        dir = current.parent().filter(|parent| *parent != current);
    }
    None
}

pub fn parse_address(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }
    if trimmed.chars().all(|c| c.is_ascii_hexdigit())
        && trimmed.chars().any(|c| c.is_ascii_alphabetic())
    {
        return u64::from_str_radix(trimmed, 16).ok();
    }
    trimmed.parse::<u64>().ok()
}

pub fn parse_project_config(raw: &str) -> Result<ProjectConfig, String> {
    toml::from_str(raw).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_address_accepts_prefixed_bare_hex_and_decimal() {
        assert_eq!(parse_address("0x401000"), Some(0x401000));
        assert_eq!(parse_address("0X401000"), Some(0x401000));
        assert_eq!(parse_address("deadbeef"), Some(0xdeadbeef));
        assert_eq!(parse_address("12345"), Some(12345));
        assert_eq!(parse_address("  0x10 "), Some(16));
        assert_eq!(parse_address(""), None);
        assert_eq!(parse_address("xyz"), None);
        assert_eq!(parse_address("0xzz"), None);
    }

    #[test]
    fn find_workspace_root_walks_up_to_revx_dir() {
        let base = std::env::temp_dir().join(format!("revx-root-{}", std::process::id()));
        let nested = base.join("a").join("b");
        fs::create_dir_all(&nested).unwrap();
        assert_eq!(find_workspace_root(&nested), None);
        fs::create_dir_all(base.join(".revx")).unwrap();
        assert_eq!(
            find_workspace_root(&nested),
            Some(base.join(".revx").parent().unwrap().to_path_buf())
        );
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn parse_project_config_reads_toml_document() {
        let raw = "schema_version = 4\nname = \"demo\"\ncreated_at = \"2026-08-21T00:00:00Z\"\n";
        let cfg = parse_project_config(raw).unwrap();
        assert_eq!(cfg.schema_version, 4);
        assert_eq!(cfg.name, "demo");
        assert_eq!(cfg.primary_binary, None);
        let raw = format!("{raw}primary_binary = \"libdemo.so\"\n");
        let cfg = parse_project_config(&raw).unwrap();
        assert_eq!(cfg.primary_binary.as_deref(), Some("libdemo.so"));
        assert!(parse_project_config("broken").is_err());
    }
}
