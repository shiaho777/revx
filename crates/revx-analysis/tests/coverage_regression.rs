use revx_analysis::{analyze, analyze_with_budget};
use revx_core::{AnalysisProfile, Architecture, BinaryFormat};
use revx_loader::load_binary;
use revx_testkit::{Case, elf64, write_temp};
use std::fs;

fn disable_lean_mode_for_seed_discovery() {
    static ON: std::sync::Once = std::sync::Once::new();
    ON.call_once(|| {
        // SAFETY: test bootstrap runs before analysis threads spawn.
        unsafe { std::env::set_var("REVX_FULL_MEM", "1") };
    });
}

fn arm64_prologue_block(ret: bool) -> Vec<u8> {
    let mut code = Vec::new();
    code.extend_from_slice(&0xd503233fu32.to_le_bytes());
    code.extend_from_slice(&0xa9bf7bfdu32.to_le_bytes());
    code.extend_from_slice(&0xa9014ff4u32.to_le_bytes());
    code.extend_from_slice(&0xa9026bf3u32.to_le_bytes());
    if ret {
        code.extend_from_slice(&0xa90373fbu32.to_le_bytes());
        code.extend_from_slice(&0xd65f03c0u32.to_le_bytes());
    }
    code
}

fn synthetic_wide_arm64_case(id: &'static str, functions: usize) -> Case {
    let mut code = Vec::new();
    for i in 0..functions {
        code.extend_from_slice(&arm64_prologue_block(i % 4 == 0));
    }
    Case {
        id,
        format: BinaryFormat::Elf,
        arch: Architecture::Arm64,
        bytes: elf64(&code, 0xb7, 0x401000),
    }
}

#[test]
fn lean_stub_pseudocode_is_reported_separately() {
    disable_lean_mode_for_seed_discovery();
    let case = synthetic_wide_arm64_case("coverage_lean_stub", 16);
    let path = write_temp(&case);
    let image = load_binary(&path).expect("load");
    let bundle = analyze(image, AnalysisProfile::Fast);
    let summary = &bundle.survey.summary;
    assert!(
        summary.function_count > 0,
        "expected functions, got {}",
        summary.function_count
    );
    assert_eq!(
        summary.lean_stub_pseudocode_count, 0,
        "non-lean path must not report lean stubs"
    );
    assert!(
        summary.total_executable_bytes > 0,
        "total_executable_bytes must be populated"
    );
    assert!(
        summary.claimed_executable_bytes > 0,
        "claimed_executable_bytes must be populated"
    );
    assert!(
        summary.coverage > 0.0 && summary.coverage <= 1.0,
        "coverage must be in (0, 1], got {}",
        summary.coverage
    );
    let _ = fs::remove_file(&path);
}

#[test]
fn full_profile_recovers_at_least_as_many_bytes_as_fast() {
    disable_lean_mode_for_seed_discovery();
    let case = synthetic_wide_arm64_case("coverage_monotonic", 64);
    let path = write_temp(&case);
    let fast = analyze(
        load_binary(&path).expect("load fast"),
        AnalysisProfile::Fast,
    );
    let full = analyze(
        load_binary(&path).expect("load full"),
        AnalysisProfile::Full,
    );
    let fast_claimed = fast.survey.summary.claimed_executable_bytes;
    let full_claimed = full.survey.summary.claimed_executable_bytes;
    let fast_cov = fast.survey.summary.coverage;
    let full_cov = full.survey.summary.coverage;
    assert!(
        full_claimed >= fast_claimed,
        "full profile should recover at least as many bytes: fast={fast_claimed} full={full_claimed}"
    );
    assert!(
        full_cov >= fast_cov,
        "coverage must not decrease from fast to full: fast={fast_cov} full={full_cov}"
    );
    let _ = fs::remove_file(&path);
}

#[test]
fn explicit_function_budget_caps_recovery() {
    disable_lean_mode_for_seed_discovery();
    let case = synthetic_wide_arm64_case("coverage_budget_cap", 48);
    let path = write_temp(&case);
    let bundle = analyze_with_budget(
        load_binary(&path).expect("load"),
        AnalysisProfile::Fast,
        Some(12),
    );
    let summary = bundle.survey.summary;
    assert_eq!(
        summary.function_count, 12,
        "explicit budget must cap recovery, got {}",
        summary.function_count
    );
    let _ = fs::remove_file(&path);
}

#[test]
fn tiny_budget_on_wide_binary_shows_low_coverage_and_warns() {
    disable_lean_mode_for_seed_discovery();
    let case = synthetic_wide_arm64_case("coverage_truncated", 200);
    let path = write_temp(&case);
    let bundle = analyze_with_budget(
        load_binary(&path).expect("load"),
        AnalysisProfile::Fast,
        Some(4),
    );
    let summary = bundle.survey.summary;
    assert_eq!(
        summary.function_count, 8,
        "MIN_FUNCTION_BUDGET floors tiny explicit budgets"
    );
    assert!(
        summary.coverage < 0.5,
        "tiny budget on 200-function binary must show low coverage, got {}",
        summary.coverage
    );
    assert!(
        summary
            .warnings
            .iter()
            .any(|w| w.contains("limit") || w.contains("truncated")),
        "expected truncation warning, got {:?}",
        summary.warnings
    );
    let _ = fs::remove_file(&path);
}

#[test]
fn budget_resolver_tiers_are_monotonic() {
    assert_eq!(
        revx_core::resolve_function_budget(true, true, false, 8 * 1024, None),
        1024
    );
    assert_eq!(
        revx_core::resolve_function_budget(true, true, false, 16 * 1024, None),
        2048
    );
    assert_eq!(
        revx_core::resolve_function_budget(true, true, false, 32 * 1024, None),
        4096
    );
    assert_eq!(
        revx_core::resolve_function_budget(true, true, false, 64 * 1024, None),
        8192
    );
    assert_eq!(
        revx_core::resolve_function_budget(true, true, true, 512 * 1024, None),
        48
    );
}
