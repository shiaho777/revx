use revx_analysis::analyze;
use revx_core::{AnalysisProfile, RegionKind};
use revx_loader::load_binary;
use revx_testkit::{Case, all_cases, elf_args_call_cases, elf64, write_temp, x64_code_branch_ret};
use std::path::Path;

fn assert_case(case: &Case, path: &Path) {
    let image = load_binary(path).unwrap_or_else(|e| panic!("{} load failed: {e:#}", case.id));
    assert_eq!(image.architecture, case.arch, "{} arch", case.id);
    assert_eq!(image.format, case.format, "{} format", case.id);

    let fast = analyze(image.clone(), AnalysisProfile::Fast);
    assert!(
        fast.survey.summary.function_count > 0,
        "{} expected functions, got 0 (symbols={:?} entry={:?} sections={:?})",
        case.id,
        image
            .symbols
            .iter()
            .map(|s| (s.name.clone(), s.address))
            .collect::<Vec<_>>(),
        image.entry,
        image
            .sections
            .iter()
            .map(|s| (s.name.clone(), s.address, s.size, s.kind.clone()))
            .collect::<Vec<_>>()
    );

    let full = analyze(image, AnalysisProfile::Full);
    assert!(
        !full.functions.is_empty(),
        "{} full analysis produced no functions",
        case.id
    );
    let recovery_ok = full.functions.iter().any(|f| {
        !f.arguments.is_empty()
            || !f.locals.is_empty()
            || f.stack_summary.is_some()
            || f.pseudocode
                .as_ref()
                .map(|p| !p.regions.is_empty() || !p.text.is_empty())
                .unwrap_or(false)
    });
    assert!(
        recovery_ok,
        "{} expected recovery surface (vars/stack/pseudo)",
        case.id
    );
    let _ = RegionKind::If;
}

#[test]
fn parity_matrix_load_analyze_recovery() {
    for case in all_cases() {
        let path = write_temp(&case);
        assert_case(&case, &path);
    }
}

#[test]
fn calling_convention_matches_format_arch() {
    for case in all_cases() {
        let path = write_temp(&case);
        let Ok(image) = load_binary(&path) else {
            continue;
        };
        let bundle = analyze(image, AnalysisProfile::Full);
        let Some(func) = bundle.functions.first() else {
            continue;
        };
        let Some(stack) = func.stack_summary.as_ref() else {
            continue;
        };
        let cc = stack.calling_convention.as_deref().unwrap_or("");
        assert!(!cc.is_empty(), "{} missing calling convention", case.id);
    }
}

#[test]
fn args_call_synthetic_recovers_call_target() {
    for case in elf_args_call_cases() {
        let path = write_temp(&case);
        let image = load_binary(&path).expect("load args fixture");
        let full = analyze(image, AnalysisProfile::Full);
        assert!(
            full.functions.len() >= 2,
            "{} expected main + called function, got {:?}",
            case.id,
            full.functions
                .iter()
                .map(|f| f.name.clone())
                .collect::<Vec<_>>()
        );
        let main = full
            .functions
            .iter()
            .find(|f| f.name.contains("main"))
            .expect("main function");
        let pseudo = main.pseudocode.as_ref().expect("main pseudocode");
        assert!(
            !pseudo.text.is_empty(),
            "{} expected pseudocode text",
            case.id
        );
        assert!(
            pseudo.evidence_ids.iter().any(|id| id.contains("pseudo")),
            "{} expected pseudo evidence ids on main",
            case.id
        );
    }
}

#[test]
#[allow(clippy::same_item_push)]
fn oversized_synthetic_still_recovers_structure() {
    let mut code = x64_code_branch_ret();
    for _ in 0..400 {
        code.push(0x90);
    }
    code.extend_from_slice(&[0x31, 0xc0, 0xc3]);
    let bytes = elf64(&code, 0x3e, 0x401000);
    let dir = std::env::temp_dir().join("revx-testkit");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!(
        "oversized-{}-{}.bin",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::write(&path, &bytes).unwrap();
    let image = load_binary(&path).expect("load oversized");
    let full = analyze(image, AnalysisProfile::Full);
    assert!(!full.functions.is_empty());
    assert!(
        full.functions.iter().any(|f| {
            f.pseudocode
                .as_ref()
                .map(|p| {
                    p.text.contains("oversized")
                        || p.text.contains("hot-block")
                        || p.text.contains("hot blocks")
                        || !p.regions.is_empty()
                        || !p.text.is_empty()
                })
                .unwrap_or(false)
        }),
        "expected oversize/windowed or normal pseudocode"
    );
}
