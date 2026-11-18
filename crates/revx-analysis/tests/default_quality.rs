use revx_analysis::analyze;
use revx_core::{AnalysisProfile, Architecture, BinaryFormat, RegionKind};
use revx_loader::load_binary;
use revx_testkit::{Case, elf64, write_temp};
use std::fs;
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn bootstrap_full_mem() {
    static ON: std::sync::Once = std::sync::Once::new();
    ON.call_once(|| {
        unsafe { std::env::set_var("REVX_FULL_MEM", "1") };
    });
}

fn with_env_lock<T>(f: impl FnOnce() -> T) -> T {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    bootstrap_full_mem();
    f()
}

fn arm64_loop_code() -> Vec<u8> {
    let insts = [
        0x52800001u32,
        0x52800142u32,
        0x6b02001fu32,
        0x5400008au32,
        0x8b010000u32,
        0x11000421u32,
        0x17fffffbu32,
        0xd65f03c0u32,
    ];
    let mut code = Vec::new();
    for inst in insts {
        code.extend_from_slice(&inst.to_le_bytes());
    }
    code
}

fn x64_loop_code() -> Vec<u8> {
    vec![
        0x31, 0xc0, 0x31, 0xc9, 0x83, 0xf9, 0x0a, 0x7d, 0x06, 0x01, 0xc8, 0x83, 0xc1, 0x01, 0xeb,
        0xf4, 0xc3,
    ]
}

fn loop_case(id: &'static str, arch: Architecture) -> Case {
    let (code, machine) = match arch {
        Architecture::Arm64 => (arm64_loop_code(), 0xb7u16),
        _ => (x64_loop_code(), 0x3eu16),
    };
    Case {
        id,
        format: BinaryFormat::Elf,
        arch,
        bytes: elf64(&code, machine, 0x401000),
    }
}

#[test]
fn default_fast_profile_structures_small_loop_functions() {
    with_env_lock(|| {
        for arch in [Architecture::Arm64, Architecture::X86_64] {
            let case = loop_case("default_quality_loop", arch);
            let path = write_temp(&case);
            let image = load_binary(&path).expect("load");
            let bundle = analyze(image, AnalysisProfile::Fast);
            assert!(
                bundle.survey.summary.function_count > 0,
                "{arch:?}: no functions recovered"
            );
            let with_loop = bundle.functions.iter().any(|f| {
                f.pseudocode.as_ref().is_some_and(|unit| {
                    unit.text.contains("while")
                        || unit.regions.iter().any(|r| r.kind == RegionKind::Loop)
                })
            });
            assert!(
                with_loop,
                "{arch:?}: default profile must structure loop functions, got {:?}",
                bundle
                    .functions
                    .iter()
                    .map(|f| f.pseudocode.as_ref().map(|p| p.text.clone()))
                    .collect::<Vec<_>>()
            );
            assert!(
                bundle.survey.summary.structured_pseudocode_count > 0,
                "{arch:?}: structured count must be positive"
            );
            let _ = fs::remove_file(&path);
        }
    });
}

#[test]
fn default_fast_profile_keeps_full_snapshot_for_small_functions() {
    with_env_lock(|| {
        let case = loop_case("default_quality_snapshot", Architecture::Arm64);
        let path = write_temp(&case);
        let image = load_binary(&path).expect("load");
        let bundle = analyze(image, AnalysisProfile::Fast);
        let typed = bundle
            .functions
            .iter()
            .filter(|f| !f.arguments.is_empty() || f.stack_summary.is_some())
            .count();
        assert!(
            typed > 0,
            "default profile must recover arguments/stack for small functions"
        );
        let _ = fs::remove_file(&path);
    });
}
