use revx_analysis::analyze;
use revx_core::AnalysisProfile;
use revx_loader::load_binary;
use revx_testkit::{elf_args_call_cases, write_temp};
use std::path::Path;

#[test]
fn synthetic_quality_surface_fast_and_full() {
    for case in elf_args_call_cases() {
        let path = write_temp(&case);
        let image = load_binary(&path).expect("load fixture");
        let fast = analyze(image.clone(), AnalysisProfile::Fast);
        let full = analyze(image, AnalysisProfile::Full);

        assert!(
            fast.survey.summary.function_count > 0,
            "{} fast funcs",
            case.id
        );
        assert!(
            full.functions.len() >= fast.functions.len(),
            "{} full functions >= fast functions",
            case.id
        );
        assert!(
            full.functions.len() >= 2,
            "{} expected call-target expansion, got {}",
            case.id,
            full.functions.len()
        );
        let entry = full
            .functions
            .iter()
            .find(|function| function.name.contains("main"))
            .expect("main function");
        let pseudo = entry.pseudocode.as_ref().expect("main pseudocode");
        assert!(
            !pseudo.text.is_empty(),
            "{} main missing pseudocode",
            case.id
        );
        assert!(
            pseudo.evidence_ids.iter().any(|id| id.contains("pseudo")),
            "{} main missing pseudo evidence",
            case.id
        );
    }
}

#[test]
fn corpus_debug_info_improves_quality_surface() {
    let Ok(corpus) = std::env::var("REVX_CORPUS_DIR") else {
        eprintln!("skipping: REVX_CORPUS_DIR not set");
        return;
    };
    let root = Path::new(&corpus);
    if !root.is_dir() {
        eprintln!("skipping: REVX_CORPUS_DIR is not a directory");
        return;
    }
    let mut analyzed = 0usize;
    if let Ok(rd) = std::fs::read_dir(root) {
        for entry in rd.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Ok(image) = load_binary(&path) else {
                continue;
            };
            let fast = analyze(image.clone(), AnalysisProfile::Fast);
            assert!(
                fast.survey.summary.function_count > 0
                    || !image.symbols.is_empty()
                    || image.entry.is_some(),
                "no analysis surface for {}",
                path.display()
            );
            let full = analyze(image, AnalysisProfile::Full);
            assert!(
                !full.functions.is_empty()
                    || full.survey.summary.function_count > 0
                    || !full.types.is_empty(),
                "full analysis empty for {}",
                path.display()
            );
            analyzed += 1;
        }
    }
    assert!(analyzed > 0, "no corpus binary could be analyzed");
}
