use revx_analysis::analyze;
use revx_core::{AnalysisProfile, RegionKind};
use revx_loader::load_binary;
use std::path::Path;

#[test]
fn typed_fixture_debug_info_improves_quality_surface() {
    let path =
        Path::new("/Users/shiaho/Desktop/ida-mini-mcp/ida-pro-mcp-main/tests/typed_fixture.elf");
    let image = load_binary(path).expect("load fixture");
    let fast = analyze(image.clone(), AnalysisProfile::Fast);
    let full = analyze(image, AnalysisProfile::Full);

    assert!(fast.survey.summary.function_count > 0);
    assert!(fast.survey.summary.typed_function_count > 0);
    assert!(fast.survey.summary.structured_pseudocode_count > 0);
    assert_eq!(
        fast.survey
            .summary
            .debug_import_coverage
            .imported_type_count
            > 0,
        true
    );

    let fast_use_wrapper = fast
        .functions
        .iter()
        .find(|function| function.name.contains("use_wrapper"))
        .expect("use_wrapper function");
    assert!(!fast_use_wrapper.arguments.is_empty());
    assert!(!fast_use_wrapper.locals.is_empty());
    assert_eq!(
        fast_use_wrapper
            .pseudocode
            .as_ref()
            .map(|unit| unit
                .regions
                .iter()
                .any(|region| region.kind == RegionKind::If))
            .unwrap_or(false),
        true
    );
    assert!(
        fast_use_wrapper
            .evidence_ids
            .iter()
            .any(|id| id.contains("pseudo"))
    );

    let full_use_wrapper = full
        .functions
        .iter()
        .find(|function| function.name.contains("use_wrapper"))
        .expect("use_wrapper function");
    assert!(full_use_wrapper.arguments.len() >= fast_use_wrapper.arguments.len());
    assert!(full_use_wrapper.locals.len() >= fast_use_wrapper.locals.len());
    assert!(
        full_use_wrapper
            .pseudocode
            .as_ref()
            .map(|unit| unit.regions.len())
            .unwrap_or(0)
            >= fast_use_wrapper
                .pseudocode
                .as_ref()
                .map(|unit| unit.regions.len())
                .unwrap_or(0)
    );
}
