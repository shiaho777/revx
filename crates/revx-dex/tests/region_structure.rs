use revx_dex::lift::lift_method_to_ssa;
use revx_dex::region::{RegionFallbackReason, StructuringMode, structure_method};
use revx_dex::render::decompile_method_with_diagnostics;
use revx_dex::{CatchHandler, CodeItem, DexFile, TryItem};

fn dex() -> DexFile {
    let mut bytes = vec![0; 0x70];
    bytes[..8].copy_from_slice(b"dex\n039\0");
    let mut dex = DexFile::parse(bytes).unwrap();
    dex.types.push("Ljava/lang/Exception;".into());
    dex
}

fn code(insns: &[u16], tries: Vec<TryItem>) -> CodeItem {
    CodeItem {
        registers_size: 2,
        ins_size: 0,
        outs_size: 0,
        tries_size: tries.len() as u16,
        debug_info_off: 0,
        insns: insns.to_vec(),
        tries,
    }
}

fn region(start: u32, count: u16, typed: &[(u32, u32)], catch_all: Option<u32>) -> TryItem {
    TryItem {
        start_addr: start,
        insn_count: count,
        handlers: typed
            .iter()
            .map(|&(type_idx, addr)| CatchHandler { type_idx, addr })
            .collect(),
        catch_all_addr: catch_all,
    }
}

fn typed_try_code() -> CodeItem {
    code(
        &[0x0000, 0x0000, 0x000e, 0x000d, 0x000e, 0x000d, 0x000e],
        vec![region(0, 3, &[(0, 3)], Some(5))],
    )
}

#[test]
fn typed_try_with_ordered_handlers_uses_region_path() {
    let dex = dex();
    let code = typed_try_code();
    let res = structure_method(&dex, &code, 0, StructuringMode::Auto);
    assert!(
        res.used_region_path,
        "expected region path, fallback {:?}\n{}",
        res.fallback_reason, res.pseudocode
    );
    assert_eq!(res.fallback_reason, None);
    assert_eq!(res.structured_try_count, 1);
    let typed = res.pseudocode.find("catch (java.lang.Exception");
    let catch_all = res.pseudocode.find("catch (Throwable");
    assert!(typed.is_some(), "missing typed catch:\n{}", res.pseudocode);
    assert!(
        catch_all.is_some(),
        "missing catch-all:\n{}",
        res.pseudocode
    );
    assert!(
        typed.unwrap() < catch_all.unwrap(),
        "typed handler must precede catch-all"
    );
    assert_eq!(
        res.pseudocode.matches("return").count(),
        3,
        "each source block must emit exactly once:\n{}",
        res.pseudocode
    );
}

#[test]
fn legacy_mode_matches_existing_pipeline() {
    let dex = dex();
    let code = typed_try_code();
    let res = structure_method(&dex, &code, 0, StructuringMode::Legacy);
    assert!(!res.used_region_path);
    let output = lift_method_to_ssa(&dex, &code, 0);
    let (expected, _) = revx_dex::render::render_method_pseudocode_with_diagnostics(
        &output,
        &revx_dex::render::build_try_info(&dex, &code.tries),
    );
    assert_eq!(res.pseudocode, expected);
}

#[test]
fn shared_handler_falls_back_to_legacy() {
    let dex = dex();
    let code = code(
        &[0x0000, 0x0000, 0x000e, 0x000d, 0x000e],
        vec![region(0, 1, &[(0, 3)], None), region(1, 2, &[(0, 3)], None)],
    );
    let res = structure_method(&dex, &code, 0, StructuringMode::Auto);
    assert!(!res.used_region_path);
    assert_eq!(
        res.fallback_reason,
        Some(RegionFallbackReason::SharedHandler)
    );
    let output = lift_method_to_ssa(&dex, &code, 0);
    let (expected, _) = revx_dex::render::render_method_pseudocode_with_diagnostics(
        &output,
        &revx_dex::render::build_try_info(&dex, &code.tries),
    );
    assert_eq!(res.pseudocode, expected);
}

#[test]
fn exception_boundaries_have_precise_whole_method_fallbacks() {
    let dex = dex();
    let cases = [
        (
            code(
                &[0x0000, 0x000d, 0x000e],
                vec![region(0, 1, &[(0, 1)], None)],
            ),
            RegionFallbackReason::OrdinaryReachableHandler,
        ),
        (
            code(
                &[0x000e, 0x000d, 0x000e],
                vec![region(0, 1, &[(99, 1)], None)],
            ),
            RegionFallbackReason::InvalidTryMetadata,
        ),
        (
            code(
                &[0x0000, 0x0000, 0x000e, 0x000d, 0x000e, 0x000d, 0x000e],
                vec![region(0, 3, &[(0, 3)], None), region(1, 1, &[(0, 5)], None)],
            ),
            RegionFallbackReason::NestedOrCrossScope,
        ),
    ];
    for (code, reason) in cases {
        let output = lift_method_to_ssa(&dex, &code, 0);
        let info = revx_dex::render::build_try_info(&dex, &code.tries);
        let (auto, _) =
            revx_dex::region::structure_lifted(&dex, &info, &output, StructuringMode::Auto);
        let (legacy, _) =
            revx_dex::region::structure_lifted(&dex, &info, &output, StructuringMode::Legacy);
        assert_eq!(auto.fallback_reason, Some(reason));
        assert!(!auto.used_region_path);
        assert_eq!(auto.pseudocode, legacy.pseudocode);
    }
}

#[test]
fn normal_and_diagnostic_apis_use_the_same_structuring_path() {
    let dex = dex();
    let output = lift_method_to_ssa(&dex, &typed_try_code(), 0);
    assert!(!output.func.cfg.blocks.is_empty());
    let normal = revx_dex::render::decompile_method(&dex, &typed_try_code(), 0);
    let (diagnostic, _) = decompile_method_with_diagnostics(&dex, &typed_try_code(), 0);
    assert_eq!(normal.pseudocode, diagnostic.pseudocode);
}
