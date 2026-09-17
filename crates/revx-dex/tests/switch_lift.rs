use revx_dex::lift::lift_method_to_ssa;
use revx_dex::{CodeItem, DexFile};
use std::collections::BTreeSet;

#[test]
fn packed_switch_preserves_shared_cases_and_default() {
    let mut bytes = vec![0; 0x70];
    bytes[..8].copy_from_slice(b"dex\n039\0");
    let dex = DexFile::parse(bytes).unwrap();
    let code = CodeItem {
        registers_size: 1,
        ins_size: 1,
        outs_size: 0,
        tries_size: 0,
        debug_info_off: 0,
        insns: vec![
            0x002b, 6, 0, 0x000e, 0x000e, 0x0000, 0x0100, 2, 10, 0, 4, 0, 4, 0,
        ],
        tries: vec![],
    };
    let output = lift_method_to_ssa(&dex, &code, 0);
    let cfg = &output.func.cfg;
    let entry = cfg.entry;
    let destinations: BTreeSet<_> = cfg.succs[entry.0 as usize]
        .iter()
        .map(|id| cfg.blocks[id.0 as usize].start_addr)
        .collect();
    assert_eq!(destinations, BTreeSet::from([3, 4]));
    let cases = &output.switch_cases[&entry];
    let addressed: Vec<_> = cases
        .iter()
        .map(|(key, id)| (key.as_str(), cfg.blocks[id.0 as usize].start_addr))
        .collect();
    assert_eq!(addressed, vec![("10", 4), ("11", 4), ("default", 3)]);
    let tree = revx_dex::region::build_region_tree(&output, &dex).unwrap_or_else(|reason| {
        panic!(
            "switch tree construction: {reason:?}; blocks={:?}; values={:?}",
            output.func.cfg.blocks, output.func.values
        )
    });
    revx_dex::region::render_region_tree(&tree, &output, &dex).expect("switch tree rendering");
    let result =
        revx_dex::region::structure_method(&dex, &code, 0, revx_dex::region::StructuringMode::Auto);
    assert!(
        result.used_region_path,
        "{:?}\n{}",
        result.fallback_reason, result.pseudocode
    );
    assert!(result.pseudocode.contains("case 10:"));
    assert!(result.pseudocode.contains("case 11:"));
    assert!(result.pseudocode.contains("default:"));
    assert_eq!(result.pseudocode.matches("return;").count(), 2);
}
