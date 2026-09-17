use revx_analysis::ssa::{BlockId, Cfg, CfgBlock};
use revx_dex::exception::{ExceptionFlow, HandlerKind};
use revx_dex::lift::{decode_all, lift_method_to_ssa};
use revx_dex::{CatchHandler, CodeItem, DexFile, TryItem};

fn dex() -> DexFile {
    let mut bytes = vec![0; 0x70];
    bytes[..8].copy_from_slice(b"dex\n039\0");
    DexFile::parse(bytes).unwrap()
}

fn code(insns: &[u16], tries: Vec<TryItem>) -> CodeItem {
    CodeItem {
        registers_size: 1,
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

#[test]
fn ordered_typed_catch_all_shared_and_ordinary_reachable_handlers() {
    let code = code(
        &[0, 0, 0, 0x0e],
        vec![
            region(0, 1, &[(7, 3), (2, 2)], Some(3)),
            region(1, 1, &[(7, 3)], None),
        ],
    );
    let output = lift_method_to_ssa(&dex(), &code, 0);
    let flow = &output.exception_flow;
    assert!(flow.diagnostics.is_empty());
    let r = &flow.regions[0];
    assert_eq!((r.try_index, r.start, r.end), (0, 0, Some(1)));
    assert_eq!(r.protected_blocks, vec![BlockId(0)]);
    assert_eq!(
        r.handlers.iter().map(|h| &h.kind).collect::<Vec<_>>(),
        vec![
            &HandlerKind::Typed { type_idx: 7 },
            &HandlerKind::Typed { type_idx: 2 },
            &HandlerKind::CatchAll,
        ]
    );
    assert_eq!(
        r.handlers.iter().map(|h| h.block).collect::<Vec<_>>(),
        vec![Some(BlockId(3)), Some(BlockId(2)), Some(BlockId(3))]
    );
    assert!(r.handlers.iter().all(|h| h.ordinary_entry_reachable));
    assert_eq!(flow.shared_handlers.len(), 1);
    let shared = &flow.shared_handlers[0];
    assert_eq!(shared.addr, 3);
    assert_eq!(
        shared
            .references
            .iter()
            .map(|r| (r.try_index, r.handler_index))
            .collect::<Vec<_>>(),
        vec![(0, 0), (0, 2), (1, 0)]
    );
    assert_eq!(flow.edges.len(), 4);
    assert_eq!(
        flow.edges
            .iter()
            .map(|e| (e.from.0, e.to.0, e.try_index, e.handler_index))
            .collect::<Vec<_>>(),
        vec![(0, 3, 0, 0), (0, 2, 0, 1), (0, 3, 0, 2), (1, 3, 1, 0)]
    );
    let counts = flow.counts();
    assert_eq!(counts.typed_handler_refs, 3);
    assert_eq!(counts.catch_all_handler_refs, 1);
    assert_eq!(counts.handler_blocks, 2);
    assert_eq!(counts.ordinary_entry_reachable_handler_blocks, 2);
}

#[test]
fn no_try_method_has_empty_exception_flow() {
    let code = code(&[0x0e], vec![]);
    let output = lift_method_to_ssa(&dex(), &code, 0);
    assert_eq!(output.exception_flow, ExceptionFlow::default());
    assert!(output.func.cfg.succs[0].is_empty());
}

#[test]
fn catch_all_only_handler_can_be_unreachable_normally() {
    let code = code(&[0x0e, 0x0d, 0x0e], vec![region(0, 1, &[], Some(1))]);
    let output = lift_method_to_ssa(&dex(), &code, 0);
    assert_eq!(
        output.exception_flow.regions[0].handlers[0].kind,
        HandlerKind::CatchAll
    );
    assert!(!output.exception_flow.regions[0].handlers[0].ordinary_entry_reachable);
    assert!(output.func.cfg.succs[0].is_empty());
    assert!(output.func.cfg.preds[1].is_empty());
    assert_eq!(output.exception_flow.edges.len(), 1);
}

#[test]
fn invalid_ranges_and_handlers_emit_diagnostics() {
    let code = code(
        &[0x13, 0, 0x0e],
        vec![
            region(u32::MAX, 2, &[], None),
            region(0, 8, &[], None),
            region(1, 1, &[], None),
            region(0, 0, &[], None),
            region(0, 2, &[(1, 1), (2, 9)], None),
        ],
    );
    let output = lift_method_to_ssa(&dex(), &code, 0);
    let codes: Vec<_> = output
        .exception_flow
        .diagnostics
        .iter()
        .map(|d| d.code)
        .collect();
    for expected in [
        "range_overflow",
        "range_out_of_bounds",
        "range_not_instruction_boundary",
        "empty_range",
        "handler_not_instruction_boundary",
        "handler_out_of_bounds",
    ] {
        assert!(codes.contains(&expected), "{expected}: {codes:?}");
    }
    assert_eq!(output.exception_flow.regions[0].end, None);
    assert!(output.exception_flow.edges.is_empty());
}

#[test]
fn non_block_boundaries_are_rejected_without_modifying_cfg() {
    let code = code(&[0, 0, 0x0e], vec![region(1, 1, &[(1, 1)], None)]);
    let cfg = Cfg {
        entry: BlockId(0),
        blocks: vec![CfgBlock {
            id: BlockId(0),
            start_addr: 0,
            end_addr: 3,
            insts: vec![],
            phis: vec![],
        }],
        succs: vec![vec![]],
        preds: vec![vec![]],
    };
    let before = format!("{cfg:?}");
    let flow = ExceptionFlow::new(&code, &decode_all(&code), &cfg);
    assert_eq!(format!("{cfg:?}"), before);
    assert_eq!(
        flow.diagnostics.iter().map(|d| d.code).collect::<Vec<_>>(),
        vec!["range_not_block_boundary", "handler_not_block_boundary"]
    );
    assert!(flow.edges.is_empty());
}

#[test]
fn same_lift_normal_and_diagnostic_rendering_are_equal() {
    let dex = dex();
    let code = code(
        &[0, 0x0e, 0x0d, 0x0e],
        vec![region(0, 2, &[(1, 2)], Some(2))],
    );
    let output = lift_method_to_ssa(&dex, &code, 0);
    let before = format!("{:?}", output.func.cfg);
    let try_info = revx_dex::render::build_try_info(&dex, &code.tries);
    let normal = revx_dex::render::render_method_pseudocode_full(&output, &try_info);
    let (diagnostic, _) =
        revx_dex::render::render_method_pseudocode_with_diagnostics(&output, &try_info);
    assert_eq!(normal, diagnostic);
    let rebuilt = ExceptionFlow::new(&code, &decode_all(&code), &output.func.cfg);
    assert_eq!(rebuilt, output.exception_flow);
    assert_eq!(format!("{:?}", output.func.cfg), before);
    let (wrapped, _, flow) = revx_dex::render::decompile_method_with_exception_flow(&dex, &code, 0);
    let (compatible, _) = revx_dex::render::decompile_method_with_diagnostics(&dex, &code, 0);
    assert_eq!(wrapped.pseudocode, compatible.pseudocode);
    assert_eq!(flow, output.exception_flow);
}

fn serialized_code(insns: &[u16], handler_off: u16, handler_list: &[u8]) -> CodeItem {
    let mut bytes = vec![0; 0x70];
    bytes[..8].copy_from_slice(b"dex\n039\0");
    for word in [1u16, 0, 0, 1] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&(insns.len() as u32).to_le_bytes());
    for word in insns {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    if insns.len() % 2 == 1 {
        bytes.extend_from_slice(&0u16.to_le_bytes());
    }
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&handler_off.to_le_bytes());
    bytes.extend_from_slice(handler_list);
    let len = bytes.len() as u32;
    bytes[0x20..0x24].copy_from_slice(&len.to_le_bytes());
    DexFile::parse(bytes).unwrap().code_item(0x70).unwrap()
}

#[test]
fn serialized_odd_insns_padding_and_nonzero_handler_offset() {
    let code = serialized_code(&[0, 0, 0x0e], 4, &[2, 1, 8, 1, 1, 7, 2]);
    assert_eq!(code.insns, vec![0, 0, 0x0e]);
    assert_eq!(code.tries.len(), 1);
    assert_eq!(code.tries[0].handlers.len(), 1);
    assert_eq!(
        (
            code.tries[0].handlers[0].type_idx,
            code.tries[0].handlers[0].addr
        ),
        (7, 2)
    );
    assert_eq!(code.tries[0].catch_all_addr, None);
}

#[test]
fn serialized_zero_encoded_handler_size_means_catch_all_only() {
    let code = serialized_code(&[0x0e, 0x0e], 1, &[1, 0, 1]);
    assert!(code.tries[0].handlers.is_empty());
    assert_eq!(code.tries[0].catch_all_addr, Some(1));
    let output = lift_method_to_ssa(&dex(), &code, 0);
    assert_eq!(output.exception_flow.counts().catch_all_handler_refs, 1);
    assert!(output.exception_flow.diagnostics.is_empty());
}
