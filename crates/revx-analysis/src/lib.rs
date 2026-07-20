pub mod ssa;
pub mod resource;
pub mod lattice;
pub use lattice::{
    advance_ibc_cursor, apply_cognitive_field_to_lattice, apply_verdict_to_hypothesis_notes,
    apply_verdict_to_hypothesis_title, build_agent_semantic_lattice, collapse_cognitive_field,
    compile_phase_conjugates, compose_proof_chain, continuum_bind_hypothesis, continuum_brief_lines,
    continuum_ledger_on_visit, continuum_ledger_on_visit_with_observation, continuum_ledger_summary,
    continuum_on_visit, continuum_on_visit_ns, continuum_on_visit_with_observation,
    detect_and_attach_orbit_conflicts, extract_case_target_map, finalize_pseudocode_unit,
    finalize_pseudocode_unit_with_context, force_advance_ibc, forge_orbit_hypothesis_drafts,
    format_cognitive_field_lines, format_proof_chain_lines, format_semantic_lattice,
    fuse_semantic_lattices, ibc_program_fingerprint, inject_diffraction_residuals_into_lattice,
    inject_proof_chain_into_lattice, interfere_cognitive_fields, lattice_action_at_pc,
    lattice_ibc_plan, lattice_primary_next_action, match_verdict_to_orbit_key, observe_ibc_execution,
    parse_collapse_verdict, project_cognitive_field, project_diffraction_residuals,
    resume_ibc_from_state, seal_plan_from_proof_chain, synthesize_observation_corpus,
    CollapseVerdict, CognitiveField, DiffractionResidual, IbcContinuumLedger, IbcContinuumState,
    IbcObserveNote, OrbitHypothesisDraft, PhaseConjugateProbe, ProofChainLink, StandingWave,
};

use object::{Object, ObjectSection};
use revx_core::{
    AnalysisBundle, AnalysisProfile, AnalysisSummary, Architecture, BasicBlock, BinaryFormat,
    DecompileStrategy,
    BinaryImage, BinarySummary, DebugCoverageSummary, DebugFunctionHint, Function, Instruction,
    PseudocodeRegion, PseudocodeUnit, Reference, ReferenceKind, RegionKind, StackSummary,
    StringLiteral, Survey, TypeDef, TypeSource, Variable, VariableRole, VariableStorage,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::{Arc, OnceLock};
use std::thread;

const MIN_FUNCTION_BUDGET: usize = 8;
const MAX_FUNCTION_BUDGET_FAST: usize = 256;
const MAX_FUNCTION_BUDGET_FULL: usize = 1024;
const DEFAULT_MAX_FUNCTION_BYTES_X64: usize = 0x800;
const DEFAULT_MAX_FUNCTION_BYTES_ARM64: usize = 0x800;
const FULL_MAX_FUNCTION_BYTES_X64: usize = 0x2000;
const FULL_MAX_FUNCTION_BYTES_ARM64: usize = 0x2000;
const ARM64_NEARBY_SEED_WINDOW: u64 = 0x80;
const ARM64_STACK_SPAN_GAP: i64 = 0x10;
const ARM64_LARGE_WORKSPACE_MIN_OFFSETS: usize = 96;
const ARM64_LARGE_WORKSPACE_MIN_SPAN: i64 = 0x400;
const ARM64_LARGE_WORKSPACE_HOT_ACCESS_COUNT: usize = 3;
const ARM64_LARGE_WORKSPACE_GAP: i64 = 0x40;
const ARM64_ARRAY_LIKE_MIN_STRIDE_HITS: usize = 16;
const ARM64_SP_ROOT_BUFFER_MIN_END: i64 = 0x20;
const ARM64_SP_ROOT_BUFFER_MIN_STORES: usize = 2;

const MAX_CFG_BLOCKS: usize = 48;
const MAX_CFG_INSTRUCTIONS: usize = 192;
const MAX_HEAVY_ANALYSIS_INSTS: usize = 256;
const MAX_HEAVY_ANALYSIS_BLOCKS: usize = 48;
const MAX_SSA_INSTS: usize = 128;
const MAX_SSA_BLOCKS: usize = 32;
const MAX_LINEAR_SSA_INSTS: usize = 512;
const MAX_LINEAR_SSA_BLOCKS: usize = 96;
const MAX_FAST_SSA_INSTS: usize = 48;
const MAX_FAST_PSEUDO_LINES: usize = 48;
const LIGHT_VAR_RECOVERY_INSTS: usize = 128;
const MAX_OVERSIZE_WINDOW_BLOCKS: usize = 64;
const MAX_OVERSIZE_WINDOW_INSTS: usize = 384;
const MAX_RECOVERY_SAMPLE_INSTS: usize = LIGHT_VAR_RECOVERY_INSTS;

fn analysis_limit_boost(profile: AnalysisProfile) -> usize {
    if resource::lean_mode() || resource::micro_mode() {
        return 1;
    }
    match profile {
        AnalysisProfile::Fast => 1,
        AnalysisProfile::Full => {
            if std::env::var_os("REVX_FULL_MEM").is_some() {
                4
            } else {
                2
            }
        }
    }
}

fn ssa_inst_limit(profile: AnalysisProfile) -> usize {
    MAX_SSA_INSTS.saturating_mul(analysis_limit_boost(profile))
}

fn ssa_block_limit(profile: AnalysisProfile) -> usize {
    MAX_SSA_BLOCKS.saturating_mul(analysis_limit_boost(profile))
}

fn linear_ssa_inst_limit(profile: AnalysisProfile) -> usize {
    MAX_LINEAR_SSA_INSTS.saturating_mul(analysis_limit_boost(profile))
}

fn linear_ssa_block_limit(profile: AnalysisProfile) -> usize {
    MAX_LINEAR_SSA_BLOCKS.saturating_mul(analysis_limit_boost(profile))
}

fn heavy_inst_limit(profile: AnalysisProfile) -> usize {
    MAX_HEAVY_ANALYSIS_INSTS.saturating_mul(analysis_limit_boost(profile))
}

fn heavy_block_limit(profile: AnalysisProfile) -> usize {
    MAX_HEAVY_ANALYSIS_BLOCKS.saturating_mul(analysis_limit_boost(profile))
}

fn pending_stream_batch_size() -> usize {
    let jobs = resource::analysis_worker_count().max(1);
    if jobs <= 1 {
        1
    } else {
        (jobs.saturating_mul(4)).min(16)
    }
}

const MAX_DATA_REF_SCAN_INSTS: usize = 256;
const MAX_PENDING_STREAM_BATCH: usize = 1;
const MAX_GLOBAL_REFERENCES: usize = 512;
const MAX_SHARED_STRING_MAP: usize = 64;


#[inline]
fn format_sub_addr(addr: u64) -> String {
    let mut s = String::with_capacity(20);
    s.push_str("sub_");
    let mut v = addr;
    if v == 0 {
        s.push('0');
        return s;
    }
    let mut buf = [0u8; 16];
    let mut i = 16usize;
    while v != 0 {
        i -= 1;
        buf[i] = b"0123456789abcdef"[(v & 0xf) as usize];
        v >>= 4;
    }
    s.push_str(unsafe { std::str::from_utf8_unchecked(&buf[i..]) });
    s
}

fn parallel_worker_count() -> usize {
    resource::analysis_worker_count().max(1)
}

fn revx_trace_enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("REVX_TRACE").is_some())
}

#[inline(always)]
fn revx_trace(f: impl FnOnce() -> String) {
    if revx_trace_enabled() {
        eprintln!("revx-trace {}", f());
    }
}

fn map_in_analysis_pool<T, R, F>(items: Vec<T>, f: F) -> Vec<R>
where
    T: Send,
    R: Send,
    F: Fn(T) -> R + Sync,
{
    let n = items.len();
    if n == 0 {
        return Vec::new();
    }
    let workers = resource::analysis_worker_count().max(1).min(n).min(4);
    if workers <= 1 || n == 1 {
        return items.into_iter().map(f).collect();
    }
    let queue = std::sync::Mutex::new(items.into_iter().enumerate().collect::<Vec<_>>());
    let results = std::sync::Mutex::new((0..n).map(|_| None).collect::<Vec<Option<R>>>());
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let next = {
                    let mut guard = queue.lock().unwrap_or_else(|e| e.into_inner());
                    guard.pop()
                };
                let Some((idx, item)) = next else {
                    break;
                };
                let value = f(item);
                let mut guard = results.lock().unwrap_or_else(|e| e.into_inner());
                guard[idx] = Some(value);
            });
        }
    });
    results
        .into_inner()
        .unwrap_or_else(|e| e.into_inner())
        .into_iter()
        .map(|item| item.expect("analysis worker missing result"))
        .collect()
}

#[derive(Debug, Clone)]
pub struct StreamedAnalysis {
    pub survey: Survey,
    pub references: Vec<Reference>,
    pub types: Vec<TypeDef>,
    pub strings: Vec<StringLiteral>,
    pub debug_import: revx_core::DebugImportSummary,
}

const MAX_CODE_WINDOW: usize = 0x1000;

enum ByteSource {
    Vec(Arc<[u8]>),
    File {
        file: Arc<std::fs::File>,
        file_offset: u64,
        size: usize,
    },
}

fn read_file_exact_at(file: &std::fs::File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        return FileExt::read_exact_at(file, buf, offset);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut done = 0usize;
        while done < buf.len() {
            let n = file.seek_read(&mut buf[done..], offset.saturating_add(done as u64))?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "failed to fill whole buffer",
                ));
            }
            done += n;
        }
        return Ok(());
    }
    #[cfg(not(any(unix, windows)))]
    {
        use std::io::{Read, Seek, SeekFrom};
        let mut cloned = file.try_clone()?;
        cloned.seek(SeekFrom::Start(offset))?;
        cloned.read_exact(buf)
    }
}

struct CodeRegion {
    start: u64,
    end: u64,
    bytes: ByteSource,
}

impl CodeRegion {
    fn read_range(&self, start: u64, end: u64) -> Option<Vec<u8>> {
        if start < self.start || start >= self.end || end <= start {
            return None;
        }
        let clipped_end = end.min(self.end);
        let offset = (start - self.start) as usize;
        let size = ((clipped_end - start) as usize).min(MAX_CODE_WINDOW);
        if size == 0 {
            return None;
        }
        match &self.bytes {
            ByteSource::Vec(data) => {
                let slice = data.get(offset..offset.saturating_add(size))?;
                Some(slice.to_vec())
            }
            ByteSource::File {
                file,
                file_offset,
                size: region_size,
            } => {
                if offset >= *region_size {
                    return None;
                }
                let size = size.min(region_size - offset);
                let mut buf = vec![0u8; size];
                read_file_exact_at(file, &mut buf, file_offset.saturating_add(offset as u64))
                    .ok()?;
                Some(buf)
            }
        }
    }

    fn data_prefix(&self, max_len: usize) -> Vec<u8> {
        self.read_range(self.start, self.start.saturating_add(max_len as u64))
            .unwrap_or_default()
    }

    #[cfg(test)]
    fn from_vec(start: u64, data: Vec<u8>) -> Self {
        let size = data.len();
        Self {
            start,
            end: start + size as u64,
            bytes: ByteSource::Vec(Arc::<[u8]>::from(data)),
        }
    }
}

fn release_code_region_pages(_code_regions: &[CodeRegion]) {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StringRange {
    start: u64,
    end: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Arm64RecoveredLocal {
    start_offset: i64,
    end_offset: Option<i64>,
    type_name: Option<String>,
    aggregate: bool,
}

#[derive(Clone, Debug)]
struct Arm64SemanticLocalRef {
    name: String,
    start_offset: i64,
    end_offset: Option<i64>,
}

type Arm64SemanticNodeId = usize;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum Arm64SemanticNode {
    Symbol(String),
    Imm(i64),
    AddImm {
        base: Arm64SemanticNodeId,
        imm: i64,
    },
    Add {
        base: Arm64SemanticNodeId,
        offset: Arm64SemanticNodeId,
    },
    Deref {
        base: Arm64SemanticNodeId,
        imm: i64,
    },
}

#[derive(Clone, Debug, Default)]
struct Arm64SemanticState {
    values: HashMap<String, Arm64SemanticNodeId>,
    prepared_args: BTreeSet<String>,
    nodes: Vec<Arm64SemanticNode>,
    node_ids: HashMap<Arm64SemanticNode, Arm64SemanticNodeId>,
    render_cache: HashMap<Arm64SemanticNodeId, String>,
}

pub fn guess_architecture_from_blocks(blocks: &[BasicBlock]) -> Architecture {
    let mut arm = 0i32;
    let mut x64 = 0i32;
    for block in blocks.iter().take(32) {
        for inst in block.instructions.iter().take(24) {
            let text = inst.text.as_ref();
            if text.starts_with("adrp ")
                || text.starts_with("ldr ")
                || text.starts_with("str ")
                || text.starts_with("bl ")
                || text.starts_with("cbz ")
                || text.starts_with("ret")
                || text.contains(" x0")
                || text.contains(" w0")
            {
                arm += 1;
            }
            if text.starts_with("mov ")
                || text.starts_with("lea ")
                || text.starts_with("call ")
                || text.starts_with("jmp ")
                || text.contains("rax")
                || text.contains("rdi")
                || text.contains("rip")
            {
                x64 += 1;
            }
        }
    }
    if arm >= x64 {
        Architecture::Arm64
    } else if x64 > 0 {
        Architecture::X86_64
    } else {
        Architecture::Unknown
    }
}

pub fn recompose_function_pseudocode(
    function: &Function,
    architecture: Architecture,
    strategy: DecompileStrategy,
) -> PseudocodeUnit {
    recompose_function_pseudocode_ctx(function, architecture, strategy, &[], &[])
}

pub fn recompose_function_pseudocode_ctx(
    function: &Function,
    architecture: Architecture,
    strategy: DecompileStrategy,
    imports: &[revx_core::Import],
    strings: &[StringLiteral],
) -> PseudocodeUnit {
    let architecture = if architecture == Architecture::Unknown {
        guess_architecture_from_blocks(&function.blocks)
    } else {
        architecture
    };
    let overrides = HashMap::new();
    let mut symbols = HashMap::new();
    for import in imports {
        if let Some(addr) = import.address {
            symbols.insert(addr, import.name.clone());
        }
    }
    for s in strings {
        let Some(addr) = s.address else {
            continue;
        };
        if !symbols.contains_key(&addr) {
            let clipped: String = s.value.chars().take(45).collect();
            let label = if s.value.len() > 48 {
                format!("str:{clipped}...")
            } else {
                format!("str:{clipped}")
            };
            symbols.insert(addr, label);
        }
    }
    let mut string_map_inner = HashMap::new();
    for s in strings {
        if let Some(addr) = s.address {
            string_map_inner.insert(addr, s.value.clone());
        }
    }
    let string_map = Arc::new(string_map_inner);
    let return_type = function
        .stack_summary
        .as_ref()
        .and_then(|s| s.return_type.as_deref());
    let inst_count = function
        .blocks
        .iter()
        .map(|b| b.instructions.len())
        .sum::<usize>();
    let use_hotblock = matches!(strategy, DecompileStrategy::Hotblock)
        || (matches!(strategy, DecompileStrategy::Full | DecompileStrategy::Auto)
            && inst_count > linear_ssa_inst_limit(AnalysisProfile::Full));
    if matches!(strategy, DecompileStrategy::Fast)
        || (matches!(strategy, DecompileStrategy::Auto) && inst_count <= MAX_FAST_SSA_INSTS)
    {
        return render_fast_pseudocode(
            &function.name,
            function.address,
            &function.blocks,
            &function.arguments,
            imports,
            strings,
            &overrides,
            &symbols,
            return_type.or(Some("int")),
            &[],
        );
    }
    if use_hotblock || matches!(strategy, DecompileStrategy::Hotblock) {
        return render_oversized_pseudocode(
            &function.name,
            function.address,
            &function.blocks,
            &function.arguments,
            &function.locals,
            imports,
            &overrides,
            &symbols,
            None,
            AnalysisProfile::Full,
            strings,
            architecture,
            &[],
            string_map,
        );
    }
    let profile = AnalysisProfile::Full;
    if !function.blocks.is_empty()
        && inst_count <= linear_ssa_inst_limit(profile)
        && function.blocks.len() <= linear_ssa_block_limit(profile)
    {
        let mut ssa_func = match architecture {
            #[cfg(feature = "arch-x64")]
            Architecture::X86_64 => {
                ssa::lift_x64_to_ssa(&function.blocks, &[], &function.arguments)
            }
            #[cfg(feature = "arch-arm64")]
            Architecture::Arm64 => {
                ssa::lift_arm64_to_ssa(&function.blocks, &[], &function.arguments)
            }
            _ => ssa::lift_arm64_to_ssa(&function.blocks, &[], &function.arguments),
        };
        ssa::refine_call_arguments_with_symbols(&mut ssa_func, &symbols);
        let text = if inst_count <= ssa_inst_limit(profile)
            && function.blocks.len() <= ssa_block_limit(profile)
        {
            ssa::render_ssa_pseudocode_named_layered_with_string_arc(
                &ssa_func,
                &function.name,
                &function.arguments,
                &symbols,
                &HashMap::new(),
                Arc::clone(&string_map),
            )
        } else {
            ssa::render_ssa_pseudocode_linear_with_string_arc(
                &ssa_func,
                &function.name,
                &function.arguments,
                &symbols,
                &HashMap::new(),
                string_map,
            )
        };
        let regions = ssa::ssa_pseudocode_regions(&ssa_func, function.address);
        return finalize_pseudocode_unit_with_context(
            &function.name,
            function.address,
            PseudocodeUnit {
                language: "c".to_string(),
                text,
                regions,
                region_artifact: None,
                evidence_ids: vec![
                    format!("pseudo:{:x}", function.address),
                    format!("pseudo:{:x}:recompose", function.address),
                ],
                semantic_lattice: None,
            },
            &[],
            &symbols,
        );
    }
    render_oversized_pseudocode(
        &function.name,
        function.address,
        &function.blocks,
        &function.arguments,
        &function.locals,
        imports,
        &overrides,
        &symbols,
        None,
        profile,
        strings,
        architecture,
        &[],
        string_map,
    )
}

pub fn resolve_decompile_strategy(
    requested: DecompileStrategy,
    force_refresh: bool,
    has_cached: bool,
    inst_count: usize,
) -> DecompileStrategy {
    match requested {
        DecompileStrategy::Cached => DecompileStrategy::Cached,
        DecompileStrategy::Fast => DecompileStrategy::Fast,
        DecompileStrategy::Full => DecompileStrategy::Full,
        DecompileStrategy::Hotblock => DecompileStrategy::Hotblock,
        DecompileStrategy::Auto => {
            if has_cached && !force_refresh {
                DecompileStrategy::Cached
            } else if inst_count > linear_ssa_inst_limit(AnalysisProfile::Full) {
                DecompileStrategy::Hotblock
            } else if inst_count > MAX_FAST_SSA_INSTS {
                DecompileStrategy::Full
            } else {
                DecompileStrategy::Fast
            }
        }
    }
}

pub fn analyze(image: BinaryImage, profile: AnalysisProfile) -> AnalysisBundle {
    let imports = image.imports.clone();
    let mut functions = Vec::new();
    let streamed = analyze_streaming(image, profile, |function| {
        functions.push(function);
        Ok::<(), std::convert::Infallible>(())
    })
    .unwrap_or_else(|never| match never {});

    AnalysisBundle {
        survey: streamed.survey,
        functions,
        references: streamed.references,
        types: streamed.types,
        strings: streamed.strings,
        debug_import: streamed.debug_import,
        imports,
    }
}

/// Analyze multiple binaries in parallel using available CPU cores.
/// Each binary is analyzed on its own thread. Results are collected and merged.
pub fn analyze_parallel(
    images: Vec<BinaryImage>,
    profile: AnalysisProfile,
) -> Vec<AnalysisBundle> {
    if images.len() <= 1 {
        return images
            .into_iter()
            .map(|img| analyze(img, profile))
            .collect();
    }

    let workers = parallel_worker_count().min(images.len());
    let chunks: Vec<Vec<BinaryImage>> = if workers >= images.len() {
        images.into_iter().map(|img| vec![img]).collect()
    } else {
        let chunk_size = images.len().div_ceil(workers);
        images
            .chunks(chunk_size)
            .map(|chunk| chunk.to_vec())
            .collect()
    };

    let mut handles = Vec::new();
    for chunk in chunks {
        handles.push(thread::spawn(move || {
            chunk
                .into_iter()
                .map(|img| analyze(img, profile))
                .collect::<Vec<_>>()
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        match handle.join() {
            Ok(bundles) => results.extend(bundles),
            Err(_) => {} // Panic in worker thread — skip and continue
        }
    }
    results
}

pub fn survey(image: BinaryImage, profile: AnalysisProfile) -> Survey {
    analyze_streaming(image, profile, |_| Ok::<(), std::convert::Infallible>(()))
        .unwrap_or_else(|never| match never {})
        .survey
}

pub fn analyze_streaming<F, E>(
    mut image: BinaryImage,
    profile: AnalysisProfile,
    mut on_function: F,
) -> std::result::Result<StreamedAnalysis, E>
where
    F: FnMut(Function) -> std::result::Result<(), E>,
{
    let function_budget = function_recovery_budget(&image, profile);
    let mut function_count = 0usize;
    let mut typed_function_count = 0usize;
    let mut structured_pseudocode_count = 0usize;
    let mut function_evidence_count = 0usize;
    let mut observed_truncated_functions = 0usize;

    let (references, mut types, truncated_functions) =
        walk_functions(&image, profile, function_budget, |function| {
            function_count += 1;
            if function
                .arguments
                .iter()
                .chain(function.locals.iter())
                .any(|var| var.type_name.is_some())
            {
                typed_function_count += 1;
            }
            if function
                .pseudocode
                .as_ref()
                .map(|unit| !unit.regions.is_empty() || !unit.text.is_empty())
                .unwrap_or(false)
            {
                structured_pseudocode_count += 1;
            }
            function_evidence_count += 1
                + usize::from(function.stack_summary.is_some())
                + usize::from(!function.arguments.is_empty() || !function.locals.is_empty())
                + usize::from(function.pseudocode.is_some());
            if !function.warnings.is_empty() {
                observed_truncated_functions += 1;
            }
            on_function(function)
        })?;
    let _ = observed_truncated_functions;

    types.extend(image.debug_import.type_defs.clone());
    dedupe_types(&mut types);
    let evidence_count = 1
        + function_evidence_count
        + references.len().min(256)
        + image.strings.len().min(64)
        + types.len();
    let string_count = image.strings.len();
    let survey = Survey {
        binary: BinarySummary::from_image(&image),
        summary: AnalysisSummary {
            binary_id: image.id.clone(),
            format: image.format,
            architecture: image.architecture,
            function_count,
            import_count: image.imports.len(),
            export_count: image.exports.len(),
            string_count,
            evidence_count,
            debug_import_coverage: DebugCoverageSummary {
                status: image.debug_import.status,
                imported_type_count: image.debug_import.imported_type_count,
                imported_function_hint_count: image.debug_import.imported_function_hint_count,
                imported_variable_hint_count: image.debug_import.imported_variable_hint_count,
            },
            typed_function_count,
            structured_pseudocode_count,
            warnings: summarize_analysis_warnings_from_counters(
                function_count,
                truncated_functions,
                function_budget,
            ),
        },
    };
    let strings = std::mem::take(&mut image.strings);
    let debug_import = std::mem::take(&mut image.debug_import);

    Ok(StreamedAnalysis {
        survey,
        references,
        types,
        strings,
        debug_import,
    })
}

fn walk_functions<F, E>(
    image: &BinaryImage,
    profile: AnalysisProfile,
    function_budget: usize,
    mut on_function: F,
) -> std::result::Result<(Vec<Reference>, Vec<TypeDef>, usize), E>
where
    F: FnMut(Function) -> std::result::Result<(), E>,
{
    let import_types = if profile == AnalysisProfile::Full {
        image
            .debug_import
            .type_defs
            .iter()
            .map(|item| item.name.clone())
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    walk_functions_inner(image, profile, function_budget, &import_types, |function| {
        on_function(function)
    })
}

fn lean_keep_pseudocode(name: &str, index: usize) -> bool {
    if index < 2 {
        return true;
    }
    if index >= 4 {
        return false;
    }
    if name.starts_with("sub_") || name.starts_with("loc_") {
        return false;
    }
    name.contains("Java_") || name == "main" || !name.starts_with("sub_")
}

fn lean_function_from_decode(
    image_id: &str,
    address: u64,
    name: String,
    size: u64,
    instructions: &[Instruction],
    keep_pseudo: bool,
) -> Function {
    let truncated = size >= 0x200;
    let mut warnings = Vec::new();
    if truncated {
        warnings.push(format!(
            "function reached decode window limit of {} bytes; boundary may be truncated",
            0x200u64
        ));
    }
    let inst_n = instructions.len();
    let pseudocode = if keep_pseudo {
        Some(PseudocodeUnit {
            language: "c".to_string(),
            text: format!("void {name}() {{ /* lean size={size:#x} insts={inst_n} */ }}"),
            regions: Vec::new(),
            region_artifact: None,
            evidence_ids: vec![format!("pseudo:{}:{:x}", image_id, address)],
            semantic_lattice: None,
        })
    } else {
        None
    };

    Function {
        name,
        address,
        size,
        blocks: Vec::new(),
        stack_summary: None,
        arguments: Vec::new(),
        locals: Vec::new(),
        pseudocode,
        evidence_ids: vec![format!("fn:{}:{:x}", image_id, address)],
        warnings,
    }
}

fn walk_functions_inner<F, E>(
    image: &BinaryImage,
    profile: AnalysisProfile,
    function_budget: usize,
    import_types: &[String],
    mut on_function: F,
) -> std::result::Result<(Vec<Reference>, Vec<TypeDef>, usize), E>
where
    F: FnMut(Function) -> std::result::Result<(), E>,
{
    let code_regions = build_code_regions(image);
    // drop parse pages before budgeting analysis work
    let import_stub_addrs = image
        .imports
        .iter()
        .filter_map(|import| import.address)
        .collect::<HashSet<_>>();
    let mut seeds = collect_function_seeds(image);
    seeds.retain(|address, _| !import_stub_addrs.contains(address));
    let mut hard_seed_addrs = seeds.keys().copied().collect::<BTreeSet<_>>();
    let mut heuristic_seed_addrs = BTreeSet::new();
    if image.architecture == Architecture::Arm64 {
        for address in if resource::micro_mode() || resource::lean_mode() {
            Vec::new()
        } else {
            collect_arm64_heuristic_seeds(&code_regions)
        } {
            heuristic_seed_addrs.insert(address);
            seeds
                .entry(address)
                .or_insert_with(|| format_sub_addr(address));
        }
    }
    let seed_priority = collect_seed_priority(image);

    for hint in &image.debug_import.function_hints {
        if let Some(address) = hint.address {
            hard_seed_addrs.insert(address);
            seeds.entry(address).or_insert_with(|| hint.name.clone());
        }
    }

    if let Some(entry) = image.entry.filter(|entry| *entry != 0) {
        hard_seed_addrs.insert(entry);
        seeds
            .entry(entry)
            .and_modify(|name| {
                if name.starts_with("sub_") || name.starts_with("entry_") {
                    *name = "main".to_string();
                }
            })
            .or_insert_with(|| "main".to_string());
    }

    if image.architecture == Architecture::Arm64 {
        seeds.retain(|address, _| address % 4 == 0);
        hard_seed_addrs.retain(|address| address % 4 == 0);
        heuristic_seed_addrs.retain(|address| address % 4 == 0);
    }
    seeds.retain(|address, _| !import_stub_addrs.contains(address));
    hard_seed_addrs.retain(|address| !import_stub_addrs.contains(address));

    if seeds.is_empty() {
        return Ok((Vec::new(), Vec::new(), 0));
    }

    let executable = executable_ranges(image);
    let (hint_by_addr, hint_by_name) = build_hint_maps(&image.debug_import.function_hints);
    let mut string_ranges = image
        .strings
        .iter()
        .filter_map(|string| {
            let start = string.address?;
            let len = string.value.len() as u64;
            if len == 0 {
                return None;
            }
            Some(StringRange {
                start,
                end: start + len,
            })
        })
        .collect::<Vec<_>>();
    string_ranges.sort_unstable_by_key(|range| range.start);
    let relocation_refs = collect_relocation_references(image, &string_ranges, &executable);

    let ref_cap = if resource::lean_mode() {
        MAX_GLOBAL_REFERENCES.min(64)
    } else {
        MAX_GLOBAL_REFERENCES.min(1024)
    };
    let mut all_references = HashSet::<Reference>::with_capacity(ref_cap);
    for reference in &relocation_refs {
        all_references.insert(*reference);
    }
    let mut function_count = 0usize;
    let mut pending = sort_seed_batch(seeds.into_iter().collect::<Vec<_>>(), &seed_priority);
    let mut priority_queue = VecDeque::new();
    let mut deferred_queue = VecDeque::new();
    let mut hard_boundaries = hard_seed_addrs;
    for seed in pending.drain(..) {
        if hard_boundaries.contains(&seed.0) {
            priority_queue.push_back(seed);
        } else {
            deferred_queue.push_back(seed);
        }
    }
    let mut visited = HashSet::with_capacity(function_budget.min(8192));
    let mut claimed_ranges: BTreeMap<u64, u64> = BTreeMap::new();

    struct PendingFunction {
        address: u64,
        name: String,
        size: u64,
        decode_end: u64,
        debug_hint: Option<DebugFunctionHint>,
    }

    let mut pending_functions: Vec<PendingFunction> = Vec::with_capacity(function_budget.min(1024));

    // ── Phase 1: Batched parallel discovery ────────────────────────────────
    // Decode is expensive and independent per candidate. Claim/seed expansion
    // stays serial so coverage remains deterministic.
    let phase1_batch_size = if resource::micro_mode() || resource::lean_mode() {
        1
    } else {
        (parallel_worker_count() * 4).clamp(4, 16)
    };
    let max_function_bytes = if resource::lean_mode() {
        (default_max_function_bytes(image.architecture, profile) as u64).min(0x200)
    } else {
        default_max_function_bytes(image.architecture, profile) as u64
    };
    let architecture = image.architecture;
    let phase1_started = std::time::Instant::now();
    let mut phase1_batches = 0usize;
    let mut budget = resource::AnalysisBudget::from_process_limits();
    budget.rebaseline();
    let mut budget_truncated = false;
    revx_trace(|| format!(
        "phase1 start seeds_priority={} seeds_deferred={} budget={} jobs={} batch={} wall_sec={} rss_kb={}",
        priority_queue.len(),
        deferred_queue.len(),
        function_budget,
        parallel_worker_count(),
        phase1_batch_size,
        resource::process_resource_limits().wall_sec,
        resource::process_resource_limits().rss_kb
    ));

    while function_count < function_budget {
        if budget.check().is_err() {
            budget_truncated = true;
            revx_trace(|| format!(
                "phase1 budget stop elapsed_ms={:?} kind={:?}",
                budget.elapsed_ms(),
                budget.exceeded()
            ));
            break;
        }
        let mut batch: Vec<(u64, String, u64, u64, bool)> = Vec::with_capacity(phase1_batch_size);
        while batch.len() < phase1_batch_size && function_count + batch.len() < function_budget {
            let Some((address, name)) = priority_queue
                .pop_front()
                .or_else(|| deferred_queue.pop_front())
            else {
                break;
            };
            let is_heuristic_seed = heuristic_seed_addrs.contains(&address);
            if !visited.insert(address) {
                continue;
            }
            let Some(range) = find_executable_range(&executable, address) else {
                continue;
            };
            let next_boundary = next_hard_boundary(address, range.1, &hard_boundaries);
            let max_end = address
                .saturating_add(max_function_bytes)
                .min(next_boundary)
                .min(range.1);
            if max_end <= address {
                continue;
            }
            if claimed_ranges
                .range(..=address)
                .next_back()
                .is_some_and(|(&start, &end)| address >= start && address < end)
            {
                continue;
            }
            batch.push((address, name, max_end, range.1, is_heuristic_seed));
        }
        if batch.is_empty() {
            break;
        }

        phase1_batches += 1;
        let batch_started = std::time::Instant::now();
        let batch_len = batch.len();
        let decoded: Vec<(
            u64,
            String,
            u64,
            bool,
            Vec<Instruction>,
            Vec<Reference>,
        )> = map_in_analysis_pool(batch, |(address, name, max_end, range_end, is_heuristic_seed)| {
                let (instructions, code_refs) = decode_function_with_references(
                    architecture,
                    &code_regions,
                    address,
                    max_end,
                    &executable,
                );
                if instructions.is_empty() {
                    return (address, name, range_end, is_heuristic_seed, Vec::new(), Vec::new());
                }
                let mut combined_references = if profile == AnalysisProfile::Full {
                    normalize_references(architecture, &code_regions, code_refs)
                } else {
                    code_refs
                };
                if profile == AnalysisProfile::Full {
                    promote_data_reference_kinds(
                        &mut combined_references,
                        &string_ranges,
                        &executable,
                    );
                    if instructions.len() <= MAX_DATA_REF_SCAN_INSTS {
                        combined_references.extend(extract_data_references(
                            architecture,
                            &instructions,
                            &string_ranges,
                            &executable,
                        ));
                    }
                    attach_relocation_references(
                        &mut combined_references,
                        &instructions,
                        &relocation_refs,
                    );
                    if combined_references.len() <= 4096 {
                        reclassify_string_references(&mut combined_references, &string_ranges);
                    }
                    dedupe_references_in_place(&mut combined_references);
                } else if combined_references.len() > 1 {
                    dedupe_references_in_place(&mut combined_references);
                }
                (
                    address,
                    name,
                    range_end,
                    is_heuristic_seed,
                    instructions,
                    combined_references,
                )
        });
        revx_trace(|| format!(
            "phase1 batch={} size={} decoded={} elapsed_ms={}",
            phase1_batches,
            batch_len,
            decoded.len(),
            batch_started.elapsed().as_millis()
        ));

        for (address, name, range_end, is_heuristic_seed, instructions, combined_references) in
            decoded
        {
            if function_count >= function_budget {
                break;
            }
            if instructions.is_empty() {
                continue;
            }
            let size = instructions
                .last()
                .map(|inst| inst.address + inst_len(inst) as u64 - address)
                .unwrap_or(0);
            if size == 0 {
                continue;
            }
            let function_end = address + size;
            if architecture == Architecture::Arm64
                && is_heuristic_seed
                && claimed_ranges
                    .range(..=address)
                    .next_back()
                    .is_some_and(|(&start, &end)| {
                        address >= start && address < end && function_end <= end && size <= 0x20
                    })
            {
                continue;
            }
            if architecture == Architecture::Arm64
                && is_heuristic_seed
                && looks_like_arm64_trampoline_fragment(&instructions, &combined_references)
            {
                continue;
            }
            if architecture == Architecture::Arm64
                && is_heuristic_seed
                && looks_like_arm64_branch_thunk(&instructions, &combined_references)
            {
                continue;
            }
            let overlaps = claimed_ranges
                .range(..=address)
                .next_back()
                .is_some_and(|(_, &end)| address < end)
                || claimed_ranges
                    .range(address..function_end)
                    .next()
                    .is_some();
            if overlaps {
                continue;
            }
            if all_references.len() < ref_cap {
                for reference in &combined_references {
                    if all_references.len() >= ref_cap {
                        break;
                    }
                    all_references.insert(*reference);
                }
            }

            let expand_calls = profile == AnalysisProfile::Full
                || (if resource::lean_mode() {
                    function_count < (function_budget / 4).max(16)
                } else {
                    pending_functions.len() < (function_budget / 4).max(32)
                });
            if expand_calls {
                for reference in combined_references
                    .iter()
                    .filter(|r| r.kind == ReferenceKind::Call)
                {
                    if visited.contains(&reference.to)
                        || import_stub_addrs.contains(&reference.to)
                        || !is_executable_address(&executable, reference.to)
                        || (image.architecture == Architecture::Arm64 && reference.to % 4 != 0)
                    {
                        continue;
                    }
                    if hard_boundaries.insert(reference.to) {
                        priority_queue.push_back((reference.to, format_sub_addr(reference.to)));
                    }
                }
            }

            let debug_hint = hint_by_addr
                .get(&address)
                .or_else(|| hint_by_name.get(name.as_str()))
                .cloned();

            if resource::lean_mode() {
                let keep_pseudo = lean_keep_pseudocode(&name, function_count);
                let function = lean_function_from_decode(
                    &image.id,
                    address,
                    name,
                    size,
                    &instructions,
                    keep_pseudo,
                );
                drop(instructions);
                drop(combined_references);
                let _ = debug_hint;
                on_function(function)?;
                function_count += 1;
                claimed_ranges.insert(address, function_end);
            } else {
                pending_functions.push(PendingFunction {
                    address,
                    name,
                    size,
                    decode_end: function_end.max(address.saturating_add(4)),
                    debug_hint,
                });
                drop(instructions);
                drop(combined_references);

                function_count += 1;
                claimed_ranges.insert(address, function_end);
            }

            if profile == AnalysisProfile::Full && architecture == Architecture::Arm64 {
                let replay_end = function_end
                    .saturating_add(ARM64_NEARBY_SEED_WINDOW)
                    .min(range_end);
                let replay_seeds =
                    collect_arm64_nearby_seeds(&code_regions, function_end, replay_end);
                for seed in replay_seeds.into_iter().rev() {
                    if visited.contains(&seed)
                        || (image.architecture == Architecture::Arm64 && seed % 4 != 0)
                        || import_stub_addrs.contains(&seed)
                    {
                        continue;
                    }
                    heuristic_seed_addrs.insert(seed);
                    hard_boundaries.insert(seed);
                    priority_queue.push_front((seed, format_sub_addr(seed)));
                }
            }
        }
    }

    revx_trace(|| format!(
        "phase1 done functions={} batches={} elapsed_ms={}",
        pending_functions.len(),
        phase1_batches,
        phase1_started.elapsed().as_millis()
    ));

    budget.rebaseline();
    budget_truncated = false;

    // ── Phase 2: Parallel function analysis (rayon) ─────────────────────────
    let image_id = &image.id;
    let image_arch = image.architecture;
    let image_imports = &image.imports;
    let image_strings = &image.strings;
    let global_symbols = {
        let mut global_symbols = HashMap::with_capacity(image.imports.len() + image.exports.len());
        for import in &image.imports {
            if let Some(addr) = import.address {
                global_symbols
                    .entry(addr)
                    .or_insert_with(|| sanitize_symbol(&import.name));
            }
        }
        for export in &image.exports {
            if let Some(addr) = export.address {
                global_symbols
                    .entry(addr)
                    .or_insert_with(|| sanitize_symbol(&export.name));
            }
        }
        global_symbols
    };
    let global_symbols = &global_symbols;
    let function_symbols = {
        let mut map = HashMap::with_capacity(global_symbols.len() + pending_functions.len());
        for (addr, name) in global_symbols {
            map.insert(*addr, name.clone());
        }
        for pf in &pending_functions {
            map.entry(pf.address)
                .or_insert_with(|| sanitize_symbol(&pf.name));
        }
        Arc::new(map)
    };
    let function_symbols = function_symbols.as_ref();
    let shared_string_map = Arc::new(
        image
            .strings
            .iter()
            .filter_map(|s| s.address.map(|a| (a, s.value.as_str())))
            .take(MAX_SHARED_STRING_MAP)
            .map(|(a, v)| (a, v.to_string()))
            .collect::<HashMap<_, _>>(),
    );

    if budget.check().is_err() {
        budget_truncated = true;
    }
    let phase2_started = std::time::Instant::now();
    let phase2_deadline = budget.deadline();
    let phase2_rss_limit = budget.rss_limit_bytes();
    revx_trace(|| format!(
        "phase2 start pending={} jobs={} budget_truncated={} remaining_ms={}",
        pending_functions.len(),
        parallel_worker_count(),
        budget_truncated,
        budget.remaining().as_millis()
    ));
    let analyze_one = |pf: PendingFunction| -> (Function, Vec<Reference>) {
            if std::time::Instant::now() >= phase2_deadline {
                return (
                    Function {
                        name: pf.name,
                        address: pf.address,
                        size: pf.size,
                        blocks: Vec::new(),
                        stack_summary: None,
                        arguments: Vec::new(),
                        locals: Vec::new(),
                        pseudocode: None,
                        evidence_ids: vec![format!("fn:{}:{:x}", image_id, pf.address)],
                        warnings: vec!["analysis_budget_exceeded:wall".to_string()],
                    },
                    Vec::new(),
                );
            }
            if resource::current_rss_bytes().is_some_and(|rss| rss >= phase2_rss_limit) {
                return (
                    Function {
                        name: pf.name,
                        address: pf.address,
                        size: pf.size,
                        blocks: Vec::new(),
                        stack_summary: None,
                        arguments: Vec::new(),
                        locals: Vec::new(),
                        pseudocode: None,
                        evidence_ids: vec![format!("fn:{}:{:x}", image_id, pf.address)],
                        warnings: vec!["analysis_budget_exceeded:memory".to_string()],
                    },
                    Vec::new(),
                );
            }
            let fn_started = std::time::Instant::now();
            let (instructions, code_refs) = decode_function_with_references(
                architecture,
                &code_regions,
                pf.address,
                pf.decode_end,
                &executable,
            );
            if instructions.is_empty() {
                return (
                    Function {
                        name: pf.name,
                        address: pf.address,
                        size: pf.size,
                        blocks: Vec::new(),
                        stack_summary: None,
                        arguments: Vec::new(),
                        locals: Vec::new(),
                        pseudocode: None,
                        evidence_ids: vec![format!("fn:{}:{:x}", image_id, pf.address)],
                        warnings: vec!["empty_decode".to_string()],
                    },
                    Vec::new(),
                );
            }
            let mut combined_references = if profile == AnalysisProfile::Full {
                normalize_references(architecture, &code_regions, code_refs)
            } else {
                code_refs
            };
            if profile == AnalysisProfile::Full {
                promote_data_reference_kinds(
                    &mut combined_references,
                    &string_ranges,
                    &executable,
                );
                if instructions.len() <= MAX_DATA_REF_SCAN_INSTS {
                    combined_references.extend(extract_data_references(
                        architecture,
                        &instructions,
                        &string_ranges,
                        &executable,
                    ));
                }
                attach_relocation_references(
                    &mut combined_references,
                    &instructions,
                    &relocation_refs,
                );
                if combined_references.len() <= 4096 {
                    reclassify_string_references(&mut combined_references, &string_ranges);
                }
                dedupe_references_in_place(&mut combined_references);
            } else if combined_references.len() > 1 {
                dedupe_references_in_place(&mut combined_references);
            }
            let call_target_overrides = call_target_overrides(&combined_references);
            revx_trace(|| format!(
                "fn-start {} @ {:#x} insts={}",
                pf.name,
                pf.address,
                instructions.len()
            ));
            let debug_hint = pf.debug_hint.as_ref();
            let large_fn = instructions.len() > LIGHT_VAR_RECOVERY_INSTS;
            let (stack_summary, mut arguments, locals) = if profile == AnalysisProfile::Fast {
                (
                    Some(recover_stack_summary_fast(
                        image_arch,
                        image.format,
                        &instructions,
                        debug_hint,
                    )),
                    recover_variables_fast(image, pf.address, debug_hint),
                    Vec::new(),
                )
            } else if large_fn {
                let sample = sample_instructions_for_recovery(&instructions);
                let mut stack = recover_stack_summary_for(
                    image_arch,
                    Some(image.format),
                    &sample,
                    debug_hint,
                    &call_target_overrides,
                    profile,
                );
                if stack.return_type.is_none() {
                    stack.return_type = infer_return_type(
                        &sample,
                        &call_target_overrides,
                    );
                }
                let (arguments, locals) =
                    recover_variables(image, pf.address, &sample, debug_hint, profile);
                (Some(stack), arguments, locals)
            } else {
                let stack_summary = Some(recover_stack_summary_for(
                    image_arch,
                    Some(image.format),
                    &instructions,
                    debug_hint,
                    &call_target_overrides,
                    profile,
                ));
                let (arguments, locals) =
                    recover_variables(image, pf.address, &instructions, debug_hint, profile);
                (stack_summary, arguments, locals)
            };
            polish_argument_names(&pf.name, &mut arguments);
            let mut combined_references = combined_references;
            let fast_return_type = if profile == AnalysisProfile::Fast {
                stack_summary
                    .as_ref()
                    .and_then(|summary| summary.return_type.clone())
                    .or_else(|| infer_return_type(&instructions, &call_target_overrides))
            } else {
                None
            };
            let blocks = if profile == AnalysisProfile::Fast {
                vec![finalize_basic_block(pf.address, instructions)]
            } else {
                split_basic_blocks(pf.address, instructions, &combined_references)
            };

            let mut inst_count_pre = 0usize;
            for block in &blocks {
                inst_count_pre += block.instructions.len();
            }
            let needs_indirect_resolve = inst_count_pre <= heavy_inst_limit(profile)
                && combined_references
                    .iter()
                    .any(|reference| reference.kind == ReferenceKind::IndirectCall);
            let resolved_calls = if needs_indirect_resolve {
                ssa::resolve_indirect_calls(&blocks, image_imports)
            } else {
                Vec::new()
            };

            let mut local_new_refs: Vec<Reference> = Vec::new();
            if !resolved_calls.is_empty() {
                let mut resolved_by_addr: HashMap<u64, u64> =
                    HashMap::with_capacity(resolved_calls.len());
                for resolved in &resolved_calls {
                    if resolved.source != ssa::CallTargetSource::Unresolved
                        && resolved.target_addr != 0
                    {
                        resolved_by_addr.insert(resolved.call_addr, resolved.target_addr);
                        local_new_refs.push(Reference {
                            from: resolved.call_addr,
                            to: resolved.target_addr,
                            kind: ReferenceKind::Call,
                        });
                    }
                }
                if !resolved_by_addr.is_empty() {
                    for reference in &mut combined_references {
                        if reference.kind == ReferenceKind::IndirectCall {
                            if let Some(&target) = resolved_by_addr.get(&reference.from) {
                                reference.to = target;
                                reference.kind = ReferenceKind::Call;
                                resolved_by_addr.remove(&reference.from);
                            }
                        }
                    }
                    for (from, to) in resolved_by_addr {
                        combined_references.push(Reference {
                            from,
                            to,
                            kind: ReferenceKind::Call,
                        });
                    }
                }
            }

            let inst_count = inst_count_pre;
            let use_ssa = profile == AnalysisProfile::Full
                && !blocks.is_empty()
                && inst_count <= ssa_inst_limit(profile)
                && blocks.len() <= ssa_block_limit(profile);
            let use_linear_ssa = profile == AnalysisProfile::Full
                && !blocks.is_empty()
                && !use_ssa
                && inst_count <= linear_ssa_inst_limit(profile)
                && blocks.len() <= linear_ssa_block_limit(profile);
            let use_heavy = profile == AnalysisProfile::Full
                && !blocks.is_empty()
                && inst_count <= heavy_inst_limit(profile)
                && blocks.len() <= heavy_block_limit(profile);
            let use_oversize_window = profile == AnalysisProfile::Full
                && !blocks.is_empty()
                && !use_ssa
                && !use_linear_ssa
                && inst_count > linear_ssa_inst_limit(profile);
            revx_trace(|| format!(
                "fn-stage {} @ {:#x} blocks={} insts={} heavy={} ssa={} linear={} vars_ms={}",
                pf.name,
                pf.address,
                blocks.len(),
                inst_count,
                use_heavy,
                use_ssa,
                use_linear_ssa,
                fn_started.elapsed().as_millis()
            ));

            let evidence_fn = format!("fn:{}:{:x}", image_id, pf.address);
            let evidence_stack = format!("stack:{}:{:x}", image_id, pf.address);
            let evidence_vars = format!("vars:{}:{:x}", image_id, pf.address);
            let evidence_pseudo = format!("pseudo:{}:{:x}", image_id, pf.address);

            let return_type_hint = fast_return_type.or_else(|| {
                stack_summary
                    .as_ref()
                    .and_then(|summary| summary.return_type.clone())
            });
            let pseudocode = if resource::micro_mode() {
                None
            } else if profile == AnalysisProfile::Fast {
                if !resource::lean_mode() && inst_count > 0 && inst_count <= MAX_FAST_SSA_INSTS {
                    let mut combined = combined_references.clone();
                    for (from, to) in &call_target_overrides {
                        if !combined
                            .iter()
                            .any(|r| r.from == *from && r.kind == ReferenceKind::Call)
                        {
                            combined.push(Reference {
                                from: *from,
                                to: *to,
                                kind: ReferenceKind::Call,
                            });
                        }
                    }
                    let mut ssa_func = match image_arch {
                        #[cfg(feature = "arch-x64")]
                        Architecture::X86_64 => {
                            ssa::lift_x64_to_ssa(&blocks, &combined, &arguments)
                        }
                        #[cfg(feature = "arch-arm64")]
                        Architecture::Arm64 => {
                            ssa::lift_arm64_to_ssa(&blocks, &combined, &arguments)
                        }
                        _ => ssa::lift_arm64_to_ssa(&blocks, &combined, &arguments),
                    };
                    ssa::refine_call_arguments_with_symbols(&mut ssa_func, function_symbols);
                    let text = ssa::render_ssa_pseudocode_linear_with_string_arc(
                        &ssa_func,
                        &pf.name,
                        &arguments,
                        function_symbols,
                        &HashMap::new(),
                        Arc::clone(&shared_string_map),
                    );
                    Some(finalize_pseudocode_unit_with_context(
                        &pf.name,
                        pf.address,
                        PseudocodeUnit {
                            language: "c".to_string(),
                            text,
                            regions: Vec::new(),
                            region_artifact: None,
                            evidence_ids: vec![evidence_pseudo.clone()],
                            semantic_lattice: None,
                        },
                        &combined_references,
                        function_symbols,
                    ))
                } else {
                    Some(render_fast_pseudocode(
                        &pf.name,
                        pf.address,
                        &blocks,
                        &arguments,
                        image_imports,
                        image_strings,
                        &call_target_overrides,
                        function_symbols,
                        return_type_hint.as_deref(),
                        &combined_references,
                    ))
                }
            } else if use_ssa || use_linear_ssa {
                let ssa_started = std::time::Instant::now();
                if use_linear_ssa {
                    if let Some(cached) =
                        ssa::linear_cache_lookup(&blocks, &pf.name, &arguments)
                    {
                        revx_trace(|| format!(
                            "fn-ssa-cache-hit {} @ {:#x} text_len={} elapsed_ms={}",
                            pf.name,
                            pf.address,
                            cached.len(),
                            ssa_started.elapsed().as_millis()
                        ));
                        Some(finalize_pseudocode_unit_with_context(
                            &pf.name,
                            pf.address,
                            PseudocodeUnit {
                                language: "c".to_string(),
                                text: cached,
                                regions: Vec::new(),
                                region_artifact: None,
                                evidence_ids: vec![format!("pseudo:{:x}", pf.address)],
                                semantic_lattice: None,
                            },
                            &combined_references,
                            function_symbols,
                        ))
                    } else {
                        None
                    }
                } else {
                    None
                }
                .or_else(|| {
                if !call_target_overrides.is_empty() {
                    for (from, to) in &call_target_overrides {
                        if !combined_references
                            .iter()
                            .any(|r| r.from == *from && r.kind == ReferenceKind::Call)
                        {
                            combined_references.push(Reference {
                                from: *from,
                                to: *to,
                                kind: ReferenceKind::Call,
                            });
                        }
                    }
                }
                let mut ssa_func = match image_arch {
                    Architecture::Arm64 => {
                        ssa::lift_arm64_to_ssa(&blocks, &combined_references, &arguments)
                    }
                    Architecture::X86_64 => {
                        ssa::lift_x64_to_ssa(&blocks, &combined_references, &arguments)
                    }
                    Architecture::Unknown => {
                        ssa::lift_arm64_to_ssa(&blocks, &combined_references, &arguments)
                    }
                };
                revx_trace(|| format!(
                    "fn-ssa-lift {} @ {:#x} values={} elapsed_ms={}",
                    pf.name,
                    pf.address,
                    ssa_func.values.len(),
                    ssa_started.elapsed().as_millis()
                ));
                let refine_started = std::time::Instant::now();
                let mut local_symbols = HashMap::new();
                if !use_linear_ssa {
                    ssa::refine_call_arguments_with_symbols(&mut ssa_func, function_symbols);
                    for resolved in &resolved_calls {
                        if resolved.target_addr != 0
                            && resolved.source != ssa::CallTargetSource::Unresolved
                            && !function_symbols.contains_key(&resolved.target_addr)
                        {
                            local_symbols.insert(resolved.target_addr, resolved.name.clone());
                        }
                    }
                } else {
                    ssa::refine_call_arguments_with_symbols(&mut ssa_func, function_symbols);
                }
                revx_trace(|| format!(
                    "fn-ssa-refine {} @ {:#x} elapsed_ms={}",
                    pf.name,
                    pf.address,
                    refine_started.elapsed().as_millis()
                ));
                let render_started = std::time::Instant::now();
                let ssa_text = if use_linear_ssa {
                    ssa::render_ssa_pseudocode_linear_with_string_arc(
                        &ssa_func,
                        &pf.name,
                        &arguments,
                        function_symbols,
                        &local_symbols,
                        Arc::clone(&shared_string_map),
                    )
                } else {
                    ssa::render_ssa_pseudocode_named_layered_with_string_arc(
                        &ssa_func,
                        &pf.name,
                        &arguments,
                        function_symbols,
                        &local_symbols,
                        Arc::clone(&shared_string_map),
                    )
                };
                if use_linear_ssa {
                    ssa::linear_cache_store(&blocks, &pf.name, &arguments, &ssa_text);
                }
                let regions = if use_linear_ssa {
                    Vec::new()
                } else {
                    ssa::ssa_pseudocode_regions(&ssa_func, pf.address)
                };
                revx_trace(|| format!(
                    "fn-ssa-render {} @ {:#x} mode={} text_len={} elapsed_ms={}",
                    pf.name,
                    pf.address,
                    if use_linear_ssa { "linear" } else { "layered" },
                    ssa_text.len(),
                    render_started.elapsed().as_millis()
                ));
                Some(finalize_pseudocode_unit_with_context(
                    &pf.name,
                    pf.address,
                    PseudocodeUnit {
                    language: "c".to_string(),
                    text: ssa_text,
                    regions,
                    region_artifact: None,
                    evidence_ids: vec![format!("pseudo:{:x}", pf.address)],
                        semantic_lattice: None,
                },
                    &combined_references,
                    function_symbols,
                ))
                })
            } else if use_oversize_window {
                Some(render_oversized_pseudocode(
                    &pf.name,
                    pf.address,
                    &blocks,
                    &arguments,
                    &locals,
                    image_imports,
                    &call_target_overrides,
                    function_symbols,
                    debug_hint,
                    profile,
                    image_strings,
                    image_arch,
                    &combined_references,
                    Arc::clone(&shared_string_map),
                ))
            } else {
                Some(render_pseudocode(
                    &pf.name,
                    pf.address,
                    &blocks,
                    &arguments,
                    &locals,
                    image_imports,
                    &call_target_overrides,
                    debug_hint,
                    profile,
                    image_strings,
                ))
            };

            let mut evidence_ids = Vec::with_capacity(4);
            evidence_ids.push(evidence_fn);
            if stack_summary.is_some() {
                evidence_ids.push(evidence_stack);
            }
            if !arguments.is_empty() || !locals.is_empty() {
                evidence_ids.push(evidence_vars);
            }
            if pseudocode.is_some() {
                evidence_ids.push(evidence_pseudo);
            }

            let mut function = Function {
                name: pf.name,
                address: pf.address,
                size: pf.size,
                blocks,
                stack_summary,
                arguments,
                locals,
                pseudocode,
                evidence_ids,
                warnings: function_warnings(pf.size, max_function_bytes),
            };
            if profile == AnalysisProfile::Full {
                let heavy_ok = function.blocks.len() <= heavy_block_limit(profile)
                    && function
                        .blocks
                        .iter()
                        .map(|b| b.instructions.len())
                        .sum::<usize>()
                        <= heavy_inst_limit(profile);
                if heavy_ok {
                    apply_heuristic_naming(&mut function);
                    deepen_function_quality(&mut function, import_types);
                } else {
                    apply_heuristic_naming(&mut function);
                }
            }
            {
                let insts = function
                    .blocks
                    .iter()
                    .map(|block| block.instructions.len())
                    .sum::<usize>();
                revx_trace(|| format!(
                    "fn {} @ {:#x} size={} blocks={} insts={} elapsed_ms={}",
                    function.name,
                    function.address,
                    function.size,
                    function.blocks.len(),
                    insts,
                    fn_started.elapsed().as_millis()
                ));
            }

            (function, local_new_refs)
    };
    revx_trace(|| format!(
        "phase2 ready pending={} elapsed_ms={}",
        pending_functions.len(),
        phase2_started.elapsed().as_millis()
    ));

    // phase3 stream
    let phase3_started = std::time::Instant::now();
    let mut truncated_functions = 0usize;
    let mut analyzed = 0usize;
    let mut recovered_types: Vec<TypeDef> = Vec::new();
    let mut seen_type_names: BTreeSet<String> = BTreeSet::new();
    while !pending_functions.is_empty() {
        if budget.check().is_err() {
            budget_truncated = true;
        }
        let take = pending_stream_batch_size().min(pending_functions.len());
        let batch: Vec<PendingFunction> = pending_functions.drain(..take).collect();
        let results = map_in_analysis_pool(batch, |pf| analyze_one(pf));
        for (function, local_new_refs) in results {
            if all_references.len() < ref_cap {
                for r in local_new_refs {
                    if all_references.len() >= ref_cap {
                        break;
                    }
                    all_references.insert(r);
                }
            }
            if !function.warnings.is_empty() {
                truncated_functions += 1;
            }
            for var in function.arguments.iter().chain(function.locals.iter()) {
                if let Some(ty) = var.type_name.as_ref() {
                    if seen_type_names.insert(ty.clone()) {
                        recovered_types.push(TypeDef {
                            id: format!("ty:inferred:{}", ty),
                            name: ty.clone(),
                            kind: "inferred".to_string(),
                            source: TypeSource::Inferred,
                            size: inferred_type_size(ty),
                            evidence_ids: var.evidence_ids.clone(),
                        });
                    }
                }
            }
            let addr = function.address;
            let name = function.name.clone();
            let ingest_started = std::time::Instant::now();
            on_function(function)?;
            analyzed += 1;
            revx_trace(|| format!(
                "phase3 ingest {} @ {:#x} elapsed_ms={}",
                name,
                addr,
                ingest_started.elapsed().as_millis()
            ));
        }
        release_code_region_pages(&code_regions);
    }
    revx_trace(|| format!(
        "phase2/3 done analyzed={} elapsed_ms={}",
        analyzed,
        phase2_started.elapsed().as_millis()
    ));

    let mut reference_list = all_references.into_iter().collect::<Vec<_>>();
    reference_list.sort_unstable_by_key(|reference| {
        (reference.from, reference.to, reference.kind as u8)
    });
    if budget_truncated || budget.exceeded().is_some() {
        revx_trace(|| format!(
            "budget exceeded kind={:?} elapsed_ms={}",
            budget.exceeded(),
            budget.elapsed_ms()
        ));
    }
    revx_trace(|| format!(
        "phase3 done refs={} elapsed_ms={} budget_truncated={}",
        reference_list.len(),
        phase3_started.elapsed().as_millis(),
        budget_truncated
    ));
    Ok((reference_list, recovered_types, truncated_functions))
}

fn executable_ranges(image: &BinaryImage) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    for section in &image.sections {
        let kind = section.kind.to_ascii_lowercase();
        let name = section.name.to_ascii_lowercase();
        if section.size == 0 {
            continue;
        }
        if kind.contains("text")
            || kind.contains("code")
            || name == "__text"
            || name.ends_with("__text")
            || name.contains(".text")
        {
            out.push((
                section.address,
                section.address.saturating_add(section.size),
            ));
        }
    }
    if out.is_empty() {
        for segment in &image.segments {
            if segment.size == 0 {
                continue;
            }
            let name = segment.name.to_ascii_lowercase();
            if name.contains("pagezero") {
                continue;
            }
            let perms = segment.permissions.to_ascii_lowercase();
            let executable = perms == "x"
                || perms == "rx"
                || perms == "rwx"
                || perms == "wx"
                || perms.contains("execute")
                || (perms.contains('x')
                    && !perms.contains("maxprot")
                    && !perms.contains("initprot"));
            if executable || name.contains("__text") || name.contains(".text") {
                out.push((
                    segment.address,
                    segment.address.saturating_add(segment.size),
                ));
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn collect_function_seeds(image: &BinaryImage) -> BTreeMap<u64, String> {
    let executable = executable_ranges(image);
    let mut seeds: BTreeMap<u64, String> = image
        .symbols
        .iter()
        .filter_map(|sym| {
            let address = sym.address?;
            if address == 0 {
                return None;
            }
            if !(sym.kind.contains("Text")
                || sym.kind.contains("Label")
                || sym.kind.contains("Unknown"))
            {
                return None;
            }
            if !is_executable_address(&executable, address) {
                return None;
            }
            Some((address, sym.name.clone()))
        })
        .collect();

    for export in &image.exports {
        let Some(address) = export.address else {
            continue;
        };
        if address == 0 || !is_executable_address(&executable, address) {
            continue;
        }
        seeds.entry(address).or_insert_with(|| export.name.clone());
    }

    seeds
}

fn collect_seed_priority(image: &BinaryImage) -> HashMap<u64, usize> {
    let mut priority = HashMap::new();

    for (idx, export) in image.exports.iter().enumerate() {
        if let Some(address) = export.address
            && address != 0
        {
            priority.entry(address).or_insert(idx);
        }
    }

    if let Some(entry) = image.entry.filter(|entry| *entry != 0) {
        priority.entry(entry).or_insert(0);
    }

    for (idx, hint) in image.debug_import.function_hints.iter().enumerate() {
        if let Some(address) = hint.address
            && address != 0
        {
            priority.entry(address).or_insert(idx);
        }
    }

    priority
}

fn is_resolved_code_target(addr: u64) -> bool {
    addr > 31
}

fn cfg_block_limit() -> usize {
    if resource::lean_mode() {
        8
    } else {
        MAX_CFG_BLOCKS
    }
}

fn cfg_inst_limit() -> usize {
    if resource::lean_mode() {
        32
    } else {
        MAX_CFG_INSTRUCTIONS
    }
}

fn default_max_function_bytes(architecture: Architecture, profile: AnalysisProfile) -> usize {
    match (architecture, profile) {
        (Architecture::Arm64, AnalysisProfile::Full) => FULL_MAX_FUNCTION_BYTES_ARM64,
        (Architecture::Arm64, _) => DEFAULT_MAX_FUNCTION_BYTES_ARM64,
        (_, AnalysisProfile::Full) => FULL_MAX_FUNCTION_BYTES_X64,
        _ => DEFAULT_MAX_FUNCTION_BYTES_X64,
    }
}

fn function_warnings(size: u64, max_bytes: u64) -> Vec<String> {
    let mut warnings = Vec::new();
    if size >= max_bytes {
        warnings.push(format!(
            "function reached decode window limit of {max_bytes} bytes; boundary may be truncated"
        ));
    }
    warnings
}

fn summarize_analysis_warnings(functions: &[Function], function_budget: usize) -> Vec<String> {
    summarize_analysis_warnings_from_counters(
        functions.len(),
        functions
            .iter()
            .filter(|function| !function.warnings.is_empty())
            .count(),
        function_budget,
    )
}

fn summarize_analysis_warnings_from_counters(
    function_count: usize,
    truncated_functions: usize,
    function_budget: usize,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if function_count >= function_budget {
        warnings.push(format!(
            "function recovery reached global limit of {function_budget}; coverage is likely truncated"
        ));
    }
    if truncated_functions > 0 {
        warnings.push(format!(
            "{truncated_functions} recovered functions reached the decode window limit and may be truncated"
        ));
    }
    warnings
}

fn memory_function_cap(profile: AnalysisProfile) -> usize {
    let rss_kb = resource::process_resource_limits().rss_kb.max(64) as usize;
    let by_rss = (rss_kb / 64).max(MIN_FUNCTION_BUDGET);
    let profile_cap = match profile {
        AnalysisProfile::Fast => {
            if resource::lean_mode() {
                MAX_FUNCTION_BUDGET_FAST.min(48)
            } else {
                MAX_FUNCTION_BUDGET_FAST
            }
        }
        AnalysisProfile::Full => {
            if resource::lean_mode() {
                MAX_FUNCTION_BUDGET_FULL.min(96)
            } else {
                MAX_FUNCTION_BUDGET_FULL
            }
        }
    };
    by_rss.min(profile_cap)
}

fn function_recovery_budget(image: &BinaryImage, profile: AnalysisProfile) -> usize {
    let executable_bytes = image
        .sections
        .iter()
        .filter(|section| section.kind.contains("Text"))
        .map(|section| section.size as usize)
        .sum::<usize>()
        .max(
            image
                .segments
                .iter()
                .map(|segment| segment.size as usize)
                .max()
                .unwrap_or(0),
        );
    let seed_budget = image
        .symbols
        .len()
        .max(image.imports.len() + image.exports.len());
    let size_budget = executable_bytes.div_ceil(0x80);
    let cap = memory_function_cap(profile);
    MIN_FUNCTION_BUDGET
        .max(size_budget.min(cap))
        .max(seed_budget.min(cap))
        .min(cap)
}

fn collect_arm64_heuristic_seeds(code_regions: &[CodeRegion]) -> Vec<u64> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();

    for region in code_regions {
        let data = region.data_prefix(4096);
        let mut offset = 0usize;
        while offset + 4 <= data.len() {
            let word = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            if is_arm64_prologue_word(word) && !is_arm64_thunk_boundary(region, offset) {
                let Some(seed_offset) = arm64_seed_offset(region, offset) else {
                    offset += 4;
                    continue;
                };
                let address = region.start + seed_offset as u64;
                if seen.insert(address) {
                    out.push(address);
                }
            }
            offset += 4;
        }
    }

    out
}

fn collect_arm64_nearby_seeds(
    code_regions: &[CodeRegion],
    scan_start: u64,
    scan_end: u64,
) -> Vec<u64> {
    if scan_end <= scan_start {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut seen = BTreeSet::new();

    for region in code_regions {
        if scan_start >= region.end || scan_end <= region.start {
            continue;
        }
        let start = scan_start.max(region.start);
        let end = scan_end.min(region.end);
        let Some(data) = region.read_range(start, end.min(start.saturating_add(4096))) else {
            continue;
        };
        let mut offset = 0usize;
        while offset + 4 <= data.len() {
            let address = start + offset as u64;
            if address >= end {
                break;
            }

            let word = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            if is_arm64_prologue_word(word) && !is_arm64_thunk_boundary(region, offset) {
                if let Some(seed_offset) = arm64_seed_offset(region, offset) {
                    let seed = region.start + seed_offset as u64;
                    if seed >= scan_start && seed < scan_end && seen.insert(seed) {
                        out.push(seed);
                    }
                }
            }

            offset += 4;
        }
    }

    out.sort_unstable();
    out
}

fn arm64_seed_offset(region: &CodeRegion, offset: usize) -> Option<usize> {
    let data = region.data_prefix(4096);
    if offset >= 4 {
        let prev_offset = offset - 4;
        let prev_text = decode_arm64_instruction_text(
            &data[prev_offset..prev_offset + 4],
            region.start + prev_offset as u64,
        )?;
        if matches!(prev_text.as_str(), "paciasp" | "pacibsp")
            && is_likely_arm64_function_boundary(region, prev_offset)
        {
            return Some(prev_offset);
        }
    }

    if is_likely_arm64_function_boundary(region, offset) {
        Some(offset)
    } else {
        None
    }
}

fn is_arm64_thunk_boundary(region: &CodeRegion, offset: usize) -> bool {
    let data = region.data_prefix(4096);
    let Some(current) =
        decode_arm64_instruction_text(&data[offset..offset + 4], region.start + offset as u64)
    else {
        return false;
    };
    if !current.starts_with("stp x29, x30") {
        return false;
    }

    let Some(next_offset) = offset.checked_add(8) else {
        return false;
    };
    if next_offset + 4 > data.len() {
        return false;
    }
    let Some(next_text) = decode_arm64_instruction_text(
        &data[next_offset..next_offset + 4],
        region.start + next_offset as u64,
    ) else {
        return false;
    };

    next_text.starts_with("b ")
}

fn is_likely_arm64_function_boundary(region: &CodeRegion, offset: usize) -> bool {
    let data = region.data_prefix(4096);
    if offset == 0 {
        return true;
    }

    let mut cursor = offset;
    let mut skipped_padding = 0usize;

    while cursor >= 4 && skipped_padding <= 2 {
        cursor -= 4;
        let Some(text) =
            decode_arm64_instruction_text(&data[cursor..cursor + 4], region.start + cursor as u64)
        else {
            return false;
        };
        if is_arm64_padding_text(&text) {
            skipped_padding += 1;
            if cursor == 0 {
                return true;
            }
            continue;
        }
        return is_arm64_terminal_text(&text);
    }

    false
}

fn next_hard_boundary(address: u64, range_end: u64, hard_boundaries: &BTreeSet<u64>) -> u64 {
    hard_boundaries
        .range((address + 1)..=range_end)
        .next()
        .copied()
        .unwrap_or(range_end)
}

fn is_arm64_prologue_word(word: u32) -> bool {
    if matches!(word, 0xd503233f | 0xd503237f) {
        return true;
    }
    if matches!(
        word,
        0xa9bf7bfd
            | 0xa9be7bfd
            | 0xa9bd7bfd
            | 0xa9bc7bfd
            | 0xa9bb7bfd
            | 0xa9ba7bfd
            | 0xa9b97bfd
            | 0xa9b87bfd
            | 0xa9b77bfd
            | 0xa9b67bfd
            | 0xa9b57bfd
            | 0xa9b47bfd
            | 0xa9b37bfd
            | 0xa9b27bfd
            | 0xa9b17bfd
            | 0xa9b07bfd
            | 0xa9af7bfd
            | 0xa9ae7bfd
            | 0xa9ad7bfd
            | 0xa9ac7bfd
            | 0xa9ab7bfd
            | 0xa9aa7bfd
            | 0xa9a97bfd
            | 0xa9a87bfd
    ) {
        return true;
    }
    // 64-bit STP pre-index/signed-offset encodings commonly used by prologues.
    // bits[31:22] == 0x2A6 (pre-index store pair) or 0x2A9 (unsigned offset store pair-ish family).
    let top = (word >> 22) & 0x3ff;
    if matches!(top, 0x2a6 | 0x2a7 | 0x2a8 | 0x2a9 | 0x2aa | 0x2ab) {
        let rt = word & 0x1f;
        let rt2 = (word >> 10) & 0x1f;
        if (rt == 29 && rt2 == 30) || (rt == 30 && rt2 == 29) || rt >= 19 {
            return true;
        }
    }
    false
}

fn decode_arm64_instruction_text(bytes: &[u8], base: u64) -> Option<String> {
    let instruction = revx_arch_arm64::decode_block(bytes, base)
        .into_iter()
        .next()?;
    Some(instruction.text.as_ref().to_string())
}

fn is_arm64_padding_text(text: &str) -> bool {
    text == "nop" || text.starts_with("hint #") || text.starts_with("bti ")
}

fn is_arm64_terminal_text(text: &str) -> bool {
    text == "ret"
        || text.starts_with("b ")
        || (text.starts_with("br ") && !text.starts_with("blr "))
        || text.starts_with("eret")
        || text.starts_with("drps")
}

fn sort_seed_batch(
    mut seeds: Vec<(u64, String)>,
    seed_priority: &HashMap<u64, usize>,
) -> Vec<(u64, String)> {
    seeds.sort_by_key(|(address, _)| {
        (
            seed_priority.get(address).copied().unwrap_or(usize::MAX),
            *address,
        )
    });
    seeds
}

fn is_executable_address(ranges: &[(u64, u64)], address: u64) -> bool {
    find_executable_range(ranges, address).is_some()
}

fn find_executable_range(ranges: &[(u64, u64)], address: u64) -> Option<(u64, u64)> {
    if ranges.is_empty() {
        return None;
    }
    let mut lo = 0usize;
    let mut hi = ranges.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        let (start, end) = ranges[mid];
        if address < start {
            hi = mid;
        } else if address >= end {
            lo = mid + 1;
        } else {
            return Some((start, end));
        }
    }
    None
}

fn decode_function(
    architecture: Architecture,
    code_regions: &[CodeRegion],
    start: u64,
    max_end: u64,
    executable: &[(u64, u64)],
) -> Vec<Instruction> {
    decode_function_with_references(architecture, code_regions, start, max_end, executable).0
}

/// Decode a function and extract references in a single pass when possible,
/// avoiding the double-decode overhead of `decode_function` +
/// `extract_references`.
fn decode_function_with_references(
    architecture: Architecture,
    code_regions: &[CodeRegion],
    start: u64,
    max_end: u64,
    executable: &[(u64, u64)],
) -> (Vec<Instruction>, Vec<Reference>) {
    match architecture {
        #[cfg(feature = "arch-x64")]
        Architecture::X86_64 => {
            decode_x64_cfg_with_references(code_regions, start, max_end, executable)
        }
        #[cfg(feature = "arch-arm64")]
        Architecture::Arm64 => {
            decode_arm64_cfg_with_references(code_regions, start, max_end, executable)
        }
        _ => (Vec::new(), Vec::new()),
    }
}

fn build_code_regions(image: &BinaryImage) -> Vec<CodeRegion> {
    if let Some(regions) = build_code_regions_from_image(image) {
        return regions;
    }
    let path = std::path::Path::new(&image.path);
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let mmap = match unsafe { memmap2::Mmap::map(&file) } {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };
    let Ok(parsed) = object::File::parse(&*mmap) else {
        return Vec::new();
    };
    let lean = resource::lean_mode();
    let file = match std::fs::File::open(path) {
        Ok(f) => Arc::new(f),
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut text_sections = 0usize;
    let max_text_sections = if lean { 4 } else { usize::MAX };

    for section in parsed.sections() {
        let kind = section.kind();
        let allow = if lean {
            matches!(kind, object::SectionKind::Text)
        } else {
            matches!(
                kind,
                object::SectionKind::Text
                    | object::SectionKind::ReadOnlyData
                    | object::SectionKind::Data
                    | object::SectionKind::ReadOnlyString
                    | object::SectionKind::ReadOnlyDataWithRel
            )
        };
        if !allow {
            continue;
        }
        let Some((file_offset, file_size)) = section.file_range() else {
            continue;
        };
        let start = section.address();
        let size = section.size();
        let file_size = file_size as usize;
        if file_size == 0 || size == 0 {
            continue;
        }
        if lean {
            if text_sections >= max_text_sections {
                break;
            }
            text_sections += 1;
        }
        let end = start.saturating_add(size);
        out.push(CodeRegion {
            start,
            end,
            bytes: ByteSource::File {
                file: Arc::clone(&file),
                file_offset,
                size: file_size,
            },
        });
    }

    advise_bytes_dontneed(&mmap);
    drop(mmap);
    out.sort_unstable_by_key(|region| region.start);
    out
}

fn build_code_regions_from_image(image: &BinaryImage) -> Option<Vec<CodeRegion>> {
    let lean = resource::lean_mode();
    let path = std::path::Path::new(&image.path);
    let file = Arc::new(std::fs::File::open(path).ok()?);
    let mut out = Vec::new();
    let mut text_sections = 0usize;
    let max_text_sections = if lean { 4 } else { usize::MAX };
    for section in &image.sections {
        let kind = section.kind.to_ascii_lowercase();
        let name = section.name.to_ascii_lowercase();
        let is_text = kind.contains("text")
            || kind.contains("code")
            || name == "__text"
            || name.ends_with("__text")
            || name == ".text";
        let allow = if lean {
            is_text
        } else {
            is_text
                || kind.contains("readonly")
                || kind.contains("data")
                || kind.contains("string")
        };
        if !allow || section.size == 0 {
            continue;
        }
        let Some(file_offset) = section.file_offset else {
            return None;
        };
        if lean {
            if text_sections >= max_text_sections {
                break;
            }
            text_sections += 1;
        }
        let end = section.address.saturating_add(section.size);
        out.push(CodeRegion {
            start: section.address,
            end,
            bytes: ByteSource::File {
                file: Arc::clone(&file),
                file_offset,
                size: section.size as usize,
            },
        });
    }
    if out.is_empty() {
        return None;
    }
    out.sort_unstable_by_key(|region| region.start);
    Some(out)
}

fn advise_bytes_dontneed(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    #[cfg(unix)]
    unsafe {
        unsafe extern "C" {
            fn madvise(addr: *mut u8, len: usize, advice: i32) -> i32;
        }
        const MADV_DONTNEED: i32 = 4;
        let _ = madvise(bytes.as_ptr() as *mut u8, bytes.len(), MADV_DONTNEED);
    }
}

fn extract_references(architecture: Architecture, instructions: &[Instruction]) -> Vec<Reference> {
    match architecture {
        #[cfg(feature = "arch-x64")]
        Architecture::X86_64 => revx_arch_x64::extract_references(instructions),
        #[cfg(feature = "arch-arm64")]
        Architecture::Arm64 => revx_arch_arm64::extract_references(instructions),
        _ => Vec::new(),
    }
}

fn normalize_references(
    architecture: Architecture,
    code_regions: &[CodeRegion],
    references: Vec<Reference>,
) -> Vec<Reference> {
    match architecture {
        Architecture::Arm64 => references
            .into_iter()
            .map(|reference| normalize_arm64_reference(code_regions, reference))
            .collect(),
        _ => references,
    }
}

fn normalize_arm64_reference(code_regions: &[CodeRegion], mut reference: Reference) -> Reference {
    if reference.kind == ReferenceKind::Call
        && let Some(target) = resolve_arm64_call_target(code_regions, reference.to)
    {
        reference.to = target;
    }
    reference
}

fn resolve_arm64_call_target(code_regions: &[CodeRegion], target: u64) -> Option<u64> {
    let mut current = target;
    for _ in 0..4 {
        let Some(next) = arm64_branch_thunk_target(code_regions, current) else {
            break;
        };
        if next == current {
            break;
        }
        current = next;
    }
    if current == target {
        None
    } else {
        Some(current)
    }
}

fn arm64_branch_thunk_target(code_regions: &[CodeRegion], address: u64) -> Option<u64> {
    let (bytes, base) = code_slice(code_regions, address, address.saturating_add(0x10))?;
    if let Some(target) = arm64_direct_branch_thunk_target(&bytes, base) {
        return Some(target);
    }
    let (instructions, references) = revx_arch_arm64::decode_block_with_references(&bytes, base);
    if looks_like_arm64_branch_thunk(&instructions, &references) {
        references
            .into_iter()
            .find(|reference| reference.kind == ReferenceKind::Jump)
            .map(|reference| reference.to)
    } else {
        None
    }
}

fn arm64_direct_branch_thunk_target(bytes: &[u8], base: u64) -> Option<u64> {
    if bytes.len() < 4 {
        return None;
    }
    let mut offset = 0usize;
    let mut saw_jump = None;
    let mut non_padding = 0usize;
    while offset + 4 <= bytes.len() && offset < 12 {
        let word = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        let pc = base + offset as u64;
        if is_arm64_nop_word(word) || is_arm64_bti_word(word) {
            offset += 4;
            continue;
        }
        if let Some(target) = decode_arm64_unconditional_b_target(word, pc) {
            if saw_jump.is_some() {
                return None;
            }
            saw_jump = Some(target);
            non_padding += 1;
            offset += 4;
            break;
        }
        return None;
    }
    if non_padding == 1 {
        saw_jump
    } else {
        None
    }
}

#[inline]
fn is_arm64_nop_word(word: u32) -> bool {
    word == 0xD503201F
}

#[inline]
fn is_arm64_bti_word(word: u32) -> bool {
    (word & 0xFFFF_FC1F) == 0xD503_241F
}

#[inline]
fn decode_arm64_unconditional_b_target(word: u32, pc: u64) -> Option<u64> {
    if (word >> 26) != 0b000101 {
        return None;
    }
    let imm26 = word & 0x03FF_FFFF;
    let signed = ((imm26 as i32) << 6) >> 6;
    let offset = (signed as i64) * 4;
    Some(pc.wrapping_add(offset as u64))
}

fn call_target_overrides(references: &[Reference]) -> HashMap<u64, u64> {
    let mut map = HashMap::with_capacity(8);
    for reference in references {
        if reference.kind == ReferenceKind::Call {
            map.insert(reference.from, reference.to);
        }
    }
    map
}

fn extract_data_references(
    architecture: Architecture,
    instructions: &[Instruction],
    string_ranges: &[StringRange],
    executable: &[(u64, u64)],
) -> Vec<Reference> {
    match architecture {
        Architecture::Arm64 => {
            extract_arm64_data_references(instructions, string_ranges, executable)
        }
        #[cfg(feature = "arch-x64")]
        Architecture::X86_64 => {
            extract_x64_data_references(instructions, string_ranges, executable)
        }
        _ => Vec::new(),
    }
}

fn promote_data_reference_kinds(
    references: &mut [Reference],
    string_ranges: &[StringRange],
    executable: &[(u64, u64)],
) {
    for reference in references {
        if reference.kind != ReferenceKind::Data || reference.to == 0 {
            continue;
        }
        if is_string_address(string_ranges, reference.to) {
            reference.kind = ReferenceKind::StringRef;
        } else if is_executable_address(executable, reference.to) {
            reference.kind = ReferenceKind::IndirectCodePtr;
        } else {
            reference.kind = ReferenceKind::DataRef;
        }
    }
}

fn collect_relocation_references(
    image: &BinaryImage,
    string_ranges: &[StringRange],
    executable: &[(u64, u64)],
) -> Vec<Reference> {
    if image.relocations.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(image.relocations.len());
    for reloc in &image.relocations {
        let Some(target) = reloc.target.filter(|t| *t != 0) else {
            continue;
        };
        let kind = if is_string_address(string_ranges, target) {
            ReferenceKind::StringRef
        } else if is_executable_address(executable, target) {
            ReferenceKind::IndirectCodePtr
        } else {
            ReferenceKind::DataRef
        };
        out.push(Reference {
            from: reloc.address,
            to: target,
            kind,
        });
    }
    out.sort_unstable_by_key(|reference| (reference.from, reference.to, reference.kind as u8));
    out
}

fn attach_relocation_references(
    references: &mut Vec<Reference>,
    instructions: &[Instruction],
    relocation_refs: &[Reference],
) {
    if relocation_refs.is_empty() || instructions.is_empty() {
        return;
    }
    let start = instructions[0].address;
    let end = instructions
        .last()
        .map(|inst| inst.address.saturating_add(inst_len(inst) as u64))
        .unwrap_or(start);
    let lo = relocation_refs.partition_point(|reference| reference.from < start);
    for reference in &relocation_refs[lo..] {
        if reference.from >= end {
            break;
        }
        references.push(*reference);
    }
}

fn split_basic_blocks(
    function_start: u64,
    instructions: Vec<Instruction>,
    references: &[Reference],
) -> Vec<BasicBlock> {
    if instructions.is_empty() {
        return Vec::new();
    }

    let first_addr = instructions[0].address;
    let last_addr = instructions[instructions.len() - 1].address;
    let mut leaders: Vec<u64> = Vec::with_capacity(references.len().min(512) + 1);
    leaders.push(function_start);
    for reference in references {
        let target = reference.to;
        if target < first_addr || target > last_addr {
            continue;
        }
        if instructions
            .binary_search_by_key(&target, |inst| inst.address)
            .is_ok()
        {
            leaders.push(target);
        }
    }
    leaders.sort_unstable();
    leaders.dedup();

    let mut leader_idx = 0usize;
    let mut current_leader = leaders[0];
    let mut next_leader = leaders.get(1).copied();
    let mut blocks = Vec::with_capacity(leaders.len());
    let mut current_block = Vec::new();

    for instruction in instructions {
        while let Some(boundary) = next_leader {
            if instruction.address < boundary {
                break;
            }
            if !current_block.is_empty() {
                blocks.push(finalize_basic_block(current_leader, current_block));
                current_block = Vec::new();
            }
            leader_idx += 1;
            current_leader = boundary;
            next_leader = leaders.get(leader_idx + 1).copied();
        }
        current_block.push(instruction);
    }

    if !current_block.is_empty() {
        blocks.push(finalize_basic_block(current_leader, current_block));
    }
    blocks
}

fn finalize_basic_block(leader: u64, instructions: Vec<Instruction>) -> BasicBlock {
    let start = instructions.first().map(|i| i.address).unwrap_or(leader);
    let end = instructions
        .last()
        .map(|i| i.address + inst_len(i) as u64)
        .unwrap_or(start);
    BasicBlock {
        address: start,
        size: end.saturating_sub(start),
        instructions,
    }
}

fn code_slice(code_regions: &[CodeRegion], start: u64, end: u64) -> Option<(Vec<u8>, u64)> {
    if code_regions.is_empty() {
        return None;
    }
    let mut lo = 0usize;
    let mut hi = code_regions.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        let region = &code_regions[mid];
        if start < region.start {
            hi = mid;
        } else if start >= region.end {
            lo = mid + 1;
        } else {
            let data = region.read_range(start, end)?;
            return Some((data, start));
        }
    }
    None
}

fn decode_arm64_cfg(
    code_regions: &[CodeRegion],
    start: u64,
    max_end: u64,
    executable: &[(u64, u64)],
) -> Vec<Instruction> {
    decode_arm64_cfg_with_references(code_regions, start, max_end, executable).0
}

/// Decode an ARM64 function with CFG traversal and collect references in a
/// single pass, avoiding the double-decode of `decode_arm64_cfg` +
/// `extract_references`.

#[inline]
fn cfg_window_before(
    map: &HashMap<u64, Instruction>,
    lo: u64,
    hi: u64,
    max: usize,
) -> Vec<Instruction> {
    let mut addrs: Vec<u64> = map
        .keys()
        .copied()
        .filter(|&a| a >= lo && a < hi)
        .collect();
    if addrs.is_empty() {
        return Vec::new();
    }
    addrs.sort_unstable();
    let start = addrs.len().saturating_sub(max);
    addrs[start..]
        .iter()
        .filter_map(|a| map.get(a).cloned())
        .collect()
}

fn decode_arm64_cfg_with_references(
    code_regions: &[CodeRegion],
    start: u64,
    max_end: u64,
    executable: &[(u64, u64)],
) -> (Vec<Instruction>, Vec<Reference>) {
    let mut queue = VecDeque::from([start]);
    let estimated_blocks = ((max_end.saturating_sub(start) / 16) as usize).clamp(4, cfg_block_limit());
    let mut visited_blocks = HashSet::with_capacity(estimated_blocks);
    let estimated_insts = ((max_end.saturating_sub(start) / 4) as usize).clamp(16, cfg_inst_limit());
    let mut instruction_map: HashMap<u64, Instruction> = HashMap::with_capacity(estimated_insts);
    let mut all_refs = Vec::with_capacity(estimated_blocks);
    let mut saw_br = false;

    while let Some(block_start) = queue.pop_front() {
        if visited_blocks.len() >= cfg_block_limit()
            || instruction_map.len() >= cfg_inst_limit()
        {
            break;
        }
        if block_start < start || block_start >= max_end {
            continue;
        }
        if !visited_blocks.insert(block_start) {
            continue;
        }
        if !is_executable_address(executable, block_start) {
            continue;
        }
        let Some((bytes, base)) = code_slice(code_regions, block_start, max_end) else {
            continue;
        };
        let (block, refs) = revx_arch_arm64::decode_block_with_references(&bytes, base);
        if block.is_empty() {
            continue;
        }

        let fallthrough = block
            .last()
            .map(|inst| inst.address.saturating_add(inst_len(inst) as u64));
        let mut has_implicit_fallthrough = arm64_block_has_implicit_fallthrough(&block);

        let mut expanded_refs = refs;
        let last_is_br = block.last().is_some_and(|inst| {
            let t = inst.text.as_ref();
            t.starts_with("br ") && !t.starts_with("blr ")
        });
        if last_is_br {
            saw_br = true;
            let mut window: Vec<Instruction> = Vec::with_capacity(64);
            if let Some(first) = block.first() {
                let lo = first.address.saturating_sub(0x80);
                let hi = first.address;
                window.extend(cfg_window_before(&instruction_map, lo, hi, 48));
            }
            window.extend(block.iter().cloned());
            if let Some(table_refs) =
                recover_arm64_pc_rel_jump_table_targets(&window, code_regions, start, max_end)
            {
                for reference in &table_refs {
                    if reference.to >= start && reference.to < max_end {
                        queue.push_back(reference.to);
                    }
                }
                expanded_refs.extend(table_refs);
                has_implicit_fallthrough = false;
            }
        }

        for reference in &expanded_refs {
            match reference.kind {
                ReferenceKind::Call | ReferenceKind::IndirectCall => {}
                ReferenceKind::Jump => {
                    has_implicit_fallthrough = false;
                    if reference.to >= start && reference.to < max_end {
                        queue.push_back(reference.to);
                    }
                }
                ReferenceKind::IndirectJump => {
                    has_implicit_fallthrough = false;
                    if reference.to >= start
                        && reference.to < max_end
                        && is_resolved_code_target(reference.to)
                    {
                        queue.push_back(reference.to);
                    }
                }
                ReferenceKind::BranchTrue
                | ReferenceKind::BranchFalse
                | ReferenceKind::Branch
                | ReferenceKind::Fallthrough => {
                    if reference.to >= start && reference.to < max_end {
                        queue.push_back(reference.to);
                    }
                }
                _ => {}
            }
        }

        for inst in block {
            if instruction_map.len() >= cfg_inst_limit() {
                break;
            }
            instruction_map.entry(inst.address).or_insert(inst);
        }
        all_refs.extend(expanded_refs);

        if has_implicit_fallthrough
            && let Some(next) = fallthrough
            && next >= start
            && next < max_end
        {
            queue.push_back(next);
        }
    }

    let mut final_extra: Vec<Reference> = Vec::new();
    if saw_br {
        let mut sorted_addrs: Vec<u64> = instruction_map.keys().copied().collect();
        sorted_addrs.sort_unstable();
        for (pos, &addr) in sorted_addrs.iter().enumerate() {
            let Some(inst) = instruction_map.get(&addr) else {
                continue;
            };
            let t = inst.text.as_ref();
            if !(t.starts_with("br ") && !t.starts_with("blr ")) {
                continue;
            }
            let from = pos.saturating_sub(48);
            let window: Vec<Instruction> = sorted_addrs[from..=pos]
                .iter()
                .filter_map(|a| instruction_map.get(a).cloned())
                .collect();
            if let Some(table_refs) =
                recover_arm64_pc_rel_jump_table_targets(&window, code_regions, start, max_end)
            {
                for reference in &table_refs {
                    if reference.to >= start
                        && reference.to < max_end
                        && !instruction_map.contains_key(&reference.to)
                    {
                        queue.push_back(reference.to);
                    }
                }
                final_extra.extend(table_refs);
            }
        }
    }
    while let Some(block_start) = queue.pop_front() {
        if visited_blocks.len() >= cfg_block_limit()
            || instruction_map.len() >= cfg_inst_limit()
        {
            break;
        }
        if block_start < start || block_start >= max_end {
            continue;
        }
        if !visited_blocks.insert(block_start) {
            continue;
        }
        if !is_executable_address(executable, block_start) {
            continue;
        }
        let Some((bytes, base)) = code_slice(code_regions, block_start, max_end) else {
            continue;
        };
        let (block, refs) = revx_arch_arm64::decode_block_with_references(&bytes, base);
        if block.is_empty() {
            continue;
        }
        let fallthrough = block
            .last()
            .map(|inst| inst.address.saturating_add(inst_len(inst) as u64));
        let mut has_implicit_fallthrough = arm64_block_has_implicit_fallthrough(&block);
        let mut expanded_refs = refs;
        let last_is_br = block.last().is_some_and(|inst| {
            let t = inst.text.as_ref();
            t.starts_with("br ") && !t.starts_with("blr ")
        });
        if last_is_br {
            let mut window: Vec<Instruction> = Vec::with_capacity(64);
            if let Some(first) = block.first() {
                let lo = first.address.saturating_sub(0x80);
                let hi = first.address;
                window.extend(cfg_window_before(&instruction_map, lo, hi, 48));
            }
            window.extend(block.iter().cloned());
            if let Some(table_refs) =
                recover_arm64_pc_rel_jump_table_targets(&window, code_regions, start, max_end)
            {
                for reference in &table_refs {
                    if reference.to >= start && reference.to < max_end {
                        queue.push_back(reference.to);
                    }
                }
                expanded_refs.extend(table_refs);
                has_implicit_fallthrough = false;
            }
        }
        for reference in &expanded_refs {
            match reference.kind {
                ReferenceKind::Jump => {
                    has_implicit_fallthrough = false;
                    if reference.to >= start && reference.to < max_end {
                        queue.push_back(reference.to);
                    }
                }
                ReferenceKind::IndirectJump => {
                    has_implicit_fallthrough = false;
                    if reference.to >= start
                        && reference.to < max_end
                        && is_resolved_code_target(reference.to)
                    {
                        queue.push_back(reference.to);
                    }
                }
                ReferenceKind::BranchTrue
                | ReferenceKind::BranchFalse
                | ReferenceKind::Branch
                | ReferenceKind::Fallthrough => {
                    if reference.to >= start && reference.to < max_end {
                        queue.push_back(reference.to);
                    }
                }
                _ => {}
            }
        }
        for inst in block {
            if instruction_map.len() >= cfg_inst_limit() {
                break;
            }
            instruction_map.entry(inst.address).or_insert(inst);
        }
        all_refs.extend(expanded_refs);
        if has_implicit_fallthrough
            && let Some(next) = fallthrough
            && next >= start
            && next < max_end
        {
            queue.push_back(next);
        }
    }
    all_refs.extend(final_extra);

    let mut instructions = instruction_map.into_values().collect::<Vec<_>>();
    instructions.sort_unstable_by_key(|inst| inst.address);
    (instructions, all_refs)
}

fn recover_arm64_pc_rel_jump_table_targets(
    block: &[Instruction],
    code_regions: &[CodeRegion],
    fn_start: u64,
    fn_end: u64,
) -> Option<Vec<Reference>> {
    if block.len() < 4 {
        return None;
    }
    let br = block.last()?;
    let br_text = br.text.as_ref();
    if !br_text.starts_with("br ") || br_text.starts_with("blr ") {
        return None;
    }
    let index_reg = br_text.split_whitespace().nth(1)?.trim().to_ascii_lowercase();

    // Patterns:
    // A) PC-relative (adr + add):
    //   adrp/add table_base
    //   ldrsw offset, [table_base, idx, lsl #2]
    //   adr anchor
    //   add target, anchor, offset
    //   br target
    // B) Base-relative (common on Android/clang):
    //   adrp/add table_base
    //   ldrsw offset, [table_base, idx, lsl #2]
    //   add target, offset, table_base
    //   br target
    let mut table_base: Option<u64> = None;
    let mut table_base_reg: Option<String> = None;
    let mut offset_reg: Option<String> = None;
    let mut anchor_pc: Option<u64> = None;
    let mut base_relative = false;
    let mut entry_size = 4i64;

    for inst in block.iter().rev().skip(1).take(48) {
        let text = inst.text.as_ref();
        let addr = inst.address;
        if text.starts_with("add ") {
            let parts: Vec<&str> = text[4..].split(',').map(|s| s.trim()).collect();
            if parts.len() == 3 {
                let dst = parts[0].to_ascii_lowercase();
                let a = parts[1].to_ascii_lowercase();
                let b = parts[2].to_ascii_lowercase();
                if dst == index_reg {
                    if b.starts_with('#') {
                        if let Some(page) = find_adrp_page(block, &a) {
                            if let Some(imm) = parse_hash_imm(&b) {
                                table_base = Some(page.wrapping_add(imm as u64));
                                table_base_reg = Some(dst.clone());
                            }
                        }
                    } else if looks_like_reg_name_simple(&a) && looks_like_reg_name_simple(&b) {
                        // add target, anchor_or_off, off_or_base
                        if let Some(pc) = parse_adr_like_anchor(block, &a)
                            .or_else(|| find_adr_def(block, &a))
                        {
                            anchor_pc = Some(pc);
                            offset_reg = Some(b);
                        } else if let Some(pc) = parse_adr_like_anchor(block, &b)
                            .or_else(|| find_adr_def(block, &b))
                        {
                            anchor_pc = Some(pc);
                            offset_reg = Some(a);
                        } else {
                            base_relative = true;
                            offset_reg = Some(a.clone());
                            table_base_reg = Some(b.clone());
                            if let Some(page) = find_adrp_page(block, &b) {
                                if let Some(imm) = find_add_imm_to(block, &b) {
                                    table_base = Some(page.wrapping_add(imm as u64));
                                } else {
                                    table_base = Some(page);
                                }
                            }
                            if table_base.is_none() {
                                if let Some(page) = find_adrp_page(block, &a) {
                                    offset_reg = Some(b.clone());
                                    table_base_reg = Some(a.clone());
                                    if let Some(imm) = find_add_imm_to(block, &a) {
                                        table_base = Some(page.wrapping_add(imm as u64));
                                    } else {
                                        table_base = Some(page);
                                    }
                                }
                            }
                        }
                    }
                } else if b.starts_with('#') {
                    if let Some(page) = find_adrp_page(block, &a) {
                        if let Some(imm) = parse_hash_imm(&b) {
                            if table_base.is_none() || table_base_reg.as_deref() == Some(&dst) {
                                table_base = Some(page.wrapping_add(imm as u64));
                                table_base_reg = Some(dst);
                            }
                        }
                    }
                }
            }
            continue;
        }
        if text.starts_with("adr ") {
            let parts: Vec<&str> = text[4..].split(',').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                let dst = parts[0].to_ascii_lowercase();
                if let Some(target) = parse_branch_or_adr_target(addr, parts[1]) {
                    if dst != index_reg {
                        anchor_pc = Some(target);
                    }
                }
            }
            continue;
        }
        if text.starts_with("adrp ") {
            let parts: Vec<&str> = text[5..].split(',').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                if let Some(page) = parse_branch_or_adr_target(addr, parts[1]) {
                    let page = page & !0xfffu64;
                    if table_base.is_none() {
                        table_base = Some(page);
                        table_base_reg = Some(parts[0].to_ascii_lowercase());
                    }
                }
            }
            continue;
        }
        if text.starts_with("ldrsw ") || text.starts_with("ldr ") {
            if let Some(open) = text.find('[') {
                let close = text.find(']')?;
                let inner = &text[open + 1..close];
                let mem_parts: Vec<&str> = inner.split(',').map(|s| s.trim()).collect();
                if mem_parts.len() >= 2 {
                    let base_reg = mem_parts[0].to_ascii_lowercase();
                    if text.starts_with("ldrsw ") {
                        entry_size = 4;
                    }
                    if let Some(page) = find_adrp_page(block, &base_reg) {
                        if let Some(imm) = find_add_imm_to(block, &base_reg) {
                            table_base = Some(page.wrapping_add(imm as u64));
                        } else {
                            table_base = Some(page);
                        }
                        table_base_reg = Some(base_reg);
                    } else if table_base_reg.as_deref() == Some(base_reg.as_str()) {
                        // keep existing table_base
                    }
                    let dst = text
                        .split_whitespace()
                        .nth(1)
                        .map(|s| s.trim().trim_end_matches(',').to_ascii_lowercase());
                    if let Some(dst) = dst {
                        offset_reg = Some(dst);
                    }
                }
            }
            continue;
        }
    }

    let table_base = table_base?;
    let anchor = if base_relative {
        table_base
    } else {
        anchor_pc.unwrap_or(if base_relative { table_base } else { br.address })
    };
    // If we never saw adr but add used table base as one operand, treat as base-relative.
    let anchor = if anchor_pc.is_none() && base_relative {
        table_base
    } else if anchor_pc.is_none() {
        // Heuristic: if no adr anchor, Android base-relative tables are common.
        table_base
    } else {
        anchor
    };

    let max_entries = if let Some(n) = infer_jump_table_bound(block) {
        n.min(256)
    } else {
        128
    };

    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut valid_entries = 0usize;
    for i in 0..max_entries {
        let entry_addr = table_base.wrapping_add((i as u64).wrapping_mul(entry_size as u64));
        let Some(rel) = read_i32_at(code_regions, entry_addr) else {
            break;
        };
        let target = anchor.wrapping_add(rel as i64 as u64);
        if target < fn_start || target >= fn_end || target % 4 != 0 {
            if i > 8 && valid_entries == 0 {
                break;
            }
            // stop if we had some entries and then hit a run of invalid
            if valid_entries >= 2 && i > valid_entries + 4 {
                break;
            }
            continue;
        }
        valid_entries += 1;
        if seen.insert(target) {
            out.push(Reference {
                from: br.address,
                to: target,
                kind: ReferenceKind::Jump,
            });
        }
        let bias = infer_jump_table_index_bias(block).unwrap_or(0);
        let ch = (bias as i64).wrapping_add(i as i64);
        if (0x09..0x7f).contains(&ch) {
            out.push(Reference {
                from: target,
                to: case_char_tag(ch as u64),
                kind: ReferenceKind::DataRef,
            });
        }
    }
    if seen.len() < 2 {
        return None;
    }
    let _ = offset_reg;
    Some(out)
}

pub(crate) const CASE_CHAR_TAG: u64 = 0xCA5E_0000;

pub(crate) fn case_char_tag(ch: u64) -> u64 {
    CASE_CHAR_TAG | (ch & 0xff)
}

pub(crate) fn case_char_untag(value: u64) -> Option<u64> {
    if value & 0xFFFF_0000 == CASE_CHAR_TAG {
        Some(value & 0xff)
    } else {
        None
    }
}

fn infer_jump_table_index_bias(block: &[Instruction]) -> Option<i64> {
    // Prefer `sub wn, wm, #imm` / `sub xn, xm, #imm` just above the table dispatch.
    for inst in block.iter().rev().take(24) {
        let text = inst.text.as_ref();
        if !text.starts_with("sub ") {
            continue;
        }
        let parts: Vec<&str> = text[4..].split(',').map(|s| s.trim()).collect();
        if parts.len() == 3 {
            if let Some(imm) = parse_hash_imm(parts[2]) {
                if (0x20..0x80).contains(&imm) {
                    return Some(imm);
                }
            }
        }
    }
    None
}

fn parse_hash_imm(text: &str) -> Option<i64> {
    let t = text.trim().trim_start_matches('#').trim();
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return i64::from_str_radix(h, 16).ok();
    }
    t.parse().ok()
}

fn looks_like_reg_name_simple(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    if n == "sp" || n == "fp" || n == "lr" || n == "xzr" || n == "wzr" {
        return true;
    }
    let rest = n.strip_prefix('x').or_else(|| n.strip_prefix('w'));
    rest.is_some_and(|r| !r.is_empty() && r.bytes().all(|b| b.is_ascii_digit()))
}

fn parse_branch_or_adr_target(pc: u64, text: &str) -> Option<u64> {
    let t = text.trim();
    if let Some(off) = t.strip_prefix("$+") {
        let imm = parse_hash_imm(off)?;
        return Some(pc.wrapping_add(imm as u64));
    }
    if let Some(off) = t.strip_prefix("$-") {
        let imm = parse_hash_imm(off)?;
        return Some(pc.wrapping_sub(imm as u64));
    }
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return u64::from_str_radix(h, 16).ok();
    }
    // bare decimal?
    if let Ok(v) = t.parse::<u64>() {
        return Some(v);
    }
    None
}

fn find_adrp_page(block: &[Instruction], reg: &str) -> Option<u64> {
    let reg = reg.to_ascii_lowercase();
    for inst in block.iter().rev() {
        let text = inst.text.as_ref();
        if text.starts_with("adrp ") {
            let parts: Vec<&str> = text[5..].split(',').map(|s| s.trim()).collect();
            if parts.len() == 2 && parts[0].eq_ignore_ascii_case(&reg) {
                let page = parse_branch_or_adr_target(inst.address, parts[1])?;
                return Some(page & !0xfffu64);
            }
        }
    }
    None
}

fn find_add_imm_to(block: &[Instruction], reg: &str) -> Option<i64> {
    let reg = reg.to_ascii_lowercase();
    for inst in block.iter().rev() {
        let text = inst.text.as_ref();
        if text.starts_with("add ") {
            let parts: Vec<&str> = text[4..].split(',').map(|s| s.trim()).collect();
            if parts.len() == 3
                && parts[0].eq_ignore_ascii_case(&reg)
                && parts[1].eq_ignore_ascii_case(&reg)
            {
                return parse_hash_imm(parts[2]);
            }
        }
    }
    None
}

fn find_adr_def(block: &[Instruction], reg: &str) -> Option<u64> {
    let reg = reg.to_ascii_lowercase();
    for inst in block.iter().rev() {
        let text = inst.text.as_ref();
        if text.starts_with("adr ") {
            let parts: Vec<&str> = text[4..].split(',').map(|s| s.trim()).collect();
            if parts.len() == 2 && parts[0].eq_ignore_ascii_case(&reg) {
                return parse_branch_or_adr_target(inst.address, parts[1]);
            }
        }
    }
    None
}

fn parse_adr_like_anchor(block: &[Instruction], reg: &str) -> Option<u64> {
    find_adr_def(block, reg)
}

fn infer_jump_table_bound(block: &[Instruction]) -> Option<usize> {
    // Look for cmp reg, #N / csel with ls / b.hi pattern; table covers 0..=N.
    for inst in block.iter().rev().take(16) {
        let text = inst.text.as_ref();
        if text.starts_with("cmp ") {
            let parts: Vec<&str> = text[4..].split(',').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                if let Some(imm) = parse_hash_imm(parts[1]) {
                    if (1..512).contains(&imm) {
                        return Some((imm as usize) + 1);
                    }
                }
            }
        }
    }
    None
}

fn read_i32_at(code_regions: &[CodeRegion], addr: u64) -> Option<i32> {
    for region in code_regions {
        if addr >= region.start && addr + 4 <= region.end {
            let data = region.read_range(addr, addr + 4)?;
            if data.len() < 4 {
                return None;
            }
            return Some(i32::from_le_bytes([data[0], data[1], data[2], data[3]]));
        }
    }
    None
}

#[cfg(feature = "arch-x64")]
fn decode_x64_cfg_with_references(
    code_regions: &[CodeRegion],
    start: u64,
    max_end: u64,
    executable: &[(u64, u64)],
) -> (Vec<Instruction>, Vec<Reference>) {
    let mut queue = VecDeque::from([start]);
    let estimated_blocks = ((max_end.saturating_sub(start) / 12) as usize).clamp(4, cfg_block_limit());
    let mut visited_blocks = HashSet::with_capacity(estimated_blocks);
    let mut instruction_map: BTreeMap<u64, Instruction> = BTreeMap::new();
    let mut all_refs = Vec::with_capacity(estimated_blocks);

    while let Some(block_start) = queue.pop_front() {
        if visited_blocks.len() >= cfg_block_limit()
            || instruction_map.len() >= cfg_inst_limit()
        {
            break;
        }
        if block_start < start || block_start >= max_end {
            continue;
        }
        if !visited_blocks.insert(block_start) {
            continue;
        }
        if !is_executable_address(executable, block_start) {
            continue;
        }
        let Some((bytes, base)) = code_slice(code_regions, block_start, max_end) else {
            continue;
        };
        let (block, refs) = revx_arch_x64::decode_block_with_references(&bytes, base);
        if block.is_empty() {
            continue;
        }

        let fallthrough = block
            .last()
            .map(|inst| inst.address.saturating_add(inst_len(inst) as u64));
        let mut has_implicit_fallthrough = x64_block_has_implicit_fallthrough(&block);

        for reference in &refs {
            match reference.kind {
                ReferenceKind::Jump | ReferenceKind::IndirectJump => {
                    has_implicit_fallthrough = false;
                    if reference.to >= start && reference.to < max_end && reference.to != 0 {
                        queue.push_back(reference.to);
                    }
                }
                ReferenceKind::BranchTrue
                | ReferenceKind::BranchFalse
                | ReferenceKind::Branch
                | ReferenceKind::Fallthrough => {
                    if reference.to >= start && reference.to < max_end && reference.to != 0 {
                        queue.push_back(reference.to);
                    }
                }
                ReferenceKind::Call | ReferenceKind::IndirectCall => {}
                _ => {}
            }
        }

        for inst in block {
            if instruction_map.len() >= cfg_inst_limit() {
                break;
            }
            instruction_map.entry(inst.address).or_insert(inst);
        }
        all_refs.extend(refs);

        if has_implicit_fallthrough
            && let Some(next) = fallthrough
            && next >= start
            && next < max_end
        {
            queue.push_back(next);
        }
    }

    let instructions = instruction_map.into_values().collect::<Vec<_>>();
    (instructions, all_refs)
}

#[cfg(feature = "arch-x64")]
fn x64_block_has_implicit_fallthrough(block: &[Instruction]) -> bool {
    let Some(last) = block.last() else {
        return false;
    };
    let text = last.text.as_ref();
    !(text.starts_with("ret")
        || text.starts_with("jmp ")
        || text == "int3"
        || text.starts_with("ud2")
        || text.starts_with("hlt"))
}

fn arm64_block_has_implicit_fallthrough(block: &[Instruction]) -> bool {
    let Some(last) = block.last() else {
        return false;
    };
    let text = last.text.as_ref();
    !(text == "ret"
        || text.starts_with("b ")
        || (text.starts_with("br ") && !text.starts_with("blr "))
        || text.starts_with("eret")
        || text.starts_with("drps"))
}

fn recover_stack_summary_fast(
    architecture: Architecture,
    format: BinaryFormat,
    instructions: &[Instruction],
    debug_hint: Option<&DebugFunctionHint>,
) -> StackSummary {
    let mut frame_size = None;
    for inst in instructions.iter().take(24) {
        let text = inst.text.as_ref();
        if let Some(size) = parse_stack_sub(text) {
            frame_size = Some(frame_size.unwrap_or(0).max(size));
        }
        if architecture == Architecture::Arm64 {
            if let Some(size) = parse_arm64_stack_setup(text) {
                frame_size = Some(frame_size.unwrap_or(0).max(size));
            }
        }
    }
    StackSummary {
        frame_size,
        calling_convention: debug_hint
            .and_then(|hint| hint.calling_convention.clone())
            .or_else(|| Some(default_calling_convention_for(architecture, Some(format)))),
        return_type: debug_hint.and_then(|hint| hint.return_type.clone()),
        stack_arg_bytes: Some(0),
        evidence_ids: vec![format!(
            "stack:{:x}",
            instructions.first().map(|i| i.address).unwrap_or_default()
        )],
    }
}

fn polish_argument_names(function_name: &str, arguments: &mut [Variable]) {
    let bare = function_name.trim_start_matches('_');
    if !bare.eq_ignore_ascii_case("main") {
        return;
    }
    if arguments.is_empty() {
        return;
    }
    if let Some(arg0) = arguments.get_mut(0) {
        if arg0.name.starts_with("arg_") {
            arg0.name = "argc".to_string();
            arg0.type_name = Some("int".to_string());
            arg0.confidence = arg0.confidence.max(0.7);
        }
    }
    if let Some(arg1) = arguments.get_mut(1) {
        if arg1.name.starts_with("arg_") {
            arg1.name = "argv".to_string();
            arg1.type_name = Some("char **".to_string());
            arg1.confidence = arg1.confidence.max(0.7);
        }
    }
}

fn recover_variables_fast(
    image: &BinaryImage,
    function_address: u64,
    debug_hint: Option<&DebugFunctionHint>,
) -> Vec<Variable> {
    if let Some(hint) = debug_hint {
        if !hint.arguments.is_empty() {
            return hint.arguments.clone();
        }
    }
    let location = match image.architecture {
        Architecture::Arm64 => "x0",
        Architecture::X86_64 => "rdi",
        Architecture::Unknown => "arg0",
    };
    vec![Variable {
        name: "arg_0".to_string(),
        role: VariableRole::Argument,
        storage: VariableStorage::Register,
        type_name: None,
        confidence: 0.2,
        location: location.to_string(),
        evidence_ids: vec![format!("vars:{function_address:x}:arg:fallback")],
    }]
}

fn recover_stack_summary(
    architecture: Architecture,
    instructions: &[Instruction],
    debug_hint: Option<&DebugFunctionHint>,
    call_target_overrides: &HashMap<u64, u64>,
    profile: AnalysisProfile,
) -> StackSummary {
    recover_stack_summary_for(
        architecture,
        None,
        instructions,
        debug_hint,
        call_target_overrides,
        profile,
    )
}

fn recover_stack_summary_for(
    architecture: Architecture,
    format: Option<BinaryFormat>,
    instructions: &[Instruction],
    debug_hint: Option<&DebugFunctionHint>,
    call_target_overrides: &HashMap<u64, u64>,
    profile: AnalysisProfile,
) -> StackSummary {
    let mut frame_size = None;
    let mut stack_arg_bytes = Some(0u64);
    let calling_convention = debug_hint
        .and_then(|hint| hint.calling_convention.clone())
        .or_else(|| Some(default_calling_convention_for(architecture, format)));
    let return_type = debug_hint
        .and_then(|hint| hint.return_type.clone())
        .or_else(|| infer_return_type(instructions, call_target_overrides));

    let scan_n = if instructions.len() > 512 {
        96
    } else if instructions.len() > 128 {
        instructions.len().min(256)
    } else {
        instructions.len()
    };
    let mut max_home_or_arg = 0i64;
    for inst in instructions.iter().take(scan_n) {
        let text = inst.text.as_ref();
        if let Some(size) = parse_stack_sub(text) {
            frame_size = Some(frame_size.unwrap_or(0).max(size));
        }
        if let Some(size) = parse_arm64_stack_setup(text) {
            frame_size = Some(frame_size.unwrap_or(0).max(size));
        }
        if architecture == Architecture::X86_64 {
            if let Some(off) = parse_x64_stack_arg_offset(text) {
                max_home_or_arg = max_home_or_arg.max(off);
            }
            if text.contains("push ") {
                frame_size = Some(frame_size.unwrap_or(0).saturating_add(8));
            }
        }
    }
    if max_home_or_arg > 0 {
        let bytes = ((max_home_or_arg + 7) / 8) * 8;
        stack_arg_bytes = Some(stack_arg_bytes.unwrap_or(0).max(bytes as u64));
    }

    if architecture == Architecture::Arm64 && instructions.len() <= LIGHT_VAR_RECOVERY_INSTS {
        stack_arg_bytes = infer_arm64_stack_arg_bytes(instructions, frame_size);
    }

    let mut evidence_ids = vec![format!(
        "stack:{:x}",
        instructions.first().map(|i| i.address).unwrap_or_default()
    )];
    if profile == AnalysisProfile::Full {
        evidence_ids.push(format!(
            "stack:{}:full",
            instructions.first().map(|i| i.address).unwrap_or_default()
        ));
        if frame_size.is_none() {
            frame_size = Some(0);
        }
    }

    StackSummary {
        frame_size,
        calling_convention,
        return_type,
        stack_arg_bytes,
        evidence_ids,
    }
}

fn parse_x64_stack_arg_offset(text: &str) -> Option<i64> {
    for base in ["[rbp+", "[rsp+", "[rbp +", "[rsp +"] {
        let Some(index) = text.find(base) else {
            continue;
        };
        let suffix = text[index + base.len()..].trim_start();
        let raw: String = suffix
            .chars()
            .take_while(|ch| ch.is_ascii_hexdigit() || *ch == 'x')
            .collect();
        if raw.is_empty() {
            continue;
        }
        let value = if let Some(hex) = raw.strip_prefix("0x").or_else(|| {
            if raw.chars().any(|c| matches!(c, 'a'..='f' | 'A'..='F')) {
                Some(raw.as_str())
            } else {
                None
            }
        }) {
            i64::from_str_radix(hex.trim_start_matches("0x"), 16).ok()?
        } else {
            raw.parse::<i64>().ok()?
        };
        if base.contains("rbp") {
            if value >= 0x10 {
                return Some(value);
            }
        } else if value >= 0x20 {
            return Some(value);
        }
    }
    None
}

fn recover_variables(
    image: &BinaryImage,
    function_address: u64,
    instructions: &[Instruction],
    debug_hint: Option<&DebugFunctionHint>,
    profile: AnalysisProfile,
) -> (Vec<Variable>, Vec<Variable>) {
    let mut arguments = debug_hint
        .map(|hint| hint.arguments.clone())
        .unwrap_or_default();
    let mut locals = debug_hint
        .map(|hint| hint.locals.clone())
        .unwrap_or_default();
    let mut seen_arg_names = arguments
        .iter()
        .map(|arg| arg.name.clone())
        .collect::<BTreeSet<_>>();
    let mut seen_local_names = locals
        .iter()
        .map(|local| local.name.clone())
        .collect::<BTreeSet<_>>();

    if image.architecture == Architecture::Arm64 {
        let light = instructions.len() > LIGHT_VAR_RECOVERY_INSTS;
        let arg_registers = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"];
        let input_mask = arm64_argument_input_mask(instructions);
        for (index, reg) in arg_registers.iter().enumerate() {
            if input_mask & (1u8 << index) == 0 {
                continue;
            }
            let wreg = match index {
                0 => "w0",
                1 => "w1",
                2 => "w2",
                3 => "w3",
                4 => "w4",
                5 => "w5",
                6 => "w6",
                _ => "w7",
            };
            let type_name = if light {
                Some("void *".to_string())
            } else {
                infer_arm64_argument_type(instructions, reg, wreg)
            };
            let name = format!("arg_{index}");
            if seen_arg_names.insert(name.clone()) {
                arguments.push(Variable {
                    name,
                    role: VariableRole::Argument,
                    storage: VariableStorage::Register,
                    type_name,
                    confidence: if profile == AnalysisProfile::Full {
                        0.6
                    } else {
                        0.45
                    },
                    location: (*reg).to_string(),
                    evidence_ids: vec![format!("vars:{function_address:x}:arg:{index}")],
                });
            }
        }

        let mut object_local_index_by_kind = BTreeMap::<String, usize>::new();
        let recovered_locals = if light {
            Vec::new()
        } else {
            recover_arm64_locals(instructions)
        };
        for (local_index, local) in recovered_locals.into_iter().enumerate() {
            let name = if matches!(
                local.type_name.as_deref(),
                Some("stack_array_t")
                    | Some("stack_buffer_t")
                    | Some("stack_workspace_t")
                    | Some("stack_span_t")
            ) {
                let kind = local
                    .type_name
                    .as_deref()
                    .unwrap_or("stack_object_t")
                    .trim_end_matches("_t");
                let current = *object_local_index_by_kind
                    .entry(kind.to_string())
                    .and_modify(|index| *index += 1)
                    .or_insert(0);
                format!("{kind}_{current}")
            } else {
                format!("local_{local_index}")
            };
            if seen_local_names.insert(name.clone()) {
                locals.push(Variable {
                    name,
                    role: VariableRole::Local,
                    storage: VariableStorage::Stack,
                    type_name: local.type_name,
                    confidence: if profile == AnalysisProfile::Full {
                        0.5
                    } else {
                        0.35
                    },
                    location: format_stack_location(local.start_offset, local.end_offset),
                    evidence_ids: vec![format!(
                        "vars:{function_address:x}:local:{:x}",
                        local.start_offset
                    )],
                });
            }
        }

        if arguments.is_empty() {
            arguments.push(Variable {
                name: "arg_0".to_string(),
                role: VariableRole::Argument,
                storage: VariableStorage::Register,
                type_name: None,
                confidence: 0.2,
                location: "x0".to_string(),
                evidence_ids: vec![format!("vars:{function_address:x}:arg:fallback")],
            });
        }
        return (arguments, locals);
    }

    #[cfg(not(feature = "arch-x64"))]
    {
        let _ = image;
        let _ = instructions;
        let _ = profile;
        let _ = function_address;
        let _ = seen_arg_names;
        let _ = seen_local_names;
        return (arguments, locals);
    }
    #[cfg(feature = "arch-x64")]
    {
    if image.architecture != Architecture::X86_64 {
        return (arguments, locals);
    }

    let win64 = matches!(image.format, BinaryFormat::Pe);
    let callee_reg_args: &[&str] = if win64 {
        &["rcx", "rdx", "r8", "r9"]
    } else {
        &["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
    };
    let input_mask = x64_argument_input_mask(instructions, callee_reg_args);

    for (index, reg) in callee_reg_args.iter().enumerate() {
        if input_mask & (1u8 << index) == 0 {
            continue;
        }
        let name = format!("arg_{index}");
        if seen_arg_names.insert(name.clone()) {
            arguments.push(Variable {
                name,
                role: VariableRole::Argument,
                storage: VariableStorage::Register,
                type_name: infer_type_from_usage(image, instructions, reg, true),
                confidence: if profile == AnalysisProfile::Full {
                    0.8
                } else {
                    0.65
                },
                location: (*reg).to_string(),
                evidence_ids: vec![format!("vars:{function_address:x}:arg:{index}")],
            });
        }
    }

    for (stack_index, offset) in collect_x64_stack_arguments(instructions, win64)
        .into_iter()
        .enumerate()
    {
        let index = callee_reg_args.len() + stack_index;
        let name = format!("arg_{index}");
        if seen_arg_names.insert(name.clone()) {
            arguments.push(Variable {
                name,
                role: VariableRole::Argument,
                storage: VariableStorage::Stack,
                type_name: infer_type_from_offset(image, instructions, offset),
                confidence: if profile == AnalysisProfile::Full {
                    0.7
                } else {
                    0.5
                },
                location: format!("stack_arg[{offset:+#x}]"),
                evidence_ids: vec![format!("vars:{function_address:x}:stack_arg:{offset}")],
            });
        }
    }

    let stack_offsets = collect_stack_offsets(instructions);
    let arg_offsets: BTreeSet<i64> = collect_x64_stack_arguments(instructions, win64)
        .into_iter()
        .collect();
    for (local_index, offset) in stack_offsets.into_iter().enumerate() {
        if arg_offsets.contains(&offset) {
            continue;
        }
        if win64 && (0x8..0x30).contains(&offset) {
            continue;
        }
        let name = format!("local_{local_index}");
        if seen_local_names.insert(name.clone()) {
            locals.push(Variable {
                name,
                role: VariableRole::Local,
                storage: VariableStorage::Stack,
                type_name: infer_type_from_offset(image, instructions, offset)
                    .or_else(|| infer_x64_stack_slot_type(instructions, offset)),
                confidence: if profile == AnalysisProfile::Full {
                    0.75
                } else {
                    0.5
                },
                location: format!("stack[{offset:+#x}]"),
                evidence_ids: vec![format!("vars:{function_address:x}:local:{offset}")],
            });
        }
    }

    if arguments.is_empty() {
        let location = if win64 { "rcx" } else { "rdi" };
        arguments.push(Variable {
            name: "arg_0".to_string(),
            role: VariableRole::Argument,
            storage: VariableStorage::Register,
            type_name: None,
            confidence: 0.25,
            location: location.to_string(),
            evidence_ids: vec![format!("vars:{function_address:x}:arg:fallback")],
        });
    }

    polish_argument_names(
        image
            .symbols
            .iter()
            .find(|s| s.address == Some(function_address))
            .map(|s| s.name.as_str())
            .unwrap_or(""),
        &mut arguments,
    );

    (arguments, locals)
    }
    #[cfg(not(feature = "arch-x64"))]
    {
        (arguments, locals)
    }
}

#[cfg(feature = "arch-x64")]
fn x64_argument_input_mask(instructions: &[Instruction], regs: &[&str]) -> u8 {
    let mut used = 0u8;
    let mut written = 0u8;
    for inst in instructions.iter().take(96) {
        let text = inst.text.as_ref();
        let opcode = text.split_whitespace().next().unwrap_or_default();
        if opcode.is_empty() {
            continue;
        }
        if matches!(opcode, "call" | "jmp" | "ret" | "retn") {
            break;
        }
        for (index, reg) in regs.iter().enumerate() {
            let bit = 1u8 << index;
            if written & bit != 0 {
                continue;
            }
            let usage = x64_register_usage(text, reg);
            match usage {
                RegisterUsage::Read | RegisterUsage::ReadWrite => used |= bit,
                RegisterUsage::Write => written |= bit,
                RegisterUsage::None => {}
            }
        }
        if used == ((1u8 << regs.len()) - 1) {
            break;
        }
    }
    used
}

#[cfg(feature = "arch-x64")]
fn x64_register_usage(text: &str, reg: &str) -> RegisterUsage {
    let reg = reg.to_ascii_lowercase();
    let aliases = x64_register_aliases(&reg);
    let lower = text.to_ascii_lowercase();
    if !aliases.iter().any(|alias| instruction_mentions_token(&lower, alias)) {
        return RegisterUsage::None;
    }
    let mut parts = lower.splitn(2, char::is_whitespace);
    let opcode = parts.next().unwrap_or_default();
    let operands = parts
        .next()
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|op| !op.is_empty())
        .collect::<Vec<_>>();
    if operands.is_empty() {
        return RegisterUsage::None;
    }
    let mut read = false;
    let mut write = false;
    for (index, operand) in operands.iter().enumerate() {
        if !aliases.iter().any(|alias| instruction_mentions_token(operand, alias)) {
            continue;
        }
        let is_dest = index == 0
            && matches!(
                opcode,
                "mov"
                    | "movzx"
                    | "movsx"
                    | "movsxd"
                    | "lea"
                    | "xor"
                    | "or"
                    | "and"
                    | "add"
                    | "sub"
                    | "imul"
                    | "pop"
                    | "not"
                    | "neg"
                    | "inc"
                    | "dec"
                    | "shl"
                    | "shr"
                    | "sar"
                    | "rol"
                    | "ror"
            );
        if is_dest {
            write = true;
            if matches!(
                opcode,
                "xor" | "or" | "and" | "add" | "sub" | "imul" | "shl" | "shr" | "sar" | "rol" | "ror"
            ) {
                read = true;
            }
            if opcode == "xor" && operands.len() >= 2 && operands[0] == operands[1] {
                read = false;
            }
        } else {
            read = true;
        }
    }
    if opcode == "push" || opcode == "cmp" || opcode == "test" {
        read = true;
        write = false;
    }
    if opcode == "pop" {
        write = true;
        read = false;
    }
    match (read, write) {
        (false, false) => RegisterUsage::None,
        (true, false) => RegisterUsage::Read,
        (false, true) => RegisterUsage::Write,
        (true, true) => RegisterUsage::ReadWrite,
    }
}

#[cfg(feature = "arch-x64")]
fn x64_register_aliases(reg: &str) -> Vec<&'static str> {
    match reg {
        "rdi" => vec!["rdi", "edi", "di", "dil"],
        "rsi" => vec!["rsi", "esi", "si", "sil"],
        "rdx" => vec!["rdx", "edx", "dx", "dl", "dh"],
        "rcx" => vec!["rcx", "ecx", "cx", "cl", "ch"],
        "r8" => vec!["r8", "r8d", "r8w", "r8b"],
        "r9" => vec!["r9", "r9d", "r9w", "r9b"],
        "rax" => vec!["rax", "eax", "ax", "al", "ah"],
        _ => vec![],
    }
}

#[cfg(feature = "arch-x64")]
fn collect_x64_stack_arguments(instructions: &[Instruction], win64: bool) -> Vec<i64> {
    let mut offsets = BTreeSet::new();
    for inst in instructions.iter().take(128) {
        let text = inst.text.as_ref();
        if let Some(off) = parse_x64_stack_arg_offset(text) {
            if win64 {
                if off >= 0x28 {
                    offsets.insert(off);
                }
            } else if off >= 0x10 {
                offsets.insert(off);
            }
        }
    }
    offsets.into_iter().collect()
}

#[cfg(feature = "arch-x64")]
fn infer_x64_stack_slot_type(instructions: &[Instruction], offset: i64) -> Option<String> {
    let patterns = [
        format!("[rbp{offset:+#x}]"),
        format!("[rbp+{offset:#x}]"),
        format!("[rbp-{offset:#x}]"),
        format!("[rsp+{offset:#x}]"),
        format!("[rsp{offset:+#x}]"),
    ];
    for inst in instructions {
        let text = inst.text.as_ref().to_ascii_lowercase();
        if !patterns.iter().any(|p| text.contains(&p.to_ascii_lowercase())) {
            if offset < 0 {
                let abs = (-offset) as u64;
                if !text.contains(&format!("[rbp-{abs:#x}]")) && !text.contains(&format!("[rbp - {abs:#x}]")) {
                    continue;
                }
            } else {
                continue;
            }
        }
        let opcode = text.split_whitespace().next().unwrap_or_default();
        if opcode.starts_with("movss") || text.contains("dword ptr") && text.contains("xmm") {
            return Some("float".to_string());
        }
        if opcode.starts_with("movsd") || text.contains("qword ptr") && text.contains("xmm") {
            return Some("double".to_string());
        }
        if text.contains("byte ptr") {
            return Some("uint8_t".to_string());
        }
        if text.contains("word ptr") && !text.contains("dword") && !text.contains("qword") {
            return Some("uint16_t".to_string());
        }
        if text.contains("dword ptr") {
            return Some("uint32_t".to_string());
        }
        if text.contains("qword ptr") {
            return Some("uint64_t".to_string());
        }
        if opcode.starts_with("lea") {
            return Some("void *".to_string());
        }
    }
    None
}


fn render_fast_pseudocode(
    name: &str,
    address: u64,
    blocks: &[BasicBlock],
    arguments: &[Variable],
    imports: &[revx_core::Import],
    strings: &[revx_core::StringLiteral],
    call_target_overrides: &HashMap<u64, u64>,
    function_symbols: &HashMap<u64, String>,
    return_type: Option<&str>,
    references: &[Reference],
) -> PseudocodeUnit {
    let capacity = blocks
        .iter()
        .map(|block| block.instructions.len() * 48)
        .sum::<usize>()
        .saturating_add(128);
    let mut body = String::with_capacity(capacity.min(12_288));
    if !arguments.is_empty() {
        body.push_str("    // args: ");
        for (i, arg) in arguments.iter().enumerate() {
            if i > 0 {
                body.push_str(", ");
            }
            body.push_str(arg.name.as_str());
            if let Some(ty) = arg.type_name.as_deref() {
                body.push('(');
                body.push_str(ty);
                body.push(')');
            }
        }
        body.push('\n');
    }

    let string_by_addr = strings
        .iter()
        .filter_map(|string| string.address.map(|addr| (addr, string.value.as_str())))
        .collect::<HashMap<_, _>>();

    let mut count = 0usize;
    let mut emitted_returns = 0usize;
    'outer: for block in blocks {
        if count < MAX_FAST_PSEUDO_LINES {
            body.push_str(&format!("    // bb @ {:#x}\n", block.address));
            count += 1;
        }
        let instructions = &block.instructions;
        let mut reg_values: HashMap<String, FastValue> = HashMap::new();
        for (index, arg) in arguments.iter().enumerate().take(8) {
            reg_values.insert(
                format!("x{index}"),
                FastValue::UnknownNamed(arg.name.clone()),
            );
        }
        let mut flags = FastFlags::default();
        let mut idx = 0usize;
        while idx < instructions.len() {
            if count >= MAX_FAST_PSEUDO_LINES {
                body.push_str("    // ...\n");
                break 'outer;
            }
            use std::fmt::Write as _;
            let inst = &instructions[idx];
            let text = inst.text.as_ref();
            track_fast_arm64_value(inst.address, text, &mut reg_values, &string_by_addr);
            track_fast_x64_value(inst.address, text, &mut reg_values, &string_by_addr);
            track_fast_flags(text, &reg_values, &mut flags);
            refine_fast_flag_exprs(&mut reg_values, &flags);

            if text == "ret" || text.starts_with("ret ") {
                let ret_val = reg_values
                    .get("x0")
                    .or_else(|| reg_values.get("w0"))
                    .or_else(|| reg_values.get("rax"))
                    .or_else(|| reg_values.get("eax"))
                    .map(fast_value_render)
                    .unwrap_or_else(|| "0".to_string());
                let _ = writeln!(body, "    return {ret_val}; // {:#x}", inst.address);
                emitted_returns += 1;
                count += 1;
                idx += 1;
                continue;
            }

            if text.starts_with("bl ")
                || text.starts_with("blr ")
                || text.starts_with("call ")
                || text.starts_with("call\t")
            {
                if let Some(line) = fast_render_call_line(
                    inst,
                    text,
                    &reg_values,
                    imports,
                    function_symbols,
                    call_target_overrides,
                ) {
                    let _ = writeln!(body, "    {line}");
                    let result = fast_call_result_value(
                        line.split('(').next().unwrap_or("result"),
                    );
                    fast_clear_caller_saved_with_result(&mut reg_values, result);
                    flags.clear();
                    count += 1;
                    idx += 1;
                    continue;
                }
            }

            if (text.starts_with("br ") || text.starts_with("br	"))
                && !text.starts_with("brk")
            {
                let scrutinee = flags
                    .lhs
                    .clone()
                    .or_else(|| {
                        reg_values
                            .get("x0")
                            .or_else(|| reg_values.get("w0"))
                            .or_else(|| reg_values.get("x16"))
                            .map(fast_value_render)
                    })
                    .unwrap_or_else(|| "value".to_string());
                let bound = flags.rhs.clone().unwrap_or_default();
                if bound.is_empty() {
                    let _ = writeln!(
                        body,
                        "    // switch ({scrutinee}) via jump table; // {:#x}",
                        inst.address
                    );
                } else {
                    let _ = writeln!(
                        body,
                        "    // switch ({scrutinee}) via jump table; // {:#x} bound={bound}",
                        inst.address
                    );
                }
                count += 1;
                idx += 1;
                continue;
            }

            if (text.starts_with("b ") || text.starts_with("b\t"))
                && !text.starts_with("b.")
                && !text.starts_with("bl ")
            {
                let target = call_target_overrides
                    .get(&inst.address)
                    .copied()
                    .or_else(|| parse_relative_target(inst.address, text));
                if let Some(target) = target {
                    let label = fast_callee_name(target, imports, function_symbols)
                        .unwrap_or_else(|| format_sub_addr(target));
                    let is_tail = idx + 1 >= instructions.len()
                        || instructions[idx + 1..].iter().all(|next| {
                            let t = next.text.as_ref();
                            t.starts_with("nop")
                                || t.starts_with("bti ")
                                || t == "ret"
                                || t.starts_with("ret ")
                        });
                    if is_tail {
                        let args = fast_call_args(&reg_values, &label);
                        let _ = writeln!(
                            body,
                            "    return {label}({}); // {:#x}",
                            args.join(", "),
                            inst.address
                        );
                        emitted_returns += 1;
                    } else {
                        let _ = writeln!(body, "    goto {label}; // {:#x}", inst.address);
                    }
                    count += 1;
                    idx += 1;
                    continue;
                }
            }

            if let Some((cond, target_addr)) =
                fast_conditional_branch(inst.address, text, &reg_values, &flags)
            {
                if let Some(target_u64) = target_addr {
                    if let Some(end_idx) =
                        fast_find_addr_index(instructions, target_u64).filter(|end| *end > idx)
                    {
                        let span = end_idx - idx;
                        if (2..=12).contains(&span) {
                            let body_cond = invert_c_condition(&cond);
                            let mut body_lines: Vec<String> = Vec::new();
                            let mut temp_regs = reg_values.clone();
                            let mut temp_flags = flags.clone();
                            let mut temp_returns = 0usize;
                            let mut j = idx + 1;
                            while j < end_idx {
                                let inner = &instructions[j];
                                let inner_text = inner.text.as_ref();
                                track_fast_arm64_value(
                                    inner.address,
                                    inner_text,
                                    &mut temp_regs,
                                    &string_by_addr,
                                );
                                track_fast_x64_value(
                                    inner.address,
                                    inner_text,
                                    &mut temp_regs,
                                    &string_by_addr,
                                );
                                track_fast_flags(inner_text, &temp_regs, &mut temp_flags);
                                refine_fast_flag_exprs(&mut temp_regs, &temp_flags);
                                if let Some(line) = fast_render_statement_line(
                                    inner,
                                    inner_text,
                                    &temp_regs,
                                    imports,
                                    function_symbols,
                                    call_target_overrides,
                                    &temp_flags,
                                ) {
                                    if line.starts_with("return ") {
                                        body_lines.push(line);
                                        temp_returns += 1;
                                    } else if let Some(call_line) = line.strip_prefix("call:") {
                                        body_lines.push(call_line.to_string());
                                        let result = fast_call_result_value(
                                            call_line.split('(').next().unwrap_or("result"),
                                        );
                                        fast_clear_caller_saved_with_result(&mut temp_regs, result);
                                        temp_flags.clear();
                                    } else if !line.starts_with("//") {
                                        body_lines.push(line);
                                    } else if line.contains('=') {
                                        body_lines.push(line);
                                    }
                                }
                                j += 1;
                            }
                            if !body_lines.is_empty() && body_lines.len() <= 8 {
                                let _ = writeln!(
                                    body,
                                    "    if ({body_cond}) {{ // {:#x}",
                                    inst.address
                                );
                                count += 1;
                                for line in &body_lines {
                                    let _ = writeln!(body, "        {line}");
                                    count += 1;
                                }
                                body.push_str("    }\n");
                                emitted_returns += temp_returns;
                                reg_values = temp_regs;
                                flags = temp_flags;
                                idx = end_idx;
                                continue;
                            }
                        }
                    }
                    let target = fast_callee_name(target_u64, imports, function_symbols)
                        .unwrap_or_else(|| format_sub_addr(target_u64));
                    let _ = writeln!(
                        body,
                        "    if ({cond}) goto {target}; // {:#x}",
                        inst.address
                    );
                    count += 1;
                    idx += 1;
                    continue;
                }
                let _ = writeln!(
                    body,
                    "    if ({cond}) goto label; // {:#x}",
                    inst.address
                );
                count += 1;
                idx += 1;
                continue;
            }

            if text.starts_with("cmp ")
                || text.starts_with("cmn ")
                || text.starts_with("tst ")
                || text.starts_with("test ")
            {
                idx += 1;
                continue;
            }

            if text.starts_with("adrp ")
                || text.starts_with("add ")
                || text.starts_with("sub ")
                || text.starts_with("mov ")
                || text.starts_with("movz ")
                || text.starts_with("movk ")
                || text.starts_with("orr ")
                || text.starts_with("and ")
                || text.starts_with("eor ")
                || text.starts_with("csel ")
                || text.starts_with("csinc ")
                || text.starts_with("cset ")
                || text.starts_with("sxtw ")
                || text.starts_with("ldr")
                || text.starts_with("ldur")
                || text.starts_with("str ")
                || text.starts_with("strb ")
                || text.starts_with("stur ")
                || text.starts_with("stp ")
                || text.starts_with("ldp ")
                || text.starts_with("nop")
                || text.starts_with("pac")
                || text.starts_with("aut")
                || text.starts_with("bti ")
            {
                if let Some(note) = fast_interesting_note(text, &reg_values) {
                    let _ = writeln!(body, "    // {:#x}: {note}", inst.address);
                    count += 1;
                }
                idx += 1;
                continue;
            }

            let _ = writeln!(body, "    // {:#x}: {}", inst.address, text);
            count += 1;
            idx += 1;
        }
    }
    if emitted_returns == 0 {
        body.push_str("    return 0;\n");
    }
    let _ = address;
    let signature_args = if arguments.is_empty() {
        "void".to_string()
    } else {
        arguments
            .iter()
            .map(|arg| {
                format!(
                    "{} {}",
                    arg.type_name
                        .clone()
                        .unwrap_or_else(|| "int64_t".to_string()),
                    arg.name
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let ret_ty = return_type.unwrap_or("int");
    finalize_pseudocode_unit_with_context(
        name,
        address,
        PseudocodeUnit {
            language: "c".to_string(),
            text: format!(
                "{ret_ty} {}({signature_args}) {{
{}}}",
                sanitize_symbol(name),
                body
            ),
            regions: Vec::new(),
            region_artifact: None,
            evidence_ids: vec![format!("pseudo:{address:x}")],
            semantic_lattice: None,
        },
        references,
        function_symbols,
    )
}

#[derive(Debug, Clone, Default)]
struct FastFlags {
    lhs: Option<String>,
    rhs: Option<String>,
    kind: FastFlagKind,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum FastFlagKind {
    #[default]
    None,
    Cmp,
    Test,
    Cmn,
}

impl FastFlags {
    fn clear(&mut self) {
        self.lhs = None;
        self.rhs = None;
        self.kind = FastFlagKind::None;
    }
}

fn refine_fast_flag_exprs(regs: &mut HashMap<String, FastValue>, flags: &FastFlags) {
    let keys: Vec<String> = regs.keys().cloned().collect();
    for key in keys {
        let Some(FastValue::Expr(expr)) = regs.get(&key).cloned() else {
            continue;
        };
        if let Some(cc) = expr.strip_prefix("/*").and_then(|s| s.strip_suffix("*/")) {
            if let Some(cond) = fast_flags_condition(cc, flags) {
                regs.insert(key, FastValue::Expr(format!("({cond} ? 1 : 0)")));
            }
            continue;
        }
        if let Some(rest) = expr.strip_prefix("(/*") {
            if let Some(idx) = rest.find("*/") {
                let cc = &rest[..idx];
                let tail = &rest[idx + 2..];
                if let Some(cond) = fast_flags_condition(cc, flags) {
                    if let Some(tail) = tail.strip_prefix(" ? ") {
                        regs.insert(key, FastValue::Expr(format!("({cond} ? {tail}")));
                    }
                }
            }
        }
    }
}

fn track_fast_flags(text: &str, regs: &HashMap<String, FastValue>, flags: &mut FastFlags) {
    let text = text.trim();
    let (kind, rest) = if let Some(rest) = text.strip_prefix("cmp ") {
        (FastFlagKind::Cmp, rest)
    } else if let Some(rest) = text.strip_prefix("cmn ") {
        (FastFlagKind::Cmn, rest)
    } else if let Some(rest) = text.strip_prefix("tst ") {
        (FastFlagKind::Test, rest)
    } else if let Some(rest) = text.strip_prefix("test ") {
        (FastFlagKind::Test, rest)
    } else {
        return;
    };
    let mut parts = rest.split(',').map(str::trim);
    let Some(lhs_raw) = parts.next() else {
        return;
    };
    let Some(rhs_raw) = parts.next() else {
        return;
    };
    let lhs = fast_operand_render(lhs_raw, regs);
    let rhs = fast_operand_render(rhs_raw, regs);
    flags.kind = kind;
    flags.lhs = Some(lhs);
    flags.rhs = Some(rhs);
}

fn fast_operand_render(raw: &str, regs: &HashMap<String, FastValue>) -> String {
    let raw = raw.trim();
    if let Some(imm) = raw.strip_prefix('#') {
        if let Some(v) = parse_imm_u64(imm) {
            return fast_imm_render(v);
        }
        return imm.to_string();
    }
    if let Some(imm) = raw
        .strip_prefix("0x")
        .and_then(|v| u64::from_str_radix(v, 16).ok())
        .or_else(|| raw.parse::<u64>().ok())
    {
        return fast_imm_render(imm);
    }
    let key = if raw.starts_with('w') || raw.starts_with('x') {
        normalize_arm64_register(raw)
    } else {
        raw.to_ascii_lowercase()
    };
    if let Some(value) = regs.get(&key).or_else(|| regs.get(raw)) {
        match value {
            FastValue::UnknownNamed(name) => name.clone(),
            other => fast_value_render(other),
        }
    } else if let Some(name) = raw.strip_prefix("/*").and_then(|s| s.strip_suffix("*/")) {
        name.to_string()
    } else {
        key
    }
}

fn fast_flags_condition(cc: &str, flags: &FastFlags) -> Option<String> {
    let lhs = flags.lhs.as_deref()?;
    let rhs = flags.rhs.as_deref()?;
    let cc = cc.trim().trim_end_matches(|c: char| !c.is_ascii_alphanumeric());
    match flags.kind {
        FastFlagKind::None => None,
        FastFlagKind::Cmp => match cc {
            "eq" => Some(format!("{lhs} == {rhs}")),
            "ne" => Some(format!("{lhs} != {rhs}")),
            "gt" | "hi" => Some(format!("{lhs} > {rhs}")),
            "ge" | "hs" | "cs" => Some(format!("{lhs} >= {rhs}")),
            "lt" | "lo" | "cc" => Some(format!("{lhs} < {rhs}")),
            "le" | "ls" => Some(format!("{lhs} <= {rhs}")),
            "mi" => Some(format!("({lhs} - {rhs}) < 0")),
            "pl" => Some(format!("({lhs} - {rhs}) >= 0")),
            _ => None,
        },
        FastFlagKind::Cmn => {
            let neg = negate_c_imm_expr(rhs);
            match cc {
                "eq" => Some(format!("{lhs} == {neg}")),
                "ne" => Some(format!("{lhs} != {neg}")),
                "gt" | "hi" => Some(format!("{lhs} > {neg}")),
                "ge" | "hs" | "cs" => Some(format!("{lhs} >= {neg}")),
                "lt" | "lo" | "cc" => Some(format!("{lhs} < {neg}")),
                "le" | "ls" => Some(format!("{lhs} <= {neg}")),
                _ => None,
            }
        }
        FastFlagKind::Test => match cc {
            "eq" => Some(format!("({lhs} & {rhs}) == 0")),
            "ne" => Some(format!("({lhs} & {rhs}) != 0")),
            "pl" => Some(format!("({lhs} & {rhs}) >= 0")),
            "mi" => Some(format!("({lhs} & {rhs}) < 0")),
            _ => None,
        },
    }
}

fn negate_c_imm_expr(expr: &str) -> String {
    let expr = expr.trim();
    if let Ok(v) = expr.parse::<i64>() {
        return format!("{}", -v);
    }
    if let Some(hex) = expr.strip_prefix("0x") {
        if let Ok(v) = u64::from_str_radix(hex, 16) {
            let s = -(v as i64);
            if (-4096..4096).contains(&s) {
                return format!("{s}");
            }
            return format!("-({expr})");
        }
    }
    format!("-({expr})")
}

fn invert_c_condition(cond: &str) -> String {
    let cond = cond.trim();
    if let Some(inner) = cond.strip_prefix("!(").and_then(|s| s.strip_suffix(')')) {
        if !inner.contains('(') {
            return inner.to_string();
        }
    }
    const PAIRS: &[(&str, &str)] = &[
        (" == ", " != "),
        (" != ", " == "),
        (" > ", " <= "),
        (" <= ", " > "),
        (" < ", " >= "),
        (" >= ", " < "),
    ];
    for (a, b) in PAIRS {
        if let Some(idx) = cond.find(a) {
            return format!("{}{}{}", &cond[..idx], b, &cond[idx + a.len()..]);
        }
    }
    format!("!({cond})")
}

fn fast_find_addr_index(instructions: &[Instruction], addr: u64) -> Option<usize> {
    instructions.iter().position(|inst| inst.address == addr)
}

fn fast_conditional_branch(
    address: u64,
    text: &str,
    regs: &HashMap<String, FastValue>,
    flags: &FastFlags,
) -> Option<(String, Option<u64>)> {
    let text = text.trim();
    if let Some(rest) = text.strip_prefix("cbz ") {
        let mut parts = rest.split(',').map(str::trim);
        let reg = parts.next()?;
        let key = normalize_arm64_register(reg);
        let lhs = regs
            .get(&key)
            .map(|v| match v {
                FastValue::UnknownNamed(n) => n.clone(),
                other => fast_value_render(other),
            })
            .unwrap_or_else(|| reg.to_string());
        let target = parse_relative_target(address, text);
        return Some((format!("{lhs} == 0"), target));
    }
    if let Some(rest) = text.strip_prefix("cbnz ") {
        let mut parts = rest.split(',').map(str::trim);
        let reg = parts.next()?;
        let key = normalize_arm64_register(reg);
        let lhs = regs
            .get(&key)
            .map(|v| match v {
                FastValue::UnknownNamed(n) => n.clone(),
                other => fast_value_render(other),
            })
            .unwrap_or_else(|| reg.to_string());
        let target = parse_relative_target(address, text);
        return Some((format!("{lhs} != 0"), target));
    }
    if let Some(rest) = text.strip_prefix("tbz ") {
        let mut parts = rest.split(',').map(str::trim);
        let reg = parts.next()?.trim();
        let bit = parts
            .next()
            .map(|b| b.trim().trim_start_matches('#'))
            .unwrap_or("bit");
        let target = parse_relative_target(address, text);
        return Some((format!("!({reg} & (1 << {bit}))"), target));
    }
    if let Some(rest) = text.strip_prefix("tbnz ") {
        let mut parts = rest.split(',').map(str::trim);
        let reg = parts.next()?.trim();
        let bit = parts
            .next()
            .map(|b| b.trim().trim_start_matches('#'))
            .unwrap_or("bit");
        let target = parse_relative_target(address, text);
        return Some((format!("({reg} & (1 << {bit}))"), target));
    }
    if text.starts_with("b.") {
        let cc = text[2..].split_whitespace().next().unwrap_or("cond");
        let cond = fast_flags_condition(cc, flags).unwrap_or_else(|| cc.to_string());
        let target = parse_relative_target(address, text);
        return Some((cond, target));
    }
    const X64: &[(&str, &str)] = &[
        ("je ", "eq"),
        ("jne ", "ne"),
        ("jz ", "eq"),
        ("jnz ", "ne"),
        ("ja ", "hi"),
        ("jb ", "lo"),
        ("jg ", "gt"),
        ("jl ", "lt"),
        ("jbe ", "ls"),
        ("jae ", "hs"),
        ("jle ", "le"),
        ("jge ", "ge"),
        ("js ", "mi"),
        ("jns ", "pl"),
    ];
    for (prefix, cc) in X64 {
        if text.starts_with(prefix) {
            let cond = fast_flags_condition(cc, flags).unwrap_or_else(|| (*cc).to_string());
            let target = parse_relative_target(address, text);
            return Some((cond, target));
        }
    }
    None
}

fn fast_render_call_line(
    inst: &Instruction,
    text: &str,
    reg_values: &HashMap<String, FastValue>,
    imports: &[revx_core::Import],
    function_symbols: &HashMap<u64, String>,
    call_target_overrides: &HashMap<u64, u64>,
) -> Option<String> {
    let target = call_target_overrides
        .get(&inst.address)
        .copied()
        .or_else(|| parse_relative_target(inst.address, text));
    if let Some(target) = target {
        let callee = fast_callee_name(target, imports, function_symbols)
            .unwrap_or_else(|| format_sub_addr(target));
        let args = fast_call_args(reg_values, &callee);
        return Some(format!(
            "{callee}({}); // {:#x}",
            args.join(", "),
            inst.address
        ));
    }
    if let Some(reg) = text.strip_prefix("blr ").map(str::trim) {
        let target = reg_values
            .get(reg)
            .map(fast_value_render)
            .unwrap_or_else(|| reg.to_string());
        let args = fast_call_args(reg_values, "indirect");
        return Some(format!(
            "({target})({}); // {:#x}",
            args.join(", "),
            inst.address
        ));
    }
    None
}

fn fast_render_statement_line(
    inst: &Instruction,
    text: &str,
    reg_values: &HashMap<String, FastValue>,
    imports: &[revx_core::Import],
    function_symbols: &HashMap<u64, String>,
    call_target_overrides: &HashMap<u64, u64>,
    flags: &FastFlags,
) -> Option<String> {
    if text == "ret" || text.starts_with("ret ") {
        let ret_val = reg_values
            .get("x0")
            .or_else(|| reg_values.get("w0"))
            .or_else(|| reg_values.get("rax"))
            .or_else(|| reg_values.get("eax"))
            .map(fast_value_render)
            .unwrap_or_else(|| "0".to_string());
        return Some(format!("return {ret_val}; // {:#x}", inst.address));
    }
    if text.starts_with("bl ")
        || text.starts_with("blr ")
        || text.starts_with("call ")
        || text.starts_with("call\t")
    {
        if let Some(line) = fast_render_call_line(
            inst,
            text,
            reg_values,
            imports,
            function_symbols,
            call_target_overrides,
        ) {
            return Some(format!("call:{line}"));
        }
    }
    if (text.starts_with("b ") || text.starts_with("b\t"))
        && !text.starts_with("b.")
        && !text.starts_with("bl ")
    {
        let target = call_target_overrides
            .get(&inst.address)
            .copied()
            .or_else(|| parse_relative_target(inst.address, text));
        if let Some(target) = target {
            let label = fast_callee_name(target, imports, function_symbols)
                .unwrap_or_else(|| format_sub_addr(target));
            return Some(format!("goto {label}; // {:#x}", inst.address));
        }
    }
    if let Some((cond, target_addr)) =
        fast_conditional_branch(inst.address, text, reg_values, flags)
    {
        let target = target_addr
            .map(|addr| {
                fast_callee_name(addr, imports, function_symbols)
                    .unwrap_or_else(|| format_sub_addr(addr))
            })
            .unwrap_or_else(|| "label".to_string());
        return Some(format!(
            "if ({cond}) goto {target}; // {:#x}",
            inst.address
        ));
    }
    if text.starts_with("cmp ")
        || text.starts_with("cmn ")
        || text.starts_with("tst ")
        || text.starts_with("test ")
        || text.starts_with("nop")
        || text.starts_with("pac")
        || text.starts_with("aut")
        || text.starts_with("bti ")
    {
        return None;
    }
    if text.starts_with("adrp ")
        || text.starts_with("add ")
        || text.starts_with("sub ")
        || text.starts_with("mov ")
        || text.starts_with("movz ")
        || text.starts_with("movk ")
        || text.starts_with("orr ")
        || text.starts_with("and ")
        || text.starts_with("eor ")
        || text.starts_with("csel ")
        || text.starts_with("csinc ")
        || text.starts_with("cset ")
        || text.starts_with("sxtw ")
        || text.starts_with("ldr")
        || text.starts_with("ldur")
        || text.starts_with("str ")
        || text.starts_with("strb ")
        || text.starts_with("stur ")
        || text.starts_with("stp ")
        || text.starts_with("ldp ")
    {
        return fast_interesting_note(text, reg_values)
            .map(|note| format!("// {:#x}: {note}", inst.address));
    }
    Some(format!("// {:#x}: {text}", inst.address))
}


#[derive(Debug, Clone)]
enum FastValue {
    Imm(u64),
    Page(u64),
    String(String),
    Addr(u64),
    Result,
    Mem(String),
    Expr(String),
    UnknownNamed(String),
    Unknown,
}

fn track_fast_arm64_value(
    address: u64,
    text: &str,
    regs: &mut HashMap<String, FastValue>,
    string_by_addr: &HashMap<u64, &str>,
) {
    if let Some((dst, page_token)) = parse_arm64_adrp_text(text) {
        if let Some(page) = parse_arm64_relative_target(address, page_token, true) {
            regs.insert(dst, FastValue::Page(page));
        }
        return;
    }
    if let Some((dst, src, imm)) = parse_arm64_add_imm_simple(text) {
        let next = if src == "x29" || src == "fp" || src == "sp" {
            FastValue::Addr(imm)
        } else {
            match regs.get(&src).cloned().unwrap_or(FastValue::Unknown) {
                FastValue::Page(page) => {
                    let addr = page.saturating_add(imm);
                    if let Some(value) = string_by_addr.get(&addr) {
                        FastValue::String((*value).to_string())
                    } else {
                        FastValue::Addr(addr)
                    }
                }
                FastValue::Imm(base) => FastValue::Imm(base.saturating_add(imm)),
                FastValue::Addr(base) => {
                    let addr = base.wrapping_add(imm);
                    if let Some(value) = string_by_addr.get(&addr) {
                        FastValue::String((*value).to_string())
                    } else {
                        FastValue::Addr(addr)
                    }
                }
                FastValue::Result => FastValue::Expr(format!("(result + {})", fast_imm_render(imm))),
                FastValue::UnknownNamed(name) => {
                    FastValue::Expr(format!("({name} + {})", fast_imm_render(imm)))
                }
                FastValue::Mem(m) => FastValue::Expr(format!("({m} + {})", fast_imm_render(imm))),
                _ => FastValue::Unknown,
            }
        };
        regs.insert(dst, next);
        return;
    }
    if let Some((dst, src, imm)) = parse_arm64_sub_imm_simple(text) {
        let next = if src == "x29" || src == "fp" || src == "sp" {
            FastValue::Addr(imm.wrapping_neg())
        } else {
            match regs.get(&src).cloned().unwrap_or(FastValue::Unknown) {
                FastValue::Imm(base) => FastValue::Imm(base.saturating_sub(imm)),
                FastValue::Addr(base) => FastValue::Addr(base.wrapping_sub(imm)),
                FastValue::Result => {
                    FastValue::Expr(format!("(result - {})", fast_imm_render(imm)))
                }
                FastValue::UnknownNamed(name) => {
                    FastValue::Expr(format!("({name} - {})", fast_imm_render(imm)))
                }
                FastValue::Expr(e) => {
                    FastValue::Expr(format!("({e} - {})", fast_imm_render(imm)))
                }
                FastValue::Mem(m) => {
                    FastValue::Expr(format!("({m} - {})", fast_imm_render(imm)))
                }
                _ => FastValue::Unknown,
            }
        };
        regs.insert(dst, next);
        return;
    }
    if let Some((dst, imm, shift)) = parse_arm64_mov_imm_shifted(text) {
        if shift == 0 {
            regs.insert(dst, FastValue::Imm(imm));
        } else {
            let base = match regs.get(&dst) {
                Some(FastValue::Imm(v)) => *v,
                _ => 0,
            };
            let mask = if shift >= 64 {
                0u64
            } else {
                !(0xffffu64 << shift)
            };
            let next = (base & mask) | (imm << shift);
            regs.insert(dst, FastValue::Imm(next));
        }
        return;
    }
    if let Some((dst, src)) = parse_arm64_mov_reg_simple(text) {
        if let Some(value) = regs.get(&src).cloned() {
            regs.insert(dst, value);
        }
        return;
    }
    if let Some((dst, base, imm, is_byte)) = parse_arm64_load_imm(text) {
        if base == "x29" || base == "fp" {
            regs.insert(dst, FastValue::Mem(frame_local_name(imm)));
            return;
        }
        if base == "sp" {
            regs.insert(dst, FastValue::Mem(stack_slot_name(imm)));
            return;
        }
        let base_val = regs.get(&base).cloned().unwrap_or(FastValue::Unknown);
        match &base_val {
            FastValue::Page(page) | FastValue::Addr(page)
                if !is_byte && *page <= 0xffff_ffff_0000_0000 && *page > 0x1000 =>
            {
                let addr = page.wrapping_add(imm);
                if let Some(value) = string_by_addr.get(&addr) {
                    regs.insert(dst, FastValue::String((*value).to_string()));
                } else {
                    regs.insert(dst, FastValue::Addr(addr));
                }
            }
            FastValue::String(s) if imm == 0 && !is_byte => {
                regs.insert(dst, FastValue::String(s.clone()));
            }
            _ => {
                regs.insert(dst, fast_mem_load_value(&base_val, imm, is_byte));
            }
        }
        return;
    }
    if let Some((dst, src, imm)) = parse_arm64_orr_imm_simple(text) {
        let next = match regs.get(&src).cloned().unwrap_or(FastValue::Imm(0)) {
            FastValue::Imm(base) if src == "xzr" || src == "wzr" || base == 0 => FastValue::Imm(imm),
            FastValue::Imm(base) => FastValue::Imm(base | imm),
            _ if src == "xzr" || src == "wzr" => FastValue::Imm(imm),
            other => other,
        };
        regs.insert(dst, next);
        return;
    }
    if let Some((dst, src, imm)) = parse_arm64_and_imm_simple(text) {
        let next = match regs.get(&src).cloned().unwrap_or(FastValue::Unknown) {
            FastValue::Imm(base) => FastValue::Imm(base & imm),
            FastValue::Result => FastValue::Expr(format!("(result & {})", fast_imm_render(imm))),
            FastValue::UnknownNamed(name) => {
                FastValue::Expr(format!("({name} & {})", fast_imm_render(imm)))
            }
            FastValue::Mem(m) => FastValue::Expr(format!("({m} & {})", fast_imm_render(imm))),
            FastValue::Expr(e) => FastValue::Expr(format!("({e} & {})", fast_imm_render(imm))),
            other => other,
        };
        regs.insert(dst, next);
        return;
    }
    if let Some((dst, src, imm)) = parse_arm64_eor_imm_simple(text) {
        let next = match regs.get(&src).cloned().unwrap_or(FastValue::Unknown) {
            FastValue::Imm(base) => FastValue::Imm(base ^ imm),
            FastValue::Result => FastValue::Expr(format!("(result ^ {})", fast_imm_render(imm))),
            FastValue::UnknownNamed(name) => {
                FastValue::Expr(format!("({name} ^ {})", fast_imm_render(imm)))
            }
            other => other,
        };
        regs.insert(dst, next);
        return;
    }
    if let Some((dst, cc)) = parse_arm64_cset(text) {
        regs.insert(dst, FastValue::Expr(format!("/*{cc}*/")));
        return;
    }
    if let Some((dst, t_reg, f_reg, cc)) = parse_arm64_csel(text) {
        let t = regs
            .get(&t_reg)
            .map(fast_value_render)
            .unwrap_or_else(|| t_reg.clone());
        let f = regs
            .get(&f_reg)
            .map(fast_value_render)
            .unwrap_or_else(|| f_reg.clone());
        if t_reg == "xzr" || t_reg == "wzr" {
            regs.insert(dst, FastValue::Expr(format!("(/*{cc}*/ ? 0 : {f})")));
        } else if f_reg == "xzr" || f_reg == "wzr" {
            regs.insert(dst, FastValue::Expr(format!("(/*{cc}*/ ? {t} : 0)")));
        } else {
            regs.insert(dst, FastValue::Expr(format!("(/*{cc}*/ ? {t} : {f})")));
        }
        return;
    }
    if let Some((dst, src)) = parse_arm64_sxtw(text) {
        if let Some(value) = regs.get(&src).cloned() {
            regs.insert(dst, value);
        }
        return;
    }
}

fn frame_local_name(imm: u64) -> String {
    let signed = imm as i64;
    if signed < 0 {
        format!("local_{:#x}", (-signed) as u64)
    } else if imm > 0xffff_ffff_0000_0000 {
        let off = (!imm).wrapping_add(1);
        format!("local_{off:#x}")
    } else {
        format!("local_{:#x}", imm)
    }
}

fn stack_slot_name(imm: u64) -> String {
    let signed = imm as i64;
    if signed < 0 {
        format!("stack_{:#x}", (-signed) as u64)
    } else if imm > 0xffff_ffff_0000_0000 {
        let off = (!imm).wrapping_add(1);
        format!("stack_{off:#x}")
    } else {
        format!("stack_{:#x}", imm)
    }
}

fn fast_mem_load_value(base: &FastValue, imm: u64, is_byte: bool) -> FastValue {
    match base {
        FastValue::Result if imm == 0 && is_byte => FastValue::Mem("result[0]".into()),
        FastValue::Result if imm == 0 => FastValue::Mem("*result".into()),
        FastValue::Result => FastValue::Mem(format!("*(result + {})", fast_imm_render(imm))),
        FastValue::UnknownNamed(name) if imm == 0 && is_byte => {
            FastValue::Mem(format!("{name}[0]"))
        }
        FastValue::UnknownNamed(name) if imm == 0 => FastValue::Mem(format!("*{name}")),
        FastValue::UnknownNamed(name) => {
            FastValue::Mem(format!("*({name} + {})", fast_imm_render(imm)))
        }
        FastValue::Addr(v) if *v > 0xffff_ffff_0000_0000 || *v < 0x1000 => {
            let local = frame_local_name(*v);
            if imm == 0 {
                FastValue::Mem(local)
            } else {
                FastValue::Mem(format!("{local}[{}]", fast_imm_render(imm)))
            }
        }
        FastValue::Addr(v) | FastValue::Page(v) => {
            let addr = v.wrapping_add(imm);
            if is_byte {
                FastValue::Mem(format!("*({addr:#x})"))
            } else if addr > 0xffff_ffff_0000_0000 || addr < 0x1000 {
                FastValue::Mem(frame_local_name(addr))
            } else {
                FastValue::Addr(addr)
            }
        }
        FastValue::Mem(m) if imm == 0 => FastValue::Mem(format!("*{m}")),
        FastValue::Mem(m) => FastValue::Mem(format!("*({m} + {})", fast_imm_render(imm))),
        FastValue::Expr(e) if imm == 0 => FastValue::Mem(format!("*({e})")),
        FastValue::String(s) if imm == 0 && is_byte => {
            FastValue::Mem(format!("{:?}[0]", s))
        }
        FastValue::Imm(v) => FastValue::Mem(format!("*({:#x})", v.saturating_add(imm))),
        _ => FastValue::Unknown,
    }
}

fn fast_imm_render(v: u64) -> String {
    let as_i = v as i64;
    if (-4096..4096).contains(&as_i) {
        format!("{as_i}")
    } else {
        format!("{v:#x}")
    }
}


fn parse_arm64_load_imm(text: &str) -> Option<(String, String, u64, bool)> {
    let text = text.trim();
    let (rest, is_byte) = if let Some(rest) = text.strip_prefix("ldrb ") {
        (rest, true)
    } else if let Some(rest) = text.strip_prefix("ldurb ") {
        (rest, true)
    } else if let Some(rest) = text.strip_prefix("ldrsb ") {
        (rest, true)
    } else if let Some(rest) = text.strip_prefix("ldrh ") {
        (rest, false)
    } else if let Some(rest) = text.strip_prefix("ldurh ") {
        (rest, false)
    } else if let Some(rest) = text.strip_prefix("ldrsh ") {
        (rest, false)
    } else if let Some(rest) = text.strip_prefix("ldrsw ") {
        (rest, false)
    } else if let Some(rest) = text.strip_prefix("ldur ") {
        (rest, false)
    } else if let Some(rest) = text.strip_prefix("ldr ") {
        (rest, false)
    } else {
        return None;
    };
    let mut parts = rest.splitn(2, ',');
    let dst = normalize_arm64_register(parts.next()?.trim());
    let mem = parts.next()?.trim();
    if mem.contains(", x") || mem.contains(", w") || mem.contains("lsl") {
        return None;
    }
    let inner = mem
        .strip_prefix('[')?
        .trim_end_matches('!')
        .strip_suffix(']')?;
    let mut mem_parts = inner.split(',').map(str::trim);
    let base = normalize_arm64_register(mem_parts.next()?);
    let imm = match mem_parts.next() {
        None => 0u64,
        Some(tok) => {
            let tok = tok.trim_start_matches('#');
            if tok.starts_with('-') {
                let v = parse_imm_u64(tok.trim_start_matches('-'))?;
                return Some((dst, base, v.wrapping_neg(), is_byte));
            }
            parse_imm_u64(tok)?
        }
    };
    Some((dst, base, imm, is_byte))
}

fn parse_arm64_orr_imm_simple(text: &str) -> Option<(String, String, u64)> {
    let rest = text.strip_prefix("orr ")?;
    let mut parts = rest.split(',').map(str::trim);
    let dst = normalize_arm64_register(parts.next()?);
    let src = normalize_arm64_register(parts.next()?);
    let imm_tok = parts.next()?;
    let imm = imm_tok.strip_prefix('#')?;
    let imm = parse_imm_u64(imm)?;
    Some((dst, src, imm))
}

fn parse_arm64_and_imm_simple(text: &str) -> Option<(String, String, u64)> {
    let rest = text.strip_prefix("and ")?;
    let mut parts = rest.split(',').map(str::trim);
    let dst = normalize_arm64_register(parts.next()?);
    let src = normalize_arm64_register(parts.next()?);
    let imm_tok = parts.next()?;
    let imm = imm_tok.strip_prefix('#')?;
    let imm = parse_imm_u64(imm)?;
    Some((dst, src, imm))
}

fn parse_arm64_eor_imm_simple(text: &str) -> Option<(String, String, u64)> {
    let rest = text.strip_prefix("eor ")?;
    let mut parts = rest.split(',').map(str::trim);
    let dst = normalize_arm64_register(parts.next()?);
    let src = normalize_arm64_register(parts.next()?);
    let imm_tok = parts.next()?;
    let imm = imm_tok.strip_prefix('#')?;
    let imm = parse_imm_u64(imm)?;
    Some((dst, src, imm))
}

fn parse_arm64_cset(text: &str) -> Option<(String, String)> {
    let rest = text.strip_prefix("cset ")?;
    let mut parts = rest.split(',').map(str::trim);
    let dst = normalize_arm64_register(parts.next()?);
    let cc = parts.next()?.to_ascii_lowercase();
    Some((dst, cc))
}

fn parse_arm64_csel(text: &str) -> Option<(String, String, String, String)> {
    let rest = text
        .strip_prefix("csel ")
        .or_else(|| text.strip_prefix("csinc "))
        .or_else(|| text.strip_prefix("csinv "))
        .or_else(|| text.strip_prefix("csneg "))?;
    let mut parts = rest.split(',').map(str::trim);
    let dst = normalize_arm64_register(parts.next()?);
    let t = normalize_arm64_register(parts.next()?);
    let f = normalize_arm64_register(parts.next()?);
    let cc = parts.next()?.to_ascii_lowercase();
    Some((dst, t, f, cc))
}

fn parse_arm64_sxtw(text: &str) -> Option<(String, String)> {
    let rest = text.strip_prefix("sxtw ")?;
    let mut parts = rest.split(',').map(str::trim);
    let dst = normalize_arm64_register(parts.next()?);
    let src = normalize_arm64_register(parts.next()?);
    Some((dst, src))
}

fn parse_arm64_mov_imm_shifted(text: &str) -> Option<(String, u64, u32)> {
    let is_movk = text.starts_with("movk ");
    let rest = text
        .strip_prefix("mov ")
        .or_else(|| text.strip_prefix("movz "))
        .or_else(|| text.strip_prefix("movk "))?;
    let mut parts = rest.split(',').map(str::trim);
    let dst = normalize_arm64_register(parts.next()?);
    let imm_tok = parts.next()?;
    let imm = parse_imm_u64(imm_tok.strip_prefix('#')?)?;
    let mut shift = 0u32;
    if let Some(shift_tok) = parts.next() {
        let shift_tok = shift_tok.trim();
        if let Some(rest) = shift_tok.strip_prefix("lsl ") {
            let rest = rest.strip_prefix('#').unwrap_or(rest);
            shift = rest.parse().ok()?;
        }
    }
    if is_movk || shift != 0 || text.starts_with("movz ") || text.starts_with("mov ") {
        return Some((dst, imm, shift));
    }
    None
}

fn parse_arm64_adrp_text(text: &str) -> Option<(String, &str)> {
    let rest = text.strip_prefix("adrp ")?;
    let mut parts = rest.split(',').map(str::trim);
    let dst = normalize_arm64_register(parts.next()?);
    let page = parts.next()?;
    Some((dst, page))
}

fn parse_arm64_add_imm_simple(text: &str) -> Option<(String, String, u64)> {
    let rest = text.strip_prefix("add ")?;
    let mut parts = rest.split(',').map(str::trim);
    let dst = normalize_arm64_register(parts.next()?);
    let src = normalize_arm64_register(parts.next()?);
    let imm_tok = parts.next()?;
    let imm = imm_tok.strip_prefix('#')?;
    let imm = parse_imm_u64(imm)?;
    Some((dst, src, imm))
}

fn parse_arm64_sub_imm_simple(text: &str) -> Option<(String, String, u64)> {
    let rest = text.strip_prefix("sub ")?;
    let mut parts = rest.split(',').map(str::trim);
    let dst = normalize_arm64_register(parts.next()?);
    let src = normalize_arm64_register(parts.next()?);
    let imm_tok = parts.next()?;
    let imm = imm_tok.strip_prefix('#')?;
    let imm = parse_imm_u64(imm)?;
    Some((dst, src, imm))
}

fn parse_arm64_mov_reg_simple(text: &str) -> Option<(String, String)> {
    let rest = text.strip_prefix("mov ")?;
    let mut parts = rest.split(',').map(str::trim);
    let dst = normalize_arm64_register(parts.next()?);
    let src = parts.next()?;
    if src.starts_with('#') {
        return None;
    }
    Some((dst, normalize_arm64_register(src)))
}

fn fast_value_render(value: &FastValue) -> String {
    match value {
        FastValue::Imm(v) => fast_imm_render(*v),
        FastValue::String(s) => format!("{:?}", s),
        FastValue::Addr(v) => {
            if *v > 0xffff_ffff_0000_0000 {
                let off = (!*v).wrapping_add(1);
                format!("&local_{off:#x}")
            } else if *v < 0x1000 {
                format!("&local_{v:#x}")
            } else {
                format!("{v:#x}")
            }
        }
        FastValue::Page(v) => format!("{v:#x}"),
        FastValue::Result => "result".to_string(),
        FastValue::Mem(expr) => expr.clone(),
        FastValue::Expr(expr) => expr.clone(),
        FastValue::UnknownNamed(name) => name.clone(),
        FastValue::Unknown => "/*?*/".to_string(),
    }
}

fn bare_symbol_name(name: &str) -> &str {
    name.strip_prefix('_').unwrap_or(name)
}

fn fast_known_arg_count(callee: &str) -> Option<usize> {
    let bare = bare_symbol_name(callee);
    match bare {
        "setlocale" | "compat_mode" | "strcmp" | "strcoll" | "fopen" | "strcpy" | "strcat"
        | "strstr" | "strchr" | "strrchr" | "fputs" | "access" | "open" | "stat" | "lstat"
        | "fstat" | "rename" | "link" | "symlink" | "dlopen" | "dlsym" | "signal" | "tgetent"
        | "tgetstr" | "warn" | "warnx" | "err" | "errx" | "sprintf" | "fprintf" | "fgets"
        | "strcasecmp" | "strncasecmp" => Some(2),
        "snprintf" | "memcpy" | "memmove" | "memset" | "memcmp" | "strncmp" | "strncpy"
        | "strncat" | "strtol" | "strtoul" | "setenv" | "socket" | "ioctl" | "readlink"
        | "execve" | "openat" | "pthread_create" | "posix_spawn" => Some(3),
        "strtonum" | "fread" | "fwrite" | "read" | "write" | "recv" | "send" | "connect"
        | "sendto" | "recvfrom" | "pwrite" | "pread" => Some(4),
        "printf" | "puts" | "getenv" | "isatty" | "atoi" | "atol" | "atoll" | "strlen"
        | "strdup" | "free" | "close" | "ftell" | "fclose" | "malloc" | "calloc" | "realloc"
        | "perror" | "exit" | "system" | "unlink" | "chdir" | "mkdir" | "rmdir"
        | "sleep" | "usleep" | "raise" | "abs" | "labs" => Some(1),
        "getuid" | "geteuid" | "getpid" | "getppid" | "fork" | "abort" | "rand" | "random" => {
            Some(0)
        },
        "getopt_long" | "getopt" | "sysctlbyname" => Some(5),
        _ => None,
    }
}

fn fast_call_result_value(callee: &str) -> FastValue {
    let bare = bare_symbol_name(callee);
    match bare {
        "getopt" | "getopt_long" => FastValue::UnknownNamed("opt".into()),
        "strcmp" | "strncmp" | "strcasecmp" | "strncasecmp" | "memcmp" | "strcoll" => {
            FastValue::UnknownNamed("cmp".into())
        }
        "strlen" => FastValue::UnknownNamed("len".into()),
        "open" | "openat" | "socket" | "accept" | "dup" | "dup2" => {
            FastValue::UnknownNamed("fd".into())
        }
        "malloc" | "calloc" | "realloc" | "aligned_alloc" => FastValue::UnknownNamed("ptr".into()),
        "read" | "write" | "pread" | "pwrite" | "send" | "recv" | "sendto" | "recvfrom" => {
            FastValue::UnknownNamed("n".into())
        }
        "atoi" | "atol" | "atoll" | "strtol" | "strtoul" | "strtonum" => {
            FastValue::UnknownNamed("num".into())
        }
        "getenv" => FastValue::UnknownNamed("env".into()),
        "isatty" => FastValue::UnknownNamed("tty".into()),
        "fork" => FastValue::UnknownNamed("pid".into()),
        _ => FastValue::Result,
    }
}

fn fast_clear_caller_saved(regs: &mut HashMap<String, FastValue>) {
    fast_clear_caller_saved_with_result(regs, FastValue::Result);
}

fn fast_clear_caller_saved_with_result(regs: &mut HashMap<String, FastValue>, result: FastValue) {
    for index in 0..18 {
        regs.remove(&format!("x{index}"));
    }
    for key in [
        "rax", "eax", "rdi", "edi", "rsi", "esi", "rdx", "edx", "rcx", "ecx", "r8", "r9", "r10",
        "r11",
    ] {
        regs.remove(key);
    }
    regs.insert("x0".to_string(), result.clone());
    regs.insert("rax".to_string(), result.clone());
    regs.insert("eax".to_string(), result);
}

fn fast_call_args(regs: &HashMap<String, FastValue>, callee: &str) -> Vec<String> {
    let max_args = fast_known_arg_count(callee).unwrap_or(2);
    if max_args == 0 {
        return Vec::new();
    }
    let arm_keys: Vec<String> = (0..max_args).map(|index| format!("x{index}")).collect();
    let x64_keys = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
    let keys: Vec<&str> = if arm_keys.iter().any(|key| matches!(regs.get(key), Some(FastValue::String(_)) | Some(FastValue::Imm(_)) | Some(FastValue::Addr(_)) | Some(FastValue::Result) | Some(FastValue::Mem(_)) | Some(FastValue::Expr(_)) | Some(FastValue::UnknownNamed(_)))) {
        arm_keys.iter().map(String::as_str).collect()
    } else {
        x64_keys.iter().take(max_args).copied().collect()
    };
    let mut highest = None;
    for (index, key) in keys.iter().enumerate() {
        match regs.get(*key) {
            None | Some(FastValue::Unknown) => {}
            Some(_) => highest = Some(index),
        }
    }
    // If arity is known and any concrete arg exists, pad through known count-1 when trailing
    // values are absent only up to highest concrete.
    let Some(highest) = highest else {
        let named: Vec<String> = keys
            .iter()
            .filter_map(|key| match regs.get(*key) {
                Some(FastValue::UnknownNamed(name)) => Some(name.clone()),
                _ => None,
            })
            .collect();
        return named;
    };
    (0..=highest)
        .map(|index| {
            let key = keys[index];
            match regs.get(key) {
                Some(FastValue::UnknownNamed(name)) => name.clone(),
                Some(FastValue::Unknown) | None => "/*?*/".to_string(),
                Some(value) => fast_value_render(value),
            }
        })
        .collect()
}

fn fast_callee_name(
    target: u64,
    imports: &[revx_core::Import],
    function_symbols: &HashMap<u64, String>,
) -> Option<String> {
    import_name_at(target, imports).or_else(|| function_symbols.get(&target).cloned())
}


fn fast_interesting_note(text: &str, regs: &HashMap<String, FastValue>) -> Option<String> {
    if text.starts_with("adrp ") || text.starts_with("add ") {
        if let Some((dst, _, _)) = parse_arm64_add_imm_simple(text) {
            if let Some(value) = regs.get(&dst) {
                match value {
                    FastValue::String(s) => return Some(format!("{dst} = {:?}", s)),
                    FastValue::Addr(a) => return Some(format!("{dst} = {a:#x}")),
                    FastValue::Mem(m) => return Some(format!("{dst} = {m}")),
                    FastValue::Expr(e) => return Some(format!("{dst} = {e}")),
                    _ => {}
                }
            }
        }
        if let Some((dst, _)) = parse_arm64_adrp_text(text) {
            if let Some(FastValue::String(s)) = regs.get(&dst) {
                return Some(format!("{dst} = {:?}", s));
            }
        }
    }
    if text.starts_with("ldr") || text.starts_with("ldur") {
        if let Some((dst, _, _, _)) = parse_arm64_load_imm(text) {
            if let Some(value) = regs.get(&dst) {
                match value {
                    FastValue::String(s) => return Some(format!("{dst} = {:?}", s)),
                    FastValue::Mem(m) => return Some(format!("{dst} = {m}")),
                    FastValue::Addr(a) => return Some(format!("{dst} = {a:#x}")),
                    FastValue::Expr(e) => return Some(format!("{dst} = {e}")),
                    FastValue::Imm(v) => return Some(format!("{dst} = {}", fast_imm_render(*v))),
                    _ => {}
                }
            }
        }
    }
    if text.starts_with("and ") || text.starts_with("eor ") {
        if let Some((dst, _, _)) = parse_arm64_and_imm_simple(text)
            .or_else(|| parse_arm64_eor_imm_simple(text))
        {
            if let Some(value) = regs.get(&dst) {
                match value {
                    FastValue::Expr(e) | FastValue::Mem(e) => {
                        return Some(format!("{dst} = {e}"));
                    }
                    FastValue::Imm(v) => return Some(format!("{dst} = {}", fast_imm_render(*v))),
                    _ => {}
                }
            }
        }
    }
    if text.starts_with("csel ")
        || text.starts_with("csinc ")
        || text.starts_with("cset ")
        || text.starts_with("sxtw ")
        || text.starts_with("sub ")
    {
        let dst = text
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.split(',').next())
            .map(|s| normalize_arm64_register(s.trim()));
        if let Some(dst) = dst {
            if let Some(value) = regs.get(&dst) {
                match value {
                    FastValue::Expr(e) | FastValue::Mem(e) => {
                        return Some(format!("{dst} = {e}"));
                    }
                    FastValue::Addr(a) if *a < 0x1000 || *a > 0xffff_ffff_0000_0000 => {
                        return Some(format!("{dst} = {}", fast_value_render(value)));
                    }
                    FastValue::Imm(v) => return Some(format!("{dst} = {}", fast_imm_render(*v))),
                    _ => {}
                }
            }
        }
    }
    None
}

fn track_fast_x64_value(
    address: u64,
    text: &str,
    regs: &mut HashMap<String, FastValue>,
    string_by_addr: &HashMap<u64, &str>,
) {
    let text = text.trim();
    if let Some(rest) = text.strip_prefix("mov ") {
        let mut parts = rest.splitn(2, ',');
        let Some(dst_raw) = parts.next() else {
            return;
        };
        let Some(src) = parts.next() else {
            return;
        };
        let dst = dst_raw.trim().to_ascii_lowercase();
        let src = src.trim();
        if let Some(imm) = src
            .strip_prefix("0x")
            .and_then(|v| u64::from_str_radix(v, 16).ok())
            .or_else(|| {
                src.strip_prefix('#')
                    .and_then(|v| v.strip_prefix("0x").and_then(|h| u64::from_str_radix(h, 16).ok()).or_else(|| v.parse().ok()))
            })
            .or_else(|| src.parse::<u64>().ok())
        {
            if let Some(value) = string_by_addr.get(&imm) {
                regs.insert(dst.clone(), FastValue::String((*value).to_string()));
            } else {
                regs.insert(dst.clone(), FastValue::Imm(imm));
            }
            if dst == "edi" {
                regs.insert("rdi".into(), FastValue::Imm(imm));
            } else if dst == "esi" {
                regs.insert("rsi".into(), FastValue::Imm(imm));
            } else if dst == "edx" {
                regs.insert("rdx".into(), FastValue::Imm(imm));
            } else if dst == "ecx" {
                regs.insert("rcx".into(), FastValue::Imm(imm));
            } else if dst == "eax" {
                regs.insert("rax".into(), FastValue::Imm(imm));
            }
            return;
        }
        let src_key = src.to_ascii_lowercase();
        if let Some(value) = regs.get(&src_key).cloned() {
            regs.insert(dst, value);
        }
        return;
    }
    if let Some(rest) = text.strip_prefix("lea ") {
        let mut parts = rest.splitn(2, ',');
        let Some(dst_raw) = parts.next() else {
            return;
        };
        let Some(src) = parts.next() else {
            return;
        };
        let dst = dst_raw.trim().to_ascii_lowercase();
        let src = src.trim();
        if let Some(inner) = src.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            if let Some(disp) = inner
                .strip_prefix("rip+")
                .or_else(|| inner.strip_prefix("rip + "))
            {
                let disp = disp.trim().strip_prefix("0x").unwrap_or(disp.trim());
                if let Ok(off) = u64::from_str_radix(disp, 16).or_else(|_| disp.parse::<u64>()) {
                    let candidates = [
                        address.saturating_add(7).saturating_add(off),
                        address.saturating_add(6).saturating_add(off),
                        address.saturating_add(off),
                    ];
                    for addr in candidates {
                        if let Some(value) = string_by_addr.get(&addr) {
                            regs.insert(dst, FastValue::String((*value).to_string()));
                            return;
                        }
                    }
                    regs.insert(
                        dst,
                        FastValue::Addr(address.saturating_add(7).saturating_add(off)),
                    );
                }
            }
        }
    }
}


fn sample_instructions_for_recovery(instructions: &[Instruction]) -> Vec<Instruction> {
    if instructions.len() <= MAX_RECOVERY_SAMPLE_INSTS {
        return instructions.to_vec();
    }
    let mut out = Vec::with_capacity(MAX_RECOVERY_SAMPLE_INSTS);
    let mut seen = BTreeSet::new();
    let push_inst = |out: &mut Vec<Instruction>, seen: &mut BTreeSet<u64>, inst: &Instruction| {
        if seen.insert(inst.address) {
            out.push(inst.clone());
        }
    };
    let head = (MAX_RECOVERY_SAMPLE_INSTS * 5 / 10).max(32);
    let tail = (MAX_RECOVERY_SAMPLE_INSTS * 2 / 10).max(16);
    for inst in instructions.iter().take(head) {
        push_inst(&mut out, &mut seen, inst);
    }
    for (index, inst) in instructions.iter().enumerate() {
        if out.len() >= MAX_RECOVERY_SAMPLE_INSTS {
            break;
        }
        let text = inst.text.as_ref();
        if !(text.starts_with("bl ")
            || text.starts_with("blr ")
            || text.starts_with("call ")
            || text.starts_with("cbz ")
            || text.starts_with("cbnz ")
            || (text.starts_with('j') && !text.starts_with("jmp"))
            || text.starts_with("b."))
        {
            continue;
        }
        let start = index.saturating_sub(3);
        let end = (index + 4).min(instructions.len());
        for sample in &instructions[start..end] {
            push_inst(&mut out, &mut seen, sample);
            if out.len() >= MAX_RECOVERY_SAMPLE_INSTS {
                break;
            }
        }
    }
    let tail_start = instructions.len().saturating_sub(tail);
    for inst in &instructions[tail_start..] {
        push_inst(&mut out, &mut seen, inst);
    }
    out.sort_by_key(|inst| inst.address);
    out
}

fn block_hotness_score(block: &BasicBlock, block_index: usize, references: &[Reference]) -> i64 {
    let mut score = 0i64;
    if block_index == 0 {
        score += 1000;
    }
    score += (block.instructions.len() as i64).min(64);
    for inst in &block.instructions {
        let t = inst.text.as_ref();
        if t.starts_with("bl ")
            || t.starts_with("blr ")
            || t.starts_with("call ")
            || t.contains("blraa")
            || t.contains("blrab")
        {
            score += 40;
        }
        if t.starts_with("cbz ")
            || t.starts_with("cbnz ")
            || t.starts_with("tbz ")
            || t.starts_with("tbnz ")
            || t.starts_with("b.")
            || (t.starts_with('j') && !t.starts_with("jmp"))
        {
            score += 18;
        }
        if is_backward_control_transfer(inst) {
            score += 55;
        }
        if t.starts_with("ret") || t == "ret" {
            score += 12;
        }
        let addr = inst.address;
        let ref_hits = references
            .iter()
            .filter(|r| r.from == addr || r.to == addr)
            .count() as i64;
        score += ref_hits.saturating_mul(8);
    }
    score
}

fn select_hot_block_indices(blocks: &[BasicBlock], references: &[Reference]) -> Vec<usize> {
    if blocks.is_empty() {
        return Vec::new();
    }
    let mut ranked = blocks
        .iter()
        .enumerate()
        .map(|(idx, block)| (block_hotness_score(block, idx, references), idx))
        .collect::<Vec<_>>();
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let mut chosen = Vec::new();
    let mut insts = 0usize;
    // always include entry
    chosen.push(0usize);
    insts += blocks[0].instructions.len();
    for (_score, idx) in ranked {
        if chosen.contains(&idx) {
            continue;
        }
        let next = insts + blocks[idx].instructions.len();
        if !chosen.is_empty()
            && (chosen.len() >= MAX_OVERSIZE_WINDOW_BLOCKS || next > MAX_OVERSIZE_WINDOW_INSTS)
        {
            continue;
        }
        chosen.push(idx);
        insts = next;
        if chosen.len() >= MAX_OVERSIZE_WINDOW_BLOCKS || insts >= MAX_OVERSIZE_WINDOW_INSTS {
            break;
        }
    }
    chosen.sort_unstable();
    chosen
}

fn select_oversize_window_blocks(
    blocks: &[BasicBlock],
    references: &[Reference],
) -> Vec<BasicBlock> {
    select_hot_block_indices(blocks, references)
        .into_iter()
        .filter_map(|idx| blocks.get(idx).cloned())
        .collect()
}

fn select_hot_ssa_windows(
    blocks: &[BasicBlock],
    references: &[Reference],
) -> Vec<Vec<BasicBlock>> {
    if blocks.is_empty() {
        return Vec::new();
    }
    let indices = select_hot_block_indices(blocks, references);
    let mut windows = Vec::new();
    // primary contiguous entry window
    let entry_window = select_oversize_window_blocks(blocks, references);
    if !entry_window.is_empty() {
        windows.push(entry_window);
    }
    // additional single hot blocks / mini windows around top call-heavy blocks
    let mut extra_inst_budget = MAX_OVERSIZE_WINDOW_INSTS / 2;
    for idx in indices.into_iter().take(8) {
        if idx == 0 {
            continue;
        }
        let start = idx.saturating_sub(1);
        let end = (idx + 2).min(blocks.len());
        let slice = blocks[start..end].to_vec();
        let slice_insts = slice.iter().map(|b| b.instructions.len()).sum::<usize>();
        if slice_insts == 0 || slice_insts > extra_inst_budget {
            continue;
        }
        // skip if fully covered by first window addresses
        if let Some(primary) = windows.first() {
            let primary_addrs: BTreeSet<u64> = primary.iter().map(|b| b.address).collect();
            if slice.iter().all(|b| primary_addrs.contains(&b.address)) {
                continue;
            }
        }
        extra_inst_budget = extra_inst_budget.saturating_sub(slice_insts);
        windows.push(slice);
        if windows.len() >= 4 || extra_inst_budget < 16 {
            break;
        }
    }
    windows
}

fn lift_window_to_ssa_text(
    name: &str,
    window: &[BasicBlock],
    architecture: Architecture,
    references: &[Reference],
    arguments: &[Variable],
    function_symbols: &HashMap<u64, String>,
    shared_string_map: Arc<HashMap<u64, String>>,
) -> Option<String> {
    if window.is_empty() {
        return None;
    }
    let mut ssa_func = match architecture {
        #[cfg(feature = "arch-x64")]
        Architecture::X86_64 => ssa::lift_x64_to_ssa(window, references, arguments),
        #[cfg(feature = "arch-arm64")]
        Architecture::Arm64 => ssa::lift_arm64_to_ssa(window, references, arguments),
        _ => ssa::lift_arm64_to_ssa(window, references, arguments),
    };
    ssa::refine_call_arguments_with_symbols(&mut ssa_func, function_symbols);
    Some(ssa::render_ssa_pseudocode_linear_with_string_arc(
        &ssa_func,
        name,
        arguments,
        function_symbols,
        &HashMap::new(),
        shared_string_map,
    ))
}

fn render_oversized_pseudocode(
    name: &str,
    address: u64,
    blocks: &[BasicBlock],
    arguments: &[Variable],
    locals: &[Variable],
    imports: &[revx_core::Import],
    call_target_overrides: &HashMap<u64, u64>,
    function_symbols: &HashMap<u64, String>,
    debug_hint: Option<&DebugFunctionHint>,
    profile: AnalysisProfile,
    strings: &[revx_core::StringLiteral],
    architecture: Architecture,
    references: &[Reference],
    shared_string_map: Arc<HashMap<u64, String>>,
) -> PseudocodeUnit {
    let windows = select_hot_ssa_windows(blocks, references);
    let primary = windows.first().cloned().unwrap_or_default();
    let regions = build_regions(
        address,
        blocks,
        arguments,
        locals,
        imports,
        call_target_overrides,
        profile,
        strings,
    );
    let mut text = format!(
        "/* oversized function: {} blocks, hot-block SSA windows={} */\n",
        blocks.len(),
        windows.len()
    );
    let mut any_ssa = false;
    for (window_idx, window) in windows.iter().enumerate() {
        let label = if window_idx == 0 {
            "entry/hot primary".to_string()
        } else {
            format!(
                "hot window {} @ {:#x}",
                window_idx,
                window.first().map(|b| b.address).unwrap_or(address)
            )
        };
        if let Some(ssa_text) = lift_window_to_ssa_text(
            name,
            window,
            architecture,
            references,
            arguments,
            function_symbols,
            Arc::clone(&shared_string_map),
        ) {
            any_ssa = true;
            text.push_str(&format!("\n/* --- {label} --- */\n"));
            text.push_str(&ssa_text);
            text.push('\n');
        }
    }
    let fast = render_fast_pseudocode(
        name,
        address,
        if primary.is_empty() { blocks } else { &primary },
        arguments,
        imports,
        strings,
        call_target_overrides,
        function_symbols,
        debug_hint
            .and_then(|hint| hint.return_type.as_deref())
            .or(Some("int")),
        references,
    );
    if !any_ssa {
        text.push_str(&fast.text);
        text.push('\n');
    } else {
        // append compact fast summary of uncovered control flow
        text.push_str("\n/* fast control sketch */\n");
        for line in fast.text.lines().take(24) {
            text.push_str(line);
            text.push('\n');
        }
    }
    if !regions.is_empty() {
        text.push_str("\n/* control-structure summary */\n");
        for region in &regions {
            let span = match (region.start_address, region.end_address) {
                (Some(s), Some(e)) => format!(" @ {s:#x}-{e:#x}"),
                (Some(s), None) => format!(" @ {s:#x}"),
                _ => String::new(),
            };
            if let Some(header) = &region.header {
                text.push_str(&format!("// {:?}: {}{}\n", region.kind, header, span));
            } else {
                text.push_str(&format!("// {:?}{}\n", region.kind, span));
            }
            for stmt in region.statements.iter().take(4) {
                text.push_str(&format!("//   {stmt}\n"));
            }
        }
    }
    // annotate hot block list in regions as evidence statements on a synthetic block
    let hot_indices = select_hot_block_indices(blocks, references);
    if !hot_indices.is_empty() {
        let mut stmts = Vec::new();
        for idx in hot_indices.iter().take(12) {
            let block = &blocks[*idx];
            let score = block_hotness_score(block, *idx, references);
            stmts.push(format!(
                "hot_bb[{idx}] @ {:#x} score={score} insts={}",
                block.address,
                block.instructions.len()
            ));
        }
        // keep as comments in text
        text.push_str("\n/* hot blocks */\n");
        for s in &stmts {
            text.push_str(&format!("// {s}\n"));
        }
    }
    let mut unit = PseudocodeUnit {
        language: "c".to_string(),
        text,
        regions,
        region_artifact: None,
        evidence_ids: vec![
            format!("pseudo:{address:x}"),
            format!("pseudo:{address:x}:oversize"),
            format!("pseudo:{address:x}:hotblock"),
        ],
        semantic_lattice: None,
    };
    if unit.regions.is_empty() {
        unit.regions = fast.regions;
    }
    finalize_pseudocode_unit_with_context(name, address, unit, references, function_symbols)
}

fn render_pseudocode(
    name: &str,
    address: u64,
    blocks: &[BasicBlock],
    arguments: &[Variable],
    locals: &[Variable],
    imports: &[revx_core::Import],
    call_target_overrides: &HashMap<u64, u64>,
    debug_hint: Option<&DebugFunctionHint>,
    profile: AnalysisProfile,
    strings: &[revx_core::StringLiteral],
) -> PseudocodeUnit {
    let signature_args = if arguments.is_empty() {
        "void".to_string()
    } else {
        arguments
            .iter()
            .map(|arg| {
                format!(
                    "{} {}",
                    arg.type_name
                        .clone()
                        .unwrap_or_else(|| "unknown_t".to_string()),
                    arg.name
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let return_type = debug_hint
        .and_then(|hint| hint.return_type.clone())
        .unwrap_or_else(|| "int".to_string());
    let regions = build_regions(
        address,
        blocks,
        arguments,
        locals,
        imports,
        call_target_overrides,
        profile,
        strings,
    );
    let mut body_lines = Vec::new();

    if !locals.is_empty() {
        for local in locals {
            let comment = local
                .type_name
                .as_deref()
                .filter(|kind| {
                    matches!(
                        *kind,
                        "stack_array_t" | "stack_buffer_t" | "stack_workspace_t" | "stack_span_t"
                    )
                })
                .map(|_| format!(" /* {} */", local.location))
                .unwrap_or_default();
            body_lines.push(format!(
                "    {} {};{}",
                local
                    .type_name
                    .clone()
                    .unwrap_or_else(|| "unknown_t".to_string()),
                local.name,
                comment
            ));
        }
        body_lines.push(String::new());
    }

    for region in &regions {
        render_region(region, 1, &mut body_lines);
    }

    if body_lines.is_empty() {
        body_lines.push("    return 0;".to_string());
    }

    let evidence_ids = vec![format!("pseudo:{address:x}")];
    finalize_pseudocode_unit(
        name,
        address,
        PseudocodeUnit {
            language: "c".to_string(),
            text: format!(
                "{} {}({}) {{
{}
}}",
                return_type,
                sanitize_symbol(name),
                signature_args,
                body_lines.join("
")
            ),
            regions,
            region_artifact: None,
            evidence_ids,
            semantic_lattice: None,
        },
    )
}

fn build_regions(
    address: u64,
    blocks: &[BasicBlock],
    arguments: &[Variable],
    locals: &[Variable],
    imports: &[revx_core::Import],
    call_target_overrides: &HashMap<u64, u64>,
    profile: AnalysisProfile,
    strings: &[revx_core::StringLiteral],
) -> Vec<PseudocodeRegion> {
    let mut out = Vec::new();
    if blocks.is_empty() {
        return out;
    }

    let first_block = &blocks[0];
    let arm64_regions = build_arm64_regions(
        address,
        blocks,
        arguments,
        locals,
        imports,
        call_target_overrides,
        strings,
    );
    let structured_has_loop = arm64_regions
        .iter()
        .any(|region| region.kind == RegionKind::Loop);
    let structured_has_if = arm64_regions
        .iter()
        .any(|region| region.kind == RegionKind::If);
    let has_conditional = blocks.iter().any(|block| {
        block.instructions.iter().any(|inst| {
            let text = inst.text.as_ref();
            (text.starts_with('j') && !text.starts_with("jmp"))
                || text.starts_with("b.")
                || text.starts_with("cbz ")
                || text.starts_with("cbnz ")
                || text.starts_with("tbz ")
                || text.starts_with("tbnz ")
        })
    });
    let has_loop = blocks.len() > 1
        && blocks.iter().any(|block| {
            block
                .instructions
                .iter()
                .any(|inst| is_backward_control_transfer(inst))
        });
    let switch_region = detect_switch_region(address, blocks);

    if !arm64_regions.is_empty() {
        out.extend(arm64_regions);
    } else if let Some(switch) = switch_region {
        out.push(switch);
    } else if has_conditional {
        let header = arm64_semantic_if_header(blocks)
            .or_else(|| x64_semantic_if_header(blocks))
            .unwrap_or_else(|| "if (cond)".to_string());
        let stmts = collect_region_body_statements(blocks, 6);
        out.push(PseudocodeRegion {
            id: format!("region:{address:x}:if"),
            kind: RegionKind::If,
            start_address: Some(first_block.address),
            end_address: Some(first_block.address + first_block.size),
            header: Some(header),
            statements: if stmts.is_empty() {
                vec!["/* conditional branch recovered */".to_string()]
            } else {
                stmts
            },
            children: Vec::new(),
            evidence_ids: vec![format!("pseudo:{address:x}:if")],
        });
    }

    if has_loop && !structured_has_loop && !out.iter().any(|r| r.kind == RegionKind::Loop) {
        let header = x64_semantic_loop_header(blocks)
            .or_else(|| Some("while (cond)".to_string()))
            .unwrap();
        out.push(PseudocodeRegion {
            id: format!("region:{address:x}:loop"),
            kind: RegionKind::Loop,
            start_address: Some(first_block.address),
            end_address: blocks.last().map(|block| block.address + block.size),
            header: Some(header),
            statements: collect_region_body_statements(blocks, 8),
            children: Vec::new(),
            evidence_ids: vec![format!("pseudo:{address:x}:loop")],
        });
    }

    let return_stmt = if let Some(stmt) = infer_arm64_return_statement(blocks, call_target_overrides)
    {
        stmt.to_string()
    } else if let Some(stmt) = infer_x64_return_statement(blocks) {
        stmt
    } else if profile == AnalysisProfile::Full {
        "return result;".to_string()
    } else {
        "return 0;".to_string()
    };
    out.push(PseudocodeRegion {
        id: format!("region:{address:x}:return"),
        kind: RegionKind::Return,
        start_address: blocks.last().map(|block| block.address),
        end_address: blocks.last().map(|block| block.address + block.size),
        header: None,
        statements: vec![return_stmt],
        children: Vec::new(),
        evidence_ids: vec![format!("pseudo:{address:x}:return")],
    });

    if out.len() == 1 && !structured_has_if {
        out.insert(
            0,
            PseudocodeRegion {
                id: format!("region:{address:x}:block"),
                kind: RegionKind::Block,
                start_address: Some(first_block.address),
                end_address: blocks.last().map(|block| block.address + block.size),
                header: None,
                statements: collect_region_body_statements(blocks, 4),
                children: Vec::new(),
                evidence_ids: vec![format!("pseudo:{address:x}:block")],
            },
        );
    }

    out
}

fn collect_region_body_statements(blocks: &[BasicBlock], limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    for block in blocks {
        for inst in &block.instructions {
            if out.len() >= limit {
                return out;
            }
            let text = inst.text.as_ref();
            if text.starts_with("nop") || text == "ret" || text.starts_with("endbr") {
                continue;
            }
            if text.starts_with("call ") || text.starts_with("bl ") {
                out.push(format!("call({});", text.split_whitespace().nth(1).unwrap_or("fn")));
            } else if text.starts_with("mov ") || text.starts_with("lea ") || text.starts_with("ldr ") {
                out.push(format!("/* {text} */"));
            }
        }
    }
    out
}

fn detect_switch_region(address: u64, blocks: &[BasicBlock]) -> Option<PseudocodeRegion> {
    let mut case_targets = BTreeSet::new();
    let mut has_bounds = false;
    let mut has_jump_table = false;
    for block in blocks {
        for inst in &block.instructions {
            let text = inst.text.as_ref().to_ascii_lowercase();
            if text.contains("cmp ") || text.contains("subs ") {
                has_bounds = true;
            }
            if text.contains("jmp ") && (text.contains("[") || text.contains("table")) {
                has_jump_table = true;
            }
            if (text.starts_with("b.") || (text.starts_with('j') && !text.starts_with("jmp")))
                && let Some(target) = parse_control_target(inst.address, inst.text.as_ref())
                    .or_else(|| parse_relative_target(inst.address, inst.text.as_ref()))
            {
                case_targets.insert(target);
            }
        }
    }
    if !(has_jump_table || (has_bounds && case_targets.len() >= 3)) {
        return None;
    }
    let mut statements = case_targets
        .iter()
        .take(12)
        .enumerate()
        .map(|(i, t)| format!("case {i}: goto {t:#x};"))
        .collect::<Vec<_>>();
    if statements.is_empty() {
        statements.push("/* switch dispatch */".to_string());
    }
    Some(PseudocodeRegion {
        id: format!("region:{address:x}:switch"),
        kind: RegionKind::Switch,
        start_address: blocks.first().map(|b| b.address),
        end_address: blocks.last().map(|b| b.address + b.size),
        header: Some("switch (value)".to_string()),
        statements,
        children: Vec::new(),
        evidence_ids: vec![format!("pseudo:{address:x}:switch")],
    })
}

fn x64_semantic_if_header(blocks: &[BasicBlock]) -> Option<String> {
    for block in blocks {
        let texts: Vec<&str> = block.instructions.iter().map(|i| i.text.as_ref()).collect();
        for window in texts.windows(2) {
            let cmp = window[0].to_ascii_lowercase();
            let jcc = window[1].to_ascii_lowercase();
            if !(cmp.starts_with("cmp ") || cmp.starts_with("test ")) {
                continue;
            }
            if !(jcc.starts_with('j') && !jcc.starts_with("jmp")) {
                continue;
            }
            let operand = cmp.split_whitespace().skip(1).collect::<Vec<_>>().join(" ");
            let parts = operand.split(',').map(str::trim).collect::<Vec<_>>();
            if parts.len() < 2 {
                continue;
            }
            let lhs = parts[0].trim_matches(|c| c == '[' || c == ']');
            let rhs = parts[1].trim_matches(|c| c == '[' || c == ']');
            let cond = if jcc.starts_with("je") || jcc.starts_with("jz") {
                format!("{lhs} == {rhs}")
            } else if jcc.starts_with("jne") || jcc.starts_with("jnz") {
                format!("{lhs} != {rhs}")
            } else if jcc.starts_with("jl") || jcc.starts_with("jb") {
                format!("{lhs} < {rhs}")
            } else if jcc.starts_with("jle") || jcc.starts_with("jbe") {
                format!("{lhs} <= {rhs}")
            } else if jcc.starts_with("jg") || jcc.starts_with("ja") {
                format!("{lhs} > {rhs}")
            } else if jcc.starts_with("jge") || jcc.starts_with("jae") {
                format!("{lhs} >= {rhs}")
            } else {
                format!("{lhs} ? {rhs}")
            };
            return Some(format!("if ({cond})"));
        }
    }
    None
}

fn x64_semantic_loop_header(blocks: &[BasicBlock]) -> Option<String> {
    for block in blocks.iter().rev() {
        for inst in block.instructions.iter().rev() {
            if is_backward_control_transfer(inst) {
                let text = inst.text.as_ref().to_ascii_lowercase();
                if text.starts_with("jmp") {
                    return Some("while (true)".to_string());
                }
                return Some("while (cond)".to_string());
            }
        }
    }
    None
}

fn infer_x64_return_statement(blocks: &[BasicBlock]) -> Option<String> {
    for block in blocks.iter().rev() {
        for inst in block.instructions.iter().rev() {
            let text = inst.text.as_ref().to_ascii_lowercase();
            if text == "ret" || text.starts_with("ret ") {
                continue;
            }
            if text.starts_with("mov eax,") || text.starts_with("mov rax,") {
                let rhs = text.split(',').nth(1)?.trim();
                return Some(format!("return {rhs};"));
            }
            if text.starts_with("xor eax, eax") || text.starts_with("xor rax, rax") {
                return Some("return 0;".to_string());
            }
            if text.starts_with("call ") {
                return Some("return result;".to_string());
            }
            break;
        }
    }
    None
}

fn build_arm64_regions(
    address: u64,
    blocks: &[BasicBlock],
    arguments: &[Variable],
    locals: &[Variable],
    imports: &[revx_core::Import],
    call_target_overrides: &HashMap<u64, u64>,
    strings: &[revx_core::StringLiteral],
) -> Vec<PseudocodeRegion> {
    let block_map = blocks
        .iter()
        .map(|block| (block.address, block))
        .collect::<BTreeMap<_, _>>();
    let mut consumed = BTreeSet::new();
    let mut out = Vec::new();
    for (block_index, block) in blocks.iter().enumerate() {
        if consumed.contains(&block.address) {
            continue;
        }

        let statements = build_arm64_semantic_statements_with_strings(
            std::slice::from_ref(block),
            arguments,
            locals,
            imports,
            call_target_overrides,
            strings,
        );
        if statements.is_empty() {
            continue;
        }

        if let Some((header, true_target, _false_target)) = arm64_block_condition(block) {
            let mut prelude = Vec::new();
            for statement in &statements {
                if !statement.starts_with("if (") && !statement.starts_with("return ") {
                    prelude.push(statement.clone());
                }
            }
            if !prelude.is_empty() {
                out.push(PseudocodeRegion {
                    id: format!("region:{address:x}:block:{block_index}:pre"),
                    kind: RegionKind::Block,
                    start_address: Some(block.address),
                    end_address: Some(block.address + block.size),
                    header: None,
                    statements: prelude,
                    children: Vec::new(),
                    evidence_ids: vec![format!("pseudo:{address:x}:block:{block_index}:pre")],
                });
            }

            let target_block = block_map.get(&true_target).copied();
            let body = target_block
                .map(|next_block| {
                    build_arm64_semantic_statements_with_strings(
                        std::slice::from_ref(next_block),
                        arguments,
                        locals,
                        imports,
                        call_target_overrides,
                        strings,
                    )
                })
                .unwrap_or_default();
            let mut filtered_body = Vec::new();
            for statement in body {
                if !statement.starts_with("if (") && !statement.starts_with("return ") {
                    filtered_body.push(statement);
                }
            }
            if let Some(next_block) = target_block {
                if next_block
                    .instructions
                    .last()
                    .map(|inst| inst.text.eq_ignore_ascii_case("ret"))
                    .unwrap_or(false)
                {
                    filtered_body.push("return result;".to_string());
                }
            }
            if !filtered_body.is_empty() {
                consumed.insert(true_target);
            }
            out.push(PseudocodeRegion {
                id: format!("region:{address:x}:if:{block_index}"),
                kind: RegionKind::If,
                start_address: Some(block.address),
                end_address: Some(block.address + block.size),
                header: Some(header),
                statements: if filtered_body.is_empty() {
                    vec!["/* conditional branch recovered */".to_string()]
                } else {
                    filtered_body
                },
                children: Vec::new(),
                evidence_ids: vec![format!("pseudo:{address:x}:if:{block_index}")],
            });
            continue;
        }

        let mut non_return_statements = Vec::new();
        for statement in &statements {
            if !statement.starts_with("return ") {
                non_return_statements.push(statement.clone());
            }
        }
        if non_return_statements.is_empty() {
            continue;
        }

        if arm64_block_has_backward_jump(block) {
            out.push(PseudocodeRegion {
                id: format!("region:{address:x}:loop:{block_index}"),
                kind: RegionKind::Loop,
                start_address: Some(block.address),
                end_address: Some(block.address + block.size),
                header: Some("while (cond)".to_string()),
                statements: non_return_statements,
                children: Vec::new(),
                evidence_ids: vec![format!("pseudo:{address:x}:loop:{block_index}")],
            });
            consumed.insert(block.address);
            continue;
        }

        out.push(PseudocodeRegion {
            id: format!("region:{address:x}:block:{block_index}"),
            kind: RegionKind::Block,
            start_address: Some(block.address),
            end_address: Some(block.address + block.size),
            header: None,
            statements: non_return_statements,
            children: Vec::new(),
            evidence_ids: vec![format!("pseudo:{address:x}:block:{block_index}")],
        });
    }
    out
}

fn arm64_block_condition(block: &BasicBlock) -> Option<(String, u64, u64)> {
    let last = block.instructions.last()?;
    let text = last.text.as_ref();
    let true_target = parse_relative_target(last.address, &text)?;
    let false_target = last.address + inst_len(last) as u64;

    if text.starts_with("cbnz x0") {
        return Some(("if (result != 0)".to_string(), true_target, false_target));
    }
    if text.starts_with("cbz x0") {
        return Some(("if (result == 0)".to_string(), true_target, false_target));
    }
    if text.starts_with("tbz ") || text.starts_with("tbnz ") || text.starts_with("b.") {
        return Some(("if (cond)".to_string(), true_target, false_target));
    }

    None
}

fn is_backward_control_transfer(inst: &Instruction) -> bool {
    let text = inst.text.as_ref();
    let is_ctrl = text.starts_with("b ")
        || text.starts_with("b.")
        || text.starts_with("cbz ")
        || text.starts_with("cbnz ")
        || text.starts_with("tbz ")
        || text.starts_with("tbnz ")
        || text.starts_with("jmp ")
        || (text.starts_with('j') && !text.starts_with("jmp"));
    if !is_ctrl {
        return false;
    }
    parse_control_target(inst.address, text)
        .or_else(|| parse_relative_target(inst.address, text))
        .map(|target| target < inst.address)
        .unwrap_or(false)
}

fn arm64_block_has_backward_jump(block: &BasicBlock) -> bool {
    let Some(last) = block.instructions.last() else {
        return false;
    };
    let text = last.text.as_ref();
    text.starts_with("b ")
        && parse_control_target(last.address, &text)
            .map(|target| target < last.address)
            .unwrap_or(false)
}

fn looks_like_arm64_trampoline_fragment(
    instructions: &[Instruction],
    references: &[Reference],
) -> bool {
    if instructions.len() > 4 {
        return false;
    }
    let call_count = references
        .iter()
        .filter(|reference| reference.kind == ReferenceKind::Call)
        .count();
    let has_ret = instructions
        .iter()
        .any(|inst| inst.text.eq_ignore_ascii_case("ret"));
    let has_prologue = instructions.iter().any(|inst| {
        let text = inst.text.as_ref();
        text.starts_with("paciasp")
            || text.starts_with("stp x29, x30")
            || text.starts_with("mov x29, sp")
    });
    let has_only_trivial_body = instructions.iter().all(|inst| {
        let text = inst.text.as_ref();
        text == "ret"
            || text.starts_with("paciasp")
            || text.starts_with("stp x29, x30")
            || text.starts_with("mov x29, sp")
            || text.starts_with("ldp x29, x30")
            || text.starts_with("autiasp")
            || text.starts_with("bl ")
    });

    has_ret && has_prologue && has_only_trivial_body && call_count <= 1
}

fn looks_like_arm64_branch_thunk(instructions: &[Instruction], references: &[Reference]) -> bool {
    if instructions.is_empty() || instructions.len() > 3 {
        return false;
    }

    let mut jump_count = 0usize;
    let mut call_count = 0usize;
    for reference in references {
        match reference.kind {
            ReferenceKind::Jump => jump_count += 1,
            ReferenceKind::Call => call_count += 1,
            _ => {}
        }
    }
    if jump_count != 1 || call_count != 0 {
        return false;
    }

    let Some(last) = instructions.last() else {
        return false;
    };
    if !last.text.starts_with("b ") {
        return false;
    }

    instructions[..instructions.len().saturating_sub(1)]
        .iter()
        .all(|inst| {
            let text = inst.text.as_ref();
            text.starts_with("bti ") || is_arm64_padding_text(text) || text.starts_with("nop")
        })
}

/// Apply heuristic naming to unnamed functions (sub_XXXX).
///
/// Naming strategies (in priority order):
/// 1. Tail-call thunk: function with a single `b <addr>` → `thunk_<target>`
/// 2. Wrapper: function with a single call to a known function → `wrapper_<func>`
/// 3. String-reference: function referencing a notable string → `str_<slug>`
/// 4. API pattern: function calling specific API combinations → descriptive name
fn apply_heuristic_naming(function: &mut Function) {
    if !function.name.starts_with("sub_") {
        return;
    }

    let mut inst_count = 0usize;
    let mut call_count = 0usize;
    let mut single_call_text: Option<&str> = None;
    let mut branch_target: Option<u64> = None;
    let mut calls_print = false;
    let mut calls_pthread_create = false;
    let mut calls_abort = false;

    for inst in function
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
    {
        inst_count += 1;
        let text = inst.text.as_ref();
        let is_call = text.starts_with("bl ") || text.starts_with("call ");
        if is_call {
            call_count += 1;
            if call_count == 1 {
                single_call_text = Some(text);
            } else {
                single_call_text = None;
            }
            if text.contains("printf")
                || text.contains("puts")
                || text.contains("fprintf")
                || text.contains("__android_log")
            {
                calls_print = true;
            }
            if text.contains("pthread_create") {
                calls_pthread_create = true;
            }
            if text.contains("abort")
                || text.contains("__stack_chk_fail")
                || text.contains("exit")
            {
                calls_abort = true;
            }
        } else if inst_count <= 3
            && text.starts_with("b ")
            && !text.starts_with("bl ")
            && !text.starts_with("b.")
        {
            if let Some(target) = parse_branch_target_text(inst.address, text) {
                branch_target = Some(target);
            }
        }
    }

    if inst_count == 0 {
        return;
    }

    if inst_count <= 3 {
        if let Some(target) = branch_target {
            function.name = format!("thunk_{target:x}");
            return;
        }
    }

    if call_count == 1 && inst_count < 20 {
        if let Some(call_text) = single_call_text {
            for (name, _, _) in KNOWN_CALL_SIGNATURES {
                if call_text.contains(name) {
                    function.name = format!("wrapper_{name}");
                    return;
                }
            }
        }
    }

    if calls_print {
        function.name = format!("log_{}", function.address);
        return;
    }
    if calls_pthread_create {
        function.name = format!("thread_starter_{}", function.address);
        return;
    }
    if calls_abort {
        function.name = format!("check_fail_{}", function.address);
    }
}

/// Parse a branch target from instruction text (e.g., "b $+0x20" → 0x1020).
fn parse_branch_target_text(address: u64, text: &str) -> Option<u64> {
    let token = text
        .split(|ch: char| ch.is_whitespace() || ch == ',')
        .filter(|token| !token.is_empty())
        .next_back()?;
    let token = token.trim_end_matches(|ch: char| ch == ']' || ch == '!' || ch == ';');
    if let Some(offset) = token.strip_prefix("$+") {
        return parse_signed_imm_text(offset).map(|imm| address.saturating_add_signed(imm));
    }
    if let Some(offset) = token.strip_prefix("$-") {
        return parse_signed_imm_text(offset).map(|imm| address.saturating_sub(imm as u64));
    }
    u64::from_str_radix(token.trim_start_matches("0x"), 16).ok()
}

fn parse_signed_imm_text(raw: &str) -> Option<i64> {
    let value = raw.trim();
    if let Some(hex) = value.strip_prefix("-0x") {
        i64::from_str_radix(hex, 16).ok().map(|num| -num)
    } else if let Some(hex) = value.strip_prefix("0x") {
        i64::from_str_radix(hex, 16).ok()
    } else {
        value.parse().ok()
    }
}

fn deepen_function_quality(function: &mut Function, import_types: &[String]) {
    if let Some(matched) = import_types
        .iter()
        .find(|ty| ty.eq_ignore_ascii_case(&function.name) || function.name.contains(ty.as_str()))
    {
        for argument in &mut function.arguments {
            if argument.type_name.is_none() && argument.name.contains("ctx") {
                argument.type_name = Some(format!("{matched} *"));
                argument.confidence = argument.confidence.max(0.55);
            }
        }
    }

    let call_info = analyze_function_calls(function);
    if let Some(ref info) = call_info {
        // Wrapper detection: function has exactly one call, small body, and passes through return.
        if info.is_wrapper {
            function.warnings.push("wrapper_function".to_string());
        }
        // Propagate parameter types from known import calls.
        if !info.inferred_arg_types.is_empty() {
            for (idx, ty) in &info.inferred_arg_types {
                if let Some(arg) = function.arguments.get_mut(*idx) {
                    if arg.type_name.is_none() || arg.type_name.as_deref() == Some("int") {
                        arg.type_name = Some(ty.clone());
                        arg.confidence = arg.confidence.max(0.7);
                    }
                }
            }
        }
    }

    // 3. Enrich pseudocode with call annotations.
    if let Some(pseudocode) = &mut function.pseudocode {
        if let Some(ref info) = call_info {
            // Add call annotations as comments in pseudocode text.
            for annotation in &info.call_annotations {
                pseudocode.text = format!("{}\n// {}", pseudocode.text, annotation);
            }
            // If wrapper, annotate in pseudocode.
            if info.is_wrapper && !info.called_names.is_empty() {
                let wrapper_note = format!(
                    "// wrapper: delegates to {}",
                    info.called_names.join(", ")
                );
                pseudocode.text = format!("{}\n{}", wrapper_note, pseudocode.text);
            }
        }

        // 4. Loop detection based on back-edges (not just block count).
        let has_back_edge = function.blocks.iter().any(|block| {
            block.instructions.iter().any(|inst| {
                let text = inst.text.as_ref();
                (text.starts_with("b ") || text.starts_with("cbz ") || text.starts_with("cbnz ")
                    || text.starts_with("b.") || text.starts_with("tbz ") || text.starts_with("tbnz "))
                    && text.contains("$-")
            })
        });
        if has_back_edge
            && !pseudocode.regions.iter().any(|r| r.kind == RegionKind::Loop)
        {
            pseudocode.regions.push(PseudocodeRegion {
                id: format!("region:{:x}:loop", function.address),
                kind: RegionKind::Loop,
                start_address: Some(function.address),
                end_address: Some(function.address + function.size),
                header: Some("do { ... } while (cond)".to_string()),
                statements: vec!["/* loop detected via back-edge */".to_string()],
                children: Vec::new(),
                evidence_ids: vec![format!("pseudo:{:x}:loop", function.address)],
            });
        }
    }

    // 5. Complexity analysis warnings.
    let block_count = function.blocks.len();
    let inst_count: usize = function.blocks.iter().map(|b| b.instructions.len()).sum();
    if block_count > 50 {
        function.warnings.push(format!("high_block_count:{block_count}"));
    }
    if inst_count > 500 {
        function.warnings.push(format!("high_instruction_count:{inst_count}"));
    }

    // 6. Obfuscation pattern detection.
    let obf_patterns = detect_obfuscation_patterns(function);
    for pattern in obf_patterns {
        function.warnings.push(pattern);
    }
}

/// Detect common obfuscation patterns in a function.
///
/// Patterns detected:
/// - `xor_decrypt_loop`: XOR-based string decryption loop (eor with immediate in a loop)
/// - `add_decrypt_loop`: ADD/SUB-based decryption loop
/// - `rol_decrypt_loop`: ROL/ROR-based decryption loop
/// - `opaque_predicate`: Potential opaque predicate (always-true/false condition)
/// - `dead_code`: Dead code injection (int3/nop sequences between real instructions)
/// - `control_flow_flattening`: Potential control flow flattening (many indirect branches to a dispatcher)
fn detect_obfuscation_patterns(function: &Function) -> Vec<String> {
    let mut patterns = Vec::new();

    let mut has_eor_imm = false;
    let mut has_add_imm_loop = false;
    let mut has_loop = false;
    let mut indirect_branch_count = 0usize;
    let mut nop_count = 0usize;
    let mut int3_count = 0usize;
    let mut cmp_zero_always_true = false;

    for block in &function.blocks {
        // Check for back-edges (loop detection).
        for inst in &block.instructions {
            let text = inst.text.as_ref();
            if (text.starts_with("b ") || text.starts_with("cbz ") || text.starts_with("cbnz ")
                || text.starts_with("b.") || text.starts_with("tbz ") || text.starts_with("tbnz "))
                && text.contains("$-")
            {
                has_loop = true;
            }

            // XOR with immediate (string decryption pattern).
            if text.starts_with("eor ") && text.contains("#0x") {
                has_eor_imm = true;
            }

            // ADD/SUB with immediate in a loop context.
            if (text.starts_with("add ") || text.starts_with("sub ")) && text.contains("#0x") {
                has_add_imm_loop = true;
            }

            // Indirect branches (control flow flattening indicator).
            if text.starts_with("br x") && !text.starts_with("blr ") {
                indirect_branch_count += 1;
            }

            // NOP sleds.
            if text == "nop" {
                nop_count += 1;
            }

            // INT3 / BRK padding (x64: int3, arm64: brk).
            if text.starts_with("brk ") || text == "int3" || text == "ud2" {
                int3_count += 1;
            }

            // Opaque predicate: cmp reg, #0 + b.eq (always true).
            if text.starts_with("cmp ") && (text.contains("#0x0") || text.contains("#0") || text.contains(", #0")) {
                cmp_zero_always_true = true;
            }
        }
    }

    // XOR decryption loop.
    if has_eor_imm && has_loop {
        patterns.push("xor_decrypt_loop".to_string());
    }

    // ADD/SUB decryption loop.
    if has_add_imm_loop && has_loop && function.blocks.len() > 3 {
        patterns.push("add_decrypt_loop".to_string());
    }

    // Control flow flattening: multiple indirect branches suggest a dispatcher.
    if indirect_branch_count >= 2 {
        patterns.push(format!("control_flow_flattening:{indirect_branch_count}"));
    }

    // Dead code injection.
    if nop_count > 10 || int3_count > 5 {
        patterns.push(format!("dead_code:nop={nop_count},brk={int3_count}"));
    }

    // Opaque predicate (weak heuristic).
    if cmp_zero_always_true && has_loop {
        patterns.push("opaque_predicate".to_string());
    }

    patterns
}

/// Information gathered by analyzing call instructions within a function.
#[derive(Default)]
struct CallAnalysisInfo {
    is_wrapper: bool,
    called_names: Vec<String>,
    call_annotations: Vec<String>,
    /// (argument_index, inferred_type) pairs from known import signatures.
    inferred_arg_types: Vec<(usize, String)>,
}

/// Analyze call instructions in a function to detect patterns and infer types.
fn analyze_function_calls(function: &Function) -> Option<CallAnalysisInfo> {
    let mut call_count = 0usize;
    let mut called_names = Vec::new();
    let mut call_annotations = Vec::new();
    let mut inferred_arg_types: Vec<(usize, String)> = Vec::new();

    for block in &function.blocks {
        for inst in &block.instructions {
            let text = inst.text.as_ref();
            if !text.starts_with("bl ") && !text.starts_with("call ") {
                continue;
            }
            call_count += 1;
            // Try to match against known import function names.
            for (name, ret_ty, arg_types) in KNOWN_CALL_SIGNATURES {
                if text.contains(name) {
                    called_names.push(name.to_string());
                    call_annotations.push(format!(
                        "call {} at 0x{:x} -> {}",
                        name, inst.address, ret_ty
                    ));
                    // Propagate argument types: if this function passes its arguments
                    // to a known function, we can infer their types.
                    for (arg_idx, arg_ty) in arg_types.iter().enumerate() {
                        inferred_arg_types.push((arg_idx, arg_ty.to_string()));
                    }
                    break;
                }
            }
        }
    }

    // Wrapper detection: exactly one call, small function (< 20 instructions).
    let total_insts: usize = function.blocks.iter().map(|b| b.instructions.len()).sum();
    let is_wrapper = call_count == 1 && total_insts < 20 && !called_names.is_empty();

    if call_count == 0 && called_names.is_empty() && total_insts == 0 {
        return None;
    }

    Some(CallAnalysisInfo {
        is_wrapper,
        called_names,
        call_annotations,
        inferred_arg_types,
    })
}

/// Known library function signatures for type propagation.
/// (function_name, return_type, argument_types[])
const KNOWN_CALL_SIGNATURES: &[(&str, &str, &[&str])] = &[
    ("malloc", "void *", &["size_t"]),
    ("calloc", "void *", &["size_t", "size_t"]),
    ("realloc", "void *", &["void *", "size_t"]),
    ("free", "void", &["void *"]),
    ("memcpy", "void *", &["void *", "const void *", "size_t"]),
    ("memmove", "void *", &["void *", "const void *", "size_t"]),
    ("memset", "void *", &["void *", "int", "size_t"]),
    ("memcmp", "int", &["const void *", "const void *", "size_t"]),
    ("strlen", "size_t", &["const char *"]),
    ("strcmp", "int", &["const char *", "const char *"]),
    ("strncmp", "int", &["const char *", "const char *", "size_t"]),
    ("strcpy", "char *", &["char *", "const char *"]),
    ("strncpy", "char *", &["char *", "const char *", "size_t"]),
    ("strcat", "char *", &["char *", "const char *"]),
    ("strncat", "char *", &["char *", "const char *", "size_t"]),
    ("strstr", "char *", &["const char *", "const char *"]),
    ("strchr", "char *", &["const char *", "int"]),
    ("strrchr", "char *", &["const char *", "int"]),
    ("strdup", "char *", &["const char *"]),
    ("strndup", "char *", &["const char *", "size_t"]),
    ("atoi", "int", &["const char *"]),
    ("atol", "long", &["const char *"]),
    ("atoll", "long long", &["const char *"]),
    ("strtol", "long", &["const char *", "char **", "int"]),
    ("strtoul", "unsigned long", &["const char *", "char **", "int"]),
    ("printf", "int", &["const char *"]),
    ("fprintf", "int", &["void *", "const char *"]),
    ("sprintf", "int", &["char *", "const char *"]),
    ("snprintf", "int", &["char *", "size_t", "const char *"]),
    ("puts", "int", &["const char *"]),
    ("fputs", "int", &["const char *", "void *"]),
    ("fopen", "void *", &["const char *", "const char *"]),
    ("fclose", "int", &["void *"]),
    ("fread", "size_t", &["void *", "size_t", "size_t", "void *"]),
    ("fwrite", "size_t", &["const void *", "size_t", "size_t", "void *"]),
    ("fseek", "int", &["void *", "long", "int"]),
    ("ftell", "long", &["void *"]),
    ("open", "int", &["const char *", "int"]),
    ("close", "int", &["int"]),
    ("read", "ssize_t", &["int", "void *", "size_t"]),
    ("write", "ssize_t", &["int", "const void *", "size_t"]),
    ("pthread_create", "int", &["void *", "const void *", "void *", "void *"]),
    ("pthread_join", "int", &["void *", "void **"]),
    ("pthread_mutex_init", "int", &["void *", "const void *"]),
    ("pthread_mutex_lock", "int", &["void *"]),
    ("pthread_mutex_unlock", "int", &["void *"]),
    ("pthread_mutex_destroy", "int", &["void *"]),
    ("__android_log_print", "int", &["int", "const char *", "const char *"]),
    ("__android_log_write", "int", &["int", "const char *", "const char *"]),
    ("dlopen", "void *", &["const char *", "int"]),
    ("dlsym", "void *", &["void *", "const char *"]),
    ("dlclose", "int", &["void *"]),
    ("getenv", "char *", &["const char *"]),
    ("setenv", "int", &["const char *", "const char *", "int"]),
    ("setlocale", "char *", &["int", "const char *"]),
    ("compat_mode", "int", &["const char *", "const char *"]),
    ("isatty", "int", &["int"]),
    ("ioctl", "int", &["int", "unsigned long", "void *"]),
    ("strtonum", "long long", &["const char *", "long long", "long long"]),
    ("socket", "int", &["int", "int", "int"]),
    ("connect", "int", &["int", "const void *", "int"]),
    ("send", "ssize_t", &["int", "const void *", "size_t", "int"]),
    ("recv", "ssize_t", &["int", "void *", "size_t", "int"]),
];

fn render_region(region: &PseudocodeRegion, indent: usize, out: &mut Vec<String>) {
    let prefix = "    ".repeat(indent);
    match region.kind {
        RegionKind::If | RegionKind::Loop | RegionKind::Switch => {
            out.push(format!(
                "{prefix}{} {{",
                region
                    .header
                    .clone()
                    .unwrap_or_else(|| "/* region */".to_string())
            ));
            for statement in &region.statements {
                render_statement_line(statement, indent + 1, out);
            }
            for child in &region.children {
                render_region(child, indent + 1, out);
            }
            out.push(format!("{prefix}}}"));
        }
        RegionKind::Return => {
            for statement in &region.statements {
                render_statement_line(statement, indent, out);
            }
        }
        RegionKind::Block => {
            for statement in &region.statements {
                render_statement_line(statement, indent, out);
            }
        }
    }
}

fn render_statement_line(statement: &str, indent: usize, out: &mut Vec<String>) {
    let prefix = "    ".repeat(indent);
    let trimmed = statement.trim();
    if trimmed.is_empty() {
        out.push(String::new());
        return;
    }

    if trimmed == "callback();" {
        out.push(format!("{prefix}callback();"));
        return;
    }
    if trimmed.starts_with("if (") {
        out.push(format!("{prefix}{trimmed}"));
        return;
    }
    if trimmed.starts_with("return ") || trimmed.starts_with("result = ") || trimmed.ends_with(");")
    {
        out.push(format!("{prefix}{trimmed}"));
        return;
    }

    out.push(format!("{prefix}{trimmed}"));
}

fn build_arm64_semantic_statements(
    blocks: &[BasicBlock],
    arguments: &[Variable],
    locals: &[Variable],
    imports: &[revx_core::Import],
    call_target_overrides: &HashMap<u64, u64>,
) -> Vec<String> {
    build_arm64_semantic_statements_with_strings(
        blocks,
        arguments,
        locals,
        imports,
        call_target_overrides,
        &[],
    )
}

fn build_arm64_semantic_statements_with_strings(
    blocks: &[BasicBlock],
    arguments: &[Variable],
    locals: &[Variable],
    imports: &[revx_core::Import],
    call_target_overrides: &HashMap<u64, u64>,
    strings: &[revx_core::StringLiteral],
) -> Vec<String> {
    let mut statements = Vec::new();
    let mut seen = BTreeSet::new();
    let local_refs = build_arm64_semantic_local_refs(locals);
    let mut state = build_arm64_semantic_state(arguments, &local_refs);
    let string_by_addr = strings
        .iter()
        .filter_map(|string| {
            let addr = string.address?;
            Some((addr, string.value.as_str()))
        })
        .collect::<HashMap<_, _>>();

    for block in blocks {
        for inst in &block.instructions {
            let text = inst.text.as_ref();
            arm64_track_semantic_state(
                inst.address,
                text,
                &local_refs,
                &mut state,
                &string_by_addr,
            );
            let Some(statement) = arm64_semantic_statement(
                inst.address,
                text,
                &state,
                imports,
                call_target_overrides,
            ) else {
                continue;
            };
            if seen.insert(statement.clone()) {
                statements.push(statement);
            }
            if text.starts_with("bl ") {
                arm64_apply_call_effects(&mut state);
            }
        }
    }

    statements
}

fn arm64_semantic_statement(
    address: u64,
    text: &str,
    state: &Arm64SemanticState,
    imports: &[revx_core::Import],
    call_target_overrides: &HashMap<u64, u64>,
) -> Option<String> {
    if text.starts_with("bl ") {
        let target = call_target_overrides
            .get(&address)
            .copied()
            .or_else(|| parse_relative_target(address, text))?;
        let callee =
            arm64_callee_name(target, imports).unwrap_or_else(|| format_sub_addr(target));
        let bare = bare_symbol_name(&callee);
        let known = fast_known_arg_count(&callee);
        let max_args = known.unwrap_or(4);
        let args = arm64_collect_call_arguments_fixed(state, max_args, known.is_some());
        let assigns_result = matches!(
            bare,
            "malloc"
                | "calloc"
                | "realloc"
                | "strlen"
                | "strcmp"
                | "memcmp"
                | "fopen"
                | "getenv"
                | "setlocale"
                | "compat_mode"
                | "isatty"
                | "strtonum"
                | "printf"
                | "puts"
                | "atoi"
                | "atol"
                | "atoll"
                | "getuid"
                | "geteuid"
                | "getpid"
        );
        if args.is_empty() {
            return Some(if assigns_result {
                format!("result = {callee}();")
            } else {
                format!("{callee}();")
            });
        }
        return Some(if assigns_result {
            format!("result = {callee}({});", args.join(", "))
        } else {
            format!("{callee}({});", args.join(", "))
        });
    }

    if text.starts_with("cbnz x0") {
        return Some("if (result != 0)".to_string());
    }
    if text.starts_with("cbz x0") {
        return Some("if (result == 0)".to_string());
    }
    if text.starts_with("blr x0") {
        return Some("callback();".to_string());
    }
    if text.starts_with("mov w0, #") || text.starts_with("mov x0, #") {
        if let Some(value) = parse_immediate_assignment(text) {
            return Some(format!("result = {value};"));
        }
    }
    if text == "ret" {
        return Some("return result;".to_string());
    }

    // Enhanced pseudocode generation for common patterns.

    // str/stp: memory store
    if text.starts_with("str ") || text.starts_with("stp ") {
        return None; // memory writes are not rendered as high-level statements
    }

    // ldr/ldp: memory load into result register
    if text.starts_with("ldr x0") || text.starts_with("ldr w0") {
        return Some("result = *ptr;".to_string());
    }

    // cmp + conditional set
    if text.starts_with("cmp ") {
        return None; // cmp is handled by branch condition extraction
    }

    // Arithmetic on x0/w0 (result accumulation)
    if text.starts_with("add w0") || text.starts_with("add x0") {
        return Some("result += value;".to_string());
    }
    if text.starts_with("sub w0") || text.starts_with("sub x0") {
        return Some("result -= value;".to_string());
    }
    if text.starts_with("mul w0") || text.starts_with("mul x0") {
        return Some("result *= value;".to_string());
    }

    // BLR (indirect call) with register
    if text.starts_with("blr x") {
        let reg = text.split_whitespace().nth(1).unwrap_or("x0");
        return Some(format!("/* indirect call via {} */", reg));
    }

    // BR (indirect jump / switch)
    if text.starts_with("br x") {
        return Some("/* switch/jump table */".to_string());
    }

    // ADRP + ADD pattern: loading string/data address
    if text.starts_with("adrp ") {
        return None; // adrp alone is not a complete statement
    }

    // SVC (supervisor call / syscall)
    if text == "svc #0x80" || text.starts_with("svc ") {
        return Some("/* syscall */".to_string());
    }

    // BRK (breakpoint)
    if text.starts_with("brk ") {
        return Some("/* breakpoint */".to_string());
    }

    let _ = address;
    None
}

fn build_arm64_semantic_local_refs(locals: &[Variable]) -> Vec<Arm64SemanticLocalRef> {
    locals
        .iter()
        .filter_map(|local| {
            parse_stack_location_range(&local.location).map(|(start_offset, end_offset)| {
                Arm64SemanticLocalRef {
                    name: local.name.clone(),
                    start_offset,
                    end_offset,
                }
            })
        })
        .collect()
}

fn build_arm64_semantic_state(
    arguments: &[Variable],
    locals: &[Arm64SemanticLocalRef],
) -> Arm64SemanticState {
    let mut state = Arm64SemanticState::default();
    for argument in arguments {
        if argument.storage != VariableStorage::Register {
            continue;
        }
        let reg = normalize_arm64_register(&argument.location);
        if reg.starts_with('x') || reg == "sp" {
            let node = arm64_symbol_node(&mut state, argument.name.clone());
            state.values.insert(reg.clone(), node);
            if matches!(
                reg.as_bytes(),
                [b'x', b'0'..=b'7'] | [b'x', b'1', b'0'..=b'7']
            ) {
                state.prepared_args.insert(reg);
            }
        }
    }
    if let Some(root_local) = locals.iter().find(|local| local.start_offset == 0) {
        let node = arm64_symbol_node(&mut state, root_local.name.clone());
        state.values.insert("sp".to_string(), node);
    }
    state
}

fn arm64_track_semantic_state(
    address: u64,
    text: &str,
    locals: &[Arm64SemanticLocalRef],
    state: &mut Arm64SemanticState,
    string_by_addr: &HashMap<u64, &str>,
) {
    if let Some((dst, page_token)) = parse_arm64_adrp_text(text) {
        if let Some(page) = parse_arm64_relative_target(address, page_token, true) {
            let node = arm64_imm_node(state, page as i64);
            arm64_store_semantic_value(state, &dst, node);
        }
        return;
    }

    if let Some((dst, base, imm)) = parse_arm64_add_imm(text) {
        if let Some(value) = arm64_value_for_add_imm(locals, state, &base, imm) {
            let resolved = arm64_resolve_string_node(state, value, string_by_addr)
                .unwrap_or(value);
            arm64_store_semantic_value(state, &dst, resolved);
            return;
        }
    }

    if let Some((dst, base, imm)) = parse_arm64_mem_imm(text)
        && let Some(value) = arm64_value_for_memory_load(locals, state, &base, imm)
    {
        arm64_store_semantic_value(state, &dst, value);
        return;
    }

    if let Some((dst0, dst1, base, imm)) = parse_arm64_ldp_imm(text)
        && let Some((value0, value1)) = arm64_value_for_pair_load(locals, state, &base, imm)
    {
        arm64_store_semantic_value(state, &dst0, value0);
        arm64_store_semantic_value(state, &dst1, value1);
        return;
    }

    if let Some((dst, base, offset_reg)) = parse_arm64_add_reg(text)
        && let Some(value) = arm64_value_for_add_reg(state, &base, &offset_reg)
    {
        arm64_store_semantic_value(state, &dst, value);
        return;
    }

    if let Some(src) = parse_arm64_mov_alias(text)
        && let Some(value) = state.values.get(&normalize_arm64_register(&src)).cloned()
    {
        let dst = parse_arm64_mov_dst(text).unwrap_or_default();
        arm64_store_semantic_value(state, &dst, value);
        return;
    }

    if let Some((dst, imm, shift)) = parse_arm64_mov_imm_shifted(text) {
        if shift == 0 {
            let node = arm64_imm_node(state, imm as i64);
            arm64_store_semantic_value(state, &dst, node);
        } else {
            let base = state
                .values
                .get(&dst)
                .and_then(|id| match state.nodes.get(*id) {
                    Some(Arm64SemanticNode::Imm(v)) => Some(*v as u64),
                    _ => None,
                })
                .unwrap_or(0);
            let mask = if shift >= 64 {
                0u64
            } else {
                !(0xffffu64 << shift)
            };
            let next = (base & mask) | ((imm & 0xffff) << shift);
            let node = arm64_imm_node(state, next as i64);
            arm64_store_semantic_value(state, &dst, node);
        }
        return;
    }

    if let Some((dst, value)) = parse_arm64_mov_immediate(text) {
        if let Some(imm) = parse_signed_imm(&value) {
            let node = arm64_imm_node(state, imm);
            arm64_store_semantic_value(state, &dst, node);
        }
        return;
    }

    if let Some(dst) = parse_arm64_zero_move(text) {
        let node = arm64_imm_node(state, 0);
        arm64_store_semantic_value(state, &dst, node);
    }
}

fn arm64_resolve_string_node(
    state: &mut Arm64SemanticState,
    value: Arm64SemanticNodeId,
    string_by_addr: &HashMap<u64, &str>,
) -> Option<Arm64SemanticNodeId> {
    let addr = arm64_const_addr(state, value)?;
    let s = string_by_addr.get(&addr)?;
    Some(arm64_symbol_node(state, format!("{:?}", s)))
}

fn arm64_const_addr(state: &Arm64SemanticState, value: Arm64SemanticNodeId) -> Option<u64> {
    match state.nodes.get(value)? {
        Arm64SemanticNode::Imm(v) if *v >= 0 => Some(*v as u64),
        Arm64SemanticNode::AddImm { base, imm } if *imm >= 0 => {
            let base_addr = arm64_const_addr(state, *base)?;
            Some(base_addr.wrapping_add(*imm as u64))
        }
        _ => None,
    }
}

fn arm64_local_name_for_offset(locals: &[Arm64SemanticLocalRef], offset: i64) -> Option<String> {
    locals.iter().find_map(|local| {
        let end = local.end_offset.unwrap_or(local.start_offset);
        (offset >= local.start_offset && offset <= end).then(|| local.name.clone())
    })
}

fn arm64_render_call_argument(state: &Arm64SemanticState, register: &str) -> String {
    let normalized = normalize_arm64_register(register);
    state
        .values
        .get(&normalized)
        .map(|node| {
            let mut cache = state.render_cache.clone();
            arm64_render_node_cached(&state.nodes, &mut cache, *node)
        })
        .unwrap_or(normalized)
}

fn arm64_collect_call_arguments(state: &Arm64SemanticState, max_args: usize) -> Vec<String> {
    let mut highest_index = None;
    for index in 0..max_args {
        let reg = format!("x{index}");
        if state.prepared_args.contains(&reg) || state.values.contains_key(&reg) {
            highest_index = Some(index);
        }
    }
    let Some(highest_index) = highest_index else {
        return Vec::new();
    };

    (0..=highest_index)
        .map(|index| arm64_render_call_argument(state, &format!("x{index}")))
        .collect()
}

fn arm64_collect_call_arguments_fixed(
    state: &Arm64SemanticState,
    max_args: usize,
    exact: bool,
) -> Vec<String> {
    if max_args == 0 {
        return Vec::new();
    }
    if exact {
        return (0..max_args)
            .map(|index| arm64_render_call_argument(state, &format!("x{index}")))
            .collect();
    }
    let mut highest = None;
    for index in 0..max_args {
        let reg = format!("x{index}");
        if state.prepared_args.contains(&reg) || state.values.contains_key(&reg) {
            highest = Some(index);
        }
    }
    let Some(highest) = highest else {
        return Vec::new();
    };
    (0..=highest)
        .map(|index| arm64_render_call_argument(state, &format!("x{index}")))
        .collect()
}

fn arm64_apply_call_effects(state: &mut Arm64SemanticState) {
    for index in 0..18 {
        state.values.remove(&format!("x{index}"));
        state.prepared_args.remove(&format!("x{index}"));
    }
    let result = arm64_symbol_node(state, "result".to_string());
    state.values.insert("x0".to_string(), result);
}

fn arm64_store_semantic_value(
    state: &mut Arm64SemanticState,
    register: &str,
    value: Arm64SemanticNodeId,
) {
    let normalized = normalize_arm64_register(register);
    if normalized.is_empty() || normalized == "xzr" {
        return;
    }
    if normalized.starts_with('x') {
        let mark_prepared = matches!(
            normalized.as_bytes(),
            [b'x', b'0'..=b'7'] | [b'x', b'1', b'0'..=b'7']
        );
        if mark_prepared {
            state.prepared_args.insert(normalized.clone());
        }
    }
    state.values.insert(normalized, value);
}

fn arm64_value_for_add_imm(
    locals: &[Arm64SemanticLocalRef],
    state: &mut Arm64SemanticState,
    base: &str,
    imm: i64,
) -> Option<Arm64SemanticNodeId> {
    let base = normalize_arm64_register(base);
    if base == "sp" {
        return arm64_local_name_for_offset(locals, imm)
            .map(|name| arm64_find_symbol_node(state, &name))
            .or_else(|| {
                let sp = arm64_find_symbol_node(state, "sp");
                arm64_compose_add_node(state, sp, imm)
            });
    }

    let base_value = *state.values.get(&base)?;
    if arm64_node_is_local_name(state, locals, base_value) {
        return Some(base_value);
    }
    arm64_compose_add_node(state, base_value, imm).or(Some(base_value))
}

fn arm64_value_for_add_reg(
    state: &mut Arm64SemanticState,
    base: &str,
    offset_reg: &str,
) -> Option<Arm64SemanticNodeId> {
    let base = normalize_arm64_register(base);
    let offset_reg = normalize_arm64_register(offset_reg);
    let base_value = *state.values.get(&base)?;
    let offset_value = state
        .values
        .get(&offset_reg)
        .copied()
        .unwrap_or_else(|| arm64_find_symbol_node(state, &offset_reg));
    if arm64_node_is_zero(state, offset_value) {
        return Some(base_value);
    }
    arm64_compose_add_value_node(state, base_value, offset_value).or(Some(base_value))
}

fn arm64_value_for_memory_load(
    locals: &[Arm64SemanticLocalRef],
    state: &mut Arm64SemanticState,
    base: &str,
    imm: i64,
) -> Option<Arm64SemanticNodeId> {
    let base = normalize_arm64_register(base);
    if base == "sp" {
        return arm64_local_name_for_offset(locals, imm)
            .map(|name| arm64_find_symbol_node(state, &name));
    }

    let base_value = *state.values.get(&base)?;
    arm64_compose_deref_node(state, base_value, imm).or(Some(base_value))
}

fn arm64_value_for_pair_load(
    locals: &[Arm64SemanticLocalRef],
    state: &mut Arm64SemanticState,
    base: &str,
    imm: i64,
) -> Option<(Arm64SemanticNodeId, Arm64SemanticNodeId)> {
    let first = arm64_value_for_memory_load(locals, state, base, imm)?;
    let second = arm64_value_for_memory_load(locals, state, base, imm + 8)?;
    Some((first, second))
}

fn arm64_node_is_local_name(
    state: &Arm64SemanticState,
    locals: &[Arm64SemanticLocalRef],
    node: Arm64SemanticNodeId,
) -> bool {
    matches!(
        state.nodes.get(node),
        Some(Arm64SemanticNode::Symbol(name)) if locals.iter().any(|local| local.name == *name)
    )
}

fn arm64_format_add(base: &str, imm: i64) -> String {
    if imm == 0 {
        return base.to_string();
    }
    if base == "0" {
        return format!("{imm:#x}");
    }
    if let Some(base_imm) = parse_signed_imm(base) {
        return format!("{:#x}", base_imm + imm);
    }
    if imm > 0 {
        format!("{base} + {imm:#x}")
    } else {
        format!("{base} - {:#x}", imm.unsigned_abs())
    }
}

fn arm64_format_deref(base: &str, imm: i64) -> String {
    if imm == 0 {
        format!("*{base}")
    } else if imm > 0 {
        format!("*({base} + {imm:#x})")
    } else {
        format!("*({base} - {:#x})", imm.unsigned_abs())
    }
}

fn arm64_symbol_node(state: &mut Arm64SemanticState, name: String) -> Arm64SemanticNodeId {
    arm64_intern_node(state, Arm64SemanticNode::Symbol(name))
}

fn arm64_imm_node(state: &mut Arm64SemanticState, value: i64) -> Arm64SemanticNodeId {
    arm64_intern_node(state, Arm64SemanticNode::Imm(value))
}

fn arm64_intern_node(
    state: &mut Arm64SemanticState,
    node: Arm64SemanticNode,
) -> Arm64SemanticNodeId {
    if let Some(existing) = state.node_ids.get(&node).copied() {
        return existing;
    }
    let id = state.nodes.len();
    state.nodes.push(node.clone());
    state.node_ids.insert(node, id);
    id
}

fn arm64_find_symbol_node(state: &mut Arm64SemanticState, name: &str) -> Arm64SemanticNodeId {
    arm64_intern_node(state, Arm64SemanticNode::Symbol(name.to_string()))
}

fn arm64_node_is_zero(state: &Arm64SemanticState, node: Arm64SemanticNodeId) -> bool {
    matches!(state.nodes.get(node), Some(Arm64SemanticNode::Imm(0)))
}

fn arm64_compose_add_node(
    state: &mut Arm64SemanticState,
    base: Arm64SemanticNodeId,
    imm: i64,
) -> Option<Arm64SemanticNodeId> {
    if imm == 0 {
        return Some(base);
    }
    match state.nodes.get(base)? {
        Arm64SemanticNode::Imm(value) => Some(arm64_imm_node(state, value + imm)),
        Arm64SemanticNode::AddImm {
            base: inner,
            imm: existing,
        } => Some(arm64_intern_node(
            state,
            Arm64SemanticNode::AddImm {
                base: *inner,
                imm: existing + imm,
            },
        )),
        _ => Some(arm64_intern_node(
            state,
            Arm64SemanticNode::AddImm { base, imm },
        )),
    }
}

fn arm64_compose_add_value_node(
    state: &mut Arm64SemanticState,
    base: Arm64SemanticNodeId,
    offset: Arm64SemanticNodeId,
) -> Option<Arm64SemanticNodeId> {
    if arm64_node_is_zero(state, offset) {
        return Some(base);
    }
    Some(arm64_intern_node(
        state,
        Arm64SemanticNode::Add { base, offset },
    ))
}

fn arm64_compose_deref_node(
    state: &mut Arm64SemanticState,
    base: Arm64SemanticNodeId,
    imm: i64,
) -> Option<Arm64SemanticNodeId> {
    Some(arm64_intern_node(
        state,
        Arm64SemanticNode::Deref { base, imm },
    ))
}

fn arm64_render_node_cached(
    nodes: &[Arm64SemanticNode],
    cache: &mut HashMap<Arm64SemanticNodeId, String>,
    node: Arm64SemanticNodeId,
) -> String {
    if let Some(rendered) = cache.get(&node) {
        return rendered.clone();
    }

    let rendered = match &nodes[node] {
        Arm64SemanticNode::Symbol(name) => name.clone(),
        Arm64SemanticNode::Imm(value) => {
            if *value < 0 {
                format!("-0x{:x}", value.unsigned_abs())
            } else {
                format!("{:#x}", value)
            }
        }
        Arm64SemanticNode::AddImm { base, imm } => {
            arm64_format_add(&arm64_render_node_cached(nodes, cache, *base), *imm)
        }
        Arm64SemanticNode::Add { base, offset } => {
            format!(
                "{} + {}",
                arm64_render_node_cached(nodes, cache, *base),
                arm64_render_node_cached(nodes, cache, *offset)
            )
        }
        Arm64SemanticNode::Deref { base, imm } => {
            arm64_format_deref(&arm64_render_node_cached(nodes, cache, *base), *imm)
        }
    };
    cache.insert(node, rendered.clone());
    rendered
}

fn normalize_arm64_register(register: &str) -> String {
    let trimmed = register.trim().trim_end_matches('!').to_ascii_lowercase();
    if trimmed == "wzr" || trimmed == "xzr" {
        return "xzr".to_string();
    }
    if trimmed == "sp" {
        return trimmed;
    }
    if let Some(index) = trimmed.strip_prefix('w')
        && index.bytes().all(|byte| byte.is_ascii_digit())
    {
        return format!("x{index}");
    }
    trimmed
}

fn parse_arm64_mov_dst(text: &str) -> Option<String> {
    if !text.starts_with("mov ") {
        return None;
    }
    text["mov ".len()..]
        .split(',')
        .next()
        .map(str::trim)
        .map(str::to_string)
}

fn parse_arm64_mov_immediate(text: &str) -> Option<(String, String)> {
    if !text.starts_with("mov ") {
        return None;
    }
    let mut operands = text["mov ".len()..].split(',').map(str::trim);
    let dst = operands.next()?.to_string();
    let src = operands.next()?;
    if !src.starts_with('#') {
        return None;
    }
    Some((dst, src.trim_start_matches('#').to_string()))
}

fn parse_arm64_zero_move(text: &str) -> Option<String> {
    if !text.starts_with("mov ") {
        return None;
    }
    let mut operands = text["mov ".len()..].split(',').map(str::trim);
    let dst = operands.next()?.to_string();
    let src = operands.next()?;
    (src == "xzr" || src == "wzr").then_some(dst)
}

fn parse_stack_location_range(location: &str) -> Option<(i64, Option<i64>)> {
    let inner = location.strip_prefix("stack[")?.strip_suffix(']')?;
    if let Some((start, end)) = inner.split_once("..") {
        Some((parse_signed_imm(start)?, Some(parse_signed_imm(end)?)))
    } else {
        Some((parse_signed_imm(inner)?, None))
    }
}

fn parse_relative_target(address: u64, text: &str) -> Option<u64> {
    parse_control_target(address, text)
}

fn parse_control_target(address: u64, text: &str) -> Option<u64> {
    let token = text
        .split(|ch: char| ch.is_whitespace() || ch == ',')
        .filter(|token| !token.is_empty())
        .next_back()?;
    parse_arm64_relative_target(address, token, false)
}

fn arm64_semantic_if_header(blocks: &[BasicBlock]) -> Option<String> {
    for block in blocks {
        for inst in &block.instructions {
            let text = inst.text.as_ref();
            if text.starts_with("cbnz x0") {
                return Some("if (result != 0)".to_string());
            }
            if text.starts_with("cbz x0") {
                return Some("if (result == 0)".to_string());
            }
        }
    }
    None
}

fn infer_arm64_return_statement(
    blocks: &[BasicBlock],
    call_target_overrides: &HashMap<u64, u64>,
) -> Option<&'static str> {
    if looks_like_arm64_passthrough_wrapper_blocks(blocks, call_target_overrides) {
        return Some("return result;");
    }
    let has_w0_write = blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .any(|inst| {
            let text = inst.text.as_ref();
            text.starts_with("mov w0, #")
                || text.starts_with("mov x0, #")
                || text.starts_with("add w0, ")
                || text.starts_with("add x0, ")
        });
    if has_w0_write {
        Some("return result;")
    } else {
        None
    }
}

fn arm64_callee_name(target: u64, imports: &[revx_core::Import]) -> Option<String> {
    import_name_at(target, imports)
}

fn import_name_at(target: u64, imports: &[revx_core::Import]) -> Option<String> {
    imports
        .iter()
        .find(|import| import.address == Some(target))
        .map(|import| sanitize_symbol(&import.name))
}

fn parse_immediate_assignment(text: &str) -> Option<String> {
    let imm = text.split('#').nth(1)?.trim();
    let value = imm
        .split_whitespace()
        .next()
        .unwrap_or(imm)
        .trim_end_matches(',');
    Some(value.to_string())
}

fn infer_return_type(
    instructions: &[Instruction],
    call_target_overrides: &HashMap<u64, u64>,
) -> Option<String> {
    if looks_like_arm64_passthrough_wrapper(instructions, call_target_overrides) {
        return Some("int".to_string());
    }
    // Check if the function calls a known library function and passes through its return.
    for inst in instructions {
        let text = inst.text.as_ref();
        if text.starts_with("bl ") || text.starts_with("call ") {
            for (name, ty) in KNOWN_RETURN_TYPES {
                if text.contains(name) {
                    return Some(ty.to_string());
                }
            }
        }
    }
    for inst in instructions {
        let text = inst.text.as_ref();
        if text.contains("xmm0") {
            return Some("double".to_string());
        }
        if text.contains("d0") {
            return Some("double".to_string());
        }
        if text.contains("s0") {
            return Some("float".to_string());
        }
        if text.contains("eax") || text.contains("rax") {
            return Some("int".to_string());
        }
        if text.contains("w0") || text.contains("x0") {
            return Some("int".to_string());
        }
    }
    Some("void".to_string())
}

fn looks_like_arm64_passthrough_wrapper(
    instructions: &[Instruction],
    call_target_overrides: &HashMap<u64, u64>,
) -> bool {
    looks_like_arm64_passthrough_wrapper_iter(instructions.iter(), call_target_overrides)
}

fn looks_like_arm64_passthrough_wrapper_blocks(
    blocks: &[BasicBlock],
    call_target_overrides: &HashMap<u64, u64>,
) -> bool {
    looks_like_arm64_passthrough_wrapper_iter(
        blocks.iter().flat_map(|block| block.instructions.iter()),
        call_target_overrides,
    )
}

fn looks_like_arm64_passthrough_wrapper_iter<'a, I>(
    instructions: I,
    call_target_overrides: &HashMap<u64, u64>,
) -> bool
where
    I: IntoIterator<Item = &'a Instruction>,
{
    let mut call_count = 0;
    let mut has_ret = false;
    for inst in instructions {
        let text = inst.text.as_ref();
        if text.starts_with("bl ") {
            let target = call_target_overrides
                .get(&inst.address)
                .copied()
                .or_else(|| parse_relative_target(inst.address, &text));
            if target.is_some() {
                call_count += 1;
                continue;
            }
        }
        if text == "ret" {
            has_ret = true;
            continue;
        }
        if text.starts_with("paciasp")
            || text.starts_with("autiasp")
            || text.starts_with("stp x29, x30")
            || text.starts_with("ldp x29, x30")
            || text.starts_with("mov x29, sp")
        {
            continue;
        }
        return false;
    }
    has_ret && call_count == 1
}

fn infer_type_from_usage(
    image: &BinaryImage,
    instructions: &[Instruction],
    register: &str,
    is_argument: bool,
) -> Option<String> {
    let _ = is_argument;
    if let Some(ty) = match_debug_type_for_register(image, register) {
        return Some(ty);
    }
    if let Some(ty) = infer_type_from_call_return(instructions, register) {
        return Some(ty);
    }
    if let Some(ty) = infer_type_from_known_call_args(instructions, register) {
        return Some(ty);
    }
    if register_used_as_pointer_to_data(instructions, register) {
        return Some("void *".to_string());
    }
    if register_used_as_memory_base(instructions, register) {
        return Some("void *".to_string());
    }
    let mentions_string = instructions.iter().any(|inst| {
        let text = inst.text.as_ref();
        text.contains(register)
            && (text.contains("offset")
                || text.contains("adrp")
                || text.contains(".str")
                || text.contains("rip"))
    });
    if mentions_string {
        return Some("char *".to_string());
    }
    let reg_l = register.to_ascii_lowercase();
    let has_int = instructions.iter().any(|inst| {
        let text = inst.text.as_ref().to_ascii_lowercase();
        if !instruction_mentions_token(&text, &reg_l)
            && !x64_register_aliases_any(&text, &reg_l)
        {
            return false;
        }
        let op = text.split_whitespace().next().unwrap_or_default();
        matches!(
            op,
            "cmp"
                | "test"
                | "add"
                | "sub"
                | "and"
                | "or"
                | "xor"
                | "shl"
                | "shr"
                | "sar"
                | "imul"
                | "inc"
                | "dec"
        )
    });
    if has_int {
        if reg_l.starts_with('e')
            || reg_l.ends_with('d')
            || matches!(reg_l.as_str(), "eax" | "ecx" | "edx" | "esi" | "edi")
        {
            return Some("int".to_string());
        }
        return Some("int64_t".to_string());
    }
    None
}

fn match_debug_type_for_register(image: &BinaryImage, register: &str) -> Option<String> {
    let reg = register.to_ascii_lowercase();
    for hint in &image.debug_import.function_hints {
        for var in hint.arguments.iter().chain(hint.locals.iter()) {
            if var.location.to_ascii_lowercase() == reg {
                if let Some(ty) = var.type_name.clone() {
                    return Some(ty);
                }
            }
        }
    }
    None
}

fn infer_type_from_known_call_args(instructions: &[Instruction], register: &str) -> Option<String> {
    let reg = register.to_ascii_lowercase();
    for (index, inst) in instructions.iter().enumerate() {
        let text = inst.text.as_ref().to_ascii_lowercase();
        if !(text.starts_with("call ") || text.starts_with("bl ") || text.starts_with("blr ")) {
            continue;
        }
        let window = &instructions[index.saturating_sub(8)..index];
        for (name, arg_types) in KNOWN_ARG_TYPES {
            if !text.contains(*name) {
                continue;
            }
            for (arg_i, arg_ty) in arg_types.iter().enumerate() {
                let expected: &[&str] = match arg_i {
                    0 => &["rdi", "edi", "rcx", "ecx", "x0", "w0"],
                    1 => &["rsi", "esi", "rdx", "edx", "x1", "w1"],
                    2 => &["rdx", "edx", "r8", "r8d", "x2", "w2"],
                    3 => &["rcx", "ecx", "r9", "r9d", "x3", "w3"],
                    _ => continue,
                };
                let used = window.iter().any(|prev| {
                    let t = prev.text.as_ref().to_ascii_lowercase();
                    expected.iter().any(|e| {
                        (*e == reg || instruction_mentions_token(&reg, e))
                            && instruction_mentions_token(&t, e)
                            && (t.starts_with("mov ")
                                || t.starts_with("lea ")
                                || t.starts_with("ldr "))
                    })
                });
                if used || expected.iter().any(|e| *e == reg) {
                    return Some((*arg_ty).to_string());
                }
            }
        }
    }
    None
}

fn x64_register_aliases_any(text: &str, reg: &str) -> bool {
    #[cfg(feature = "arch-x64")]
    {
        x64_register_aliases(reg)
            .iter()
            .any(|alias| instruction_mentions_token(text, alias))
    }
    #[cfg(not(feature = "arch-x64"))]
    {
        let _ = (text, reg);
        false
    }
}

fn infer_type_from_call_return(instructions: &[Instruction], register: &str) -> Option<String> {
    let reg_lower = register.to_ascii_lowercase();
    // Check if this register is x0 (ARM64) or rax/eax (x64) — return value registers.
    let is_return_reg = reg_lower == "x0" || reg_lower == "rax" || reg_lower == "eax";
    if !is_return_reg {
        return None;
    }

    for inst in instructions {
        let text = inst.text.as_ref();
        if !text.starts_with("bl ") && !text.starts_with("call ") {
            continue;
        }
        // Check if the call target name matches a known library function.
        for (name, ty) in KNOWN_RETURN_TYPES {
            if text.contains(name) {
                return Some(ty.to_string());
            }
        }
    }
    None
}

/// Known return types for common library functions.
const KNOWN_ARG_TYPES: &[(&str, &[&str])] = &[
    ("malloc", &["size_t"]),
    ("calloc", &["size_t", "size_t"]),
    ("realloc", &["void *", "size_t"]),
    ("memcpy", &["void *", "void *", "size_t"]),
    ("memset", &["void *", "int", "size_t"]),
    ("memmove", &["void *", "void *", "size_t"]),
    ("strlen", &["char *"]),
    ("strcmp", &["char *", "char *"]),
    ("strncmp", &["char *", "char *", "size_t"]),
    ("strcpy", &["char *", "char *"]),
    ("strncpy", &["char *", "char *", "size_t"]),
    ("strstr", &["char *", "char *"]),
    ("strchr", &["char *", "int"]),
    ("printf", &["char *"]),
    ("sprintf", &["char *", "char *"]),
    ("snprintf", &["char *", "size_t", "char *"]),
    ("fprintf", &["void *", "char *"]),
    ("fopen", &["char *", "char *"]),
    ("fread", &["void *", "size_t", "size_t", "void *"]),
    ("fwrite", &["void *", "size_t", "size_t", "void *"]),
    ("open", &["char *", "int"]),
    ("read", &["int", "void *", "size_t"]),
    ("write", &["int", "void *", "size_t"]),
    ("free", &["void *"]),
];

const KNOWN_RETURN_TYPES: &[(&str, &str)] = &[
    ("malloc", "void *"),
    ("calloc", "void *"),
    ("realloc", "void *"),
    ("memcpy", "void *"),
    ("memset", "void *"),
    ("memmove", "void *"),
    ("strlen", "size_t"),
    ("strcmp", "int"),
    ("strncmp", "int"),
    ("strcpy", "char *"),
    ("strncpy", "char *"),
    ("strcat", "char *"),
    ("strstr", "char *"),
    ("strchr", "char *"),
    ("printf", "int"),
    ("sprintf", "int"),
    ("snprintf", "int"),
    ("fprintf", "int"),
    ("fopen", "void *"),
    ("fclose", "int"),
    ("fread", "size_t"),
    ("fwrite", "size_t"),
    ("open", "int"),
    ("close", "int"),
    ("read", "ssize_t"),
    ("write", "ssize_t"),
    ("pthread_create", "int"),
    ("pthread_join", "int"),
    ("__android_log_print", "int"),
    ("__android_log_write", "int"),
];

/// Check if the register is loaded with a PC-relative address (pointer to data).
fn register_used_as_pointer_to_data(instructions: &[Instruction], register: &str) -> bool {
    let reg_lower = register.to_ascii_lowercase();
    // ARM64: `adrp xN, ...` or `add xN, xN, #imm` pattern
    // x64: `lea rN, [rip+...]`
    let mut has_adrp = false;
    let mut has_add = false;
    for inst in instructions {
        let text = inst.text.as_ref();
        if text.starts_with("adrp ") && text.contains(&reg_lower) {
            has_adrp = true;
        }
        if text.starts_with("add ") && text.contains(&reg_lower) && text.contains("#0x") {
            has_add = true;
        }
        if text.starts_with("lea ") && text.contains(&reg_lower) && text.contains("rip") {
            return true;
        }
    }
    has_adrp && has_add
}

/// Check if the register is used as a memory base (dereferenced via [xN] or [rN]).
fn register_used_as_memory_base(instructions: &[Instruction], register: &str) -> bool {
    let reg_lower = register.to_ascii_lowercase();
    instructions.iter().any(|inst| {
        let text = inst.text.as_ref();
        // ARM64: [xN], [xN, #imm], [xN, xM]
        // x64: [rN], [rN+imm], [rN+rM]
        text.contains(&format!("[{reg_lower}"))
    })
}

fn infer_arm64_argument_type(
    instructions: &[Instruction],
    x_reg: &str,
    w_reg: &str,
) -> Option<String> {
    // 1. Check if register is loaded from PC-relative address (string/data pointer).
    if register_used_as_pointer_to_data(instructions, x_reg) {
        return Some("void *".to_string());
    }

    // 2. Check if register is used as a memory base (pointer dereference).
    if register_used_as_memory_base(instructions, x_reg) {
        return Some("void *".to_string());
    }

    // 3. Check for string-related patterns.
    let mentions_string = instructions.iter().any(|inst| {
        let text = inst.text.as_ref();
        text.contains(x_reg) && (text.contains("offset") || text.contains("adrp") || text.contains(".str"))
    });
    if mentions_string {
        return Some("char *".to_string());
    }

    // 4. Check for float/double usage via SIMD registers.
    let has_simd_usage = instructions.iter().any(|inst| {
        let text = inst.text.as_ref();
        let s_reg = format!("s{}", &x_reg[1..]);
        let d_reg = format!("d{}", &x_reg[1..]);
        (text.contains(&s_reg) || text.contains(&d_reg))
            && (text.contains("fadd") || text.contains("fmul") || text.contains("fcvt") || text.contains("ldr"))
    });
    if has_simd_usage {
        return Some("double".to_string());
    }

    // 5. Check for 32-bit integer usage (w register).
    let has_w_register_integer_usage = instructions.iter().any(|inst| {
        let text = inst.text.as_ref();
        if !matches!(
            arm64_register_usage(&text, x_reg, w_reg),
            RegisterUsage::Read | RegisterUsage::ReadWrite
        ) {
            return false;
        }
        instruction_mentions_token(&text, w_reg) && arm64_opcode_looks_integer(&text)
    });
    if has_w_register_integer_usage {
        return Some("int".to_string());
    }

    // 6. Check for 64-bit integer usage (x register in arithmetic).
    let has_x_register_integer_usage = instructions.iter().any(|inst| {
        let text = inst.text.as_ref();
        if !matches!(
            arm64_register_usage(&text, x_reg, w_reg),
            RegisterUsage::Read | RegisterUsage::ReadWrite
        ) {
            return false;
        }
        !arm64_memory_operand_uses_base(&text, x_reg) && arm64_opcode_looks_integer(&text)
    });
    if has_x_register_integer_usage {
        return Some("int64_t".to_string());
    }

    None
}

fn infer_arm64_stack_slot_type(instructions: &[Instruction], offset: i64) -> Option<String> {
    for inst in instructions {
        let text = inst.text.as_ref();
        if !arm64_stack_operand_matches_offset(&text, offset) {
            continue;
        }
        let opcode = text.split_whitespace().next().unwrap_or_default();
        let first_operand = arm64_first_operand(&text).unwrap_or_default();
        if first_operand.starts_with('d') {
            return Some("double".to_string());
        }
        if first_operand.starts_with('s') {
            return Some("float".to_string());
        }
        if opcode.ends_with('b') {
            return Some("uint8_t".to_string());
        }
        if opcode.ends_with('h') {
            return Some("uint16_t".to_string());
        }
        if opcode == "ldrsw" {
            return Some("int32_t".to_string());
        }
        if first_operand.starts_with('w') {
            return Some("uint32_t".to_string());
        }
        if first_operand.starts_with('x') {
            return Some("uint64_t".to_string());
        }
    }

    None
}

fn recover_arm64_locals(instructions: &[Instruction]) -> Vec<Arm64RecoveredLocal> {
    let access_counts = collect_arm64_stack_offset_access_counts(instructions);
    let offsets = access_counts.keys().copied().collect::<Vec<_>>();
    let mut locals = Vec::new();

    if let Some(root_buffer) = detect_arm64_sp_root_buffer(instructions) {
        locals.push(root_buffer);
    }

    if offsets.is_empty() {
        return locals;
    }
    let root_covered_end = locals
        .iter()
        .filter(|local| local.start_offset == 0)
        .filter_map(|local| local.end_offset)
        .max();
    let offsets = if let Some(end) = root_covered_end {
        offsets
            .into_iter()
            .filter(|offset| *offset < 0 || *offset > end)
            .collect::<Vec<_>>()
    } else {
        offsets
    };
    if offsets.is_empty() {
        return locals;
    }
    let offset_set = offsets.iter().copied().collect::<BTreeSet<_>>();

    let large_workspace = arm64_large_workspace_bounds(&offsets);
    let large_workspace_type =
        large_workspace.map(|(start, end)| classify_arm64_workspace_kind(&offsets, start, end));
    let hot_workspace_offsets = large_workspace
        .map(|_| {
            access_counts
                .iter()
                .filter_map(|(offset, count)| {
                    (*offset >= 0 && *count >= ARM64_LARGE_WORKSPACE_HOT_ACCESS_COUNT)
                        .then_some(*offset)
                })
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let mut index = 0;
    while index < offsets.len() {
        let start = offsets[index];
        let type_name = infer_arm64_stack_slot_type(instructions, start);
        let mut end = start;
        let mut aggregate = false;

        if let Some((array_end, pair_count)) = arm64_record_array_end(&offset_set, start)
            && pair_count >= 8
        {
            locals.push(Arm64RecoveredLocal {
                start_offset: start,
                end_offset: Some(array_end),
                type_name: Some("stack_array_t".to_string()),
                aggregate: true,
            });
            while index < offsets.len() && offsets[index] <= array_end {
                index += 1;
            }
            continue;
        }

        if let Some((workspace_start, workspace_end)) = large_workspace
            && start >= workspace_start
            && start <= workspace_end
            && !hot_workspace_offsets.contains(&start)
        {
            let mut last = start;
            let mut lookahead = index + 1;
            while lookahead < offsets.len() {
                let next = offsets[lookahead];
                if next < workspace_start
                    || next > workspace_end
                    || hot_workspace_offsets.contains(&next)
                    || next - last > ARM64_LARGE_WORKSPACE_GAP
                {
                    break;
                }
                end = next;
                aggregate = true;
                last = next;
                lookahead += 1;
            }

            if aggregate && end - start >= 0x40 {
                locals.push(Arm64RecoveredLocal {
                    start_offset: start,
                    end_offset: Some(end),
                    type_name: Some(
                        large_workspace_type
                            .clone()
                            .unwrap_or_else(|| "stack_workspace_t".to_string()),
                    ),
                    aggregate: true,
                });
                index = lookahead;
                continue;
            }
        }

        if start >= 0 {
            let mut last = start;
            let mut lookahead = index + 1;
            while lookahead < offsets.len() {
                let next = offsets[lookahead];
                if next < 0 || next - last > ARM64_STACK_SPAN_GAP {
                    break;
                }
                if infer_arm64_stack_slot_type(instructions, next) != type_name {
                    break;
                }
                aggregate = true;
                end = next;
                last = next;
                lookahead += 1;
            }

            if aggregate && end - start >= 0x20 {
                locals.push(Arm64RecoveredLocal {
                    start_offset: start,
                    end_offset: Some(end),
                    type_name: Some("stack_span_t".to_string()),
                    aggregate: true,
                });
                index = lookahead;
                continue;
            }
        }

        locals.push(Arm64RecoveredLocal {
            start_offset: start,
            end_offset: None,
            type_name,
            aggregate,
        });
        index += 1;
    }

    locals
}

fn infer_type_from_offset(
    image: &BinaryImage,
    instructions: &[Instruction],
    offset: i64,
) -> Option<String> {
    if let Some(debug_type) = image.debug_import.type_defs.first() {
        return Some(debug_type.name.clone());
    }
    let large_store = instructions.iter().any(|inst| {
        let text = inst.text.as_ref();
        text.contains(&format!("{offset:x}")) && (text.contains("qword") || text.contains("rax"))
    });
    if large_store {
        Some("uint64_t".to_string())
    } else {
        None
    }
}

fn collect_stack_offsets(instructions: &[Instruction]) -> BTreeSet<i64> {
    let mut offsets = BTreeSet::new();
    for inst in instructions {
        let text = inst.text.as_ref();
        for base in ["[rbp-", "[rsp+", "[rbp+"] {
            if let Some(index) = text.find(base) {
                let suffix = &text[index + base.len()..];
                let hex = suffix
                    .chars()
                    .take_while(|ch| ch.is_ascii_hexdigit())
                    .collect::<String>();
                if hex.is_empty() {
                    continue;
                }
                if let Ok(value) = i64::from_str_radix(&hex, 16) {
                    let signed = if base == "[rbp-" { -value } else { value };
                    offsets.insert(signed);
                }
            }
        }
    }
    offsets
}

fn collect_arm64_stack_offset_access_counts(instructions: &[Instruction]) -> BTreeMap<i64, usize> {
    let mut counts = BTreeMap::new();
    for inst in instructions {
        let text = inst.text.as_ref();
        if looks_like_arm64_frame_save_slot(&text) {
            continue;
        }
        for base in ["[sp, #", "[x29, #"] {
            let Some(index) = text.find(base) else {
                continue;
            };
            let suffix = &text[index + base.len()..];
            let raw = suffix
                .chars()
                .take_while(|ch| ch.is_ascii_hexdigit() || *ch == '-' || *ch == 'x')
                .collect::<String>();
            if raw.is_empty() {
                continue;
            }
            if let Some(value) = parse_signed_imm(&raw) {
                *counts.entry(value).or_insert(0) += 1;
            }
        }
    }
    counts
}

fn detect_arm64_sp_root_buffer(instructions: &[Instruction]) -> Option<Arm64RecoveredLocal> {
    let mut max_end = None;
    let mut store_count = 0usize;
    let mut min_offset = None;

    for inst in instructions {
        let text = inst.text.as_ref();
        if looks_like_arm64_frame_save_slot(&text) {
            continue;
        }
        let Some((base, offset)) = parse_arm64_memory_operand(&text) else {
            continue;
        };
        if !base.eq_ignore_ascii_case("sp") || offset < 0 {
            continue;
        }
        let opcode = text.split_whitespace().next().unwrap_or_default();
        if !opcode.starts_with("str") && !opcode.starts_with("stp") {
            continue;
        }
        min_offset = Some(
            min_offset
                .map(|current: i64| current.min(offset))
                .unwrap_or(offset),
        );
        let width = arm64_memory_access_width(&text).unwrap_or(8);
        let end = offset + width - 1;
        max_end = Some(max_end.map(|current: i64| current.max(end)).unwrap_or(end));
        store_count += 1;
    }

    let max_end = max_end?;
    if min_offset != Some(0)
        || max_end < ARM64_SP_ROOT_BUFFER_MIN_END
        || store_count < ARM64_SP_ROOT_BUFFER_MIN_STORES
    {
        return None;
    }

    Some(Arm64RecoveredLocal {
        start_offset: 0,
        end_offset: Some(max_end),
        type_name: Some("stack_buffer_t".to_string()),
        aggregate: true,
    })
}

fn infer_arm64_stack_arg_bytes(
    instructions: &[Instruction],
    frame_size: Option<u64>,
) -> Option<u64> {
    let frame_size = frame_size.unwrap_or(0) as i64;
    let mut max_stack_arg_bytes = 0;

    for inst in instructions {
        let text = inst.text.as_ref();
        if looks_like_arm64_frame_save_slot(&text) {
            continue;
        }
        for base in ["[sp, #", "[x29, #"] {
            let Some(index) = text.find(base) else {
                continue;
            };
            let suffix = &text[index + base.len()..];
            let end = suffix
                .find(|ch: char| !(ch.is_ascii_hexdigit() || ch == '-' || ch == 'x'))
                .unwrap_or(suffix.len());
            let raw = &suffix[..end];
            let Some(offset) = parse_signed_imm(raw) else {
                continue;
            };
            if offset < frame_size {
                continue;
            }
            let used = (offset - frame_size) as u64 + 8;
            max_stack_arg_bytes = max_stack_arg_bytes.max(used);
        }
    }

    Some(max_stack_arg_bytes)
}

fn arm64_argument_input_mask(instructions: &[Instruction]) -> u8 {
    let mut written = 0u8;
    let mut used = 0u8;
    for inst in instructions {
        if written == 0xff {
            break;
        }
        let text = inst.text.as_ref();
        let mut parts = text.splitn(2, char::is_whitespace);
        let opcode = parts.next().unwrap_or_default();
        let operand_text = parts.next().unwrap_or_default().trim();
        if opcode.is_empty() || operand_text.is_empty() {
            continue;
        }
        let operands = operand_text
            .split(',')
            .map(str::trim)
            .filter(|operand| !operand.is_empty())
            .collect::<Vec<_>>();
        if operands.is_empty() {
            continue;
        }
        let write_mask = arm64_write_operand_mask(opcode, operands.len());
        if written == 0xff {
            break;
        }
        for index in 0..8u8 {
            let bit = 1u8 << index;
            if written & bit != 0 {
                continue;
            }
            let (x_reg, w_reg) = match index {
                0 => ("x0", "w0"),
                1 => ("x1", "w1"),
                2 => ("x2", "w2"),
                3 => ("x3", "w3"),
                4 => ("x4", "w4"),
                5 => ("x5", "w5"),
                6 => ("x6", "w6"),
                _ => ("x7", "w7"),
            };
            let mut read = false;
            let mut write = false;
            for (op_index, operand) in operands.iter().enumerate() {
                if !arm64_operand_mentions_register(operand, x_reg, w_reg) {
                    continue;
                }
                if op_index < 8 && (write_mask & (1u8 << op_index)) != 0 {
                    write = true;
                } else {
                    read = true;
                }
            }
            if read {
                used |= bit;
            } else if write {
                written |= bit;
            }
        }
    }
    used
}

fn arm64_register_used_as_input(instructions: &[Instruction], x_reg: &str, w_reg: &str) -> bool {
    for inst in instructions {
        match arm64_register_usage(&inst.text.as_ref(), x_reg, w_reg) {
            RegisterUsage::None => continue,
            RegisterUsage::Read | RegisterUsage::ReadWrite => return true,
            RegisterUsage::Write => return false,
        }
    }
    false
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegisterUsage {
    None,
    Read,
    Write,
    ReadWrite,
}

fn arm64_register_usage(text: &str, x_reg: &str, w_reg: &str) -> RegisterUsage {
    let mut parts = text.splitn(2, char::is_whitespace);
    let opcode = parts.next().unwrap_or_default();
    let operand_text = parts.next().unwrap_or_default().trim();
    if opcode.is_empty() || operand_text.is_empty() {
        return RegisterUsage::None;
    }

    let operands = operand_text
        .split(',')
        .map(str::trim)
        .filter(|operand| !operand.is_empty())
        .collect::<Vec<_>>();
    if operands.is_empty() {
        return RegisterUsage::None;
    }

    let write_mask = arm64_write_operand_mask(opcode, operands.len());
    let mut read = false;
    let mut write = false;
    for (index, operand) in operands.iter().enumerate() {
        if !arm64_operand_mentions_register(operand, x_reg, w_reg) {
            continue;
        }
        if index < 8 && (write_mask & (1u8 << index)) != 0 {
            write = true;
        } else {
            read = true;
        }
    }

    match (read, write) {
        (false, false) => RegisterUsage::None,
        (true, false) => RegisterUsage::Read,
        (false, true) => RegisterUsage::Write,
        (true, true) => RegisterUsage::ReadWrite,
    }
}

fn arm64_operand_mentions_register(operand: &str, x_reg: &str, w_reg: &str) -> bool {
    instruction_mentions_token(operand, x_reg) || instruction_mentions_token(operand, w_reg)
}

fn arm64_opcode_looks_integer(text: &str) -> bool {
    let opcode = text.split_whitespace().next().unwrap_or_default();
    matches!(
        opcode,
        "cmp"
            | "cmn"
            | "tst"
            | "add"
            | "adds"
            | "sub"
            | "subs"
            | "csinc"
            | "csel"
            | "csinv"
            | "csneg"
            | "and"
            | "ands"
            | "orr"
            | "eor"
            | "lsl"
            | "lsr"
            | "asr"
            | "mul"
            | "madd"
            | "msub"
            | "sdiv"
            | "udiv"
            | "neg"
            | "mov"
            | "movz"
            | "movk"
            | "movn"
            | "cset"
            | "cinc"
    )
}

fn arm64_write_operand_mask(opcode: &str, operand_count: usize) -> u8 {
    if matches!(
        opcode,
        "stp" | "str" | "stur" | "sturb" | "sturh" | "strb" | "strh"
    ) || opcode.starts_with("st")
        || matches!(
            opcode,
            "cmp" | "cmn" | "tst" | "cbz" | "cbnz" | "tbz" | "tbnz"
        )
        || opcode.starts_with('b')
        || matches!(opcode, "ret" | "autiasp" | "paciasp" | "nop" | "hint")
    {
        return 0;
    }
    if matches!(opcode, "ldp" | "ldpsw") {
        let n = operand_count.min(2);
        return if n >= 2 { 0b11 } else if n == 1 { 0b1 } else { 0 };
    }
    0b1
}

fn arm64_write_operand_indices(opcode: &str, operand_count: usize) -> Vec<usize> {
    let mask = arm64_write_operand_mask(opcode, operand_count);
    let mut out = Vec::with_capacity(2);
    for index in 0..8usize {
        if mask & (1u8 << index) != 0 {
            out.push(index);
        }
    }
    out
}

fn instruction_mentions_token(text: &str, token: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .any(|part| part.eq_ignore_ascii_case(token))
}

fn looks_like_arm64_frame_save_slot(text: &str) -> bool {
    let tokens = text
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    let Some(opcode) = tokens.first().copied() else {
        return false;
    };
    if !matches!(opcode, "str" | "ldr" | "stur" | "ldur" | "stp" | "ldp") {
        return false;
    }
    let frame_base_index = tokens
        .iter()
        .rposition(|token| *token == "sp" || *token == "x29");
    let Some(frame_base_index) = frame_base_index else {
        return false;
    };
    tokens[1..frame_base_index]
        .iter()
        .any(|token| is_arm64_callee_saved_register(token))
}

fn is_arm64_callee_saved_register(token: &str) -> bool {
    let Some(num) = token
        .strip_prefix('x')
        .or_else(|| token.strip_prefix('w'))
        .and_then(|raw| raw.parse::<u8>().ok())
    else {
        return false;
    };
    (19..=30).contains(&num)
}

fn parse_stack_sub(text: &str) -> Option<u64> {
    if !text.starts_with("sub rsp,") && !text.starts_with("sub     rsp,") {
        return None;
    }
    let value = text.split(',').nth(1)?.trim();
    if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        value.parse().ok()
    }
}

fn parse_arm64_stack_setup(text: &str) -> Option<u64> {
    if let Some(value) = text
        .strip_prefix("sub sp, sp, ")
        .or_else(|| text.strip_prefix("sub     sp, sp, "))
        .and_then(parse_imm_u64)
    {
        return Some(value);
    }

    let marker = "[sp, #-";
    let index = text.find(marker)?;
    let suffix = &text[index + marker.len()..];
    let raw = suffix
        .chars()
        .take_while(|ch| ch.is_ascii_hexdigit() || *ch == 'x')
        .collect::<String>();
    parse_imm_u64(&raw)
}

fn parse_arm64_memory_operand(text: &str) -> Option<(String, i64)> {
    let open = text.find('[')?;
    let close = text[open..].find(']')? + open;
    let mem = &text[open + 1..close];
    let mut parts = mem.split(',').map(str::trim);
    let base = parts.next()?.to_string();
    let offset = parts
        .next()
        .and_then(|raw| parse_signed_imm(raw.trim_start_matches('#')))
        .unwrap_or(0);
    Some((base, offset))
}

fn arm64_memory_access_width(text: &str) -> Option<i64> {
    let opcode = text.split_whitespace().next()?;
    if opcode.ends_with('b') {
        return Some(1);
    }
    if opcode.ends_with('h') {
        return Some(2);
    }
    if opcode == "ldrsw" {
        return Some(4);
    }
    if opcode.starts_with("stp") || opcode.starts_with("ldp") {
        let first = arm64_first_operand(text)?;
        return Some(arm64_register_width(first)? * 2);
    }
    let first = arm64_first_operand(text)?;
    arm64_register_width(first)
}

fn arm64_register_width(register: &str) -> Option<i64> {
    let reg = register.trim().trim_end_matches('!').to_ascii_lowercase();
    if reg.starts_with('q') {
        return Some(16);
    }
    if reg.starts_with('d') {
        return Some(8);
    }
    if reg.starts_with('s') {
        return Some(4);
    }
    if reg.starts_with('h') {
        return Some(2);
    }
    if reg.starts_with('b') {
        return Some(1);
    }
    if reg.starts_with('x') {
        return Some(8);
    }
    if reg.starts_with('w') {
        return Some(4);
    }
    None
}

fn arm64_memory_operand_uses_base(text: &str, base: &str) -> bool {
    parse_arm64_memory_operand(text)
        .map(|(found_base, _)| found_base.eq_ignore_ascii_case(base))
        .unwrap_or(false)
}

fn arm64_stack_operand_matches_offset(text: &str, offset: i64) -> bool {
    parse_arm64_memory_operand(text)
        .map(|(base, found_offset)| {
            (base.eq_ignore_ascii_case("sp") || base.eq_ignore_ascii_case("x29"))
                && found_offset == offset
        })
        .unwrap_or(false)
}

fn arm64_first_operand(text: &str) -> Option<&str> {
    let (_, operands) = text.split_once(char::is_whitespace)?;
    operands.split(',').next().map(str::trim)
}

fn parse_signed_imm(raw: &str) -> Option<i64> {
    let value = raw.trim();
    if let Some(hex) = value.strip_prefix("-0x") {
        i64::from_str_radix(hex, 16).ok().map(|num| -num)
    } else if let Some(hex) = value.strip_prefix("+0x") {
        i64::from_str_radix(hex, 16).ok()
    } else if let Some(decimal) = value.strip_prefix('+') {
        decimal.parse().ok()
    } else if let Some(hex) = value.strip_prefix("0x") {
        i64::from_str_radix(hex, 16).ok()
    } else {
        value.parse().ok()
    }
}

fn parse_imm_u64(raw: &str) -> Option<u64> {
    let value = raw.trim_end_matches(|ch: char| ch == ']' || ch == '!' || ch == ';');
    if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        value.parse().ok()
    }
}

fn arm64_large_workspace_bounds(offsets: &[i64]) -> Option<(i64, i64)> {
    let positive = offsets
        .iter()
        .copied()
        .filter(|offset| *offset >= 0)
        .collect::<Vec<_>>();
    if positive.len() < ARM64_LARGE_WORKSPACE_MIN_OFFSETS {
        return None;
    }
    let start = *positive.first()?;
    let end = *positive.last()?;
    (end - start >= ARM64_LARGE_WORKSPACE_MIN_SPAN).then_some((start, end))
}

fn classify_arm64_workspace_kind(offsets: &[i64], start: i64, end: i64) -> String {
    let positive = offsets
        .iter()
        .copied()
        .filter(|offset| *offset >= start && *offset <= end)
        .collect::<Vec<_>>();
    let mut stride8 = 0usize;
    let mut stride16 = 0usize;
    for window in positive.windows(2) {
        let delta = window[1] - window[0];
        if delta == 0x8 {
            stride8 += 1;
        } else if delta == 0x10 {
            stride16 += 1;
        }
    }

    if stride8 >= ARM64_ARRAY_LIKE_MIN_STRIDE_HITS || stride16 >= ARM64_ARRAY_LIKE_MIN_STRIDE_HITS {
        "stack_array_t".to_string()
    } else {
        "stack_buffer_t".to_string()
    }
}

fn arm64_record_array_end(offsets: &BTreeSet<i64>, start: i64) -> Option<(i64, usize)> {
    if start < 0 {
        return None;
    }

    let mut base = start;
    let mut pairs = 0usize;
    loop {
        if !offsets.contains(&base) || !offsets.contains(&(base + 0x10)) {
            break;
        }
        pairs += 1;
        let next_base = base + 0x18;
        if offsets.contains(&next_base) {
            base = next_base;
            continue;
        }
        break;
    }

    (pairs > 0).then_some((base + 0x10, pairs))
}

fn format_signed_hex(offset: i64) -> String {
    if offset < 0 {
        format!("-0x{:x}", offset.unsigned_abs())
    } else {
        format!("+0x{:x}", offset as u64)
    }
}

fn format_stack_location(start_offset: i64, end_offset: Option<i64>) -> String {
    match end_offset {
        Some(end_offset) if end_offset != start_offset => {
            format!(
                "stack[{}..{}]",
                format_signed_hex(start_offset),
                format_signed_hex(end_offset)
            )
        }
        _ => format!("stack[{}]", format_signed_hex(start_offset)),
    }
}

#[inline]
fn inst_len(inst: &Instruction) -> usize {
    let n = inst.bytes.len();
    if n == 8 {
        4
    } else if n == 2 {
        1
    } else {
        n / 2
    }
}

fn sanitize_symbol(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "sub_unknown".to_string()
    } else {
        out
    }
}

fn default_calling_convention(architecture: Architecture) -> String {
    default_calling_convention_for(architecture, None)
}

fn default_calling_convention_for(
    architecture: Architecture,
    format: Option<BinaryFormat>,
) -> String {
    match architecture {
        Architecture::X86_64 => match format {
            Some(BinaryFormat::Pe) => "win64".to_string(),
            Some(BinaryFormat::Elf) | Some(BinaryFormat::MachO) => "sysv_amd64".to_string(),
            _ => "sysv_amd64".to_string(),
        },
        Architecture::Arm64 => match format {
            Some(BinaryFormat::Pe) => "win_aarch64".to_string(),
            _ => "aapcs64".to_string(),
        },
        Architecture::Unknown => "unknown".to_string(),
    }
}

fn build_hint_maps(
    hints: &[DebugFunctionHint],
) -> (HashMap<u64, DebugFunctionHint>, HashMap<String, DebugFunctionHint>) {
    let mut by_addr = HashMap::with_capacity(hints.len());
    let mut by_name = HashMap::with_capacity(hints.len());
    for hint in hints {
        if let Some(address) = hint.address {
            by_addr.entry(address).or_insert_with(|| hint.clone());
        }
        if !hint.name.is_empty() {
            by_name.entry(hint.name.clone()).or_insert_with(|| hint.clone());
        }
    }
    (by_addr, by_name)
}


fn dedupe_references(mut references: Vec<Reference>) -> Vec<Reference> {
    if references.len() <= 1 {
        return references;
    }
    if references.len() <= 32 {
        references.sort_unstable_by_key(|reference| {
            (reference.from, reference.to, reference.kind as u8)
        });
        references.dedup_by(|a, b| a.from == b.from && a.to == b.to && a.kind == b.kind);
        return references;
    }
    let mut seen = HashSet::with_capacity(references.len());
    references.retain(|reference| seen.insert((reference.from, reference.to, reference.kind)));
    references
}

fn dedupe_references_in_place(references: &mut Vec<Reference>) {
    if references.len() <= 1 {
        return;
    }
    if references.len() <= 32 {
        references.sort_unstable_by_key(|reference| {
            (reference.from, reference.to, reference.kind as u8)
        });
        references.dedup_by(|a, b| a.from == b.from && a.to == b.to && a.kind == b.kind);
        return;
    }
    let mut seen = HashSet::with_capacity(references.len());
    references.retain(|reference| seen.insert((reference.from, reference.to, reference.kind)));
}

fn inferred_type_size(name: &str) -> Option<u64> {
    let n = name.trim().trim_end_matches('*').trim();
    match n {
        "uint8_t" | "int8_t" | "char" | "bool" => Some(1),
        "uint16_t" | "int16_t" | "short" => Some(2),
        "uint32_t" | "int32_t" | "int" | "float" => Some(4),
        "uint64_t" | "int64_t" | "size_t" | "ssize_t" | "double" | "long" => Some(8),
        "void" => None,
        _ if name.contains('*') => Some(8),
        _ => None,
    }
}

fn dedupe_types(types: &mut Vec<TypeDef>) {
    let mut seen = BTreeSet::new();
    types.retain(|item| seen.insert((item.name.clone(), item.kind.clone(), item.source)));
}

fn extract_arm64_data_references(
    instructions: &[Instruction],
    string_ranges: &[StringRange],
    executable: &[(u64, u64)],
) -> Vec<Reference> {
    let mut refs = Vec::with_capacity(8);
    let mut register_targets: [Option<u64>; 32] = [None; 32];

    for inst in instructions {
        let text = inst.text.as_ref();
        if let Some((reg, target)) = parse_arm64_adr_target(inst.address, text) {
            if let Some(slot) = arm64_reg_index(&reg) {
                register_targets[slot] = Some(target);
            }
            if is_string_address(string_ranges, target) {
                refs.push(Reference {
                    from: inst.address,
                    to: target,
                    kind: ReferenceKind::StringRef,
                });
            }
            continue;
        }
        if let Some((dst, base, imm)) = parse_arm64_add_imm(text)
            && let Some(base_slot) = arm64_reg_index(&base)
            && let Some(base_target) = register_targets[base_slot]
        {
            let target = base_target.saturating_add_signed(imm);
            if let Some(dst_slot) = arm64_reg_index(&dst) {
                register_targets[dst_slot] = Some(target);
            }
            if is_string_address(string_ranges, target) {
                refs.push(Reference {
                    from: inst.address,
                    to: target,
                    kind: ReferenceKind::StringRef,
                });
            }
            continue;
        }
        if let Some((dst, base, imm)) = parse_arm64_mem_imm(text)
            && let Some(base_slot) = arm64_reg_index(&base)
            && let Some(base_target) = register_targets[base_slot]
        {
            let target = base_target.saturating_add_signed(imm);
            if let Some(dst_slot) = arm64_reg_index(&dst) {
                register_targets[dst_slot] = Some(target);
            }
            if is_string_address(string_ranges, target) {
                refs.push(Reference {
                    from: inst.address,
                    to: target,
                    kind: ReferenceKind::StringRef,
                });
            } else if is_executable_address(executable, target) {
                refs.push(Reference {
                    from: inst.address,
                    to: target,
                    kind: ReferenceKind::IndirectCodePtr,
                });
            } else {
                refs.push(Reference {
                    from: inst.address,
                    to: target,
                    kind: ReferenceKind::DataRef,
                });
            }
            continue;
        }
        if let Some(reg) = parse_arm64_mov_alias(text)
            && let Some(slot) = arm64_reg_index(&reg)
            && let Some(target) = register_targets[slot]
            && is_string_address(string_ranges, target)
        {
            refs.push(Reference {
                from: inst.address,
                to: target,
                kind: ReferenceKind::StringRef,
            });
        }
    }

    dedupe_references(refs)
}

#[inline]
fn arm64_reg_index(reg: &str) -> Option<usize> {
    let bytes = reg.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let prefix = bytes[0].to_ascii_lowercase();
    if prefix != b'x' && prefix != b'w' {
        return None;
    }
    if bytes.len() == 1 {
        return None;
    }
    let mut value = 0usize;
    for &b in &bytes[1..] {
        if !b.is_ascii_digit() {
            return None;
        }
        value = value * 10 + (b - b'0') as usize;
        if value > 31 {
            return None;
        }
    }
    Some(value)
}

fn parse_arm64_adr_target(address: u64, text: &str) -> Option<(&str, u64)> {
    let mut parts = text.splitn(2, ' ');
    let opcode = parts.next()?.trim();
    let operands = parts.next()?.trim();
    if opcode != "adr" && opcode != "adrp" {
        return None;
    }
    let mut operands = operands.split(',').map(str::trim);
    let reg = operands.next()?;
    let target_token = operands.next()?;
    let target = parse_arm64_relative_target(address, target_token, opcode == "adrp")?;
    Some((reg, target))
}

fn parse_arm64_add_imm(text: &str) -> Option<(&str, &str, i64)> {
    if !text.starts_with("add ") {
        return None;
    }
    let mut operands = text["add ".len()..].split(',').map(str::trim);
    let dst = operands.next()?;
    let base = operands.next()?;
    let imm = parse_signed_imm(operands.next()?.trim_start_matches('#'))?;
    Some((dst, base, imm))
}

fn parse_arm64_mem_imm(text: &str) -> Option<(&str, &str, i64)> {
    let opcode = text.split_whitespace().next()?;
    if !opcode.starts_with("ldr") && !opcode.starts_with("ldrs") {
        return None;
    }
    let rest = text[opcode.len()..].trim();
    let mut operands = rest.split(',').map(str::trim);
    let dst = operands.next()?;
    let mem_part = text.split_once(',')?.1.trim();
    let open = mem_part.find('[')?;
    let close = mem_part[open..].find(']')? + open;
    let mem = &mem_part[open + 1..close];
    let mut mem_parts = mem.split(',').map(str::trim);
    let base = mem_parts.next()?;
    let imm = mem_parts
        .next()
        .and_then(|raw| parse_signed_imm(raw.trim_start_matches('#')))
        .unwrap_or(0);
    Some((dst, base, imm))
}

fn parse_arm64_ldp_imm(text: &str) -> Option<(String, String, String, i64)> {
    if !text.starts_with("ldp ") {
        return None;
    }
    let mut operands = text["ldp ".len()..].split(',').map(str::trim);
    let dst0 = operands.next()?.to_string();
    let dst1 = operands.next()?.to_string();
    let rest = text.split_once(',')?.1.split_once(',')?.1.trim();
    let open = rest.find('[')?;
    let close = rest[open..].find(']')? + open;
    let mem = &rest[open + 1..close];
    let mut mem_parts = mem.split(',').map(str::trim);
    let base = mem_parts.next()?.to_string();
    let imm = mem_parts
        .next()
        .and_then(|raw| parse_signed_imm(raw.trim_start_matches('#')))
        .unwrap_or(0);
    Some((dst0, dst1, base, imm))
}

fn parse_arm64_add_reg(text: &str) -> Option<(String, String, String)> {
    if !text.starts_with("add ") {
        return None;
    }
    let mut operands = text["add ".len()..].split(',').map(str::trim);
    let dst = operands.next()?.to_string();
    let base = operands.next()?.to_string();
    let third = operands.next()?.to_string();
    if third.starts_with('#') {
        return None;
    }
    Some((dst, base, third))
}

fn parse_arm64_mov_alias(text: &str) -> Option<&str> {
    if !text.starts_with("mov ") {
        return None;
    }
    let mut operands = text["mov ".len()..].split(',').map(str::trim);
    let dst = operands.next()?;
    let src = operands.next()?;
    let dst_ok = dst.starts_with('x') || dst.eq_ignore_ascii_case("sp");
    let src_ok = src.starts_with('x') || src.eq_ignore_ascii_case("sp");
    if dst_ok && src_ok {
        Some(src)
    } else {
        None
    }
}

fn parse_arm64_relative_target(address: u64, token: &str, page_align: bool) -> Option<u64> {
    let token = token.trim();
    if let Some(offset) = token.strip_prefix("$+") {
        let imm = parse_signed_imm(offset)?;
        let base = if page_align {
            address & !0xfff
        } else {
            address
        };
        return Some(base.saturating_add_signed(imm));
    }
    if let Some(offset) = token.strip_prefix("$-") {
        let imm = parse_signed_imm(offset)?;
        let base = if page_align {
            address & !0xfff
        } else {
            address
        };
        return Some(base.saturating_sub(imm as u64));
    }
    parse_imm_u64(token)
}

#[cfg(feature = "arch-x64")]
fn extract_x64_data_references(
    instructions: &[Instruction],
    string_ranges: &[StringRange],
    executable: &[(u64, u64)],
) -> Vec<Reference> {
    let mut refs = Vec::with_capacity(instructions.len() / 8 + 4);
    for inst in instructions {
        let text = inst.text.as_ref();
        let Some(target) = parse_x64_data_target(inst.address, inst_len(inst) as u64, text) else {
            continue;
        };
        if target == 0 {
            continue;
        }
        if is_string_address(string_ranges, target) {
            refs.push(Reference {
                from: inst.address,
                to: target,
                kind: ReferenceKind::StringRef,
            });
        } else if is_executable_address(executable, target) {
            refs.push(Reference {
                from: inst.address,
                to: target,
                kind: ReferenceKind::IndirectCodePtr,
            });
        } else {
            refs.push(Reference {
                from: inst.address,
                to: target,
                kind: ReferenceKind::DataRef,
            });
        }
    }
    refs
}

fn parse_x64_data_target(ip: u64, inst_size: u64, text: &str) -> Option<u64> {
    let next = ip.saturating_add(inst_size.max(1));
    if let Some(idx) = find_ascii_ci(text, "[rip") {
        let rest = &text[idx + 4..];
        let end = rest.find(']').unwrap_or(rest.len());
        let expr = rest[..end].trim();
        if expr.is_empty() {
            return Some(next);
        }
        if let Some(hex) = expr.strip_prefix("+0x").or_else(|| expr.strip_prefix("+0X")) {
            let disp = u64::from_str_radix(hex, 16).ok()?;
            return Some(next.wrapping_add(disp));
        }
        if let Some(hex) = expr.strip_prefix("-0x").or_else(|| expr.strip_prefix("-0X")) {
            let disp = u64::from_str_radix(hex, 16).ok()?;
            return Some(next.wrapping_sub(disp));
        }
        if let Some(num) = expr.strip_prefix('+') {
            let disp = num.parse::<u64>().ok()?;
            return Some(next.wrapping_add(disp));
        }
        if let Some(num) = expr.strip_prefix('-') {
            let disp = num.parse::<u64>().ok()?;
            return Some(next.wrapping_sub(disp));
        }
        return None;
    }
    if !(starts_with_ascii_ci(text, "lea ") || starts_with_ascii_ci(text, "mov ")) {
        return None;
    }
    if text.contains('[') {
        return None;
    }
    if let Some(idx) = find_ascii_ci(text, "0x") {
        let token = &text[idx..];
        let hex_end = token
            .char_indices()
            .take_while(|(i, c)| *i < 2 || c.is_ascii_hexdigit())
            .map(|(i, _)| i + 1)
            .last()
            .unwrap_or(0);
        let token = &token[..hex_end];
        if let Some(hex) = token.strip_prefix("0x").or_else(|| token.strip_prefix("0X")) {
            if let Ok(value) = u64::from_str_radix(hex, 16) {
                if value > 0x1000 {
                    return Some(value);
                }
            }
        }
    }
    None
}

#[inline]
fn starts_with_ascii_ci(haystack: &str, prefix: &str) -> bool {
    haystack.len() >= prefix.len()
        && haystack
            .as_bytes()
            .iter()
            .zip(prefix.as_bytes())
            .all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase())
}

#[inline]
fn find_ascii_ci(haystack: &str, needle: &str) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if h.len() < n.len() {
        return None;
    }
    for i in 0..=(h.len() - n.len()) {
        if h[i..i + n.len()]
            .iter()
            .zip(n.iter())
            .all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase())
        {
            return Some(i);
        }
    }
    None
}

fn reclassify_string_references(references: &mut [Reference], string_ranges: &[StringRange]) {
    for reference in references {
        if matches!(
            reference.kind,
            ReferenceKind::Data | ReferenceKind::DataRef
        ) && is_string_address(string_ranges, reference.to)
        {
            reference.kind = ReferenceKind::StringRef;
        }
    }
}

fn is_string_address(string_ranges: &[StringRange], target: u64) -> bool {
    if string_ranges.is_empty() {
        return false;
    }
    let mut lo = 0usize;
    let mut hi = string_ranges.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        let range = string_ranges[mid];
        if target < range.start {
            hi = mid;
        } else if target >= range.end {
            lo = mid + 1;
        } else {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use super::{
        CodeRegion, MAX_FUNCTION_BUDGET_FAST, MAX_FUNCTION_BUDGET_FULL, MIN_FUNCTION_BUDGET,
        memory_function_cap,
        arm64_block_has_implicit_fallthrough, arm64_register_used_as_input,
        arm64_track_semantic_state, build_arm64_semantic_local_refs, build_arm64_semantic_state,
        build_arm64_semantic_statements, build_regions, collect_arm64_heuristic_seeds,
        collect_arm64_nearby_seeds, decode_arm64_cfg, decode_arm64_cfg_with_references, decode_x64_cfg_with_references,
        extract_x64_data_references, find_executable_range, function_recovery_budget,
        infer_arm64_argument_type, infer_arm64_return_statement, infer_arm64_stack_arg_bytes,
        infer_arm64_stack_slot_type, infer_return_type, is_string_address, next_hard_boundary,
        attach_relocation_references, promote_data_reference_kinds, reclassify_string_references, recover_arm64_locals,
        split_basic_blocks, summarize_analysis_warnings, StringRange,
    };
    use revx_core::{
        AnalysisProfile, Architecture, BasicBlock, BinaryFormat, BinaryImage, DebugImportSummary,
        Function, Import, Instruction, Reference, ReferenceKind, RegionKind, Section, Variable,
        VariableRole, VariableStorage,
    };
    use std::collections::{BTreeSet, HashMap};

    #[test]
    fn arm64_ret_block_does_not_fall_through_into_next_function() {
        let code_regions = vec![CodeRegion::from_vec(
            0x1000,
            vec![
                0xc0, 0x03, 0x5f, 0xd6, // ret
                0xfd, 0x7b, 0xbe, 0xa9, // stp x29, x30, [sp, #-0x20]!
            ],
        )];

        let instructions = decode_arm64_cfg(&code_regions, 0x1000, 0x1008, &[(0x1000, 0x1008)]);

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].text.as_ref(), "ret");
    }

    #[test]
    fn split_basic_blocks_owned_preserves_boundaries() {
        let instructions = vec![
            Instruction {
                address: 0x1000,
                bytes: std::sync::Arc::from("00000000"),
                text: std::sync::Arc::from("mov x0, x0"),
            },
            Instruction {
                address: 0x1004,
                bytes: std::sync::Arc::from("00000000"),
                text: std::sync::Arc::from("b $+0x8"),
            },
            Instruction {
                address: 0x1008,
                bytes: std::sync::Arc::from("00000000"),
                text: std::sync::Arc::from("ret"),
            },
        ];
        let references = vec![revx_core::Reference {
            from: 0x1004,
            to: 0x1008,
            kind: revx_core::ReferenceKind::BranchFalse,
        }];

        let blocks = split_basic_blocks(0x1000, instructions, &references);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].address, 0x1000);
        assert_eq!(blocks[0].instructions.len(), 2);
        assert_eq!(blocks[1].address, 0x1008);
        assert_eq!(blocks[1].instructions.len(), 1);
    }

    #[test]
    fn arm64_return_and_indirect_branch_blocks_have_no_implicit_fallthrough() {
        assert!(!arm64_block_has_implicit_fallthrough(&[Instruction {
            address: 0x1000,
            bytes: std::sync::Arc::from("c0035fd6"),
            text: std::sync::Arc::from("ret"),
        }]));
        assert!(!arm64_block_has_implicit_fallthrough(&[Instruction {
            address: 0x1004,
            bytes: std::sync::Arc::from("20001fd6"),
            text: std::sync::Arc::from("br x1"),
        }]));
        assert!(arm64_block_has_implicit_fallthrough(&[Instruction {
            address: 0x1008,
            bytes: std::sync::Arc::from("00000094"),
            text: std::sync::Arc::from("bl $+0x0"),
        }]));
    }

    


    #[test]
    fn arm64_encryptor_ssa_render_smoke() {
        let so = std::fs::read("/Users/shiaho/Desktop/ida-mini-mcp/arm64-v8a/libEncryptorP.so").unwrap();
        let region = CodeRegion::from_vec(0, so);
        let code_regions = [region];
        let executable = vec![(0xd68u64, 0x2594u64)];
        let (insts, refs) =
            decode_arm64_cfg_with_references(&code_regions, 0xd68, 0x2594, &executable);
        let blocks = split_basic_blocks(0xd68, insts, &refs);
        let args = vec![];
        let t0 = std::time::Instant::now();
        let ssa = crate::ssa::lift_arm64_to_ssa(&blocks, &refs, &args);
        eprintln!("lift {:?} values={}", t0.elapsed(), ssa.values.len());
        let t1 = std::time::Instant::now();
        let text = crate::ssa::render_ssa_pseudocode_named_layered(
            &ssa,
            "sub_d68",
            &args,
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
        );
        eprintln!("render {:?} lines={}", t1.elapsed(), text.lines().count());
        assert!(text.len() > 50);
        assert!(t1.elapsed().as_secs() < 30, "render too slow {:?}", t1.elapsed());
    }

    #[test]
    fn arm64_encryptor_cfg_size_smoke() {
        let so = std::fs::read("/Users/shiaho/Desktop/ida-mini-mcp/arm64-v8a/libEncryptorP.so").unwrap();
        let region = CodeRegion::from_vec(0, so);
        let code_regions = [region];
        let executable = vec![(0xd68u64, 0xd68 + 0x8000)];
        let (insts, refs) =
            decode_arm64_cfg_with_references(&code_regions, 0xd68, 0xd68 + 0x8000, &executable);
        eprintln!("insts={} jump_refs={}", insts.len(), refs.iter().filter(|r| r.kind==ReferenceKind::Jump).count());
        assert!(insts.len() > 100);
        assert!(insts.len() < 50_000, "pathological decode size {}", insts.len());
    }

    #[test]
    fn arm64_encryptor_style_jump_table_from_real_pattern() {
        // Real pattern from libEncryptorP sub_d68:
        // adrp/add x27 -> table @ 0x7b60
        // ... bit ops ...
        // ldrsw x3, [x27, x10, lsl #2]
        // add x2, x3, x27
        // br x2
        let so = std::fs::read("/Users/shiaho/Desktop/ida-mini-mcp/arm64-v8a/libEncryptorP.so")
            .expect("so");
        // Map whole file at VA 0
        let region = CodeRegion::from_vec(0, so);
        let code_regions = [region];
        // Use CFG decode over the function range
        let executable = vec![(0xd68u64, 0x2594u64)];
        let (insts, refs) =
            decode_arm64_cfg_with_references(&code_regions, 0xd68, 0x2594, &executable);
        let addrs: std::collections::BTreeSet<u64> = insts.iter().map(|i| i.address).collect();
        assert!(
            addrs.contains(&0xe90) || addrs.contains(&0xf10) || addrs.len() > 200,
            "expected jump-table cases recovered; inst_count={} refs_jump={}",
            insts.len(),
            refs.iter().filter(|r| r.kind == ReferenceKind::Jump).count()
        );
        // specifically case targets from table
        for t in [0xe90u64, 0xf10, 0x101c, 0x11ac] {
            assert!(
                addrs.contains(&t),
                "missing case target {t:#x}; count={} sample={:?}",
                insts.len(),
                insts.iter().map(|i| i.address).take(30).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn arm64_base_relative_jump_table_targets_are_recovered() {
        // Android/clang style:
        //   adrp+add table_base
        //   ldrsw x3, [x27, x10, lsl #2]
        //   add x2, x3, x27
        //   br x2
        // entries are signed offsets from table_base itself.
        let mut region_data = vec![0u8; 0x300];
        let table_off = 0x200usize;
        let base = 0x1000u64 + table_off as u64;
        let cases = [0x1100u64, 0x1140, 0x1180, 0x11c0];
        for (i, case) in cases.iter().enumerate() {
            let rel = (*case as i64) - (base as i64);
            region_data[table_off + i * 4..table_off + i * 4 + 4]
                .copy_from_slice(&(rel as i32).to_le_bytes());
        }
        let region = CodeRegion::from_vec(0x1000, region_data);
        let code_regions = [region];
        let block = vec![
            Instruction {
                address: 0x1020,
                bytes: std::sync::Arc::from("00"),
                text: std::sync::Arc::from("adrp x27, $+0x0"),
            },
            Instruction {
                address: 0x1024,
                bytes: std::sync::Arc::from("00"),
                text: std::sync::Arc::from("add x27, x27, #0x200"),
            },
            Instruction {
                address: 0x1028,
                bytes: std::sync::Arc::from("00"),
                text: std::sync::Arc::from("ldrsw x3, [x27, x10, lsl #2]"),
            },
            Instruction {
                address: 0x102c,
                bytes: std::sync::Arc::from("00"),
                text: std::sync::Arc::from("add x2, x3, x27"),
            },
            Instruction {
                address: 0x1030,
                bytes: std::sync::Arc::from("00"),
                text: std::sync::Arc::from("br x2"),
            },
        ];
        let refs = super::recover_arm64_pc_rel_jump_table_targets(
            &block,
            &code_regions,
            0x1000,
            0x1300,
        )
        .expect("base-relative jump table");
        let targets: std::collections::BTreeSet<u64> = refs
            .iter()
            .filter(|r| r.kind == ReferenceKind::Jump)
            .map(|r| r.to)
            .collect();
        for case in cases {
            assert!(targets.contains(&case), "missing {case:#x} in {targets:?}");
        }
    }

    #[test]
    fn arm64_pc_rel_jump_table_targets_are_recovered() {
        // Pattern from /bin/ls getopt dispatch:
        //   cmp / csel / adrp+add table / ldrsw / adr / add / br
        let mut region_data = vec![0u8; 0x200];
        // table at region+0x100 with 4 relative entries to local case stubs
        let table_off = 0x100usize;
        let anchor = 0x1000u64 + 0x40; // adr at 0x1040
        let cases = [0x1050u64, 0x1060, 0x1070, 0x1080];
        for (i, case) in cases.iter().enumerate() {
            let rel = (*case as i64) - (anchor as i64);
            let bytes = (rel as i32).to_le_bytes();
            region_data[table_off + i * 4..table_off + i * 4 + 4].copy_from_slice(&bytes);
        }
        let region = CodeRegion::from_vec(0x1000, region_data);
        let code_regions = [region];
        let block = vec![
            Instruction {
                address: 0x101c,
                bytes: std::sync::Arc::from("00"),
                text: std::sync::Arc::from("sub w16, w0, #0x25"),
            },
            Instruction {
                address: 0x1020,
                bytes: std::sync::Arc::from("00"),
                text: std::sync::Arc::from("cmp x16, #0x3"),
            },
            Instruction {
                address: 0x1024,
                bytes: std::sync::Arc::from("00"),
                text: std::sync::Arc::from("csel x16, x16, xzr, ls"),
            },
            Instruction {
                address: 0x1028,
                bytes: std::sync::Arc::from("00"),
                text: std::sync::Arc::from("adrp x17, $+0x0"),
            },
            Instruction {
                address: 0x102c,
                bytes: std::sync::Arc::from("00"),
                text: std::sync::Arc::from("add x17, x17, #0x100"),
            },
            Instruction {
                address: 0x1030,
                bytes: std::sync::Arc::from("00"),
                text: std::sync::Arc::from("ldrsw x16, [x17, x16, lsl #2]"),
            },
            Instruction {
                address: 0x1040,
                bytes: std::sync::Arc::from("00"),
                text: std::sync::Arc::from("adr x17, $+0x0"),
            },
            Instruction {
                address: 0x1044,
                bytes: std::sync::Arc::from("00"),
                text: std::sync::Arc::from("add x16, x17, x16"),
            },
            Instruction {
                address: 0x1048,
                bytes: std::sync::Arc::from("00"),
                text: std::sync::Arc::from("br x16"),
            },
        ];
        let refs = super::recover_arm64_pc_rel_jump_table_targets(&block, &code_regions, 0x1000, 0x1200)
            .expect("jump table targets");
        let jump_targets: std::collections::BTreeSet<u64> = refs
            .iter()
            .filter(|r| r.kind == ReferenceKind::Jump)
            .map(|r| r.to)
            .collect();
        for case in cases {
            assert!(jump_targets.contains(&case), "missing {case:#x} in {jump_targets:?}");
        }
        // With sub #0x25 bias, first slot is case '%'.
        let case_chars: std::collections::BTreeSet<u64> = refs
            .iter()
            .filter(|r| r.kind == ReferenceKind::DataRef)
            .filter_map(|r| super::case_char_untag(r.to))
            .collect();
        assert!(
            case_chars.contains(&0x25),
            "missing case char annotations in {case_chars:?}"
        );
        assert!(refs.len() >= 4);
    }

#[test]
    fn arm64_heuristic_seeds_require_a_real_boundary() {
        let code_regions = vec![CodeRegion::from_vec(
            0x1000,
            vec![
                0xc0, 0x03, 0x5f, 0xd6, // ret
                0xfd, 0x7b, 0xbe, 0xa9, // stp x29, x30, [sp, #-0x20]!
                0xfd, 0x03, 0x00, 0x91, // mov x29, sp
                0xfd, 0x7b, 0xbe, 0xa9, // same prologue pattern again, but not at a boundary
                0x1f, 0x20, 0x03, 0xd5, // nop
                0xc0, 0x03, 0x5f, 0xd6, // ret
            ],
        )];

        let seeds = collect_arm64_heuristic_seeds(&code_regions);
        assert_eq!(seeds, vec![0x1004]);
    }

    #[test]
    fn arm64_paciasp_prefixed_prologues_seed_the_real_function_start() {
        let code_regions = vec![CodeRegion::from_vec(
            0x5081f0,
            vec![
                0x5f, 0x24, 0x03, 0xd5, // bti c
                0xe3, 0xff, 0xff, 0x17, // b $-0x7c
                0x3f, 0x23, 0x03, 0xd5, // paciasp
                0xfd, 0x7b, 0xbf, 0xa9, // stp x29, x30, [sp, #-0x10]!
                0xfd, 0x03, 0x00, 0x91, // mov x29, sp
            ],
        )];

        let seeds = collect_arm64_heuristic_seeds(&code_regions);
        assert!(seeds.contains(&0x5081f8));
        assert!(!seeds.contains(&0x5081fc));
    }

    #[test]
    fn arm64_nearby_seed_scan_finds_follow_on_function_after_return() {
        let code_regions = vec![CodeRegion::from_vec(
            0x5081b4,
            vec![
                0xf3, 0x0b, 0x40, 0xf9, // ldr x19, [sp, #0x10]
                0xfd, 0x7b, 0xc2, 0xa8, // ldp x29, x30, [sp], #0x20
                0xbf, 0x23, 0x03, 0xd5, // autiasp
                0xc0, 0x03, 0x5f, 0xd6, // ret
                0x00, 0x01, 0x80, 0x52, // mov w0, #8
                0x2c, 0x00, 0x00, 0x94, // bl $+0xb0
                0xf3, 0x03, 0x00, 0xaa, // mov x19, x0
                0xc9, 0x99, 0xff, 0x97, // bl $-0x1999c
                0x21, 0x00, 0x00, 0x90, // adrp x1, 0x51c000
                0x22, 0x00, 0x00, 0x90, // adrp x2, 0x51c000
                0xe0, 0x03, 0x13, 0xaa, // mov x0, x19
                0x21, 0x14, 0x46, 0xf9, // ldr x1, [x1, #0xc28]
                0x42, 0x18, 0x46, 0xf9, // ldr x2, [x2, #0xc30]
                0x6c, 0x00, 0x00, 0x94, // bl $+0x1b0
                0x5b, 0x02, 0xf3, 0x97, // bl $-0x33f694
                0x5f, 0x24, 0x03, 0xd5, // bti c
                0xe3, 0xff, 0xff, 0x17, // b $-0x7c
                0x3f, 0x23, 0x03, 0xd5, // paciasp
                0xfd, 0x7b, 0xbf, 0xa9, // stp x29, x30, [sp, #-0x10]!
                0xfd, 0x03, 0x00, 0x91, // mov x29, sp
            ],
        )];

        let seeds = collect_arm64_nearby_seeds(&code_regions, 0x5081f0, 0x508208);
        assert!(seeds.contains(&0x5081f8));
    }

    #[test]
    fn arm64_frame_save_slots_are_not_reported_as_locals() {
        let instructions = vec![
            Instruction {
                address: 0x5081f8,
                bytes: std::sync::Arc::from("3f2303d5"),
                text: std::sync::Arc::from("paciasp"),
            },
            Instruction {
                address: 0x5081fc,
                bytes: std::sync::Arc::from("fd7bbfa9"),
                text: std::sync::Arc::from("stp x29, x30, [sp, #-0x10]!"),
            },
            Instruction {
                address: 0x508200,
                bytes: std::sync::Arc::from("fd030091"),
                text: std::sync::Arc::from("mov x29, sp"),
            },
            Instruction {
                address: 0x508204,
                bytes: std::sync::Arc::from("fbffff97"),
                text: std::sync::Arc::from("bl $-0x14"),
            },
            Instruction {
                address: 0x508208,
                bytes: std::sync::Arc::from("fd7bc1a8"),
                text: std::sync::Arc::from("ldp x29, x30, [sp], #0x10"),
            },
            Instruction {
                address: 0x50820c,
                bytes: std::sync::Arc::from("bf2303d5"),
                text: std::sync::Arc::from("autiasp"),
            },
            Instruction {
                address: 0x508210,
                bytes: std::sync::Arc::from("c0035fd6"),
                text: std::sync::Arc::from("ret"),
            },
        ];

        assert!(recover_arm64_locals(&instructions).is_empty());
    }

    #[test]
    fn arm64_wrapper_has_no_inferred_stack_args() {
        let instructions = vec![
            Instruction {
                address: 0x5081f8,
                bytes: std::sync::Arc::from("3f2303d5"),
                text: std::sync::Arc::from("paciasp"),
            },
            Instruction {
                address: 0x5081fc,
                bytes: std::sync::Arc::from("fd7bbfa9"),
                text: std::sync::Arc::from("stp x29, x30, [sp, #-0x10]!"),
            },
            Instruction {
                address: 0x508200,
                bytes: std::sync::Arc::from("fd030091"),
                text: std::sync::Arc::from("mov x29, sp"),
            },
            Instruction {
                address: 0x508204,
                bytes: std::sync::Arc::from("fbffff97"),
                text: std::sync::Arc::from("bl $-0x14"),
            },
            Instruction {
                address: 0x508208,
                bytes: std::sync::Arc::from("fd7bc1a8"),
                text: std::sync::Arc::from("ldp x29, x30, [sp], #0x10"),
            },
            Instruction {
                address: 0x508210,
                bytes: std::sync::Arc::from("c0035fd6"),
                text: std::sync::Arc::from("ret"),
            },
        ];

        assert_eq!(
            infer_arm64_stack_arg_bytes(&instructions, Some(16)),
            Some(0)
        );
    }

    #[test]
    fn arm64_positive_sp_offsets_past_frame_are_counted_as_stack_args() {
        let instructions = vec![
            Instruction {
                address: 0x1000,
                bytes: std::sync::Arc::from("ff8300d1"),
                text: std::sync::Arc::from("sub sp, sp, #0x20"),
            },
            Instruction {
                address: 0x1004,
                bytes: std::sync::Arc::from("00c340f9"),
                text: std::sync::Arc::from("ldr x0, [sp, #0x38]"),
            },
        ];

        assert_eq!(
            infer_arm64_stack_arg_bytes(&instructions, Some(32)),
            Some(32)
        );
    }

    #[test]
    fn arm64_register_written_before_read_is_not_treated_as_argument() {
        let instructions = vec![
            Instruction {
                address: 0x5081d4,
                bytes: std::sync::Arc::from("21000090"),
                text: std::sync::Arc::from("adrp x1, $+0x14000"),
            },
            Instruction {
                address: 0x5081d8,
                bytes: std::sync::Arc::from("22000090"),
                text: std::sync::Arc::from("adrp x2, $+0x14000"),
            },
            Instruction {
                address: 0x5081e0,
                bytes: std::sync::Arc::from("211446f9"),
                text: std::sync::Arc::from("ldr x1, [x1, #0xc28]"),
            },
            Instruction {
                address: 0x5081e4,
                bytes: std::sync::Arc::from("421846f9"),
                text: std::sync::Arc::from("ldr x2, [x2, #0xc30]"),
            },
        ];

        assert!(!arm64_register_used_as_input(&instructions, "x1", "w1"));
        assert!(!arm64_register_used_as_input(&instructions, "x2", "w2"));
    }

    #[test]
    fn arm64_register_read_before_write_is_treated_as_argument() {
        let instructions = vec![
            Instruction {
                address: 0x508190,
                bytes: std::sync::Arc::from("1f0400f1"),
                text: std::sync::Arc::from("cmp x0, #0x1"),
            },
            Instruction {
                address: 0x508194,
                bytes: std::sync::Arc::from("1304809a"),
                text: std::sync::Arc::from("csinc x19, x0, xzr, hi"),
            },
        ];

        assert!(arm64_register_used_as_input(&instructions, "x0", "w0"));
    }

    #[test]
    fn arm64_cmp_usage_infers_integer_argument_type() {
        let instructions = vec![
            Instruction {
                address: 0x508190,
                bytes: std::sync::Arc::from("1f0400f1"),
                text: std::sync::Arc::from("cmp x0, #0x1"),
            },
            Instruction {
                address: 0x508194,
                bytes: std::sync::Arc::from("1304809a"),
                text: std::sync::Arc::from("csinc x19, x0, xzr, hi"),
            },
        ];

        assert_eq!(
            infer_arm64_argument_type(&instructions, "x0", "w0"),
            Some("int64_t".to_string())
        );
    }

    #[test]
    fn arm64_memory_base_usage_infers_pointer_argument_type() {
        let instructions = vec![
            Instruction {
                address: 0x1000,
                bytes: std::sync::Arc::from("010040f9"),
                text: std::sync::Arc::from("ldr x1, [x0, #0x8]"),
            },
            Instruction {
                address: 0x1004,
                bytes: std::sync::Arc::from("200000b4"),
                text: std::sync::Arc::from("cbz x1, $+0x4"),
            },
        ];

        assert_eq!(
            infer_arm64_argument_type(&instructions, "x0", "w0"),
            Some("void *".to_string())
        );
    }

    #[test]
    fn arm64_stack_slot_type_tracks_register_width() {
        let instructions = vec![
            Instruction {
                address: 0x1000,
                bytes: std::sync::Arc::from("e00f00b9"),
                text: std::sync::Arc::from("str w0, [sp, #0xc]"),
            },
            Instruction {
                address: 0x1004,
                bytes: std::sync::Arc::from("e10b40f9"),
                text: std::sync::Arc::from("ldr x1, [sp, #0x10]"),
            },
        ];

        assert_eq!(
            infer_arm64_stack_slot_type(&instructions, 0xc),
            Some("uint32_t".to_string())
        );
        assert_eq!(
            infer_arm64_stack_slot_type(&instructions, 0x10),
            Some("uint64_t".to_string())
        );
    }

    #[test]
    fn arm64_large_positive_stack_runs_are_grouped_into_spans() {
        let instructions = vec![
            Instruction {
                address: 0x1000,
                bytes: std::sync::Arc::from("e00f40f9"),
                text: std::sync::Arc::from("ldr x0, [sp, #0x20]"),
            },
            Instruction {
                address: 0x1004,
                bytes: std::sync::Arc::from("e11340f9"),
                text: std::sync::Arc::from("ldr x1, [sp, #0x28]"),
            },
            Instruction {
                address: 0x1008,
                bytes: std::sync::Arc::from("e21740f9"),
                text: std::sync::Arc::from("ldr x2, [sp, #0x30]"),
            },
            Instruction {
                address: 0x100c,
                bytes: std::sync::Arc::from("e31b40f9"),
                text: std::sync::Arc::from("ldr x3, [sp, #0x38]"),
            },
            Instruction {
                address: 0x1010,
                bytes: std::sync::Arc::from("e41f40f9"),
                text: std::sync::Arc::from("ldr x4, [sp, #0x40]"),
            },
        ];

        let locals = recover_arm64_locals(&instructions);
        assert_eq!(locals.len(), 1);
        assert_eq!(locals[0].start_offset, 0x20);
        assert_eq!(locals[0].end_offset, Some(0x40));
        assert_eq!(locals[0].type_name, Some("stack_span_t".to_string()));
    }

    #[test]
    fn arm64_large_dense_workspace_becomes_workspace_span() {
        let mut instructions = Vec::new();
        let mut address = 0x2000u64;
        for offset in (0x100..=0x740).step_by(8) {
            instructions.push(Instruction {
                address,
                bytes: std::sync::Arc::from("000040f9"),
                text: std::sync::Arc::from(format!("ldr x0, [sp, #{offset:#x}]").as_str()),
            });
            address += 4;
        }

        let locals = recover_arm64_locals(&instructions);
        assert_eq!(locals.len(), 1);
        assert_eq!(locals[0].start_offset, 0x100);
        assert_eq!(locals[0].end_offset, Some(0x740));
        assert_eq!(locals[0].type_name, Some("stack_array_t".to_string()));
    }

    #[test]
    fn arm64_record_array_pattern_becomes_array_span() {
        let mut instructions = Vec::new();
        let mut address = 0x2800u64;
        for base in (0x48..=0x1f8).step_by(0x18) {
            instructions.push(Instruction {
                address,
                bytes: std::sync::Arc::from("000040f9"),
                text: std::sync::Arc::from(format!("ldr x0, [sp, #{base:#x}]").as_str()),
            });
            address += 4;
            instructions.push(Instruction {
                address,
                bytes: std::sync::Arc::from("00000039"),
                text: std::sync::Arc::from(format!("ldrb w0, [sp, #{:#x}]", base + 0x10).as_str()),
            });
            address += 4;
        }

        let locals = recover_arm64_locals(&instructions);
        assert_eq!(locals.len(), 1);
        assert_eq!(locals[0].start_offset, 0x48);
        assert_eq!(locals[0].end_offset, Some(0x208));
        assert_eq!(locals[0].type_name, Some("stack_array_t".to_string()));
    }

    #[test]
    fn arm64_sp_root_buffer_becomes_stack_object() {
        let instructions = vec![
            Instruction {
                address: 0x1000,
                bytes: std::sync::Arc::from("00000039"),
                text: std::sync::Arc::from("strb w8, [sp, #0x40]"),
            },
            Instruction {
                address: 0x1004,
                bytes: std::sync::Arc::from("e0031faa"),
                text: std::sync::Arc::from("mov x0, sp"),
            },
            Instruction {
                address: 0x1008,
                bytes: std::sync::Arc::from("e00f00ad"),
                text: std::sync::Arc::from("stp q0, q0, [sp]"),
            },
            Instruction {
                address: 0x100c,
                bytes: std::sync::Arc::from("e01f01ad"),
                text: std::sync::Arc::from("stp q0, q0, [sp, #0x20]"),
            },
        ];

        let locals = recover_arm64_locals(&instructions);
        assert!(locals.iter().any(|local| {
            local.start_offset == 0
                && local.end_offset == Some(0x40)
                && local.type_name == Some("stack_buffer_t".to_string())
        }));
    }

    #[test]
    fn arm64_semantic_calls_use_sp_root_buffer_aliases() {
        let block = BasicBlock {
            address: 0x1000,
            size: 20,
            instructions: vec![
                Instruction {
                    address: 0x1000,
                    bytes: std::sync::Arc::from("00000039"),
                    text: std::sync::Arc::from("strb w8, [sp, #0x40]"),
                },
                Instruction {
                    address: 0x1004,
                    bytes: std::sync::Arc::from("e00f00ad"),
                    text: std::sync::Arc::from("stp q0, q0, [sp]"),
                },
                Instruction {
                    address: 0x1008,
                    bytes: std::sync::Arc::from("e01f01ad"),
                    text: std::sync::Arc::from("stp q0, q0, [sp, #0x20]"),
                },
                Instruction {
                    address: 0x100c,
                    bytes: std::sync::Arc::from("e0031faa"),
                    text: std::sync::Arc::from("mov x1, sp"),
                },
                Instruction {
                    address: 0x1010,
                    bytes: std::sync::Arc::from("20000094"),
                    text: std::sync::Arc::from("bl $+0x8"),
                },
            ],
        };
        let locals = vec![Variable {
            name: "stack_buffer_0".to_string(),
            role: VariableRole::Local,
            storage: VariableStorage::Stack,
            type_name: Some("stack_buffer_t".to_string()),
            confidence: 0.35,
            location: "stack[+0x0..+0x40]".to_string(),
            evidence_ids: vec!["vars:test:local:0".to_string()],
        }];
        let imports = vec![Import {
            library: Some("libc.so".to_string()),
            name: "memcpy".to_string(),
            address: Some(0x1018),
        }];
        let overrides = HashMap::from([(0x1010, 0x1018)]);

        let arguments = vec![Variable {
            name: "arg_0".to_string(),
            role: VariableRole::Argument,
            storage: VariableStorage::Register,
            type_name: None,
            confidence: 0.2,
            location: "x0".to_string(),
            evidence_ids: vec!["vars:test:arg:0".to_string()],
        }];
        let statements =
            build_arm64_semantic_statements(&[block], &arguments, &locals, &imports, &overrides);
        assert!(
            statements
                .iter()
                .any(|item| item == "memcpy(arg_0, stack_buffer_0, x2);"),
            "got: {statements:?}"
        );
    }

    #[test]
    fn arm64_semantic_values_degrade_before_recursive_blowup() {
        let locals = vec![Variable {
            name: "stack_buffer_0".to_string(),
            role: VariableRole::Local,
            storage: VariableStorage::Stack,
            type_name: Some("stack_buffer_t".to_string()),
            confidence: 0.35,
            location: "stack[+0x0..+0x40]".to_string(),
            evidence_ids: vec!["vars:test:local:0".to_string()],
        }];
        let local_refs = build_arm64_semantic_local_refs(&locals);
        let arguments = vec![Variable {
            name: "arg_0".to_string(),
            role: VariableRole::Argument,
            storage: VariableStorage::Register,
            type_name: None,
            confidence: 0.2,
            location: "x0".to_string(),
            evidence_ids: vec!["vars:test:arg:0".to_string()],
        }];
        let mut state = build_arm64_semantic_state(&arguments, &local_refs);

        let empty = HashMap::<u64, &str>::new();
        arm64_track_semantic_state(0, "mov x1, sp", &local_refs, &mut state, &empty);
        for _ in 0..64 {
            arm64_track_semantic_state(0, "add x1, x1, x2", &local_refs, &mut state, &empty);
            arm64_track_semantic_state(0, "ldr x1, [x1, #0x8]", &local_refs, &mut state, &empty);
        }

        let x1 = state.values.get("x1").copied().unwrap_or_default();
        assert!(state.nodes.get(x1).is_some());
        assert_eq!(state.nodes.len(), state.node_ids.len());
        assert!(state.nodes.len() <= (2 * 64) + 8);
    }

    #[test]
    fn arm64_semantic_calls_use_stack_object_aliases() {
        let block = BasicBlock {
            address: 0x1000,
            size: 16,
            instructions: vec![
                Instruction {
                    address: 0x1000,
                    bytes: std::sync::Arc::from("e0130091"),
                    text: std::sync::Arc::from("add x0, sp, #0x48"),
                },
                Instruction {
                    address: 0x1004,
                    bytes: std::sync::Arc::from("1f000094"),
                    text: std::sync::Arc::from("bl $+0x4"),
                },
                Instruction {
                    address: 0x1008,
                    bytes: std::sync::Arc::from("e1130091"),
                    text: std::sync::Arc::from("add x1, sp, #0x48"),
                },
                Instruction {
                    address: 0x100c,
                    bytes: std::sync::Arc::from("20000094"),
                    text: std::sync::Arc::from("bl $+0x8"),
                },
            ],
        };
        let locals = vec![Variable {
            name: "stack_array_0".to_string(),
            role: VariableRole::Local,
            storage: VariableStorage::Stack,
            type_name: Some("stack_array_t".to_string()),
            confidence: 0.35,
            location: "stack[+0x48..+0x238]".to_string(),
            evidence_ids: vec!["vars:test:local:48".to_string()],
        }];
        let imports = vec![
            Import {
                library: Some("libc.so".to_string()),
                name: "free".to_string(),
                address: Some(0x1008),
            },
            Import {
                library: Some("libc.so".to_string()),
                name: "memcpy".to_string(),
                address: Some(0x1014),
            },
        ];
        let overrides = HashMap::from([(0x1004, 0x1008), (0x100c, 0x1014)]);

        let arguments = vec![Variable {
            name: "arg_0".to_string(),
            role: VariableRole::Argument,
            storage: VariableStorage::Register,
            type_name: None,
            confidence: 0.2,
            location: "x0".to_string(),
            evidence_ids: vec!["vars:test:arg:0".to_string()],
        }];
        let statements =
            build_arm64_semantic_statements(&[block], &arguments, &locals, &imports, &overrides);
        assert!(statements.iter().any(|item| item == "free(stack_array_0);"));
        assert!(
            statements
                .iter()
                .any(|item| item == "memcpy(result, stack_array_0, x2);"),
            "got: {statements:?}"
        );
    }

    #[test]
    fn arm64_large_sparse_workspace_stays_discrete_under_current_rules() {
        let mut instructions = Vec::new();
        let mut address = 0x3000u64;
        for offset in (0x100..=0x700).step_by(0x28) {
            instructions.push(Instruction {
                address,
                bytes: std::sync::Arc::from("00000039"),
                text: std::sync::Arc::from(format!("strb w0, [sp, #{offset:#x}]").as_str()),
            });
            address += 4;
        }

        let locals = recover_arm64_locals(&instructions);
        assert!(locals.len() > 16);
        assert!(
            locals
                .iter()
                .all(|local| local.type_name != Some("stack_buffer_t".to_string()))
        );
    }

    #[test]
    fn arm64_wrapper_without_usage_keeps_argument_type_unknown() {
        let instructions = vec![
            Instruction {
                address: 0x5081f8,
                bytes: std::sync::Arc::from("3f2303d5"),
                text: std::sync::Arc::from("paciasp"),
            },
            Instruction {
                address: 0x5081fc,
                bytes: std::sync::Arc::from("fd7bbfa9"),
                text: std::sync::Arc::from("stp x29, x30, [sp, #-0x10]!"),
            },
            Instruction {
                address: 0x508200,
                bytes: std::sync::Arc::from("fd030091"),
                text: std::sync::Arc::from("mov x29, sp"),
            },
            Instruction {
                address: 0x508204,
                bytes: std::sync::Arc::from("fbffff97"),
                text: std::sync::Arc::from("bl $-0x14"),
            },
            Instruction {
                address: 0x508208,
                bytes: std::sync::Arc::from("fd7bc1a8"),
                text: std::sync::Arc::from("ldp x29, x30, [sp], #0x10"),
            },
            Instruction {
                address: 0x508210,
                bytes: std::sync::Arc::from("c0035fd6"),
                text: std::sync::Arc::from("ret"),
            },
        ];

        assert_eq!(infer_arm64_argument_type(&instructions, "x0", "w0"), None);
    }

    #[test]
    fn function_recovery_budget_scales_with_executable_text_size() {
        let image = BinaryImage {
            id: "test".to_string(),
            path: "/tmp/test".to_string(),
            format: BinaryFormat::Elf,
            architecture: Architecture::Arm64,
            entry: None,
            image_base: None,
            size: 0,
            hash_blake3: "hash".to_string(),
            modules: Vec::new(),
            segments: Vec::new(),
            sections: vec![Section {
                name: ".text".to_string(),
                address: 0,
                size: 0x80000,
                kind: "Text".to_string(),
                file_offset: None,
            }],
            imports: Vec::new(),
            exports: Vec::new(),
            relocations: Vec::new(),
            debug_artifacts: Vec::new(),
            debug_import: DebugImportSummary::default(),
            symbols: Vec::new(),
            strings: Vec::new(),
        };

        let fast = function_recovery_budget(&image, AnalysisProfile::Fast);
        let full = function_recovery_budget(&image, AnalysisProfile::Full);
        assert!(fast >= MIN_FUNCTION_BUDGET);
        assert!(full >= MIN_FUNCTION_BUDGET);
        assert!(fast <= MAX_FUNCTION_BUDGET_FAST);
        assert!(full <= MAX_FUNCTION_BUDGET_FULL);
        assert!(full >= fast);
    }

    #[test]
    fn x64_rip_relative_loads_become_data_or_string_refs() {
        let instructions = vec![
            Instruction {
                address: 0x1000,
                bytes: std::sync::Arc::from("488d0d00000000"),
                text: std::sync::Arc::from("lea rcx, [rip+0x10]"),
            },
            Instruction {
                address: 0x1007,
                bytes: std::sync::Arc::from("488b1500000000"),
                text: std::sync::Arc::from("mov rdx, qword ptr [rip+0x20]"),
            },
        ];
        let string_ranges = vec![StringRange {
            start: 0x1017,
            end: 0x1020,
        }];
        let executable = vec![(0x1000, 0x1010)];
        let refs = extract_x64_data_references(&instructions, &string_ranges, &executable);
        assert!(
            refs.iter()
                .any(|r| r.kind == ReferenceKind::StringRef && r.to == 0x1017),
            "expected string ref to rip+0x10 target: {refs:?}"
        );
        assert!(
            refs.iter()
                .any(|r| r.kind == ReferenceKind::DataRef && r.to == 0x102e),
            "expected data ref to rip+0x20 target: {refs:?}"
        );
    }

    #[test]
    fn relocation_refs_attach_to_function_range() {
        let instructions = vec![
            Instruction {
                address: 0x1000,
                bytes: std::sync::Arc::from("c3"),
                text: std::sync::Arc::from("ret"),
            },
            Instruction {
                address: 0x1001,
                bytes: std::sync::Arc::from("90"),
                text: std::sync::Arc::from("nop"),
            },
        ];
        let reloc = vec![
            Reference {
                from: 0x1000,
                to: 0x4000,
                kind: ReferenceKind::DataRef,
            },
            Reference {
                from: 0x2000,
                to: 0x4000,
                kind: ReferenceKind::DataRef,
            },
        ];
        let mut refs = Vec::new();
        attach_relocation_references(&mut refs, &instructions, &reloc);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].from, 0x1000);
    }

    #[test]
    fn promote_data_refs_classifies_string_code_and_data() {
        let ranges = vec![StringRange {
            start: 0x4000,
            end: 0x4010,
        }];
        let executable = vec![(0x1000, 0x2000)];
        let mut refs = vec![
            Reference {
                from: 0x1100,
                to: 0x4004,
                kind: ReferenceKind::Data,
            },
            Reference {
                from: 0x1108,
                to: 0x1500,
                kind: ReferenceKind::Data,
            },
            Reference {
                from: 0x1110,
                to: 0x5000,
                kind: ReferenceKind::Data,
            },
        ];
        promote_data_reference_kinds(&mut refs, &ranges, &executable);
        assert_eq!(refs[0].kind, ReferenceKind::StringRef);
        assert_eq!(refs[1].kind, ReferenceKind::IndirectCodePtr);
        assert_eq!(refs[2].kind, ReferenceKind::DataRef);
    }

    #[test]
    fn x64_lea_to_executable_becomes_indirect_code_ptr() {
        let instructions = vec![Instruction {
            address: 0x1000,
            bytes: std::sync::Arc::from("488d0d00000000"),
            text: std::sync::Arc::from("lea rcx, [rip+0x10]"),
        }];
        let string_ranges = Vec::new();
        let executable = vec![(0x1000, 0x1100)];
        let refs = extract_x64_data_references(&instructions, &string_ranges, &executable);
        assert!(
            refs.iter()
                .any(|r| r.kind == ReferenceKind::IndirectCodePtr && r.to == 0x1017),
            "expected code ptr to rip+0x10 target: {refs:?}"
        );
    }

    #[test]
    fn reclassify_promotes_data_refs_into_string_ranges() {
        let ranges = vec![StringRange {
            start: 0x4000,
            end: 0x4010,
        }];
        let mut refs = vec![Reference {
            from: 0x1000,
            to: 0x4004,
            kind: ReferenceKind::Data,
        }];
        reclassify_string_references(&mut refs, &ranges);
        assert_eq!(refs[0].kind, ReferenceKind::StringRef);
        assert!(is_string_address(&ranges, 0x4004));
        assert!(!is_string_address(&ranges, 0x4010));
    }


    #[test]
    fn parallel_worker_count_is_capped() {
        let n = super::parallel_worker_count();
        assert!(n >= 1, "{n}");
        assert!(n <= 2, "{n}");
    }

    #[test]
    fn arm64_cfg_follows_low_va_unconditional_jumps() {
        // Buffer mapped at VA 0xe00. Sequence:
        // 0xe00: nop
        // 0xe04: b +8 -> 0xe0c
        // 0xe08: ret   (skipped)
        // 0xe0c: mov w0, #1
        // 0xe10: ret
        let mut bytes = vec![0u8; 0x14];
        bytes[0..4].copy_from_slice(&0xD503201Fu32.to_le_bytes()); // nop
        bytes[4..8].copy_from_slice(&0x14000002u32.to_le_bytes()); // b +8
        bytes[8..12].copy_from_slice(&0xD65F03C0u32.to_le_bytes()); // ret
        bytes[12..16].copy_from_slice(&0x52800020u32.to_le_bytes()); // mov w0, #1
        bytes[16..20].copy_from_slice(&0xD65F03C0u32.to_le_bytes()); // ret
        let regions = vec![CodeRegion::from_vec(0xe00, bytes)];
        let executable = vec![(0xe00u64, 0xe14u64)];
        let (instructions, references) =
            decode_arm64_cfg_with_references(&regions, 0xe00, 0xe14, &executable);
        assert!(
            references.iter().any(|r| {
                r.kind == ReferenceKind::Jump && r.from == 0xe04 && r.to == 0xe0c
            }),
            "expected jump 0xe04 -> 0xe0c, refs={references:?}"
        );
        assert!(
            instructions.iter().any(|i| i.address == 0xe0c),
            "expected CFG to follow low-VA jump into 0xe0c, insts={:?}",
            instructions.iter().map(|i| i.address).collect::<Vec<_>>()
        );
        assert!(
            !instructions.iter().any(|i| i.address == 0xe08),
            "skipped fallthrough ret should not be required, but jump target must be present"
        );
    }

    #[test]
    fn x64_cfg_decode_follows_conditional_branches() {
        // cmp eax,0 ; je target ; mov eax,1 ; ret ; target: mov eax,2 ; ret
        // je rel8 = +5 skips the false-path mov+ret and lands on true-path mov.
        let bytes = vec![
            0x83, 0xf8, 0x00, // 1000: cmp eax, 0
            0x74, 0x06, // 1003: je +6 -> 100b
            0xb8, 0x01, 0x00, 0x00, 0x00, // 1005: mov eax, 1
            0xc3, // 100a: ret
            0xb8, 0x02, 0x00, 0x00, 0x00, // 100b: mov eax, 2
            0xc3, // 1010: ret
        ];
        let regions = vec![CodeRegion::from_vec(0x1000, bytes)];
        let (instructions, references) =
            decode_x64_cfg_with_references(&regions, 0x1000, 0x1020, &[(0x1000, 0x1020)]);
        assert!(
            instructions.len() >= 5,
            "expected full CFG coverage, got {} insts: {:?}",
            instructions.len(),
            instructions
                .iter()
                .map(|i| (i.address, i.text.as_ref().to_string()))
                .collect::<Vec<_>>()
        );
        assert!(
            references.iter().any(|r| r.kind == ReferenceKind::BranchTrue),
            "expected conditional branch true edge"
        );
        assert!(
            references.iter().any(|r| r.kind == ReferenceKind::BranchFalse),
            "expected conditional branch false edge"
        );
        assert!(
            instructions.iter().any(|i| i.address == 0x100b),
            "expected true-path target at 0x100b"
        );
    }

    #[test]
    fn find_executable_range_uses_sorted_binary_search() {
        let ranges = vec![(0x1000, 0x2000), (0x3000, 0x4000), (0x5000, 0x6000)];
        assert_eq!(find_executable_range(&ranges, 0x1000), Some((0x1000, 0x2000)));
        assert_eq!(find_executable_range(&ranges, 0x1fff), Some((0x1000, 0x2000)));
        assert_eq!(find_executable_range(&ranges, 0x2000), None);
        assert_eq!(find_executable_range(&ranges, 0x3500), Some((0x3000, 0x4000)));
        assert_eq!(find_executable_range(&ranges, 0x0fff), None);
        assert_eq!(find_executable_range(&ranges, 0x6000), None);
        assert_eq!(find_executable_range(&ranges, 0x5000), Some((0x5000, 0x6000)));
    }

    #[test]
    fn large_text_section_raises_function_budget_with_profile_cap() {
        let image = BinaryImage {
            id: "large".to_string(),
            path: "large.so".to_string(),
            format: BinaryFormat::Elf,
            architecture: Architecture::Arm64,
            entry: None,
            image_base: None,
            size: 200 * 1024 * 1024,
            hash_blake3: "00".to_string(),
            modules: Vec::new(),
            segments: Vec::new(),
            sections: vec![Section {
                name: ".text".to_string(),
                address: 0x1000,
                size: 80 * 1024 * 1024,
                kind: "Text".to_string(),
                file_offset: None,
            }],
            imports: Vec::new(),
            exports: Vec::new(),
            relocations: Vec::new(),
            debug_artifacts: Vec::new(),
            debug_import: DebugImportSummary::default(),
            symbols: Vec::new(),
            strings: Vec::new(),
        };
        let size_budget = (80 * 1024 * 1024usize).div_ceil(0x80);
        let fast = function_recovery_budget(&image, AnalysisProfile::Fast);
        let full = function_recovery_budget(&image, AnalysisProfile::Full);
        assert_eq!(fast, size_budget.min(memory_function_cap(AnalysisProfile::Fast)));
        assert_eq!(full, size_budget.min(memory_function_cap(AnalysisProfile::Full)));
        assert!(fast <= MAX_FUNCTION_BUDGET_FAST);
        assert!(full <= MAX_FUNCTION_BUDGET_FULL);
        assert!(full >= fast);
    }

    #[test]
    fn summary_warning_uses_actual_function_budget() {
        let warnings = summarize_analysis_warnings(&Vec::new(), 4096);
        assert!(warnings.is_empty());

        let dummy = Function {
            name: "sub_0".to_string(),
            address: 0,
            size: 4,
            blocks: Vec::new(),
            stack_summary: None,
            arguments: Vec::new(),
            locals: Vec::new(),
            pseudocode: None,
            evidence_ids: Vec::new(),
            warnings: Vec::new(),
        };
        let warnings = summarize_analysis_warnings(&vec![dummy.clone(), dummy], 2);
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("global limit of 2"))
        );
    }

    #[test]
    fn arm64_passthrough_wrapper_infers_int_return_type() {
        let instructions = vec![
            Instruction {
                address: 0x5081f8,
                bytes: std::sync::Arc::from("3f2303d5"),
                text: std::sync::Arc::from("paciasp"),
            },
            Instruction {
                address: 0x5081fc,
                bytes: std::sync::Arc::from("fd7bbfa9"),
                text: std::sync::Arc::from("stp x29, x30, [sp, #-0x10]!"),
            },
            Instruction {
                address: 0x508200,
                bytes: std::sync::Arc::from("fd030091"),
                text: std::sync::Arc::from("mov x29, sp"),
            },
            Instruction {
                address: 0x508204,
                bytes: std::sync::Arc::from("fbffff97"),
                text: std::sync::Arc::from("bl $-0x14"),
            },
            Instruction {
                address: 0x508208,
                bytes: std::sync::Arc::from("fd7bc1a8"),
                text: std::sync::Arc::from("ldp x29, x30, [sp], #0x10"),
            },
            Instruction {
                address: 0x50820c,
                bytes: std::sync::Arc::from("bf2303d5"),
                text: std::sync::Arc::from("autiasp"),
            },
            Instruction {
                address: 0x508210,
                bytes: std::sync::Arc::from("c0035fd6"),
                text: std::sync::Arc::from("ret"),
            },
        ];
        let overrides = HashMap::from([(0x508204, 0x508180)]);
        assert_eq!(
            infer_return_type(&instructions, &overrides),
            Some("int".to_string())
        );
    }

    #[test]
    fn arm64_passthrough_wrapper_infers_return_result_statement() {
        let blocks = vec![BasicBlock {
            address: 0x5081f8,
            size: 28,
            instructions: vec![
                Instruction {
                    address: 0x5081f8,
                    bytes: std::sync::Arc::from("3f2303d5"),
                    text: std::sync::Arc::from("paciasp"),
                },
                Instruction {
                    address: 0x5081fc,
                    bytes: std::sync::Arc::from("fd7bbfa9"),
                    text: std::sync::Arc::from("stp x29, x30, [sp, #-0x10]!"),
                },
                Instruction {
                    address: 0x508200,
                    bytes: std::sync::Arc::from("fd030091"),
                    text: std::sync::Arc::from("mov x29, sp"),
                },
                Instruction {
                    address: 0x508204,
                    bytes: std::sync::Arc::from("fbffff97"),
                    text: std::sync::Arc::from("bl $-0x14"),
                },
                Instruction {
                    address: 0x508208,
                    bytes: std::sync::Arc::from("fd7bc1a8"),
                    text: std::sync::Arc::from("ldp x29, x30, [sp], #0x10"),
                },
                Instruction {
                    address: 0x50820c,
                    bytes: std::sync::Arc::from("bf2303d5"),
                    text: std::sync::Arc::from("autiasp"),
                },
                Instruction {
                    address: 0x508210,
                    bytes: std::sync::Arc::from("c0035fd6"),
                    text: std::sync::Arc::from("ret"),
                },
            ],
        }];
        let overrides = HashMap::from([(0x508204, 0x508180)]);
        assert_eq!(
            infer_arm64_return_statement(&blocks, &overrides),
            Some("return result;")
        );
    }






    #[test]
    fn fast_pseudocode_recovers_string_call_args() {
        use revx_core::{Import, Instruction, StringLiteral};
        use std::collections::HashMap;
        use std::sync::Arc;
        let blocks = vec![BasicBlock {
            address: 0x1000009b0,
            size: 0x30,
            instructions: vec![
                Instruction {
                    address: 0x1000009b0,
                    bytes: Arc::from("00"),
                    text: Arc::from("adrp x1, $+0x4000"),
                },
                Instruction {
                    address: 0x1000009b4,
                    bytes: Arc::from("00"),
                    text: Arc::from("add x1, x1, #0x8ed"),
                },
                Instruction {
                    address: 0x1000009b8,
                    bytes: Arc::from("00"),
                    text: Arc::from("mov w0, #0x0"),
                },
                Instruction {
                    address: 0x1000009bc,
                    bytes: Arc::from("00"),
                    text: Arc::from("bl $+0x3c88"),
                },
                Instruction {
                    address: 0x1000009c0,
                    bytes: Arc::from("00"),
                    text: Arc::from("adrp x0, $+0x4000"),
                },
                Instruction {
                    address: 0x1000009c4,
                    bytes: Arc::from("00"),
                    text: Arc::from("add x0, x0, #0x8ee"),
                },
                Instruction {
                    address: 0x1000009c8,
                    bytes: Arc::from("00"),
                    text: Arc::from("adrp x1, $+0x4000"),
                },
                Instruction {
                    address: 0x1000009cc,
                    bytes: Arc::from("00"),
                    text: Arc::from("add x1, x1, #0x8f5"),
                },
                Instruction {
                    address: 0x1000009d0,
                    bytes: Arc::from("00"),
                    text: Arc::from("bl $+0x3ae4"),
                },
                Instruction {
                    address: 0x1000009d4,
                    bytes: Arc::from("00"),
                    text: Arc::from("mov w0, #0x1"),
                },
                Instruction {
                    address: 0x1000009d8,
                    bytes: Arc::from("00"),
                    text: Arc::from("bl $+0x3b6c"),
                },
                Instruction {
                    address: 0x1000009dc,
                    bytes: Arc::from("00"),
                    text: Arc::from("adrp x0, $+0x4000"),
                },
                Instruction {
                    address: 0x1000009e0,
                    bytes: Arc::from("00"),
                    text: Arc::from("add x0, x0, #0x8fe"),
                },
                Instruction {
                    address: 0x1000009e4,
                    bytes: Arc::from("00"),
                    text: Arc::from("bl $+0x3ae0"),
                },
            ],
        }];
        let imports = vec![
            Import {
                library: Some("libSystem".into()),
                name: "_setlocale".into(),
                address: Some(0x100004644),
            },
            Import {
                library: Some("libSystem".into()),
                name: "_compat_mode".into(),
                address: Some(0x1000043b4),
            },
            Import {
                library: Some("libSystem".into()),
                name: "_isatty".into(),
                address: Some(0x100004544),
            },
            Import {
                library: Some("libSystem".into()),
                name: "_getenv".into(),
                address: Some(0x1000044c4),
            },
        ];
        let strings = vec![
            StringLiteral {
                address: Some(0x1000048ed),
                value: "".into(),
            },
            StringLiteral {
                address: Some(0x1000048ee),
                value: "bin/ls".into(),
            },
            StringLiteral {
                address: Some(0x1000048f5),
                value: "Unix2003".into(),
            },
            StringLiteral {
                address: Some(0x1000048fe),
                value: "COLUMNS".into(),
            },
        ];
        let mut overrides = HashMap::new();
        overrides.insert(0x1000009bc, 0x100004644);
        overrides.insert(0x1000009d0, 0x1000043b4);
        overrides.insert(0x1000009d8, 0x100004544);
        overrides.insert(0x1000009e4, 0x1000044c4);
        let symbols = HashMap::new();
        let unit = super::render_fast_pseudocode(
            "main",
            0x100000960,
            &blocks,
            &[],
            &imports,
            &strings,
            &overrides,
            &symbols,
            None, &[]);
        assert!(
            unit.text.contains("_setlocale(0x0, \"\")")
                || unit.text.contains("_setlocale(0, \"\")"),
            "missing empty setlocale arg:\n{}",
            unit.text
        );
        assert!(
            unit.text.contains("_compat_mode(\"bin/ls\", \"Unix2003\")"),
            "missing compat_mode args:\n{}",
            unit.text
        );
        assert!(
            unit.text.contains("_isatty(0x1)") || unit.text.contains("_isatty(1)"),
            "isatty should take one arg:\n{}",
            unit.text
        );
        assert!(
            !unit.text.contains("_isatty(0x1, \"Unix2003\")")
                && !unit.text.contains("_isatty(1, \"Unix2003\")"),
            "stale arg leak into isatty:\n{}",
            unit.text
        );
        assert!(
            unit.text.contains("_getenv(\"COLUMNS\")"),
            "missing getenv arg:\n{}",
            unit.text
        );
        assert!(
            !unit.text.contains("_getenv(\"COLUMNS\", \"Unix2003\")"),
            "stale arg leak into getenv:\n{}",
            unit.text
        );
    }

    #[test]
    fn fast_pseudocode_resolves_local_callee_and_return() {
        let blocks = vec![BasicBlock {
            address: 0x1000,
            size: 0x20,
            instructions: vec![
                Instruction {
                    address: 0x1000,
                    bytes: Arc::from("00"),
                    text: Arc::from("mov w0, #0x2a"),
                },
                Instruction {
                    address: 0x1004,
                    bytes: Arc::from("00"),
                    text: Arc::from("bl $+0x100"),
                },
                Instruction {
                    address: 0x1008,
                    bytes: Arc::from("00"),
                    text: Arc::from("ret"),
                },
            ],
        }];
        let mut overrides = HashMap::new();
        overrides.insert(0x1004, 0x1104);
        let mut symbols = HashMap::new();
        symbols.insert(0x1104, "helper_init".to_string());
        let unit = super::render_fast_pseudocode(
            "caller",
            0x1000,
            &blocks,
            &[],
            &[],
            &[],
            &overrides,
            &symbols,
            Some("int"), &[]);
        assert!(
            unit.text.contains("helper_init("),
            "local callee not resolved:\n{}",
            unit.text
        );
        assert!(
            unit.text.contains("return result;"),
            "return of call result missing:\n{}",
            unit.text
        );
        assert!(
            unit.text.starts_with("int caller("),
            "signature missing return type:\n{}",
            unit.text
        );
    }

    #[test]
    fn fast_pseudocode_emits_tail_call_return() {
        let blocks = vec![BasicBlock {
            address: 0x2000,
            size: 0x10,
            instructions: vec![
                Instruction {
                    address: 0x2000,
                    bytes: Arc::from("00"),
                    text: Arc::from("mov w0, #0x1"),
                },
                Instruction {
                    address: 0x2004,
                    bytes: Arc::from("00"),
                    text: Arc::from("b $+0x20"),
                },
            ],
        }];
        let mut overrides = HashMap::new();
        overrides.insert(0x2004, 0x2024);
        let mut symbols = HashMap::new();
        symbols.insert(0x2024, "finish".to_string());
        let unit = super::render_fast_pseudocode(
            "wrapper",
            0x2000,
            &blocks,
            &[],
            &[],
            &[],
            &overrides,
            &symbols,
            Some("int"), &[]);
        assert!(
            unit.text.contains("return finish("),
            "tail call should become return:\n{}",
            unit.text
        );
    }

    #[test]
    fn fast_pseudocode_semantic_cmp_condition() {
        let args = vec![Variable {
            name: "argc".into(),
            role: VariableRole::Argument,
            storage: VariableStorage::Register,
            type_name: Some("int".into()),
            confidence: 0.9,
            location: "x0".into(),
            evidence_ids: Vec::new(),
        }];
        let blocks = vec![BasicBlock {
            address: 0x3000,
            size: 0x20,
            instructions: vec![
                Instruction {
                    address: 0x3000,
                    bytes: Arc::from("00"),
                    text: Arc::from("cmp w0, #0x0"),
                },
                Instruction {
                    address: 0x3004,
                    bytes: Arc::from("00"),
                    text: Arc::from("b.le $+0xc"),
                },
                Instruction {
                    address: 0x3008,
                    bytes: Arc::from("00"),
                    text: Arc::from("bl $+0x100"),
                },
                Instruction {
                    address: 0x300c,
                    bytes: Arc::from("00"),
                    text: Arc::from("mov w0, #0x1"),
                },
                Instruction {
                    address: 0x3010,
                    bytes: Arc::from("00"),
                    text: Arc::from("ret"),
                },
            ],
        }];
        let mut overrides = HashMap::new();
        overrides.insert(0x3008, 0x3108);
        let mut symbols = HashMap::new();
        symbols.insert(0x3108, "usage".to_string());
        let unit = super::render_fast_pseudocode(
            "main",
            0x3000,
            &blocks,
            &args,
            &[],
            &[],
            &overrides,
            &symbols,
            Some("int"), &[]);
        assert!(
            unit.text.contains("argc"),
            "argc should appear in condition:\n{}",
            unit.text
        );
        assert!(
            unit.text.contains("if (") && (unit.text.contains(">") || unit.text.contains("<") || unit.text.contains("!=")),
            "semantic comparison expected:\n{}",
            unit.text
        );
        assert!(
            unit.text.contains("usage("),
            "structured/call body missing:\n{}",
            unit.text
        );
    }

    #[test]
    fn fast_pseudocode_structures_forward_skip_if() {
        let blocks = vec![BasicBlock {
            address: 0x4000,
            size: 0x20,
            instructions: vec![
                Instruction {
                    address: 0x4000,
                    bytes: Arc::from("00"),
                    text: Arc::from("cbz x0, $+0xc"),
                },
                Instruction {
                    address: 0x4004,
                    bytes: Arc::from("00"),
                    text: Arc::from("bl $+0x100"),
                },
                Instruction {
                    address: 0x4008,
                    bytes: Arc::from("00"),
                    text: Arc::from("mov w0, #0x0"),
                },
                Instruction {
                    address: 0x400c,
                    bytes: Arc::from("00"),
                    text: Arc::from("ret"),
                },
            ],
        }];
        let mut overrides = HashMap::new();
        overrides.insert(0x4004, 0x4104);
        let mut symbols = HashMap::new();
        symbols.insert(0x4104, "work".to_string());
        // cbz x0, $+0xc from 0x4000 -> target 0x400c
        let unit = super::render_fast_pseudocode(
            "gate",
            0x4000,
            &blocks,
            &[],
            &[],
            &[],
            &overrides,
            &symbols,
            Some("int"), &[]);
        assert!(
            unit.text.contains("if ("),
            "expected if structure:\n{}",
            unit.text
        );
        assert!(
            unit.text.contains("work("),
            "expected call inside if body:\n{}",
            unit.text
        );
        assert!(
            unit.text.contains('{') && unit.text.contains('}'),
            "expected braces:\n{}",
            unit.text
        );
    }

    #[test]
    fn fast_pseudocode_tracks_byte_load_conditions() {
        let blocks = vec![BasicBlock {
            address: 0x5000,
            size: 0x20,
            instructions: vec![
                Instruction {
                    address: 0x5000,
                    bytes: Arc::from("00"),
                    text: Arc::from("bl $+0x100"),
                },
                Instruction {
                    address: 0x5004,
                    bytes: Arc::from("00"),
                    text: Arc::from("ldrb w8, [x0]"),
                },
                Instruction {
                    address: 0x5008,
                    bytes: Arc::from("00"),
                    text: Arc::from("cbz w8, $+0x8"),
                },
                Instruction {
                    address: 0x500c,
                    bytes: Arc::from("00"),
                    text: Arc::from("bl $+0x200"),
                },
                Instruction {
                    address: 0x5010,
                    bytes: Arc::from("00"),
                    text: Arc::from("ret"),
                },
            ],
        }];
        let mut overrides = HashMap::new();
        overrides.insert(0x5000, 0x5100);
        overrides.insert(0x500c, 0x5200);
        let mut symbols = HashMap::new();
        symbols.insert(0x5100, "getenv".to_string());
        symbols.insert(0x5200, "use_env".to_string());
        let unit = super::render_fast_pseudocode(
            "probe",
            0x5000,
            &blocks,
            &[],
            &[],
            &[],
            &overrides,
            &symbols,
            Some("int"), &[]);
        assert!(
            unit.text.contains("result[0]")
                || unit.text.contains("*result")
                || unit.text.contains("env[0]")
                || unit.text.contains("*env"),
            "byte load from call result missing:\n{}",
            unit.text
        );
        assert!(
            unit.text.contains("use_env("),
            "expected gated call:\n{}",
            unit.text
        );
        assert!(
            !unit.text.contains("if (w8"),
            "raw register condition leaked:\n{}",
            unit.text
        );
    }

    #[test]
    fn fast_pseudocode_cmn_negates_imm_cleanly() {
        let blocks = vec![BasicBlock {
            address: 0x6000,
            size: 0x10,
            instructions: vec![
                Instruction {
                    address: 0x6000,
                    bytes: Arc::from("00"),
                    text: Arc::from("cmn w0, #0x1"),
                },
                Instruction {
                    address: 0x6004,
                    bytes: Arc::from("00"),
                    text: Arc::from("b.eq $+0x8"),
                },
                Instruction {
                    address: 0x6008,
                    bytes: Arc::from("00"),
                    text: Arc::from("ret"),
                },
                Instruction {
                    address: 0x600c,
                    bytes: Arc::from("00"),
                    text: Arc::from("ret"),
                },
            ],
        }];
        let unit = super::render_fast_pseudocode(
            "check",
            0x6000,
            &blocks,
            &[],
            &[],
            &[],
            &HashMap::new(),
            &HashMap::new(),
            Some("int"), &[]);
        assert!(
            unit.text.contains("== -1")
                || unit.text.contains("!= -1")
                || unit.text.contains("== -0x1"),
            "cmn should compare against -1:\n{}",
            unit.text
        );
        assert!(
            !unit.text.contains("-(0x1)") && !unit.text.contains("-("),
            "ugly cmn negation:\n{}",
            unit.text
        );
    }

    #[test]
    fn fast_pseudocode_frame_load_conditions() {
        let blocks = vec![BasicBlock {
            address: 0x7000,
            size: 0x20,
            instructions: vec![
                Instruction { address: 0x7000, bytes: Arc::from("00"), text: Arc::from("ldurh w0, [x29, #-0x5e]") },
                Instruction { address: 0x7004, bytes: Arc::from("00"), text: Arc::from("cbz w0, $+0x8") },
                Instruction { address: 0x7008, bytes: Arc::from("00"), text: Arc::from("bl $+0x100") },
                Instruction { address: 0x700c, bytes: Arc::from("00"), text: Arc::from("ret") },
            ],
        }];
        let mut overrides = HashMap::new();
        overrides.insert(0x7008, 0x7108);
        let mut symbols = HashMap::new();
        symbols.insert(0x7108, "handle".to_string());
        let unit = super::render_fast_pseudocode("frame", 0x7000, &blocks, &[], &[], &[], &overrides, &symbols, Some("int"), &[]);
        assert!(unit.text.contains("local_0x5e"), "frame load not named:\n{}", unit.text);
        assert!(!unit.text.contains("if (/*?*/)"), "unknown condition leaked:\n{}", unit.text);
        assert!(unit.text.contains("handle("), "expected gated call:\n{}", unit.text);
    }

    #[test]
    fn fast_pseudocode_csel_uses_flags() {
        let blocks = vec![BasicBlock {
            address: 0x8000,
            size: 0x20,
            instructions: vec![
                Instruction { address: 0x8000, bytes: Arc::from("00"), text: Arc::from("cmp w0, #0x0") },
                Instruction { address: 0x8004, bytes: Arc::from("00"), text: Arc::from("mov w1, #0x1") },
                Instruction { address: 0x8008, bytes: Arc::from("00"), text: Arc::from("mov w2, #0x2") },
                Instruction { address: 0x800c, bytes: Arc::from("00"), text: Arc::from("csel w0, w1, w2, eq") },
                Instruction { address: 0x8010, bytes: Arc::from("00"), text: Arc::from("ret") },
            ],
        }];
        let args = vec![Variable {
            name: "flag".into(),
            role: VariableRole::Argument,
            storage: VariableStorage::Register,
            type_name: Some("int".into()),
            confidence: 0.9,
            location: "x0".into(),
            evidence_ids: Vec::new(),
        }];
        let unit = super::render_fast_pseudocode("pick", 0x8000, &blocks, &args, &[], &[], &HashMap::new(), &HashMap::new(), Some("int"), &[]);
        assert!(unit.text.contains("return ") && unit.text.contains('?'), "csel ternary missing:\n{}", unit.text);
        assert!(unit.text.contains("flag") || unit.text.contains("== 0"), "csel condition should reference cmp:\n{}", unit.text);
    }

    #[test]
    fn fast_pseudocode_jump_table_comment() {
        let blocks = vec![BasicBlock {
            address: 0x9000,
            size: 0x20,
            instructions: vec![
                Instruction { address: 0x9000, bytes: Arc::from("00"), text: Arc::from("cmp w0, #0x5b") },
                Instruction { address: 0x9004, bytes: Arc::from("00"), text: Arc::from("b.hi $+0x10") },
                Instruction { address: 0x9008, bytes: Arc::from("00"), text: Arc::from("adr x17, $+0x0") },
                Instruction { address: 0x900c, bytes: Arc::from("00"), text: Arc::from("ldrsw x16, [x17, x16, lsl #2]") },
                Instruction { address: 0x9010, bytes: Arc::from("00"), text: Arc::from("br x16") },
                Instruction { address: 0x9014, bytes: Arc::from("00"), text: Arc::from("ret") },
            ],
        }];
        let unit = super::render_fast_pseudocode("dispatch", 0x9000, &blocks, &[], &[], &[], &HashMap::new(), &HashMap::new(), Some("int"), &[]);
        assert!(unit.text.contains("switch"), "jump table should be annotated:\n{}", unit.text);
    }

    #[test]
    fn fast_pseudocode_result_flows_to_switch() {
        let blocks = vec![BasicBlock {
            address: 0xa000,
            size: 0x30,
            instructions: vec![
                Instruction { address: 0xa000, bytes: Arc::from("00"), text: Arc::from("bl $+0x100") },
                Instruction { address: 0xa004, bytes: Arc::from("00"), text: Arc::from("sub w16, w0, #0x25") },
                Instruction { address: 0xa008, bytes: Arc::from("00"), text: Arc::from("cmp w16, #0x5b") },
                Instruction { address: 0xa00c, bytes: Arc::from("00"), text: Arc::from("b.hi $+0x10") },
                Instruction { address: 0xa010, bytes: Arc::from("00"), text: Arc::from("adr x17, $+0x0") },
                Instruction { address: 0xa014, bytes: Arc::from("00"), text: Arc::from("ldrsw x16, [x17, x16, lsl #2]") },
                Instruction { address: 0xa018, bytes: Arc::from("00"), text: Arc::from("br x16") },
                Instruction { address: 0xa01c, bytes: Arc::from("00"), text: Arc::from("ret") },
            ],
        }];
        let mut overrides = HashMap::new();
        overrides.insert(0xa000, 0xa100);
        let mut symbols = HashMap::new();
        symbols.insert(0xa100, "_getopt_long".to_string());
        let unit = super::render_fast_pseudocode(
            "dispatch",
            0xa000,
            &blocks,
            &[],
            &[],
            &[],
            &overrides,
            &symbols,
            Some("int"), &[]);
        assert!(
            unit.text.contains("opt") || unit.text.contains("result"),
            "call result should flow into control:\n{}",
            unit.text
        );
        assert!(
            unit.text.contains("switch") && !unit.text.contains("switch (/*?*/)"),
            "switch scrutinee should not be unknown:\n{}",
            unit.text
        );
        assert!(
            unit.text.contains("0x25") || unit.text.contains("37") || unit.text.contains("- 37") || unit.text.contains("- 0x25") || unit.text.contains("opt"),
            "sub of call result should appear:\n{}",
            unit.text
        );
    }

    #[test]
    fn fast_pseudocode_named_args_in_calls() {
        let args = vec![
            Variable {
                name: "argc".into(),
                role: VariableRole::Argument,
                storage: VariableStorage::Register,
                type_name: Some("int".into()),
                confidence: 0.9,
                location: "x0".into(),
                evidence_ids: Vec::new(),
            },
            Variable {
                name: "argv".into(),
                role: VariableRole::Argument,
                storage: VariableStorage::Register,
                type_name: Some("char**".into()),
                confidence: 0.9,
                location: "x1".into(),
                evidence_ids: Vec::new(),
            },
        ];
        let blocks = vec![BasicBlock {
            address: 0xb000,
            size: 0x10,
            instructions: vec![
                Instruction { address: 0xb000, bytes: Arc::from("00"), text: Arc::from("adrp x2, $+0x0") },
                Instruction { address: 0xb004, bytes: Arc::from("00"), text: Arc::from("add x2, x2, #0x10") },
                Instruction { address: 0xb008, bytes: Arc::from("00"), text: Arc::from("bl $+0x100") },
                Instruction { address: 0xb00c, bytes: Arc::from("00"), text: Arc::from("ret") },
            ],
        }];
        let mut overrides = HashMap::new();
        overrides.insert(0xb008, 0xb100);
        let mut symbols = HashMap::new();
        symbols.insert(0xb100, "usage".to_string());
        let strings = vec![revx_core::StringLiteral {
            address: Some(0x10),
            value: "help".into(),
        }];
        // adrp+add to 0x10 depends on page alignment from 0xb000 - may not resolve string;
        // named args should still appear.
        let unit = super::render_fast_pseudocode(
            "main",
            0xb000,
            &blocks,
            &args,
            &[],
            &strings,
            &overrides,
            &symbols,
            Some("int"), &[]);
        assert!(
            unit.text.contains("usage(argc") || unit.text.contains("usage(argc,"),
            "named argc should appear in call:\n{}",
            unit.text
        );
        assert!(
            unit.text.contains("argv"),
            "named argv should appear in call:\n{}",
            unit.text
        );
    }

    #[test]
    fn entry_seed_is_named_main() {
        use revx_core::{
            BinaryFormat, BinaryImage, DebugFunctionHint, DebugImportSummary, Section,
        };
        let mut image = BinaryImage {
            id: "t".into(),
            path: "t".into(),
            format: BinaryFormat::MachO,
            architecture: Architecture::Arm64,
            entry: Some(0x100000960),
            image_base: Some(0x100000000),
            size: 0x1000,
            hash_blake3: "0".into(),
            modules: Vec::new(),
            segments: Vec::new(),
            sections: vec![Section {
                name: "__text".into(),
                address: 0x100000700,
                size: 0x400,
                kind: "Text".into(),
                file_offset: None,
            }],
            imports: Vec::new(),
            exports: Vec::new(),
            relocations: Vec::new(),
            debug_artifacts: Vec::new(),
            debug_import: DebugImportSummary {
                function_hints: vec![DebugFunctionHint {
                    address: Some(0x100000960),
                    name: "sub_100000960".into(),
                    return_type: None,
                    calling_convention: None,
                    arguments: Vec::new(),
                    locals: Vec::new(),
                    source_anchor: None,
                    evidence_ids: Vec::new(),
                }],
                ..Default::default()
            },
            symbols: Vec::new(),
            strings: Vec::new(),
        };
        let seeds = {
            // emulate collect + entry rename path via analyze seeds indirectly is heavy;
            // unit-check naming helper behavior through walk by checking collect + manual rename rules.
            let mut seeds = super::collect_function_seeds(&image);
            if let Some(entry) = image.entry.filter(|e| *e != 0) {
                seeds
                    .entry(entry)
                    .and_modify(|name| {
                        if name.starts_with("sub_") || name.starts_with("entry_") {
                            *name = "main".to_string();
                        }
                    })
                    .or_insert_with(|| "main".to_string());
            }
            seeds
        };
        assert_eq!(seeds.get(&0x100000960).map(String::as_str), Some("main"));
        let _ = &mut image;
    }

    #[test]
    fn executable_ranges_prefer_text_sections_over_pagezero() {
        use revx_core::{BinaryFormat, BinaryImage, Section, Segment};
        let image = BinaryImage {
            id: "t".into(),
            path: "t".into(),
            format: BinaryFormat::MachO,
            architecture: Architecture::Arm64,
            entry: Some(0x100000960),
            image_base: Some(0x100000000),
            size: 0x10000,
            hash_blake3: "0".into(),
            modules: Vec::new(),
            segments: vec![
                Segment {
                    name: "__PAGEZERO".into(),
                    address: 0,
                    size: 0x100000000,
                    permissions: "none".into(),
                },
                Segment {
                    name: "__TEXT".into(),
                    address: 0x100000000,
                    size: 0x8000,
                    permissions: "rx".into(),
                },
            ],
            sections: vec![Section {
                name: "__text".into(),
                address: 0x100000700,
                size: 0x3ba4,
                kind: "Text".into(),
                file_offset: None,
            }],
            imports: Vec::new(),
            exports: Vec::new(),
            relocations: Vec::new(),
            debug_artifacts: Vec::new(),
            debug_import: Default::default(),
            symbols: Vec::new(),
            strings: Vec::new(),
        };
        let ranges = super::executable_ranges(&image);
        assert_eq!(ranges, vec![(0x100000700, 0x100000700 + 0x3ba4)]);
        assert!(super::is_executable_address(&ranges, 0x100000960));
        assert!(!super::is_executable_address(&ranges, 0x10));
    }

    #[test]
    fn arm64_prologue_recognizes_pac_and_stp_variants() {
        assert!(super::is_arm64_prologue_word(0xd503237f));
        assert!(super::is_arm64_prologue_word(0xd503233f));
        assert!(super::is_arm64_prologue_word(0xa9ba6ffc));
        assert!(super::is_arm64_prologue_word(0xa9bf7bfd));
        assert!(!super::is_arm64_prologue_word(0x9101a000));
    }

    #[test]
    fn heuristic_seeds_do_not_force_function_boundaries() {
        let hard_boundaries = BTreeSet::from([0x1000, 0x1030]);
        assert_eq!(next_hard_boundary(0x1000, 0x1040, &hard_boundaries), 0x1030);
        assert_eq!(next_hard_boundary(0x1020, 0x1040, &hard_boundaries), 0x1030);
    }

    #[test]
    fn arm64_conditional_regions_do_not_embed_nested_if_lines_as_statements() {
        let blocks = vec![
            BasicBlock {
                address: 0x508198,
                size: 12,
                instructions: vec![
                    Instruction {
                        address: 0x508198,
                        bytes: std::sync::Arc::from("e00313aa"),
                        text: std::sync::Arc::from("mov x0, x19"),
                    },
                    Instruction {
                        address: 0x50819c,
                        bytes: std::sync::Arc::from("fd170094"),
                        text: std::sync::Arc::from("bl $+0x5ff4"),
                    },
                    Instruction {
                        address: 0x5081a0,
                        bytes: std::sync::Arc::from("a00000b5"),
                        text: std::sync::Arc::from("cbnz x0, $+0x14"),
                    },
                ],
            },
            BasicBlock {
                address: 0x5081a4,
                size: 8,
                instructions: vec![
                    Instruction {
                        address: 0x5081a4,
                        bytes: std::sync::Arc::from("5699ff97"),
                        text: std::sync::Arc::from("bl $-0x19aa8"),
                    },
                    Instruction {
                        address: 0x5081a8,
                        bytes: std::sync::Arc::from("e00000b4"),
                        text: std::sync::Arc::from("cbz x0, $+0x1c"),
                    },
                ],
            },
            BasicBlock {
                address: 0x5081ac,
                size: 8,
                instructions: vec![
                    Instruction {
                        address: 0x5081ac,
                        bytes: std::sync::Arc::from("00003fd6"),
                        text: std::sync::Arc::from("blr x0"),
                    },
                    Instruction {
                        address: 0x5081b0,
                        bytes: std::sync::Arc::from("faffff17"),
                        text: std::sync::Arc::from("b $-0x18"),
                    },
                ],
            },
            BasicBlock {
                address: 0x5081b4,
                size: 16,
                instructions: vec![Instruction {
                    address: 0x5081c0,
                    bytes: std::sync::Arc::from("c0035fd6"),
                    text: std::sync::Arc::from("ret"),
                }],
            },
        ];

        let regions = build_regions(
            0x508180,
            &blocks,
            &[],
            &[],
            &[],
            &HashMap::new(),
            AnalysisProfile::Fast,
        &[],
        );
        let if_regions = regions
            .iter()
            .filter(|region| region.kind == RegionKind::If)
            .collect::<Vec<_>>();

        assert!(!if_regions.is_empty());
        for region in if_regions {
            assert!(
                region
                    .statements
                    .iter()
                    .all(|statement| !statement.starts_with("if ("))
            );
        }
    }

    #[test]
    fn detects_xor_decrypt_loop_pattern() {
        let function = Function {
            name: "sub_1000".to_string(),
            address: 0x1000,
            size: 48,
            blocks: vec![
                BasicBlock {
                    address: 0x1000,
                    size: 16,
                    instructions: vec![
                        Instruction { address: 0x1000, bytes: std::sync::Arc::from("00"), text: std::sync::Arc::from("adrp x0, $+0x1000") },
                        Instruction { address: 0x1004, bytes: std::sync::Arc::from("00"), text: std::sync::Arc::from("mov x1, #0x0") },
                    ],
                },
                BasicBlock {
                    address: 0x1008,
                    size: 16,
                    instructions: vec![
                        Instruction { address: 0x1008, bytes: std::sync::Arc::from("00"), text: std::sync::Arc::from("ldrb w2, [x0, x1]") },
                        Instruction { address: 0x100c, bytes: std::sync::Arc::from("00"), text: std::sync::Arc::from("eor w2, w2, #0x42") },
                        Instruction { address: 0x1010, bytes: std::sync::Arc::from("00"), text: std::sync::Arc::from("strb w2, [x0, x1]") },
                        Instruction { address: 0x1014, bytes: std::sync::Arc::from("00"), text: std::sync::Arc::from("add x1, x1, #0x1") },
                    ],
                },
                BasicBlock {
                    address: 0x1018,
                    size: 16,
                    instructions: vec![
                        Instruction { address: 0x1018, bytes: std::sync::Arc::from("00"), text: std::sync::Arc::from("cmp x1, #0x10") },
                        Instruction { address: 0x101c, bytes: std::sync::Arc::from("00"), text: std::sync::Arc::from("b.ne $-0x14") },
                    ],
                },
            ],
            stack_summary: None,
            arguments: Vec::new(),
            locals: Vec::new(),
            pseudocode: None,
            evidence_ids: Vec::new(),
            warnings: Vec::new(),
        };
        let patterns = super::detect_obfuscation_patterns(&function);
        assert!(
            patterns.iter().any(|p| p == "xor_decrypt_loop"),
            "expected xor_decrypt_loop pattern, got: {:?}", patterns
        );
    }

    #[test]
    fn detects_control_flow_flattening_pattern() {
        let function = Function {
            name: "sub_2000".to_string(),
            address: 0x2000,
            size: 32,
            blocks: vec![
                BasicBlock {
                    address: 0x2000,
                    size: 8,
                    instructions: vec![
                        Instruction { address: 0x2000, bytes: std::sync::Arc::from("00"), text: std::sync::Arc::from("mov x0, #0x1") },
                        Instruction { address: 0x2004, bytes: std::sync::Arc::from("00"), text: std::sync::Arc::from("br x0") },
                    ],
                },
                BasicBlock {
                    address: 0x2008,
                    size: 8,
                    instructions: vec![
                        Instruction { address: 0x2008, bytes: std::sync::Arc::from("00"), text: std::sync::Arc::from("mov x0, #0x2") },
                        Instruction { address: 0x200c, bytes: std::sync::Arc::from("00"), text: std::sync::Arc::from("br x0") },
                    ],
                },
                BasicBlock {
                    address: 0x2010,
                    size: 8,
                    instructions: vec![
                        Instruction { address: 0x2010, bytes: std::sync::Arc::from("00"), text: std::sync::Arc::from("mov x0, #0x3") },
                        Instruction { address: 0x2014, bytes: std::sync::Arc::from("00"), text: std::sync::Arc::from("br x0") },
                    ],
                },
            ],
            stack_summary: None,
            arguments: Vec::new(),
            locals: Vec::new(),
            pseudocode: None,
            evidence_ids: Vec::new(),
            warnings: Vec::new(),
        };
        let patterns = super::detect_obfuscation_patterns(&function);
        assert!(
            patterns.iter().any(|p| p.starts_with("control_flow_flattening")),
            "expected control_flow_flattening pattern, got: {:?}", patterns
        );
    }

    #[test]
    fn detects_dead_code_injection() {
        let function = Function {
            name: "sub_3000".to_string(),
            address: 0x3000,
            size: 64,
            blocks: vec![
                BasicBlock {
                    address: 0x3000,
                    size: 64,
                    instructions: (0..16).map(|i| Instruction {
                        address: 0x3000 + i as u64 * 4,
                        bytes: std::sync::Arc::from("00"),
                        text: if i % 2 == 0 { std::sync::Arc::from("nop") } else { std::sync::Arc::from("brk #0x1") },
                    }).collect(),
                },
            ],
            stack_summary: None,
            arguments: Vec::new(),
            locals: Vec::new(),
            pseudocode: None,
            evidence_ids: Vec::new(),
            warnings: Vec::new(),
        };
        let patterns = super::detect_obfuscation_patterns(&function);
        assert!(
            patterns.iter().any(|p| p.starts_with("dead_code")),
            "expected dead_code pattern, got: {:?}", patterns
        );
    }
}
