use crate::DexFile;
use crate::lift::LiftOutput;
use crate::structure::{GotoReason, StructuringDiagnostics};
use revx_analysis::ssa::BlockId;
use std::collections::{BTreeMap, BTreeSet};

pub const CENSUS_SCHEMA_VERSION: u32 = 7;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FinalGotoProvenance {
    IrreducibleLoop,
    Handler,
    Switch,
    Unstructured,
    #[default]
    Unknown,
}

impl FinalGotoProvenance {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IrreducibleLoop => "irreducible_loop",
            Self::Handler => "handler",
            Self::Switch => "switch",
            Self::Unstructured => "unstructured",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalGotoSite {
    pub line: usize,
    pub target: String,
    pub provenance: FinalGotoProvenance,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FinalGotoScan {
    pub count: usize,
    pub line_count: usize,
    pub sites: Vec<FinalGotoSite>,
    pub target_counts: BTreeMap<String, usize>,
    pub labels: BTreeMap<String, usize>,
    pub dangling_targets: Vec<String>,
}

struct Token<'a> {
    text: &'a str,
    line: usize,
}

fn tokens(text: &str) -> Vec<Token<'_>> {
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let (mut pos, mut line) = (0, 1);
    while pos < bytes.len() {
        let start = pos;
        let start_line = line;
        match bytes[pos] {
            b'/' if bytes.get(pos + 1) == Some(&b'/') => {
                pos += 2;
                while pos < bytes.len() && bytes[pos] != b'\n' {
                    pos += 1;
                }
                continue;
            }
            b'/' if bytes.get(pos + 1) == Some(&b'*') => {
                pos += 2;
                while pos < bytes.len() {
                    if bytes[pos..].starts_with(b"*/") {
                        pos += 2;
                        break;
                    }
                    line += usize::from(bytes[pos] == b'\n');
                    pos += 1;
                }
                continue;
            }
            b'"' | b'\'' | b'`' => {
                let quote = bytes[pos];
                let width = if quote == b'"' && bytes[pos..].starts_with(b"\"\"\"") {
                    3
                } else {
                    1
                };
                pos += width;
                while pos < bytes.len() {
                    if bytes[pos] == b'\\' {
                        pos += 1;
                        if pos < bytes.len() {
                            line += usize::from(bytes[pos] == b'\n');
                            pos += 1;
                        }
                    } else if bytes[pos..].starts_with(&bytes[start..start + width]) {
                        pos += width;
                        break;
                    } else {
                        line += usize::from(bytes[pos] == b'\n');
                        pos += 1;
                    }
                }
                tokens.push(Token {
                    text: "<literal>",
                    line: start_line,
                });
                continue;
            }
            b if b.is_ascii_whitespace() => {
                line += usize::from(b == b'\n');
                pos += 1;
                continue;
            }
            b if identifier_byte(b) => {
                pos += 1;
                while pos < bytes.len() && identifier_byte(bytes[pos]) {
                    pos += 1;
                }
            }
            _ => pos += 1,
        }
        tokens.push(Token {
            text: &text[start..pos],
            line: start_line,
        });
    }
    tokens
}

fn identifier_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'$') || b >= 0x80
}

fn label(token: &str) -> bool {
    token
        .strip_prefix('L')
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

pub fn count_final_gotos(text: &str) -> FinalGotoScan {
    let tokens = tokens(text);
    let mut result = FinalGotoScan::default();
    for (i, token) in tokens.iter().enumerate() {
        let previous = i.checked_sub(1).map(|p| tokens[p].text);
        if token.text == "goto"
            && !matches!(previous, Some("." | "::" | "@"))
            && let Some(target) = tokens.get(i + 1)
            && label(target.text)
            && tokens.get(i + 2).is_some_and(|t| t.text == ";")
        {
            result.sites.push(FinalGotoSite {
                line: token.line,
                target: target.text.into(),
                provenance: FinalGotoProvenance::Unknown,
            });
            *result.target_counts.entry(target.text.into()).or_default() += 1;
        }
        if label(token.text)
            && tokens.get(i + 1).is_some_and(|t| t.text == ":")
            && (previous.is_none()
                || matches!(previous, Some(";" | "{" | "}" | ":"))
                || i.checked_sub(1)
                    .is_some_and(|p| tokens[p].line < token.line))
        {
            *result.labels.entry(token.text.into()).or_default() += 1;
        }
    }
    result.count = result.sites.len();
    result.line_count = result
        .sites
        .iter()
        .map(|s| s.line)
        .collect::<BTreeSet<_>>()
        .len();
    result.dangling_targets = result
        .target_counts
        .keys()
        .filter(|t| !result.labels.contains_key(*t))
        .cloned()
        .collect();
    result
}

pub fn attribute_final_gotos(scan: &mut FinalGotoScan, output: &LiftOutput) {
    let handlers = handler_blocks(output);
    let irreducible = crate::loopnorm::multi_entry_scc_blocks(&output.func.cfg);
    let mut switch_targets = BTreeSet::new();
    for cases in output.switch_cases.values() {
        for (_, target) in cases {
            switch_targets.insert(*target);
        }
    }
    let n = output.func.cfg.blocks.len();
    for site in &mut scan.sites {
        site.provenance =
            classify_target(&site.target, n, &handlers, &irreducible, &switch_targets);
    }
}

fn classify_target(
    target: &str,
    block_count: usize,
    handlers: &BTreeSet<BlockId>,
    irreducible: &BTreeSet<BlockId>,
    switch_targets: &BTreeSet<BlockId>,
) -> FinalGotoProvenance {
    let Some(block) = parse_label(target) else {
        return FinalGotoProvenance::Unknown;
    };
    if (block.0 as usize) >= block_count {
        return FinalGotoProvenance::Unknown;
    }
    if handlers.contains(&block) {
        FinalGotoProvenance::Handler
    } else if irreducible.contains(&block) {
        FinalGotoProvenance::IrreducibleLoop
    } else if switch_targets.contains(&block) {
        FinalGotoProvenance::Switch
    } else {
        FinalGotoProvenance::Unstructured
    }
}

fn parse_label(target: &str) -> Option<BlockId> {
    target
        .strip_prefix('L')
        .and_then(|n| n.parse::<u32>().ok())
        .map(BlockId)
}

fn handler_blocks(output: &LiftOutput) -> BTreeSet<BlockId> {
    let mut blocks = BTreeSet::new();
    for region in &output.exception_flow.regions {
        for handler in &region.handlers {
            if let Some(block) = handler.block {
                blocks.insert(block);
            }
        }
    }
    for shared in &output.exception_flow.shared_handlers {
        if let Some(block) = shared.block {
            blocks.insert(block);
        }
    }
    blocks
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReasonCounts {
    pub revisit: usize,
    pub forward_revisit: usize,
    pub irreducible_loop: usize,
    pub handler: usize,
    pub switch: usize,
    pub unstructured: usize,
    pub unknown: usize,
}

impl ReasonCounts {
    fn add(&mut self, other: &Self) {
        self.revisit += other.revisit;
        self.forward_revisit += other.forward_revisit;
        self.irreducible_loop += other.irreducible_loop;
        self.handler += other.handler;
        self.switch += other.switch;
        self.unstructured += other.unstructured;
        self.unknown += other.unknown;
    }
}

#[derive(Clone, Debug, Default)]
pub struct CensusCounts {
    pub final_goto_count: usize,
    pub final_goto_line_count: usize,
    pub by_reason: ReasonCounts,
    pub raw_emission_count: usize,
    pub raw_by_reason: ReasonCounts,
    pub bailed_methods: usize,
    pub region_methods: usize,
    pub legacy_methods: usize,
    pub structured_try_count: usize,
    pub fallback_by_reason: BTreeMap<String, usize>,
    pub nodes_split: usize,
    pub loop_norm_methods: usize,
    pub phi_lower_methods: usize,
    pub unknown_methods: usize,
}

fn reason_counts(scan: &FinalGotoScan) -> ReasonCounts {
    let mut counts = ReasonCounts::default();
    for site in &scan.sites {
        match site.provenance {
            FinalGotoProvenance::IrreducibleLoop => counts.irreducible_loop += 1,
            FinalGotoProvenance::Handler => counts.handler += 1,
            FinalGotoProvenance::Switch => counts.switch += 1,
            FinalGotoProvenance::Unstructured => counts.unstructured += 1,
            FinalGotoProvenance::Unknown => counts.unknown += 1,
        }
    }
    counts
}

impl CensusCounts {
    fn from_scan(scan: &FinalGotoScan, diagnostics: &StructuringDiagnostics) -> Self {
        let mut result = Self {
            final_goto_count: scan.count,
            final_goto_line_count: scan.line_count,
            by_reason: reason_counts(scan),
            raw_emission_count: diagnostics.goto_emissions.len(),
            bailed_methods: usize::from(diagnostics.bailed),
            ..Default::default()
        };
        for emission in &diagnostics.goto_emissions {
            match emission.reason {
                GotoReason::Revisit => result.raw_by_reason.revisit += 1,
                GotoReason::ForwardRevisit => result.raw_by_reason.forward_revisit += 1,
            }
        }
        result
    }

    fn add(&mut self, other: &Self) {
        self.final_goto_count += other.final_goto_count;
        self.final_goto_line_count += other.final_goto_line_count;
        self.raw_emission_count += other.raw_emission_count;
        self.bailed_methods += other.bailed_methods;
        self.region_methods += other.region_methods;
        self.legacy_methods += other.legacy_methods;
        self.structured_try_count += other.structured_try_count;
        self.nodes_split += other.nodes_split;
        self.loop_norm_methods += other.loop_norm_methods;
        self.phi_lower_methods += other.phi_lower_methods;
        self.unknown_methods += other.unknown_methods;
        for (reason, count) in &other.fallback_by_reason {
            *self.fallback_by_reason.entry(reason.clone()).or_default() += count;
        }
        self.by_reason.add(&other.by_reason);
        self.raw_by_reason.add(&other.raw_by_reason);
    }
}

#[derive(Debug)]
pub struct MethodCensus {
    pub class: String,
    pub method_idx: u32,
    pub signature: String,
    pub code_off: u32,
    pub status: &'static str,
    pub error: Option<String>,
    pub counts: Option<CensusCounts>,
    pub final_scan: Option<FinalGotoScan>,
    pub raw_diagnostics: Option<StructuringDiagnostics>,
    pub exception_counts: Option<crate::exception::ExceptionFlowCounts>,
    pub exception_flow: Option<crate::exception::ExceptionFlow>,
    pub region: Option<crate::region::RegionPathInfo>,
    pub evidence_id: Option<String>,
    pub unknown_id: Option<String>,
}

#[derive(Debug)]
pub struct CensusSelection {
    pub requested_limit: Option<usize>,
    pub total_defined_methods: usize,
    pub selected_methods: usize,
    pub unselected_methods: usize,
    pub truncated: bool,
    pub skipped_codeless_methods: usize,
    pub failed_methods: usize,
    pub completed_methods: usize,
}

#[derive(Debug)]
pub struct GotoCensus {
    pub schema_version: u32,
    pub methods: Vec<MethodCensus>,
    pub totals: CensusCounts,
    pub selection: CensusSelection,
    pub exception_totals: crate::exception::ExceptionFlowCounts,
}

pub fn census_dex(dex: &DexFile, limit: Option<usize>) -> GotoCensus {
    census_dex_with_mode(dex, limit, crate::region::StructuringMode::Auto)
}

pub fn census_dex_with_mode(
    dex: &DexFile,
    limit: Option<usize>,
    mode: crate::region::StructuringMode,
) -> GotoCensus {
    let total_defined_methods = dex.defined_methods().count();
    let selected_methods = limit
        .unwrap_or(total_defined_methods)
        .min(total_defined_methods);
    let mut report = GotoCensus {
        schema_version: CENSUS_SCHEMA_VERSION,
        methods: Vec::new(),
        totals: CensusCounts::default(),
        selection: CensusSelection {
            requested_limit: limit,
            total_defined_methods,
            selected_methods,
            unselected_methods: total_defined_methods - selected_methods,
            truncated: selected_methods < total_defined_methods,
            skipped_codeless_methods: 0,
            failed_methods: 0,
            completed_methods: 0,
        },
        exception_totals: crate::exception::ExceptionFlowCounts::default(),
    };
    for (class, method) in dex.defined_methods().take(selected_methods) {
        let mut row = MethodCensus {
            class: class.class.clone(),
            method_idx: method.method_idx,
            signature: dex.method_signature(method.method_idx),
            code_off: method.code_off,
            status: "skipped_codeless",
            error: None,
            counts: None,
            final_scan: None,
            raw_diagnostics: None,
            exception_counts: None,
            exception_flow: None,
            region: None,
            evidence_id: None,
            unknown_id: None,
        };
        if method.code_off == 0 {
            report.selection.skipped_codeless_methods += 1;
        } else {
            let result = dex
                .code_item(method.code_off)
                .map_err(|e| e.to_string())
                .and_then(|code| {
                    if dex.method_proto(method.method_idx).is_none() {
                        return Err("invalid method or prototype index".into());
                    }
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let lifted = crate::lift::lift_method_to_ssa(dex, &code, method.method_idx);
                        let info = crate::render::build_try_info(dex, &code.tries);
                        let (result, diagnostics) =
                            crate::region::structure_lifted(dex, &info, &lifted, mode);
                        (result, diagnostics, lifted)
                    }))
                    .map_err(|_| "decompilation panicked".into())
                });
            match result {
                Ok((output, diagnostics, lifted)) => {
                    let mut scan = count_final_gotos(&output.pseudocode);
                    attribute_final_gotos(&mut scan, &lifted);
                    let mut counts = CensusCounts::from_scan(&scan, &diagnostics);
                    counts.region_methods = usize::from(output.used_region_path);
                    counts.legacy_methods = usize::from(!output.used_region_path);
                    counts.structured_try_count = output.structured_try_count;
                    counts.nodes_split = output.nodes_split;
                    counts.loop_norm_methods = usize::from(output.nodes_split > 0);
                    counts.phi_lower_methods = usize::from(output.phi_lowered);
                    if let Some(reason) = output.fallback_reason {
                        counts.fallback_by_reason.insert(reason.as_str().into(), 1);
                    }
                    let (observation, unknown) = crate::evidence::observe_region(
                        &row.class,
                        &row.signature,
                        row.method_idx,
                        &output,
                        0,
                        crate::evidence::DEFAULT_VIEW_LINES,
                        false,
                    );
                    row.evidence_id = Some(observation.evidence.evidence_id);
                    row.unknown_id = unknown.map(|item| item.unknown_id);
                    counts.unknown_methods = usize::from(row.unknown_id.is_some());
                    row.region = Some(crate::region::RegionPathInfo {
                        used: output.used_region_path,
                        fallback_reason: output.fallback_reason,
                        structured_try_count: output.structured_try_count,
                        nodes_split: output.nodes_split,
                        phi_lowered: output.phi_lowered,
                    });
                    let exception_counts = lifted.exception_flow.counts();
                    report.exception_totals.add(&exception_counts);
                    report.totals.add(&counts);
                    report.selection.completed_methods += 1;
                    row.status = "completed";
                    row.counts = Some(counts);
                    row.final_scan = Some(scan);
                    row.raw_diagnostics = Some(diagnostics);
                    row.exception_counts = Some(exception_counts);
                    row.exception_flow = Some(lifted.exception_flow);
                }
                Err(error) => {
                    row.status = "failed";
                    row.error = Some(error);
                    report.selection.failed_methods += 1;
                }
            }
        }
        report.methods.push(row);
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structure::GotoEmission;

    #[test]
    fn final_counts_are_independent_of_raw_emissions() {
        let diagnostics = StructuringDiagnostics {
            goto_emissions: vec![GotoEmission {
                target: 2,
                reason: GotoReason::Revisit,
            }],
            bailed: false,
        };
        let removed = CensusCounts::from_scan(&count_final_gotos("return;"), &diagnostics);
        assert_eq!(removed.raw_emission_count, 1);
        assert_eq!(removed.final_goto_count, 0);
        let copied = CensusCounts::from_scan(
            &count_final_gotos("goto L2; goto L2; L2: return;"),
            &diagnostics,
        );
        assert_eq!(copied.raw_emission_count, 1);
        assert_eq!(copied.final_goto_count, 2);
        assert_eq!(copied.by_reason.unknown, 2);
    }
}
