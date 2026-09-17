use crate::DexFile;
use crate::structure::{GotoReason, StructuringDiagnostics};
use std::collections::{BTreeMap, BTreeSet};

pub const CENSUS_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalGotoSite {
    pub line: usize,
    pub target: String,
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReasonCounts {
    pub revisit: usize,
    pub forward_revisit: usize,
    pub unknown: usize,
}

impl ReasonCounts {
    fn add(&mut self, other: &Self) {
        self.revisit += other.revisit;
        self.forward_revisit += other.forward_revisit;
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
}

impl CensusCounts {
    fn from_scan(scan: &FinalGotoScan, diagnostics: &StructuringDiagnostics) -> Self {
        let mut result = Self {
            final_goto_count: scan.count,
            final_goto_line_count: scan.line_count,
            by_reason: ReasonCounts {
                unknown: scan.count,
                ..Default::default()
            },
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
}

pub fn census_dex(dex: &DexFile, limit: Option<usize>) -> GotoCensus {
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
                        crate::render::decompile_method_with_diagnostics(
                            dex,
                            &code,
                            method.method_idx,
                        )
                    }))
                    .map_err(|_| "decompilation panicked".into())
                });
            match result {
                Ok((output, diagnostics)) => {
                    let scan = count_final_gotos(&output.pseudocode);
                    let counts = CensusCounts::from_scan(&scan, &diagnostics);
                    report.totals.add(&counts);
                    report.selection.completed_methods += 1;
                    row.status = "completed";
                    row.counts = Some(counts);
                    row.final_scan = Some(scan);
                    row.raw_diagnostics = Some(diagnostics);
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
