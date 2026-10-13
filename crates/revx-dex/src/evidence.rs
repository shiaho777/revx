use crate::DexFile;
use crate::region::{RegionFallbackReason, RegionResult};
use revx_core::{AnalysisEvidence, AnalysisViewPage, Coverage};
pub use revx_core::{CoverageStatus, DexMethodRecord, EvidenceConfidence, ResidualUnknown};

pub const DEFAULT_VIEW_LINES: usize = 80;

pub fn observe_region(
    class: &str,
    signature: &str,
    method_idx: u32,
    result: &RegionResult,
    view_offset: usize,
    view_limit: usize,
    complete: bool,
) -> (DexMethodRecord, Option<ResidualUnknown>) {
    let text_digest = blake3::hash(result.pseudocode.as_bytes()).to_hex();
    let fallback = result.fallback_reason.map(RegionFallbackReason::as_str);
    let evidence_id = format!(
        "ev_{}",
        digest(&[
            "dex_decompile",
            class,
            signature,
            &method_idx.to_string(),
            if result.used_region_path { "1" } else { "0" },
            fallback.unwrap_or("-"),
            &result.nodes_split.to_string(),
            &result.structured_try_count.to_string(),
            text_digest.as_str(),
        ])
    );
    let unknown = result.fallback_reason.map(|reason| ResidualUnknown {
        unknown_id: format!(
            "unk_{}",
            digest(&[
                "dex.structuring",
                reason.as_str(),
                class,
                signature,
                &method_idx.to_string(),
            ])
        ),
        question: unknown_question(reason),
        domain: "dex.structuring".into(),
        reason: reason.as_str().into(),
        status: "open".into(),
        evidence_id: evidence_id.clone(),
    });
    let coverage = if result.used_region_path {
        Coverage {
            status: CoverageStatus::Complete,
            reason: None,
            limitations: Vec::new(),
        }
    } else if let Some(reason) = fallback {
        Coverage {
            status: CoverageStatus::Partial,
            reason: Some(reason.to_string()),
            limitations: vec![format!("legacy render; region tree rejected: {reason}")],
        }
    } else {
        Coverage {
            status: CoverageStatus::Unknown,
            reason: Some("unstructured".into()),
            limitations: vec!["legacy render without a recorded fallback reason".into()],
        }
    };
    let unknown_ids = unknown
        .as_ref()
        .map(|item| vec![item.unknown_id.clone()])
        .unwrap_or_default();
    let limitations = coverage.limitations.clone();
    let view = AnalysisViewPage::from_text(
        evidence_id.clone(),
        &result.pseudocode,
        view_offset,
        view_limit,
    );
    let record = DexMethodRecord {
        class: class.into(),
        signature: signature.into(),
        method_idx,
        used_region_path: result.used_region_path,
        fallback_reason: fallback.map(str::to_string),
        nodes_split: result.nodes_split,
        structured_try_count: result.structured_try_count,
        evidence: AnalysisEvidence {
            evidence_id,
            operation: "dex_decompile".into(),
            subject: signature.into(),
            confidence: EvidenceConfidence::Observed,
            coverage,
            limitations,
            unknown_ids,
        },
        view,
        pseudocode: complete.then(|| result.pseudocode.clone()),
        source_text: result.pseudocode.clone(),
    };
    (record, unknown)
}

pub fn observe_dex(
    dex: &DexFile,
    class_filter: Option<&str>,
    method_filter: Option<&str>,
    limit: usize,
    view_offset: usize,
    view_limit: usize,
    complete: bool,
) -> (Vec<DexMethodRecord>, Vec<ResidualUnknown>) {
    let mut methods = Vec::new();
    let mut unknowns = Vec::new();
    for class in &dex.classes {
        if let Some(filter) = class_filter
            && !class.class.contains(filter)
        {
            continue;
        }
        let Some(data) = &class.class_data else {
            continue;
        };
        for method in data
            .direct_methods
            .iter()
            .chain(data.virtual_methods.iter())
        {
            if methods.len() >= limit {
                return (methods, unknowns);
            }
            let signature = dex.method_signature(method.method_idx);
            if let Some(filter) = method_filter
                && !signature.contains(filter)
            {
                continue;
            }
            let result = if method.code_off == 0 {
                RegionResult {
                    pseudocode: "    <no code>".into(),
                    used_region_path: false,
                    fallback_reason: None,
                    structured_try_count: 0,
                    nodes_split: 0,
                }
            } else {
                match dex.code_item(method.code_off) {
                    Ok(code) => {
                        let output = crate::lift::lift_method_to_ssa(dex, &code, method.method_idx);
                        let info = crate::render::build_try_info(dex, &code.tries);
                        crate::region::structure_lifted(
                            dex,
                            &info,
                            &output,
                            crate::region::StructuringMode::Auto,
                        )
                        .0
                    }
                    Err(error) => RegionResult {
                        pseudocode: format!("    <error: {error}>"),
                        used_region_path: false,
                        fallback_reason: None,
                        structured_try_count: 0,
                        nodes_split: 0,
                    },
                }
            };
            let (mut record, unknown) = observe_region(
                &class.class,
                &signature,
                method.method_idx,
                &result,
                view_offset,
                view_limit,
                complete,
            );
            if method.code_off == 0 {
                record.evidence.coverage = Coverage {
                    status: CoverageStatus::Unknown,
                    reason: Some("no_code".into()),
                    limitations: vec!["method has no code item".into()],
                };
                record.evidence.limitations = record.evidence.coverage.limitations.clone();
            }
            if let Some(item) = unknown {
                unknowns.push(item);
            }
            methods.push(record);
        }
    }
    (methods, unknowns)
}

fn digest(parts: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update(&[0]);
    }
    hasher.finalize().to_hex().to_string()
}

fn unknown_question(reason: RegionFallbackReason) -> String {
    match reason {
        RegionFallbackReason::SharedHandler => {
            "How should a shared exception handler be owned by one region?".into()
        }
        RegionFallbackReason::OrdinaryReachableHandler => {
            "Handler is reachable from ordinary control flow; how should it be structured?".into()
        }
        RegionFallbackReason::InvalidTryMetadata => {
            "Try metadata is invalid; what is the intended handler layout?".into()
        }
        RegionFallbackReason::NestedOrCrossScope => {
            "A control-flow edge crosses region or try scope; how should it be structured?".into()
        }
        RegionFallbackReason::LoopExceptionIntersection => {
            "A multi-entry loop intersects exception metadata; how should it be structured without splitting?".into()
        }
        RegionFallbackReason::UnsupportedShape => {
            "Control-flow shape is unsupported; what is the intended structure?".into()
        }
        RegionFallbackReason::Budget => {
            "Structuring or loop-split budget was exceeded; does a larger budget recover a region tree?".into()
        }
        RegionFallbackReason::ValidationFailed => {
            "Region tree failed validation; which block ownership or edge is missing?".into()
        }
    }
}
