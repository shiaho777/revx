use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceConfidence {
    Observed,
    Derived,
    Inferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Complete,
    Partial,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceDetail {
    #[default]
    Summary,
    Complete,
}

impl EvidenceDetail {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "summary" | "" => Some(Self::Summary),
            "complete" | "full" => Some(Self::Complete),
            _ => None,
        }
    }

    pub fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Coverage {
    pub status: CoverageStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResidualUnknown {
    pub unknown_id: String,
    pub question: String,
    pub domain: String,
    pub reason: String,
    pub status: String,
    pub evidence_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnalysisViewPage {
    pub evidence_id: String,
    pub offset: usize,
    pub limit: usize,
    pub total: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    pub truncated: bool,
    pub text: String,
}

impl AnalysisViewPage {
    pub fn from_text(
        evidence_id: impl Into<String>,
        text: &str,
        offset: usize,
        limit: usize,
    ) -> Self {
        let lines: Vec<&str> = text.lines().collect();
        let total = lines.len();
        let offset = offset.min(total);
        let end = offset.saturating_add(limit).min(total);
        let truncated = end < total;
        Self {
            evidence_id: evidence_id.into(),
            offset,
            limit,
            total,
            next_offset: truncated.then_some(end),
            truncated,
            text: lines[offset..end].join("\n"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnalysisEvidence {
    pub evidence_id: String,
    pub operation: String,
    pub subject: String,
    pub confidence: EvidenceConfidence,
    pub coverage: Coverage,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unknown_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DexMethodRecord {
    pub class: String,
    pub signature: String,
    pub method_idx: u32,
    pub used_region_path: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<String>,
    pub nodes_split: usize,
    pub structured_try_count: usize,
    pub evidence: AnalysisEvidence,
    pub view: AnalysisViewPage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pseudocode: Option<String>,
    #[serde(skip)]
    pub source_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexDecompileRequest {
    pub path: String,
    #[serde(default)]
    pub class: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub detail: Option<EvidenceDetail>,
    #[serde(default)]
    pub view_offset: Option<usize>,
    #[serde(default)]
    pub view_limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexDecompileResponse {
    pub methods: Vec<DexMethodRecord>,
    pub unknowns: Vec<ResidualUnknown>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectAnalysisViewRequest {
    pub evidence_id: String,
    #[serde(default)]
    pub offset: Option<usize>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectAnalysisViewResponse {
    pub view: AnalysisViewPage,
    pub coverage: Coverage,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unknown_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListUnknownsRequest {
    #[serde(default)]
    pub offset: Option<usize>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListUnknownsResponse {
    pub total: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    pub unknowns: Vec<ResidualUnknown>,
}
