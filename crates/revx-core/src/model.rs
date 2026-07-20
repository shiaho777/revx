use chrono::{DateTime, Utc};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn utc_now() -> DateTime<Utc> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    DateTime::<Utc>::from_timestamp(duration.as_secs() as i64, duration.subsec_nanos())
        .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).expect("unix epoch"))
}
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

pub const PROJECT_SCHEMA_VERSION: u32 = 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
    pub schema_version: u32,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub primary_binary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactHandle {
    pub hash_blake3: String,
    pub relative_path: String,
    pub size: u64,
    pub content_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniversalObject {
    pub id: String,
    pub path: Option<String>,
    pub display_name: String,
    pub kind: ObjectKind,
    pub format: Option<String>,
    pub size: u64,
    pub hash_blake3: Option<String>,
    pub media_type: Option<String>,
    pub entropy: Option<f64>,
    pub depth: usize,
    pub flags: Vec<String>,
    pub metadata: serde_json::Value,
    #[serde(default)]
    pub analyses: Vec<ObjectAnalysisSummary>,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectAnalysisSummary {
    pub analyzer: String,
    pub status: ObjectAnalysisStatus,
    pub summary: String,
    pub details: serde_json::Value,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectEdge {
    pub from: String,
    pub to: String,
    pub kind: ObjectEdgeKind,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectGraph {
    pub root_id: String,
    pub objects: Vec<UniversalObject>,
    pub edges: Vec<ObjectEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryImage {
    pub id: String,
    pub path: String,
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub entry: Option<u64>,
    pub image_base: Option<u64>,
    pub size: u64,
    pub hash_blake3: String,
    pub modules: Vec<Module>,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub relocations: Vec<Relocation>,
    pub debug_artifacts: Vec<DebugArtifact>,
    pub debug_import: DebugImportSummary,
    pub symbols: Vec<Symbol>,
    pub strings: Vec<StringLiteral>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Module {
    pub name: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Segment {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub permissions: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub kind: String,
    #[serde(default)]
    pub file_offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    pub name: String,
    pub address: Option<u64>,
    pub kind: String,
    pub size: Option<u64>,
    pub global: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Import {
    pub library: Option<String>,
    pub name: String,
    pub address: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Export {
    pub name: String,
    pub address: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relocation {
    pub address: u64,
    pub target: Option<u64>,
    pub symbol: Option<String>,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugArtifact {
    pub kind: String,
    pub identifier: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DebugImportSummary {
    pub status: DebugImportStatus,
    pub source_kind: Option<String>,
    pub artifact_path: Option<String>,
    pub imported_type_count: usize,
    pub imported_function_hint_count: usize,
    pub imported_variable_hint_count: usize,
    pub type_defs: Vec<TypeDef>,
    pub function_hints: Vec<DebugFunctionHint>,
    pub variable_hints: Vec<DebugVariableHint>,
    pub source_anchors: Vec<SourceAnchor>,
    pub evidence_ids: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugFunctionHint {
    pub address: Option<u64>,
    pub name: String,
    pub return_type: Option<String>,
    pub calling_convention: Option<String>,
    pub arguments: Vec<Variable>,
    pub locals: Vec<Variable>,
    pub source_anchor: Option<SourceAnchor>,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugVariableHint {
    pub function_name: Option<String>,
    pub function_address: Option<u64>,
    pub variable: Variable,
    pub source_anchor: Option<SourceAnchor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceAnchor {
    pub file: Option<String>,
    pub line: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Function {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub blocks: Vec<BasicBlock>,
    pub stack_summary: Option<StackSummary>,
    pub arguments: Vec<Variable>,
    pub locals: Vec<Variable>,
    pub pseudocode: Option<PseudocodeUnit>,
    pub evidence_ids: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionOverview {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub stack_summary: Option<StackSummary>,
    pub arguments: Vec<Variable>,
    pub locals: Vec<Variable>,
    pub evidence_ids: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl From<&Function> for FunctionOverview {
    fn from(function: &Function) -> Self {
        Self {
            name: function.name.clone(),
            address: function.address,
            size: function.size,
            stack_summary: function.stack_summary.clone(),
            arguments: function.arguments.clone(),
            locals: function.locals.clone(),
            evidence_ids: function.evidence_ids.clone(),
            warnings: function.warnings.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StackSummary {
    pub frame_size: Option<u64>,
    pub calling_convention: Option<String>,
    pub return_type: Option<String>,
    pub stack_arg_bytes: Option<u64>,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub address: u64,
    pub size: u64,
    pub instructions: Vec<Instruction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    pub address: u64,
    pub bytes: Arc<str>,
    pub text: Arc<str>,
}

/// Lightweight enumeration of reference kinds. Stored as a single byte in
/// memory (Copy, no heap allocation) but serializes to the same snake_case
/// string representation used by SQLite and JSON for backward compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum ReferenceKind {
    Call = 0,
    IndirectCall = 1,
    Jump = 2,
    IndirectJump = 3,
    BranchTrue = 4,
    BranchFalse = 5,
    Branch = 6,
    Data = 7,
    StringRef = 8,
    IndirectCodePtr = 9,
    DataRef = 10,
    Fallthrough = 11,
}

impl ReferenceKind {
    /// Returns the snake_case string representation, matching SQLite storage.
    #[inline]
    pub fn as_str(&self) -> &'static str {
        match self {
            ReferenceKind::Call => "call",
            ReferenceKind::IndirectCall => "indirect_call",
            ReferenceKind::Jump => "jump",
            ReferenceKind::IndirectJump => "indirect_jump",
            ReferenceKind::BranchTrue => "branch_true",
            ReferenceKind::BranchFalse => "branch_false",
            ReferenceKind::Branch => "branch",
            ReferenceKind::Data => "data",
            ReferenceKind::StringRef => "string_ref",
            ReferenceKind::IndirectCodePtr => "indirect_code_ptr",
            ReferenceKind::DataRef => "data_ref",
            ReferenceKind::Fallthrough => "fallthrough",
        }
    }

    /// Parse a string into a ReferenceKind. Falls back to `Data` for unknown kinds.
    pub fn from_str(s: &str) -> Self {
        match s {
            "call" => ReferenceKind::Call,
            "indirect_call" => ReferenceKind::IndirectCall,
            "jump" => ReferenceKind::Jump,
            "indirect_jump" => ReferenceKind::IndirectJump,
            "branch_true" => ReferenceKind::BranchTrue,
            "branch_false" => ReferenceKind::BranchFalse,
            "branch" => ReferenceKind::Branch,
            "data" => ReferenceKind::Data,
            "string_ref" => ReferenceKind::StringRef,
            "indirect_code_ptr" => ReferenceKind::IndirectCodePtr,
            "data_ref" => ReferenceKind::DataRef,
            "fallthrough" => ReferenceKind::Fallthrough,
            _ => ReferenceKind::Data,
        }
    }
}

/// Allow `r.kind == "call"` comparisons without changing test code.
impl PartialEq<&str> for ReferenceKind {
    #[inline]
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<str> for ReferenceKind {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl std::fmt::Display for ReferenceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Reference {
    pub from: u64,
    pub to: u64,
    pub kind: ReferenceKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEdge {
    pub caller_name: String,
    pub caller_address: u64,
    pub callee_name: Option<String>,
    pub callee_address: u64,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringLiteral {
    pub address: Option<u64>,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeDef {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub source: TypeSource,
    pub size: Option<u64>,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Variable {
    pub name: String,
    pub role: VariableRole,
    pub storage: VariableStorage,
    pub type_name: Option<String>,
    pub confidence: f32,
    pub location: String,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PseudocodeUnit {
    pub language: String,
    pub text: String,
    pub regions: Vec<PseudocodeRegion>,
    pub region_artifact: Option<ArtifactHandle>,
    pub evidence_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_lattice: Option<AgentSemanticLattice>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PseudocodeRegion {
    pub id: String,
    pub kind: RegionKind,
    pub start_address: Option<u64>,
    pub end_address: Option<u64>,
    pub header: Option<String>,
    pub statements: Vec<String>,
    pub children: Vec<PseudocodeRegion>,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub subject: String,
    pub summary: String,
    pub kind: String,
    pub details: serde_json::Value,
    pub provenance: EvidenceProvenance,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvidenceProvenance {
    pub source: String,
    pub binary_id: Option<String>,
    pub function_address: Option<u64>,
    pub instruction_address: Option<u64>,
    pub profile: Option<AnalysisProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hypothesis {
    pub id: String,
    pub title: String,
    pub notes: String,
    pub evidence_ids: Vec<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    pub timestamp: DateTime<Utc>,
    pub process: String,
    pub thread: String,
    pub kind: String,
    pub location: Option<u64>,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub id: String,
    pub topic: String,
    pub body: String,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BinaryFormat {
    #[default]
    Pe,
    Elf,
    MachO,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    File,
    Directory,
    Archive,
    Binary,
    Text,
    Image,
    Document,
    Package,
    FilesystemImage,
    MemoryDump,
    NetworkCapture,
    Database,
    Model,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectEdgeKind {
    Contains,
    ExpandsTo,
    InterpretsAs,
    DerivedFrom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectAnalysisStatus {
    Completed,
    Partial,
    Skipped,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    Arm64,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisProfile {
    Fast,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisRunState {
    Pending,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DebugImportStatus {
    #[default]
    NotFound,
    Parsed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeSource {
    Debug,
    Inferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VariableRole {
    Argument,
    Local,
    Temporary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VariableStorage {
    Register,
    Stack,
    Global,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionKind {
    Block,
    If,
    Loop,
    Switch,
    Return,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSummary {
    pub binary_id: String,
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub function_count: usize,
    pub import_count: usize,
    pub export_count: usize,
    pub string_count: usize,
    pub evidence_count: usize,
    pub debug_import_coverage: DebugCoverageSummary,
    pub typed_function_count: usize,
    pub structured_pseudocode_count: usize,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DebugCoverageSummary {
    pub status: DebugImportStatus,
    pub imported_type_count: usize,
    pub imported_function_hint_count: usize,
    pub imported_variable_hint_count: usize,
}

/// Lightweight metadata snapshot of a binary, used in `Survey` instead of
/// the full `BinaryImage` to avoid holding all symbols/strings/imports in
/// memory. Only the fields needed by consumers are included.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BinarySummary {
    pub id: String,
    pub path: String,
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub entry: Option<u64>,
    pub image_base: Option<u64>,
    pub size: u64,
    pub hash_blake3: String,
    pub import_count: usize,
    pub export_count: usize,
    pub string_count: usize,
}

impl BinarySummary {
    /// Extract a lightweight summary from a full `BinaryImage` without cloning.
    pub fn from_image(image: &BinaryImage) -> Self {
        Self {
            id: image.id.clone(),
            path: image.path.clone(),
            format: image.format,
            architecture: image.architecture,
            entry: image.entry,
            image_base: image.image_base,
            size: image.size,
            hash_blake3: image.hash_blake3.clone(),
            import_count: image.imports.len(),
            export_count: image.exports.len(),
            string_count: image.strings.len(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Survey {
    pub binary: BinarySummary,
    pub summary: AnalysisSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisBundle {
    pub survey: Survey,
    pub functions: Vec<Function>,
    pub references: Vec<Reference>,
    pub types: Vec<TypeDef>,
    #[serde(default)]
    pub strings: Vec<StringLiteral>,
    #[serde(default)]
    pub debug_import: DebugImportSummary,
    #[serde(default)]
    pub imports: Vec<Import>,
}

impl BinaryImage {
    /// Convenience: create a Survey from this image + summary.
    pub fn to_survey(&self, summary: AnalysisSummary) -> Survey {
        Survey {
            binary: BinarySummary::from_image(self),
            summary,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryRecord {
    pub id: String,
    pub path: String,
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub last_analysis_at: Option<DateTime<Utc>>,
    pub function_count: usize,
    pub import_count: usize,
    pub export_count: usize,
    pub string_count: usize,
    pub typed_function_count: usize,
    pub structured_pseudocode_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSearchHit {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByteMatch {
    pub offset: u64,
    pub bytes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewArtifact<T> {
    pub preview: T,
    pub artifact: Option<ArtifactHandle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectOpenRequest {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectOpenResponse {
    pub workspace_root: String,
    pub project: ProjectConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectStatusRequest;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectStatusResponse {
    pub workspace_root: String,
    pub project: ProjectConfig,
    pub binary_count: usize,
    pub binaries: Vec<BinaryRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectIdentifyRequest {
    pub path: String,
    pub max_depth: Option<usize>,
    pub max_children: Option<usize>,
    pub include_graph: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectIdentifyResponse {
    pub root_id: String,
    pub object_count: usize,
    pub edge_count: usize,
    pub evidence_count: usize,
    pub evidence_ids: Vec<String>,
    pub graph: Option<ObjectGraph>,
    pub artifact: Option<ArtifactHandle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectSearchRequest {
    pub query: String,
    pub kind: Option<ObjectKind>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectSearchResponse {
    pub objects: Vec<ObjectSearchHit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectSearchHit {
    pub id: String,
    pub path: Option<String>,
    pub display_name: String,
    pub kind: ObjectKind,
    pub format: Option<String>,
    pub size: u64,
    pub hash_blake3: Option<String>,
    pub flags: Vec<String>,
    pub analyzer_names: Vec<String>,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectProfileRequest {
    pub query: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectProfileResponse {
    pub object: UniversalObject,
    pub incoming_edges: Vec<ObjectEdge>,
    pub outgoing_edges: Vec<ObjectEdge>,
    pub evidence_ids: Vec<String>,
    pub artifact: Option<ArtifactHandle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectMaterializeRequest {
    pub query: String,
    pub preview_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectMaterializeResponse {
    pub object: UniversalObject,
    pub artifact: ArtifactHandle,
    pub content_type: String,
    pub evidence_id: String,
    pub source: String,
    pub preview_hex: Option<String>,
    pub preview_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectExtractRangeRequest {
    pub query: String,
    pub offset: u64,
    pub length: u64,
    pub context_bytes: Option<u64>,
    pub preview_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectExtractRangeResponse {
    pub object: UniversalObject,
    pub offset: u64,
    pub requested_length: u64,
    pub extracted_offset: u64,
    pub extracted_size: u64,
    pub artifact: ArtifactHandle,
    pub content_type: String,
    pub evidence_id: String,
    pub source: String,
    pub preview_hex: Option<String>,
    pub preview_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectSignatureScanRequest {
    pub query: String,
    pub limit: Option<usize>,
    pub max_object_bytes: Option<usize>,
    pub preview_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectSignatureScanResponse {
    pub object: UniversalObject,
    pub source: String,
    pub scanned_size: u64,
    pub returned_count: usize,
    pub truncated: bool,
    pub signatures: Vec<ObjectSignatureHit>,
    pub evidence_id: String,
    pub artifact: ArtifactHandle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectSignatureHit {
    pub offset: u64,
    pub signature: String,
    pub format: String,
    pub description: String,
    pub confidence: f32,
    pub suggested_length: Option<u64>,
    pub preview_hex: String,
    pub preview_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectCarveSignaturesRequest {
    pub query: String,
    pub limit: Option<usize>,
    pub max_object_bytes: Option<usize>,
    pub max_carve_bytes: Option<usize>,
    pub min_confidence: Option<f32>,
    pub preview_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectCarveSignaturesResponse {
    pub object: UniversalObject,
    pub source: String,
    pub scanned_size: u64,
    pub scanned_count: usize,
    pub carved_count: usize,
    pub skipped_count: usize,
    pub truncated: bool,
    pub scan_evidence_id: String,
    pub carve_evidence_id: String,
    pub artifact: ArtifactHandle,
    pub carves: Vec<ObjectSignatureCarve>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectSignatureCarve {
    pub offset: u64,
    pub length: u64,
    pub signature: String,
    pub format: String,
    pub description: String,
    pub confidence: f32,
    pub artifact: ArtifactHandle,
    pub preview_hex: Option<String>,
    pub preview_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectCarveIdentifyRequest {
    pub query: String,
    pub limit: Option<usize>,
    pub max_object_bytes: Option<usize>,
    pub max_carve_bytes: Option<usize>,
    pub min_confidence: Option<f32>,
    pub preview_bytes: Option<usize>,
    pub max_depth: Option<usize>,
    pub max_children: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectCarveIdentifyResponse {
    pub object: UniversalObject,
    pub source: String,
    pub scanned_size: u64,
    pub carved_count: usize,
    pub identified_count: usize,
    pub failed_count: usize,
    pub scan_evidence_id: String,
    pub carve_evidence_id: String,
    pub identify_evidence_id: String,
    pub artifact: ArtifactHandle,
    pub carves: Vec<ObjectCarveIdentifyResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectCarveIdentifyResult {
    pub carve: ObjectSignatureCarve,
    pub root_id: Option<String>,
    pub object_ids: Vec<String>,
    pub object_count: usize,
    pub edge_count: usize,
    pub evidence_ids: Vec<String>,
    pub graph_artifact: Option<ArtifactHandle>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectAnalyzerKind {
    Auto,
    ByteHistogram,
    Strings,
    StructuredText,
    ZipListing,
    AndroidPackage,
    DexBytecode,
    IosPackage,
    JavaArchive,
    JvmClass,
    PythonBytecode,
    ShellLink,
    PortableExecutable,
    DotnetMetadata,
    ElfBinary,
    MachOBinary,
    OpenXmlDocument,
    SqliteSchema,
    WasmModule,
    PdfDocument,
    PngImage,
    JpegImage,
    GifImage,
    BmpImage,
    RiffContainer,
    PcapCapture,
    OleCompound,
    SafeTensorsModel,
    GgufModel,
    PyTorchModel,
    IsoBmff,
    CabArchive,
    ArArchive,
    SevenZipArchive,
    RarArchive,
    FontFile,
    TiffImage,
    AudioMedia,
    DiskImage,
    UnknownBlob,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectAnalyzeRequest {
    pub query: String,
    pub analyzers: Option<Vec<ObjectAnalyzerKind>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LatticeQuality {
    pub claim_density: f32,
    pub evidence_coverage: f32,
    pub ambiguity: f32,
    pub escalate: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escalate_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticAnchor {
    pub id: String,
    pub kind: String,
    pub surface: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<u64>,
    pub confidence: f32,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentNextAction {
    pub tool: String,
    pub reason: String,
    pub priority: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default)]
    pub args: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentClaim {
    pub id: String,
    pub intent: String,
    pub kind: String,
    pub confidence: f32,
    #[serde(default)]
    pub anchors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confutation: Option<String>,
    #[serde(default)]
    pub probes: Vec<AgentNextAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalChain {
    pub id: String,
    pub narrative: String,
    pub confidence: f32,
    #[serde(default)]
    pub steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IbcStep {
    pub pc: u16,
    pub op: String,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(default)]
    pub args: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseLexeme {
    pub glyph: String,
    pub code: u32,
    #[serde(default)]
    pub takes_arg: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meaning: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FlagBehaviorEdge {
    pub glyph: String,
    pub code: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler_name: Option<String>,
    #[serde(default)]
    pub behaviors: Vec<String>,
    #[serde(default)]
    pub effects: Vec<String>,
    #[serde(default)]
    pub confidence: f32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orbit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentSemanticLattice {
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub thesis: String,
    #[serde(default)]
    pub claims: Vec<AgentClaim>,
    #[serde(default)]
    pub anchors: Vec<SemanticAnchor>,
    #[serde(default)]
    pub chains: Vec<CausalChain>,
    #[serde(default)]
    pub case_lexicon: Vec<CaseLexeme>,
    #[serde(default)]
    pub behavior_graph: Vec<FlagBehaviorEdge>,
    #[serde(default)]
    pub contradictions: Vec<String>,
    #[serde(default)]
    pub investigation_bytecode: Vec<String>,
    #[serde(default)]
    pub ibc: Vec<IbcStep>,
    #[serde(default)]
    pub ibc_pc: u16,
    #[serde(default)]
    pub ibc_status: String,
    #[serde(default)]
    pub quality: LatticeQuality,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentInteractionBrief {
    pub headline: String,
    #[serde(default)]
    pub key_findings: Vec<String>,
    #[serde(default)]
    pub open_questions: Vec<String>,
    #[serde(default)]
    pub next_actions: Vec<AgentNextAction>,
    #[serde(default)]
    pub stop_conditions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_lattice: Option<AgentSemanticLattice>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectAnalyzeResponse {
    pub object: UniversalObject,
    pub analyses: Vec<ObjectAnalysisSummary>,
    pub evidence_ids: Vec<String>,
    pub artifact: Option<ArtifactHandle>,
    #[serde(default)]
    pub next_actions: Vec<AgentNextAction>,
    #[serde(default)]
    pub agent_brief: AgentInteractionBrief,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ObjectPluginListRequest;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectPluginListResponse {
    pub plugins: Vec<ObjectPluginDefinition>,
    pub artifact: Option<ArtifactHandle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectPluginRunRequest {
    pub plugin_id: String,
    pub query: String,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectPluginRunResponse {
    pub plugin: ObjectPluginDefinition,
    pub object: UniversalObject,
    pub materialized_artifact: ArtifactHandle,
    pub status: ObjectAnalysisStatus,
    pub summary: String,
    pub evidence_id: String,
    pub artifact: ArtifactHandle,
    pub stdout_preview: Option<String>,
    pub stderr_preview: Option<String>,
    pub output_json: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectPluginDefinition {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub command: Vec<String>,
    #[serde(default)]
    pub accepted_kinds: Vec<ObjectKind>,
    #[serde(default)]
    pub accepted_formats: Vec<String>,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectRegisterBinaryRequest {
    pub query: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectRegisterBinaryResponse {
    pub object: UniversalObject,
    pub materialized_artifact: ArtifactHandle,
    pub survey: Survey,
    pub survey_artifact: ArtifactHandle,
    pub evidence_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectAnalyzeBinaryRequest {
    pub query: String,
    pub profile: AnalysisProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectAnalyzeBinaryResponse {
    pub object: UniversalObject,
    pub materialized_artifact: ArtifactHandle,
    pub run_id: String,
    pub status: AnalysisRunState,
    pub summary: AnalysisSummary,
    pub evidence_count: usize,
    pub evidence_ids: Vec<String>,
    pub evidence_artifact: Option<ArtifactHandle>,
    pub link_evidence_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectPipelineRequest {
    pub path: String,
    pub max_depth: Option<usize>,
    pub max_children: Option<usize>,
    pub object_limit: Option<usize>,
    pub analyze_objects: Option<bool>,
    pub carve_embedded: Option<bool>,
    pub carve_limit: Option<usize>,
    pub max_carve_object_bytes: Option<usize>,
    pub max_carve_bytes: Option<usize>,
    pub min_carve_confidence: Option<f32>,
    pub carve_max_depth: Option<usize>,
    pub carve_max_children: Option<usize>,
    pub plugin_ids: Option<Vec<String>>,
    pub analyze_binaries: Option<bool>,
    pub binary_profile: Option<AnalysisProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectPipelineResponse {
    pub pipeline_id: String,
    pub root_id: String,
    pub object_count: usize,
    pub edge_count: usize,
    pub analyzed_object_count: usize,
    pub carved_object_count: usize,
    pub identified_embedded_object_count: usize,
    pub failed_embedded_identify_count: usize,
    pub binary_candidate_count: usize,
    pub analyzed_binary_count: usize,
    pub failed_step_count: usize,
    pub evidence_count: usize,
    pub evidence_ids: Vec<String>,
    pub graph_artifact: ArtifactHandle,
    pub report_artifact: ArtifactHandle,
    pub steps: Vec<ObjectPipelineStep>,
    #[serde(default)]
    pub next_actions: Vec<AgentNextAction>,
    #[serde(default)]
    pub agent_brief: AgentInteractionBrief,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectPipelineStep {
    pub stage: ObjectPipelineStage,
    pub object_id: Option<String>,
    pub object_path: Option<String>,
    pub status: ObjectAnalysisStatus,
    pub summary: String,
    pub evidence_ids: Vec<String>,
    pub artifact: Option<ArtifactHandle>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectPipelineStage {
    Identify,
    ObjectAnalyze,
    CarveIdentify,
    PluginAnalyze,
    BinaryAnalyze,
    PipelineSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BinaryListRequest;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryListResponse {
    pub binaries: Vec<BinaryRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisRunRequest {
    pub binary_path: String,
    pub profile: AnalysisProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisRunResponse {
    pub run_id: String,
    pub status: AnalysisRunState,
    pub summary: AnalysisSummary,
    pub evidence_count: usize,
    pub evidence_ids: Vec<String>,
    pub evidence_artifact: Option<ArtifactHandle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisStatusRequest {
    pub run_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisStatusResponse {
    pub run_id: String,
    pub binary_id: String,
    pub profile: AnalysisProfile,
    pub status: AnalysisRunState,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub summary: AnalysisSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinarySurveyRequest {
    pub binary_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinarySurveyResponse {
    pub survey: Option<Survey>,
    pub preview: AnalysisSummary,
    pub evidence_count: usize,
    pub evidence_ids: Vec<String>,
    pub evidence_artifact: Option<ArtifactHandle>,
    pub artifact: Option<ArtifactHandle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSearchRequest {
    pub query: String,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSearchResponse {
    pub functions: Vec<FunctionSearchHit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionProfileRequest {
    pub query: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionProfileResponse {
    pub function: Function,
    pub incoming_xrefs: Vec<Reference>,
    pub outgoing_xrefs: Vec<Reference>,
    pub callers: Vec<CallEdge>,
    pub callees: Vec<CallEdge>,
    pub artifact: Option<ArtifactHandle>,
    #[serde(default)]
    pub agent_brief: AgentInteractionBrief,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DecompileStrategy {
    #[default]
    Auto,
    Cached,
    Fast,
    Full,
    Hotblock,
}

impl DecompileStrategy {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "auto" | "" => Some(Self::Auto),
            "cached" | "cache" => Some(Self::Cached),
            "fast" => Some(Self::Fast),
            "full" => Some(Self::Full),
            "hotblock" | "hot" | "oversize" => Some(Self::Hotblock),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompileFunctionRequest {
    pub query: String,
    #[serde(default)]
    pub strategy: Option<DecompileStrategy>,
    #[serde(default)]
    pub force_refresh: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompileFunctionResponse {
    pub function_name: String,
    pub address: u64,
    pub pseudocode: Option<PseudocodeUnit>,
    pub evidence_ids: Vec<String>,
    pub artifact: Option<ArtifactHandle>,
    #[serde(default)]
    pub strategy_used: DecompileStrategy,
    #[serde(default)]
    pub cache_hit: bool,
    #[serde(default)]
    pub available_strategies: Vec<String>,
    #[serde(default)]
    pub agent_brief: AgentInteractionBrief,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompileCacheStatusRequest {
    pub query: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompileCacheEntry {
    pub strategy: String,
    pub region_count: usize,
    pub text_len: usize,
    pub has_lattice: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompileCacheStatusResponse {
    pub function_name: String,
    pub address: u64,
    pub has_function_pseudocode: bool,
    pub function_region_count: usize,
    pub function_text_len: usize,
    pub strategies: Vec<DecompileCacheEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassembleFunctionRequest {
    pub query: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassembleFunctionResponse {
    pub function_name: String,
    pub address: u64,
    pub blocks: Vec<BasicBlock>,
    pub annotations: Option<ArtifactHandle>,
    pub artifact: Option<ArtifactHandle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrefsQueryRequest {
    pub query: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrefsQueryResponse {
    pub references: Vec<Reference>,
    #[serde(default)]
    pub agent_brief: AgentInteractionBrief,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallgraphSliceRequest {
    pub query: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallgraphSliceResponse {
    pub edges: Vec<CallEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringSearchRequest {
    pub pattern: String,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringSearchResponse {
    pub matches: Vec<StringLiteral>,
    #[serde(default)]
    pub agent_brief: AgentInteractionBrief,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchBytesRequest {
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchBytesResponse {
    pub matches: Vec<ByteMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectContentSearchRequest {
    pub pattern: String,
    pub mode: Option<ObjectContentSearchMode>,
    pub query: Option<String>,
    pub limit: Option<usize>,
    pub per_object_limit: Option<usize>,
    pub max_object_bytes: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectContentSearchMode {
    Text,
    Hex,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectContentSearchResponse {
    pub pattern: String,
    pub mode: ObjectContentSearchMode,
    pub object_count: usize,
    pub searched_object_count: usize,
    pub skipped_object_count: usize,
    pub returned_count: usize,
    pub truncated: bool,
    pub matches: Vec<ObjectContentMatch>,
    pub artifact: Option<ArtifactHandle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectContentMatch {
    pub object_id: String,
    pub object_path: Option<String>,
    pub display_name: String,
    pub object_kind: ObjectKind,
    pub object_format: Option<String>,
    pub offset: u64,
    pub length: usize,
    pub preview_hex: String,
    pub preview_text: Option<String>,
    pub artifact: ArtifactHandle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePackRequest {
    pub subject: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePackResponse {
    pub preview: Vec<Evidence>,
    pub artifact: Option<ArtifactHandle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceGraphRequest {
    pub subject: String,
    pub depth: Option<usize>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceGraphResponse {
    pub subject: String,
    pub node_count: usize,
    pub edge_count: usize,
    pub evidence_count: usize,
    pub artifact: ArtifactHandle,
    pub nodes: Vec<EvidenceGraphNode>,
    pub edges: Vec<EvidenceGraphEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceGraphNode {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub summary: Option<String>,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceGraphEdge {
    pub from: String,
    pub to: String,
    pub kind: String,
    pub label: String,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactReadRequest {
    pub relative_path: Option<String>,
    pub hash_blake3: Option<String>,
    pub offset: Option<u64>,
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactReadResponse {
    pub artifact: ArtifactHandle,
    pub offset: u64,
    pub total_size: u64,
    pub returned_size: usize,
    pub truncated: bool,
    pub preview_hex: String,
    pub preview_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactListRequest {
    pub query: Option<String>,
    pub content_type: Option<String>,
    pub role: Option<String>,
    pub limit: Option<usize>,
    pub include_unreferenced: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactListResponse {
    pub total_count: usize,
    pub returned_count: usize,
    pub truncated: bool,
    pub artifacts: Vec<ArtifactSearchHit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactSearchHit {
    pub artifact: ArtifactHandle,
    pub roles: Vec<String>,
    pub references: Vec<ArtifactReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactReference {
    pub kind: String,
    pub id: String,
    pub subject: Option<String>,
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolicSolveRequest {
    pub subject: String,
    pub variables: Vec<SymbolicVariable>,
    pub constraints: Vec<SymbolicConstraint>,
    pub max_solutions: Option<usize>,
    pub iteration_limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolicVariable {
    pub name: String,
    pub domain: SymbolicDomain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SymbolicDomain {
    IntRange { min: i64, max: i64 },
    IntValues { values: Vec<i64> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolicConstraint {
    pub id: Option<String>,
    pub left: SymbolicLinearExpr,
    pub op: SymbolicConstraintOp,
    pub right: SymbolicLinearExpr,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SymbolicLinearExpr {
    #[serde(default)]
    pub terms: Vec<SymbolicTerm>,
    #[serde(default)]
    pub constant: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolicTerm {
    pub variable: String,
    pub coefficient: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolicConstraintOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolicSolveStatus {
    Sat,
    Unsat,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolicSolveResponse {
    pub case_id: String,
    pub subject: String,
    pub status: SymbolicSolveStatus,
    pub constraint_count: usize,
    pub checked_assignments: usize,
    pub solutions: Vec<BTreeMap<String, i64>>,
    pub warnings: Vec<String>,
    pub evidence_id: String,
    pub artifact: ArtifactHandle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationRunRequest {
    pub subject: String,
    pub path: Option<String>,
    pub run_object_pipeline: Option<bool>,
    pub max_depth: Option<usize>,
    pub max_children: Option<usize>,
    pub object_limit: Option<usize>,
    pub carve_max_depth: Option<usize>,
    pub carve_max_children: Option<usize>,
    pub plugin_ids: Option<Vec<String>>,
    pub analyze_binaries: Option<bool>,
    pub binary_profile: Option<AnalysisProfile>,
    pub graph_depth: Option<usize>,
    pub graph_limit: Option<usize>,
    pub trace_kind: Option<String>,
    pub trace_limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationRunResponse {
    pub investigation_id: String,
    pub subject: String,
    pub summary: String,
    pub evidence_ids: Vec<String>,
    pub evidence_count: usize,
    pub graph: EvidenceGraphResponse,
    pub pipeline: Option<ObjectPipelineResponse>,
    pub trace_count: usize,
    pub report: Report,
    pub report_artifact: ArtifactHandle,
    pub artifact: ArtifactHandle,
    #[serde(default)]
    pub next_actions: Vec<AgentNextAction>,
    #[serde(default)]
    pub agent_brief: AgentInteractionBrief,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesisCreateRequest {
    pub title: String,
    pub notes: String,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesisCreateResponse {
    pub hypothesis: Hypothesis,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesisUpdateRequest {
    pub id: String,
    pub title: Option<String>,
    pub notes: Option<String>,
    pub evidence_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesisUpdateResponse {
    pub hypothesis: Hypothesis,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IbcStatusRequest {
    #[serde(default)]
    pub namespace: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IbcStatusResponse {
    pub summary: String,
    #[serde(default)]
    pub active_namespace: String,
    #[serde(default)]
    pub focus: String,
    #[serde(default)]
    pub pc: u16,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub epoch: u64,
    #[serde(default)]
    pub witnesses: Vec<String>,
    #[serde(default)]
    pub hypothesis_ids: Vec<String>,
    #[serde(default)]
    pub next_actions: Vec<AgentNextAction>,
    #[serde(default)]
    pub agent_brief: AgentInteractionBrief,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_lattice: Option<AgentSemanticLattice>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IbcAdvanceRequest {
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub tool: Option<String>,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub force_next: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IbcAdvanceResponse {
    pub advanced: bool,
    pub note: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub pc: u16,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub epoch: u64,
    #[serde(default)]
    pub hypothesis_ids: Vec<String>,
    #[serde(default)]
    pub next_actions: Vec<AgentNextAction>,
    #[serde(default)]
    pub agent_brief: AgentInteractionBrief,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_lattice: Option<AgentSemanticLattice>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportGenerateRequest {
    pub topic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportGenerateResponse {
    pub report: Report,
    pub artifact: Option<ArtifactHandle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceImportRequest {
    pub events: Vec<TraceEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceImportResponse {
    pub imported: usize,
    pub evidence_count: usize,
    pub evidence_ids: Vec<String>,
    pub artifact: Option<ArtifactHandle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceQueryRequest {
    pub kind: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceQueryResponse {
    pub events: Vec<TraceEvent>,
    pub artifact: Option<ArtifactHandle>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisBriefRequest {
    pub query: String,
    #[serde(default)]
    pub string_limit: Option<usize>,
    #[serde(default)]
    pub function_limit: Option<usize>,
    #[serde(default)]
    pub hot_function_limit: Option<usize>,
    #[serde(default)]
    pub xref_limit: Option<usize>,
    #[serde(default)]
    pub include_pseudocode: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisStringHit {
    pub address: Option<u64>,
    pub value: String,
    pub xref_count: usize,
    pub owning_functions: Vec<FunctionSearchHit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisHotFunction {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub reason: String,
    pub score: u32,
    pub confidence: f32,
    pub caller_count: usize,
    pub callee_count: usize,
    #[serde(default)]
    pub caller_samples: Vec<String>,
    #[serde(default)]
    pub callee_samples: Vec<String>,
    #[serde(default)]
    pub quality_tags: Vec<String>,
    pub digest: String,
    pub string_hits: Vec<String>,
    pub pseudocode_preview: Option<String>,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisImportHit {
    pub name: String,
    pub address: Option<u64>,
    pub library: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisBriefResponse {
    pub query: String,
    #[serde(default)]
    pub query_tokens: Vec<String>,
    pub headline: String,
    pub summary: String,
    pub string_hits: Vec<AnalysisStringHit>,
    pub function_hits: Vec<FunctionSearchHit>,
    #[serde(default)]
    pub import_hits: Vec<AnalysisImportHit>,
    pub hot_functions: Vec<AnalysisHotFunction>,
    pub xref_samples: Vec<Reference>,
    pub key_findings: Vec<String>,
    #[serde(default)]
    pub next_actions: Vec<AgentNextAction>,
    #[serde(default)]
    pub agent_brief: AgentInteractionBrief,
    pub artifact: Option<ArtifactHandle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "capability", content = "payload", rename_all = "snake_case")]
pub enum CapabilityRequest {
    ProjectOpen(ProjectOpenRequest),
    ProjectStatus(ProjectStatusRequest),
    ObjectIdentify(ObjectIdentifyRequest),
    ObjectSearch(ObjectSearchRequest),
    ObjectProfile(ObjectProfileRequest),
    ObjectMaterialize(ObjectMaterializeRequest),
    ObjectExtractRange(ObjectExtractRangeRequest),
    ObjectSignatureScan(ObjectSignatureScanRequest),
    ObjectCarveSignatures(ObjectCarveSignaturesRequest),
    ObjectCarveIdentify(ObjectCarveIdentifyRequest),
    ObjectAnalyze(ObjectAnalyzeRequest),
    ObjectPluginList(ObjectPluginListRequest),
    ObjectPluginRun(ObjectPluginRunRequest),
    ObjectRegisterBinary(ObjectRegisterBinaryRequest),
    ObjectAnalyzeBinary(ObjectAnalyzeBinaryRequest),
    ObjectPipeline(ObjectPipelineRequest),
    ObjectContentSearch(ObjectContentSearchRequest),
    BinaryList(BinaryListRequest),
    AnalysisRun(AnalysisRunRequest),
    AnalysisStatus(AnalysisStatusRequest),
    BinarySurvey(BinarySurveyRequest),
    FunctionSearch(FunctionSearchRequest),
    FunctionProfile(FunctionProfileRequest),
    DecompileFunction(DecompileFunctionRequest),
    DecompileCacheStatus(DecompileCacheStatusRequest),
    DisassembleFunction(DisassembleFunctionRequest),
    XrefsQuery(XrefsQueryRequest),
    CallgraphSlice(CallgraphSliceRequest),
    StringSearch(StringSearchRequest),
    SearchBytes(SearchBytesRequest),
    ArtifactRead(ArtifactReadRequest),
    ArtifactList(ArtifactListRequest),
    EvidencePack(EvidencePackRequest),
    EvidenceGraph(EvidenceGraphRequest),
    SymbolicSolve(SymbolicSolveRequest),
    AnalysisBrief(AnalysisBriefRequest),
    InvestigationRun(InvestigationRunRequest),
    HypothesisCreate(HypothesisCreateRequest),
    HypothesisUpdate(HypothesisUpdateRequest),
    IbcStatus(IbcStatusRequest),
    IbcAdvance(IbcAdvanceRequest),
    ReportGenerate(ReportGenerateRequest),
    TraceImport(TraceImportRequest),
    TraceQuery(TraceQueryRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "capability", content = "payload", rename_all = "snake_case")]
pub enum CapabilityResponse {
    ProjectOpen(ProjectOpenResponse),
    ProjectStatus(ProjectStatusResponse),
    ObjectIdentify(ObjectIdentifyResponse),
    ObjectSearch(ObjectSearchResponse),
    ObjectProfile(ObjectProfileResponse),
    ObjectMaterialize(ObjectMaterializeResponse),
    ObjectExtractRange(ObjectExtractRangeResponse),
    ObjectSignatureScan(ObjectSignatureScanResponse),
    ObjectCarveSignatures(ObjectCarveSignaturesResponse),
    ObjectCarveIdentify(ObjectCarveIdentifyResponse),
    ObjectAnalyze(ObjectAnalyzeResponse),
    ObjectPluginList(ObjectPluginListResponse),
    ObjectPluginRun(ObjectPluginRunResponse),
    ObjectRegisterBinary(ObjectRegisterBinaryResponse),
    ObjectAnalyzeBinary(ObjectAnalyzeBinaryResponse),
    ObjectPipeline(ObjectPipelineResponse),
    ObjectContentSearch(ObjectContentSearchResponse),
    BinaryList(BinaryListResponse),
    AnalysisRun(AnalysisRunResponse),
    AnalysisStatus(AnalysisStatusResponse),
    BinarySurvey(BinarySurveyResponse),
    FunctionSearch(FunctionSearchResponse),
    FunctionProfile(FunctionProfileResponse),
    DecompileFunction(DecompileFunctionResponse),
    DecompileCacheStatus(DecompileCacheStatusResponse),
    DisassembleFunction(DisassembleFunctionResponse),
    XrefsQuery(XrefsQueryResponse),
    CallgraphSlice(CallgraphSliceResponse),
    StringSearch(StringSearchResponse),
    SearchBytes(SearchBytesResponse),
    ArtifactRead(ArtifactReadResponse),
    ArtifactList(ArtifactListResponse),
    EvidencePack(EvidencePackResponse),
    EvidenceGraph(EvidenceGraphResponse),
    SymbolicSolve(SymbolicSolveResponse),
    AnalysisBrief(AnalysisBriefResponse),
    InvestigationRun(InvestigationRunResponse),
    HypothesisCreate(HypothesisCreateResponse),
    HypothesisUpdate(HypothesisUpdateResponse),
    IbcStatus(IbcStatusResponse),
    IbcAdvance(IbcAdvanceResponse),
    ReportGenerate(ReportGenerateResponse),
    TraceImport(TraceImportResponse),
    TraceQuery(TraceQueryResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityEnvelope {
    pub id: Option<String>,
    pub request: CapabilityRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityReply {
    pub id: Option<String>,
    pub response: Option<CapabilityResponse>,
    pub error: Option<CapabilityError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityError {
    pub code: String,
    pub message: String,
}
