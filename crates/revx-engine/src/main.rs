use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use revx_core::{
    AnalysisProfile, ArtifactListRequest, ArtifactReadRequest, BinarySurveyRequest,
    CapabilityRequest, DecompileCacheStatusRequest, DecompileFunctionRequest, DecompileStrategy, DisassembleFunctionRequest,
    EvidenceGraphRequest, EvidencePackRequest, FunctionProfileRequest,
    FunctionSearchRequest, InvestigationRunRequest, ObjectAnalyzeBinaryRequest,
    ObjectAnalyzeRequest, ObjectAnalyzerKind, ObjectCarveIdentifyRequest,
    ObjectCarveSignaturesRequest, ObjectContentSearchMode, ObjectContentSearchRequest,
    ObjectExtractRangeRequest, ObjectKind, ObjectMaterializeRequest, ObjectPipelineRequest,
    ObjectPluginListRequest, ObjectPluginRunRequest, ObjectProfileRequest,
    ObjectRegisterBinaryRequest, ObjectSearchRequest, ObjectSignatureScanRequest,
    AnalysisBriefRequest, ProjectStatusRequest, ReportGenerateRequest, SearchBytesRequest, StringSearchRequest,
    SymbolicSolveRequest, TraceImportRequest, XrefsQueryRequest,
};
use revx_daemon::{CapabilityService, send_ipc_request, serve_ipc, serve_mcp_stdio, socket_path};
use revx_loader::load_binary;
use revx_workspace::Workspace;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "revx")]
#[command(about = "Workspace-first reverse engineering CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Init {
        path: PathBuf,
    },
    #[command(subcommand)]
    Object(ObjectCommands),
    Add {
        path: PathBuf,
    },
    Analyze(AnalyzeArgs),
    Status,
    Survey,
    Funcs(FuncsArgs),
    Func {
        query: String,
    },
    Decompile {
        query: String,
        #[arg(long, value_parser = parse_decompile_strategy)]
        strategy: Option<DecompileStrategy>,
        #[arg(long)]
        force_refresh: bool,
    },
    DecompileCache {
        query: String,
    },
    Disasm {
        query: String,
    },
    Xrefs {
        target: String,
    },
    Strings(StringsArgs),
    #[command(subcommand)]
    Search(SearchCommands),
    #[command(subcommand)]
    Artifact(ArtifactCommands),
    Evidence {
        subject: String,
    },
    EvidenceGraph(EvidenceGraphArgs),
    Brief(BriefArgs),
    Investigate(InvestigateArgs),
    #[command(subcommand)]
    Symbolic(SymbolicCommands),
    #[command(subcommand)]
    Report(ReportCommands),
    #[command(subcommand)]
    Trace(TraceCommands),
    #[command(subcommand)]
    Daemon(DaemonCommands),
    #[command(subcommand)]
    Mcp(McpCommands),
}

#[derive(Args)]
struct AnalyzeArgs {
    path: PathBuf,
    #[arg(long, value_enum, default_value_t = ProfileValue::Fast)]
    profile: ProfileValue,
    #[arg(long, default_value_t = false)]
    micro: bool,
}

#[derive(Args)]
struct FuncsArgs {
    #[arg(long, default_value_t = 200)]
    limit: usize,
    #[arg(long, default_value_t = 0)]
    offset: usize,
}

#[derive(Args)]
struct StringsArgs {
    #[arg(long, default_value_t = 200)]
    limit: usize,
    #[arg(long, default_value_t = 0)]
    offset: usize,
}

#[derive(Subcommand)]
enum ObjectCommands {
    Identify(ObjectIdentifyArgs),
    Search(ObjectSearchArgs),
    Profile(ObjectProfileArgs),
    Materialize(ObjectMaterializeArgs),
    ExtractRange(ObjectExtractRangeArgs),
    ScanSignatures(ObjectSignatureScanArgs),
    CarveSignatures(ObjectCarveSignaturesArgs),
    CarveIdentify(ObjectCarveIdentifyArgs),
    Analyze(ObjectAnalyzeArgs),
    Plugins,
    PluginRun(ObjectPluginRunArgs),
    RegisterBinary(ObjectRegisterBinaryArgs),
    AnalyzeBinary(ObjectAnalyzeBinaryArgs),
    Pipeline(ObjectPipelineArgs),
}

#[derive(Args)]
struct ObjectIdentifyArgs {
    path: PathBuf,
    #[arg(long, default_value_t = 2)]
    max_depth: usize,
    #[arg(long, default_value_t = 256)]
    max_children: usize,
    #[arg(long)]
    no_graph: bool,
}

#[derive(Args)]
struct ObjectSearchArgs {
    query: String,
    #[arg(long, value_enum)]
    kind: Option<ObjectKindValue>,
    #[arg(long, default_value_t = 200)]
    limit: usize,
}

#[derive(Args)]
struct ObjectProfileArgs {
    query: String,
}

#[derive(Args)]
struct ObjectMaterializeArgs {
    query: String,
    #[arg(long, default_value_t = 256)]
    preview_bytes: usize,
}

#[derive(Args)]
struct ObjectExtractRangeArgs {
    query: String,
    #[arg(long, value_parser = parse_u64_cli)]
    offset: u64,
    #[arg(long, value_parser = parse_u64_cli)]
    length: u64,
    #[arg(long, value_parser = parse_u64_cli, default_value_t = 0)]
    context_bytes: u64,
    #[arg(long, default_value_t = 256)]
    preview_bytes: usize,
}

#[derive(Args)]
struct ObjectSignatureScanArgs {
    query: String,
    #[arg(long, default_value_t = 200)]
    limit: usize,
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    max_object_bytes: usize,
    #[arg(long, default_value_t = 64)]
    preview_bytes: usize,
}

#[derive(Args)]
struct ObjectCarveSignaturesArgs {
    query: String,
    #[arg(long, default_value_t = 100)]
    limit: usize,
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    max_object_bytes: usize,
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    max_carve_bytes: usize,
    #[arg(long, default_value_t = 0.9)]
    min_confidence: f32,
    #[arg(long, default_value_t = 64)]
    preview_bytes: usize,
}

#[derive(Args)]
struct ObjectCarveIdentifyArgs {
    query: String,
    #[arg(long, default_value_t = 100)]
    limit: usize,
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    max_object_bytes: usize,
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    max_carve_bytes: usize,
    #[arg(long, default_value_t = 0.9)]
    min_confidence: f32,
    #[arg(long, default_value_t = 64)]
    preview_bytes: usize,
    #[arg(long, default_value_t = 2)]
    max_depth: usize,
    #[arg(long, default_value_t = 256)]
    max_children: usize,
}

#[derive(Args)]
struct ObjectAnalyzeArgs {
    query: String,
    #[arg(long = "analyzer", value_enum)]
    analyzers: Vec<ObjectAnalyzerValue>,
}

#[derive(Args)]
struct ObjectPluginRunArgs {
    plugin_id: String,
    query: String,
    #[arg(long)]
    timeout_ms: Option<u64>,
}

#[derive(Args)]
struct ObjectRegisterBinaryArgs {
    query: String,
}

#[derive(Args)]
struct ObjectAnalyzeBinaryArgs {
    query: String,
    #[arg(long, value_enum, default_value_t = ProfileValue::Fast)]
    profile: ProfileValue,
}

#[derive(Args)]
struct ObjectPipelineArgs {
    path: PathBuf,
    #[arg(long, default_value_t = 4)]
    max_depth: usize,
    #[arg(long, default_value_t = 512)]
    max_children: usize,
    #[arg(long, default_value_t = 256)]
    object_limit: usize,
    #[arg(long)]
    no_analyze_objects: bool,
    #[arg(long)]
    no_carve_embedded: bool,
    #[arg(long, default_value_t = 32)]
    carve_limit: usize,
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    max_carve_object_bytes: usize,
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    max_carve_bytes: usize,
    #[arg(long, default_value_t = 0.9)]
    min_carve_confidence: f32,
    #[arg(long, default_value_t = 2)]
    carve_max_depth: usize,
    #[arg(long, default_value_t = 256)]
    carve_max_children: usize,
    #[arg(long = "plugin")]
    plugin_ids: Vec<String>,
    #[arg(long)]
    no_analyze_binaries: bool,
    #[arg(long, value_enum, default_value_t = ProfileValue::Fast)]
    binary_profile: ProfileValue,
}

#[derive(Args)]
struct EvidenceGraphArgs {
    subject: String,
    #[arg(long, default_value_t = 2)]
    depth: usize,
    #[arg(long, default_value_t = 200)]
    limit: usize,
}

#[derive(Args)]
struct BriefArgs {
    query: String,
    #[arg(long, default_value_t = 12)]
    string_limit: usize,
    #[arg(long, default_value_t = 12)]
    function_limit: usize,
    #[arg(long, default_value_t = 6)]
    hot_function_limit: usize,
    #[arg(long, default_value_t = 24)]
    xref_limit: usize,
    #[arg(long, default_value_t = false)]
    no_pseudocode: bool,
}

#[derive(Args)]
struct InvestigateArgs {
    subject: String,
    #[arg(long)]
    path: Option<PathBuf>,
    #[arg(long)]
    no_pipeline: bool,
    #[arg(long, default_value_t = 4)]
    max_depth: usize,
    #[arg(long, default_value_t = 512)]
    max_children: usize,
    #[arg(long, default_value_t = 256)]
    object_limit: usize,
    #[arg(long, default_value_t = 2)]
    carve_max_depth: usize,
    #[arg(long, default_value_t = 512)]
    carve_max_children: usize,
    #[arg(long = "plugin")]
    plugin_ids: Vec<String>,
    #[arg(long)]
    no_analyze_binaries: bool,
    #[arg(long, value_enum, default_value_t = ProfileValue::Fast)]
    binary_profile: ProfileValue,
    #[arg(long, default_value_t = 3)]
    graph_depth: usize,
    #[arg(long, default_value_t = 300)]
    graph_limit: usize,
    #[arg(long)]
    trace_kind: Option<String>,
    #[arg(long, default_value_t = 50)]
    trace_limit: usize,
}

#[derive(Clone, Copy, ValueEnum)]
enum ProfileValue {
    Fast,
    Full,
}

#[derive(Clone, Copy, ValueEnum)]
enum ObjectKindValue {
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

#[derive(Clone, Copy, ValueEnum)]
enum ObjectAnalyzerValue {
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

impl From<ProfileValue> for AnalysisProfile {
    fn from(value: ProfileValue) -> Self {
        match value {
            ProfileValue::Fast => AnalysisProfile::Fast,
            ProfileValue::Full => AnalysisProfile::Full,
        }
    }
}

impl From<ObjectKindValue> for ObjectKind {
    fn from(value: ObjectKindValue) -> Self {
        match value {
            ObjectKindValue::File => ObjectKind::File,
            ObjectKindValue::Directory => ObjectKind::Directory,
            ObjectKindValue::Archive => ObjectKind::Archive,
            ObjectKindValue::Binary => ObjectKind::Binary,
            ObjectKindValue::Text => ObjectKind::Text,
            ObjectKindValue::Image => ObjectKind::Image,
            ObjectKindValue::Document => ObjectKind::Document,
            ObjectKindValue::Package => ObjectKind::Package,
            ObjectKindValue::FilesystemImage => ObjectKind::FilesystemImage,
            ObjectKindValue::MemoryDump => ObjectKind::MemoryDump,
            ObjectKindValue::NetworkCapture => ObjectKind::NetworkCapture,
            ObjectKindValue::Database => ObjectKind::Database,
            ObjectKindValue::Model => ObjectKind::Model,
            ObjectKindValue::Unknown => ObjectKind::Unknown,
        }
    }
}

impl From<ObjectAnalyzerValue> for ObjectAnalyzerKind {
    fn from(value: ObjectAnalyzerValue) -> Self {
        match value {
            ObjectAnalyzerValue::Auto => ObjectAnalyzerKind::Auto,
            ObjectAnalyzerValue::ByteHistogram => ObjectAnalyzerKind::ByteHistogram,
            ObjectAnalyzerValue::Strings => ObjectAnalyzerKind::Strings,
            ObjectAnalyzerValue::StructuredText => ObjectAnalyzerKind::StructuredText,
            ObjectAnalyzerValue::ZipListing => ObjectAnalyzerKind::ZipListing,
            ObjectAnalyzerValue::AndroidPackage => ObjectAnalyzerKind::AndroidPackage,
            ObjectAnalyzerValue::DexBytecode => ObjectAnalyzerKind::DexBytecode,
            ObjectAnalyzerValue::IosPackage => ObjectAnalyzerKind::IosPackage,
            ObjectAnalyzerValue::JavaArchive => ObjectAnalyzerKind::JavaArchive,
            ObjectAnalyzerValue::JvmClass => ObjectAnalyzerKind::JvmClass,
            ObjectAnalyzerValue::PythonBytecode => ObjectAnalyzerKind::PythonBytecode,
            ObjectAnalyzerValue::ShellLink => ObjectAnalyzerKind::ShellLink,
            ObjectAnalyzerValue::PortableExecutable => ObjectAnalyzerKind::PortableExecutable,
            ObjectAnalyzerValue::DotnetMetadata => ObjectAnalyzerKind::DotnetMetadata,
            ObjectAnalyzerValue::ElfBinary => ObjectAnalyzerKind::ElfBinary,
            ObjectAnalyzerValue::MachOBinary => ObjectAnalyzerKind::MachOBinary,
            ObjectAnalyzerValue::OpenXmlDocument => ObjectAnalyzerKind::OpenXmlDocument,
            ObjectAnalyzerValue::SqliteSchema => ObjectAnalyzerKind::SqliteSchema,
            ObjectAnalyzerValue::WasmModule => ObjectAnalyzerKind::WasmModule,
            ObjectAnalyzerValue::PdfDocument => ObjectAnalyzerKind::PdfDocument,
            ObjectAnalyzerValue::PngImage => ObjectAnalyzerKind::PngImage,
            ObjectAnalyzerValue::JpegImage => ObjectAnalyzerKind::JpegImage,
            ObjectAnalyzerValue::GifImage => ObjectAnalyzerKind::GifImage,
            ObjectAnalyzerValue::BmpImage => ObjectAnalyzerKind::BmpImage,
            ObjectAnalyzerValue::RiffContainer => ObjectAnalyzerKind::RiffContainer,
            ObjectAnalyzerValue::PcapCapture => ObjectAnalyzerKind::PcapCapture,
            ObjectAnalyzerValue::OleCompound => ObjectAnalyzerKind::OleCompound,
            ObjectAnalyzerValue::SafeTensorsModel => ObjectAnalyzerKind::SafeTensorsModel,
            ObjectAnalyzerValue::GgufModel => ObjectAnalyzerKind::GgufModel,
            ObjectAnalyzerValue::PyTorchModel => ObjectAnalyzerKind::PyTorchModel,
            ObjectAnalyzerValue::IsoBmff => ObjectAnalyzerKind::IsoBmff,
            ObjectAnalyzerValue::CabArchive => ObjectAnalyzerKind::CabArchive,
            ObjectAnalyzerValue::ArArchive => ObjectAnalyzerKind::ArArchive,
            ObjectAnalyzerValue::SevenZipArchive => ObjectAnalyzerKind::SevenZipArchive,
            ObjectAnalyzerValue::RarArchive => ObjectAnalyzerKind::RarArchive,
            ObjectAnalyzerValue::FontFile => ObjectAnalyzerKind::FontFile,
            ObjectAnalyzerValue::TiffImage => ObjectAnalyzerKind::TiffImage,
            ObjectAnalyzerValue::AudioMedia => ObjectAnalyzerKind::AudioMedia,
            ObjectAnalyzerValue::DiskImage => ObjectAnalyzerKind::DiskImage,
            ObjectAnalyzerValue::UnknownBlob => ObjectAnalyzerKind::UnknownBlob,
        }
    }
}

impl From<SearchModeValue> for ObjectContentSearchMode {
    fn from(value: SearchModeValue) -> Self {
        match value {
            SearchModeValue::Text => ObjectContentSearchMode::Text,
            SearchModeValue::Hex => ObjectContentSearchMode::Hex,
        }
    }
}

#[derive(Subcommand)]
enum SearchCommands {
    Text { pattern: String, #[arg(long, default_value_t = 200)] limit: usize, #[arg(long, default_value_t = 0)] offset: usize },
    Bytes { pattern: String },
    Objects(ObjectContentSearchArgs),
}

#[derive(Args)]
struct ObjectContentSearchArgs {
    pattern: String,
    #[arg(long, value_enum, default_value_t = SearchModeValue::Text)]
    mode: SearchModeValue,
    #[arg(long)]
    query: Option<String>,
    #[arg(long, default_value_t = 200)]
    limit: usize,
    #[arg(long, default_value_t = 20)]
    per_object_limit: usize,
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    max_object_bytes: usize,
}

#[derive(Clone, Copy, ValueEnum)]
enum SearchModeValue {
    Text,
    Hex,
}

#[derive(Subcommand)]
enum ArtifactCommands {
    Read(ArtifactReadArgs),
    List(ArtifactListArgs),
    Search(ArtifactSearchArgs),
}

#[derive(Args)]
struct ArtifactReadArgs {
    #[arg(long)]
    path: Option<String>,
    #[arg(long)]
    hash: Option<String>,
    #[arg(long, default_value_t = 0)]
    offset: u64,
    #[arg(long, default_value_t = 65536)]
    max_bytes: usize,
}

#[derive(Args)]
struct ArtifactListArgs {
    #[arg(long)]
    query: Option<String>,
    #[arg(long)]
    content_type: Option<String>,
    #[arg(long)]
    role: Option<String>,
    #[arg(long, default_value_t = 200)]
    limit: usize,
    #[arg(long)]
    include_unreferenced: bool,
}

#[derive(Args)]
struct ArtifactSearchArgs {
    query: String,
    #[arg(long)]
    content_type: Option<String>,
    #[arg(long)]
    role: Option<String>,
    #[arg(long, default_value_t = 200)]
    limit: usize,
    #[arg(long)]
    include_unreferenced: bool,
}

#[derive(Subcommand)]
enum TraceCommands {
    Import { file: PathBuf },
}

#[derive(Subcommand)]
enum SymbolicCommands {
    Solve { file: PathBuf },
}

#[derive(Subcommand)]
enum ReportCommands {
    Generate { topic: String },
}

#[derive(Subcommand)]
enum DaemonCommands {
    Start,
    Status,
    Stop,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum McpHost {
    Generic,
    Cursor,
    Claude,
    Codex,
}

#[derive(Subcommand)]
enum McpCommands {
    Serve {
        #[arg(long, short = 'C')]
        workspace: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        init: bool,
    },
    Doctor {
        #[arg(long, short = 'C')]
        workspace: Option<PathBuf>,
    },
    Config {
        #[arg(long, value_enum, default_value_t = McpHost::Generic)]
        host: McpHost,
        #[arg(long, short = 'C')]
        workspace: Option<PathBuf>,
        #[arg(long)]
        bin: Option<PathBuf>,
    },
    Install {
        #[arg(long)]
        prefix: Option<PathBuf>,
        #[arg(long, short = 'C')]
        workspace: Option<PathBuf>,
        #[arg(long, value_enum)]
        host: Vec<McpHost>,
        #[arg(long, default_value_t = false)]
        write_config: bool,
        #[arg(long, default_value_t = false)]
        init_workspace: bool,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    if std::env::var_os("RUST_LOG").is_some() || std::env::var_os("REVX_TRACE").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .init();
    }
    let cli = Cli::parse();

    match cli.command {
        Command::Init { path } => cmd_init(&path),
        Command::Object(ObjectCommands::Identify(args)) => cmd_object_identify(&args).await,
        Command::Object(ObjectCommands::Search(args)) => cmd_object_search(&args).await,
        Command::Object(ObjectCommands::Profile(args)) => cmd_object_profile(&args).await,
        Command::Object(ObjectCommands::Materialize(args)) => cmd_object_materialize(&args).await,
        Command::Object(ObjectCommands::ExtractRange(args)) => {
            cmd_object_extract_range(&args).await
        }
        Command::Object(ObjectCommands::ScanSignatures(args)) => {
            cmd_object_scan_signatures(&args).await
        }
        Command::Object(ObjectCommands::CarveSignatures(args)) => {
            cmd_object_carve_signatures(&args).await
        }
        Command::Object(ObjectCommands::CarveIdentify(args)) => {
            cmd_object_carve_identify(&args).await
        }
        Command::Object(ObjectCommands::Analyze(args)) => cmd_object_analyze(&args).await,
        Command::Object(ObjectCommands::Plugins) => cmd_object_plugins().await,
        Command::Object(ObjectCommands::PluginRun(args)) => cmd_object_plugin_run(&args).await,
        Command::Object(ObjectCommands::RegisterBinary(args)) => {
            cmd_object_register_binary(&args).await
        }
        Command::Object(ObjectCommands::AnalyzeBinary(args)) => {
            cmd_object_analyze_binary(&args).await
        }
        Command::Object(ObjectCommands::Pipeline(args)) => cmd_object_pipeline(&args).await,
        Command::Add { path } => cmd_add(&path),
        Command::Analyze(args) => cmd_analyze(&args).await,
        Command::Status => cmd_status().await,
        Command::Survey => cmd_survey().await,
        Command::Funcs(args) => cmd_funcs(&args).await,
        Command::Func { query } => cmd_func(&query).await,
        Command::Decompile {
            query,
            strategy,
            force_refresh,
        } => cmd_decompile(&query, strategy, force_refresh).await,
        Command::DecompileCache { query } => cmd_decompile_cache(&query).await,
        Command::Disasm { query } => cmd_disasm(&query).await,
        Command::Xrefs { target } => cmd_xrefs(&target).await,
        Command::Strings(args) => cmd_strings(&args).await,
        Command::Search(SearchCommands::Text { pattern, limit, offset }) => cmd_search_text(&pattern, limit, offset).await,
        Command::Search(SearchCommands::Bytes { pattern }) => cmd_search_bytes(&pattern).await,
        Command::Search(SearchCommands::Objects(args)) => cmd_search_objects(&args).await,
        Command::Artifact(ArtifactCommands::Read(args)) => cmd_artifact_read(&args).await,
        Command::Artifact(ArtifactCommands::List(args)) => cmd_artifact_list(&args).await,
        Command::Artifact(ArtifactCommands::Search(args)) => cmd_artifact_search(&args).await,
        Command::Evidence { subject } => cmd_evidence(&subject).await,
        Command::EvidenceGraph(args) => cmd_evidence_graph(&args).await,
        Command::Brief(args) => cmd_brief(&args).await,
        Command::Investigate(args) => cmd_investigate(&args).await,
        Command::Symbolic(SymbolicCommands::Solve { file }) => cmd_symbolic_solve(&file).await,
        Command::Report(ReportCommands::Generate { topic }) => cmd_report_generate(&topic).await,
        Command::Trace(TraceCommands::Import { file }) => cmd_trace_import(&file).await,
        Command::Daemon(DaemonCommands::Start) => cmd_daemon_start().await,
        Command::Daemon(DaemonCommands::Status) => cmd_daemon_status(),
        Command::Daemon(DaemonCommands::Stop) => cmd_daemon_stop(),
        Command::Mcp(McpCommands::Serve { workspace, init }) => {
            cmd_mcp_serve(workspace, init).await
        }
        Command::Mcp(McpCommands::Doctor { workspace }) => cmd_mcp_doctor(workspace),
        Command::Mcp(McpCommands::Config {
            host,
            workspace,
            bin,
        }) => cmd_mcp_config(host, workspace, bin),
        Command::Mcp(McpCommands::Install {
            prefix,
            workspace,
            host,
            write_config,
            init_workspace,
        }) => cmd_mcp_install(prefix, workspace, host, write_config, init_workspace),
    }
}

fn cmd_init(path: &Path) -> Result<()> {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "revx-project".to_string());
    Workspace::init(path, &name, None)?;
    println!(
        "Initialized revx workspace at {}",
        path.join(".revx").display()
    );
    Ok(())
}

fn cmd_add(path: &Path) -> Result<()> {
    let ws = workspace_from_cwd()?;
    let image = load_binary(path)?;
    let survey = ws.register_binary(&image)?;
    println!("{}", serde_json::to_string_pretty(&survey)?);
    Ok(())
}


fn cmd_analyze_micro(path: &std::path::Path) -> Result<()> {
    let micro = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("revx-micro")))
        .filter(|p| p.exists())
        .unwrap_or_else(|| std::path::PathBuf::from("revx-micro"));
    let status = std::process::Command::new(&micro)
        .arg("analyze")
        .arg(path)
        .status()
        .with_context(|| format!("failed to spawn {}", micro.display()))?;
    if !status.success() {
        anyhow::bail!("revx-micro failed with {status}");
    }
    Ok(())
}

async fn cmd_analyze(args: &AnalyzeArgs) -> Result<()> {
    if args.micro {
        return cmd_analyze_micro(&args.path);
    }
    let response = dispatch_from_cwd(CapabilityRequest::AnalysisRun(
        revx_core::AnalysisRunRequest {
            binary_path: args.path.display().to_string(),
            profile: args.profile.into(),
        },
    ))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_status() -> Result<()> {
    let response =
        dispatch_from_cwd(CapabilityRequest::ProjectStatus(ProjectStatusRequest)).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_object_identify(args: &ObjectIdentifyArgs) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::ObjectIdentify(
        revx_core::ObjectIdentifyRequest {
            path: args.path.display().to_string(),
            max_depth: Some(args.max_depth),
            max_children: Some(args.max_children),
            include_graph: Some(!args.no_graph),
        },
    ))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_object_search(args: &ObjectSearchArgs) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::ObjectSearch(ObjectSearchRequest {
        query: args.query.clone(),
        kind: args.kind.map(ObjectKind::from),
        limit: Some(args.limit),
    }))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_object_profile(args: &ObjectProfileArgs) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::ObjectProfile(ObjectProfileRequest {
        query: args.query.clone(),
    }))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_object_materialize(args: &ObjectMaterializeArgs) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::ObjectMaterialize(
        ObjectMaterializeRequest {
            query: args.query.clone(),
            preview_bytes: Some(args.preview_bytes),
        },
    ))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_object_extract_range(args: &ObjectExtractRangeArgs) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::ObjectExtractRange(
        ObjectExtractRangeRequest {
            query: args.query.clone(),
            offset: args.offset,
            length: args.length,
            context_bytes: Some(args.context_bytes),
            preview_bytes: Some(args.preview_bytes),
        },
    ))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_object_scan_signatures(args: &ObjectSignatureScanArgs) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::ObjectSignatureScan(
        ObjectSignatureScanRequest {
            query: args.query.clone(),
            limit: Some(args.limit),
            max_object_bytes: Some(args.max_object_bytes),
            preview_bytes: Some(args.preview_bytes),
        },
    ))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_object_carve_signatures(args: &ObjectCarveSignaturesArgs) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::ObjectCarveSignatures(
        ObjectCarveSignaturesRequest {
            query: args.query.clone(),
            limit: Some(args.limit),
            max_object_bytes: Some(args.max_object_bytes),
            max_carve_bytes: Some(args.max_carve_bytes),
            min_confidence: Some(args.min_confidence),
            preview_bytes: Some(args.preview_bytes),
        },
    ))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_object_carve_identify(args: &ObjectCarveIdentifyArgs) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::ObjectCarveIdentify(
        ObjectCarveIdentifyRequest {
            query: args.query.clone(),
            limit: Some(args.limit),
            max_object_bytes: Some(args.max_object_bytes),
            max_carve_bytes: Some(args.max_carve_bytes),
            min_confidence: Some(args.min_confidence),
            preview_bytes: Some(args.preview_bytes),
            max_depth: Some(args.max_depth),
            max_children: Some(args.max_children),
        },
    ))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_object_analyze(args: &ObjectAnalyzeArgs) -> Result<()> {
    let analyzers = (!args.analyzers.is_empty()).then(|| {
        args.analyzers
            .iter()
            .copied()
            .map(ObjectAnalyzerKind::from)
            .collect()
    });
    let response = dispatch_from_cwd(CapabilityRequest::ObjectAnalyze(ObjectAnalyzeRequest {
        query: args.query.clone(),
        analyzers,
    }))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_object_plugins() -> Result<()> {
    let response =
        dispatch_from_cwd(CapabilityRequest::ObjectPluginList(ObjectPluginListRequest)).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_object_plugin_run(args: &ObjectPluginRunArgs) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::ObjectPluginRun(ObjectPluginRunRequest {
        plugin_id: args.plugin_id.clone(),
        query: args.query.clone(),
        timeout_ms: args.timeout_ms,
    }))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_object_register_binary(args: &ObjectRegisterBinaryArgs) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::ObjectRegisterBinary(
        ObjectRegisterBinaryRequest {
            query: args.query.clone(),
        },
    ))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_object_analyze_binary(args: &ObjectAnalyzeBinaryArgs) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::ObjectAnalyzeBinary(
        ObjectAnalyzeBinaryRequest {
            query: args.query.clone(),
            profile: args.profile.into(),
        },
    ))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_object_pipeline(args: &ObjectPipelineArgs) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::ObjectPipeline(ObjectPipelineRequest {
        path: args.path.display().to_string(),
        max_depth: Some(args.max_depth),
        max_children: Some(args.max_children),
        object_limit: Some(args.object_limit),
        analyze_objects: Some(!args.no_analyze_objects),
        carve_embedded: Some(!args.no_carve_embedded),
        carve_limit: Some(args.carve_limit),
        max_carve_object_bytes: Some(args.max_carve_object_bytes),
        max_carve_bytes: Some(args.max_carve_bytes),
        min_carve_confidence: Some(args.min_carve_confidence),
        carve_max_depth: Some(args.carve_max_depth),
        carve_max_children: Some(args.carve_max_children),
        plugin_ids: (!args.plugin_ids.is_empty()).then(|| args.plugin_ids.clone()),
        analyze_binaries: Some(!args.no_analyze_binaries),
        binary_profile: Some(args.binary_profile.into()),
    }))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_survey() -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::BinarySurvey(BinarySurveyRequest {
        binary_id: None,
    }))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_funcs(args: &FuncsArgs) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::FunctionSearch(FunctionSearchRequest {
        query: String::new(),
        limit: Some(args.limit),
        offset: Some(args.offset),
    }))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_func(query: &str) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::FunctionProfile(FunctionProfileRequest {
        query: query.to_string(),
    }))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn parse_decompile_strategy(raw: &str) -> std::result::Result<DecompileStrategy, String> {
    DecompileStrategy::parse(raw).ok_or_else(|| format!("unknown decompile strategy: {raw}"))
}

async fn cmd_decompile(
    query: &str,
    strategy: Option<DecompileStrategy>,
    force_refresh: bool,
) -> Result<()> {
    let response =
        dispatch_from_cwd(CapabilityRequest::DecompileFunction(DecompileFunctionRequest {
            query: query.to_string(),
            strategy,
            force_refresh: Some(force_refresh),
        }))
        .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_decompile_cache(query: &str) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::DecompileCacheStatus(
        DecompileCacheStatusRequest {
            query: query.to_string(),
        },
    ))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_disasm(query: &str) -> Result<()> {
    let response =
        dispatch_from_cwd(CapabilityRequest::DisassembleFunction(DisassembleFunctionRequest {
            query: query.to_string(),
        }))
        .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_xrefs(target: &str) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::XrefsQuery(XrefsQueryRequest {
        query: target.to_string(),
    }))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_strings(args: &StringsArgs) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::StringSearch(StringSearchRequest {
        pattern: String::new(),
        limit: Some(args.limit),
        offset: Some(args.offset),
    }))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_search_text(pattern: &str, limit: usize, offset: usize) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::StringSearch(StringSearchRequest {
        pattern: pattern.to_string(),
        limit: Some(limit),
        offset: Some(offset),
    }))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_search_bytes(pattern: &str) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::SearchBytes(SearchBytesRequest {
        pattern: pattern.to_string(),
    }))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_search_objects(args: &ObjectContentSearchArgs) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::ObjectContentSearch(
        ObjectContentSearchRequest {
            pattern: args.pattern.clone(),
            mode: Some(ObjectContentSearchMode::from(args.mode)),
            query: args.query.clone(),
            limit: Some(args.limit),
            per_object_limit: Some(args.per_object_limit),
            max_object_bytes: Some(args.max_object_bytes),
        },
    ))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_artifact_read(args: &ArtifactReadArgs) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::ArtifactRead(ArtifactReadRequest {
        relative_path: args.path.clone(),
        hash_blake3: args.hash.clone(),
        offset: Some(args.offset),
        max_bytes: Some(args.max_bytes),
    }))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_artifact_list(args: &ArtifactListArgs) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::ArtifactList(ArtifactListRequest {
        query: args.query.clone(),
        content_type: args.content_type.clone(),
        role: args.role.clone(),
        limit: Some(args.limit),
        include_unreferenced: Some(args.include_unreferenced),
    }))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_artifact_search(args: &ArtifactSearchArgs) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::ArtifactList(ArtifactListRequest {
        query: Some(args.query.clone()),
        content_type: args.content_type.clone(),
        role: args.role.clone(),
        limit: Some(args.limit),
        include_unreferenced: Some(args.include_unreferenced),
    }))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_evidence(subject: &str) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::EvidencePack(EvidencePackRequest {
        subject: subject.to_string(),
    }))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_evidence_graph(args: &EvidenceGraphArgs) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::EvidenceGraph(EvidenceGraphRequest {
        subject: args.subject.clone(),
        depth: Some(args.depth),
        limit: Some(args.limit),
    }))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_brief(args: &BriefArgs) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::AnalysisBrief(AnalysisBriefRequest {
        query: args.query.clone(),
        string_limit: Some(args.string_limit),
        function_limit: Some(args.function_limit),
        hot_function_limit: Some(args.hot_function_limit),
        xref_limit: Some(args.xref_limit),
        include_pseudocode: Some(!args.no_pseudocode),
    }))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_investigate(args: &InvestigateArgs) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::InvestigationRun(
        InvestigationRunRequest {
            subject: args.subject.clone(),
            path: args.path.as_ref().map(|path| path.display().to_string()),
            run_object_pipeline: Some(!args.no_pipeline && args.path.is_some()),
            max_depth: Some(args.max_depth),
            max_children: Some(args.max_children),
            object_limit: Some(args.object_limit),
            carve_max_depth: Some(args.carve_max_depth),
            carve_max_children: Some(args.carve_max_children),
            plugin_ids: (!args.plugin_ids.is_empty()).then(|| args.plugin_ids.clone()),
            analyze_binaries: Some(!args.no_analyze_binaries),
            binary_profile: Some(args.binary_profile.into()),
            graph_depth: Some(args.graph_depth),
            graph_limit: Some(args.graph_limit),
            trace_kind: args.trace_kind.clone(),
            trace_limit: Some(args.trace_limit),
        },
    ))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_symbolic_solve(file: &Path) -> Result<()> {
    let raw = fs::read_to_string(file)?;
    let request: SymbolicSolveRequest = serde_json::from_str(&raw)?;
    let response = dispatch_from_cwd(CapabilityRequest::SymbolicSolve(request)).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_report_generate(topic: &str) -> Result<()> {
    let response = dispatch_from_cwd(CapabilityRequest::ReportGenerate(ReportGenerateRequest {
        topic: topic.to_string(),
    }))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_trace_import(file: &Path) -> Result<()> {
    let raw = fs::read_to_string(file)?;
    let events: Vec<revx_core::TraceEvent> = serde_json::from_str(&raw)?;
    let response = dispatch_from_cwd(CapabilityRequest::TraceImport(TraceImportRequest {
        events,
    }))
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn cmd_daemon_start() -> Result<()> {
    let workspace_dir = workspace_parent_from_cwd()?;
    serve_ipc(workspace_dir).await
}

fn cmd_daemon_status() -> Result<()> {
    let workspace_dir = workspace_parent_from_cwd()?;
    let socket = socket_path(&workspace_dir);
    println!(
        "{}",
        serde_json::json!({
            "workspace_root": workspace_dir.display().to_string(),
            "ipc_path": socket.display().to_string(),
            "available": socket.exists(),
        })
    );
    Ok(())
}

fn cmd_daemon_stop() -> Result<()> {
    let workspace_dir = workspace_parent_from_cwd()?;
    let socket = socket_path(&workspace_dir);
    if socket.exists() {
        fs::remove_file(&socket)
            .with_context(|| format!("failed to remove {}", socket.display()))?;
        println!("Removed daemon socket {}", socket.display());
    } else {
        println!("No daemon socket present at {}", socket.display());
    }
    Ok(())
}

async fn cmd_mcp_serve(workspace: Option<PathBuf>, init: bool) -> Result<()> {
    let project = resolve_mcp_project_root(workspace, init)?;
    serve_mcp_stdio(project).await
}

fn cmd_mcp_doctor(workspace: Option<PathBuf>) -> Result<()> {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("revx-engine"));
    println!("revx-engine: {}", exe.display());
    println!("version: {}", env!("CARGO_PKG_VERSION"));
    match resolve_mcp_project_root(workspace, false) {
        Ok(project) => {
            let revx = project.join(".revx");
            println!("workspace: {}", project.display());
            println!("revx_dir: {}", revx.display());
            println!("project_toml: {}", revx.join("project.toml").exists());
            println!("state_sqlite: {}", revx.join("state.sqlite").exists());
            match Workspace::open(&project) {
                Ok(ws) => match ws.project_config() {
                    Ok(cfg) => {
                        println!("schema_version: {}", cfg.schema_version);
                        println!("project_name: {}", cfg.name);
                        println!("status: ok");
                    }
                    Err(err) => {
                        println!("status: workspace_open_ok_config_error");
                        println!("error: {err:#}");
                    }
                },
                Err(err) => {
                    println!("status: workspace_error");
                    println!("error: {err:#}");
                }
            }
        }
        Err(err) => {
            println!("workspace: unresolved");
            println!("status: missing_workspace");
            println!("error: {err:#}");
            println!("hint: revx-engine mcp serve --workspace <path> --init");
        }
    }
    Ok(())
}

fn cmd_mcp_config(
    host: McpHost,
    workspace: Option<PathBuf>,
    bin: Option<PathBuf>,
) -> Result<()> {
    let engine = resolve_engine_bin(bin)?;
    let project = match workspace {
        Some(path) => canonicalize_path(&path)?,
        None => match resolve_mcp_project_root(None, false) {
            Ok(path) => path,
            Err(_) => std::env::current_dir()?,
        },
    };
    print!("{}", render_mcp_host_config(host, &engine, &project));
    Ok(())
}

fn cmd_mcp_install(
    prefix: Option<PathBuf>,
    workspace: Option<PathBuf>,
    hosts: Vec<McpHost>,
    write_config: bool,
    init_workspace: bool,
) -> Result<()> {
    let prefix = expand_user_path(prefix.unwrap_or_else(default_install_prefix))?;
    let bin_dir = prefix.join("bin");
    let conf_dir = prefix.join("share/revx/mcp");
    fs::create_dir_all(&bin_dir)?;
    fs::create_dir_all(&conf_dir)?;

    let current = std::env::current_exe().context("failed to resolve current executable")?;
    let engine_dst = bin_dir.join("revx-engine");
    let same = current
        .canonicalize()
        .ok()
        .zip(engine_dst.canonicalize().ok())
        .map(|(a, b)| a == b)
        .unwrap_or(false);
    if !same {
        fs::copy(&current, &engine_dst).with_context(|| {
            format!(
                "failed to install {} -> {}",
                current.display(),
                engine_dst.display()
            )
        })?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&engine_dst)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&engine_dst, perms)?;
    }

    let project = resolve_mcp_project_root(workspace, init_workspace).unwrap_or_else(|_| {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    });
    if init_workspace && !project.join(".revx").exists() {
        let _ = resolve_mcp_project_root(Some(project.clone()), true)?;
    }

    let host_list = if hosts.is_empty() {
        vec![
            McpHost::Generic,
            McpHost::Cursor,
            McpHost::Claude,
            McpHost::Codex,
        ]
    } else {
        hosts
    };

    println!("installed: {}", engine_dst.display());
    println!("workspace: {}", project.display());

    for host in host_list {
        let body = render_mcp_host_config(host, &engine_dst, &project);
        let name = match host {
            McpHost::Generic => "generic.mcp.json",
            McpHost::Cursor => "cursor.mcp.json",
            McpHost::Claude => "claude_desktop.mcp.json",
            McpHost::Codex => "codex.mcp.json",
        };
        let path = conf_dir.join(name);
        if write_config {
            fs::write(&path, &body)?;
            println!("config: {}", path.display());
        } else {
            println!("--- {} ---", name);
            print!("{body}");
        }
    }

    println!("serve: {} mcp serve --workspace {}", engine_dst.display(), project.display());
    println!("doctor: {} mcp doctor --workspace {}", engine_dst.display(), project.display());
    Ok(())
}

fn default_install_prefix() -> PathBuf {
    home_dir()
        .map(|h| h.join(".local"))
        .unwrap_or_else(|| PathBuf::from(".revx-install"))
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
}

fn expand_user_path(path: PathBuf) -> Result<PathBuf> {
    let raw = path.to_string_lossy();
    if raw == "~" {
        return home_dir().context("HOME not set");
    }
    if let Some(rest) = raw.strip_prefix("~/") {
        let home = home_dir().context("HOME not set")?;
        return Ok(home.join(rest));
    }
    Ok(path)
}

fn resolve_engine_bin(bin: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = bin {
        return canonicalize_path(&path);
    }
    if let Some(path) = std::env::var_os("REVX_ENGINE") {
        return canonicalize_path(Path::new(&path));
    }
    if let Ok(path) = std::env::current_exe() {
        return canonicalize_path(&path);
    }
    Ok(PathBuf::from("revx-engine"))
}

fn canonicalize_path(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        return path
            .canonicalize()
            .with_context(|| format!("failed to canonicalize {}", path.display()));
    }
    Ok(path.to_path_buf())
}

fn resolve_mcp_project_root(workspace: Option<PathBuf>, init: bool) -> Result<PathBuf> {
    let project = if let Some(path) = workspace {
        let path = expand_user_path(path)?;
        if path.join(".revx").exists() {
            canonicalize_path(&path)?
        } else if path.file_name().and_then(|s| s.to_str()) == Some(".revx") {
            path.parent()
                .map(|p| p.to_path_buf())
                .context("invalid .revx path")?
        } else {
            path
        }
    } else {
        match workspace_parent_from_cwd() {
            Ok(path) => path,
            Err(_) => std::env::current_dir()?,
        }
    };

    let project = if project.exists() {
        canonicalize_path(&project).unwrap_or(project)
    } else {
        project
    };

    if init && !project.join(".revx").exists() {
        fs::create_dir_all(&project)?;
        let name = project
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "revx-project".to_string());
        Workspace::init(&project, &name, None)?;
    }

    if !project.join(".revx").exists() {
        anyhow::bail!(
            "no revx workspace at {} (missing .revx). Use --workspace and/or --init",
            project.display()
        );
    }
    Ok(project)
}

fn render_mcp_host_config(host: McpHost, engine: &Path, workspace: &Path) -> String {
    let engine_s = engine.display().to_string();
    let workspace_s = workspace.display().to_string();
    match host {
        McpHost::Generic | McpHost::Codex => serde_json::json!({
            "mcpServers": {
                "revx": {
                    "command": engine_s,
                    "args": ["mcp", "serve", "--workspace", workspace_s],
                }
            }
        })
        .to_string()
            + "
",
        McpHost::Cursor => serde_json::json!({
            "mcpServers": {
                "revx": {
                    "command": engine_s,
                    "args": ["mcp", "serve", "--workspace", workspace_s]
                }
            }
        })
        .to_string()
            + "
",
        McpHost::Claude => serde_json::json!({
            "mcpServers": {
                "revx": {
                    "command": engine_s,
                    "args": ["mcp", "serve", "--workspace", workspace_s]
                }
            }
        })
        .to_string()
            + "
",
    }
}

fn workspace_from_cwd() -> Result<Workspace> {
    let cwd = std::env::current_dir()?;
    let mut dir = cwd.as_path();
    loop {
        if dir.join(".revx").exists() {
            return Workspace::open(dir);
        }
        match dir.parent() {
            Some(parent) if parent != dir => dir = parent,
            _ => break,
        }
    }
    anyhow::bail!("no revx workspace in {} or parents", cwd.display())
}

fn workspace_parent_from_cwd() -> Result<PathBuf> {
    let ws = workspace_from_cwd()?;
    Ok(ws
        .root()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(".")))
}

fn local_service_for_cwd() -> Result<CapabilityService> {
    Ok(CapabilityService::new(workspace_parent_from_cwd()?))
}

fn parse_u64_cli(value: &str) -> std::result::Result<u64, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("expected an integer".to_string());
    }
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).map_err(|err| err.to_string())
    } else {
        trimmed.parse::<u64>().map_err(|err| err.to_string())
    }
}

async fn dispatch_from_cwd(request: CapabilityRequest) -> Result<revx_core::CapabilityResponse> {
    let workspace_root = workspace_parent_from_cwd()?;
    let ipc_path = socket_path(&workspace_root);
    if ipc_path.exists() {
        send_ipc_request(&workspace_root, request).await
    } else {
        local_service_for_cwd()?.dispatch(request)
    }
}
