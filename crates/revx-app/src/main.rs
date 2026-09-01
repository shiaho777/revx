use revx_query::QueryWorkspace;
use serde_json::json;
use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

mod ghidra_bridge;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help" | "help") {
        print_help();
        return Ok(());
    }
    if matches!(args[0].as_str(), "-V" | "--version") {
        println!("revx {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    match args[0].as_str() {
        "init" => {
            let path = args
                .get(1)
                .map(PathBuf::from)
                .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            cmd_init(&path)
        }
        "status" => cmd_status(),
        "survey" => cmd_survey(parse_opt_flag(&args[1..], "--binary-id")),
        "funcs" => {
            let limit = parse_usize_flag(&args[1..], "--limit", 200);
            let offset = parse_usize_flag(&args[1..], "--offset", 0);
            let query = free_args(&args[1..]).into_iter().next().unwrap_or_default();
            cmd_funcs(&query, limit, offset)
        }
        "strings" => {
            let limit = parse_usize_flag(&args[1..], "--limit", 200);
            let offset = parse_usize_flag(&args[1..], "--offset", 0);
            let pattern = free_args(&args[1..]).into_iter().next().unwrap_or_default();
            cmd_strings(&pattern, limit, offset)
        }
        "xrefs" => {
            let target = args
                .get(1)
                .cloned()
                .ok_or_else(|| "usage: revx xrefs <target>".to_string())?;
            cmd_xrefs(&target)
        }
        "func" => {
            let query = args
                .get(1)
                .cloned()
                .ok_or_else(|| "usage: revx func <query>".to_string())?;
            cmd_func(&query)
        }
        "decompile" => {
            let query = args
                .get(1)
                .cloned()
                .ok_or_else(|| "usage: revx decompile <query>".to_string())?;
            let engine = parse_opt_flag(&args[1..], "--engine");
            cmd_decompile(&query, engine.as_deref())
        }
        "disasm" => {
            let query = args
                .get(1)
                .cloned()
                .ok_or_else(|| "usage: revx disasm <query>".to_string())?;
            cmd_disasm(&query)
        }
        "il2cpp-scan" => {
            let path = free_args(&args[1..])
                .into_iter()
                .next()
                .ok_or_else(|| "usage: revx il2cpp-scan <path>".to_string())?;
            cmd_il2cpp_scan(Path::new(&path))
        }
        "export-offsets" => {
            let binary = parse_opt_flag(&args[1..], "--binary")
                .or_else(|| free_args(&args[1..]).into_iter().next())
                .ok_or_else(|| {
                    "usage: revx export-offsets --binary <path-or-id> [--out FILE]".to_string()
                })?;
            let out = parse_opt_flag(&args[1..], "--out").map(PathBuf::from);
            cmd_export_offsets(&binary, out.as_deref())
        }
        "analyze" => {
            if args.iter().any(|a| a == "--micro") {
                let path = free_args(&args[1..])
                    .into_iter()
                    .next()
                    .ok_or_else(|| "usage: revx analyze --micro <path>".to_string())?;
                return cmd_analyze_micro(Path::new(&path));
            }
            forward_to_engine(&args)
        }
        "search" if args.get(1).map(|s| s.as_str()) == Some("text") => {
            let rest = &args[2..];
            let limit = parse_usize_flag(rest, "--limit", 200);
            let offset = parse_usize_flag(rest, "--offset", 0);
            let pattern = free_args(rest)
                .into_iter()
                .next()
                .ok_or_else(|| "usage: revx search text <pattern>".to_string())?;
            cmd_strings(&pattern, limit, offset)
        }
        _ => forward_to_engine(&args),
    }
}

fn print_help() {
    print!(
        "\
revx {version}
thin reverse-engineering CLI

LIGHT:
  init [path]
  status
  survey [--binary-id ID]
  funcs [--limit N] [--offset N] [query]
  strings [--limit N] [--offset N] [pattern]
  search text <pattern>
  xrefs <target>
  func <query>
  decompile <query>
  disasm <query>
  analyze --micro <path>
  il2cpp-scan <path>
  export-offsets --binary <path-or-id> [--out FILE]

ENGINE (spawns revx-engine):
  analyze, add, object, ...
",
        version = env!("CARGO_PKG_VERSION")
    );
}

fn cmd_init(path: &Path) -> Result<(), String> {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "revx-project".to_string());
    QueryWorkspace::init(path, &name).map_err(|e| e.to_string())?;
    println!(
        "Initialized revx workspace at {}",
        path.join(".revx").display()
    );
    Ok(())
}

fn cmd_status() -> Result<(), String> {
    let ws = workspace_from_cwd()?;
    let project = ws.project_config().map_err(|e| e.to_string())?;
    let binaries = ws.binary_record_list().map_err(|e| e.to_string())?;
    let response = json!({
        "workspace_root": ws.root().display().to_string(),
        "project": project,
        "binary_count": binaries.len(),
        "binaries": binaries,
    });
    print_json(&response)
}

fn cmd_survey(binary_id: Option<String>) -> Result<(), String> {
    let ws = workspace_from_cwd()?;
    let survey = ws
        .survey_preview(binary_id.as_deref())
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "survey not found".to_string())?;
    let response = json!({
        "preview": survey.summary,
        "survey": null,
        "evidence_count": survey.evidence_count,
        "evidence_ids": survey.evidence_ids,
        "evidence_artifact": null,
        "artifact": survey.artifact,
    });
    print_json(&response)
}

fn cmd_funcs(query: &str, limit: usize, offset: usize) -> Result<(), String> {
    let ws = workspace_from_cwd()?;
    let functions = ws
        .search_functions_paged(query, limit, offset)
        .map_err(|e| e.to_string())?;
    print_json(&json!({ "functions": functions }))
}

fn cmd_strings(pattern: &str, limit: usize, offset: usize) -> Result<(), String> {
    let ws = workspace_from_cwd()?;
    let matches = ws
        .search_strings_paged(pattern, limit, offset)
        .map_err(|e| e.to_string())?;
    print_json(&json!({ "matches": matches, "agent_brief": {
        "headline": "",
        "key_findings": [],
        "open_questions": [],
        "next_actions": [],
        "stop_conditions": [],
    }}))
}

fn cmd_xrefs(target: &str) -> Result<(), String> {
    let ws = workspace_from_cwd()?;
    let refs = ws.find_references(target).map_err(|e| e.to_string())?;
    print_json(&json!({ "references": refs }))
}

fn cmd_il2cpp_scan(path: &Path) -> Result<(), String> {
    let image = revx_loader::load_binary(path).map_err(|e| e.to_string())?;
    let api_exports = revx_loader::il2cpp_code::il2cpp_api_exports(&image).len();
    let scan = revx_loader::il2cpp_code::scan_reloc_tables(&image);
    let mut tables_total = 0usize;
    let mut entries_total = 0usize;
    let mut sample: Vec<u64> = Vec::new();
    let mut entries_by_table: Vec<u64> = Vec::new();
    if let Some(scan) = scan.as_ref() {
        tables_total = scan.tables.len();
        entries_total = scan.entries.len();
        entries_by_table = scan.tables.iter().map(|(_, c)| *c as u64).collect();
        entries_by_table.sort_unstable();
        entries_by_table.reverse();
        sample = scan
            .entries
            .iter()
            .take(4)
            .map(|(_, target)| *target)
            .collect();
    }
    print_json(&json!({
        "binary": image.path,
        "architecture": format!("{:?}", image.architecture),
        "relocations": image.relocations.len(),
        "il2cpp_api_exports": api_exports,
        "method_pointer_tables": tables_total,
        "method_entries": entries_total,
        "largest_tables": entries_by_table.into_iter().take(8).collect::<Vec<_>>(),
        "sample_entry_addresses": sample,
        "metadata_candidates": revx_loader::il2cpp::metadata_candidates(path)
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>(),
    }))
}

/// Resolve --binary (path or workspace binary id) to a workspace record.
fn resolve_binary_record(
    ws: &QueryWorkspace,
    binary: &str,
) -> Result<(String, String, Option<String>), String> {
    let records = ws.binary_record_list().map_err(|e| e.to_string())?;
    let matches: Vec<_> = records
        .iter()
        .filter(|r| r.id == binary || r.path == binary)
        .collect();
    if let Some(record) = matches.first() {
        return Ok((
            record.id.clone(),
            record.path.clone(),
            record.last_analysis_at.clone(),
        ));
    }
    let suffix_match = records
        .iter()
        .filter(|r| r.path.ends_with(binary))
        .collect::<Vec<_>>();
    if let Some(record) = suffix_match.first() {
        return Ok((
            record.id.clone(),
            record.path.clone(),
            record.last_analysis_at.clone(),
        ));
    }
    Err(format!(
        "binary not found in workspace: {binary} (run `revx analyze` first)"
    ))
}

/// `revx export-offsets`: emit the esp-offsets (format=esp-offsets, version=1)
/// table consumed by esp-overlay's OffsetTable. Classes/fields come from the
/// workspace types table (il2cpp metadata enrichment); method addresses come
/// from the reloc-scan of the target image; globals are not yet derivable and
/// stay empty until a real global-metadata ground truth lands.
fn cmd_export_offsets(binary: &str, out: Option<&std::path::Path>) -> Result<(), String> {
    let ws = workspace_from_cwd()?;
    let (binary_id, binary_path, last_analysis_at) = resolve_binary_record(&ws, binary)?;

    // Classes + fields from persisted il2cpp types. Field names are stored as
    // "Type.field"; class statics offsets are not yet in the DB, so tables
    // carry fields only.
    let mut classes: BTreeMap<String, Vec<(String, u64, Option<String>)>> = BTreeMap::new();
    let mut warning: Option<String> = None;
    let rows = ws.offset_type_rows(&binary_id).map_err(|e| e.to_string())?;
    if rows.is_empty() {
        warning = Some(
            "no il2cpp types in workspace for this binary (analysis ran lean/micro or global-metadata.dat missing); classes empty".to_string(),
        );
    }
    for row in rows {
        match row.kind.as_str() {
            "il2cpp_class" => {
                classes.entry(row.name).or_default();
            }
            "il2cpp_field" => {
                if let Some((class, field)) = row.name.split_once('.') {
                    classes.entry(class.to_string()).or_default().push((
                        field.to_string(),
                        0,
                        None,
                    ));
                }
            }
            _ => {}
        }
    }

    // Method addresses from the reloc scan of the image itself (still valid
    // offline; the scan does not need the workspace).
    let image = revx_loader::load_binary(Path::new(&binary_path)).map_err(|e| e.to_string())?;
    let mut methods: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    if let Some(scan) = revx_loader::il2cpp_code::scan_reloc_tables(&image)
        && let Some((table, count)) = scan.tables.iter().max_by_key(|(_, c)| *c).copied()
    {
        for (index, address) in
            revx_loader::il2cpp_code::method_addresses(&image, table, count.min(64))
                .into_iter()
                .enumerate()
        {
            if address != 0 {
                methods.insert(
                    format!("methodPointerTable[{index}]"),
                    serde_json::json!({ "address": address }),
                );
            }
        }
    }

    let class_json = classes
        .into_iter()
        .map(|(class, fields)| {
            (
                class,
                serde_json::json!({
                    "fields": fields
                        .into_iter()
                        .map(|(name, offset, ty)| {
                            let mut entry = serde_json::Map::new();
                            entry.insert("offset".to_string(), serde_json::json!(offset));
                            if let Some(ty) = ty {
                                entry.insert("type".to_string(), serde_json::json!(ty));
                            }
                            (name, serde_json::Value::Object(entry))
                        })
                        .collect::<serde_json::Map<_, _>>(),
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();

    let payload = serde_json::json!({
        "format": "esp-offsets",
        "version": 1,
        "binary": Path::new(&binary_path)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| binary_path.clone()),
        "hash_blake3": image.hash_blake3,
        "generated": last_analysis_at,
        "generator": format!("revx {}", env!("CARGO_PKG_VERSION")),
        "binary_format": format!("{:?}", image.format),
        "binary_architecture": format!("{:?}", image.architecture),
        "warnings": warning.into_iter().collect::<Vec<_>>(),
        "classes": class_json,
        "globals": {},
        "methods": methods,
    });

    let rendered = serde_json::to_string_pretty(&payload).map_err(|e| e.to_string())?;
    match out {
        Some(path) => {
            std::fs::write(path, rendered + "\n").map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::json!({
                    "written": path.display().to_string(),
                    "binary_id": binary_id,
                    "classes": class_json.len(),
                    "methods": methods.len(),
                })
            );
        }
        None => println!("{rendered}"),
    }
    Ok(())
}

fn cmd_func(query: &str) -> Result<(), String> {
    let ws = workspace_from_cwd()?;
    let function = ws
        .resolve_function(query)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("function not found: {query}"))?;
    print_json(&json!({ "function": function }))
}

fn cmd_decompile(query: &str, engine: Option<&str>) -> Result<(), String> {
    let ws = workspace_from_cwd()?;
    let function = ws
        .resolve_function(query)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("function not found: {query}"))?;
    if engine == Some("ghidra") {
        // Vendored Ghidra core: feed function bytes as a binaryimage XML and
        // hand back native-quality C. Falls through to an error when the
        // vendored binary has not been built (see third_party README).
        let image_path = binary_path_for(&function.address)?;
        let name = function.name.rsplit("::").next().unwrap_or(&function.name);
        let c_text = ghidra_bridge::try_decompile(&image_path, function.address, name)?;
        match c_text {
            Some(text) => print_json(&json!({
                "engine": "ghidra",
                "function": function.name,
                "address": function.address,
                "pseudocode": { "language": "c", "text": text }
            })),
            None => Err(
                "ghidra engine not found: build third_party/ghidra-decompiler (see its README.md)"
                    .to_string(),
            ),
        }
    } else {
        print_json(&json!({ "pseudocode": function.pseudocode }))
    }
}

/// Resolve the on-disk image path for a function address from the workspace.
fn binary_path_for(address: &u64) -> Result<String, String> {
    let records = workspace_from_cwd()?
        .binary_record_list()
        .map_err(|e| e.to_string())?;
    for record in &records {
        // functions live under the single analyzed image in thin-CLI workspaces
        if record.function_count > 0 {
            return Ok(record.path.clone());
        }
    }
    Err(format!("no analyzed binary contains address {address:#x}"))
}

fn cmd_disasm(query: &str) -> Result<(), String> {
    let ws = workspace_from_cwd()?;
    let function = ws
        .resolve_function(query)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("function not found: {query}"))?;
    print_json(&json!({ "blocks": function.blocks }))
}

fn print_json(value: &serde_json::Value) -> Result<(), String> {
    let out = serde_json::to_string(value).map_err(|e| e.to_string())?;
    println!("{out}");
    Ok(())
}

fn cmd_analyze_micro(path: &Path) -> Result<(), String> {
    let micro = env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("revx-micro")))
        .filter(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from("revx-micro"));
    let status = Command::new(&micro)
        .arg("analyze")
        .arg(path)
        .status()
        .map_err(|e| format!("failed to spawn {}: {e}", micro.display()))?;
    if !status.success() {
        return Err(format!("revx-micro failed with {status}"));
    }
    Ok(())
}

fn forward_to_engine(args: &[String]) -> Result<(), String> {
    let engine = resolve_engine()?;
    let status = Command::new(&engine)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| format!("failed to spawn {}: {e}", engine.display()))?;
    if let Some(code) = status.code() {
        std::process::exit(code);
    }
    if !status.success() {
        return Err(format!("revx-engine failed with {status}"));
    }
    Ok(())
}

fn resolve_engine() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("REVX_ENGINE") {
        return Ok(PathBuf::from(path));
    }
    if let Ok(exe) = env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join("revx-engine");
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Ok(PathBuf::from("revx-engine"))
}

fn workspace_from_cwd() -> Result<QueryWorkspace, String> {
    let cwd = env::current_dir().map_err(|e| e.to_string())?;
    let root = revx_core::find_workspace_root(&cwd)
        .ok_or_else(|| format!("no revx workspace in {} or parents", cwd.display()))?;
    QueryWorkspace::open(&root).map_err(|e| e.to_string())
}

fn parse_usize_flag(args: &[String], flag: &str, default: usize) -> usize {
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag
            && let Some(v) = args.get(i + 1)
            && let Ok(n) = v.parse()
        {
            return n;
        }
        if let Some(rest) = args[i].strip_prefix(&format!("{flag}="))
            && let Ok(n) = rest.parse()
        {
            return n;
        }
        i += 1;
    }
    default
}

fn parse_opt_flag(args: &[String], flag: &str) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            return args.get(i + 1).cloned();
        }
        if let Some(rest) = args[i].strip_prefix(&format!("{flag}=")) {
            return Some(rest.to_string());
        }
        i += 1;
    }
    None
}

fn free_args(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--micro" {
            i += 1;
            continue;
        }
        if a.starts_with("--") {
            if a.contains('=') {
                i += 1;
                continue;
            }
            i += 2;
            continue;
        }
        out.push(a.clone());
        i += 1;
    }
    out
}
