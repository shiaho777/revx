use revx_query::QueryWorkspace;
use serde_json::json;
use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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
            let query = free_args(&args[1..])
                .into_iter()
                .next()
                .unwrap_or_default();
            cmd_funcs(&query, limit, offset)
        }
        "strings" => {
            let limit = parse_usize_flag(&args[1..], "--limit", 200);
            let offset = parse_usize_flag(&args[1..], "--offset", 0);
            let pattern = free_args(&args[1..])
                .into_iter()
                .next()
                .unwrap_or_default();
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
            cmd_decompile(&query)
        }
        "disasm" => {
            let query = args
                .get(1)
                .cloned()
                .ok_or_else(|| "usage: revx disasm <query>".to_string())?;
            cmd_disasm(&query)
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

fn cmd_func(query: &str) -> Result<(), String> {
    let ws = workspace_from_cwd()?;
    let function = ws
        .resolve_function(query)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("function not found: {query}"))?;
    print_json(&json!({ "function": function }))
}

fn cmd_decompile(query: &str) -> Result<(), String> {
    let ws = workspace_from_cwd()?;
    let function = ws
        .resolve_function(query)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("function not found: {query}"))?;
    print_json(&json!({ "pseudocode": function.pseudocode }))
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
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("revx-engine");
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }
    Ok(PathBuf::from("revx-engine"))
}

fn workspace_from_cwd() -> Result<QueryWorkspace, String> {
    let cwd = env::current_dir().map_err(|e| e.to_string())?;
    let mut dir = cwd.as_path();
    loop {
        if dir.join(".revx").exists() {
            return QueryWorkspace::open(dir).map_err(|e| e.to_string());
        }
        match dir.parent() {
            Some(parent) if parent != dir => dir = parent,
            _ => break,
        }
    }
    Err(format!("no revx workspace in {} or parents", cwd.display()))
}

fn parse_usize_flag(args: &[String], flag: &str, default: usize) -> usize {
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            if let Some(v) = args.get(i + 1) {
                if let Ok(n) = v.parse() {
                    return n;
                }
            }
        }
        if let Some(rest) = args[i].strip_prefix(&format!("{flag}=")) {
            if let Ok(n) = rest.parse() {
                return n;
            }
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
