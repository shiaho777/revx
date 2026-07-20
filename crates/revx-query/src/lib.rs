use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::{Value, json};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const PROJECT_SCHEMA_VERSION: u32 = 4;

#[derive(Clone)]
pub struct QueryWorkspace {
    root: PathBuf,
}

#[derive(Debug, Serialize)]
pub struct ProjectConfig {
    pub schema_version: u32,
    pub name: String,
    pub created_at: String,
    pub primary_binary: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BinaryRecord {
    pub id: String,
    pub path: String,
    pub format: Value,
    pub architecture: Value,
    pub last_analysis_at: Option<String>,
    pub function_count: usize,
    pub import_count: usize,
    pub export_count: usize,
    pub string_count: usize,
    pub typed_function_count: usize,
    pub structured_pseudocode_count: usize,
}

#[derive(Debug, Serialize)]
pub struct FunctionHit {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct StringHit {
    pub address: Option<u64>,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct ReferenceHit {
    pub from: u64,
    pub to: u64,
    pub kind: String,
}

#[derive(Debug, Serialize)]
pub struct FunctionDetail {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub blocks: Value,
    pub stack_summary: Value,
    pub arguments: Value,
    pub locals: Value,
    pub pseudocode: Option<Value>,
    pub evidence_ids: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SurveyPreview {
    pub binary_id: String,
    pub binary_path: String,
    pub summary: Value,
    pub artifact: Option<Value>,
    pub evidence_count: usize,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug)]
pub struct QueryError(pub String);

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for QueryError {}

impl From<rusqlite::Error> for QueryError {
    fn from(value: rusqlite::Error) -> Self {
        Self(value.to_string())
    }
}

impl From<io::Error> for QueryError {
    fn from(value: io::Error) -> Self {
        Self(value.to_string())
    }
}

impl From<serde_json::Error> for QueryError {
    fn from(value: serde_json::Error) -> Self {
        Self(value.to_string())
    }
}

type Result<T> = std::result::Result<T, QueryError>;

impl QueryWorkspace {
    pub fn init(root: &Path, project_name: &str) -> Result<Self> {
        let revx_root = root.join(".revx");
        fs::create_dir_all(revx_root.join("artifacts"))?;
        fs::create_dir_all(revx_root.join("cache"))?;
        fs::create_dir_all(revx_root.join("plugins"))?;
        fs::create_dir_all(revx_root.join("reports"))?;
        fs::create_dir_all(revx_root.join("log"))?;
        let created_at = now_rfc3339();
        let body = format!(
            "schema_version = {PROJECT_SCHEMA_VERSION}\nname = {name}\ncreated_at = {created}\n",
            name = toml_string(project_name),
            created = toml_string(&created_at),
        );
        fs::write(revx_root.join("project.toml"), body)?;
        Ok(Self { root: revx_root })
    }

    pub fn open(root: &Path) -> Result<Self> {
        let revx_root = root.join(".revx");
        let path = revx_root.join("project.toml");
        if !path.exists() {
            return Err(QueryError(format!("missing {}", path.display())));
        }
        let ws = Self { root: revx_root };
        let _ = ws.project_config()?;
        Ok(ws)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn project_config(&self) -> Result<ProjectConfig> {
        let path = self.root.join("project.toml");
        let raw = fs::read_to_string(&path)?;
        let cfg = parse_project_toml(&raw)?;
        if cfg.schema_version != PROJECT_SCHEMA_VERSION {
            return Err(QueryError(format!(
                "unsupported workspace schema_version={} at {}; expected {}",
                cfg.schema_version,
                self.root.display(),
                PROJECT_SCHEMA_VERSION
            )));
        }
        Ok(cfg)
    }

    pub fn binary_record_list(&self) -> Result<Vec<BinaryRecord>> {
        let Some(conn) = open_db_if_present(&self.root.join("state.sqlite"))? else {
            return Ok(Vec::new());
        };
        if !table_exists(&conn, "binaries")? {
            return Ok(Vec::new());
        }
        let mut stmt = conn.prepare(
            "SELECT id, path, format, architecture, last_analysis_at, function_count, import_count, export_count, string_count, typed_function_count, structured_pseudocode_count FROM binaries ORDER BY path ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(BinaryRecord {
                id: row.get(0)?,
                path: row.get(1)?,
                format: decode_json_cell(row.get::<_, String>(2)?),
                architecture: decode_json_cell(row.get::<_, String>(3)?),
                last_analysis_at: row.get(4)?,
                function_count: row.get::<_, i64>(5)? as usize,
                import_count: row.get::<_, i64>(6)? as usize,
                export_count: row.get::<_, i64>(7)? as usize,
                string_count: row.get::<_, i64>(8)? as usize,
                typed_function_count: row.get::<_, i64>(9)? as usize,
                structured_pseudocode_count: row.get::<_, i64>(10)? as usize,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn search_functions_paged(
        &self,
        query: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<FunctionHit>> {
        let Some(conn) = open_db_if_present(&self.root.join("state.sqlite"))? else {
            return Ok(Vec::new());
        };
        if !table_exists(&conn, "functions")? {
            return Ok(Vec::new());
        }
        if query.is_empty() {
            let mut stmt = conn.prepare(
                "SELECT name, address, size, evidence_ids_json FROM functions ORDER BY address ASC LIMIT ?1 OFFSET ?2",
            )?;
            let rows = stmt.query_map(params![limit as i64, offset as i64], map_function_hit)?;
            return rows
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(Into::into);
        }
        let fetch_limit = (limit.saturating_add(offset))
            .saturating_mul(4)
            .max(limit)
            .min(2_000);
        let mut stmt = conn.prepare(
            "SELECT name, address, size, evidence_ids_json FROM functions WHERE name LIKE ?1 ORDER BY address ASC LIMIT ?2",
        )?;
        let pattern = format!("%{query}%");
        let rows = stmt.query_map(params![pattern, fetch_limit as i64], map_function_hit)?;
        let mut hits = rows
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(QueryError::from)?;
        hits.sort_by(|a, b| {
            rank_name(query, &b.name)
                .cmp(&rank_name(query, &a.name))
                .then(a.address.cmp(&b.address))
        });
        Ok(hits.into_iter().skip(offset).take(limit).collect())
    }

    pub fn search_strings_paged(
        &self,
        pattern: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<StringHit>> {
        let Some(conn) = open_db_if_present(&self.root.join("state.sqlite"))? else {
            return Ok(Vec::new());
        };
        if !table_exists(&conn, "strings")? {
            return Ok(Vec::new());
        }
        if pattern.is_empty() {
            let mut stmt = conn.prepare(
                "SELECT address, value FROM strings ORDER BY address ASC LIMIT ?1 OFFSET ?2",
            )?;
            let rows = stmt.query_map(params![limit as i64, offset as i64], map_string)?;
            return rows
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(Into::into);
        }
        let fetch_limit = (limit.saturating_add(offset))
            .saturating_mul(4)
            .max(limit)
            .min(2_000);
        let mut stmt = conn.prepare(
            "SELECT address, value FROM strings WHERE value LIKE ?1 ORDER BY address ASC LIMIT ?2",
        )?;
        let like = format!("%{pattern}%");
        let rows = stmt.query_map(params![like, fetch_limit as i64], map_string)?;
        let mut hits = rows
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(QueryError::from)?;
        hits.sort_by(|a, b| {
            rank_name(pattern, &b.value)
                .cmp(&rank_name(pattern, &a.value))
                .then(a.address.cmp(&b.address))
        });
        Ok(hits.into_iter().skip(offset).take(limit).collect())
    }

    pub fn survey_preview(&self, binary_id: Option<&str>) -> Result<Option<SurveyPreview>> {
        let Some(conn) = open_db_if_present(&self.root.join("state.sqlite"))? else {
            return Ok(None);
        };
        if !table_exists(&conn, "binaries")? {
            return Ok(None);
        }
        let sql = if binary_id.is_some() {
            "SELECT id, path, format, architecture, function_count, import_count, export_count, string_count, typed_function_count, structured_pseudocode_count, survey_artifact_hash, survey_artifact_path, survey_artifact_size
             FROM binaries WHERE id = ?1 LIMIT 1"
        } else {
            "SELECT id, path, format, architecture, function_count, import_count, export_count, string_count, typed_function_count, structured_pseudocode_count, survey_artifact_hash, survey_artifact_path, survey_artifact_size
             FROM binaries ORDER BY last_analysis_at DESC LIMIT 1"
        };
        let mut stmt = conn.prepare(sql)?;
        let row = if let Some(binary_id) = binary_id {
            stmt.query_row([binary_id], map_survey).optional()?
        } else {
            stmt.query_row([], map_survey).optional()?
        };
        let Some(mut preview) = row else {
            return Ok(None);
        };
        if table_exists(&conn, "evidence")? {
            let pattern = format!("%{}%", preview.binary_path);
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM evidence WHERE subject LIKE ?1 OR id LIKE ?1",
                    [&pattern],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            preview.evidence_count = count.max(0) as usize;
            if let Ok(mut id_stmt) = conn.prepare(
                "SELECT id FROM evidence WHERE subject LIKE ?1 OR id LIKE ?1 ORDER BY id LIMIT 32",
            ) {
                if let Ok(ids) = id_stmt.query_map([&pattern], |r| r.get::<_, String>(0)) {
                    preview.evidence_ids = ids
                        .collect::<std::result::Result<Vec<_>, _>>()
                        .unwrap_or_default();
                }
            }
        }
        if let Some(summary) = preview.summary.as_object_mut() {
            summary.insert("evidence_count".into(), json!(preview.evidence_count));
        }
        Ok(Some(preview))
    }

    pub fn find_references(&self, query: &str) -> Result<Vec<ReferenceHit>> {
        let Some(conn) = open_db_if_present(&self.root.join("state.sqlite"))? else {
            return Ok(Vec::new());
        };
        if !table_exists(&conn, "code_references")? {
            return Ok(Vec::new());
        }
        if let Some((address, size)) = self.lookup_function_range(&conn, query)? {
            let start = address as i64;
            let end = (address + size) as i64;
            let mut stmt = conn.prepare(
                "SELECT from_addr, to_addr, kind FROM code_references WHERE (from_addr >= ?1 AND from_addr < ?2) OR (to_addr >= ?1 AND to_addr < ?2) ORDER BY from_addr ASC, to_addr ASC",
            )?;
            let rows = stmt.query_map(params![start, end], map_reference)?;
            return rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into);
        }
        if let Some(address) = parse_address(query) {
            let mut stmt = conn.prepare(
                "SELECT from_addr, to_addr, kind FROM code_references WHERE from_addr = ?1 OR to_addr = ?1 ORDER BY from_addr ASC, to_addr ASC",
            )?;
            let rows = stmt.query_map([address as i64], map_reference)?;
            return rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into);
        }
        Ok(Vec::new())
    }

    pub fn resolve_function(&self, query: &str) -> Result<Option<FunctionDetail>> {
        let Some(conn) = open_db_if_present(&self.root.join("state.sqlite"))? else {
            return Ok(None);
        };
        if !table_exists(&conn, "functions")? {
            return Ok(None);
        }
        let Some((name, address, size, snapshot_path, pseudo_path, stack_json, evidence_json, warnings_json)) =
            self.lookup_function_row(&conn, query)?
        else {
            return Ok(None);
        };
        let blocks = read_json_file::<serde_json::Value>(&self.root, snapshot_path.as_deref())
            .and_then(|v| v.get("blocks").cloned())
            .unwrap_or_else(|| serde_json::json!([]));
        let arguments = read_json_file::<serde_json::Value>(&self.root, snapshot_path.as_deref())
            .and_then(|v| v.get("arguments").cloned())
            .unwrap_or_else(|| serde_json::json!([]));
        let locals = read_json_file::<serde_json::Value>(&self.root, snapshot_path.as_deref())
            .and_then(|v| v.get("locals").cloned())
            .unwrap_or_else(|| serde_json::json!([]));
        let mut pseudocode = read_json_file::<serde_json::Value>(&self.root, snapshot_path.as_deref())
            .and_then(|v| v.get("pseudocode").cloned())
            .filter(|v| !v.is_null());
        if pseudocode.is_none() {
            if let Some(path) = pseudo_path.as_deref().filter(|p| !p.is_empty()) {
                if snapshot_path.as_deref() != Some(path) {
                    pseudocode = read_json_file::<serde_json::Value>(&self.root, Some(path));
                }
            }
        }
        Ok(Some(FunctionDetail {
            name,
            address,
            size,
            blocks,
            stack_summary: serde_json::from_str(&stack_json).unwrap_or(serde_json::Value::Null),
            arguments,
            locals,
            pseudocode,
            evidence_ids: serde_json::from_str(&evidence_json).unwrap_or_default(),
            warnings: serde_json::from_str(&warnings_json).unwrap_or_default(),
        }))
    }

    fn lookup_function_range(
        &self,
        conn: &Connection,
        query: &str,
    ) -> Result<Option<(u64, u64)>> {
        if let Some(address) = parse_address(query) {
            let row = conn
                .query_row(
                    "SELECT address, size FROM functions WHERE address = ?1 LIMIT 1",
                    [address as i64],
                    |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64)),
                )
                .optional()?;
            return Ok(row);
        }
        let pattern = format!("%{query}%");
        let row = conn
            .query_row(
                "SELECT address, size FROM functions WHERE name = ?1 OR name LIKE ?2 ORDER BY address ASC LIMIT 1",
                params![query, pattern],
                |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64)),
            )
            .optional()?;
        Ok(row)
    }

    fn lookup_function_row(
        &self,
        conn: &Connection,
        query: &str,
    ) -> Result<
        Option<(
            String,
            u64,
            u64,
            Option<String>,
            Option<String>,
            String,
            String,
            String,
        )>,
    > {
        let map = |row: &rusqlite::Row<'_>| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? as u64,
                row.get::<_, i64>(2)? as u64,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        };
        if let Some(address) = parse_address(query) {
            let row = conn
                .query_row(
                    "SELECT name, address, size, function_snapshot_path, pseudocode_artifact_path, stack_summary_json, evidence_ids_json, warnings_json FROM functions WHERE address = ?1 LIMIT 1",
                    [address as i64],
                    map,
                )
                .optional()?;
            return Ok(row);
        }
        let pattern = format!("%{query}%");
        let row = conn
            .query_row(
                "SELECT name, address, size, function_snapshot_path, pseudocode_artifact_path, stack_summary_json, evidence_ids_json, warnings_json FROM functions WHERE name = ?1 OR name LIKE ?2 ORDER BY CASE WHEN name = ?1 THEN 0 ELSE 1 END, address ASC LIMIT 1",
                params![query, pattern],
                map,
            )
            .optional()?;
        Ok(row)
    }

}

fn open_db_if_present(path: &Path) -> Result<Option<Connection>> {
    if !path.exists() {
        return Ok(None);
    }
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "PRAGMA query_only=ON;
         PRAGMA cache_size=-16;
         PRAGMA mmap_size=0;
         PRAGMA temp_store=FILE;
         PRAGMA soft_heap_limit=262144;
         PRAGMA hard_heap_limit=1048576;",
    )?;
    Ok(Some(conn))
}

fn table_exists(conn: &Connection, name: &str) -> Result<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
        [name],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

fn map_function_hit(row: &rusqlite::Row<'_>) -> rusqlite::Result<FunctionHit> {
    let evidence_raw: String = row.get(3)?;
    Ok(FunctionHit {
        name: row.get(0)?,
        address: row.get::<_, i64>(1)? as u64,
        size: row.get::<_, i64>(2)? as u64,
        evidence_ids: serde_json::from_str(&evidence_raw).unwrap_or_default(),
    })
}

fn map_string(row: &rusqlite::Row<'_>) -> rusqlite::Result<StringHit> {
    Ok(StringHit {
        address: row.get::<_, Option<i64>>(0)?.map(|value| value as u64),
        value: row.get(1)?,
    })
}

fn map_survey(row: &rusqlite::Row<'_>) -> rusqlite::Result<SurveyPreview> {
    let id: String = row.get(0)?;
    let path: String = row.get(1)?;
    let format = decode_json_cell(row.get::<_, String>(2)?);
    let architecture = decode_json_cell(row.get::<_, String>(3)?);
    let function_count = row.get::<_, i64>(4)? as usize;
    let import_count = row.get::<_, i64>(5)? as usize;
    let export_count = row.get::<_, i64>(6)? as usize;
    let string_count = row.get::<_, i64>(7)? as usize;
    let typed_function_count = row.get::<_, i64>(8)? as usize;
    let structured_pseudocode_count = row.get::<_, i64>(9)? as usize;
    let hash: Option<String> = row.get(10)?;
    let relative_path: Option<String> = row.get(11)?;
    let size: Option<i64> = row.get(12)?;
    let artifact = match (hash, relative_path) {
        (Some(hash_blake3), Some(relative_path)) if !hash_blake3.is_empty() => Some(json!({
            "hash_blake3": hash_blake3,
            "relative_path": relative_path,
            "size": size.unwrap_or(0).max(0) as u64,
            "content_type": "application/json",
        })),
        _ => None,
    };
    Ok(SurveyPreview {
        binary_id: id.clone(),
        binary_path: path,
        summary: json!({
            "binary_id": id,
            "format": format,
            "architecture": architecture,
            "function_count": function_count,
            "import_count": import_count,
            "export_count": export_count,
            "string_count": string_count,
            "evidence_count": 0,
            "typed_function_count": typed_function_count,
            "structured_pseudocode_count": structured_pseudocode_count,
            "warnings": [],
        }),
        artifact,
        evidence_count: 0,
        evidence_ids: Vec::new(),
    })
}

fn decode_json_cell(raw: String) -> Value {
    serde_json::from_str(&raw).unwrap_or(Value::String(raw))
}

fn map_reference(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReferenceHit> {
    Ok(ReferenceHit {
        from: row.get::<_, i64>(0)? as u64,
        to: row.get::<_, i64>(1)? as u64,
        kind: row.get(2)?,
    })
}

fn parse_address(query: &str) -> Option<u64> {
    let q = query.trim();
    if let Some(hex) = q.strip_prefix("0x").or_else(|| q.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    if q.chars().all(|c| c.is_ascii_hexdigit()) && q.chars().any(|c| c.is_ascii_alphabetic()) {
        return u64::from_str_radix(q, 16).ok();
    }
    q.parse::<u64>().ok()
}

fn read_json_file<T: serde::de::DeserializeOwned>(root: &Path, relative: Option<&str>) -> Option<T> {
    let relative = relative.filter(|p| !p.is_empty())?;
    let path = root.join(relative);
    if !path.is_file() {
        return None;
    }
    let raw = fs::read(path).ok()?;
    serde_json::from_slice(&raw).ok()
}

fn rank_name(query: &str, value: &str) -> i32 {
    let q = query.trim().to_ascii_lowercase();
    if q.is_empty() {
        return 0;
    }
    let v = value.to_ascii_lowercase();
    if v == q {
        50_000
    } else if v.starts_with(&q) {
        20_000
    } else if v.contains(&q) {
        8_000
    } else {
        0
    }
}

fn parse_project_toml(raw: &str) -> Result<ProjectConfig> {
    let mut schema_version = None;
    let mut name = None;
    let mut created_at = None;
    let mut primary_binary = None;
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "schema_version" => {
                schema_version = value.parse::<u32>().ok();
            }
            "name" => name = Some(unquote(value)),
            "created_at" => created_at = Some(unquote(value)),
            "primary_binary" => {
                if value == "null" {
                    primary_binary = None;
                } else {
                    primary_binary = Some(unquote(value));
                }
            }
            _ => {}
        }
    }
    Ok(ProjectConfig {
        schema_version: schema_version.ok_or_else(|| QueryError("missing schema_version".into()))?,
        name: name.ok_or_else(|| QueryError("missing name".into()))?,
        created_at: created_at.ok_or_else(|| QueryError("missing created_at".into()))?,
        primary_binary,
    })
}

fn unquote(value: &str) -> String {
    let v = value.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        let inner = &v[1..v.len() - 1];
        return inner.replace("\\\"", "\"").replace("\\\\", "\\");
    }
    v.to_string()
}

fn toml_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

fn civil_from_unix(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    let s = (secs % 60) as u32;
    let mins = secs / 60;
    let mi = (mins % 60) as u32;
    let hours = mins / 60;
    let h = (hours % 24) as u32;
    let mut day = (hours / 24) as i64;
    let mut y = 1970i32;
    loop {
        let diy = if is_leap(y) { 366 } else { 365 };
        if day < diy {
            break;
        }
        day -= diy;
        y += 1;
    }
    let mdays = if is_leap(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut mo = 1u32;
    for dim in mdays {
        if day < dim {
            break;
        }
        day -= dim;
        mo += 1;
    }
    (y, mo, (day as u32) + 1, h, mi, s)
}

fn is_leap(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}
