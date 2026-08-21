use super::*;

pub(crate) fn sqlite_heap_limits() -> (i64, i64, i64) {
    if revx_core::micro_mode() {
        (64 * 1024, 256 * 1024, -8)
    } else if revx_core::lean_mode() {
        (4 * 1024 * 1024, 64 * 1024 * 1024, -64)
    } else {
        (1024 * 1024, 8 * 1024 * 1024, -64)
    }
}

pub(crate) fn apply_performance_pragmas(conn: &Connection) -> Result<()> {
    let (soft, hard, cache) = sqlite_heap_limits();
    conn.execute_batch(&format!(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA cache_size={cache};
         PRAGMA mmap_size=0;
         PRAGMA busy_timeout=2000;
         PRAGMA foreign_keys=ON;
         PRAGMA temp_store=FILE;
         PRAGMA wal_autocheckpoint=32;
         PRAGMA journal_size_limit=32768;
         PRAGMA page_size=4096;
         PRAGMA soft_heap_limit={soft};
         PRAGMA hard_heap_limit={hard};"
    ))?;
    Ok(())
}

pub(crate) fn apply_analysis_ingest_pragmas(conn: &Connection) -> Result<()> {
    let (soft, hard, cache) = sqlite_heap_limits();
    conn.execute_batch(&format!(
        "PRAGMA synchronous=OFF;
         PRAGMA temp_store=FILE;
         PRAGMA cache_size={cache};
         PRAGMA mmap_size=0;
         PRAGMA journal_size_limit=32768;
         PRAGMA soft_heap_limit={soft};
         PRAGMA hard_heap_limit={hard};"
    ))?;
    Ok(())
}

pub(crate) fn restore_after_analysis_ingest_pragmas(conn: &Connection) -> Result<()> {
    let (soft, hard, cache) = sqlite_heap_limits();
    conn.execute_batch(&format!(
        "PRAGMA synchronous=NORMAL;
         PRAGMA cache_size={cache};
         PRAGMA mmap_size=0;
         PRAGMA soft_heap_limit={soft};
         PRAGMA hard_heap_limit={hard};"
    ))?;
    Ok(())
}

/// Per-database-path schema initialization (once per path per process).
static SCHEMA_READY: OnceLock<std::sync::Mutex<BTreeSet<PathBuf>>> = OnceLock::new();

pub(crate) fn ensure_pragmas(conn: &Connection, _db_path: &Path) -> Result<()> {
    apply_performance_pragmas(conn)
}

pub(crate) fn ensure_schema(conn: &Connection, db_path: &Path) -> Result<()> {
    let set = SCHEMA_READY.get_or_init(|| std::sync::Mutex::new(BTreeSet::new()));
    let mut ready = set.lock().unwrap_or_else(|p| p.into_inner());
    if ready.contains(db_path) {
        return Ok(());
    }
    init_schema(conn)?;
    ready.insert(db_path.to_path_buf());
    Ok(())
}

pub(crate) fn init_schema(conn: &Connection) -> Result<()> {
    let user_version: i32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if user_version >= 6 {
        return Ok(());
    }
    if user_version < 5 {
        conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS binaries(
            id TEXT PRIMARY KEY,
            path TEXT NOT NULL,
            format TEXT NOT NULL,
            architecture TEXT NOT NULL,
            entry_addr INTEGER,
            image_base INTEGER,
            hash_blake3 TEXT NOT NULL,
            last_analysis_at TEXT,
            function_count INTEGER NOT NULL DEFAULT 0,
            import_count INTEGER NOT NULL DEFAULT 0,
            export_count INTEGER NOT NULL DEFAULT 0,
            string_count INTEGER NOT NULL DEFAULT 0,
            typed_function_count INTEGER NOT NULL DEFAULT 0,
            structured_pseudocode_count INTEGER NOT NULL DEFAULT 0,
            survey_artifact_hash TEXT,
            survey_artifact_path TEXT,
            survey_artifact_size INTEGER
        );
        CREATE TABLE IF NOT EXISTS analysis_runs(
            id TEXT PRIMARY KEY,
            binary_id TEXT NOT NULL,
            profile TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            summary_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS functions(
            binary_id TEXT NOT NULL,
            address INTEGER NOT NULL,
            name TEXT NOT NULL,
            size INTEGER NOT NULL,
            function_snapshot_hash TEXT NOT NULL,
            function_snapshot_path TEXT NOT NULL,
            function_snapshot_size INTEGER NOT NULL,
            pseudocode_artifact_hash TEXT,
            pseudocode_artifact_path TEXT,
            pseudocode_artifact_size INTEGER,
            stack_summary_json TEXT NOT NULL,
            evidence_ids_json TEXT NOT NULL,
            warnings_json TEXT NOT NULL DEFAULT '[]',
            PRIMARY KEY(binary_id, address)
        );
        CREATE TABLE IF NOT EXISTS basic_blocks(
            binary_id TEXT NOT NULL,
            function_address INTEGER NOT NULL,
            address INTEGER NOT NULL,
            size INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS instructions(
            binary_id TEXT NOT NULL,
            function_address INTEGER NOT NULL,
            block_address INTEGER NOT NULL,
            address INTEGER NOT NULL,
            bytes TEXT NOT NULL,
            text TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS code_references(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            binary_id TEXT NOT NULL,
            from_addr INTEGER NOT NULL,
            to_addr INTEGER NOT NULL,
            kind TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS strings(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            binary_id TEXT NOT NULL,
            address INTEGER,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS debug_imports(
            binary_id TEXT PRIMARY KEY,
            status_json TEXT NOT NULL,
            source_kind TEXT,
            artifact_hash TEXT,
            artifact_path TEXT,
            artifact_size INTEGER,
            imported_type_count INTEGER NOT NULL DEFAULT 0,
            imported_function_hint_count INTEGER NOT NULL DEFAULT 0,
            imported_variable_hint_count INTEGER NOT NULL DEFAULT 0,
            notes_json TEXT NOT NULL,
            evidence_ids_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS types(
            id TEXT PRIMARY KEY,
            binary_id TEXT NOT NULL,
            name TEXT NOT NULL,
            kind TEXT NOT NULL,
            source_json TEXT NOT NULL,
            size INTEGER,
            evidence_ids_json TEXT NOT NULL,
            artifact_hash TEXT NOT NULL,
            artifact_path TEXT NOT NULL,
            artifact_size INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS binary_types(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            binary_id TEXT NOT NULL,
            type_id TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS evidence(
            id TEXT PRIMARY KEY,
            subject TEXT NOT NULL,
            kind TEXT NOT NULL,
            summary TEXT NOT NULL,
            details_json TEXT NOT NULL,
            provenance_json TEXT NOT NULL,
            evidence_artifact_hash TEXT,
            evidence_artifact_path TEXT,
            evidence_artifact_size INTEGER
        );
        CREATE TABLE IF NOT EXISTS hypotheses(
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            notes TEXT NOT NULL,
            evidence_ids_json TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS trace_events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            process TEXT NOT NULL,
            thread TEXT NOT NULL,
            kind TEXT NOT NULL,
            location INTEGER,
            payload_json TEXT NOT NULL,
            trace_artifact_hash TEXT,
            trace_artifact_path TEXT,
            trace_artifact_size INTEGER
        );
        CREATE TABLE IF NOT EXISTS reports(
            id TEXT PRIMARY KEY,
            topic TEXT NOT NULL,
            evidence_ids_json TEXT NOT NULL,
            artifact_hash TEXT NOT NULL,
            artifact_path TEXT NOT NULL,
            artifact_size INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS objects(
            id TEXT PRIMARY KEY,
            path TEXT,
            display_name TEXT NOT NULL,
            kind_json TEXT NOT NULL,
            format TEXT,
            size INTEGER NOT NULL,
            hash_blake3 TEXT,
            media_type TEXT,
            entropy REAL,
            depth INTEGER NOT NULL,
            flags_json TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            analyses_json TEXT NOT NULL DEFAULT '[]',
            evidence_ids_json TEXT NOT NULL,
            graph_artifact_hash TEXT NOT NULL,
            graph_artifact_path TEXT NOT NULL,
            graph_artifact_size INTEGER NOT NULL,
            last_seen_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS object_edges(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            graph_root_id TEXT NOT NULL,
            from_id TEXT NOT NULL,
            to_id TEXT NOT NULL,
            kind_json TEXT NOT NULL,
            metadata_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS operation_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            kind TEXT NOT NULL,
            details_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(name);
        CREATE INDEX IF NOT EXISTS idx_functions_binary_addr ON functions(binary_id, address);
        CREATE INDEX IF NOT EXISTS idx_functions_addr_range ON functions(address, size);
        CREATE INDEX IF NOT EXISTS idx_code_references_from ON code_references(binary_id, from_addr);
        CREATE INDEX IF NOT EXISTS idx_code_references_to ON code_references(binary_id, to_addr);
        CREATE INDEX IF NOT EXISTS idx_code_references_to_only ON code_references(to_addr);
        CREATE INDEX IF NOT EXISTS idx_strings_binary ON strings(binary_id, address);
        CREATE INDEX IF NOT EXISTS idx_strings_value ON strings(value);
        CREATE INDEX IF NOT EXISTS idx_evidence_subject ON evidence(subject);
        CREATE INDEX IF NOT EXISTS idx_evidence_kind ON evidence(kind);
        CREATE INDEX IF NOT EXISTS idx_types_binary ON types(binary_id);
        CREATE INDEX IF NOT EXISTS idx_binary_types_binary ON binary_types(binary_id);
        CREATE INDEX IF NOT EXISTS idx_analysis_runs_binary ON analysis_runs(binary_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_objects_path ON objects(path);
        CREATE INDEX IF NOT EXISTS idx_objects_hash ON objects(hash_blake3);
        CREATE INDEX IF NOT EXISTS idx_objects_display ON objects(display_name);
        CREATE INDEX IF NOT EXISTS idx_object_edges_from ON object_edges(from_id);
        CREATE INDEX IF NOT EXISTS idx_object_edges_to ON object_edges(to_id);
        CREATE INDEX IF NOT EXISTS idx_object_edges_root ON object_edges(graph_root_id);
        CREATE INDEX IF NOT EXISTS idx_trace_events_kind ON trace_events(kind);
        "#,
    )
    .context("failed to initialize schema")?;
        let _ = conn.execute(
            "ALTER TABLE functions ADD COLUMN warnings_json TEXT NOT NULL DEFAULT '[]'",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE objects ADD COLUMN analyses_json TEXT NOT NULL DEFAULT '[]'",
            [],
        );
    }
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS binary_imports(
            binary_id TEXT NOT NULL,
            name TEXT NOT NULL,
            address INTEGER,
            library TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_binary_imports_addr ON binary_imports(address);
        CREATE INDEX IF NOT EXISTS idx_binary_imports_binary ON binary_imports(binary_id, address);
        "#,
    )?;
    conn.execute_batch("PRAGMA user_version = 6")?;
    Ok(())
}
