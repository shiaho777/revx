use revx_core::Reference;
use revx_core::{
    AnalysisBundle, AnalysisProfile, AnalysisSummary, Architecture, BasicBlock, BinaryFormat,
    BinaryImage, BinarySummary, DebugCoverageSummary, DebugImportStatus, DebugImportSummary,
    Function, Instruction, Module, ObjectAnalysisStatus, ObjectAnalyzerKind,
    PROJECT_SCHEMA_VERSION, PseudocodeRegion, PseudocodeUnit, RegionKind, Section, Segment,
    StackSummary, StringLiteral, Survey, SymbolicConstraint, SymbolicConstraintOp,
    SymbolicDomain, SymbolicLinearExpr, SymbolicSolveResponse, SymbolicSolveStatus,
    SymbolicTerm, SymbolicVariable, TraceEvent, TypeDef, TypeSource, Variable, VariableRole,
    VariableStorage,
};
use revx_workspace::Workspace;
use std::io::Write;
use std::process::Command;
use tempfile::tempdir;

fn sample_bundle(binary_id: &str, path: &str) -> AnalysisBundle {
    let function = Function {
        name: "sub_test".to_string(),
        address: 0x401000,
        size: 5,
        blocks: vec![BasicBlock {
            address: 0x401000,
            size: 5,
            instructions: vec![Instruction {
                address: 0x401000,
                bytes: std::sync::Arc::from("c3"),
                text: std::sync::Arc::from("ret"),
            }],
        }],
        stack_summary: Some(StackSummary {
            frame_size: Some(0),
            calling_convention: Some("system_default_x64".to_string()),
            return_type: Some("void".to_string()),
            stack_arg_bytes: Some(0),
            evidence_ids: vec!["stack:401000".to_string()],
        }),
        arguments: vec![Variable {
            name: "arg_0".to_string(),
            role: VariableRole::Argument,
            storage: VariableStorage::Register,
            type_name: Some("int".to_string()),
            confidence: 0.8,
            location: "rdi".to_string(),
            evidence_ids: vec!["vars:401000:arg_0".to_string()],
        }],
        locals: vec![Variable {
            name: "local_0".to_string(),
            role: VariableRole::Local,
            storage: VariableStorage::Stack,
            type_name: Some("uint64_t".to_string()),
            confidence: 0.7,
            location: "stack[-0x8]".to_string(),
            evidence_ids: vec!["vars:401000:local_0".to_string()],
        }],
        pseudocode: Some(PseudocodeUnit {
            language: "c".to_string(),
            text: "int sub_test(int arg_0) {\n    uint64_t local_0;\n    return 0;\n}".to_string(),
            regions: vec![PseudocodeRegion {
                id: "region:401000:return".to_string(),
                kind: RegionKind::Return,
                start_address: Some(0x401000),
                end_address: Some(0x401005),
                header: None,
                statements: vec!["return 0;".to_string()],
                children: Vec::new(),
                evidence_ids: vec!["pseudo:401000:return".to_string()],
            }],
            region_artifact: None,
            evidence_ids: vec!["pseudo:401000".to_string()],
                    semantic_lattice: None,
        }),
        evidence_ids: vec![format!("fn:{binary_id}:401000")],
        warnings: Vec::new(),
    };

    AnalysisBundle {
        survey: Survey {
            binary: BinarySummary {
                id: binary_id.to_string(),
                path: path.to_string(),
                format: BinaryFormat::Elf,
                architecture: Architecture::X86_64,
                entry: Some(0x401000),
                image_base: Some(0x400000),
                size: 1,
                hash_blake3: binary_id.to_string(),
                import_count: 0,
                export_count: 0,
                string_count: 1,
            },
            summary: AnalysisSummary {
                binary_id: binary_id.to_string(),
                format: BinaryFormat::Elf,
                architecture: Architecture::X86_64,
                function_count: 1,
                import_count: 0,
                export_count: 0,
                string_count: 1,
                evidence_count: 1,
                debug_import_coverage: DebugCoverageSummary {
                    status: DebugImportStatus::Parsed,
                    imported_type_count: 1,
                    imported_function_hint_count: 1,
                    imported_variable_hint_count: 1,
                },
                typed_function_count: 1,
                structured_pseudocode_count: 1,
                warnings: Vec::new(),
            },
        },
        functions: vec![function],
        references: vec![Reference {
            from: 0x401000,
            to: 0x402000,
            kind: revx_core::ReferenceKind::Call,
        }],
        types: vec![TypeDef {
            id: "type:test:int".to_string(),
            name: "int".to_string(),
            kind: "base_type".to_string(),
            source: TypeSource::Debug,
            size: Some(4),
            evidence_ids: vec!["type:test:int".to_string()],
        }],
        strings: vec![StringLiteral {
            address: Some(0x402000),
            value: "hello".to_string(),
        }],
        debug_import: DebugImportSummary {
            status: DebugImportStatus::Parsed,
            source_kind: Some("dwarf".to_string()),
            artifact_path: None,
            imported_type_count: 1,
            imported_function_hint_count: 1,
            imported_variable_hint_count: 1,
            type_defs: vec![TypeDef {
                id: "type:test:int".to_string(),
                name: "int".to_string(),
                kind: "base_type".to_string(),
                source: TypeSource::Debug,
                size: Some(4),
                evidence_ids: vec!["type:test:int".to_string()],
            }],
            function_hints: Vec::new(),
            variable_hints: Vec::new(),
            source_anchors: Vec::new(),
            evidence_ids: vec!["debug:test".to_string()],
            notes: vec!["fixture debug".to_string()],
        },
        imports: Vec::new(),
    }
}

#[test]
fn initializes_workspace_layout() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    assert!(ws.root().join("project.toml").exists());
    assert!(ws.root().join("state.sqlite").exists());
    assert!(ws.root().join("reports").exists());
    let cfg = ws.project_config().unwrap();
    assert_eq!(cfg.schema_version, PROJECT_SCHEMA_VERSION);
}

#[test]
fn reads_artifact_previews_by_path_or_hash() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let artifact = ws
        .write_json_artifact(
            "application/json",
            &serde_json::json!({ "purpose": "artifact-read", "agent": true }),
        )
        .unwrap();

    let by_path = ws
        .read_artifact_preview(Some(&artifact.relative_path), None, 0, 32)
        .unwrap();
    assert_eq!(by_path.artifact.hash_blake3, artifact.hash_blake3);
    assert_eq!(by_path.offset, 0);
    assert!(by_path.returned_size <= 32);
    assert!(
        by_path
            .preview_text
            .as_deref()
            .is_some_and(|text| text.starts_with('{'))
    );

    let by_hash = ws
        .read_artifact_preview(None, Some(&artifact.hash_blake3), 0, 4096)
        .unwrap();
    assert_eq!(
        by_hash.preview_text,
        Some(std::fs::read_to_string(ws.root().join(&artifact.relative_path)).unwrap())
    );
    assert!(
        ws.read_artifact_preview(Some("../project.toml"), None, 0, 16)
            .is_err()
    );
}

#[test]
fn lists_artifacts_with_roles_references_and_unreferenced_files() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let orphan = ws
        .write_json_artifact(
            "application/json",
            &serde_json::json!({ "purpose": "catalog-orphan" }),
        )
        .unwrap();
    ws.insert_evidence(revx_core::Evidence {
        id: "evidence:catalog".to_string(),
        subject: "catalog-subject".to_string(),
        summary: "Evidence with embedded artifact".to_string(),
        kind: "custom_artifact".to_string(),
        details: serde_json::json!({ "artifact": orphan.clone() }),
        provenance: revx_core::EvidenceProvenance {
            source: "unit_test".to_string(),
            binary_id: None,
            function_address: None,
            instruction_address: None,
            profile: None,
        },
    })
    .unwrap();

    let referenced = ws
        .list_artifacts(Some("catalog-subject"), None, None, 10, false)
        .unwrap();
    assert_eq!(referenced.returned_count, 1);
    let hit = &referenced.artifacts[0];
    assert_eq!(hit.artifact.hash_blake3, orphan.hash_blake3);
    assert!(hit.roles.iter().any(|role| role == "custom_artifact"));
    assert!(hit.roles.iter().any(|role| role == "evidence_detail"));
    assert!(
        hit.references
            .iter()
            .any(|reference| reference.id == "evidence:catalog")
    );

    let hidden = ws
        .list_artifacts(
            Some(&orphan.hash_blake3),
            None,
            Some("stored_file"),
            10,
            false,
        )
        .unwrap();
    assert_eq!(hidden.returned_count, 0);

    let visible = ws
        .list_artifacts(
            Some(&orphan.hash_blake3),
            None,
            Some("stored_file"),
            10,
            true,
        )
        .unwrap();
    assert_eq!(visible.returned_count, 1);
    assert!(
        visible.artifacts[0]
            .roles
            .iter()
            .any(|role| role == "stored_file")
    );
}

#[test]
fn persists_universal_object_graph_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let sample = dir.path().join("sample.json");
    std::fs::write(&sample, r#"{"purpose":"universal"}"#).unwrap();

    let graph = revx_loader::identify_object_graph(&sample, 0, 16).unwrap();
    assert!(
        graph.objects[0]
            .analyses
            .iter()
            .any(|analysis| analysis.analyzer == "json_structure")
    );
    let root_id = graph.root_id.clone();
    let (artifact, evidence_ids) = ws.save_object_graph(&graph).unwrap();

    assert!(ws.root().join(&artifact.relative_path).exists());
    assert_eq!(evidence_ids.len(), 3);
    assert!(evidence_ids[0].starts_with("object:"));

    let evidence = ws
        .export_evidence_by_subject(sample.to_str().unwrap(), 10)
        .unwrap();
    assert_eq!(evidence.count, 3);
    assert!(
        evidence
            .preview
            .iter()
            .any(|item| item.kind == "object_identity"
                && item.provenance.source == "universal_object_identify"
                && item.details["graph_root_id"] == serde_json::json!(root_id))
    );
    assert!(
        evidence.preview.iter().any(
            |item| item.kind == "object_analysis" && item.provenance.source == "json_structure"
        )
    );
}

#[test]
fn persists_object_analysis_summaries_in_graph_artifact() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let archive = dir.path().join("payload.zip");
    {
        let file = std::fs::File::create(&archive).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        use std::io::Write;
        zip.start_file("inner.txt", options).unwrap();
        zip.write_all(b"nested evidence").unwrap();
        zip.finish().unwrap();
    }

    let graph = revx_loader::identify_object_graph(&archive, 1, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    let zip_analysis = root
        .analyses
        .iter()
        .find(|analysis| analysis.analyzer == "zip_container")
        .unwrap();
    assert_eq!(zip_analysis.status, ObjectAnalysisStatus::Completed);

    let root_path = root.path.clone().unwrap();
    let (artifact, evidence_ids) = ws.save_object_graph(&graph).unwrap();
    assert!(evidence_ids.iter().any(|id| id.ends_with(":zip_container")));
    let saved: revx_core::ObjectGraph = serde_json::from_str(
        &std::fs::read_to_string(ws.root().join(&artifact.relative_path)).unwrap(),
    )
    .unwrap();
    let saved_root = saved
        .objects
        .iter()
        .find(|object| object.id == saved.root_id)
        .unwrap();
    assert!(
        saved_root
            .analyses
            .iter()
            .any(|analysis| analysis.analyzer == "zip_container")
    );
    let evidence = ws.export_evidence_by_subject(&root_path, 10).unwrap();
    assert!(evidence
        .preview
        .iter()
        .any(|item| item.kind == "object_analysis"
            && item.provenance.source == "zip_container"));
}

#[test]
fn derives_evidence_graph_from_objects_artifacts_and_provenance() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let sample = dir.path().join("config.json");
    std::fs::write(&sample, r#"{"purpose":"graph","agent":true}"#).unwrap();

    let graph = revx_loader::identify_object_graph(&sample, 0, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    ws.analyze_object("config.json", Some(&[ObjectAnalyzerKind::Strings]))
        .unwrap()
        .expect("object analysis");

    let evidence_graph = ws.evidence_graph("config.json", 2, 100).unwrap();
    assert_eq!(evidence_graph.subject, "config.json");
    assert!(evidence_graph.node_count >= 5);
    assert!(evidence_graph.edge_count >= 4);
    assert!(evidence_graph.evidence_count >= 3);
    assert!(
        std::fs::metadata(ws.root().join(&evidence_graph.artifact.relative_path))
            .unwrap()
            .is_file()
    );
    assert!(
        evidence_graph
            .nodes
            .iter()
            .any(|node| node.kind == "object" && node.label == "config.json")
    );
    assert!(
        evidence_graph
            .nodes
            .iter()
            .any(|node| node.kind == "source" && node.label == "strings")
    );
    assert!(evidence_graph.nodes.iter().any(|node| {
        node.kind == "evidence" && node.data["kind"] == serde_json::json!("object_analysis")
    }));
    assert!(
        evidence_graph
            .nodes
            .iter()
            .any(|node| node.kind == "artifact")
    );
    assert!(
        evidence_graph
            .edges
            .iter()
            .any(|edge| edge.kind == "supported_by")
    );
    assert!(
        evidence_graph
            .edges
            .iter()
            .any(|edge| edge.kind == "about_object")
    );
    assert!(
        evidence_graph
            .edges
            .iter()
            .any(|edge| edge.kind == "has_artifact")
    );
}

#[test]
fn analyzes_structured_text_objects_for_agent_signals() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let sample = dir.path().join("config.json");
    std::fs::write(
        &sample,
        r#"{
  "package": "com.example.reverse.target",
  "api": { "endpoint": "https://api.example.test/v1/login" },
  "permissions": ["android.permission.INTERNET"],
  "secretToken": "ABCD1234EFGH5678IJKL9012"
}"#,
    )
    .unwrap();

    let graph = revx_loader::identify_object_graph(&sample, 0, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object("config.json", Some(&[ObjectAnalyzerKind::StructuredText]))
        .unwrap()
        .expect("structured analysis");
    assert_eq!(analysis.analyses[0].analyzer, "structured_text");
    assert_eq!(analysis.analyses[0].status, ObjectAnalysisStatus::Completed);
    assert_eq!(
        analysis.analyses[0].details["parse_status"],
        serde_json::json!("parsed_json")
    );
    assert!(
        analysis.analyses[0].details["paths"]
            .as_array()
            .unwrap()
            .iter()
            .any(|path| path["path"] == serde_json::json!("$.api.endpoint"))
    );
    assert!(
        analysis.analyses[0].details["interesting_signals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|signal| signal
                .as_str()
                .is_some_and(|value| value.starts_with("url:https://api.example.test")))
    );

    let evidence = ws.export_evidence_by_subject("config.json", 20).unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_analysis" && item.provenance.source == "structured_text"
    }));
}

#[test]
fn imports_runtime_traces_as_evidence_graph_nodes() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let sample = dir.path().join("config.json");
    std::fs::write(&sample, r#"{"purpose":"runtime","agent":true}"#).unwrap();
    let graph = revx_loader::identify_object_graph(&sample, 0, 16).unwrap();
    let object_id = graph.root_id.clone();
    ws.save_object_graph(&graph).unwrap();

    let material = ws
        .save_trace_events(&[TraceEvent {
            timestamp: chrono::DateTime::parse_from_rfc3339("2026-06-09T12:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            process: "sampled-agent".to_string(),
            thread: "main".to_string(),
            kind: "file_open".to_string(),
            location: Some(0x401000),
            payload: serde_json::json!({
                "object_id": object_id,
                "path": "config.json",
                "subject": "config.json"
            }),
        }])
        .unwrap();
    assert_eq!(material.evidence_ids.len(), 1);

    let evidence = ws.export_evidence_by_subject("file_open", 10).unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "runtime_trace_event" && item.provenance.source == "trace_import"
    }));

    let evidence_graph = ws.evidence_graph("file_open", 2, 100).unwrap();
    assert!(
        evidence_graph
            .nodes
            .iter()
            .any(|node| node.kind == "trace_event" && node.label.contains("file_open"))
    );
    assert!(
        evidence_graph
            .nodes
            .iter()
            .any(|node| node.kind == "process" && node.label == "sampled-agent")
    );
    assert!(
        evidence_graph
            .nodes
            .iter()
            .any(|node| node.kind == "thread" && node.label == "sampled-agent:main")
    );
    assert!(
        evidence_graph
            .nodes
            .iter()
            .any(|node| node.kind == "artifact"
                && node.data["hash_blake3"] == serde_json::json!(material.artifact.hash_blake3))
    );
    assert!(
        evidence_graph
            .edges
            .iter()
            .any(|edge| edge.kind == "observed_in_trace")
    );
    assert!(
        evidence_graph
            .edges
            .iter()
            .any(|edge| edge.kind == "trace_artifact")
    );
    assert!(
        evidence_graph
            .edges
            .iter()
            .any(|edge| edge.kind == "mentions_object")
    );
}

#[test]
fn persists_symbolic_results_as_evidence_graph_nodes() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let variables = vec![
        SymbolicVariable {
            name: "x".to_string(),
            domain: SymbolicDomain::IntRange { min: 0, max: 10 },
        },
        SymbolicVariable {
            name: "y".to_string(),
            domain: SymbolicDomain::IntValues {
                values: vec![1, 2, 3],
            },
        },
    ];
    let constraints = vec![
        SymbolicConstraint {
            id: Some("sum".to_string()),
            left: SymbolicLinearExpr {
                terms: vec![
                    SymbolicTerm {
                        variable: "x".to_string(),
                        coefficient: 1,
                    },
                    SymbolicTerm {
                        variable: "y".to_string(),
                        coefficient: 1,
                    },
                ],
                constant: 0,
            },
            op: SymbolicConstraintOp::Eq,
            right: SymbolicLinearExpr {
                terms: Vec::new(),
                constant: 7,
            },
        },
        SymbolicConstraint {
            id: Some("ordered".to_string()),
            left: SymbolicLinearExpr {
                terms: vec![SymbolicTerm {
                    variable: "x".to_string(),
                    coefficient: 1,
                }],
                constant: 0,
            },
            op: SymbolicConstraintOp::Gt,
            right: SymbolicLinearExpr {
                terms: vec![SymbolicTerm {
                    variable: "y".to_string(),
                    coefficient: 1,
                }],
                constant: 0,
            },
        },
    ];
    let response = ws
        .save_symbolic_solution(
            SymbolicSolveResponse {
                case_id: "case-test".to_string(),
                subject: "symbolic-auth-branch".to_string(),
                status: SymbolicSolveStatus::Sat,
                constraint_count: constraints.len(),
                checked_assignments: 4,
                solutions: vec![std::collections::BTreeMap::from([
                    ("x".to_string(), 5),
                    ("y".to_string(), 2),
                ])],
                warnings: Vec::new(),
                evidence_id: String::new(),
                artifact: revx_core::ArtifactHandle {
                    hash_blake3: String::new(),
                    relative_path: String::new(),
                    size: 0,
                    content_type: "application/json".to_string(),
                },
            },
            &variables,
            &constraints,
        )
        .unwrap();

    assert!(response.evidence_id.starts_with("symbolic:case-test:sat"));
    let evidence = ws
        .export_evidence_by_subject("symbolic-auth-branch", 10)
        .unwrap();
    assert_eq!(evidence.count, 1);
    assert_eq!(evidence.preview[0].kind, "symbolic_analysis");

    let graph = ws.evidence_graph("symbolic-auth-branch", 2, 100).unwrap();
    assert!(
        graph
            .nodes
            .iter()
            .any(|node| node.kind == "symbolic_case" && node.label == "case-test")
    );
    assert!(
        graph
            .nodes
            .iter()
            .any(|node| node.kind == "symbolic_constraint" && node.label == "sum")
    );
    assert!(
        graph
            .nodes
            .iter()
            .any(|node| node.kind == "symbolic_solution")
    );
    assert!(graph.edges.iter().any(|edge| edge.kind == "has_solution"));
    assert!(
        graph
            .edges
            .iter()
            .any(|edge| edge.kind == "describes_symbolic_case")
    );
}

#[test]
fn searches_and_profiles_universal_objects_from_index() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let archive = dir.path().join("payload.apk");
    {
        let file = std::fs::File::create(&archive).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        use std::io::Write;
        zip.start_file("classes.dex", options).unwrap();
        zip.write_all(b"dex\n035\0tiny").unwrap();
        zip.start_file("assets/config.json", options).unwrap();
        zip.write_all(br#"{"feature":"universal"}"#).unwrap();
        zip.finish().unwrap();
    }

    let graph = revx_loader::identify_object_graph(&archive, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();

    let json_hits = ws
        .search_objects("config", Some(revx_core::ObjectKind::Text), 10)
        .unwrap();
    assert_eq!(json_hits.len(), 1);
    assert_eq!(json_hits[0].display_name, "assets/config.json");
    assert!(
        json_hits[0]
            .analyzer_names
            .iter()
            .any(|name| name == "json_structure")
    );
    assert!(
        json_hits[0]
            .evidence_ids
            .iter()
            .any(|id| id.ends_with(":json_structure"))
    );

    let profile = ws
        .object_profile("classes.dex")
        .unwrap()
        .expect("object profile");
    assert_eq!(profile.object.display_name, "classes.dex");
    assert!(
        profile
            .incoming_edges
            .iter()
            .any(|edge| edge.from == graph.root_id)
    );
    assert!(
        profile
            .object
            .analyses
            .iter()
            .any(|analysis| analysis.analyzer == "dex_header")
    );
    assert!(
        profile
            .evidence_ids
            .iter()
            .any(|id| id.ends_with(":dex_header"))
    );
    assert!(
        profile
            .evidence_ids
            .iter()
            .any(|id| id.starts_with("object_edge:"))
    );
    assert!(profile.artifact.is_some());
}

#[test]
fn materializes_virtual_zip_objects_as_artifacts() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let archive = dir.path().join("payload.apk");
    let dex_bytes = b"dex\n035\0materialize-me";
    {
        let file = std::fs::File::create(&archive).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        use std::io::Write;
        zip.start_file("classes.dex", options).unwrap();
        zip.write_all(dex_bytes).unwrap();
        zip.finish().unwrap();
    }

    let graph = revx_loader::identify_object_graph(&archive, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();

    let materialized = ws
        .materialize_object("classes.dex", 8)
        .unwrap()
        .expect("materialized object");
    assert_eq!(materialized.object.display_name, "classes.dex");
    assert_eq!(materialized.content_type, "application/vnd.android.dex");
    assert!(materialized.source.contains("payload.apk!/classes.dex"));
    assert_eq!(
        materialized.preview_hex.as_deref(),
        Some("6465780a30333500")
    );
    assert!(materialized.preview_text.is_none());

    let artifact_bytes =
        std::fs::read(ws.root().join(&materialized.artifact.relative_path)).unwrap();
    assert_eq!(artifact_bytes, dex_bytes);

    let evidence = ws.export_evidence_by_subject("classes.dex", 10).unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_materialization"
            && item.id == materialized.evidence_id
            && item.provenance.source == "object_materialize"
    }));
}

#[test]
fn materializes_nested_virtual_zip_objects_as_artifacts() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let archive = dir.path().join("outer.zip");
    let nested_bytes = {
        let mut bytes = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut bytes);
            let mut zip = zip::ZipWriter::new(cursor);
            let options = zip::write::SimpleFileOptions::default();
            use std::io::Write;
            zip.start_file("deep/config.json", options).unwrap();
            zip.write_all(br#"{"nested":true,"agent":"revx"}"#).unwrap();
            zip.finish().unwrap();
        }
        bytes
    };
    {
        let file = std::fs::File::create(&archive).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        use std::io::Write;
        zip.start_file("nested.zip", options).unwrap();
        zip.write_all(&nested_bytes).unwrap();
        zip.finish().unwrap();
    }

    let graph = revx_loader::identify_object_graph(&archive, 2, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();

    let materialized = ws
        .materialize_object("deep/config.json", 64)
        .unwrap()
        .expect("nested materialized object");
    assert_eq!(materialized.object.display_name, "deep/config.json");
    assert!(materialized.source.contains("nested.zip!/deep/config.json"));
    assert!(
        materialized
            .preview_text
            .as_deref()
            .unwrap()
            .contains("\"agent\":\"revx\"")
    );

    let analysis = ws
        .analyze_object("deep/config.json", Some(&[ObjectAnalyzerKind::Strings]))
        .unwrap()
        .expect("nested object analysis");
    assert_eq!(analysis.analyses[0].analyzer, "strings");
    assert!(
        analysis
            .evidence_ids
            .iter()
            .any(|id| id.ends_with(":strings"))
    );
}

#[test]
fn materializes_and_searches_virtual_tar_objects_as_artifacts() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let archive = dir.path().join("bundle.tar");
    let config_bytes = br#"{"token":"TAR_NEEDLE","agent":"revx"}"#;
    {
        let file = std::fs::File::create(&archive).unwrap();
        let mut tar = tar::Builder::new(file);
        let mut config_header = tar::Header::new_gnu();
        config_header.set_size(config_bytes.len() as u64);
        config_header.set_cksum();
        tar.append_data(&mut config_header, "config.json", &config_bytes[..])
            .unwrap();
        let payload = b"plain tar payload";
        let mut payload_header = tar::Header::new_gnu();
        payload_header.set_size(payload.len() as u64);
        payload_header.set_cksum();
        tar.append_data(&mut payload_header, "bin/payload.txt", &payload[..])
            .unwrap();
        tar.finish().unwrap();
    }

    let graph = revx_loader::identify_object_graph(&archive, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();

    let materialized = ws
        .materialize_object("config.json", 64)
        .unwrap()
        .expect("materialized tar object");
    assert_eq!(materialized.object.display_name, "config.json");
    assert_eq!(materialized.content_type, "application/json");
    assert!(materialized.source.contains("bundle.tar!/config.json"));
    assert!(
        materialized
            .preview_text
            .as_deref()
            .unwrap()
            .contains("TAR_NEEDLE")
    );
    let artifact_bytes =
        std::fs::read(ws.root().join(&materialized.artifact.relative_path)).unwrap();
    assert_eq!(artifact_bytes, config_bytes);

    let text = ws
        .search_object_content(
            "TAR_NEEDLE",
            revx_core::ObjectContentSearchMode::Text,
            Some("config.json"),
            10,
            5,
            1024 * 1024,
        )
        .unwrap();
    assert_eq!(text.returned_count, 1);
    assert_eq!(text.matches[0].display_name, "config.json");

    let analysis = ws
        .analyze_object("config.json", Some(&[ObjectAnalyzerKind::Strings]))
        .unwrap()
        .expect("tar object analysis");
    assert_eq!(analysis.analyses[0].analyzer, "strings");
    assert!(
        analysis
            .evidence_ids
            .iter()
            .any(|id| id.ends_with(":strings"))
    );
}

#[test]
fn materializes_virtual_gzip_tar_objects_as_artifacts() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let archive = dir.path().join("bundle.tar.gz");
    let config_bytes = br#"{"token":"TGZ_NEEDLE","agent":"revx"}"#;
    {
        let file = std::fs::File::create(&archive).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        let mut config_header = tar::Header::new_gnu();
        config_header.set_size(config_bytes.len() as u64);
        config_header.set_cksum();
        tar.append_data(&mut config_header, "config.json", &config_bytes[..])
            .unwrap();
        tar.finish().unwrap();
        tar.into_inner().unwrap().finish().unwrap();
    }

    let graph = revx_loader::identify_object_graph(&archive, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();

    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.format.as_deref(), Some("tar.gz"));
    let materialized = ws
        .materialize_object("config.json", 64)
        .unwrap()
        .expect("materialized tgz object");
    assert_eq!(materialized.object.display_name, "config.json");
    assert!(materialized.source.contains("bundle.tar.gz!/config.json"));
    assert!(
        materialized
            .preview_text
            .as_deref()
            .unwrap()
            .contains("TGZ_NEEDLE")
    );
    let artifact_bytes =
        std::fs::read(ws.root().join(&materialized.artifact.relative_path)).unwrap();
    assert_eq!(artifact_bytes, config_bytes);
}

#[test]
fn materializes_virtual_bzip2_tar_objects_as_artifacts() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let archive = dir.path().join("bundle.tar.bz2");
    let config_bytes = br#"{"token":"TBZ_NEEDLE","agent":"revx"}"#;
    {
        let file = std::fs::File::create(&archive).unwrap();
        let encoder = bzip2::write::BzEncoder::new(file, bzip2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        let mut config_header = tar::Header::new_gnu();
        config_header.set_size(config_bytes.len() as u64);
        config_header.set_cksum();
        tar.append_data(&mut config_header, "config.json", &config_bytes[..])
            .unwrap();
        tar.finish().unwrap();
        tar.into_inner().unwrap().finish().unwrap();
    }

    let graph = revx_loader::identify_object_graph(&archive, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();

    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.format.as_deref(), Some("tar.bz2"));
    let materialized = ws
        .materialize_object("config.json", 64)
        .unwrap()
        .expect("materialized tbz object");
    assert_eq!(materialized.object.display_name, "config.json");
    assert!(materialized.source.contains("bundle.tar.bz2!/config.json"));
    assert!(
        materialized
            .preview_text
            .as_deref()
            .unwrap()
            .contains("TBZ_NEEDLE")
    );
    let artifact_bytes =
        std::fs::read(ws.root().join(&materialized.artifact.relative_path)).unwrap();
    assert_eq!(artifact_bytes, config_bytes);
}

#[test]
fn materializes_virtual_zstd_tar_objects_as_artifacts() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let archive = dir.path().join("bundle.tar.zst");
    let config_bytes = br#"{"token":"TZST_NEEDLE","agent":"revx"}"#;
    {
        let mut tar_bytes = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut tar_bytes);
            let mut config_header = tar::Header::new_gnu();
            config_header.set_size(config_bytes.len() as u64);
            config_header.set_cksum();
            tar.append_data(&mut config_header, "config.json", &config_bytes[..])
                .unwrap();
            tar.finish().unwrap();
        }
        let compressed = ruzstd::encoding::compress_to_vec(
            tar_bytes.as_slice(),
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        std::fs::write(&archive, compressed).unwrap();
    }

    let graph = revx_loader::identify_object_graph(&archive, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();

    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.format.as_deref(), Some("tar.zst"));
    let materialized = ws
        .materialize_object("config.json", 64)
        .unwrap()
        .expect("materialized tzst object");
    assert_eq!(materialized.object.display_name, "config.json");
    assert!(materialized.source.contains("bundle.tar.zst!/config.json"));
    assert!(
        materialized
            .preview_text
            .as_deref()
            .unwrap()
            .contains("TZST_NEEDLE")
    );
    let artifact_bytes =
        std::fs::read(ws.root().join(&materialized.artifact.relative_path)).unwrap();
    assert_eq!(artifact_bytes, config_bytes);
}

#[test]
fn materializes_and_searches_virtual_gzip_payload_as_artifact() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let archive = dir.path().join("config.json.gz");
    let config_bytes = br#"{"token":"GZIP_NEEDLE","agent":"revx"}"#;
    {
        let file = std::fs::File::create(&archive).unwrap();
        let mut encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        use std::io::Write;
        encoder.write_all(config_bytes).unwrap();
        encoder.finish().unwrap();
    }

    let graph = revx_loader::identify_object_graph(&archive, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();

    let materialized = ws
        .materialize_object("config.json", 64)
        .unwrap()
        .expect("materialized gzip payload");
    assert_eq!(materialized.object.display_name, "config.json");
    assert_eq!(materialized.content_type, "application/json");
    assert!(materialized.source.contains("config.json.gz!/config.json"));
    assert!(
        materialized
            .preview_text
            .as_deref()
            .unwrap()
            .contains("GZIP_NEEDLE")
    );
    let artifact_bytes =
        std::fs::read(ws.root().join(&materialized.artifact.relative_path)).unwrap();
    assert_eq!(artifact_bytes, config_bytes);

    let text = ws
        .search_object_content(
            "GZIP_NEEDLE",
            revx_core::ObjectContentSearchMode::Text,
            Some("config.json"),
            10,
            5,
            1024 * 1024,
        )
        .unwrap();
    assert!(text.returned_count >= 1);
    assert!(text.matches.iter().any(|item| {
        item.display_name == "config.json"
            && item
                .preview_text
                .as_deref()
                .is_some_and(|preview| preview.contains("GZIP_NEEDLE"))
    }));
}

#[test]
fn materializes_and_searches_virtual_zstd_payload_as_artifact() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let archive = dir.path().join("config.json.zst");
    let config_bytes = br#"{"token":"ZSTD_NEEDLE","agent":"revx"}"#;
    {
        let compressed = ruzstd::encoding::compress_to_vec(
            &config_bytes[..],
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        std::fs::write(&archive, compressed).unwrap();
    }

    let graph = revx_loader::identify_object_graph(&archive, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();

    let materialized = ws
        .materialize_object("config.json", 64)
        .unwrap()
        .expect("materialized zstd payload");
    assert_eq!(materialized.object.display_name, "config.json");
    assert!(materialized.source.contains("config.json.zst!/config.json"));
    assert!(
        materialized
            .preview_text
            .as_deref()
            .unwrap()
            .contains("ZSTD_NEEDLE")
    );
    let artifact_bytes =
        std::fs::read(ws.root().join(&materialized.artifact.relative_path)).unwrap();
    assert_eq!(artifact_bytes, config_bytes);

    let text = ws
        .search_object_content(
            "ZSTD_NEEDLE",
            revx_core::ObjectContentSearchMode::Text,
            Some("config.json"),
            10,
            5,
            1024 * 1024,
        )
        .unwrap();
    assert!(text.returned_count >= 1);
    assert!(text.matches.iter().any(|item| {
        item.display_name == "config.json"
            && item
                .preview_text
                .as_deref()
                .is_some_and(|preview| preview.contains("ZSTD_NEEDLE"))
    }));
}

#[test]
fn materializes_and_searches_virtual_bzip2_payload_as_artifact() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let archive = dir.path().join("config.json.bz2");
    let config_bytes = br#"{"token":"BZ2_NEEDLE","agent":"revx"}"#;
    {
        let file = std::fs::File::create(&archive).unwrap();
        let mut encoder = bzip2::write::BzEncoder::new(file, bzip2::Compression::default());
        use std::io::Write;
        encoder.write_all(config_bytes).unwrap();
        encoder.finish().unwrap();
    }

    let graph = revx_loader::identify_object_graph(&archive, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();

    let materialized = ws
        .materialize_object("config.json", 64)
        .unwrap()
        .expect("materialized bzip2 payload");
    assert_eq!(materialized.object.display_name, "config.json");
    assert!(materialized.source.contains("config.json.bz2!/config.json"));
    assert!(
        materialized
            .preview_text
            .as_deref()
            .unwrap()
            .contains("BZ2_NEEDLE")
    );
    let artifact_bytes =
        std::fs::read(ws.root().join(&materialized.artifact.relative_path)).unwrap();
    assert_eq!(artifact_bytes, config_bytes);

    let text = ws
        .search_object_content(
            "BZ2_NEEDLE",
            revx_core::ObjectContentSearchMode::Text,
            Some("config.json"),
            10,
            5,
            1024 * 1024,
        )
        .unwrap();
    assert_eq!(text.returned_count, 1);
    assert_eq!(text.matches[0].display_name, "config.json");
}

#[test]
fn materializes_virtual_xz_payload_as_artifact() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let archive = dir.path().join("config.json.xz");
    let config_bytes = br#"{"token":"XZ_NEEDLE","agent":"revx"}"#;
    {
        let file = std::fs::File::create(&archive).unwrap();
        let mut encoder = xz2::write::XzEncoder::new(file, 6);
        use std::io::Write;
        encoder.write_all(config_bytes).unwrap();
        encoder.finish().unwrap();
    }

    let graph = revx_loader::identify_object_graph(&archive, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();

    let materialized = ws
        .materialize_object("config.json", 64)
        .unwrap()
        .expect("materialized xz payload");
    assert_eq!(materialized.object.display_name, "config.json");
    assert!(materialized.source.contains("config.json.xz!/config.json"));
    assert!(
        materialized
            .preview_text
            .as_deref()
            .unwrap()
            .contains("XZ_NEEDLE")
    );
    let artifact_bytes =
        std::fs::read(ws.root().join(&materialized.artifact.relative_path)).unwrap();
    assert_eq!(artifact_bytes, config_bytes);
}

#[test]
fn materializes_ico_virtual_png_entries_for_nested_analysis() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let ico_path = dir.path().join("sample.ico");
    let png = sample_png_with_metadata_and_trailing_zip(&[]);
    let ico = sample_ico_with_png_icon(&png);
    std::fs::write(&ico_path, ico).unwrap();

    let graph = revx_loader::identify_object_graph(&ico_path, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();

    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.format.as_deref(), Some("ico"));
    assert!(
        root.analyses
            .iter()
            .any(|analysis| analysis.analyzer == "ico_container"
                && analysis.status == ObjectAnalysisStatus::Completed)
    );
    let child = graph
        .objects
        .iter()
        .find(|object| object.display_name == "icon_0_16x16_32bpp.png")
        .expect("ico png child");
    assert_eq!(child.format.as_deref(), Some("png"));
    assert_eq!(child.metadata["container_format"], serde_json::json!("ico"));
    assert_eq!(child.metadata["ico_image_offset"], serde_json::json!(22));
    assert_eq!(
        child.metadata["ico_image_size"],
        serde_json::json!(png.len())
    );

    let materialized = ws
        .materialize_object("icon_0_16x16_32bpp.png", 64)
        .unwrap()
        .expect("materialized ico png");
    assert_eq!(materialized.object.display_name, "icon_0_16x16_32bpp.png");
    assert_eq!(materialized.content_type, "image/png");
    assert!(
        materialized
            .source
            .contains("sample.ico!/icon_0_16x16_32bpp.png")
    );
    assert_eq!(
        std::fs::read(ws.root().join(&materialized.artifact.relative_path)).unwrap(),
        png
    );

    let analysis = ws
        .analyze_object(
            "icon_0_16x16_32bpp.png",
            Some(&[ObjectAnalyzerKind::PngImage]),
        )
        .unwrap()
        .expect("png analysis for ico child");
    assert_eq!(analysis.analyses.len(), 1);
    assert_eq!(analysis.analyses[0].analyzer, "png_image");
    assert_eq!(analysis.analyses[0].details["width"], serde_json::json!(2));
    assert_eq!(analysis.analyses[0].details["height"], serde_json::json!(3));

    let evidence = ws
        .export_evidence_by_subject("icon_0_16x16_32bpp.png", 10)
        .unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_analysis"
            && item.provenance.source == "png_image"
            && item.id.ends_with(":png_image")
    }));
}

#[test]
fn analyzes_bmp_and_ico_dib_entries_as_structured_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let bmp_path = dir.path().join("sample.bmp");
    std::fs::write(&bmp_path, sample_bmp_file()).unwrap();

    let graph = revx_loader::identify_object_graph(&bmp_path, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(
            &bmp_path.display().to_string(),
            Some(&[ObjectAnalyzerKind::BmpImage]),
        )
        .unwrap()
        .expect("bmp analysis");
    assert_eq!(analysis.analyses.len(), 1);
    let bmp = &analysis.analyses[0];
    assert_eq!(bmp.analyzer, "bmp_image");
    assert_eq!(bmp.status, ObjectAnalysisStatus::Completed);
    assert_eq!(bmp.details["has_file_header"], serde_json::json!(true));
    assert_eq!(bmp.details["width"], serde_json::json!(2));
    assert_eq!(bmp.details["height"], serde_json::json!(2));
    assert_eq!(bmp.details["bit_count"], serde_json::json!(32));
    assert_eq!(bmp.details["compression_name"], serde_json::json!("BI_RGB"));

    let ico_path = dir.path().join("bitmap.ico");
    let dib = sample_ico_dib_payload();
    std::fs::write(&ico_path, sample_ico_with_dib_icon(&dib)).unwrap();
    let graph = revx_loader::identify_object_graph(&ico_path, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();

    let materialized = ws
        .materialize_object("icon_0_16x16_32bpp.dib", 64)
        .unwrap()
        .expect("materialized ico dib");
    assert_eq!(materialized.object.display_name, "icon_0_16x16_32bpp.dib");
    assert_eq!(materialized.content_type, "image/bmp");
    assert!(
        materialized
            .source
            .contains("bitmap.ico!/icon_0_16x16_32bpp.dib")
    );
    assert_eq!(
        std::fs::read(ws.root().join(&materialized.artifact.relative_path)).unwrap(),
        dib
    );

    let analysis = ws
        .analyze_object(
            "icon_0_16x16_32bpp.dib",
            Some(&[ObjectAnalyzerKind::BmpImage]),
        )
        .unwrap()
        .expect("dib analysis for ico child");
    assert_eq!(analysis.analyses.len(), 1);
    let dib_analysis = &analysis.analyses[0];
    assert_eq!(dib_analysis.analyzer, "bmp_image");
    assert_eq!(dib_analysis.status, ObjectAnalysisStatus::Completed);
    assert_eq!(dib_analysis.details["format"], serde_json::json!("dib"));
    assert_eq!(
        dib_analysis.details["has_file_header"],
        serde_json::json!(false)
    );
    assert_eq!(dib_analysis.details["width"], serde_json::json!(16));
    assert_eq!(dib_analysis.details["height"], serde_json::json!(32));
    assert_eq!(
        dib_analysis.details["ico_display_height"],
        serde_json::json!(16)
    );
    assert_eq!(
        dib_analysis.details["pixel_data"]["offset"],
        serde_json::json!(40)
    );

    let evidence = ws
        .export_evidence_by_subject("icon_0_16x16_32bpp.dib", 10)
        .unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_analysis"
            && item.provenance.source == "bmp_image"
            && item.id.ends_with(":bmp_image")
    }));
}

#[test]
fn analyzes_and_materializes_riff_media_chunks_as_structured_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let webp_path = dir.path().join("sample.webp");
    let webp = sample_webp_riff();
    std::fs::write(&webp_path, &webp).unwrap();

    let graph = revx_loader::identify_object_graph(&webp_path, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.format.as_deref(), Some("webp"));
    assert!(
        root.analyses
            .iter()
            .any(|analysis| analysis.analyzer == "riff_container"
                && analysis.status == ObjectAnalysisStatus::Completed)
    );

    let materialized = ws
        .materialize_object("riff_001_WEBP_ICCP.icc", 16)
        .unwrap()
        .expect("materialized riff chunk");
    assert_eq!(materialized.object.display_name, "riff_001_WEBP_ICCP.icc");
    assert!(
        materialized
            .source
            .contains("sample.webp!/riff_001_WEBP_ICCP.icc")
    );
    assert_eq!(
        std::fs::read(ws.root().join(&materialized.artifact.relative_path)).unwrap(),
        b"abc"
    );

    let analysis = ws
        .analyze_object(
            &webp_path.display().to_string(),
            Some(&[ObjectAnalyzerKind::RiffContainer]),
        )
        .unwrap()
        .expect("riff analysis");
    assert_eq!(analysis.analyses.len(), 1);
    let riff = &analysis.analyses[0];
    assert_eq!(riff.analyzer, "riff_container");
    assert_eq!(riff.status, ObjectAnalysisStatus::Completed);
    assert_eq!(riff.details["form_type"], serde_json::json!("WEBP"));
    assert_eq!(riff.details["chunk_count"], serde_json::json!(2));
    assert_eq!(
        riff.details["webp"]["canvas"]["width"],
        serde_json::json!(2)
    );
    assert_eq!(
        riff.details["webp"]["canvas"]["height"],
        serde_json::json!(3)
    );
    assert_eq!(riff.details["webp"]["alpha"], serde_json::json!(true));

    let wav_path = dir.path().join("sample.wav");
    std::fs::write(&wav_path, sample_wav_riff()).unwrap();
    let graph = revx_loader::identify_object_graph(&wav_path, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(
            &wav_path.display().to_string(),
            Some(&[ObjectAnalyzerKind::RiffContainer]),
        )
        .unwrap()
        .expect("wav riff analysis");
    let wav = &analysis.analyses[0];
    assert_eq!(wav.details["form_type"], serde_json::json!("WAVE"));
    assert_eq!(
        wav.details["wav"]["format"]["audio_format_name"],
        serde_json::json!("PCM")
    );
    assert_eq!(
        wav.details["wav"]["format"]["sample_rate"],
        serde_json::json!(44_100)
    );
    assert_eq!(wav.details["wav"]["data_bytes"], serde_json::json!(4));

    let evidence = ws.export_evidence_by_subject("sample.webp", 20).unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_analysis"
            && item.provenance.source == "riff_container"
            && item.id.ends_with(":riff_container")
    }));
}

#[test]
fn carving_signatures_skips_whole_object_self_matches() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let webp_path = dir.path().join("sample.webp");
    std::fs::write(&webp_path, sample_webp_riff()).unwrap();

    let graph = revx_loader::identify_object_graph(&webp_path, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();

    let scanned = ws
        .scan_object_signatures("sample.webp", 10, 1024 * 1024, 16)
        .unwrap()
        .expect("signature scan");
    assert!(
        scanned
            .signatures
            .iter()
            .any(|hit| hit.format == "riff" && hit.offset == 0)
    );

    let carved = ws
        .carve_object_signatures("sample.webp", 10, 1024 * 1024, 1024 * 1024, 0.9, 16)
        .unwrap()
        .expect("signature carve");
    assert_eq!(carved.scanned_count, 1);
    assert_eq!(carved.carved_count, 0);
    assert_eq!(carved.skipped_count, 1);

    let profile = ws
        .object_profile("sample.webp")
        .unwrap()
        .expect("sample profile");
    assert_eq!(
        profile.object.path.as_deref(),
        Some(webp_path.to_str().unwrap())
    );
}

#[test]
fn lists_workspace_object_plugins_from_manifests() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let plugin_dir = ws.root().join("plugins");
    std::fs::write(
        plugin_dir.join("json-shape.json"),
        serde_json::json!({
            "id": "json-shape",
            "name": "JSON Shape",
            "description": "Summarize JSON objects",
            "command": ["python3", "shape.py", "{artifact_path}"],
            "accepted_kinds": ["text"],
            "accepted_formats": ["json"],
            "timeout_ms": 1000
        })
        .to_string(),
    )
    .unwrap();

    let plugins = ws.list_object_plugins().unwrap();
    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0].id, "json-shape");
    assert_eq!(plugins[0].accepted_kinds, vec![revx_core::ObjectKind::Text]);
    assert_eq!(plugins[0].accepted_formats, vec!["json".to_string()]);
    assert_eq!(plugins[0].command[2], "{artifact_path}");

    let resolved = ws
        .resolve_object_plugin("JSON Shape")
        .unwrap()
        .expect("plugin by name");
    assert_eq!(resolved.id, "json-shape");
}

#[test]
fn analyzes_objects_with_generic_static_analyzers() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let archive = dir.path().join("payload.apk");
    {
        let file = std::fs::File::create(&archive).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        use std::io::Write;
        zip.start_file("assets/config.json", options).unwrap();
        zip.write_all(br#"{"feature":"universal","agent":true}"#)
            .unwrap();
        zip.finish().unwrap();
    }

    let graph = revx_loader::identify_object_graph(&archive, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();

    let root_analysis = ws
        .analyze_object(&archive.display().to_string(), None)
        .unwrap()
        .expect("root analysis");
    let root_analyzers = root_analysis
        .analyses
        .iter()
        .map(|analysis| analysis.analyzer.as_str())
        .collect::<Vec<_>>();
    assert!(root_analyzers.contains(&"byte_histogram"));
    assert!(root_analyzers.contains(&"strings"));
    assert!(root_analyzers.contains(&"zip_listing"));
    assert!(
        root_analysis
            .evidence_ids
            .iter()
            .any(|id| id.ends_with(":zip_listing"))
    );

    let json_analysis = ws
        .analyze_object("assets/config.json", Some(&[ObjectAnalyzerKind::Strings]))
        .unwrap()
        .expect("json analysis");
    assert_eq!(json_analysis.analyses.len(), 1);
    assert_eq!(json_analysis.analyses[0].analyzer, "strings");
    assert!(
        json_analysis.analyses[0].details["strings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["value"].as_str().unwrap().contains("universal"))
    );
    let evidence = ws.export_evidence_by_subject("config.json", 10).unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_analysis"
            && item.provenance.source == "strings"
            && item.id.ends_with(":strings")
    }));
}

#[test]
fn analyzes_android_packages_as_agent_ready_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let apk_path = dir.path().join("sample.apk");
    std::fs::write(&apk_path, sample_android_package()).unwrap();

    let graph = revx_loader::identify_object_graph(&apk_path, 2, 32).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(&apk_path.display().to_string(), None)
        .unwrap()
        .expect("APK analysis");
    let android = analysis
        .analyses
        .iter()
        .find(|analysis| analysis.analyzer == "android_package")
        .expect("android analyzer");
    assert_eq!(android.status, ObjectAnalysisStatus::Completed);
    assert_eq!(
        android.details["manifest"]["package"],
        serde_json::json!("com.example.agent")
    );
    assert_eq!(android.details["dex_count"], serde_json::json!(1));
    assert_eq!(
        android.details["dex_files"][0]["method_ids_size"],
        serde_json::json!(3)
    );
    assert_eq!(
        android.details["native_abis"][0],
        serde_json::json!("arm64-v8a")
    );
    assert!(
        android.details["risk_signals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|signal| signal.as_str().unwrap() == "manifest_debuggable_true")
    );
    assert!(
        android.details["risk_signals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|signal| signal.as_str().unwrap() == "exported_activity_without_permission")
    );
    assert!(
        android.details["risk_signals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|signal| signal.as_str().unwrap() == "native_code_present")
    );
    assert!(
        analysis
            .evidence_ids
            .iter()
            .any(|id| id.ends_with(":android_package"))
    );

    let manifest = ws
        .materialize_object("AndroidManifest.xml", 256)
        .unwrap()
        .expect("manifest object");
    assert!(
        manifest
            .preview_text
            .as_deref()
            .unwrap()
            .contains("com.example.agent")
    );
}

#[test]
fn analyzes_dex_bytecode_as_agent_ready_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let dex_path = dir.path().join("classes.dex");
    std::fs::write(&dex_path, sample_dex_bytecode()).unwrap();

    let graph = revx_loader::identify_object_graph(&dex_path, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(&dex_path.display().to_string(), None)
        .unwrap()
        .expect("DEX analysis");
    let dex = analysis
        .analyses
        .iter()
        .find(|analysis| analysis.analyzer == "dex_bytecode")
        .expect("DEX bytecode analyzer");
    assert_eq!(dex.status, ObjectAnalysisStatus::Completed);
    assert_eq!(dex.details["header"]["version"], serde_json::json!("035"));
    assert_eq!(dex.details["string_count"], serde_json::json!(13));
    assert_eq!(dex.details["type_count"], serde_json::json!(6));
    assert_eq!(dex.details["method_count"], serde_json::json!(3));
    assert_eq!(dex.details["class_count"], serde_json::json!(1));
    assert!(
        dex.details["strings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|string| string["value"] == "https://c2.example.invalid/stage")
    );
    assert!(
        dex.details["methods"]
            .as_array()
            .unwrap()
            .iter()
            .any(|method| method["signature"]
                == "Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;")
    );
    assert!(
        dex.details["classes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|class| class["descriptor"] == "Lcom/example/Agent;"
                && class["class_data"]["virtual_methods"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|method| method["method"] == "Lcom/example/Agent;->run()V"))
    );
    for expected in [
        "dex_bytecode_present",
        "class_definitions_present",
        "class_data_present",
        "method_ids_present",
        "runtime_exec_reference",
        "shell_command_strings",
        "url_strings_present",
    ] {
        assert!(
            dex.details["risk_signals"]
                .as_array()
                .unwrap()
                .iter()
                .any(|signal| signal.as_str().unwrap() == expected),
            "missing {expected}"
        );
    }
    assert!(
        analysis
            .evidence_ids
            .iter()
            .any(|id| id.ends_with(":dex_bytecode"))
    );

    let evidence = ws.export_evidence_by_subject("classes.dex", 10).unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_analysis"
            && item.provenance.source == "dex_bytecode"
            && item.id.ends_with(":dex_bytecode")
    }));
}

#[test]
fn analyzes_ios_packages_as_agent_ready_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let ipa_path = dir.path().join("sample.ipa");
    std::fs::write(&ipa_path, sample_ios_package()).unwrap();

    let graph = revx_loader::identify_object_graph(&ipa_path, 2, 48).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(&ipa_path.display().to_string(), None)
        .unwrap()
        .expect("IPA analysis");
    let ios = analysis
        .analyses
        .iter()
        .find(|analysis| analysis.analyzer == "ios_package")
        .expect("iOS package analyzer");
    assert_eq!(ios.status, ObjectAnalysisStatus::Completed);
    assert_eq!(ios.details["app_count"], serde_json::json!(1));
    assert_eq!(
        ios.details["apps"][0]["info_plist"]["bundle_identifier"],
        serde_json::json!("com.example.ios")
    );
    assert_eq!(
        ios.details["apps"][0]["info_plist"]["executable"],
        serde_json::json!("Example")
    );
    assert_eq!(ios.details["executable_count"], serde_json::json!(1));
    assert_eq!(ios.details["framework_count"], serde_json::json!(1));
    assert_eq!(ios.details["app_extension_count"], serde_json::json!(1));
    assert!(
        ios.details["apps"][0]["info_plist"]["url_schemes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|scheme| scheme.as_str().unwrap() == "example")
    );
    for expected in [
        "custom_url_schemes",
        "background_modes_present",
        "privacy_sensitive_usage_descriptions",
        "ats_allows_arbitrary_loads",
        "embedded_frameworks_present",
        "app_extensions_present",
        "embedded_mobileprovision_present",
        "code_signature_resources_present",
        "macho_executable_present",
    ] {
        assert!(
            ios.details["risk_signals"]
                .as_array()
                .unwrap()
                .iter()
                .any(|signal| signal.as_str().unwrap() == expected),
            "missing {expected}"
        );
    }
    assert!(
        analysis
            .evidence_ids
            .iter()
            .any(|id| id.ends_with(":ios_package"))
    );

    let executable_object = graph
        .objects
        .iter()
        .find(|object| object.display_name == "Payload/Example.app/Example")
        .expect("executable graph object");
    let executable = ws
        .materialize_object(&executable_object.id, 4)
        .unwrap()
        .expect("executable object");
    assert_eq!(executable.preview_hex.as_deref(), Some("cffaedfe"));
}

#[test]
fn analyzes_java_archives_as_agent_ready_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let jar_path = dir.path().join("plugin.jar");
    std::fs::write(&jar_path, sample_java_archive()).unwrap();

    let graph = revx_loader::identify_object_graph(&jar_path, 2, 32).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(&jar_path.display().to_string(), None)
        .unwrap()
        .expect("JAR analysis");
    let java = analysis
        .analyses
        .iter()
        .find(|analysis| analysis.analyzer == "java_archive")
        .expect("java archive analyzer");
    assert_eq!(java.status, ObjectAnalysisStatus::Completed);
    assert_eq!(
        java.details["manifest"]["main_class"],
        serde_json::json!("com.example.Main")
    );
    assert_eq!(
        java.details["manifest"]["premain_class"],
        serde_json::json!("com.example.Agent")
    );
    assert_eq!(java.details["class_count"], serde_json::json!(3));
    assert_eq!(
        java.details["classes"][0]["major_version"],
        serde_json::json!(61)
    );
    assert_eq!(java.details["service_count"], serde_json::json!(1));
    assert_eq!(
        java.details["services"][0]["providers"][0],
        serde_json::json!("com.example.Plugin")
    );
    assert!(
        java.details["risk_signals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|signal| signal.as_str().unwrap() == "java_agent_entry_present")
    );
    assert!(
        java.details["risk_signals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|signal| signal.as_str().unwrap() == "service_loader_entries")
    );
    assert!(
        java.details["risk_signals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|signal| signal.as_str().unwrap() == "native_libraries_in_archive")
    );
    assert!(
        java.details["risk_signals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|signal| signal.as_str().unwrap() == "nested_archives_in_archive")
    );
    assert!(
        java.details["risk_signals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|signal| signal.as_str().unwrap() == "multi_release_class_entries")
    );
    assert!(
        analysis
            .evidence_ids
            .iter()
            .any(|id| id.ends_with(":java_archive"))
    );

    let class = ws
        .materialize_object("com/example/Main.class", 8)
        .unwrap()
        .expect("class object");
    assert_eq!(class.preview_hex.as_deref(), Some("cafebabe0000003d"));
}

#[test]
fn analyzes_jvm_classes_as_agent_ready_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let class_path = dir.path().join("Agent.class");
    std::fs::write(&class_path, sample_jvm_class()).unwrap();

    let graph = revx_loader::identify_object_graph(&class_path, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(&class_path.display().to_string(), None)
        .unwrap()
        .expect("JVM class analysis");
    let class = analysis
        .analyses
        .iter()
        .find(|analysis| analysis.analyzer == "jvm_class")
        .expect("JVM class analyzer");
    assert_eq!(class.status, ObjectAnalysisStatus::Completed);
    assert_eq!(class.details["major_version"], serde_json::json!(61));
    assert_eq!(
        class.details["class"]["name"],
        serde_json::json!("com/example/Agent")
    );
    assert_eq!(
        class.details["class"]["super_name"],
        serde_json::json!("java/lang/Object")
    );
    assert!(
        class.details["methods"]
            .as_array()
            .unwrap()
            .iter()
            .any(|method| method["name"] == "run" && method["descriptor"] == "()V")
    );
    assert!(
        class.details["references"]
            .as_array()
            .unwrap()
            .iter()
            .any(|reference| reference["class"] == "java/lang/Runtime"
                && reference["name"] == "exec")
    );
    assert!(
        class.details["string_constants"]
            .as_array()
            .unwrap()
            .iter()
            .any(|string| string["value"] == "https://c2.example.invalid/stage")
    );
    for expected in [
        "jvm_class_present",
        "modern_java_class_version",
        "runtime_exec_reference",
        "native_library_loading_reference",
        "static_initializer_present",
        "url_strings_present",
        "shell_command_strings",
    ] {
        assert!(
            class.details["risk_signals"]
                .as_array()
                .unwrap()
                .iter()
                .any(|signal| signal.as_str().unwrap() == expected),
            "missing {expected}"
        );
    }
    assert!(
        analysis
            .evidence_ids
            .iter()
            .any(|id| id.ends_with(":jvm_class"))
    );

    let evidence = ws.export_evidence_by_subject("Agent.class", 10).unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_analysis"
            && item.provenance.source == "jvm_class"
            && item.id.ends_with(":jvm_class")
    }));
}

#[test]
fn analyzes_python_bytecode_as_agent_ready_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let source_path = dir.path().join("agent.py");
    let pyc_path = dir.path().join("agent.pyc");
    std::fs::write(
        &source_path,
        r#"import subprocess
import socket

ENDPOINT = "https://c2.example.invalid/stage"
SHELL = "/bin/sh"

def run(cmd):
    return subprocess.Popen([SHELL, "-c", cmd])
"#,
    )
    .unwrap();
    let output = Command::new("python3")
        .arg("-c")
        .arg("import py_compile, sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True)")
        .arg(&source_path)
        .arg(&pyc_path)
        .output()
        .expect("python3 py_compile");
    assert!(
        output.status.success(),
        "py_compile failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let graph = revx_loader::identify_object_graph(&pyc_path, 1, 16).unwrap();
    assert_eq!(graph.objects[0].format.as_deref(), Some("python_bytecode"));
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(&pyc_path.display().to_string(), None)
        .unwrap()
        .expect("Python bytecode analysis");
    let pyc = analysis
        .analyses
        .iter()
        .find(|analysis| analysis.analyzer == "python_bytecode")
        .expect("Python bytecode analyzer");
    assert_eq!(pyc.status, ObjectAnalysisStatus::Completed);
    assert_eq!(
        pyc.details["header"]["hash_based"],
        serde_json::json!(false)
    );
    assert!(
        pyc.details["names"]
            .as_array()
            .unwrap()
            .iter()
            .any(|name| name["value"] == "subprocess")
    );
    assert!(
        pyc.details["strings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|string| string["value"] == "https://c2.example.invalid/stage")
    );
    assert!(
        pyc.details["code_objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|code| code["name"] == "run")
    );
    for expected in [
        "python_bytecode_present",
        "subprocess_reference",
        "network_api_reference",
        "url_strings_present",
        "shell_command_strings",
    ] {
        assert!(
            pyc.details["risk_signals"]
                .as_array()
                .unwrap()
                .iter()
                .any(|signal| signal.as_str().unwrap() == expected),
            "missing {expected}"
        );
    }
    assert!(
        analysis
            .evidence_ids
            .iter()
            .any(|id| id.ends_with(":python_bytecode"))
    );

    let evidence = ws.export_evidence_by_subject("agent.pyc", 10).unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_analysis"
            && item.provenance.source == "python_bytecode"
            && item.id.ends_with(":python_bytecode")
    }));
}

#[test]
fn analyzes_windows_shell_links_as_agent_ready_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let lnk_path = dir.path().join("launch.lnk");
    std::fs::write(&lnk_path, sample_shell_link()).unwrap();

    let graph = revx_loader::identify_object_graph(&lnk_path, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(&lnk_path.display().to_string(), None)
        .unwrap()
        .expect("LNK analysis");
    let lnk = analysis
        .analyses
        .iter()
        .find(|analysis| analysis.analyzer == "shell_link")
        .expect("shell link analyzer");
    assert_eq!(lnk.status, ObjectAnalysisStatus::Completed);
    assert_eq!(
        lnk.details["string_data"]["relative_path"],
        serde_json::json!("powershell.exe")
    );
    assert!(
        lnk.details["string_data"]["command_line_arguments"]
            .as_str()
            .unwrap()
            .contains("-EncodedCommand")
    );
    assert_eq!(
        lnk.details["link_info"]["common_network"]["net_name"],
        serde_json::json!("\\\\fileserver\\share")
    );
    assert!(
        lnk.details["extra_data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|block| block["kind"] == "environment_variables_location"
                && block["target_unicode"]
                    .as_str()
                    .unwrap()
                    .contains("%APPDATA%"))
    );
    for expected in [
        "shell_link_present",
        "network_target_reference",
        "script_or_lolbin_target",
        "encoded_or_dynamic_command",
        "url_reference",
        "environment_variable_target",
        "user_writable_or_startup_path",
    ] {
        assert!(
            lnk.details["risk_signals"]
                .as_array()
                .unwrap()
                .iter()
                .any(|signal| signal.as_str().unwrap() == expected),
            "missing {expected}"
        );
    }
    assert!(
        analysis
            .evidence_ids
            .iter()
            .any(|id| id.ends_with(":shell_link"))
    );

    let evidence = ws.export_evidence_by_subject("launch.lnk", 10).unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_analysis"
            && item.provenance.source == "shell_link"
            && item.id.ends_with(":shell_link")
    }));
}

#[test]
fn analyzes_safetensors_models_as_agent_ready_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let model_path = dir.path().join("adapter.safetensors");
    std::fs::write(&model_path, sample_safetensors_model()).unwrap();

    let graph = revx_loader::identify_object_graph(&model_path, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(&model_path.display().to_string(), None)
        .unwrap()
        .expect("SafeTensors analysis");
    let model = analysis
        .analyses
        .iter()
        .find(|analysis| analysis.analyzer == "safe_tensors_model")
        .expect("SafeTensors analyzer");
    assert_eq!(model.status, ObjectAnalysisStatus::Completed);
    assert_eq!(model.details["tensor_count"], serde_json::json!(3));
    assert_eq!(model.details["parameter_count"], serde_json::json!(12));
    assert!(
        model.details["tensors"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |tensor| tensor["name"] == "model.layers.0.self_attn.q_proj.weight"
                    && tensor["role"] == "attention"
                    && tensor["byte_size_matches_shape"] == serde_json::json!(true)
            )
    );
    assert!(
        model.details["tensors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tensor| tensor["name"] == "adapter.lora_A.weight" && tensor["role"] == "adapter")
    );
    assert!(
        model.details["dtype_counts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|dtype| dtype["dtype"] == "F16" && dtype["count"] == serde_json::json!(2))
    );
    for expected in [
        "safetensors_model_present",
        "adapter_or_lora_tensors_present",
        "adapter_or_lora_metadata",
    ] {
        assert!(
            model.details["risk_signals"]
                .as_array()
                .unwrap()
                .iter()
                .any(|signal| signal.as_str().unwrap() == expected),
            "missing {expected}"
        );
    }
    assert!(
        analysis
            .evidence_ids
            .iter()
            .any(|id| id.ends_with(":safe_tensors_model"))
    );

    let evidence = ws
        .export_evidence_by_subject("adapter.safetensors", 10)
        .unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_analysis"
            && item.provenance.source == "safe_tensors_model"
            && item.id.ends_with(":safe_tensors_model")
    }));
}

#[test]
fn analyzes_safetensors_index_as_agent_ready_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let index_path = dir.path().join("model.safetensors.index.json");
    std::fs::write(&index_path, sample_safetensors_index()).unwrap();

    let graph = revx_loader::identify_object_graph(&index_path, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Model);
    assert_eq!(root.format.as_deref(), Some("safetensors_index"));

    let analysis = ws
        .analyze_object(&index_path.display().to_string(), None)
        .unwrap()
        .expect("SafeTensors index analysis");
    let structured = analysis
        .analyses
        .iter()
        .find(|analysis| analysis.analyzer == "structured_text")
        .expect("structured text analyzer");
    assert_eq!(structured.status, ObjectAnalysisStatus::Completed);
    assert_eq!(
        structured.details["parse_status"],
        serde_json::json!("parsed_safetensors_index")
    );
    assert_eq!(
        structured.details["model_index"]["tensor_count"],
        serde_json::json!(3)
    );
    assert_eq!(
        structured.details["model_index"]["shard_count"],
        serde_json::json!(2)
    );
    assert_eq!(
        structured.details["model_index"]["total_size"],
        serde_json::json!(32)
    );
    assert!(
        structured.details["model_index"]["shards"]
            .as_array()
            .unwrap()
            .iter()
            .any(|shard| shard["name"] == "model-00002-of-00002.safetensors"
                && shard["tensor_count"] == serde_json::json!(2))
    );
    for expected in [
        "safetensors_index_present",
        "sharded_safetensors_model",
        "adapter_or_lora_tensors_present",
    ] {
        assert!(
            structured.details["model_index"]["risk_signals"]
                .as_array()
                .unwrap()
                .iter()
                .any(|signal| signal.as_str().unwrap() == expected),
            "missing {expected}"
        );
    }

    let evidence = ws
        .export_evidence_by_subject("model.safetensors.index.json", 10)
        .unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_analysis"
            && item.provenance.source == "structured_text"
            && item.id.ends_with(":structured_text")
    }));
}

#[test]
fn analyzes_gguf_models_as_agent_ready_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let model_path = dir.path().join("Tiny-1B-v1.0-Q4_0.gguf");
    std::fs::write(&model_path, sample_gguf_model()).unwrap();

    let graph = revx_loader::identify_object_graph(&model_path, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Model);
    assert_eq!(root.format.as_deref(), Some("gguf"));

    let analysis = ws
        .analyze_object(&model_path.display().to_string(), None)
        .unwrap()
        .expect("GGUF analysis");
    let gguf = analysis
        .analyses
        .iter()
        .find(|analysis| analysis.analyzer == "gguf_model")
        .expect("GGUF analyzer");
    assert_eq!(gguf.status, ObjectAnalysisStatus::Completed);
    assert_eq!(gguf.details["version"], serde_json::json!(3));
    assert_eq!(gguf.details["tensor_count"], serde_json::json!(2));
    assert_eq!(gguf.details["metadata_kv_count"], serde_json::json!(4));
    assert_eq!(gguf.details["layout"]["alignment"], serde_json::json!(32));
    assert!(
        gguf.details["tensors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tensor| tensor["name"] == "token_embd.weight"
                && tensor["role"] == "embedding"
                && tensor["tensor_type_name"] == "F16")
    );
    assert!(
        gguf.details["tensors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tensor| tensor["name"] == "adapter.lora_A.weight"
                && tensor["role"] == "adapter"
                && tensor["tensor_type_name"] == "Q4_0")
    );
    for expected in [
        "gguf_model_present",
        "adapter_or_lora_tensors_present",
        "adapter_or_lora_metadata",
    ] {
        assert!(
            gguf.details["risk_signals"]
                .as_array()
                .unwrap()
                .iter()
                .any(|signal| signal.as_str().unwrap() == expected),
            "missing {expected}"
        );
    }
    assert!(
        analysis
            .evidence_ids
            .iter()
            .any(|id| id.ends_with(":gguf_model"))
    );

    let evidence = ws
        .export_evidence_by_subject("Tiny-1B-v1.0-Q4_0.gguf", 10)
        .unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_analysis"
            && item.provenance.source == "gguf_model"
            && item.id.ends_with(":gguf_model")
    }));
}

#[test]
fn analyzes_pytorch_zip_models_as_agent_ready_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let model_path = dir.path().join("checkpoint.pt");
    std::fs::write(&model_path, sample_pytorch_zip_model()).unwrap();

    let graph = revx_loader::identify_object_graph(&model_path, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Model);
    assert_eq!(root.format.as_deref(), Some("pytorch"));

    let analysis = ws
        .analyze_object(&model_path.display().to_string(), None)
        .unwrap()
        .expect("PyTorch analysis");
    let pytorch = analysis
        .analyses
        .iter()
        .find(|analysis| analysis.analyzer == "pytorch_model")
        .expect("PyTorch analyzer");
    assert_eq!(pytorch.status, ObjectAnalysisStatus::Completed);
    assert_eq!(pytorch.details["container"], serde_json::json!("zip"));
    assert_eq!(pytorch.details["pickle_count"], serde_json::json!(1));
    assert_eq!(pytorch.details["storage_count"], serde_json::json!(1));
    assert!(
        pytorch.details["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "archive/data.pkl" && entry["role"] == "pickle")
    );
    assert!(
        pytorch.details["pickles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|pickle| pickle["globals"]
                .as_array()
                .unwrap()
                .iter()
                .any(|global| global.as_str() == Some("torch._utils._rebuild_tensor_v2")))
    );
    for expected in [
        "pytorch_model_present",
        "pickle_globals_present",
        "pickle_callable_opcodes_present",
        "torch_pickle_globals_present",
    ] {
        assert!(
            pytorch.details["risk_signals"]
                .as_array()
                .unwrap()
                .iter()
                .any(|signal| signal.as_str().unwrap() == expected),
            "missing {expected}"
        );
    }
    assert!(
        analysis
            .evidence_ids
            .iter()
            .any(|id| id.ends_with(":pytorch_model"))
    );

    let evidence = ws.export_evidence_by_subject("checkpoint.pt", 10).unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_analysis"
            && item.provenance.source == "pytorch_model"
            && item.id.ends_with(":pytorch_model")
    }));
}

#[test]
fn analyzes_portable_executables_as_agent_ready_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let pe_path = dir.path().join("agent.exe");
    std::fs::write(&pe_path, sample_portable_executable()).unwrap();

    let graph = revx_loader::identify_object_graph(&pe_path, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(&pe_path.display().to_string(), None)
        .unwrap()
        .expect("PE analysis");
    let pe = analysis
        .analyses
        .iter()
        .find(|analysis| analysis.analyzer == "portable_executable")
        .expect("portable executable analyzer");
    assert_eq!(pe.status, ObjectAnalysisStatus::Completed);
    assert_eq!(
        pe.details["coff"]["machine_name"],
        serde_json::json!("x86_64")
    );
    assert_eq!(
        pe.details["optional_header"]["kind"],
        serde_json::json!("PE32+")
    );
    assert_eq!(
        pe.details["optional_header"]["subsystem_name"],
        serde_json::json!("windows_cui")
    );
    assert_eq!(pe.details["section_count"], serde_json::json!(3));
    assert!(
        pe.details["sections"]
            .as_array()
            .unwrap()
            .iter()
            .any(|section| section["name"] == ".text"
                && section["flags"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|flag| flag == "execute")
                && section["flags"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|flag| flag == "write"))
    );
    assert_eq!(pe.details["imports"]["library_count"], serde_json::json!(2));
    assert!(
        pe.details["imports"]["libraries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|library| library["library"] == "KERNEL32.dll"
                && library["functions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|function| function["name"] == "VirtualAlloc"))
    );
    assert!(
        pe.details["imports"]["libraries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|library| library["library"] == "WININET.dll"
                && library["functions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|function| function["name"] == "InternetOpenUrlA"))
    );
    assert_eq!(
        pe.details["exports"]["module_name"],
        serde_json::json!("agent.dll")
    );
    assert!(
        pe.details["exports"]["functions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|function| function["name"] == "RunAgent"
                && function["ordinal"] == serde_json::json!(1))
    );
    for expected in [
        "imports_present",
        "exports_present",
        "resources_present",
        "debug_directory_present",
        "tls_directory_present",
        "relocations_present",
        "writable_executable_section",
        "dynamic_code_or_injection_imports",
        "network_api_imports",
        "overlay_data_present",
    ] {
        assert!(
            pe.details["risk_signals"]
                .as_array()
                .unwrap()
                .iter()
                .any(|signal| signal.as_str().unwrap() == expected),
            "missing {expected}"
        );
    }
    assert!(
        analysis
            .evidence_ids
            .iter()
            .any(|id| id.ends_with(":portable_executable"))
    );

    let evidence = ws.export_evidence_by_subject("agent.exe", 10).unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_analysis"
            && item.provenance.source == "portable_executable"
            && item.id.ends_with(":portable_executable")
    }));
}

#[test]
fn analyzes_dotnet_metadata_as_agent_ready_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let pe_path = dir.path().join("agent-dotnet.exe");
    std::fs::write(&pe_path, sample_dotnet_pe()).unwrap();

    let graph = revx_loader::identify_object_graph(&pe_path, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(&pe_path.display().to_string(), None)
        .unwrap()
        .expect(".NET PE analysis");
    let dotnet = analysis
        .analyses
        .iter()
        .find(|analysis| analysis.analyzer == "dotnet_metadata")
        .expect(".NET metadata analyzer");
    assert_eq!(dotnet.status, ObjectAnalysisStatus::Completed);
    assert_eq!(
        dotnet.details["clr_header"]["entry_point"]["table_name"],
        serde_json::json!("MethodDef")
    );
    assert_eq!(
        dotnet.details["metadata_root"]["version_string"],
        serde_json::json!("v4.0.30319")
    );
    assert!(
        dotnet.details["type_defs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|ty| ty["qualified_name"] == "Example.Agent")
    );
    assert!(
        dotnet.details["method_defs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|method| method["qualified_name"] == "Example.Agent.Run")
    );
    assert!(
        dotnet.details["member_refs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member["qualified_name"] == "System.Diagnostics.Process.Start")
    );
    assert!(
        dotnet.details["member_refs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member["qualified_name"] == "System.Net.Http.HttpClient.GetAsync")
    );
    assert!(
        dotnet.details["assembly_refs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|assembly| assembly["name"] == "System.Net.Http")
    );
    for expected in [
        "dotnet_metadata_present",
        "managed_entrypoint_present",
        "assembly_refs_present",
        "manifest_resources_present",
        "embedded_manifest_resources_present",
        "interesting_manifest_resource_name",
        "module_refs_present",
        "impl_maps_present",
        "native_module_ref_present",
        "suspicious_pinvoke_import",
        "process_api_reference",
        "network_api_reference",
        "reflection_reference",
        "pinvoke_or_native_interop_reference",
        "dynamic_loading_reference",
    ] {
        assert!(
            dotnet.details["risk_signals"]
                .as_array()
                .unwrap()
                .iter()
                .any(|signal| signal.as_str().unwrap() == expected),
            "missing {expected}"
        );
    }
    assert!(
        dotnet.details["manifest_resources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|resource| {
                resource["name"] == "Example.Agent.payload.pdf"
                    && resource["is_embedded"].as_bool().unwrap_or(false)
            }),
        "details={}",
        dotnet.details["manifest_resources"]
    );
    assert!(
        dotnet.details["module_refs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|module| module["name"] == "KERNEL32.dll"),
        "details={}",
        dotnet.details["module_refs"]
    );
    assert!(
        dotnet.details["impl_maps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| {
                item["import_name"] == "VirtualAlloc"
                    && item["module_name"] == "KERNEL32.dll"
            }),
        "details={}",
        dotnet.details["impl_maps"]
    );
    assert!(
        dotnet.details["user_strings"]["strings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["value"]
                .as_str()
                .is_some_and(|value| value.contains("https://revx.example/payload"))),
        "details={}",
        dotnet.details["user_strings"]
    );
    assert!(
        dotnet.details["risk_signals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|signal| signal.as_str() == Some("user_string_url")),
        "missing user_string_url in {:?}",
        dotnet.details["risk_signals"]
    );
    assert!(
        analysis
            .evidence_ids
            .iter()
            .any(|id| id.ends_with(":dotnet_metadata"))
    );

    let evidence = ws
        .export_evidence_by_subject("agent-dotnet.exe", 10)
        .unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_analysis"
            && item.provenance.source == "dotnet_metadata"
            && item.id.ends_with(":dotnet_metadata")
    }));
}

#[test]
fn auto_expands_dotnet_manifest_resources() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let pe_path = dir.path().join("managed-resources.exe");
    std::fs::write(&pe_path, sample_dotnet_pe()).unwrap();
    let graph = revx_loader::identify_object_graph(&pe_path, 0, 8).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object("managed-resources.exe", None)
        .unwrap()
        .expect("dotnet pe analysis");
    let expand = analysis
        .analyses
        .iter()
        .find(|item| item.analyzer == "auto_expand")
        .expect("auto_expand");
    let expanded = expand.details["expanded"].as_array().cloned().unwrap_or_default();
    assert!(
        expanded.iter().any(|item| {
            item.get("expand_kind")
                .and_then(|value| value.as_str())
                .is_some_and(|kind| kind == "dotnet_manifest_resource")
                || item
                    .get("entry_name")
                    .and_then(|value| value.as_str())
                    .is_some_and(|name| name.contains("manifest/") || name.contains("payload.pdf"))
        }),
        "details={}",
        expand.details
    );
}

#[test]
fn analyzes_elf_binaries_as_agent_ready_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let elf_path = dir.path().join("agent.elf");
    std::fs::write(&elf_path, sample_elf_binary()).unwrap();

    let graph = revx_loader::identify_object_graph(&elf_path, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(&elf_path.display().to_string(), None)
        .unwrap()
        .expect("ELF analysis");
    let elf = analysis
        .analyses
        .iter()
        .find(|analysis| analysis.analyzer == "elf_binary")
        .expect("ELF binary analyzer");
    assert_eq!(elf.status, ObjectAnalysisStatus::Completed);
    assert_eq!(elf.details["ident"]["class"], serde_json::json!("ELF64"));
    assert_eq!(
        elf.details["header"]["machine_name"],
        serde_json::json!("x86_64")
    );
    assert_eq!(
        elf.details["interpreter"],
        serde_json::json!("/lib64/ld-linux-x86-64.so.2")
    );
    assert_eq!(
        elf.details["dynamic"]["needed_libraries"][0],
        serde_json::json!("libc.so.6")
    );
    assert!(
        elf.details["program_headers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|header| header["type_name"] == "load"
                && header["flag_names"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|flag| flag == "write")
                && header["flag_names"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|flag| flag == "execute"))
    );
    assert!(
        elf.details["sections"]
            .as_array()
            .unwrap()
            .iter()
            .any(|section| section["name"] == ".dynsym")
    );
    assert!(
        elf.details["symbols"]["dynamic"]
            .as_array()
            .unwrap()
            .iter()
            .any(|symbol| symbol["name"] == "mprotect")
    );
    for expected in [
        "shared_object_or_pie",
        "interpreter_present",
        "dynamic_dependencies_present",
        "static_symbols_absent_or_stripped",
        "sensitive_api_imports",
        "writable_executable_segment",
        "gnu_stack_present",
        "relro_segment_present",
    ] {
        assert!(
            elf.details["risk_signals"]
                .as_array()
                .unwrap()
                .iter()
                .any(|signal| signal.as_str().unwrap() == expected),
            "missing {expected}"
        );
    }
    assert!(
        analysis
            .evidence_ids
            .iter()
            .any(|id| id.ends_with(":elf_binary"))
    );

    let evidence = ws.export_evidence_by_subject("agent.elf", 10).unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_analysis"
            && item.provenance.source == "elf_binary"
            && item.id.ends_with(":elf_binary")
    }));
}

#[test]
fn analyzes_macho_binaries_as_agent_ready_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let macho_path = dir.path().join("agent.macho");
    std::fs::write(&macho_path, sample_macho_binary()).unwrap();

    let graph = revx_loader::identify_object_graph(&macho_path, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(&macho_path.display().to_string(), None)
        .unwrap()
        .expect("Mach-O analysis");
    let macho = analysis
        .analyses
        .iter()
        .find(|analysis| analysis.analyzer == "macho_binary")
        .expect("Mach-O binary analyzer");
    assert_eq!(macho.status, ObjectAnalysisStatus::Completed);
    assert_eq!(
        macho.details["header"]["cpu_name"],
        serde_json::json!("arm64")
    );
    assert_eq!(
        macho.details["header"]["file_type_name"],
        serde_json::json!("execute")
    );
    assert_eq!(macho.details["dylib_count"], serde_json::json!(1));
    assert_eq!(
        macho.details["dylibs"][0]["name"],
        serde_json::json!("/usr/lib/libSystem.B.dylib")
    );
    assert_eq!(
        macho.details["rpaths"][0],
        serde_json::json!("@executable_path/Frameworks")
    );
    assert_eq!(
        macho.details["build_versions"][0]["platform_name"],
        serde_json::json!("ios")
    );
    assert!(
        macho.details["segments"]
            .as_array()
            .unwrap()
            .iter()
            .any(|segment| segment["name"] == "__DATA"
                && segment["initprot_names"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|flag| flag == "write")
                && segment["initprot_names"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|flag| flag == "execute"))
    );
    assert!(
        macho.details["segments"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|segment| segment["sections"].as_array().unwrap().iter())
            .any(|section| section["name"] == "__mod_init_func")
    );
    for expected in [
        "executable_image",
        "linked_dylibs_present",
        "rpaths_present",
        "dyld_info_present",
        "code_signature_present",
        "function_starts_present",
        "writable_executable_segment",
        "initializer_functions_present",
        "pie_enabled",
    ] {
        assert!(
            macho.details["risk_signals"]
                .as_array()
                .unwrap()
                .iter()
                .any(|signal| signal.as_str().unwrap() == expected),
            "missing {expected}"
        );
    }
    assert!(
        analysis
            .evidence_ids
            .iter()
            .any(|id| id.ends_with(":macho_binary"))
    );

    let evidence = ws.export_evidence_by_subject("agent.macho", 10).unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_analysis"
            && item.provenance.source == "macho_binary"
            && item.id.ends_with(":macho_binary")
    }));
}

#[test]
fn analyzes_sqlite_schema_as_structured_object_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let db_path = dir.path().join("app.sqlite");
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE accounts(
                 id INTEGER PRIMARY KEY,
                 username TEXT NOT NULL UNIQUE,
                 created_at TEXT DEFAULT CURRENT_TIMESTAMP
             );
             CREATE TABLE sessions(
                 id INTEGER PRIMARY KEY,
                 account_id INTEGER NOT NULL REFERENCES accounts(id),
                 token TEXT NOT NULL,
                 expires_at INTEGER
             );
             CREATE INDEX idx_sessions_account_id ON sessions(account_id);
             CREATE VIEW active_sessions AS
                 SELECT sessions.id, accounts.username
                 FROM sessions JOIN accounts ON accounts.id = sessions.account_id;
             CREATE TRIGGER sessions_ai AFTER INSERT ON sessions
                 BEGIN
                     SELECT NEW.id;
                 END;",
        )
        .unwrap();
    }

    let graph = revx_loader::identify_object_graph(&db_path, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(&db_path.display().to_string(), None)
        .unwrap()
        .expect("sqlite analysis");
    let schema = analysis
        .analyses
        .iter()
        .find(|item| item.analyzer == "sqlite_schema")
        .expect("sqlite schema analyzer");
    assert_eq!(schema.status, ObjectAnalysisStatus::Completed);
    assert_eq!(schema.details["counts"]["tables"], serde_json::json!(2));
    assert_eq!(schema.details["counts"]["views"], serde_json::json!(1));
    assert_eq!(schema.details["counts"]["triggers"], serde_json::json!(1));
    assert_eq!(schema.details["truncated"], serde_json::json!(false));

    let objects = schema.details["objects"].as_array().unwrap();
    let accounts = objects
        .iter()
        .find(|item| item["type"] == serde_json::json!("table") && item["name"] == "accounts")
        .expect("accounts table");
    assert!(
        accounts["columns"]
            .as_array()
            .unwrap()
            .iter()
            .any(|column| column["name"] == "username"
                && column["type"] == "TEXT"
                && column["not_null"] == true)
    );
    let sessions = objects
        .iter()
        .find(|item| item["type"] == serde_json::json!("table") && item["name"] == "sessions")
        .expect("sessions table");
    assert!(
        sessions["indexes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|index| index["name"] == "idx_sessions_account_id")
    );
    assert!(
        sessions["foreign_keys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|fk| fk["target_table"] == "accounts" && fk["from"] == "account_id")
    );
    assert!(objects.iter().any(|item| {
        item["type"] == serde_json::json!("view") && item["name"] == "active_sessions"
    }));

    let explicit = ws
        .analyze_object(
            &db_path.display().to_string(),
            Some(&[ObjectAnalyzerKind::SqliteSchema]),
        )
        .unwrap()
        .expect("explicit sqlite analysis");
    assert_eq!(explicit.analyses.len(), 1);
    assert_eq!(explicit.analyses[0].analyzer, "sqlite_schema");
    assert!(
        explicit
            .evidence_ids
            .iter()
            .any(|id| id.ends_with(":sqlite_schema"))
    );

    let evidence = ws.export_evidence_by_subject("app.sqlite", 10).unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_analysis"
            && item.provenance.source == "sqlite_schema"
            && item.id.ends_with(":sqlite_schema")
    }));
}

#[test]
fn analyzes_wasm_module_as_structured_object_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let wasm_path = dir.path().join("module.wasm");
    std::fs::write(&wasm_path, sample_wasm_module()).unwrap();

    let graph = revx_loader::identify_object_graph(&wasm_path, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(&wasm_path.display().to_string(), None)
        .unwrap()
        .expect("wasm analysis");
    let module = analysis
        .analyses
        .iter()
        .find(|item| item.analyzer == "wasm_module")
        .expect("wasm module analyzer");
    assert_eq!(module.status, ObjectAnalysisStatus::Completed);
    assert_eq!(module.details["version"], serde_json::json!(1));
    assert_eq!(module.details["encoding"], serde_json::json!("module"));
    assert_eq!(
        module.details["counts"]["defined_functions"],
        serde_json::json!(1)
    );
    assert!(
        module.details["imports"]
            .as_array()
            .unwrap()
            .iter()
            .any(|import| import["module"] == "env" && import["name"] == "log")
    );
    assert!(
        module.details["exports"]
            .as_array()
            .unwrap()
            .iter()
            .any(|export| export["name"] == "run" && export["kind"] == "func")
    );
    assert!(
        module.details["memories"]
            .as_array()
            .unwrap()
            .iter()
            .any(|memory| memory["initial_pages"] == 1)
    );
    assert!(
        module.details["data_segments"]
            .as_array()
            .unwrap()
            .iter()
            .any(|segment| segment["preview_text"] == "hi")
    );

    let explicit = ws
        .analyze_object(
            &wasm_path.display().to_string(),
            Some(&[ObjectAnalyzerKind::WasmModule]),
        )
        .unwrap()
        .expect("explicit wasm analysis");
    assert_eq!(explicit.analyses.len(), 1);
    assert_eq!(explicit.analyses[0].analyzer, "wasm_module");
    assert!(
        explicit
            .evidence_ids
            .iter()
            .any(|id| id.ends_with(":wasm_module"))
    );

    let evidence = ws.export_evidence_by_subject("module.wasm", 10).unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_analysis"
            && item.provenance.source == "wasm_module"
            && item.id.ends_with(":wasm_module")
    }));
}

#[test]
fn analyzes_pdf_document_as_structured_object_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let pdf_path = dir.path().join("sample.pdf");
    std::fs::write(&pdf_path, sample_pdf_document()).unwrap();

    let graph = revx_loader::identify_object_graph(&pdf_path, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(&pdf_path.display().to_string(), None)
        .unwrap()
        .expect("pdf analysis");
    let pdf = analysis
        .analyses
        .iter()
        .find(|item| item.analyzer == "pdf_document")
        .expect("pdf document analyzer");
    assert_eq!(pdf.status, ObjectAnalysisStatus::Completed);
    assert_eq!(pdf.details["version"], serde_json::json!("1.7"));
    assert_eq!(pdf.details["page_count"], serde_json::json!(1));
    assert_eq!(
        pdf.details["catalog"]["has_open_action"],
        serde_json::json!(true)
    );
    assert!(
        pdf.details["risk_signals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|signal| signal["name"] == "javascript")
    );
    assert!(
        pdf.details["interesting_objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["action"] == "JavaScript")
    );

    let explicit = ws
        .analyze_object(
            &pdf_path.display().to_string(),
            Some(&[ObjectAnalyzerKind::PdfDocument]),
        )
        .unwrap()
        .expect("explicit pdf analysis");
    assert_eq!(explicit.analyses.len(), 1);
    assert_eq!(explicit.analyses[0].analyzer, "pdf_document");
    assert!(
        explicit
            .evidence_ids
            .iter()
            .any(|id| id.ends_with(":pdf_document"))
    );

    let evidence = ws.export_evidence_by_subject("sample.pdf", 10).unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_analysis"
            && item.provenance.source == "pdf_document"
            && item.id.ends_with(":pdf_document")
    }));
}

#[test]
fn analyzes_png_image_as_structured_object_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let png_path = dir.path().join("carrier.png");
    let embedded_zip = sample_embedded_zip("payload.txt", b"hidden zip follows");
    let png = sample_png_with_metadata_and_trailing_zip(&embedded_zip);
    std::fs::write(&png_path, &png).unwrap();

    let graph = revx_loader::identify_object_graph(&png_path, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(&png_path.display().to_string(), None)
        .unwrap()
        .expect("png analysis");
    let png_analysis = analysis
        .analyses
        .iter()
        .find(|item| item.analyzer == "png_image")
        .expect("png image analyzer");
    assert_eq!(png_analysis.status, ObjectAnalysisStatus::Partial);
    assert_eq!(png_analysis.details["valid"], serde_json::json!(true));
    assert_eq!(png_analysis.details["width"], serde_json::json!(2));
    assert_eq!(png_analysis.details["height"], serde_json::json!(3));
    assert_eq!(
        png_analysis.details["color_type_name"],
        serde_json::json!("truecolor")
    );
    assert_eq!(png_analysis.details["chunk_count"], serde_json::json!(4));
    assert_eq!(png_analysis.details["idat_count"], serde_json::json!(1));
    assert_eq!(png_analysis.details["idat_bytes"], serde_json::json!(5));
    assert!(
        png_analysis.details["chunks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|chunk| chunk["crc_valid"] == true)
    );
    assert!(
        png_analysis.details["text_chunks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|chunk| chunk["kind"] == "tEXt"
                && chunk["keyword"] == "Comment"
                && chunk["text"] == "hidden zip follows")
    );
    assert_eq!(
        png_analysis.details["trailing_data"]["size"],
        serde_json::json!(embedded_zip.len())
    );
    assert!(
        png_analysis.details["trailing_data"]["embedded_signatures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|hit| hit["format"] == "zip"
                && hit["offset"] == png.len() as u64 - embedded_zip.len() as u64)
    );
    assert!(
        png_analysis.details["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning == "PNG has trailing data after IEND")
    );

    let explicit = ws
        .analyze_object(
            &png_path.display().to_string(),
            Some(&[ObjectAnalyzerKind::PngImage]),
        )
        .unwrap()
        .expect("explicit png analysis");
    assert_eq!(explicit.analyses.len(), 1);
    assert_eq!(explicit.analyses[0].analyzer, "png_image");
    assert!(
        explicit
            .evidence_ids
            .iter()
            .any(|id| id.ends_with(":png_image"))
    );

    let evidence = ws.export_evidence_by_subject("carrier.png", 10).unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_analysis"
            && item.provenance.source == "png_image"
            && item.id.ends_with(":png_image")
    }));
}

#[test]
fn analyzes_jpeg_image_as_structured_object_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let jpeg_path = dir.path().join("carrier.jpg");
    let embedded_zip = sample_embedded_zip("payload.txt", b"jpeg tail payload");
    let jpeg = sample_jpeg_with_metadata_and_trailing_zip(&embedded_zip);
    std::fs::write(&jpeg_path, &jpeg).unwrap();

    let graph = revx_loader::identify_object_graph(&jpeg_path, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(&jpeg_path.display().to_string(), None)
        .unwrap()
        .expect("jpeg analysis");
    let jpeg_analysis = analysis
        .analyses
        .iter()
        .find(|item| item.analyzer == "jpeg_image")
        .expect("jpeg image analyzer");
    assert_eq!(jpeg_analysis.status, ObjectAnalysisStatus::Partial);
    assert_eq!(jpeg_analysis.details["valid"], serde_json::json!(true));
    assert_eq!(jpeg_analysis.details["width"], serde_json::json!(4));
    assert_eq!(jpeg_analysis.details["height"], serde_json::json!(5));
    assert_eq!(jpeg_analysis.details["precision"], serde_json::json!(8));
    assert_eq!(
        jpeg_analysis.details["frame_marker"],
        serde_json::json!("SOF0")
    );
    assert_eq!(
        jpeg_analysis.details["component_count"],
        serde_json::json!(3)
    );
    assert_eq!(jpeg_analysis.details["scan_count"], serde_json::json!(1));
    assert!(
        jpeg_analysis.details["metadata_segments"]
            .as_array()
            .unwrap()
            .iter()
            .any(|segment| segment["marker"] == "APP0" && segment["identifier"] == "JFIF")
    );
    assert!(
        jpeg_analysis.details["metadata_segments"]
            .as_array()
            .unwrap()
            .iter()
            .any(|segment| segment["marker"] == "COM"
                && segment["preview_text"] == "hidden jpeg comment")
    );
    assert_eq!(
        jpeg_analysis.details["trailing_data"]["size"],
        serde_json::json!(embedded_zip.len())
    );
    assert!(
        jpeg_analysis.details["trailing_data"]["embedded_signatures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|hit| hit["format"] == "zip"
                && hit["offset"] == jpeg.len() as u64 - embedded_zip.len() as u64)
    );
    assert!(
        jpeg_analysis.details["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning == "JPEG has trailing data after EOI")
    );

    let explicit = ws
        .analyze_object(
            &jpeg_path.display().to_string(),
            Some(&[ObjectAnalyzerKind::JpegImage]),
        )
        .unwrap()
        .expect("explicit jpeg analysis");
    assert_eq!(explicit.analyses.len(), 1);
    assert_eq!(explicit.analyses[0].analyzer, "jpeg_image");
    assert!(
        explicit
            .evidence_ids
            .iter()
            .any(|id| id.ends_with(":jpeg_image"))
    );

    let evidence = ws.export_evidence_by_subject("carrier.jpg", 10).unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_analysis"
            && item.provenance.source == "jpeg_image"
            && item.id.ends_with(":jpeg_image")
    }));
}

#[test]
fn analyzes_gif_image_as_structured_object_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let gif_path = dir.path().join("carrier.gif");
    let embedded_zip = sample_embedded_zip("payload.txt", b"gif tail payload");
    let gif = sample_gif_with_metadata_and_trailing_zip(&embedded_zip);
    std::fs::write(&gif_path, &gif).unwrap();

    let graph = revx_loader::identify_object_graph(&gif_path, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(&gif_path.display().to_string(), None)
        .unwrap()
        .expect("gif analysis");
    let gif_analysis = analysis
        .analyses
        .iter()
        .find(|item| item.analyzer == "gif_image")
        .expect("gif image analyzer");
    assert_eq!(gif_analysis.status, ObjectAnalysisStatus::Partial);
    assert_eq!(gif_analysis.details["valid"], serde_json::json!(true));
    assert_eq!(gif_analysis.details["version"], serde_json::json!("89a"));
    assert_eq!(gif_analysis.details["width"], serde_json::json!(4));
    assert_eq!(gif_analysis.details["height"], serde_json::json!(5));
    assert_eq!(gif_analysis.details["frame_count"], serde_json::json!(1));
    assert_eq!(
        gif_analysis.details["extension_count"],
        serde_json::json!(3)
    );
    assert_eq!(
        gif_analysis.details["logical_screen"]["global_color_table_size"],
        serde_json::json!(2)
    );
    assert!(
        gif_analysis.details["comments"]
            .as_array()
            .unwrap()
            .iter()
            .any(|comment| comment["comment"]["text"] == "hidden gif comment")
    );
    assert!(
        gif_analysis.details["application_extensions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|extension| {
                extension["application"]["identifier"] == "NETSCAPE"
                    && extension["application"]["authentication_code"] == "2.0"
            })
    );
    assert_eq!(
        gif_analysis.details["trailing_data"]["size"],
        serde_json::json!(embedded_zip.len())
    );
    assert!(
        gif_analysis.details["trailing_data"]["embedded_signatures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|hit| hit["format"] == "zip"
                && hit["offset"] == gif.len() as u64 - embedded_zip.len() as u64)
    );
    assert!(
        gif_analysis.details["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning == "GIF has trailing data after trailer")
    );

    let explicit = ws
        .analyze_object(
            &gif_path.display().to_string(),
            Some(&[ObjectAnalyzerKind::GifImage]),
        )
        .unwrap()
        .expect("explicit gif analysis");
    assert_eq!(explicit.analyses.len(), 1);
    assert_eq!(explicit.analyses[0].analyzer, "gif_image");
    assert!(
        explicit
            .evidence_ids
            .iter()
            .any(|id| id.ends_with(":gif_image"))
    );

    let evidence = ws.export_evidence_by_subject("carrier.gif", 10).unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_analysis"
            && item.provenance.source == "gif_image"
            && item.id.ends_with(":gif_image")
    }));
}

#[test]
fn analyzes_pcap_capture_as_structured_network_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let pcap_path = dir.path().join("sample.pcap");
    std::fs::write(&pcap_path, sample_pcap_capture()).unwrap();

    let graph = revx_loader::identify_object_graph(&pcap_path, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(
            &pcap_path.display().to_string(),
            Some(&[ObjectAnalyzerKind::PcapCapture]),
        )
        .unwrap()
        .expect("pcap analysis");
    assert_eq!(analysis.analyses.len(), 1);
    let pcap = &analysis.analyses[0];
    assert_eq!(pcap.analyzer, "pcap_capture");
    assert_eq!(pcap.status, ObjectAnalysisStatus::Completed);
    assert_eq!(pcap.details["container"], serde_json::json!("pcap"));
    assert_eq!(pcap.details["packet_count"], serde_json::json!(1));
    assert_eq!(
        pcap.details["header"]["network_name"],
        serde_json::json!("ETHERNET")
    );
    assert_eq!(
        pcap.details["packets"][0]["decoded"]["network"]["src_ip"],
        serde_json::json!("192.0.2.1")
    );
    assert_eq!(
        pcap.details["packets"][0]["decoded"]["network"]["dst_ip"],
        serde_json::json!("198.51.100.2")
    );
    assert_eq!(
        pcap.details["packets"][0]["decoded"]["network"]["transport"]["dst_port"],
        serde_json::json!(443)
    );
    assert_eq!(pcap.details["protocols"]["TCP"], serde_json::json!(1));
    assert_eq!(pcap.details["endpoints"]["192.0.2.1"], serde_json::json!(1));

    let evidence = ws.export_evidence_by_subject("sample.pcap", 10).unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_analysis"
            && item.provenance.source == "pcap_capture"
            && item.id.ends_with(":pcap_capture")
    }));
}

#[test]
fn analyzes_pcapng_capture_blocks_as_structured_network_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let pcapng_path = dir.path().join("sample.pcapng");
    std::fs::write(&pcapng_path, sample_pcapng_capture()).unwrap();

    let graph = revx_loader::identify_object_graph(&pcapng_path, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(
            &pcapng_path.display().to_string(),
            Some(&[ObjectAnalyzerKind::PcapCapture]),
        )
        .unwrap()
        .expect("pcapng analysis");
    let pcapng = &analysis.analyses[0];
    assert_eq!(pcapng.analyzer, "pcap_capture");
    assert_eq!(pcapng.status, ObjectAnalysisStatus::Completed);
    assert_eq!(pcapng.details["container"], serde_json::json!("pcapng"));
    assert_eq!(pcapng.details["block_count"], serde_json::json!(1));
    assert_eq!(
        pcapng.details["blocks"][0]["block_type_name"],
        serde_json::json!("section_header")
    );
}

#[test]
fn analyzes_open_xml_word_documents_as_semantic_evidence() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let docx_path = dir.path().join("sample.docx");
    std::fs::write(&docx_path, sample_docx_package()).unwrap();

    let graph = revx_loader::identify_object_graph(&docx_path, 2, 32).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let auto = ws
        .analyze_object(&docx_path.display().to_string(), None)
        .unwrap()
        .expect("auto openxml analysis");
    assert!(
        auto.analyses
            .iter()
            .any(|analysis| analysis.analyzer == "open_xml_document")
    );

    let analysis = ws
        .analyze_object(
            &docx_path.display().to_string(),
            Some(&[ObjectAnalyzerKind::OpenXmlDocument]),
        )
        .unwrap()
        .expect("docx analysis");
    let openxml = &analysis.analyses[0];
    assert_eq!(openxml.analyzer, "open_xml_document");
    assert_eq!(openxml.status, ObjectAnalysisStatus::Completed);
    assert_eq!(openxml.details["format"], serde_json::json!("docx"));
    assert_eq!(
        openxml.details["package"]["word"]["paragraph_count"],
        serde_json::json!(2)
    );
    assert!(
        openxml.details["package"]["word"]["text_preview"]
            .as_str()
            .unwrap()
            .contains("Hello OpenXML")
    );
    assert_eq!(
        openxml.details["relationships"]["external_count"],
        serde_json::json!(1)
    );
    assert!(
        openxml.details["risk_signals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|signal| signal
                .as_str()
                .unwrap()
                .contains("macro:vba_project:word/vbaProject.bin"))
    );
    assert!(
        openxml.details["risk_signals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|signal| signal.as_str().unwrap().contains("external_relationship"))
    );

    let evidence = ws.export_evidence_by_subject("sample.docx", 10).unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_analysis"
            && item.provenance.source == "open_xml_document"
            && item.id.ends_with(":open_xml_document")
    }));
}

#[test]
fn analyzes_open_xml_workbooks_with_sheet_cells() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let xlsx_path = dir.path().join("sample.xlsx");
    std::fs::write(&xlsx_path, sample_xlsx_package()).unwrap();

    let graph = revx_loader::identify_object_graph(&xlsx_path, 2, 32).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(
            &xlsx_path.display().to_string(),
            Some(&[ObjectAnalyzerKind::OpenXmlDocument]),
        )
        .unwrap()
        .expect("xlsx analysis");
    let openxml = &analysis.analyses[0];
    assert_eq!(openxml.analyzer, "open_xml_document");
    assert_eq!(openxml.status, ObjectAnalysisStatus::Completed);
    assert_eq!(openxml.details["format"], serde_json::json!("xlsx"));
    assert_eq!(
        openxml.details["package"]["workbook"]["sheet_count"],
        serde_json::json!(1)
    );
    assert_eq!(
        openxml.details["package"]["workbook"]["sheets"][0]["name"],
        serde_json::json!("Indicators")
    );
    assert_eq!(
        openxml.details["package"]["workbook"]["sheets"][0]["summary"]["sample_cells"][0]["value"],
        serde_json::json!("Threat")
    );
    assert_eq!(
        openxml.details["package"]["workbook"]["sheets"][0]["summary"]["sample_cells"][1]["formula"],
        serde_json::json!("SUM(1,2)")
    );
    assert_eq!(
        openxml.details["package"]["workbook"]["defined_names"][0]["name"],
        serde_json::json!("Auto_Open")
    );
    assert!(
        openxml.details["risk_signals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|signal| signal.as_str().unwrap() == "defined_name:auto_open")
    );
}

#[test]
fn analyzes_and_materializes_ole_compound_streams() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let ole_path = dir.path().join("legacy.doc");
    std::fs::write(&ole_path, sample_ole_compound_file()).unwrap();

    let graph = revx_loader::identify_object_graph(&ole_path, 2, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(
            &ole_path.display().to_string(),
            Some(&[ObjectAnalyzerKind::OleCompound]),
        )
        .unwrap()
        .expect("ole analysis");
    let ole = &analysis.analyses[0];
    assert_eq!(ole.analyzer, "ole_compound");
    assert_eq!(ole.status, ObjectAnalysisStatus::Completed);
    assert_eq!(ole.details["stream_count"], serde_json::json!(2));
    assert_eq!(
        ole.details["vba_project"]["module_count"],
        serde_json::json!(1)
    );
    assert_eq!(
        ole.details["vba_project"]["decoded_module_count"],
        serde_json::json!(1)
    );
    assert!(
        ole.details["vba_project"]["modules"][0]["source_preview"]
            .as_str()
            .unwrap()
            .contains("CreateObject")
    );
    assert_eq!(ole.details["storage_count"], serde_json::json!(1));
    assert!(
        ole.details["risk_signals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|signal| signal.as_str().unwrap().contains("vba_auto_exec:autoopen"))
    );
    assert!(
        ole.details["risk_signals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|signal| signal
                .as_str()
                .unwrap()
                .contains("vba_behavior:createobject"))
    );

    let materialized = ws
        .materialize_object("VBA/Module1", 128)
        .unwrap()
        .expect("materialized OLE stream");
    assert_eq!(
        materialized.object.metadata["ole_stream_path"],
        "VBA/Module1"
    );
    let artifact_bytes =
        std::fs::read(ws.root().join(&materialized.artifact.relative_path)).unwrap();
    assert_eq!(artifact_bytes, sample_vba_module_source());

    let evidence = ws.export_evidence_by_subject("legacy.doc", 10).unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_analysis"
            && item.provenance.source == "ole_compound"
            && item.id.ends_with(":ole_compound")
    }));
}

#[test]
fn persists_functions_for_lookup() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let binary_id = "binary-1".to_string();
    let bundle = sample_bundle(&binary_id, "/tmp/test.bin");
    let function = bundle.functions[0].clone();

    ws.save_analysis(bundle, AnalysisProfile::Fast).unwrap();
    let functions = ws.list_functions().unwrap();
    assert_eq!(functions.len(), 1);
    assert_eq!(functions[0].address, function.address);
    assert_eq!(functions[0].arguments.len(), 1);
    assert_eq!(functions[0].locals.len(), 1);
    assert!(ws.get_function("sub_test").unwrap().is_some());
    assert!(ws.get_function("0x401000").unwrap().is_some());
    let containing = ws.resolve_function("0x401002").unwrap().unwrap();
    assert_eq!(containing.address, 0x401000);
    assert_eq!(containing.name, "sub_test");
    let refs = ws.find_references("0x401000").unwrap();
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].to, 0x402000);
    let callgraph = ws.callgraph_slice("sub_test").unwrap();
    assert_eq!(callgraph.len(), 1);
    assert_eq!(callgraph[0].caller_name, "sub_test");
    assert_eq!(callgraph[0].callee_address, 0x402000);
    let survey = ws.latest_survey().unwrap().unwrap();
    assert_eq!(survey.summary.function_count, 1);
    assert_eq!(survey.summary.typed_function_count, 1);
    assert_eq!(survey.summary.structured_pseudocode_count, 1);
    assert!(
        ws.root()
            .join("artifacts")
            .read_dir()
            .unwrap()
            .next()
            .is_some()
    );

    let evidence_export = ws
        .export_evidence_ids_by_subject("/tmp/test.bin", 32)
        .unwrap();
    assert_eq!(evidence_export.count, 8);
    assert_eq!(evidence_export.preview_ids.len(), 8);
    for expected in [
        "debug:binary-1:summary",
        "fn:binary-1:401000",
        "pseudo:binary-1:401000",
        "stack:binary-1:401000",
        "str:binary-1:4202496",
        "type:binary-1:type:test:int",
        "vars:binary-1:401000",
        "ref:binary-1:401000:402000:call",
    ] {
        assert!(evidence_export.preview_ids.iter().any(|id| id == expected));
    }
    let artifact_ids: Vec<String> = serde_json::from_str(
        &std::fs::read_to_string(ws.root().join(&evidence_export.artifact.relative_path)).unwrap(),
    )
    .unwrap();
    assert_eq!(artifact_ids.len(), 8);
    for expected in [
        "debug:binary-1:summary",
        "fn:binary-1:401000",
        "pseudo:binary-1:401000",
        "stack:binary-1:401000",
        "str:binary-1:4202496",
        "type:binary-1:type:test:int",
        "vars:binary-1:401000",
        "ref:binary-1:401000:402000:call",
    ] {
        assert!(artifact_ids.iter().any(|id| id == expected));
    }

    let evidence_pack = ws.export_evidence_by_subject("/tmp/test.bin", 50).unwrap();
    assert_eq!(evidence_pack.count, 8);
    assert_eq!(evidence_pack.preview.len(), 8);
    assert!(evidence_pack.artifact.is_none());
}

#[test]
fn function_evidence_ids_resolve_without_full_subject_scan() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let bundle = sample_bundle("binary-2", "/tmp/test-evidence.bin");
    ws.save_analysis(bundle, AnalysisProfile::Fast).unwrap();

    let ids = ws
        .function_evidence_ids("0x401002")
        .unwrap()
        .expect("function evidence ids");
    assert!(ids.iter().any(|id| id == "fn:binary-2:401000"));
}

#[test]
fn evidence_search_matches_kind_details_and_provenance() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let bundle = sample_bundle("binary-5", "/tmp/test-evidence-search.bin");
    ws.save_analysis(bundle, AnalysisProfile::Fast).unwrap();

    let debug = ws
        .export_evidence_by_subject("loader_debug_import", 10)
        .unwrap();
    assert!(
        debug
            .preview
            .iter()
            .any(|item| item.provenance.source == "loader_debug_import")
    );

    let kind = ws
        .export_evidence_by_subject("function_recovery", 10)
        .unwrap();
    assert!(
        kind.preview
            .iter()
            .any(|item| item.kind == "function_recovery")
    );
}

#[test]
fn search_bytes_matches_across_chunk_boundaries() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let binary_path = dir.path().join("boundary.bin");
    let mut bytes = vec![0u8; 65_534];
    bytes.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
    std::fs::write(&binary_path, &bytes).unwrap();

    let bundle = sample_bundle("binary-3", &binary_path.display().to_string());
    ws.save_analysis(bundle, AnalysisProfile::Fast).unwrap();

    let result = ws.search_bytes("aa bb cc dd").unwrap();
    assert_eq!(result.matches.len(), 1);
    assert_eq!(result.matches[0].offset, 65_534);
}

#[test]
fn searches_content_across_persisted_and_virtual_objects() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let archive = dir.path().join("bundle.zip");
    {
        let file = std::fs::File::create(&archive).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("config.json", options).unwrap();
        use std::io::Write;
        zip.write_all(br#"{"token":"NEEDLE_TOKEN","agent":true}"#)
            .unwrap();
        zip.start_file("payload.bin", options).unwrap();
        zip.write_all(&[0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xff])
            .unwrap();
        zip.finish().unwrap();
    }

    let graph = revx_loader::identify_object_graph(&archive, 2, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();

    let text = ws
        .search_object_content(
            "NEEDLE_TOKEN",
            revx_core::ObjectContentSearchMode::Text,
            Some("config.json"),
            10,
            5,
            1024 * 1024,
        )
        .unwrap();
    assert_eq!(text.returned_count, 1);
    assert_eq!(text.matches[0].display_name, "config.json");
    assert!(
        text.matches[0]
            .preview_text
            .as_deref()
            .is_some_and(|preview| preview.contains("NEEDLE_TOKEN"))
    );
    assert!(
        std::fs::metadata(ws.root().join(&text.matches[0].artifact.relative_path))
            .unwrap()
            .is_file()
    );

    let hex = ws
        .search_object_content(
            "aa bb cc dd",
            revx_core::ObjectContentSearchMode::Hex,
            Some("payload.bin"),
            10,
            5,
            1024 * 1024,
        )
        .unwrap();
    assert_eq!(hex.returned_count, 1);
    assert_eq!(hex.matches[0].display_name, "payload.bin");
    assert_eq!(hex.matches[0].offset, 1);
}

#[test]
fn extracts_byte_range_from_virtual_object_as_evidence_artifact() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let archive = dir.path().join("bundle.zip");
    {
        let file = std::fs::File::create(&archive).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        use std::io::Write;
        zip.start_file("payload.bin", options).unwrap();
        zip.write_all(&[0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xff])
            .unwrap();
        zip.finish().unwrap();
    }

    let graph = revx_loader::identify_object_graph(&archive, 2, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();

    let extracted = ws
        .extract_object_range("payload.bin", 1, 3, 1, 16)
        .unwrap()
        .expect("extracted object range");
    assert_eq!(extracted.object.display_name, "payload.bin");
    assert_eq!(extracted.offset, 1);
    assert_eq!(extracted.requested_length, 3);
    assert_eq!(extracted.extracted_offset, 0);
    assert_eq!(extracted.extracted_size, 5);
    assert_eq!(extracted.preview_hex.as_deref(), Some("00aabbccdd"));
    assert!(extracted.source.contains("bundle.zip!/payload.bin"));

    let artifact_bytes = std::fs::read(ws.root().join(&extracted.artifact.relative_path)).unwrap();
    assert_eq!(artifact_bytes, vec![0x00, 0xaa, 0xbb, 0xcc, 0xdd]);

    let evidence = ws.export_evidence_by_subject("payload.bin", 10).unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_range_extraction"
            && item.id == extracted.evidence_id
            && item.provenance.source == "object_extract_range"
    }));
}

#[test]
fn scans_embedded_file_signatures_as_followup_offsets() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let blob = dir.path().join("firmware.blob");
    let embedded_zip = {
        let mut bytes = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut bytes);
            let mut zip = zip::ZipWriter::new(cursor);
            let options = zip::write::SimpleFileOptions::default();
            use std::io::Write;
            zip.start_file("inner.txt", options).unwrap();
            zip.write_all(b"embedded-zip").unwrap();
            zip.finish().unwrap();
        }
        bytes
    };
    let mut bytes = b"noise-prefix".to_vec();
    bytes.extend_from_slice(b"\x7fELF\x02\x01\x01\0embedded");
    bytes.extend_from_slice(b"padding");
    let zip_offset = bytes.len() as u64;
    bytes.extend_from_slice(&embedded_zip);
    std::fs::write(&blob, &bytes).unwrap();

    let graph = revx_loader::identify_object_graph(&blob, 0, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();

    let scanned = ws
        .scan_object_signatures("firmware.blob", 10, 1024 * 1024, 16)
        .unwrap()
        .expect("signature scan");
    assert_eq!(scanned.object.display_name, "firmware.blob");
    assert_eq!(scanned.returned_count, 2);
    assert!(
        scanned
            .signatures
            .iter()
            .any(|hit| hit.format == "elf" && hit.offset == 12)
    );
    let zip_hit = scanned
        .signatures
        .iter()
        .find(|hit| hit.format == "zip")
        .expect("zip signature");
    assert_eq!(zip_hit.offset, zip_offset);
    assert_eq!(zip_hit.suggested_length, Some(embedded_zip.len() as u64));
    assert!(zip_hit.preview_hex.starts_with("504b0304"));

    let extracted = ws
        .extract_object_range(
            "firmware.blob",
            zip_hit.offset,
            zip_hit.suggested_length.unwrap(),
            0,
            16,
        )
        .unwrap()
        .expect("extracted embedded zip");
    let artifact_bytes = std::fs::read(ws.root().join(&extracted.artifact.relative_path)).unwrap();
    assert_eq!(artifact_bytes, embedded_zip);
    assert!(
        std::fs::metadata(ws.root().join(&scanned.artifact.relative_path))
            .unwrap()
            .is_file()
    );

    let evidence = ws.export_evidence_by_subject("firmware.blob", 10).unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_signature_scan"
            && item.id == scanned.evidence_id
            && item.provenance.source == "object_scan_signatures"
    }));
}

#[test]
fn scans_png_signatures_with_exact_extractable_length() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let blob = dir.path().join("image-carrier.blob");
    let png = minimal_png_bytes();
    let mut bytes = b"carrier".to_vec();
    let png_offset = bytes.len() as u64;
    bytes.extend_from_slice(&png);
    bytes.extend_from_slice(b"suffix");
    std::fs::write(&blob, &bytes).unwrap();

    let graph = revx_loader::identify_object_graph(&blob, 0, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();

    let scanned = ws
        .scan_object_signatures("image-carrier.blob", 10, 1024 * 1024, 32)
        .unwrap()
        .expect("signature scan");
    let png_hit = scanned
        .signatures
        .iter()
        .find(|hit| hit.format == "png")
        .expect("png signature");
    assert_eq!(png_hit.offset, png_offset);
    assert_eq!(png_hit.suggested_length, Some(png.len() as u64));

    let extracted = ws
        .extract_object_range(
            "image-carrier.blob",
            png_hit.offset,
            png_hit.suggested_length.unwrap(),
            0,
            16,
        )
        .unwrap()
        .expect("extracted embedded png");
    let artifact_bytes = std::fs::read(ws.root().join(&extracted.artifact.relative_path)).unwrap();
    assert_eq!(artifact_bytes, png);
}

#[test]
fn carves_bounded_embedded_signatures_into_artifacts() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let blob = dir.path().join("carrier.blob");
    let embedded_zip = {
        let mut bytes = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut bytes);
            let mut zip = zip::ZipWriter::new(cursor);
            let options = zip::write::SimpleFileOptions::default();
            use std::io::Write;
            zip.start_file("inner.txt", options).unwrap();
            zip.write_all(b"embedded-zip").unwrap();
            zip.finish().unwrap();
        }
        bytes
    };
    let png = minimal_png_bytes();
    let mut bytes = b"carrier-prefix".to_vec();
    let zip_offset = bytes.len() as u64;
    bytes.extend_from_slice(&embedded_zip);
    bytes.extend_from_slice(b"middle");
    let png_offset = bytes.len() as u64;
    bytes.extend_from_slice(&png);
    bytes.extend_from_slice(b"suffix");
    std::fs::write(&blob, &bytes).unwrap();

    let graph = revx_loader::identify_object_graph(&blob, 0, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();

    let carved = ws
        .carve_object_signatures("carrier.blob", 10, 1024 * 1024, 1024 * 1024, 0.9, 16)
        .unwrap()
        .expect("signature carves");
    assert_eq!(carved.object.display_name, "carrier.blob");
    assert_eq!(carved.carved_count, 2);
    assert_eq!(carved.skipped_count, 0);

    let zip_carve = carved
        .carves
        .iter()
        .find(|carve| carve.format == "zip")
        .expect("zip carve");
    assert_eq!(zip_carve.offset, zip_offset);
    assert_eq!(zip_carve.length, embedded_zip.len() as u64);
    assert_eq!(zip_carve.artifact.content_type, "application/zip");
    assert_eq!(
        std::fs::read(ws.root().join(&zip_carve.artifact.relative_path)).unwrap(),
        embedded_zip
    );

    let png_carve = carved
        .carves
        .iter()
        .find(|carve| carve.format == "png")
        .expect("png carve");
    assert_eq!(png_carve.offset, png_offset);
    assert_eq!(png_carve.length, png.len() as u64);
    assert_eq!(png_carve.artifact.content_type, "image/png");
    assert_eq!(
        std::fs::read(ws.root().join(&png_carve.artifact.relative_path)).unwrap(),
        png
    );

    let evidence = ws.export_evidence_by_subject("carrier.blob", 10).unwrap();
    assert!(evidence.preview.iter().any(|item| {
        item.kind == "object_signature_carve"
            && item.id == carved.carve_evidence_id
            && item.provenance.source == "object_carve_signatures"
    }));
}

#[test]
fn callgraph_slice_resolves_external_callee_without_full_hydration() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let bundle = sample_bundle("binary-4", "/tmp/test-callgraph.bin");
    ws.save_analysis(bundle, AnalysisProfile::Fast).unwrap();

    let edges = ws.callgraph_slice("sub_test").unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].caller_address, 0x401000);
    assert_eq!(edges[0].callee_address, 0x402000);
}

#[test]
fn callgraph_slice_names_import_callees() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let mut bundle = sample_bundle("binary-import-cg", "/tmp/test-callgraph-import.bin");
    bundle.imports = vec![revx_core::Import {
        name: "puts".to_string(),
        address: Some(0x402000),
        library: Some("libc".to_string()),
    }];
    bundle.survey.summary.import_count = 1;
    bundle.survey.binary.import_count = 1;
    ws.save_analysis(bundle, AnalysisProfile::Fast).unwrap();

    let edges = ws.callgraph_slice("sub_test").unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].callee_address, 0x402000);
    assert_eq!(edges[0].callee_name.as_deref(), Some("puts"));
}


fn minimal_png_bytes() -> Vec<u8> {
    let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
    append_png_chunk(
        &mut bytes,
        b"IHDR",
        &[
            0, 0, 0, 1, // width
            0, 0, 0, 1, // height
            8, 2, 0, 0, 0,
        ],
    );
    append_png_chunk(&mut bytes, b"IEND", &[]);
    bytes
}

fn sample_png_with_metadata_and_trailing_zip(embedded_zip: &[u8]) -> Vec<u8> {
    let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
    append_png_chunk(
        &mut bytes,
        b"IHDR",
        &[
            0, 0, 0, 2, // width
            0, 0, 0, 3, // height
            8, 2, 0, 0, 0,
        ],
    );
    append_png_chunk(&mut bytes, b"tEXt", b"Comment\0hidden zip follows");
    append_png_chunk(&mut bytes, b"IDAT", &[0x78, 0x9c, 0x63, 0x00, 0x00]);
    append_png_chunk(&mut bytes, b"IEND", &[]);
    bytes.extend_from_slice(embedded_zip);
    bytes
}

fn append_png_chunk(bytes: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    bytes.extend_from_slice(&(data.len() as u32).to_be_bytes());
    bytes.extend_from_slice(kind);
    bytes.extend_from_slice(data);
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(kind);
    hasher.update(data);
    bytes.extend_from_slice(&hasher.finalize().to_be_bytes());
}

fn sample_jpeg_with_metadata_and_trailing_zip(embedded_zip: &[u8]) -> Vec<u8> {
    let mut bytes = b"\xff\xd8".to_vec();
    append_jpeg_segment(&mut bytes, 0xe0, b"JFIF\0\x01\x02\0\0\x01\0\x01\0\0");
    append_jpeg_segment(&mut bytes, 0xfe, b"hidden jpeg comment");
    append_jpeg_segment(
        &mut bytes,
        0xc0,
        &[8, 0, 5, 0, 4, 3, 1, 0x11, 0, 2, 0x11, 1, 3, 0x11, 1],
    );
    append_jpeg_segment(&mut bytes, 0xda, &[1, 1, 0, 0, 63, 0]);
    bytes.extend_from_slice(&[0x11, 0x22, 0xff, 0x00, 0x33, 0xff, 0xd0, 0x44]);
    bytes.extend_from_slice(b"\xff\xd9");
    bytes.extend_from_slice(embedded_zip);
    bytes
}

fn append_jpeg_segment(bytes: &mut Vec<u8>, marker: u8, payload: &[u8]) {
    bytes.extend_from_slice(&[0xff, marker]);
    bytes.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
    bytes.extend_from_slice(payload);
}

fn sample_gif_with_metadata_and_trailing_zip(embedded_zip: &[u8]) -> Vec<u8> {
    let mut bytes = b"GIF89a".to_vec();
    bytes.extend_from_slice(&4u16.to_le_bytes());
    bytes.extend_from_slice(&5u16.to_le_bytes());
    bytes.extend_from_slice(&[0x80, 0x00, 0x00]);
    bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0xff, 0xff, 0xff]);
    append_gif_extension(&mut bytes, 0xf9, &[0x04, 0x09, 0x0a, 0x00, 0x01]);
    append_gif_extension(&mut bytes, 0xfe, b"hidden gif comment");
    append_gif_extension(&mut bytes, 0xff, b"NETSCAPE2.0\x03\x01\0\0");
    bytes.push(0x2c);
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&4u16.to_le_bytes());
    bytes.extend_from_slice(&5u16.to_le_bytes());
    bytes.push(0x00);
    bytes.push(0x02);
    bytes.extend_from_slice(&[0x02, 0x4c, 0x01, 0x00]);
    bytes.push(0x3b);
    bytes.extend_from_slice(embedded_zip);
    bytes
}

fn sample_ico_with_png_icon(png: &[u8]) -> Vec<u8> {
    let image_offset = 6 + 16;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&[16, 16, 0, 0]);
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&32u16.to_le_bytes());
    bytes.extend_from_slice(&(png.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(image_offset as u32).to_le_bytes());
    bytes.extend_from_slice(png);
    bytes
}

fn sample_bmp_file() -> Vec<u8> {
    let dib = sample_bmp_dib_payload(2, 2);
    let pixel_offset = 14 + dib_header_len(&dib);
    let mut bytes = b"BM".to_vec();
    bytes.extend_from_slice(&((14 + dib.len()) as u32).to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&(pixel_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&dib);
    bytes
}

fn sample_ico_dib_payload() -> Vec<u8> {
    sample_bmp_dib_payload(16, 32)
}

fn sample_bmp_dib_payload(width: i32, height: i32) -> Vec<u8> {
    let row_stride = (((width as usize * 32) + 31) / 32) * 4;
    let pixel_bytes = row_stride * height.unsigned_abs() as usize;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&40u32.to_le_bytes());
    bytes.extend_from_slice(&width.to_le_bytes());
    bytes.extend_from_slice(&height.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&32u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&(pixel_bytes as u32).to_le_bytes());
    bytes.extend_from_slice(&2835i32.to_le_bytes());
    bytes.extend_from_slice(&2835i32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend(std::iter::repeat_n(0x7fu8, pixel_bytes));
    bytes
}

fn dib_header_len(dib: &[u8]) -> usize {
    u32::from_le_bytes([dib[0], dib[1], dib[2], dib[3]]) as usize
}

fn sample_ico_with_dib_icon(dib: &[u8]) -> Vec<u8> {
    let image_offset = 6 + 16;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&[16, 16, 0, 0]);
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&32u16.to_le_bytes());
    bytes.extend_from_slice(&(dib.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(image_offset as u32).to_le_bytes());
    bytes.extend_from_slice(dib);
    bytes
}

fn sample_webp_riff() -> Vec<u8> {
    let mut payload = b"WEBP".to_vec();
    let mut vp8x = vec![0x30, 0, 0, 0];
    vp8x.extend_from_slice(&1u32.to_le_bytes()[..3]);
    vp8x.extend_from_slice(&2u32.to_le_bytes()[..3]);
    append_riff_chunk(&mut payload, b"VP8X", &vp8x);
    append_riff_chunk(&mut payload, b"ICCP", b"abc");
    wrap_riff_payload(payload)
}

fn sample_wav_riff() -> Vec<u8> {
    let mut payload = b"WAVE".to_vec();
    let mut fmt = Vec::new();
    fmt.extend_from_slice(&1u16.to_le_bytes());
    fmt.extend_from_slice(&1u16.to_le_bytes());
    fmt.extend_from_slice(&44_100u32.to_le_bytes());
    fmt.extend_from_slice(&88_200u32.to_le_bytes());
    fmt.extend_from_slice(&2u16.to_le_bytes());
    fmt.extend_from_slice(&16u16.to_le_bytes());
    append_riff_chunk(&mut payload, b"fmt ", &fmt);
    append_riff_chunk(&mut payload, b"data", &[0x00, 0x00, 0xff, 0x7f]);
    wrap_riff_payload(payload)
}

fn wrap_riff_payload(payload: Vec<u8>) -> Vec<u8> {
    let mut bytes = b"RIFF".to_vec();
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&payload);
    bytes
}

fn append_riff_chunk(bytes: &mut Vec<u8>, id: &[u8; 4], data: &[u8]) {
    bytes.extend_from_slice(id);
    bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
    bytes.extend_from_slice(data);
    if data.len() % 2 == 1 {
        bytes.push(0);
    }
}

fn sample_pcap_capture() -> Vec<u8> {
    let packet = sample_ethernet_ipv4_tcp_packet();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    bytes.extend_from_slice(&2u16.to_le_bytes());
    bytes.extend_from_slice(&4u16.to_le_bytes());
    bytes.extend_from_slice(&0i32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&65_535u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&1_700_000_000u32.to_le_bytes());
    bytes.extend_from_slice(&123_456u32.to_le_bytes());
    bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&packet);
    bytes
}

fn sample_pcapng_capture() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x0a0d0d0au32.to_le_bytes());
    bytes.extend_from_slice(&28u32.to_le_bytes());
    bytes.extend_from_slice(&0x1a2b3c4du32.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&(-1i64).to_le_bytes());
    bytes.extend_from_slice(&28u32.to_le_bytes());
    bytes
}

fn sample_docx_package() -> Vec<u8> {
    let cursor = std::io::Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(cursor);
    let options = zip::write::SimpleFileOptions::default();
    use std::io::Write;
    zip.start_file("[Content_Types].xml", options).unwrap();
    zip.write_all(br#"<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
</Types>"#).unwrap();
    zip.start_file("_rels/.rels", options).unwrap();
    zip.write_all(br#"<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rRoot" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"#).unwrap();
    zip.start_file("word/_rels/document.xml.rels", options)
        .unwrap();
    zip.write_all(br#"<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rLink" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.invalid/payload" TargetMode="External"/>
  <Relationship Id="rOle" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="embeddings/oleObject1.bin"/>
</Relationships>"#).unwrap();
    zip.start_file("word/document.xml", options).unwrap();
    zip.write_all(br#"<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <w:body>
    <w:p><w:r><w:t>Hello OpenXML</w:t></w:r></w:p>
    <w:p><w:r><w:t>DDEAUTO suspicious field</w:t></w:r></w:p>
  </w:body>
</w:document>"#).unwrap();
    zip.start_file("word/vbaProject.bin", options).unwrap();
    zip.write_all(b"VBA").unwrap();
    zip.start_file("word/embeddings/oleObject1.bin", options)
        .unwrap();
    zip.write_all(b"OLE").unwrap();
    zip.start_file("docProps/core.xml", options).unwrap();
    zip.write_all(br#"<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>Sample Doc</dc:title><dc:creator>revx</dc:creator></cp:coreProperties>"#).unwrap();
    zip.finish().unwrap().into_inner()
}

fn sample_xlsx_package() -> Vec<u8> {
    let cursor = std::io::Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(cursor);
    let options = zip::write::SimpleFileOptions::default();
    use std::io::Write;
    zip.start_file("[Content_Types].xml", options).unwrap();
    zip.write_all(br#"<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>"#).unwrap();
    zip.start_file("_rels/.rels", options).unwrap();
    zip.write_all(br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rRoot" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>"#).unwrap();
    zip.start_file("xl/_rels/workbook.xml.rels", options)
        .unwrap();
    zip.write_all(br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rSheet1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>"#).unwrap();
    zip.start_file("xl/workbook.xml", options).unwrap();
    zip.write_all(br#"<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Indicators" sheetId="1" r:id="rSheet1"/></sheets><definedNames><definedName name="Auto_Open">Sheet1!$A$1</definedName></definedNames></workbook>"#).unwrap();
    zip.start_file("xl/sharedStrings.xml", options).unwrap();
    zip.write_all(br#"<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="1" uniqueCount="1"><si><t>Threat</t></si></sst>"#).unwrap();
    zip.start_file("xl/worksheets/sheet1.xml", options).unwrap();
    zip.write_all(br#"<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><dimension ref="A1:B1"/><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1"><f>SUM(1,2)</f><v>3</v></c></row></sheetData></worksheet>"#).unwrap();
    zip.finish().unwrap().into_inner()
}

fn sample_android_package() -> Vec<u8> {
    let cursor = std::io::Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(cursor);
    let options = zip::write::SimpleFileOptions::default();
    use std::io::Write;
    zip.start_file("AndroidManifest.xml", options).unwrap();
    zip.write_all(
        br#"<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.agent" android:versionCode="7" android:versionName="1.2.3">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/>
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.READ_SMS"/>
  <application android:label="Agent" android:debuggable="true" android:allowBackup="true" android:usesCleartextTraffic="true">
    <activity android:name=".MainActivity" android:exported="true"/>
    <service android:name=".SyncService" android:exported="false"/>
    <receiver android:name=".BootReceiver" android:exported="true" android:permission="android.permission.RECEIVE_BOOT_COMPLETED"/>
  </application>
</manifest>"#,
    )
    .unwrap();
    zip.start_file("classes.dex", options).unwrap();
    zip.write_all(&sample_dex_header()).unwrap();
    zip.start_file("lib/arm64-v8a/libnative.so", options)
        .unwrap();
    zip.write_all(b"\x7fELF\x02\x01\x01\x00native").unwrap();
    zip.start_file("res/xml/network_security_config.xml", options)
        .unwrap();
    zip.write_all(br#"<network-security-config/>"#).unwrap();
    zip.start_file("assets/config.json", options).unwrap();
    zip.write_all(br#"{"endpoint":"https://example.invalid"}"#)
        .unwrap();
    zip.start_file("META-INF/MANIFEST.MF", options).unwrap();
    zip.write_all(b"Manifest-Version: 1.0\r\n").unwrap();
    zip.start_file("META-INF/CERT.SF", options).unwrap();
    zip.write_all(b"Signature-Version: 1.0\r\n").unwrap();
    zip.start_file("META-INF/CERT.RSA", options).unwrap();
    zip.write_all(b"signature").unwrap();
    zip.finish().unwrap().into_inner()
}

fn sample_ios_package() -> Vec<u8> {
    let cursor = std::io::Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(cursor);
    let options = zip::write::SimpleFileOptions::default();
    use std::io::Write;
    zip.start_file("Payload/Example.app/Info.plist", options)
        .unwrap();
    zip.write_all(
        br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.example.ios</string>
  <key>CFBundleName</key><string>Example</string>
  <key>CFBundleDisplayName</key><string>Example App</string>
  <key>CFBundleExecutable</key><string>Example</string>
  <key>CFBundleShortVersionString</key><string>1.2.3</string>
  <key>CFBundleVersion</key><string>7</string>
  <key>MinimumOSVersion</key><string>15.0</string>
  <key>DTSDKName</key><string>iphoneos17.0</string>
  <key>CFBundleSupportedPlatforms</key><array><string>iPhoneOS</string></array>
  <key>CFBundleURLTypes</key><array><dict><key>CFBundleURLSchemes</key><array><string>example</string></array></dict></array>
  <key>UIBackgroundModes</key><array><string>audio</string></array>
  <key>NSCameraUsageDescription</key><string>Camera</string>
  <key>LSApplicationQueriesSchemes</key><array><string>fb</string></array>
  <key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict>
</dict></plist>"#,
    )
    .unwrap();
    zip.start_file("Payload/Example.app/Example", options)
        .unwrap();
    zip.write_all(&sample_macho_header()).unwrap();
    zip.start_file(
        "Payload/Example.app/Frameworks/ExampleKit.framework/ExampleKit",
        options,
    )
    .unwrap();
    zip.write_all(&sample_macho_header()).unwrap();
    zip.start_file(
        "Payload/Example.app/PlugIns/Share.appex/Info.plist",
        options,
    )
    .unwrap();
    zip.write_all(br#"<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.example.ios.share</string></dict></plist>"#)
        .unwrap();
    zip.start_file("Payload/Example.app/_CodeSignature/CodeResources", options)
        .unwrap();
    zip.write_all(b"codesign").unwrap();
    zip.start_file("Payload/Example.app/embedded.mobileprovision", options)
        .unwrap();
    zip.write_all(b"mobileprovision").unwrap();
    zip.finish().unwrap().into_inner()
}

fn sample_macho_header() -> Vec<u8> {
    vec![
        0xcf, 0xfa, 0xed, 0xfe, // MH_MAGIC_64 little-endian
        0x0c, 0x00, 0x00, 0x01, // CPU_TYPE_ARM64
        0x00, 0x00, 0x00, 0x00, // CPU subtype
        0x02, 0x00, 0x00, 0x00, // MH_EXECUTE
        0x00, 0x00, 0x00, 0x00, // ncmds
        0x00, 0x00, 0x00, 0x00, // sizeofcmds
        0x00, 0x00, 0x00, 0x00, // flags
        0x00, 0x00, 0x00, 0x00, // reserved
    ]
}

fn sample_java_archive() -> Vec<u8> {
    let cursor = std::io::Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(cursor);
    let options = zip::write::SimpleFileOptions::default();
    use std::io::Write;
    zip.start_file("META-INF/MANIFEST.MF", options).unwrap();
    zip.write_all(
        b"Manifest-Version: 1.0\r\nMain-Class: com.example.Main\r\nPremain-Class: com.example.Agent\r\nClass-Path: lib/dependency.jar\r\nMulti-Release: true\r\nAutomatic-Module-Name: com.example.plugin\r\n\r\n",
    )
    .unwrap();
    zip.start_file("com/example/Main.class", options).unwrap();
    zip.write_all(&sample_java_class_header(61)).unwrap();
    zip.start_file("com/example/Agent.class", options).unwrap();
    zip.write_all(&sample_java_class_header(61)).unwrap();
    zip.start_file("META-INF/services/com.example.Plugin", options)
        .unwrap();
    zip.write_all(b"com.example.Plugin\n").unwrap();
    zip.start_file("META-INF/versions/17/com/example/Main.class", options)
        .unwrap();
    zip.write_all(&sample_java_class_header(61)).unwrap();
    zip.start_file("native/libplugin.so", options).unwrap();
    zip.write_all(b"\x7fELF\x02\x01\x01\x00native").unwrap();
    zip.start_file("lib/dependency.jar", options).unwrap();
    zip.write_all(&sample_embedded_zip("nested.txt", b"nested jar"))
        .unwrap();
    zip.start_file("META-INF/CERT.SF", options).unwrap();
    zip.write_all(b"Signature-Version: 1.0\r\n").unwrap();
    zip.start_file("META-INF/CERT.RSA", options).unwrap();
    zip.write_all(b"signature").unwrap();
    zip.finish().unwrap().into_inner()
}

fn sample_shell_link() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x4c];
    put_u32(&mut bytes, 0, 0x4c);
    bytes[4..20].copy_from_slice(&[
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ]);
    put_u32(&mut bytes, 20, 0x0000_00ba);
    put_u32(&mut bytes, 24, 0x20);
    put_u32(&mut bytes, 60, 1);

    let link_info = sample_shell_link_info();
    bytes.extend_from_slice(&link_info);
    append_lnk_string(&mut bytes, "powershell.exe");
    append_lnk_string(&mut bytes, "%TEMP%");
    append_lnk_string(
        &mut bytes,
        "-NoP -EncodedCommand SQBFAFgA http://example.invalid/payload",
    );
    append_lnk_environment_block(
        &mut bytes,
        "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\run.lnk",
    );
    append_u32(&mut bytes, 0);
    bytes
}

fn sample_safetensors_model() -> Vec<u8> {
    let tensors = [
        ("model.embed_tokens.weight", "F16", vec![2, 3], 12usize),
        (
            "model.layers.0.self_attn.q_proj.weight",
            "F32",
            vec![2, 2],
            16usize,
        ),
        ("adapter.lora_A.weight", "F16", vec![1, 2], 4usize),
    ];
    let mut offset = 0usize;
    let mut entries = Vec::new();
    for (name, dtype, shape, byte_len) in tensors {
        let start = offset;
        offset += byte_len;
        entries.push((name, dtype, shape, start, offset));
    }
    let mut header = serde_json::Map::new();
    header.insert(
        "__metadata__".to_string(),
        serde_json::json!({
            "format": "pt",
            "adapter": "lora",
            "source": "unit-test",
        }),
    );
    for (name, dtype, shape, start, end) in entries {
        header.insert(
            name.to_string(),
            serde_json::json!({
                "dtype": dtype,
                "shape": shape,
                "data_offsets": [start, end],
            }),
        );
    }
    let header_bytes = serde_json::to_vec(&serde_json::Value::Object(header)).unwrap();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(header_bytes.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&header_bytes);
    bytes.extend(std::iter::repeat_n(0x42u8, offset));
    bytes
}

fn sample_safetensors_index() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "metadata": {
            "total_size": 32,
        },
        "weight_map": {
            "model.embed_tokens.weight": "model-00001-of-00002.safetensors",
            "model.layers.0.self_attn.q_proj.weight": "model-00002-of-00002.safetensors",
            "adapter.lora_A.weight": "model-00002-of-00002.safetensors",
        },
    }))
    .unwrap()
}

fn sample_gguf_model() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"GGUF");
    append_u32(&mut bytes, 3);
    append_u64(&mut bytes, 2);
    append_u64(&mut bytes, 4);
    append_gguf_string(&mut bytes, "general.architecture");
    append_u32(&mut bytes, 8);
    append_gguf_string(&mut bytes, "llama");
    append_gguf_string(&mut bytes, "general.name");
    append_u32(&mut bytes, 8);
    append_gguf_string(&mut bytes, "Tiny LoRA");
    append_gguf_string(&mut bytes, "general.alignment");
    append_u32(&mut bytes, 4);
    append_u32(&mut bytes, 32);
    append_gguf_string(&mut bytes, "tokenizer.ggml.tokens");
    append_u32(&mut bytes, 9);
    append_u32(&mut bytes, 8);
    append_u64(&mut bytes, 2);
    append_gguf_string(&mut bytes, "<s>");
    append_gguf_string(&mut bytes, "</s>");
    append_gguf_tensor(&mut bytes, "token_embd.weight", &[2, 3], 1, 0);
    append_gguf_tensor(&mut bytes, "adapter.lora_A.weight", &[1, 2], 2, 32);
    while bytes.len() % 32 != 0 {
        bytes.push(0);
    }
    bytes.extend(std::iter::repeat_n(0x44u8, 64));
    bytes
}

fn sample_pytorch_zip_model() -> Vec<u8> {
    let cursor = std::io::Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(cursor);
    let options: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default();
    zip.start_file("archive/data.pkl", options).unwrap();
    zip.write_all(sample_pickle_payload().as_slice()).unwrap();
    zip.start_file("archive/version", options).unwrap();
    zip.write_all(b"3\n").unwrap();
    zip.start_file("archive/byteorder", options).unwrap();
    zip.write_all(b"little").unwrap();
    zip.start_file("archive/data/0", options).unwrap();
    zip.write_all(&[0u8; 16]).unwrap();
    zip.finish().unwrap().into_inner()
}

fn sample_pickle_payload() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0x80, 0x02]);
    bytes.extend_from_slice(b"ctorch._utils\n_rebuild_tensor_v2\n");
    bytes.extend_from_slice(b"U\x07storage");
    bytes.push(b'R');
    bytes.push(b'.');
    bytes
}

fn append_gguf_tensor(
    bytes: &mut Vec<u8>,
    name: &str,
    shape: &[u64],
    tensor_type: u32,
    offset: u64,
) {
    append_gguf_string(bytes, name);
    append_u32(bytes, shape.len() as u32);
    for dim in shape {
        append_u64(bytes, *dim);
    }
    append_u32(bytes, tensor_type);
    append_u64(bytes, offset);
}

fn append_gguf_string(bytes: &mut Vec<u8>, value: &str) {
    append_u64(bytes, value.len() as u64);
    bytes.extend_from_slice(value.as_bytes());
}

fn sample_shell_link_info() -> Vec<u8> {
    let mut info = vec![0u8; 36];
    let common_network_offset = 36u32;
    let network = sample_shell_link_network();
    let suffix_offset = common_network_offset + network.len() as u32;
    let suffix = b"payload.exe\0";
    let suffix_unicode_offset = suffix_offset + suffix.len() as u32;
    let suffix_unicode = utf16le_null("payload.exe");
    info.extend_from_slice(&network);
    info.extend_from_slice(suffix);
    info.extend_from_slice(&suffix_unicode);
    let info_size = info.len() as u32;
    put_u32(&mut info, 0, info_size);
    put_u32(&mut info, 4, 36);
    put_u32(&mut info, 8, 0x2);
    put_u32(&mut info, 20, common_network_offset);
    put_u32(&mut info, 24, suffix_offset);
    put_u32(&mut info, 32, suffix_unicode_offset);
    info
}

fn sample_shell_link_network() -> Vec<u8> {
    let mut network = vec![0u8; 28];
    let net_name_offset = 28u32;
    let net_name = b"\\\\fileserver\\share\0";
    let net_name_unicode_offset = net_name_offset + net_name.len() as u32;
    let net_name_unicode = utf16le_null("\\\\fileserver\\share");
    network.extend_from_slice(net_name);
    network.extend_from_slice(&net_name_unicode);
    let network_size = network.len() as u32;
    put_u32(&mut network, 0, network_size);
    put_u32(&mut network, 4, 0x2);
    put_u32(&mut network, 8, net_name_offset);
    put_u32(&mut network, 16, 0x0020_0000);
    put_u32(&mut network, 20, net_name_unicode_offset);
    network
}

fn append_lnk_string(bytes: &mut Vec<u8>, value: &str) {
    let units = value.encode_utf16().collect::<Vec<_>>();
    append_u16(bytes, units.len() as u16);
    for unit in units {
        append_u16(bytes, unit);
    }
}

fn append_lnk_environment_block(bytes: &mut Vec<u8>, value: &str) {
    let size = 0x314usize;
    let start = bytes.len();
    bytes.resize(start + size, 0);
    put_u32(bytes, start, size as u32);
    put_u32(bytes, start + 4, 0xa000_0001);
    let ansi = value.as_bytes();
    bytes[start + 8..start + 8 + ansi.len()].copy_from_slice(ansi);
    let unicode = value.encode_utf16().collect::<Vec<_>>();
    for (index, unit) in unicode.iter().take(259).enumerate() {
        let offset = start + 268 + index * 2;
        bytes[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
    }
}

fn utf16le_null(value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for unit in value.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn sample_portable_executable() -> Vec<u8> {
    const PE_OFFSET: usize = 0x80;
    const OPTIONAL_HEADER_SIZE: usize = 0xf0;
    const SECTION_TABLE_OFFSET: usize = PE_OFFSET + 24 + OPTIONAL_HEADER_SIZE;
    const TEXT_RAW: usize = 0x400;
    const IDATA_RAW: usize = 0x600;
    const EDATA_RAW: usize = 0x800;
    const TEXT_RVA: u32 = 0x1000;
    const IDATA_RVA: u32 = 0x2000;
    const EDATA_RVA: u32 = 0x3000;

    let mut bytes = vec![0u8; 0xa00];
    bytes[0..2].copy_from_slice(b"MZ");
    put_u32(&mut bytes, 0x3c, PE_OFFSET as u32);
    bytes[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

    let coff = PE_OFFSET + 4;
    put_u16(&mut bytes, coff, 0x8664);
    put_u16(&mut bytes, coff + 2, 3);
    put_u32(&mut bytes, coff + 4, 1_700_000_000);
    put_u16(&mut bytes, coff + 16, OPTIONAL_HEADER_SIZE as u16);
    put_u16(&mut bytes, coff + 18, 0x0022);

    let opt = PE_OFFSET + 24;
    put_u16(&mut bytes, opt, 0x20b);
    bytes[opt + 2] = 14;
    put_u32(&mut bytes, opt + 16, TEXT_RVA);
    put_u32(&mut bytes, opt + 20, TEXT_RVA);
    put_u64(&mut bytes, opt + 24, 0x1400_0000);
    put_u32(&mut bytes, opt + 32, 0x1000);
    put_u32(&mut bytes, opt + 36, 0x200);
    put_u16(&mut bytes, opt + 40, 6);
    put_u16(&mut bytes, opt + 48, 6);
    put_u32(&mut bytes, opt + 56, 0x5000);
    put_u32(&mut bytes, opt + 60, 0x400);
    put_u16(&mut bytes, opt + 68, 3);
    put_u16(&mut bytes, opt + 70, 0x0140);
    put_u64(&mut bytes, opt + 72, 0x100000);
    put_u64(&mut bytes, opt + 80, 0x1000);
    put_u64(&mut bytes, opt + 88, 0x100000);
    put_u64(&mut bytes, opt + 96, 0x1000);
    put_u32(&mut bytes, opt + 108, 16);

    let dirs = opt + 112;
    put_data_directory(&mut bytes, dirs, 0, EDATA_RVA, 0x80);
    put_data_directory(&mut bytes, dirs, 1, IDATA_RVA, 0x100);
    put_data_directory(&mut bytes, dirs, 2, 0x4000, 0x40);
    put_data_directory(&mut bytes, dirs, 5, 0x4100, 0x20);
    put_data_directory(&mut bytes, dirs, 6, 0x4200, 0x1c);
    put_data_directory(&mut bytes, dirs, 9, 0x4300, 0x28);

    write_section_header(
        &mut bytes,
        SECTION_TABLE_OFFSET,
        ".text",
        0x200,
        TEXT_RVA,
        0x200,
        TEXT_RAW as u32,
        0xe000_0020,
    );
    write_section_header(
        &mut bytes,
        SECTION_TABLE_OFFSET + 40,
        ".idata",
        0x200,
        IDATA_RVA,
        0x200,
        IDATA_RAW as u32,
        0x4000_0040,
    );
    write_section_header(
        &mut bytes,
        SECTION_TABLE_OFFSET + 80,
        ".edata",
        0x200,
        EDATA_RVA,
        0x200,
        EDATA_RAW as u32,
        0x4000_0040,
    );

    bytes[TEXT_RAW..TEXT_RAW + 6].copy_from_slice(&[0x48, 0x83, 0xec, 0x28, 0xc3, 0x90]);

    put_import_descriptor(
        &mut bytes,
        IDATA_RAW,
        IDATA_RVA + 0x60,
        IDATA_RVA + 0xa0,
        IDATA_RVA + 0x40,
    );
    put_import_descriptor(
        &mut bytes,
        IDATA_RAW + 20,
        IDATA_RVA + 0x70,
        IDATA_RVA + 0xc0,
        IDATA_RVA + 0x4d,
    );
    write_c_string(&mut bytes, IDATA_RAW + 0x40, b"KERNEL32.dll");
    write_c_string(&mut bytes, IDATA_RAW + 0x4d, b"WININET.dll");
    put_u64(&mut bytes, IDATA_RAW + 0x60, (IDATA_RVA + 0xd0) as u64);
    put_u64(&mut bytes, IDATA_RAW + 0x68, 0);
    put_u64(&mut bytes, IDATA_RAW + 0x70, (IDATA_RVA + 0xe0) as u64);
    put_u64(&mut bytes, IDATA_RAW + 0x78, 0);
    put_u16(&mut bytes, IDATA_RAW + 0xd0, 0);
    write_c_string(&mut bytes, IDATA_RAW + 0xd2, b"VirtualAlloc");
    put_u16(&mut bytes, IDATA_RAW + 0xe0, 0);
    write_c_string(&mut bytes, IDATA_RAW + 0xe2, b"InternetOpenUrlA");
    put_u64(&mut bytes, IDATA_RAW + 0xa0, (IDATA_RVA + 0xd0) as u64);
    put_u64(&mut bytes, IDATA_RAW + 0xa8, 0);
    put_u64(&mut bytes, IDATA_RAW + 0xc0, (IDATA_RVA + 0xe0) as u64);
    put_u64(&mut bytes, IDATA_RAW + 0xc8, 0);

    put_u32(&mut bytes, EDATA_RAW + 12, EDATA_RVA + 0x60);
    put_u32(&mut bytes, EDATA_RAW + 16, 1);
    put_u32(&mut bytes, EDATA_RAW + 20, 1);
    put_u32(&mut bytes, EDATA_RAW + 24, 1);
    put_u32(&mut bytes, EDATA_RAW + 28, EDATA_RVA + 0x40);
    put_u32(&mut bytes, EDATA_RAW + 32, EDATA_RVA + 0x44);
    put_u32(&mut bytes, EDATA_RAW + 36, EDATA_RVA + 0x48);
    put_u32(&mut bytes, EDATA_RAW + 0x40, TEXT_RVA);
    put_u32(&mut bytes, EDATA_RAW + 0x44, EDATA_RVA + 0x6a);
    put_u16(&mut bytes, EDATA_RAW + 0x48, 0);
    write_c_string(&mut bytes, EDATA_RAW + 0x60, b"agent.dll");
    write_c_string(&mut bytes, EDATA_RAW + 0x6a, b"RunAgent");
    bytes.extend_from_slice(b"OVERLAY:agent configuration");
    bytes
}

fn sample_dotnet_pe() -> Vec<u8> {
    const PE_OFFSET: usize = 0x80;
    const OPTIONAL_HEADER_SIZE: usize = 0xf0;
    const SECTION_TABLE_OFFSET: usize = PE_OFFSET + 24 + OPTIONAL_HEADER_SIZE;
    const TEXT_RAW: usize = 0x400;
    const TEXT_RVA: u32 = 0x2000;
    const CLR_HEADER_RVA: u32 = TEXT_RVA + 0x80;
    const CLR_HEADER_RAW: usize = TEXT_RAW + 0x80;
    const METADATA_RVA: u32 = TEXT_RVA + 0x100;
    const METADATA_RAW: usize = TEXT_RAW + 0x100;
    const RESOURCES_RVA: u32 = TEXT_RVA + 0x700;
    const RESOURCES_RAW: usize = TEXT_RAW + 0x700;

    let metadata = sample_dotnet_metadata_root();
    let payload = b"%PDF-1.4\n%revx-dotnet-resource\ntrailer\n<<>>\nstartxref\n0\n%%EOF\n";
    let resource_blob_len = 4 + payload.len();
    let mut bytes = vec![0u8; 0x1200];
    bytes[0..2].copy_from_slice(b"MZ");
    put_u32(&mut bytes, 0x3c, PE_OFFSET as u32);
    bytes[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

    let coff = PE_OFFSET + 4;
    put_u16(&mut bytes, coff, 0x8664);
    put_u16(&mut bytes, coff + 2, 1);
    put_u32(&mut bytes, coff + 4, 1_700_000_100);
    put_u16(&mut bytes, coff + 16, OPTIONAL_HEADER_SIZE as u16);
    put_u16(&mut bytes, coff + 18, 0x0022);

    let opt = PE_OFFSET + 24;
    put_u16(&mut bytes, opt, 0x20b);
    bytes[opt + 2] = 14;
    put_u32(&mut bytes, opt + 16, TEXT_RVA + 0x300);
    put_u32(&mut bytes, opt + 20, TEXT_RVA);
    put_u64(&mut bytes, opt + 24, 0x1800_0000);
    put_u32(&mut bytes, opt + 32, 0x1000);
    put_u32(&mut bytes, opt + 36, 0x200);
    put_u16(&mut bytes, opt + 40, 6);
    put_u16(&mut bytes, opt + 48, 6);
    put_u32(&mut bytes, opt + 56, 0x4000);
    put_u32(&mut bytes, opt + 60, 0x400);
    put_u16(&mut bytes, opt + 68, 3);
    put_u16(&mut bytes, opt + 70, 0x0140);
    put_u64(&mut bytes, opt + 72, 0x100000);
    put_u64(&mut bytes, opt + 80, 0x1000);
    put_u64(&mut bytes, opt + 88, 0x100000);
    put_u64(&mut bytes, opt + 96, 0x1000);
    put_u32(&mut bytes, opt + 108, 16);

    let dirs = opt + 112;
    put_data_directory(&mut bytes, dirs, 14, CLR_HEADER_RVA, 0x48);

    write_section_header(
        &mut bytes,
        SECTION_TABLE_OFFSET,
        ".text",
        0xe00,
        TEXT_RVA,
        0xe00,
        TEXT_RAW as u32,
        0x6000_0020,
    );

    put_u32(&mut bytes, CLR_HEADER_RAW, 0x48);
    put_u16(&mut bytes, CLR_HEADER_RAW + 4, 2);
    put_u16(&mut bytes, CLR_HEADER_RAW + 6, 5);
    put_u32(&mut bytes, CLR_HEADER_RAW + 8, METADATA_RVA);
    put_u32(&mut bytes, CLR_HEADER_RAW + 12, metadata.len() as u32);
    put_u32(&mut bytes, CLR_HEADER_RAW + 16, 0x1);
    put_u32(&mut bytes, CLR_HEADER_RAW + 20, 0x0600_0001);
    put_u32(&mut bytes, CLR_HEADER_RAW + 24, RESOURCES_RVA);
    put_u32(&mut bytes, CLR_HEADER_RAW + 28, resource_blob_len as u32);
    bytes[METADATA_RAW..METADATA_RAW + metadata.len()].copy_from_slice(&metadata);
    put_u32(&mut bytes, RESOURCES_RAW, payload.len() as u32);
    bytes[RESOURCES_RAW + 4..RESOURCES_RAW + 4 + payload.len()].copy_from_slice(payload);
    bytes
}

fn sample_dotnet_metadata_root() -> Vec<u8> {
    let mut strings = vec![0u8];
    let module_name = add_dotnet_string(&mut strings, "ReVX.Agent");
    let module_type_name = add_dotnet_string(&mut strings, "<Module>");
    let agent_name = add_dotnet_string(&mut strings, "Agent");
    let example_namespace = add_dotnet_string(&mut strings, "Example");
    let run_name = add_dotnet_string(&mut strings, "Run");
    let diagnostics_namespace = add_dotnet_string(&mut strings, "System.Diagnostics");
    let process_name = add_dotnet_string(&mut strings, "Process");
    let start_name = add_dotnet_string(&mut strings, "Start");
    let net_http_namespace = add_dotnet_string(&mut strings, "System.Net.Http");
    let http_client_name = add_dotnet_string(&mut strings, "HttpClient");
    let get_async_name = add_dotnet_string(&mut strings, "GetAsync");
    let reflection_namespace = add_dotnet_string(&mut strings, "System.Reflection");
    let assembly_name = add_dotnet_string(&mut strings, "Assembly");
    let system_namespace = add_dotnet_string(&mut strings, "System");
    let object_name = add_dotnet_string(&mut strings, "Object");
    let system_runtime_name = add_dotnet_string(&mut strings, "System.Runtime");
    let system_net_http_name = add_dotnet_string(&mut strings, "System.Net.Http");
    add_dotnet_string(&mut strings, "System.Runtime.InteropServices.Marshal");
    add_dotnet_string(&mut strings, "DllImport");
    add_dotnet_string(&mut strings, "NativeLibrary.Load");
    add_dotnet_string(&mut strings, "Assembly.Load");
    add_dotnet_string(&mut strings, "Type.GetType");
    add_dotnet_string(&mut strings, "Activator.CreateInstance");
    let payload_resource_name = add_dotnet_string(&mut strings, "Example.Agent.payload.pdf");
    let kernel32_name = add_dotnet_string(&mut strings, "KERNEL32.dll");
    let virtual_alloc_name = add_dotnet_string(&mut strings, "VirtualAlloc");

    let mut tables = Vec::new();
    append_u32(&mut tables, 0);
    tables.push(2);
    tables.push(0);
    tables.push(0);
    tables.push(1);
    let valid_mask = (1u64 << 0)
        | (1u64 << 1)
        | (1u64 << 2)
        | (1u64 << 6)
        | (1u64 << 10)
        | (1u64 << 26)
        | (1u64 << 28)
        | (1u64 << 32)
        | (1u64 << 35)
        | (1u64 << 40);
    append_u64(&mut tables, valid_mask);
    append_u64(&mut tables, 0);
    // Module, TypeRef, TypeDef, MethodDef, MemberRef, ModuleRef, ImplMap, Assembly, AssemblyRef, ManifestResource
    for rows in [1u32, 4, 2, 1, 2, 1, 1, 1, 2, 1] {
        append_u32(&mut tables, rows);
    }

    append_u16(&mut tables, 0);
    append_u16(&mut tables, module_name);
    append_u16(&mut tables, 1);
    append_u16(&mut tables, 0);
    append_u16(&mut tables, 0);

    append_u16(&mut tables, (1 << 2) | 2);
    append_u16(&mut tables, process_name);
    append_u16(&mut tables, diagnostics_namespace);
    append_u16(&mut tables, (2 << 2) | 2);
    append_u16(&mut tables, http_client_name);
    append_u16(&mut tables, net_http_namespace);
    append_u16(&mut tables, (1 << 2) | 2);
    append_u16(&mut tables, assembly_name);
    append_u16(&mut tables, reflection_namespace);
    append_u16(&mut tables, (1 << 2) | 2);
    append_u16(&mut tables, object_name);
    append_u16(&mut tables, system_namespace);

    append_u32(&mut tables, 0);
    append_u16(&mut tables, module_type_name);
    append_u16(&mut tables, 0);
    append_u16(&mut tables, 0);
    append_u16(&mut tables, 1);
    append_u16(&mut tables, 1);
    append_u32(&mut tables, 0x0010_0001);
    append_u16(&mut tables, agent_name);
    append_u16(&mut tables, example_namespace);
    append_u16(&mut tables, (4 << 2) | 1);
    append_u16(&mut tables, 1);
    append_u16(&mut tables, 1);

    append_u32(&mut tables, 0x2300);
    append_u16(&mut tables, 0);
    append_u16(&mut tables, 0x0096);
    append_u16(&mut tables, run_name);
    append_u16(&mut tables, 0);
    append_u16(&mut tables, 1);

    append_u16(&mut tables, (1 << 3) | 1);
    append_u16(&mut tables, start_name);
    append_u16(&mut tables, 0);
    append_u16(&mut tables, (2 << 3) | 1);
    append_u16(&mut tables, get_async_name);
    append_u16(&mut tables, 0);

    // ModuleRef row 1
    append_u16(&mut tables, kernel32_name);

    // ImplMap row 1: MappingFlags, MemberForwarded(MethodDef#1), ImportName, ImportScope(ModuleRef#1)
    append_u16(&mut tables, 0x0001); // NoMangle
    append_u16(&mut tables, (1 << 1) | 1); // MethodDef tag=1, row=1
    append_u16(&mut tables, virtual_alloc_name);
    append_u16(&mut tables, 1); // ModuleRef #1

    append_u32(&mut tables, 0x0000_8004);
    append_u16(&mut tables, 1);
    append_u16(&mut tables, 0);
    append_u16(&mut tables, 0);
    append_u16(&mut tables, 0);
    append_u32(&mut tables, 0);
    append_u16(&mut tables, 0);
    append_u16(&mut tables, module_name);
    append_u16(&mut tables, 0);

    for name in [system_runtime_name, system_net_http_name] {
        append_u16(&mut tables, 8);
        append_u16(&mut tables, 0);
        append_u16(&mut tables, 0);
        append_u16(&mut tables, 0);
        append_u32(&mut tables, 0);
        append_u16(&mut tables, 0);
        append_u16(&mut tables, name);
        append_u16(&mut tables, 0);
        append_u16(&mut tables, 0);
    }

    append_u32(&mut tables, 0);
    append_u32(&mut tables, 0x1);
    append_u16(&mut tables, payload_resource_name);
    append_u16(&mut tables, 0);

    let streams = vec![
        ("#~", tables),
        ("#Strings", strings),
        ("#GUID", vec![0x42u8; 16]),
        ("#Blob", vec![0u8]),
        ("#US", vec![0, 57, 104, 0, 116, 0, 116, 0, 112, 0, 115, 0, 58, 0, 47, 0, 47, 0, 114, 0, 101, 0, 118, 0, 120, 0, 46, 0, 101, 0, 120, 0, 97, 0, 109, 0, 112, 0, 108, 0, 101, 0, 47, 0, 112, 0, 97, 0, 121, 0, 108, 0, 111, 0, 97, 0, 100, 0, 0]),
    ];
    let mut metadata = Vec::new();
    metadata.extend_from_slice(b"BSJB");
    append_u16(&mut metadata, 1);
    append_u16(&mut metadata, 1);
    append_u32(&mut metadata, 0);
    let version = b"v4.0.30319\0\0";
    append_u32(&mut metadata, version.len() as u32);
    metadata.extend_from_slice(version);
    while metadata.len() % 4 != 0 {
        metadata.push(0);
    }
    append_u16(&mut metadata, 0);
    append_u16(&mut metadata, streams.len() as u16);

    let stream_header_size = streams
        .iter()
        .map(|(name, _)| 8 + align4_len(name.len() + 1))
        .sum::<usize>();
    let mut data_offset = align4_len(metadata.len() + stream_header_size);
    let mut descriptors = Vec::new();
    for (_, data) in &streams {
        descriptors.push((data_offset, data.len()));
        data_offset = align4_len(data_offset + data.len());
    }
    for ((name, _), (offset, size)) in streams.iter().zip(descriptors.iter()) {
        append_u32(&mut metadata, *offset as u32);
        append_u32(&mut metadata, *size as u32);
        metadata.extend_from_slice(name.as_bytes());
        metadata.push(0);
        while metadata.len() % 4 != 0 {
            metadata.push(0);
        }
    }
    if let Some((first_offset, _)) = descriptors.first() {
        while metadata.len() < *first_offset {
            metadata.push(0);
        }
    }
    for ((_, data), (offset, _)) in streams.iter().zip(descriptors.iter()) {
        while metadata.len() < *offset {
            metadata.push(0);
        }
        metadata.extend_from_slice(data);
        while metadata.len() % 4 != 0 {
            metadata.push(0);
        }
    }
    metadata
}

fn sample_elf_binary() -> Vec<u8> {
    const PHOFF: usize = 0x40;
    const PHENTSIZE: usize = 56;
    const PHNUM: usize = 5;
    const INTERP_OFF: usize = 0x200;
    const DYNAMIC_OFF: usize = 0x280;
    const DYNSTR_OFF: usize = 0x340;
    const DYNSYM_OFF: usize = 0x380;
    const SHSTRTAB_OFF: usize = 0x500;
    const SHOFF: usize = 0x600;
    const BASE_VADDR: u64 = 0x400000;

    let mut bytes = vec![0u8; 0x800];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[7] = 3;
    put_u16(&mut bytes, 16, 3);
    put_u16(&mut bytes, 18, 62);
    put_u32(&mut bytes, 20, 1);
    put_u64(&mut bytes, 24, BASE_VADDR + 0x120);
    put_u64(&mut bytes, 32, PHOFF as u64);
    put_u64(&mut bytes, 40, SHOFF as u64);
    put_u16(&mut bytes, 52, 64);
    put_u16(&mut bytes, 54, PHENTSIZE as u16);
    put_u16(&mut bytes, 56, PHNUM as u16);
    put_u16(&mut bytes, 58, 64);
    put_u16(&mut bytes, 60, 6);
    put_u16(&mut bytes, 62, 5);

    write_elf_program_header(
        &mut bytes, PHOFF, 1, 0x7, 0, BASE_VADDR, BASE_VADDR, 0x580, 0x580, 0x1000,
    );
    write_elf_program_header(
        &mut bytes,
        PHOFF + PHENTSIZE,
        3,
        0x4,
        INTERP_OFF as u64,
        BASE_VADDR + INTERP_OFF as u64,
        BASE_VADDR + INTERP_OFF as u64,
        0x1c,
        0x1c,
        1,
    );
    write_elf_program_header(
        &mut bytes,
        PHOFF + PHENTSIZE * 2,
        2,
        0x6,
        DYNAMIC_OFF as u64,
        BASE_VADDR + DYNAMIC_OFF as u64,
        BASE_VADDR + DYNAMIC_OFF as u64,
        0x80,
        0x80,
        8,
    );
    write_elf_program_header(
        &mut bytes,
        PHOFF + PHENTSIZE * 3,
        0x6474_e551,
        0x6,
        0,
        0,
        0,
        0,
        0,
        16,
    );
    write_elf_program_header(
        &mut bytes,
        PHOFF + PHENTSIZE * 4,
        0x6474_e552,
        0x4,
        DYNAMIC_OFF as u64,
        BASE_VADDR + DYNAMIC_OFF as u64,
        BASE_VADDR + DYNAMIC_OFF as u64,
        0x80,
        0x80,
        8,
    );

    write_c_string(&mut bytes, INTERP_OFF, b"/lib64/ld-linux-x86-64.so.2");
    write_c_string(&mut bytes, DYNSTR_OFF, b"");
    write_c_string(&mut bytes, DYNSTR_OFF + 1, b"libc.so.6");
    write_c_string(&mut bytes, DYNSTR_OFF + 11, b"mprotect");
    write_c_string(&mut bytes, DYNSTR_OFF + 20, b"dlopen");
    write_c_string(&mut bytes, DYNSTR_OFF + 27, b"agent_symbol");

    put_u64(&mut bytes, DYNAMIC_OFF, 1);
    put_u64(&mut bytes, DYNAMIC_OFF + 8, 1);
    put_u64(&mut bytes, DYNAMIC_OFF + 16, 5);
    put_u64(&mut bytes, DYNAMIC_OFF + 24, BASE_VADDR + DYNSTR_OFF as u64);
    put_u64(&mut bytes, DYNAMIC_OFF + 32, 6);
    put_u64(&mut bytes, DYNAMIC_OFF + 40, BASE_VADDR + DYNSYM_OFF as u64);
    put_u64(&mut bytes, DYNAMIC_OFF + 48, 10);
    put_u64(&mut bytes, DYNAMIC_OFF + 56, 64);
    put_u64(&mut bytes, DYNAMIC_OFF + 64, 0);
    put_u64(&mut bytes, DYNAMIC_OFF + 72, 0);

    write_elf_symbol(&mut bytes, DYNSYM_OFF + 24, 11, 0x12, 0, 0, 0, 0);
    write_elf_symbol(&mut bytes, DYNSYM_OFF + 48, 20, 0x12, 0, 0, 0, 0);
    write_elf_symbol(
        &mut bytes,
        DYNSYM_OFF + 72,
        27,
        0x12,
        0,
        1,
        BASE_VADDR + 0x120,
        8,
    );

    let shstr = b"\0.interp\0.dynamic\0.dynstr\0.dynsym\0.shstrtab\0";
    bytes[SHSTRTAB_OFF..SHSTRTAB_OFF + shstr.len()].copy_from_slice(shstr);
    write_elf_section_header(
        &mut bytes,
        SHOFF + 64,
        1,
        1,
        0x2,
        BASE_VADDR + INTERP_OFF as u64,
        INTERP_OFF as u64,
        0x1c,
        0,
        0,
        1,
        0,
    );
    write_elf_section_header(
        &mut bytes,
        SHOFF + 128,
        9,
        6,
        0x3,
        BASE_VADDR + DYNAMIC_OFF as u64,
        DYNAMIC_OFF as u64,
        0x50,
        3,
        0,
        8,
        16,
    );
    write_elf_section_header(
        &mut bytes,
        SHOFF + 192,
        18,
        3,
        0x2,
        BASE_VADDR + DYNSTR_OFF as u64,
        DYNSTR_OFF as u64,
        0x60,
        0,
        0,
        1,
        0,
    );
    write_elf_section_header(
        &mut bytes,
        SHOFF + 256,
        26,
        11,
        0x2,
        BASE_VADDR + DYNSYM_OFF as u64,
        DYNSYM_OFF as u64,
        0x60,
        3,
        1,
        8,
        24,
    );
    write_elf_section_header(
        &mut bytes,
        SHOFF + 320,
        34,
        3,
        0,
        0,
        SHSTRTAB_OFF as u64,
        shstr.len() as u64,
        0,
        0,
        1,
        0,
    );
    bytes
}

fn sample_macho_fat() -> Vec<u8> {
    let arm = sample_macho_binary();
    let mut x64 = sample_macho_binary();
    // mark second slice as x86_64
    put_u32(&mut x64, 4, 0x0100_0007);

    let mut bytes = vec![0u8; 0x1000];
    // fat magic
    put_u32_be(&mut bytes, 0, 0xcafebabe);
    put_u32_be(&mut bytes, 4, 2);

    // arch0 arm64 @ 0x1000 would overflow; place slices at 0x100 and 0x600
    // fat_arch 20 bytes each
    // arch0
    put_u32_be(&mut bytes, 8, 0x0100_000c); // CPU_TYPE_ARM64
    put_u32_be(&mut bytes, 12, 0);
    put_u32_be(&mut bytes, 16, 0x100);
    put_u32_be(&mut bytes, 20, arm.len() as u32);
    put_u32_be(&mut bytes, 24, 0);
    // arch1
    put_u32_be(&mut bytes, 28, 0x0100_0007); // CPU_TYPE_X86_64
    put_u32_be(&mut bytes, 32, 0);
    put_u32_be(&mut bytes, 36, 0x600);
    put_u32_be(&mut bytes, 40, x64.len() as u32);
    put_u32_be(&mut bytes, 44, 0);

    if 0x100 + arm.len() > bytes.len() || 0x600 + x64.len() > bytes.len() {
        let need = (0x600 + x64.len()).max(0x100 + arm.len());
        bytes.resize(need, 0);
        put_u32_be(&mut bytes, 0, 0xcafebabe);
        put_u32_be(&mut bytes, 4, 2);
        put_u32_be(&mut bytes, 8, 0x0100_000c);
        put_u32_be(&mut bytes, 12, 0);
        put_u32_be(&mut bytes, 16, 0x100);
        put_u32_be(&mut bytes, 20, arm.len() as u32);
        put_u32_be(&mut bytes, 24, 0);
        put_u32_be(&mut bytes, 28, 0x0100_0007);
        put_u32_be(&mut bytes, 32, 0);
        put_u32_be(&mut bytes, 36, 0x600);
        put_u32_be(&mut bytes, 40, x64.len() as u32);
        put_u32_be(&mut bytes, 44, 0);
    }
    bytes[0x100..0x100 + arm.len()].copy_from_slice(&arm);
    bytes[0x600..0x600 + x64.len()].copy_from_slice(&x64);
    bytes
}

fn put_u32_be(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn sample_macho_binary() -> Vec<u8> {
    let segment_text_size = 72 + 80;
    let segment_data_size = 72 + 80;
    let dylib_size = align8(24 + "/usr/lib/libSystem.B.dylib".len() + 1);
    let rpath_size = align8(12 + "@executable_path/Frameworks".len() + 1);
    let command_sizes = [
        segment_text_size,
        segment_data_size,
        dylib_size,
        rpath_size,
        48,
        24,
        24,
        16,
        16,
        24,
    ];
    let sizeofcmds: usize = command_sizes.iter().sum();
    let mut bytes = vec![0u8; 32 + sizeofcmds + 0x200];
    put_u32(&mut bytes, 0, 0xfeedfacf);
    put_u32(&mut bytes, 4, 0x0100_000c);
    put_u32(&mut bytes, 8, 0);
    put_u32(&mut bytes, 12, 2);
    put_u32(&mut bytes, 16, command_sizes.len() as u32);
    put_u32(&mut bytes, 20, sizeofcmds as u32);
    put_u32(&mut bytes, 24, 0x20_0085);
    put_u32(&mut bytes, 28, 0);

    let mut cursor = 32;
    write_macho_segment64(
        &mut bytes,
        cursor,
        "__TEXT",
        0x100000000,
        0x1000,
        0,
        0x1000,
        0x5,
        0x5,
        0,
        &[("__text", "__TEXT", 0x100000100, 0x20, 0x100, 0x8000_0400)],
    );
    cursor += segment_text_size;
    write_macho_segment64(
        &mut bytes,
        cursor,
        "__DATA",
        0x100001000,
        0x1000,
        0x1000,
        0x1000,
        0x7,
        0x7,
        0,
        &[("__mod_init_func", "__DATA", 0x100001100, 0x8, 0x1100, 0x9)],
    );
    cursor += segment_data_size;
    write_macho_dylib_command(&mut bytes, cursor, 0xc, "/usr/lib/libSystem.B.dylib");
    cursor += dylib_size;
    write_macho_rpath_command(&mut bytes, cursor, "@executable_path/Frameworks");
    cursor += rpath_size;
    write_macho_dyld_info_command(&mut bytes, cursor);
    cursor += 48;
    put_u32(&mut bytes, cursor, 0x24);
    put_u32(&mut bytes, cursor + 4, 24);
    put_u64(&mut bytes, cursor + 8, 0x100);
    put_u64(&mut bytes, cursor + 16, 0);
    cursor += 24;
    put_u32(&mut bytes, cursor, 0x29);
    put_u32(&mut bytes, cursor + 4, 16);
    put_u32(&mut bytes, cursor + 8, (32 + sizeofcmds + 0x80) as u32);
    put_u32(&mut bytes, cursor + 12, 0x40);
    cursor += 16;
    put_u32(&mut bytes, cursor, 0x26);
    put_u32(&mut bytes, cursor + 4, 16);
    put_u32(&mut bytes, cursor + 8, (32 + sizeofcmds + 0x40) as u32);
    put_u32(&mut bytes, cursor + 12, 0x10);
    cursor += 16;
    put_u32(&mut bytes, cursor, 0x32);
    put_u32(&mut bytes, cursor + 4, 24);
    put_u32(&mut bytes, cursor + 8, 2);
    put_u32(&mut bytes, cursor + 12, 0x000f_0000);
    put_u32(&mut bytes, cursor + 16, 0x0011_0000);
    put_u32(&mut bytes, cursor + 20, 0);
    cursor += 24;
    put_u32(&mut bytes, cursor, 0x1b);
    put_u32(&mut bytes, cursor + 4, 24);
    bytes[cursor + 8..cursor + 24].copy_from_slice(&[
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ]);
    bytes
}

fn write_macho_segment64(
    bytes: &mut [u8],
    offset: usize,
    name: &str,
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    maxprot: u32,
    initprot: u32,
    flags: u32,
    sections: &[(&str, &str, u64, u64, u32, u32)],
) {
    put_u32(bytes, offset, 0x19);
    put_u32(bytes, offset + 4, (72 + sections.len() * 80) as u32);
    write_fixed_name(bytes, offset + 8, 16, name);
    put_u64(bytes, offset + 24, vmaddr);
    put_u64(bytes, offset + 32, vmsize);
    put_u64(bytes, offset + 40, fileoff);
    put_u64(bytes, offset + 48, filesize);
    put_u32(bytes, offset + 56, maxprot);
    put_u32(bytes, offset + 60, initprot);
    put_u32(bytes, offset + 64, sections.len() as u32);
    put_u32(bytes, offset + 68, flags);
    for (index, (sectname, segname, addr, size, file_offset, flags)) in sections.iter().enumerate()
    {
        let section_offset = offset + 72 + index * 80;
        write_fixed_name(bytes, section_offset, 16, sectname);
        write_fixed_name(bytes, section_offset + 16, 16, segname);
        put_u64(bytes, section_offset + 32, *addr);
        put_u64(bytes, section_offset + 40, *size);
        put_u32(bytes, section_offset + 48, *file_offset);
        put_u32(bytes, section_offset + 52, 3);
        put_u32(bytes, section_offset + 64, *flags);
    }
}

fn write_macho_dylib_command(bytes: &mut [u8], offset: usize, command: u32, name: &str) {
    let size = align8(24 + name.len() + 1);
    put_u32(bytes, offset, command);
    put_u32(bytes, offset + 4, size as u32);
    put_u32(bytes, offset + 8, 24);
    put_u32(bytes, offset + 12, 0);
    put_u32(bytes, offset + 16, 0);
    put_u32(bytes, offset + 20, 0);
    write_c_string(bytes, offset + 24, name.as_bytes());
}

fn write_macho_rpath_command(bytes: &mut [u8], offset: usize, path: &str) {
    let size = align8(12 + path.len() + 1);
    put_u32(bytes, offset, 0x8000_001c);
    put_u32(bytes, offset + 4, size as u32);
    put_u32(bytes, offset + 8, 12);
    write_c_string(bytes, offset + 12, path.as_bytes());
}

fn write_macho_dyld_info_command(bytes: &mut [u8], offset: usize) {
    put_u32(bytes, offset, 0x22);
    put_u32(bytes, offset + 4, 48);
    put_u32(bytes, offset + 8, 0x1200);
    put_u32(bytes, offset + 12, 0x10);
    put_u32(bytes, offset + 16, 0x1210);
    put_u32(bytes, offset + 20, 0x20);
    put_u32(bytes, offset + 24, 0);
    put_u32(bytes, offset + 28, 0);
    put_u32(bytes, offset + 32, 0x1230);
    put_u32(bytes, offset + 36, 0x18);
    put_u32(bytes, offset + 40, 0x1248);
    put_u32(bytes, offset + 44, 0x30);
}

fn write_fixed_name(bytes: &mut [u8], offset: usize, width: usize, value: &str) {
    let src = value.as_bytes();
    let len = src.len().min(width);
    bytes[offset..offset + width].fill(0);
    bytes[offset..offset + len].copy_from_slice(&src[..len]);
}

fn align8(value: usize) -> usize {
    (value + 7) & !7
}

fn write_elf_program_header(
    bytes: &mut [u8],
    offset: usize,
    p_type: u32,
    flags: u32,
    file_offset: u64,
    vaddr: u64,
    paddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
) {
    put_u32(bytes, offset, p_type);
    put_u32(bytes, offset + 4, flags);
    put_u64(bytes, offset + 8, file_offset);
    put_u64(bytes, offset + 16, vaddr);
    put_u64(bytes, offset + 24, paddr);
    put_u64(bytes, offset + 32, filesz);
    put_u64(bytes, offset + 40, memsz);
    put_u64(bytes, offset + 48, align);
}

fn write_elf_section_header(
    bytes: &mut [u8],
    offset: usize,
    name: u32,
    sh_type: u32,
    flags: u64,
    address: u64,
    file_offset: u64,
    size: u64,
    link: u32,
    info: u32,
    align: u64,
    entry_size: u64,
) {
    put_u32(bytes, offset, name);
    put_u32(bytes, offset + 4, sh_type);
    put_u64(bytes, offset + 8, flags);
    put_u64(bytes, offset + 16, address);
    put_u64(bytes, offset + 24, file_offset);
    put_u64(bytes, offset + 32, size);
    put_u32(bytes, offset + 40, link);
    put_u32(bytes, offset + 44, info);
    put_u64(bytes, offset + 48, align);
    put_u64(bytes, offset + 56, entry_size);
}

fn write_elf_symbol(
    bytes: &mut [u8],
    offset: usize,
    name: u32,
    info: u8,
    other: u8,
    section_index: u16,
    value: u64,
    size: u64,
) {
    put_u32(bytes, offset, name);
    bytes[offset + 4] = info;
    bytes[offset + 5] = other;
    put_u16(bytes, offset + 6, section_index);
    put_u64(bytes, offset + 8, value);
    put_u64(bytes, offset + 16, size);
}

fn write_section_header(
    bytes: &mut [u8],
    offset: usize,
    name: &str,
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_pointer: u32,
    characteristics: u32,
) {
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(8);
    bytes[offset..offset + name_len].copy_from_slice(&name_bytes[..name_len]);
    put_u32(bytes, offset + 8, virtual_size);
    put_u32(bytes, offset + 12, virtual_address);
    put_u32(bytes, offset + 16, raw_size);
    put_u32(bytes, offset + 20, raw_pointer);
    put_u32(bytes, offset + 36, characteristics);
}

fn put_data_directory(bytes: &mut [u8], base: usize, index: usize, rva: u32, size: u32) {
    let offset = base + index * 8;
    put_u32(bytes, offset, rva);
    put_u32(bytes, offset + 4, size);
}

fn put_import_descriptor(
    bytes: &mut [u8],
    offset: usize,
    original_first_thunk: u32,
    first_thunk: u32,
    name_rva: u32,
) {
    put_u32(bytes, offset, original_first_thunk);
    put_u32(bytes, offset + 12, name_rva);
    put_u32(bytes, offset + 16, first_thunk);
}

fn write_c_string(bytes: &mut [u8], offset: usize, value: &[u8]) {
    bytes[offset..offset + value.len()].copy_from_slice(value);
    bytes[offset + value.len()] = 0;
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn append_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn append_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn append_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn align4_len(value: usize) -> usize {
    (value + 3) & !3
}

fn add_dotnet_string(heap: &mut Vec<u8>, value: &str) -> u16 {
    let offset = heap.len();
    heap.extend_from_slice(value.as_bytes());
    heap.push(0);
    offset as u16
}

fn sample_java_class_header(major_version: u16) -> Vec<u8> {
    let mut bytes = vec![0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00];
    bytes.extend_from_slice(&major_version.to_be_bytes());
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes
}

fn sample_jvm_class() -> Vec<u8> {
    let mut cp = Vec::new();
    cp_utf8(&mut cp, "com/example/Agent"); // 1
    cp_class(&mut cp, 1); // 2
    cp_utf8(&mut cp, "java/lang/Object"); // 3
    cp_class(&mut cp, 3); // 4
    cp_utf8(&mut cp, "run"); // 5
    cp_utf8(&mut cp, "()V"); // 6
    cp_utf8(&mut cp, "<clinit>"); // 7
    cp_utf8(&mut cp, "Code"); // 8
    cp_utf8(&mut cp, "java/lang/Runtime"); // 9
    cp_class(&mut cp, 9); // 10
    cp_utf8(&mut cp, "exec"); // 11
    cp_utf8(&mut cp, "(Ljava/lang/String;)Ljava/lang/Process;"); // 12
    cp_name_and_type(&mut cp, 11, 12); // 13
    cp_methodref(&mut cp, 10, 13); // 14
    cp_utf8(&mut cp, "java/lang/System"); // 15
    cp_class(&mut cp, 15); // 16
    cp_utf8(&mut cp, "loadLibrary"); // 17
    cp_utf8(&mut cp, "(Ljava/lang/String;)V"); // 18
    cp_name_and_type(&mut cp, 17, 18); // 19
    cp_methodref(&mut cp, 16, 19); // 20
    cp_utf8(&mut cp, "https://c2.example.invalid/stage"); // 21
    cp_string(&mut cp, 21); // 22
    cp_utf8(&mut cp, "/bin/sh"); // 23
    cp_string(&mut cp, 23); // 24

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
    push_be_u16(&mut bytes, 0);
    push_be_u16(&mut bytes, 61);
    push_be_u16(&mut bytes, 25);
    bytes.extend_from_slice(&cp);
    push_be_u16(&mut bytes, 0x0021);
    push_be_u16(&mut bytes, 2);
    push_be_u16(&mut bytes, 4);
    push_be_u16(&mut bytes, 0);
    push_be_u16(&mut bytes, 0);
    push_be_u16(&mut bytes, 2);
    write_jvm_method(&mut bytes, 0x0009, 5, 6, 8);
    write_jvm_method(&mut bytes, 0x0008, 7, 6, 8);
    push_be_u16(&mut bytes, 0);
    bytes
}

fn write_jvm_method(
    bytes: &mut Vec<u8>,
    access_flags: u16,
    name_index: u16,
    descriptor_index: u16,
    code_name_index: u16,
) {
    push_be_u16(bytes, access_flags);
    push_be_u16(bytes, name_index);
    push_be_u16(bytes, descriptor_index);
    push_be_u16(bytes, 1);
    push_be_u16(bytes, code_name_index);
    let mut code = Vec::new();
    push_be_u16(&mut code, 1);
    push_be_u16(&mut code, 1);
    push_be_u32(&mut code, 1);
    code.push(0xb1);
    push_be_u16(&mut code, 0);
    push_be_u16(&mut code, 0);
    push_be_u32(bytes, code.len() as u32);
    bytes.extend_from_slice(&code);
}

fn cp_utf8(bytes: &mut Vec<u8>, value: &str) {
    bytes.push(1);
    push_be_u16(bytes, value.len() as u16);
    bytes.extend_from_slice(value.as_bytes());
}

fn cp_class(bytes: &mut Vec<u8>, name_index: u16) {
    bytes.push(7);
    push_be_u16(bytes, name_index);
}

fn cp_string(bytes: &mut Vec<u8>, string_index: u16) {
    bytes.push(8);
    push_be_u16(bytes, string_index);
}

fn cp_name_and_type(bytes: &mut Vec<u8>, name_index: u16, descriptor_index: u16) {
    bytes.push(12);
    push_be_u16(bytes, name_index);
    push_be_u16(bytes, descriptor_index);
}

fn cp_methodref(bytes: &mut Vec<u8>, class_index: u16, name_and_type_index: u16) {
    bytes.push(10);
    push_be_u16(bytes, class_index);
    push_be_u16(bytes, name_and_type_index);
}

fn push_be_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn push_be_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn sample_dex_header() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x70];
    let file_size = bytes.len() as u32;
    bytes[0..8].copy_from_slice(b"dex\n035\0");
    write_le_u32(&mut bytes, 32, file_size);
    write_le_u32(&mut bytes, 36, 0x70);
    write_le_u32(&mut bytes, 40, 0x1234_5678);
    write_le_u32(&mut bytes, 56, 5);
    write_le_u32(&mut bytes, 64, 4);
    write_le_u32(&mut bytes, 72, 2);
    write_le_u32(&mut bytes, 80, 1);
    write_le_u32(&mut bytes, 88, 3);
    write_le_u32(&mut bytes, 96, 1);
    write_le_u32(&mut bytes, 104, 16);
    bytes
}

fn sample_dex_bytecode() -> Vec<u8> {
    let strings = [
        "Lcom/example/Agent;",
        "Ljava/lang/Object;",
        "Ljava/lang/String;",
        "Ljava/lang/Runtime;",
        "Ljava/lang/Process;",
        "V",
        "run",
        "exec",
        "<init>",
        "()V",
        "Ljava/lang/String;Ljava/lang/Process;",
        "https://c2.example.invalid/stage",
        "/system/bin/sh",
    ];
    let type_string_indices = [0usize, 1, 2, 3, 4, 5];
    let string_ids_off = 0x70usize;
    let type_ids_off = string_ids_off + strings.len() * 4;
    let proto_ids_off = type_ids_off + type_string_indices.len() * 4;
    let field_ids_off = proto_ids_off + 2 * 12;
    let method_ids_off = field_ids_off;
    let class_defs_off = method_ids_off + 3 * 8;
    let data_off = align4(class_defs_off + 32);
    let mut bytes = vec![0u8; data_off];

    let mut string_offsets = Vec::new();
    for value in strings {
        string_offsets.push(bytes.len() as u32);
        write_dex_string_data(&mut bytes, value);
    }
    let proto_params_off = align4(bytes.len());
    bytes.resize(proto_params_off, 0);
    let proto_params_off = bytes.len();
    write_le_u32_vec(&mut bytes, 1);
    write_le_u16_vec(&mut bytes, 2);
    let class_data_off = bytes.len();
    write_uleb128(&mut bytes, 0);
    write_uleb128(&mut bytes, 0);
    write_uleb128(&mut bytes, 1);
    write_uleb128(&mut bytes, 1);
    write_uleb128(&mut bytes, 0);
    write_uleb128(&mut bytes, 0x10001);
    write_uleb128(&mut bytes, 0);
    write_uleb128(&mut bytes, 1);
    write_uleb128(&mut bytes, 0x1);
    write_uleb128(&mut bytes, 0);
    let file_size = bytes.len() as u32;

    bytes[0..8].copy_from_slice(b"dex\n035\0");
    write_le_u32(&mut bytes, 32, file_size);
    write_le_u32(&mut bytes, 36, 0x70);
    write_le_u32(&mut bytes, 40, 0x1234_5678);
    write_le_u32(&mut bytes, 56, strings.len() as u32);
    write_le_u32(&mut bytes, 60, string_ids_off as u32);
    write_le_u32(&mut bytes, 64, type_string_indices.len() as u32);
    write_le_u32(&mut bytes, 68, type_ids_off as u32);
    write_le_u32(&mut bytes, 72, 2);
    write_le_u32(&mut bytes, 76, proto_ids_off as u32);
    write_le_u32(&mut bytes, 80, 0);
    write_le_u32(&mut bytes, 84, field_ids_off as u32);
    write_le_u32(&mut bytes, 88, 3);
    write_le_u32(&mut bytes, 92, method_ids_off as u32);
    write_le_u32(&mut bytes, 96, 1);
    write_le_u32(&mut bytes, 100, class_defs_off as u32);
    write_le_u32(&mut bytes, 104, (file_size as usize - data_off) as u32);
    write_le_u32(&mut bytes, 108, data_off as u32);

    for (index, offset) in string_offsets.iter().enumerate() {
        write_le_u32(&mut bytes, string_ids_off + index * 4, *offset);
    }
    for (index, string_index) in type_string_indices.iter().enumerate() {
        write_le_u32(&mut bytes, type_ids_off + index * 4, *string_index as u32);
    }
    write_le_u32(&mut bytes, proto_ids_off, 9);
    write_le_u32(&mut bytes, proto_ids_off + 4, 5);
    write_le_u32(&mut bytes, proto_ids_off + 8, 0);
    write_le_u32(&mut bytes, proto_ids_off + 12, 10);
    write_le_u32(&mut bytes, proto_ids_off + 16, 4);
    write_le_u32(&mut bytes, proto_ids_off + 20, proto_params_off as u32);
    write_dex_method_id(&mut bytes, method_ids_off, 0, 0, 8);
    write_dex_method_id(&mut bytes, method_ids_off + 8, 0, 0, 6);
    write_dex_method_id(&mut bytes, method_ids_off + 16, 3, 1, 7);
    write_le_u32(&mut bytes, class_defs_off, 0);
    write_le_u32(&mut bytes, class_defs_off + 4, 0x1);
    write_le_u32(&mut bytes, class_defs_off + 8, 1);
    write_le_u32(&mut bytes, class_defs_off + 12, 0);
    write_le_u32(&mut bytes, class_defs_off + 16, 0xffff_ffff);
    write_le_u32(&mut bytes, class_defs_off + 20, 0);
    write_le_u32(&mut bytes, class_defs_off + 24, class_data_off as u32);
    write_le_u32(&mut bytes, class_defs_off + 28, 0);
    bytes
}

fn write_dex_method_id(
    bytes: &mut [u8],
    offset: usize,
    class_idx: u16,
    proto_idx: u16,
    name_idx: u32,
) {
    write_le_u16(bytes, offset, class_idx);
    write_le_u16(bytes, offset + 2, proto_idx);
    write_le_u32(bytes, offset + 4, name_idx);
}

fn write_dex_string_data(bytes: &mut Vec<u8>, value: &str) {
    write_uleb128(bytes, value.chars().count() as u32);
    bytes.extend_from_slice(value.as_bytes());
    bytes.push(0);
}

fn write_uleb128(bytes: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        bytes.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn write_le_u16_vec(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn write_le_u32_vec(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn sample_ole_compound_file() -> Vec<u8> {
    const SECTOR_SIZE: usize = 512;
    let mut bytes = vec![0u8; SECTOR_SIZE * 5];
    bytes[0..8].copy_from_slice(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1");
    write_le_u16(&mut bytes, 24, 0x003e);
    write_le_u16(&mut bytes, 26, 0x0003);
    write_le_u16(&mut bytes, 28, 0xfffe);
    write_le_u16(&mut bytes, 30, 9);
    write_le_u16(&mut bytes, 32, 6);
    write_le_u32(&mut bytes, 40, 0);
    write_le_u32(&mut bytes, 44, 1);
    write_le_u32(&mut bytes, 48, 0);
    write_le_u32(&mut bytes, 56, 4096);
    write_le_u32(&mut bytes, 60, 3);
    write_le_u32(&mut bytes, 64, 1);
    write_le_u32(&mut bytes, 68, 0xffff_fffe);
    write_le_u32(&mut bytes, 72, 0);
    write_le_u32(&mut bytes, 76, 1);
    for index in 1..109 {
        write_le_u32(&mut bytes, 76 + index * 4, 0xffff_ffff);
    }

    let fat_offset = SECTOR_SIZE * 2;
    for index in 0..(SECTOR_SIZE / 4) {
        write_le_u32(&mut bytes, fat_offset + index * 4, 0xffff_ffff);
    }
    write_le_u32(&mut bytes, fat_offset, 0xffff_fffe);
    write_le_u32(&mut bytes, fat_offset + 4, 0xffff_fffd);
    write_le_u32(&mut bytes, fat_offset + 8, 0xffff_fffe);
    write_le_u32(&mut bytes, fat_offset + 12, 0xffff_fffe);

    let mini_fat_offset = SECTOR_SIZE * 4;
    for index in 0..(SECTOR_SIZE / 4) {
        write_le_u32(&mut bytes, mini_fat_offset + index * 4, 0xffff_ffff);
    }
    write_le_u32(&mut bytes, mini_fat_offset, 0xffff_fffe);
    write_le_u32(&mut bytes, mini_fat_offset + 4, 2);
    write_le_u32(&mut bytes, mini_fat_offset + 8, 0xffff_fffe);

    let directory_offset = SECTOR_SIZE;
    let dir_stream = sample_vba_dir_stream();
    let module_source = sample_vba_module_source();
    assert!(dir_stream.len() <= 64);
    assert!(module_source.len() <= 128);
    write_cfb_dir_entry(
        &mut bytes[directory_offset..directory_offset + 128],
        "Root Entry",
        5,
        0xffff_ffff,
        0xffff_ffff,
        1,
        2,
        192,
    );
    write_cfb_dir_entry(
        &mut bytes[directory_offset + 128..directory_offset + 256],
        "VBA",
        1,
        0xffff_ffff,
        3,
        2,
        0xffff_fffe,
        0,
    );
    write_cfb_dir_entry(
        &mut bytes[directory_offset + 256..directory_offset + 384],
        "dir",
        2,
        0xffff_ffff,
        3,
        0xffff_ffff,
        0,
        dir_stream.len() as u64,
    );
    write_cfb_dir_entry(
        &mut bytes[directory_offset + 384..directory_offset + 512],
        "Module1",
        2,
        0xffff_ffff,
        0xffff_ffff,
        0xffff_ffff,
        1,
        module_source.len() as u64,
    );
    let root_stream_offset = SECTOR_SIZE * 3;
    bytes[root_stream_offset..root_stream_offset + dir_stream.len()].copy_from_slice(&dir_stream);
    bytes[root_stream_offset + 64..root_stream_offset + 64 + module_source.len()]
        .copy_from_slice(module_source);
    bytes
}

fn sample_vba_dir_stream() -> Vec<u8> {
    let mut bytes = Vec::new();
    push_vba_record(&mut bytes, 0x0019, b"Module1");
    push_vba_record(&mut bytes, 0x0032, b"Module1");
    push_vba_record(&mut bytes, 0x0031, &0u32.to_le_bytes());
    push_vba_record(&mut bytes, 0x002b, &[]);
    bytes
}

fn push_vba_record(bytes: &mut Vec<u8>, record_id: u16, data: &[u8]) {
    bytes.extend_from_slice(&record_id.to_le_bytes());
    bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
    bytes.extend_from_slice(data);
}

fn sample_vba_module_source() -> &'static [u8] {
    b"Attribute VB_Name = \"Module1\"\r\nSub AutoOpen()\r\nCreateObject(\"WScript.Shell\").Run \"cmd.exe /c calc\"\r\nEnd Sub\r\n"
}

fn write_cfb_dir_entry(
    entry: &mut [u8],
    name: &str,
    object_type: u8,
    left: u32,
    right: u32,
    child: u32,
    start_sector: u32,
    stream_size: u64,
) {
    let mut utf16 = name.encode_utf16().collect::<Vec<_>>();
    utf16.push(0);
    for (index, unit) in utf16.iter().take(32).enumerate() {
        entry[index * 2..index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
    }
    write_le_u16(entry, 64, (utf16.len().min(32) * 2) as u16);
    entry[66] = object_type;
    entry[67] = 1;
    write_le_u32(entry, 68, left);
    write_le_u32(entry, 72, right);
    write_le_u32(entry, 76, child);
    write_le_u32(entry, 116, start_sector);
    write_le_u64(entry, 120, stream_size);
}

fn write_le_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_le_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_le_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn sample_ethernet_ipv4_tcp_packet() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    bytes.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    bytes.extend_from_slice(&0x0800u16.to_be_bytes());
    bytes.push(0x45);
    bytes.push(0);
    bytes.extend_from_slice(&40u16.to_be_bytes());
    bytes.extend_from_slice(&0x1234u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.push(64);
    bytes.push(6);
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&[192, 0, 2, 1]);
    bytes.extend_from_slice(&[198, 51, 100, 2]);
    bytes.extend_from_slice(&12345u16.to_be_bytes());
    bytes.extend_from_slice(&443u16.to_be_bytes());
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.push(0x50);
    bytes.push(0x02);
    bytes.extend_from_slice(&64240u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes
}

fn append_gif_extension(bytes: &mut Vec<u8>, label: u8, payload: &[u8]) {
    bytes.extend_from_slice(&[0x21, label]);
    for chunk in payload.chunks(255) {
        bytes.push(chunk.len() as u8);
        bytes.extend_from_slice(chunk);
    }
    bytes.push(0);
}

fn sample_embedded_zip(name: &str, content: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut bytes);
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        use std::io::Write;
        zip.start_file(name, options).unwrap();
        zip.write_all(content).unwrap();
        zip.finish().unwrap();
    }
    bytes
}

fn sample_wasm_module() -> Vec<u8> {
    vec![
        0x00, 0x61, 0x73, 0x6d, // magic
        0x01, 0x00, 0x00, 0x00, // version
        0x01, 0x09, 0x02, 0x60, 0x01, 0x7f, 0x00, 0x60, 0x00, 0x01, 0x7f, // type
        0x02, 0x0b, 0x01, 0x03, b'e', b'n', b'v', 0x03, b'l', b'o', b'g', 0x00,
        0x00, // import env.log func type 0
        0x03, 0x02, 0x01, 0x01, // function type index 1
        0x05, 0x03, 0x01, 0x00, 0x01, // memory min 1
        0x07, 0x10, 0x02, 0x03, b'r', b'u', b'n', 0x00, 0x01, 0x06, b'm', b'e', b'm', b'o', b'r',
        b'y', 0x02, 0x00, // exports
        0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b, // code: i32.const 42
        0x0b, 0x08, 0x01, 0x00, 0x41, 0x00, 0x0b, 0x02, b'h', b'i', // data
    ]
}

fn sample_pdf_document() -> Vec<u8> {
    let objects = [
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>\nendobj\n",
        "4 0 obj\n<< /Length 44 >>\nstream\nBT /F1 12 Tf 72 720 Td (Hello ReVX) Tj ET\nendstream\nendobj\n",
        "5 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert('revx')) >>\nendobj\n",
    ];
    let mut bytes = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for object in objects {
        offsets.push(bytes.len());
        bytes.extend_from_slice(object.as_bytes());
    }
    let xref_offset = bytes.len();
    bytes.extend_from_slice(format!("xref\n0 {}\n", offsets.len() + 1).as_bytes());
    bytes.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets {
        bytes.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    bytes.extend_from_slice(
        format!("trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n").as_bytes(),
    );
    bytes
}


#[test]
fn extracts_utf16_and_content_class_signals() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let sample = dir.path().join("sample.bin");
    let mut bytes = b"ASCII_MARKER https://example.test/path\0\0".to_vec();
    for unit in "WideSecretToken".encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.extend_from_slice(&[0, 0]);
    for unit in "https://wide.example/api".encode_utf16() {
        bytes.extend_from_slice(&unit.to_be_bytes());
    }
    bytes.extend_from_slice(&[0, 0]);
    for index in 0..128u16 {
        bytes.push(((index * 91) % 255) as u8);
    }
    std::fs::write(&sample, &bytes).unwrap();
    let graph = revx_loader::identify_object_graph(&sample, 0, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(
            "sample.bin",
            Some(&[ObjectAnalyzerKind::ByteHistogram, ObjectAnalyzerKind::Strings]),
        )
        .unwrap()
        .expect("object analysis");
    let histogram = analysis
        .analyses
        .iter()
        .find(|item| item.analyzer == "byte_histogram")
        .expect("histogram");
    assert!(histogram.details.get("content_class").is_some());
    assert!(histogram.details.get("entropy").is_some());
    assert!(histogram.details.get("tags").is_some());
    let strings = analysis
        .analyses
        .iter()
        .find(|item| item.analyzer == "strings")
        .expect("strings");
    assert!(
        strings.details["utf16le_count"].as_u64().unwrap_or(0) > 0
            || strings.details["utf16be_count"].as_u64().unwrap_or(0) > 0,
        "details={}",
        strings.details
    );
    assert!(
        strings.details["interesting_count"].as_u64().unwrap_or(0) > 0,
        "details={}",
        strings.details
    );
}


#[test]
fn analyzes_iso_bmff_and_unknown_blob_signals() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();

    let mp4 = dir.path().join("clip.mp4");
    let mp4_bytes = b"\0\0\0\x18ftypisom\0\0\x02\0isomiso2\0\0\0\x08free";
    std::fs::write(&mp4, mp4_bytes).unwrap();
    let graph = revx_loader::identify_object_graph(&mp4, 0, 8).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object("clip.mp4", Some(&[ObjectAnalyzerKind::IsoBmff]))
        .unwrap()
        .expect("mp4 analysis");
    assert_eq!(analysis.analyses[0].analyzer, "iso_bmff");
    assert_eq!(
        analysis.analyses[0].details["major_brand"],
        serde_json::json!("isom")
    );
    assert!(
        analysis.analyses[0].details["box_count"]
            .as_u64()
            .unwrap_or(0)
            >= 1
    );

    let cab = dir.path().join("sample.cab");
    let mut cab_bytes = b"MSCF".to_vec();
    cab_bytes.extend_from_slice(&[0u8; 4]); // reserved
    cab_bytes.extend_from_slice(&0x40u32.to_le_bytes()); // cbCabinet
    cab_bytes.extend_from_slice(&[0u8; 4]); // reserved
    cab_bytes.extend_from_slice(&0u32.to_le_bytes()); // coffFiles
    cab_bytes.extend_from_slice(&[0u8; 4]); // reserved
    cab_bytes.push(3); // version minor
    cab_bytes.push(1); // version major
    cab_bytes.extend_from_slice(&1u16.to_le_bytes()); // folders
    cab_bytes.extend_from_slice(&1u16.to_le_bytes()); // files
    cab_bytes.extend_from_slice(&0u16.to_le_bytes()); // flags
    cab_bytes.extend_from_slice(&0u16.to_le_bytes()); // set id
    cab_bytes.extend_from_slice(&0u16.to_le_bytes()); // iCabinet
    std::fs::write(&cab, &cab_bytes).unwrap();
    let graph = revx_loader::identify_object_graph(&cab, 0, 8).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object("sample.cab", Some(&[ObjectAnalyzerKind::CabArchive]))
        .unwrap()
        .expect("cab analysis");
    assert_eq!(analysis.analyses[0].analyzer, "cab_archive");
    assert_eq!(
        analysis.analyses[0].details["file_count"],
        serde_json::json!(1)
    );

    let mut opaque = vec![0x11u8; 64];
    opaque.extend_from_slice(b"%PDF-1.7\n%revx\n");
    opaque.extend_from_slice(&[0x22u8; 32]);
    let blob = dir.path().join("opaque.bin");
    std::fs::write(&blob, &opaque).unwrap();
    let graph = revx_loader::identify_object_graph(&blob, 0, 8).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object("opaque.bin", Some(&[ObjectAnalyzerKind::UnknownBlob]))
        .unwrap()
        .expect("blob analysis");
    assert_eq!(analysis.analyses[0].analyzer, "unknown_blob");
    assert!(
        analysis.analyses[0].details["embedded_signature_count"]
            .as_u64()
            .unwrap_or(0)
            >= 1,
        "details={}",
        analysis.analyses[0].details
    );
    assert!(
        analysis.analyses[0].details["suggested_followups"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == "object_carve_signatures"))
    );
}

#[test]
fn analyzes_font_audio_disk_and_tiff_formats() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();

    let font = dir.path().join("font.ttf");
    let mut ttf = vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    ttf.extend_from_slice(b"head");
    ttf.extend_from_slice(&0u32.to_be_bytes());
    ttf.extend_from_slice(&12u32.to_be_bytes());
    ttf.extend_from_slice(&4u32.to_be_bytes());
    std::fs::write(&font, &ttf).unwrap();
    let graph = revx_loader::identify_object_graph(&font, 0, 4).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object("font.ttf", Some(&[ObjectAnalyzerKind::FontFile]))
        .unwrap()
        .expect("font");
    assert_eq!(analysis.analyses[0].analyzer, "font_file");
    assert_eq!(
        analysis.analyses[0].details["font_kind"],
        serde_json::json!("ttf")
    );

    let flac = dir.path().join("a.flac");
    std::fs::write(&flac, b"fLaC\0\0\0\x22").unwrap();
    let graph = revx_loader::identify_object_graph(&flac, 0, 4).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object("a.flac", Some(&[ObjectAnalyzerKind::AudioMedia]))
        .unwrap()
        .expect("flac");
    assert_eq!(analysis.analyses[0].analyzer, "audio_media");

    let qcow = dir.path().join("disk.qcow2");
    let mut q = b"QFI\xfb".to_vec();
    q.extend_from_slice(&3u32.to_be_bytes());
    q.extend_from_slice(&[0u8; 12]);
    q.extend_from_slice(&16u32.to_be_bytes()); // cluster bits
    q.extend_from_slice(&1024u64.to_be_bytes()); // size
    q.extend_from_slice(&0u32.to_be_bytes()); // crypt
    q.extend_from_slice(&1u32.to_be_bytes()); // l1 size
    std::fs::write(&qcow, &q).unwrap();
    let graph = revx_loader::identify_object_graph(&qcow, 0, 4).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object("disk.qcow2", Some(&[ObjectAnalyzerKind::DiskImage]))
        .unwrap()
        .expect("qcow");
    assert_eq!(analysis.analyses[0].analyzer, "disk_image");
    assert_eq!(
        analysis.analyses[0].details["disk_kind"],
        serde_json::json!("qcow2")
    );

    let tiff = dir.path().join("photo.tif");
    std::fs::write(&tiff, b"II*\0\x08\0\0\0").unwrap();
    let graph = revx_loader::identify_object_graph(&tiff, 0, 4).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object("photo.tif", Some(&[ObjectAnalyzerKind::TiffImage]))
        .unwrap()
        .expect("tiff");
    assert_eq!(analysis.analyses[0].analyzer, "tiff_image");
    assert_eq!(
        analysis.analyses[0].details["endian"],
        serde_json::json!("le")
    );
}

#[test]
fn auto_expands_macho_fat_slices() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let path = dir.path().join("universal");
    std::fs::write(&path, sample_macho_fat()).unwrap();
    let graph = revx_loader::identify_object_graph(&path, 0, 8).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object("universal", None)
        .unwrap()
        .expect("macho fat analysis");
    let expand = analysis
        .analyses
        .iter()
        .find(|item| item.analyzer == "auto_expand")
        .expect("auto_expand");
    let expanded = expand.details["expanded"].as_array().cloned().unwrap_or_default();
    assert!(
        expanded.iter().any(|item| {
            item.get("expand_kind")
                .and_then(|value| value.as_str())
                .is_some_and(|kind| kind == "macho_fat_slice")
                || item
                    .get("entry_name")
                    .and_then(|value| value.as_str())
                    .is_some_and(|name| name.starts_with("fat/"))
        }),
        "details={}",
        expand.details
    );
    assert!(
        expanded.len() >= 2,
        "expected both fat slices, details={}",
        expand.details
    );
}

#[test]
fn analyzes_seven_zip_and_rar_archives() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();

    let mut seven = b"7z\xbc\xaf'\x1c".to_vec();
    seven.extend_from_slice(&0u32.to_le_bytes());
    seven.extend_from_slice(&0u64.to_le_bytes());
    seven.extend_from_slice(&0u64.to_le_bytes());
    seven.extend_from_slice(&0u32.to_le_bytes());
    let seven_path = dir.path().join("sample.7z");
    std::fs::write(&seven_path, &seven).unwrap();
    let graph = revx_loader::identify_object_graph(&seven_path, 0, 8).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object("sample.7z", Some(&[ObjectAnalyzerKind::SevenZipArchive]))
        .unwrap()
        .expect("7z analysis");
    assert_eq!(analysis.analyses[0].analyzer, "seven_zip_archive");
    assert_eq!(
        analysis.analyses[0].details["signature_ok"],
        serde_json::json!(true)
    );
    assert!(
        analysis.analyses[0].details["risk_signals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|signal| signal == "seven_zip_archive_present")
    );

    let mut rar = b"Rar!\x1a\x07\x00".to_vec();
    rar.extend_from_slice(&0u16.to_le_bytes());
    rar.push(0x73);
    rar.extend_from_slice(&0x0080u16.to_le_bytes());
    rar.extend_from_slice(&13u16.to_le_bytes());
    let rar_path = dir.path().join("sample.rar");
    std::fs::write(&rar_path, &rar).unwrap();
    let graph = revx_loader::identify_object_graph(&rar_path, 0, 8).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object("sample.rar", Some(&[ObjectAnalyzerKind::RarArchive]))
        .unwrap()
        .expect("rar analysis");
    assert_eq!(analysis.analyses[0].analyzer, "rar_archive");
    assert_eq!(
        analysis.analyses[0].details["encrypted"],
        serde_json::json!(true)
    );
    assert!(
        analysis.analyses[0].details["risk_signals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|signal| signal == "encrypted_archive")
    );
}

#[test]
fn auto_expands_pe_overlay_and_resources() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let mut pe = sample_portable_executable();
    // Append a high-value overlay payload (embedded PDF + ELF-like).
    pe.extend_from_slice(b"%PDF-1.4\n%revx-overlay\ntrailer\n<<>>\nstartxref\n0\n%%EOF\n");
    let mut elf = vec![0u8; 0x40];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    pe.extend_from_slice(&elf);
    let path = dir.path().join("packed.exe");
    std::fs::write(&path, &pe).unwrap();
    let graph = revx_loader::identify_object_graph(&path, 0, 8).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object("packed.exe", None)
        .unwrap()
        .expect("pe analysis");
    let pe_analysis = analysis
        .analyses
        .iter()
        .find(|item| item.analyzer == "portable_executable")
        .expect("portable_executable");
    assert!(
        pe_analysis.details["overlay"]["present"].as_bool().unwrap_or(false),
        "details={}",
        pe_analysis.details["overlay"]
    );
    assert!(
        pe_analysis.details["overlay"]["embedded_signature_count"]
            .as_u64()
            .unwrap_or(0)
            >= 1
            || pe_analysis.details["resources"]["entries"].as_array().is_some(),
        "details={}",
        pe_analysis.details
    );
    let expand = analysis
        .analyses
        .iter()
        .find(|item| item.analyzer == "auto_expand")
        .expect("auto_expand");
    let expanded = expand.details["expanded"].as_array().cloned().unwrap_or_default();
    assert!(
        expanded.iter().any(|item| {
            item.get("expand_kind")
                .and_then(|value| value.as_str())
                .is_some_and(|kind| kind == "pe_overlay" || kind == "pe_resource")
                || item
                    .get("entry_name")
                    .and_then(|value| value.as_str())
                    .is_some_and(|name| name.contains("overlay") || name.starts_with("rsrc/"))
        }),
        "details={}",
        expand.details
    );
}

#[test]
fn auto_expands_ar_native_members() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let mut elf = vec![0u8; 0x80];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    // Build minimal ar archive with one ELF member.
    let mut ar = b"!<arch>\n".to_vec();
    let name = b"libdemo.o/      "; // 16 bytes padded later
    let mut header = vec![b' '; 60];
    let name_bytes = b"libdemo.o/";
    header[..name_bytes.len()].copy_from_slice(name_bytes);
    let size = format!("{:<10}", elf.len());
    header[48..58].copy_from_slice(size.as_bytes());
    header[58] = b'`';
    header[59] = b'\n';
    ar.extend_from_slice(&header);
    ar.extend_from_slice(&elf);
    if ar.len() % 2 == 1 {
        ar.push(b'\n');
    }
    let path = dir.path().join("libdemo.a");
    std::fs::write(&path, &ar).unwrap();
    let graph = revx_loader::identify_object_graph(&path, 0, 8).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object("libdemo.a", None)
        .unwrap()
        .expect("ar analysis");
    let expand = analysis
        .analyses
        .iter()
        .find(|item| item.analyzer == "auto_expand")
        .expect("auto_expand");
    let expanded = expand.details["expanded"].as_array().cloned().unwrap_or_default();
    assert!(
        expanded.iter().any(|item| {
            item.get("object_format")
                .and_then(|value| value.as_str())
                == Some("elf")
                || item
                    .get("binary_candidate")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false)
                || item
                    .get("entry_name")
                    .and_then(|value| value.as_str())
                    .is_some_and(|name| name.contains("libdemo"))
        }),
        "details={}",
        expand.details
    );
    let candidates = ws.dug_native_binary_candidates(&analysis.analyses, 8);
    assert!(
        !candidates.is_empty()
            || expanded.iter().any(|item| item
                .get("object_format")
                .and_then(|value| value.as_str())
                == Some("elf")),
        "expected native candidates details={}",
        expand.details
    );
    let _ = name;
}

#[test]
fn auto_expands_tar_gz_high_value_members() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();

    let mut elf = vec![0u8; 0x80];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;

    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        let mut header = tar::Header::new_gnu();
        header.set_path("bin/libpayload.so").unwrap();
        header.set_size(elf.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder.append(&header, elf.as_slice()).unwrap();
        let mut header = tar::Header::new_gnu();
        header.set_path("readme.txt").unwrap();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, b"hello".as_slice()).unwrap();
        builder.finish().unwrap();
    }
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    use std::io::Write;
    encoder.write_all(&tar_bytes).unwrap();
    let gz = encoder.finish().unwrap();
    let path = dir.path().join("bundle.tar.gz");
    std::fs::write(&path, &gz).unwrap();

    let graph = revx_loader::identify_object_graph(&path, 0, 8).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object("bundle.tar.gz", None)
        .unwrap()
        .expect("tar.gz analysis");
    let expand = analysis
        .analyses
        .iter()
        .find(|item| item.analyzer == "auto_expand")
        .expect("auto_expand");
    let expanded = expand.details["expanded"].as_array().cloned().unwrap_or_default();
    assert!(
        expanded.iter().any(|item| {
            item.get("entry_name")
                .and_then(|value| value.as_str())
                .is_some_and(|name| name.contains("libpayload.so"))
                || item
                    .get("binary_candidate")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false)
        }),
        "details={}",
        expand.details
    );
    let candidates = ws.dug_native_binary_candidates(&analysis.analyses, 8);
    assert!(
        !candidates.is_empty()
            || expanded.iter().any(|item| item
                .get("object_format")
                .and_then(|value| value.as_str())
                == Some("elf")),
        "expected native from tar.gz details={}",
        expand.details
    );
}

#[test]
fn auto_expands_ipa_and_jar_high_value_members() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    use std::io::Write;

    // IPA-like
    let mut macho = vec![0u8; 0x40];
    macho[0..4].copy_from_slice(b"\xcf\xfa\xed\xfe");
    let ipa = dir.path().join("demo.ipa");
    {
        let file = std::fs::File::create(&ipa).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("Payload/Demo.app/Demo", options).unwrap();
        zip.write_all(&macho).unwrap();
        zip.start_file("Payload/Demo.app/Frameworks/libx.dylib", options)
            .unwrap();
        zip.write_all(&macho).unwrap();
        zip.start_file("Payload/Demo.app/Info.plist", options).unwrap();
        zip.write_all(b"<?xml version=\"1.0\"?><plist></plist>").unwrap();
        zip.finish().unwrap();
    }
    let graph = revx_loader::identify_object_graph(&ipa, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let ipa_analysis = ws.analyze_object("demo.ipa", None).unwrap().expect("ipa");
    let expand = ipa_analysis
        .analyses
        .iter()
        .find(|item| item.analyzer == "auto_expand")
        .expect("ipa auto_expand");
    let expanded = expand.details["expanded"].as_array().cloned().unwrap_or_default();
    assert!(
        expanded.iter().any(|item| {
            item.get("entry_name")
                .and_then(|value| value.as_str())
                .is_some_and(|name| name.contains("Demo") || name.ends_with(".dylib"))
        }),
        "details={}",
        expand.details
    );

    // JAR-like
    let jar = dir.path().join("demo.jar");
    {
        let file = std::fs::File::create(&jar).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("com/revx/Main.class", options).unwrap();
        let mut class = vec![0u8; 16];
        class[0..4].copy_from_slice(b"\xca\xfe\xba\xbe");
        class[6] = 0;
        class[7] = 52; // major 52
        zip.write_all(&class).unwrap();
        zip.start_file("native/libhelper.so", options).unwrap();
        let mut elf = vec![0u8; 0x40];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        zip.write_all(&elf).unwrap();
        zip.finish().unwrap();
    }
    let graph = revx_loader::identify_object_graph(&jar, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let jar_analysis = ws.analyze_object("demo.jar", None).unwrap().expect("jar");
    let expand = jar_analysis
        .analyses
        .iter()
        .find(|item| item.analyzer == "auto_expand")
        .expect("jar auto_expand");
    let expanded = expand.details["expanded"].as_array().cloned().unwrap_or_default();
    assert!(
        expanded.iter().any(|item| {
            item.get("entry_name")
                .and_then(|value| value.as_str())
                .is_some_and(|name| name.ends_with(".class") || name.ends_with(".so"))
        }),
        "details={}",
        expand.details
    );
}

#[test]
fn dex_bytecode_surfaces_interesting_methods_and_strings() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    // Use a minimal handcrafted DEX-like blob may not parse fully; prefer real-ish if available via analyze path.
    // Build a tiny valid-enough header-only DEX and ensure analyzer runs without panic and exposes new fields.
    let mut dex = vec![0u8; 0x70];
    dex[0..4].copy_from_slice(b"dex\n");
    dex[4..8].copy_from_slice(b"035\0");
    // checksum/signature leave zero
    dex[32..36].copy_from_slice(&(0x70u32).to_le_bytes()); // file_size
    dex[36..40].copy_from_slice(&(0x70u32).to_le_bytes()); // header_size
    dex[40..44].copy_from_slice(&0x12345678u32.to_le_bytes()); // endian
    let path = dir.path().join("tiny.dex");
    std::fs::write(&path, &dex).unwrap();
    let graph = revx_loader::identify_object_graph(&path, 0, 4).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object("tiny.dex", Some(&[ObjectAnalyzerKind::DexBytecode]))
        .unwrap()
        .expect("dex");
    let dex_analysis = analysis
        .analyses
        .iter()
        .find(|item| item.analyzer == "dex_bytecode")
        .expect("dex_bytecode");
    assert!(
        dex_analysis.details.get("interesting_string_count").is_some(),
        "details={}",
        dex_analysis.details
    );
    assert!(
        dex_analysis.details.get("interesting_method_count").is_some(),
        "details={}",
        dex_analysis.details
    );
}

#[test]
fn auto_expands_compressed_and_package_high_value_members() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();

    // gzip around a small ELF-like payload
    let mut elf = vec![0u8; 0x80];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    use std::io::Write;
    encoder.write_all(&elf).unwrap();
    let gzip_bytes = encoder.finish().unwrap();
    let gzip_path = dir.path().join("payload.gz");
    std::fs::write(&gzip_path, &gzip_bytes).unwrap();
    let graph = revx_loader::identify_object_graph(&gzip_path, 0, 8).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let gzip_analysis = ws
        .analyze_object("payload.gz", None)
        .unwrap()
        .expect("gzip analysis");
    assert!(
        gzip_analysis
            .analyses
            .iter()
            .any(|item| item.analyzer == "auto_expand"),
        "analyzers={:?}",
        gzip_analysis
            .analyses
            .iter()
            .map(|a| &a.analyzer)
            .collect::<Vec<_>>()
    );

    // APK-like zip with embedded .so and classes.dex
    let apk = dir.path().join("sample.apk");
    {
        let file = std::fs::File::create(&apk).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("AndroidManifest.xml", options).unwrap();
        zip.write_all(br#"<?xml version="1.0"?><manifest package="com.revx.demo"></manifest>"#)
            .unwrap();
        zip.start_file("classes.dex", options).unwrap();
        let mut dex = vec![0u8; 0x70];
        dex[0..4].copy_from_slice(b"dex\n");
        dex[4..8].copy_from_slice(b"035\0");
        dex[32..36].copy_from_slice(&(0x70u32).to_le_bytes());
        zip.write_all(&dex).unwrap();
        zip.start_file("lib/arm64-v8a/libdemo.so", options).unwrap();
        zip.write_all(&elf).unwrap();
        zip.finish().unwrap();
    }
    let graph = revx_loader::identify_object_graph(&apk, 1, 16).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let apk_analysis = ws
        .analyze_object("sample.apk", None)
        .unwrap()
        .expect("apk analysis");
    let expand = apk_analysis
        .analyses
        .iter()
        .find(|item| item.analyzer == "auto_expand")
        .expect("auto_expand for apk");
    let expanded = expand.details["expanded"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        !expanded.is_empty(),
        "details={}",
        expand.details
    );
    assert!(
        expanded.iter().any(|item| {
            item.get("binary_candidate")
                .and_then(|value| value.as_bool())
                .unwrap_or(false)
                || item
                    .get("entry_name")
                    .and_then(|value| value.as_str())
                    .is_some_and(|name| name.contains("libdemo.so") || name.ends_with(".dex"))
        }),
        "expanded={expanded:?}"
    );
    let candidates = ws.dug_native_binary_candidates(&apk_analysis.analyses, 8);
    assert!(
        !candidates.is_empty()
            || expanded.iter().any(|item| item
                .get("object_format")
                .and_then(|value| value.as_str())
                == Some("elf")),
        "expected native candidates details={}",
        expand.details
    );
}

#[test]
fn auto_digs_and_ranks_native_and_mobile_payloads() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let mut blob = vec![0x41u8; 48];
    blob.extend_from_slice(b"%PDF-1.4\n%revx\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\nstartxref\n0\n%%EOF\n");
    blob.extend_from_slice(&[0x42u8; 24]);
    // Minimal valid-looking MZ/PE
    let pe_start = blob.len();
    let mut pe = vec![0u8; 0x200];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3c] = 0x80;
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    pe[0x86] = 1; // NumberOfSections = 1
    pe[0x94] = 0xe0; // SizeOfOptionalHeader low
    // section table at 0x80+24+0xe0 = 0x184
    let section = 0x80 + 24 + 0xe0;
    if section + 40 <= pe.len() {
        pe[section + 16] = 0x20; // SizeOfRawData
        pe[section + 20] = 0x00;
        pe[section + 20] = 0x00; // PointerToRawData low stays 0; set meaningful end via SizeOfRawData
        pe[section + 20] = 0x00;
        pe[section + 16..section + 20].copy_from_slice(&0x40u32.to_le_bytes());
        pe[section + 20..section + 24].copy_from_slice(&0x180u32.to_le_bytes());
    }
    blob.extend_from_slice(&pe);
    blob.extend_from_slice(&[0x43u8; 16]);
    // DEX header prefix with size fields
    let mut dex = vec![0u8; 0x70];
    dex[0..4].copy_from_slice(b"dex\n");
    dex[4..8].copy_from_slice(b"035\0");
    dex[32..36].copy_from_slice(&(0x70u32).to_le_bytes());
    blob.extend_from_slice(&dex);
    blob.extend_from_slice(&[0x44u8; 16]);
    // Mach-O 64 LE magic
    blob.extend_from_slice(b"\xcf\xfa\xed\xfe");
    blob.extend_from_slice(&[0u8; 60]);
    blob.extend_from_slice(&[0x45u8; 16]);
    // OLE
    blob.extend_from_slice(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1");
    blob.extend_from_slice(&[0u8; 64]);

    let path = dir.path().join("polyglot.bin");
    std::fs::write(&path, &blob).unwrap();
    let graph = revx_loader::identify_object_graph(&path, 0, 8).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(
            "polyglot.bin",
            Some(&[ObjectAnalyzerKind::UnknownBlob]),
        )
        .unwrap()
        .expect("analysis");
    let dig = analysis
        .analyses
        .iter()
        .find(|item| item.analyzer == "auto_dig")
        .expect("auto_dig");
    let dug = dig.details["dug"].as_array().cloned().unwrap_or_default();
    assert!(!dug.is_empty(), "details={}", dig.details);
    let formats = dug
        .iter()
        .filter_map(|item| item.get("object_format").and_then(|v| v.as_str()))
        .collect::<Vec<_>>();
    assert!(
        formats.iter().any(|f| *f == "pdf" || *f == "pe" || *f == "dex" || *f == "macho" || *f == "ole"),
        "formats={formats:?} details={}",
        dig.details
    );
    let candidates = ws.dug_native_binary_candidates(&analysis.analyses, 8);
    if formats.iter().any(|f| matches!(*f, "pe" | "elf" | "macho" | "macho_fat")) {
        assert!(
            !candidates.is_empty(),
            "expected native candidates from formats={formats:?}"
        );
    }
    let _ = pe_start;
}

#[test]
fn auto_digs_embedded_pdf_from_unknown_blob() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let mut blob = vec![0x41u8; 48];
    let pdf = sample_pdf_document();
    blob.extend_from_slice(&pdf);
    blob.extend_from_slice(&[0x42u8; 24]);
    let path = dir.path().join("payload.bin");
    std::fs::write(&path, &blob).unwrap();
    let graph = revx_loader::identify_object_graph(&path, 0, 8).unwrap();
    ws.save_object_graph(&graph).unwrap();

    let analysis = ws
        .analyze_object("payload.bin", Some(&[ObjectAnalyzerKind::UnknownBlob]))
        .unwrap()
        .expect("analysis");
    assert!(
        !analysis.analyses.is_empty(),
        "analyses empty: {:?}",
        analysis.analyses
    );
    let dig = analysis
        .analyses
        .iter()
        .find(|item| item.analyzer == "auto_dig")
        .unwrap_or_else(|| {
            panic!(
                "auto_dig analysis missing; analyzers={:?}",
                analysis
                    .analyses
                    .iter()
                    .map(|item| {
                        (
                            item.analyzer.clone(),
                            item.summary.clone(),
                            item.details.clone(),
                        )
                    })
                    .collect::<Vec<_>>()
            )
        });
    assert!(
        dig.details["dug_count"].as_u64().unwrap_or(0) >= 1,
        "details={}",
        dig.details
    );
    let child_ids = dig.details["child_object_ids"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(!child_ids.is_empty());
    let child_id = child_ids[0].as_str().expect("child id");
    let profile = ws.object_profile(child_id).unwrap().expect("child profile");
    assert_eq!(profile.object.format.as_deref(), Some("pdf"));
    assert!(
        profile
            .object
            .flags
            .iter()
            .any(|flag| flag == "auto_dig" || flag == "carved")
    );
    let recursive = dig.details["dug"][0]["recursive_analysis"].clone();
    assert_eq!(
        recursive["status"],
        serde_json::json!("completed"),
        "recursive={}",
        recursive
    );
    assert!(
        recursive["analysis_count"].as_u64().unwrap_or(0) >= 1,
        "recursive={}",
        recursive
    );
    let child = ws.resolve_object(child_id).unwrap().expect("child object");
    assert!(
        child
            .analyses
            .iter()
            .any(|analysis| analysis.analyzer == "pdf_document" || analysis.analyzer == "strings"),
        "child analyses={:?}",
        child
            .analyses
            .iter()
            .map(|a| &a.analyzer)
            .collect::<Vec<_>>()
    );
}

#[test]
fn recursively_analyzes_nested_dug_children_with_depth_bound() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let png = sample_png_with_metadata_and_trailing_zip(&[]);
    let mut outer = vec![0x11u8; 32];
    outer.extend_from_slice(&png);
    outer.extend_from_slice(&[0x22u8; 16]);
    let path = dir.path().join("nested.bin");
    std::fs::write(&path, &outer).unwrap();
    let graph = revx_loader::identify_object_graph(&path, 0, 4).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object("nested.bin", Some(&[ObjectAnalyzerKind::UnknownBlob]))
        .unwrap()
        .expect("analysis");
    let dig = analysis
        .analyses
        .iter()
        .find(|item| item.analyzer == "auto_dig")
        .expect("auto_dig");
    assert!(
        dig.details["dug_count"].as_u64().unwrap_or(0) >= 1,
        "details={}",
        dig.details
    );
    let child_id = dig.details["child_object_ids"][0]
        .as_str()
        .expect("child id");
    let child = ws.resolve_object(child_id).unwrap().expect("child");
    assert_eq!(child.format.as_deref(), Some("png"));
    assert!(
        child
            .analyses
            .iter()
            .any(|analysis| analysis.analyzer == "png_image"),
        "child analyses={:?}",
        child
            .analyses
            .iter()
            .map(|a| &a.analyzer)
            .collect::<Vec<_>>()
    );
}


#[test]
fn object_analyze_emits_agent_interaction_contract() {
    let dir = tempdir().unwrap();
    let ws = Workspace::init(dir.path(), "test", None).unwrap();
    let sample = dir.path().join("opaque.bin");
    let mut bytes = b"opaque-prefix".to_vec();
    bytes.extend_from_slice(b"PK\x03\x04");
    bytes.extend_from_slice(&[0u8; 26]);
    bytes.extend_from_slice(b"PK\x05\x06");
    bytes.extend_from_slice(&[0u8; 18]);
    std::fs::write(&sample, &bytes).unwrap();
    let graph = revx_loader::identify_object_graph(&sample, 0, 8).unwrap();
    ws.save_object_graph(&graph).unwrap();
    let analysis = ws
        .analyze_object(&sample.display().to_string(), None)
        .unwrap()
        .expect("analysis");
    assert!(
        !analysis.next_actions.is_empty(),
        "object_analyze should emit ranked next_actions"
    );
    assert!(
        !analysis.agent_brief.headline.is_empty(),
        "object_analyze should emit agent_brief.headline"
    );
    assert_eq!(
        analysis.agent_brief.next_actions.len(),
        analysis.next_actions.len()
    );
    let top = &analysis.next_actions[0];
    assert!(!top.tool.is_empty());
    assert!(top.priority > 0);
    assert!(
        analysis
            .agent_brief
            .stop_conditions
            .iter()
            .any(|item| item.contains("one top") || item.contains("next_actions[0]"))
    );
    for action in &analysis.next_actions {
        assert!(
            matches!(
                action.tool.as_str(),
                "object_analyze"
                    | "object_analyze_binary"
                    | "object_carve_signatures"
                    | "object_carve_identify"
                    | "object_scan_signatures"
                    | "object_pipeline"
                    | "evidence_pack"
                    | "evidence_graph"
                    | "string_search"
                    | "function_search"
                    | "trace_query"
                    | "artifact_read"
                    | "report_generate"
            ),
            "unexpected tool in next_actions: {}",
            action.tool
        );
    }
}
