use super::*;

pub(crate) fn tool_name_to_request(
    name: &str,
    arguments: serde_json::Value,
) -> Result<CapabilityRequest> {
    match name {
        "project_open" => Ok(CapabilityRequest::ProjectOpen(serde_json::from_value(
            arguments,
        )?)),
        "project_status" => Ok(CapabilityRequest::ProjectStatus(parse_empty_or_default(
            arguments,
        )?)),
        "object_identify" => Ok(CapabilityRequest::ObjectIdentify(serde_json::from_value(
            arguments,
        )?)),
        "object_search" => Ok(CapabilityRequest::ObjectSearch(serde_json::from_value(
            arguments,
        )?)),
        "object_profile" => Ok(CapabilityRequest::ObjectProfile(serde_json::from_value(
            arguments,
        )?)),
        "object_materialize" => Ok(CapabilityRequest::ObjectMaterialize(
            serde_json::from_value(arguments)?,
        )),
        "object_extract_range" => Ok(CapabilityRequest::ObjectExtractRange(
            serde_json::from_value(arguments)?,
        )),
        "object_scan_signatures" => Ok(CapabilityRequest::ObjectSignatureScan(
            serde_json::from_value(arguments)?,
        )),
        "object_carve_signatures" => Ok(CapabilityRequest::ObjectCarveSignatures(
            serde_json::from_value(arguments)?,
        )),
        "object_carve_identify" => Ok(CapabilityRequest::ObjectCarveIdentify(
            serde_json::from_value(arguments)?,
        )),
        "object_analyze" => Ok(CapabilityRequest::ObjectAnalyze(serde_json::from_value(
            arguments,
        )?)),
        "object_plugin_list" => Ok(CapabilityRequest::ObjectPluginList(parse_empty_or_default(
            arguments,
        )?)),
        "object_plugin_run" => Ok(CapabilityRequest::ObjectPluginRun(serde_json::from_value(
            arguments,
        )?)),
        "object_register_binary" => Ok(CapabilityRequest::ObjectRegisterBinary(
            serde_json::from_value(arguments)?,
        )),
        "object_analyze_binary" => Ok(CapabilityRequest::ObjectAnalyzeBinary(
            serde_json::from_value(arguments)?,
        )),
        "object_pipeline" => Ok(CapabilityRequest::ObjectPipeline(serde_json::from_value(
            arguments,
        )?)),
        "binary_list" => Ok(CapabilityRequest::BinaryList(parse_empty_or_default(
            arguments,
        )?)),
        "analysis_run" => Ok(CapabilityRequest::AnalysisRun(serde_json::from_value(
            arguments,
        )?)),
        "analysis_status" => Ok(CapabilityRequest::AnalysisStatus(serde_json::from_value(
            arguments,
        )?)),
        "binary_survey" => Ok(CapabilityRequest::BinarySurvey(serde_json::from_value(
            arguments,
        )?)),
        "function_search" => Ok(CapabilityRequest::FunctionSearch(serde_json::from_value(
            arguments,
        )?)),
        "function_profile" => Ok(CapabilityRequest::FunctionProfile(serde_json::from_value(
            arguments,
        )?)),
        "decompile_function" => Ok(CapabilityRequest::DecompileFunction(
            serde_json::from_value(arguments)?,
        )),
        "decompile_cache_status" => Ok(CapabilityRequest::DecompileCacheStatus(
            serde_json::from_value(arguments)?,
        )),
        "disassemble_function" => Ok(CapabilityRequest::DisassembleFunction(
            serde_json::from_value(arguments)?,
        )),
        "xrefs_query" => Ok(CapabilityRequest::XrefsQuery(serde_json::from_value(
            arguments,
        )?)),
        "callgraph_slice" => Ok(CapabilityRequest::CallgraphSlice(serde_json::from_value(
            arguments,
        )?)),
        "string_search" => Ok(CapabilityRequest::StringSearch(serde_json::from_value(
            arguments,
        )?)),
        "search_bytes" => Ok(CapabilityRequest::SearchBytes(serde_json::from_value(
            arguments,
        )?)),
        "object_search_content" => Ok(CapabilityRequest::ObjectContentSearch(
            serde_json::from_value(arguments)?,
        )),
        "artifact_read" => Ok(CapabilityRequest::ArtifactRead(serde_json::from_value(
            arguments,
        )?)),
        "artifact_list" => Ok(CapabilityRequest::ArtifactList(serde_json::from_value(
            arguments,
        )?)),
        "evidence_pack" => Ok(CapabilityRequest::EvidencePack(serde_json::from_value(
            arguments,
        )?)),
        "evidence_graph" => Ok(CapabilityRequest::EvidenceGraph(serde_json::from_value(
            arguments,
        )?)),
        "symbolic_solve" => Ok(CapabilityRequest::SymbolicSolve(serde_json::from_value(
            arguments,
        )?)),
        "analysis_brief" => Ok(CapabilityRequest::AnalysisBrief(serde_json::from_value(
            arguments,
        )?)),
        "investigation_run" => Ok(CapabilityRequest::InvestigationRun(serde_json::from_value(
            arguments,
        )?)),
        "ibc_status" => Ok(CapabilityRequest::IbcStatus(parse_empty_or_default(
            arguments,
        )?)),
        "ibc_advance" => Ok(CapabilityRequest::IbcAdvance(parse_empty_or_default(
            arguments,
        )?)),
        "hypothesis_create" => Ok(CapabilityRequest::HypothesisCreate(serde_json::from_value(
            arguments,
        )?)),
        "hypothesis_update" => Ok(CapabilityRequest::HypothesisUpdate(serde_json::from_value(
            arguments,
        )?)),
        "report_generate" => Ok(CapabilityRequest::ReportGenerate(serde_json::from_value(
            arguments,
        )?)),
        "trace_import" => Ok(CapabilityRequest::TraceImport(serde_json::from_value(
            arguments,
        )?)),
        "trace_query" => Ok(CapabilityRequest::TraceQuery(serde_json::from_value(
            arguments,
        )?)),
        _ => anyhow::bail!("unknown tool: {name}"),
    }
}

pub(crate) fn parse_empty_or_default<T>(arguments: serde_json::Value) -> Result<T>
where
    T: serde::de::DeserializeOwned + Default,
{
    match arguments {
        serde_json::Value::Null => Ok(T::default()),
        serde_json::Value::Object(map) if map.is_empty() => Ok(T::default()),
        other => Ok(serde_json::from_value(other)?),
    }
}

pub(crate) fn mcp_tools_manifest() -> Vec<serde_json::Value> {
    vec![
        tool_manifest(
            "project_open",
            "Open a revx workspace",
            serde_json::json!({
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"]
            }),
        ),
        tool_manifest(
            "project_status",
            "Read workspace status",
            serde_json::json!({
                "type": "object",
                "properties": {}
            }),
        ),
        tool_manifest(
            "object_identify",
            "Identify an arbitrary file or directory as a universal object graph",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "max_depth": { "type": ["integer", "null"] },
                    "max_children": { "type": ["integer", "null"] },
                    "include_graph": { "type": ["boolean", "null"] }
                },
                "required": ["path"]
            }),
        ),
        tool_manifest(
            "object_search",
            "Search persisted universal objects by id, path, format, hash, metadata, or analyzer output",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" },
                    "kind": {
                        "type": ["string", "null"],
                        "enum": [
                            "file", "directory", "archive", "binary", "text", "image",
                            "document", "package", "filesystem_image", "memory_dump",
                            "network_capture", "database", "model", "unknown", null
                        ]
                    },
                    "limit": { "type": ["integer", "null"] }
                },
                "required": ["query"]
            }),
        ),
        tool_manifest(
            "object_profile",
            "Read a persisted universal object profile with graph edges and evidence ids",
            serde_json::json!({
                "type": "object",
                "properties": { "query": { "type": "string" } },
                "required": ["query"]
            }),
        ),
        tool_manifest(
            "object_materialize",
            "Materialize a persisted object, including virtual container children, into an artifact",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" },
                    "preview_bytes": { "type": ["integer", "null"] }
                },
                "required": ["query"]
            }),
        ),
        tool_manifest(
            "object_extract_range",
            "Extract a byte range from a persisted object, including virtual container children, into a new evidence artifact",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" },
                    "offset": { "type": "integer" },
                    "length": { "type": "integer" },
                    "context_bytes": { "type": ["integer", "null"] },
                    "preview_bytes": { "type": ["integer", "null"] }
                },
                "required": ["query", "offset", "length"]
            }),
        ),
        tool_manifest(
            "object_scan_signatures",
            "Scan a persisted object for embedded file signatures and offsets that can be extracted as follow-up evidence",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" },
                    "limit": { "type": ["integer", "null"] },
                    "max_object_bytes": { "type": ["integer", "null"] },
                    "preview_bytes": { "type": ["integer", "null"] }
                },
                "required": ["query"]
            }),
        ),
        tool_manifest(
            "object_carve_signatures",
            "Scan a persisted object for bounded embedded signatures and carve them into evidence artifacts",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" },
                    "limit": { "type": ["integer", "null"] },
                    "max_object_bytes": { "type": ["integer", "null"] },
                    "max_carve_bytes": { "type": ["integer", "null"] },
                    "min_confidence": { "type": ["number", "null"] },
                    "preview_bytes": { "type": ["integer", "null"] }
                },
                "required": ["query"]
            }),
        ),
        tool_manifest(
            "object_carve_identify",
            "Carve bounded embedded signatures into artifacts, recursively identify each carved artifact, and persist the resulting object graphs",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" },
                    "limit": { "type": ["integer", "null"] },
                    "max_object_bytes": { "type": ["integer", "null"] },
                    "max_carve_bytes": { "type": ["integer", "null"] },
                    "min_confidence": { "type": ["number", "null"] },
                    "preview_bytes": { "type": ["integer", "null"] },
                    "max_depth": { "type": ["integer", "null"] },
                    "max_children": { "type": ["integer", "null"] }
                },
                "required": ["query"]
            }),
        ),
        tool_manifest(
            "object_analyze",
            "Analyze a persisted object. Read agent_brief.headline + next_actions[0] and execute exactly one ranked follow-up using next_actions[0].args; honor stop_conditions",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" },
                    "analyzers": {
                        "type": ["array", "null"],
                        "items": {
                            "type": "string",
                            "enum": ["auto", "byte_histogram", "strings", "structured_text", "zip_listing", "android_package", "dex_bytecode", "ios_package", "java_archive", "jvm_class", "python_bytecode", "shell_link", "portable_executable", "dotnet_metadata", "elf_binary", "macho_binary", "open_xml_document", "sqlite_schema", "wasm_module", "pdf_document", "png_image", "jpeg_image", "gif_image", "bmp_image", "riff_container", "pcap_capture", "ole_compound", "safe_tensors_model", "gguf_model", "pytorch_model", "iso_bmff", "cab_archive", "ar_archive", "font_file", "tiff_image", "audio_media", "disk_image", "unknown_blob"]
                        }
                    }
                },
                "required": ["query"]
            }),
        ),
        tool_manifest(
            "object_plugin_list",
            "List workspace object analyzer plugins from .revx/plugins/*.json",
            serde_json::json!({
                "type": "object",
                "properties": {}
            }),
        ),
        tool_manifest(
            "object_plugin_run",
            "Materialize an object, run a workspace plugin analyzer command, and persist its output as evidence",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "plugin_id": { "type": "string" },
                    "query": { "type": "string" },
                    "timeout_ms": { "type": ["integer", "null"] }
                },
                "required": ["plugin_id", "query"]
            }),
        ),
        tool_manifest(
            "object_register_binary",
            "Materialize an object and register it as a binary survey",
            serde_json::json!({
                "type": "object",
                "properties": { "query": { "type": "string" } },
                "required": ["query"]
            }),
        ),
        tool_manifest(
            "object_analyze_binary",
            "Materialize an object and run binary analysis over it",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" },
                    "profile": { "type": "string", "enum": ["fast", "full"] }
                },
                "required": ["query", "profile"]
            }),
        ),
        tool_manifest(
            "object_pipeline",
            "Run recursive object discovery/carving. Consume agent_brief.next_actions[0] for the single next high-value tool call",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "max_depth": { "type": ["integer", "null"] },
                    "max_children": { "type": ["integer", "null"] },
                    "object_limit": { "type": ["integer", "null"] },
                    "analyze_objects": { "type": ["boolean", "null"] },
                    "carve_embedded": { "type": ["boolean", "null"] },
                    "carve_limit": { "type": ["integer", "null"] },
                    "max_carve_object_bytes": { "type": ["integer", "null"] },
                    "max_carve_bytes": { "type": ["integer", "null"] },
                    "min_carve_confidence": { "type": ["number", "null"] },
                    "carve_max_depth": { "type": ["integer", "null"] },
                    "carve_max_children": { "type": ["integer", "null"] },
                    "plugin_ids": { "type": ["array", "null"], "items": { "type": "string" } },
                    "analyze_binaries": { "type": ["boolean", "null"] },
                    "binary_profile": { "type": ["string", "null"], "enum": ["fast", "full", null] }
                },
                "required": ["path"]
            }),
        ),
        tool_manifest(
            "binary_list",
            "List registered binaries",
            serde_json::json!({
                "type": "object",
                "properties": {}
            }),
        ),
        tool_manifest(
            "analysis_run",
            "Analyze a binary and return run status plus function/import/string coverage in tool text",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "binary_path": { "type": "string" },
                    "profile": { "type": "string", "enum": ["fast", "full"] }
                },
                "required": ["binary_path", "profile"]
            }),
        ),
        tool_manifest(
            "analysis_status",
            "Read analysis run status",
            serde_json::json!({
                "type": "object",
                "properties": { "run_id": { "type": ["string", "null"] } }
            }),
        ),
        tool_manifest(
            "binary_survey",
            "Read binary survey stats (format/arch/functions/strings/debug coverage) with next-step guidance",
            serde_json::json!({
                "type": "object",
                "properties": { "binary_id": { "type": ["string", "null"] } }
            }),
        ),
        tool_manifest(
            "function_search",
            "Search functions by name/address. Text includes ranked matches with addresses and sizes; use function_profile/decompile_function on a hit",
            serde_json::json!({
                "type": "object",
                "properties": { "query": { "type": "string" } },
                "required": ["query"]
            }),
        ),
        tool_manifest(
            "function_profile",
            "Read a function dossier: args/locals, callers/callees, xrefs, and pseudocode preview in the tool text response",
            serde_json::json!({
                "type": "object",
                "properties": { "query": { "type": "string" } },
                "required": ["query"]
            }),
        ),
        tool_manifest(
            "decompile_cache_status",
            "List function pseudocode artifact and per-strategy cache entries (fast/full/hotblock) for a function query",
            serde_json::json!({
                "type": "object",
                "properties": { "query": { "type": "string" } },
                "required": ["query"]
            }),
        ),
        tool_manifest(
            "decompile_function",
            "Return deterministic pseudocode text and region outline for a function. strategy: auto|cached|fast|full|hotblock; force_refresh recomputes",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" },
                    "strategy": {
                        "type": "string",
                        "enum": ["auto", "cached", "fast", "full", "hotblock"]
                    },
                    "force_refresh": { "type": "boolean" }
                },
                "required": ["query"]
            }),
        ),
        tool_manifest(
            "disassemble_function",
            "Return recovered basic blocks and instruction listing in tool text (bounded for large functions)",
            serde_json::json!({
                "type": "object",
                "properties": { "query": { "type": "string" } },
                "required": ["query"]
            }),
        ),
        tool_manifest(
            "xrefs_query",
            "Query xrefs; tool text lists from->to with kind. Prefer address queries from string/function hits",
            serde_json::json!({
                "type": "object",
                "properties": { "query": { "type": "string" } },
                "required": ["query"]
            }),
        ),
        tool_manifest(
            "callgraph_slice",
            "Return callgraph edges around a function; tool text lists caller/callee names and addresses",
            serde_json::json!({
                "type": "object",
                "properties": { "query": { "type": "string" } },
                "required": ["query"]
            }),
        ),
        tool_manifest(
            "string_search",
            "Search recovered strings; text lists address+value matches. Follow with xrefs_query on a string address",
            serde_json::json!({
                "type": "object",
                "properties": { "pattern": { "type": "string" } },
                "required": ["pattern"]
            }),
        ),
        tool_manifest(
            "search_bytes",
            "Search bytes in the latest analyzed binary",
            serde_json::json!({
                "type": "object",
                "properties": { "pattern": { "type": "string" } },
                "required": ["pattern"]
            }),
        ),
        tool_manifest(
            "object_search_content",
            "Search text or hex bytes across persisted universal objects, including virtual container children",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string" },
                    "mode": { "type": ["string", "null"], "enum": ["text", "hex", null] },
                    "query": { "type": ["string", "null"] },
                    "limit": { "type": ["integer", "null"] },
                    "per_object_limit": { "type": ["integer", "null"] },
                    "max_object_bytes": { "type": ["integer", "null"] }
                },
                "required": ["pattern"]
            }),
        ),
        tool_manifest(
            "artifact_read",
            "Read a bounded preview of a workspace artifact by relative path or blake3 hash",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "relative_path": { "type": ["string", "null"] },
                    "hash_blake3": { "type": ["string", "null"] },
                    "offset": { "type": ["integer", "null"] },
                    "max_bytes": { "type": ["integer", "null"] }
                }
            }),
        ),
        tool_manifest(
            "artifact_list",
            "List and search workspace artifacts with roles and provenance references for agent navigation",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "query": { "type": ["string", "null"] },
                    "content_type": { "type": ["string", "null"] },
                    "role": { "type": ["string", "null"] },
                    "limit": { "type": ["integer", "null"] },
                    "include_unreferenced": { "type": ["boolean", "null"] }
                }
            }),
        ),
        tool_manifest(
            "evidence_pack",
            "Read evidence for a subject; tool text includes summaries and key details, not just counts",
            serde_json::json!({
                "type": "object",
                "properties": { "subject": { "type": "string" } },
                "required": ["subject"]
            }),
        ),
        tool_manifest(
            "evidence_graph",
            "Derive a bounded evidence graph connecting subjects, objects, artifacts, provenance, binaries, and functions",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "subject": { "type": "string" },
                    "depth": { "type": ["integer", "null"] },
                    "limit": { "type": ["integer", "null"] }
                },
                "required": ["subject"]
            }),
        ),
        tool_manifest(
            "symbolic_solve",
            "Solve a finite symbolic constraint case and persist the result as evidence",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "subject": { "type": "string" },
                    "variables": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": { "type": "string" },
                                "domain": {
                                    "type": "object",
                                    "properties": {
                                        "kind": { "type": "string", "enum": ["int_range", "int_values"] },
                                        "min": { "type": "integer" },
                                        "max": { "type": "integer" },
                                        "values": { "type": "array", "items": { "type": "integer" } }
                                    },
                                    "required": ["kind"]
                                }
                            },
                            "required": ["name", "domain"]
                        }
                    },
                    "constraints": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": { "type": ["string", "null"] },
                                "left": {
                                    "type": "object",
                                    "properties": {
                                        "terms": {
                                            "type": "array",
                                            "items": {
                                                "type": "object",
                                                "properties": {
                                                    "variable": { "type": "string" },
                                                    "coefficient": { "type": "integer" }
                                                },
                                                "required": ["variable", "coefficient"]
                                            }
                                        },
                                        "constant": { "type": "integer" }
                                    }
                                },
                                "op": { "type": "string", "enum": ["eq", "ne", "lt", "le", "gt", "ge"] },
                                "right": {
                                    "type": "object",
                                    "properties": {
                                        "terms": {
                                            "type": "array",
                                            "items": {
                                                "type": "object",
                                                "properties": {
                                                    "variable": { "type": "string" },
                                                    "coefficient": { "type": "integer" }
                                                },
                                                "required": ["variable", "coefficient"]
                                            }
                                        },
                                        "constant": { "type": "integer" }
                                    }
                                }
                            },
                            "required": ["left", "op", "right"]
                        }
                    },
                    "max_solutions": { "type": ["integer", "null"] },
                    "iteration_limit": { "type": ["integer", "null"] }
                },
                "required": ["subject", "variables", "constraints"]
            }),
        ),
        tool_manifest(
            "analysis_brief",
            "One-shot multi-hop RE brief for agents: ranked strings/functions, xref-backed hot functions, pseudocode previews, and next_actions with args. Prefer this over chaining string_search→xrefs→function_profile manually",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" },
                    "string_limit": { "type": ["integer", "null"] },
                    "function_limit": { "type": ["integer", "null"] },
                    "hot_function_limit": { "type": ["integer", "null"] },
                    "xref_limit": { "type": ["integer", "null"] },
                    "include_pseudocode": { "type": ["boolean", "null"] }
                },
                "required": ["query"]
            }),
        ),
        tool_manifest(
            "investigation_run",
            "Run an AI-native investigation. Tool text includes agent_brief, ranked next_actions with args, key findings, report body; execute next_actions[0] only then reassess",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "subject": { "type": "string" },
                    "path": { "type": ["string", "null"] },
                    "run_object_pipeline": { "type": ["boolean", "null"] },
                    "max_depth": { "type": ["integer", "null"] },
                    "max_children": { "type": ["integer", "null"] },
                    "object_limit": { "type": ["integer", "null"] },
                    "carve_max_depth": { "type": ["integer", "null"] },
                    "carve_max_children": { "type": ["integer", "null"] },
                    "plugin_ids": { "type": ["array", "null"], "items": { "type": "string" } },
                    "analyze_binaries": { "type": ["boolean", "null"] },
                    "binary_profile": { "type": ["string", "null"], "enum": ["fast", "full", null] },
                    "graph_depth": { "type": ["integer", "null"] },
                    "graph_limit": { "type": ["integer", "null"] },
                    "trace_kind": { "type": ["string", "null"] },
                    "trace_limit": { "type": ["integer", "null"] }
                },
                "required": ["subject"]
            }),
        ),
        tool_manifest(
            "ibc_status",
            "Inspect durable CASL IBC continuum: pc/status/epoch/witnesses/orbit hypotheses and ranked next_actions",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "namespace": { "type": ["string", "null"] }
                }
            }),
        ),
        tool_manifest(
            "ibc_advance",
            "Advance durable CASL IBC continuum: force_next or warp by tool+query; auto-binds orbit hypotheses",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "namespace": { "type": ["string", "null"] },
                    "tool": { "type": ["string", "null"] },
                    "query": { "type": ["string", "null"] },
                    "force_next": { "type": ["boolean", "null"] }
                }
            }),
        ),
        tool_manifest(
            "hypothesis_create",
            "Create a workspace-local hypothesis",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "title": { "type": "string" },
                    "notes": { "type": "string" },
                    "evidence_ids": { "type": "array", "items": { "type": "string" } }
                },
                "required": ["title", "notes", "evidence_ids"]
            }),
        ),
        tool_manifest(
            "hypothesis_update",
            "Update a workspace-local hypothesis",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "title": { "type": ["string", "null"] },
                    "notes": { "type": ["string", "null"] },
                    "evidence_ids": { "type": ["array", "null"], "items": { "type": "string" } }
                },
                "required": ["id"]
            }),
        ),
        tool_manifest(
            "report_generate",
            "Generate a report preview and artifact",
            serde_json::json!({
                "type": "object",
                "properties": { "topic": { "type": "string" } },
                "required": ["topic"]
            }),
        ),
        tool_manifest(
            "trace_import",
            "Import trace events",
            serde_json::json!({
                "type": "object",
                "properties": { "events": { "type": "array" } },
                "required": ["events"]
            }),
        ),
        tool_manifest(
            "trace_query",
            "Query imported traces",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "kind": { "type": ["string", "null"] },
                    "limit": { "type": ["integer", "null"] }
                }
            }),
        ),
    ]
}

pub(crate) fn tool_manifest(
    name: &str,
    description: &str,
    input_schema: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
    })
}
