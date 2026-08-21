use super::*;

pub(crate) fn mcp_response_summary(response: &CapabilityResponse) -> String {
    const MAX_CHARS: usize = 24_000;
    let body = match response {
        CapabilityResponse::ProjectOpen(payload) => format!(
            "# project_open\nworkspace: {}\nproject: {}\nschema: {}",
            payload.workspace_root, payload.project.name, payload.project.schema_version
        ),
        CapabilityResponse::ProjectStatus(payload) => {
            let mut lines = vec![
                "# project_status".to_string(),
                format!("workspace: {}", payload.workspace_root),
                format!("project: {}", payload.project.name),
                format!("binaries: {}", payload.binary_count),
            ];
            if !payload.binaries.is_empty() {
                lines.push("\n## Binaries".to_string());
                for binary in payload.binaries.iter().take(40) {
                    lines.push(format!(
                        "- {}  path={}  {:?}/{:?}  funcs={} imports={} strings={} typed={} pseudocode={}",
                        binary.id,
                        binary.path,
                        binary.format,
                        binary.architecture,
                        binary.function_count,
                        binary.import_count,
                        binary.string_count,
                        binary.typed_function_count,
                        binary.structured_pseudocode_count
                    ));
                }
                if payload.binaries.len() > 40 {
                    lines.push(format!("- ... {} more", payload.binaries.len() - 40));
                }
            }
            lines.join("\n")
        }
        CapabilityResponse::ObjectIdentify(payload) => {
            let mut lines = vec![
                "# object_identify".to_string(),
                format!("root: {}", payload.root_id),
                format!(
                    "objects: {}  edges: {}  evidence: {}",
                    payload.object_count, payload.edge_count, payload.evidence_count
                ),
            ];
            if let Some(graph) = &payload.graph {
                lines.push("\n## Objects".to_string());
                for object in graph.objects.iter().take(30) {
                    lines.push(format!(
                        "- {}  name={}  kind={:?}  format={}  size={}  depth={}",
                        object.id,
                        object.display_name,
                        object.kind,
                        object.format.as_deref().unwrap_or("-"),
                        object.size,
                        object.depth
                    ));
                }
                if graph.objects.len() > 30 {
                    lines.push(format!("- ... {} more objects", graph.objects.len() - 30));
                }
            }
            if !payload.evidence_ids.is_empty() {
                lines.push(format!(
                    "\n## Evidence IDs\n{}",
                    format_id_list(&payload.evidence_ids, 20)
                ));
            }
            lines.join("\n")
        }
        CapabilityResponse::ObjectSearch(payload) => {
            let mut lines = vec![
                "# object_search".to_string(),
                format!("matches: {}", payload.objects.len()),
            ];
            for object in payload.objects.iter().take(40) {
                lines.push(format!(
                    "- {}  name={}  kind={:?}  format={}  size={}",
                    object.id,
                    object.display_name,
                    object.kind,
                    object.format.as_deref().unwrap_or("-"),
                    object.size
                ));
            }
            if payload.objects.len() > 40 {
                lines.push(format!("- ... {} more", payload.objects.len() - 40));
            }
            lines.join("\n")
        }
        CapabilityResponse::ObjectProfile(payload) => {
            let mut lines = vec![
                "# object_profile".to_string(),
                format!(
                    "id: {}  name: {}  kind: {:?}  format: {}  size: {}",
                    payload.object.id,
                    payload.object.display_name,
                    payload.object.kind,
                    payload.object.format.as_deref().unwrap_or("-"),
                    payload.object.size
                ),
            ];
            if !payload.incoming_edges.is_empty() {
                lines.push("\n## Incoming".to_string());
                for edge in payload.incoming_edges.iter().take(20) {
                    lines.push(format!("- {:?} {} -> {}", edge.kind, edge.from, edge.to));
                }
            }
            if !payload.outgoing_edges.is_empty() {
                lines.push("\n## Outgoing".to_string());
                for edge in payload.outgoing_edges.iter().take(20) {
                    lines.push(format!("- {:?} {} -> {}", edge.kind, edge.from, edge.to));
                }
            }
            if !payload.object.analyses.is_empty() {
                lines.push("\n## Analyses".to_string());
                for analysis in payload.object.analyses.iter().take(12) {
                    lines.push(format!(
                        "- {} [{:?}]: {}",
                        analysis.analyzer,
                        analysis.status,
                        truncate_chars(&analysis.summary, 240)
                    ));
                }
            }
            if !payload.evidence_ids.is_empty() {
                lines.push(format!(
                    "\n## Evidence IDs\n{}",
                    format_id_list(&payload.evidence_ids, 20)
                ));
            }
            lines.join("\n")
        }
        CapabilityResponse::ObjectMaterialize(payload) => format!(
            "# object_materialize\nid: {}\nname: {}\nartifact: {}\nsize: {}\ncontent_type: {}\nevidence: {}\npreview_hex: {}\npreview_text:\n{}",
            payload.object.id,
            payload.object.display_name,
            payload.artifact.relative_path,
            payload.artifact.size,
            payload.artifact.content_type,
            payload.evidence_id,
            truncate_chars(payload.preview_hex.as_deref().unwrap_or(""), 240),
            truncate_chars(payload.preview_text.as_deref().unwrap_or(""), 1_500)
        ),
        CapabilityResponse::ObjectExtractRange(payload) => format!(
            "# object_extract_range\nid: {}\noffset: 0x{:x}\nrequested: {}\nextracted: {}\nartifact: {}\nevidence: {}\npreview_hex: {}\npreview_text:\n{}",
            payload.object.id,
            payload.offset,
            payload.requested_length,
            payload.extracted_size,
            payload.artifact.relative_path,
            payload.evidence_id,
            truncate_chars(payload.preview_hex.as_deref().unwrap_or(""), 240),
            truncate_chars(payload.preview_text.as_deref().unwrap_or(""), 1_500)
        ),
        CapabilityResponse::ObjectSignatureScan(payload) => {
            let mut lines = vec![
                "# object_scan_signatures".to_string(),
                format!(
                    "object: {}  scanned: {}  signatures: {}  truncated: {}",
                    payload.object.id,
                    payload.scanned_size,
                    payload.returned_count,
                    payload.truncated
                ),
                format!("artifact: {}", payload.artifact.relative_path),
                format!("evidence: {}", payload.evidence_id),
            ];
            if !payload.signatures.is_empty() {
                lines.push("\n## Signatures".to_string());
                for hit in payload.signatures.iter().take(30) {
                    lines.push(format!(
                        "- 0x{:x}  {}  format={}  conf={:.2}  len={:?}  {}",
                        hit.offset,
                        hit.signature,
                        hit.format,
                        hit.confidence,
                        hit.suggested_length,
                        truncate_chars(&hit.description, 120)
                    ));
                }
            }
            lines.join("\n")
        }
        CapabilityResponse::ObjectCarveSignatures(payload) => {
            let mut lines = vec![
                "# object_carve_signatures".to_string(),
                format!(
                    "object: {}  scanned: {}  carved: {}  skipped: {}  truncated: {}",
                    payload.object.id,
                    payload.scanned_count,
                    payload.carved_count,
                    payload.skipped_count,
                    payload.truncated
                ),
                format!("artifact: {}", payload.artifact.relative_path),
                format!("evidence: {}", payload.carve_evidence_id),
            ];
            if !payload.carves.is_empty() {
                lines.push("\n## Carves".to_string());
                for carve in payload.carves.iter().take(20) {
                    lines.push(format!(
                        "- 0x{:x}+{}  {}  format={}  conf={:.2}  artifact={}",
                        carve.offset,
                        carve.length,
                        carve.signature,
                        carve.format,
                        carve.confidence,
                        carve.artifact.relative_path
                    ));
                }
            }
            lines.join("\n")
        }
        CapabilityResponse::ObjectCarveIdentify(payload) => {
            let mut lines = vec![
                "# object_carve_identify".to_string(),
                format!(
                    "object: {}  carved: {}  identified: {}  failed: {}",
                    payload.object.id,
                    payload.carved_count,
                    payload.identified_count,
                    payload.failed_count
                ),
                format!("artifact: {}", payload.artifact.relative_path),
            ];
            for item in payload.carves.iter().take(20) {
                lines.push(format!(
                    "- carve 0x{:x}+{} -> root={} objects={} edges={} error={}",
                    item.carve.offset,
                    item.carve.length,
                    item.root_id.as_deref().unwrap_or("-"),
                    item.object_count,
                    item.edge_count,
                    item.error.as_deref().unwrap_or("-")
                ));
            }
            lines.join("\n")
        }
        CapabilityResponse::ObjectAnalyze(payload) => {
            let mut lines = vec![
                "# object_analyze".to_string(),
                format!(
                    "object: {}  name: {}  kind: {:?}  format: {}",
                    payload.object.id,
                    payload.object.display_name,
                    payload.object.kind,
                    payload.object.format.as_deref().unwrap_or("-")
                ),
                format_agent_brief_section(&payload.agent_brief),
            ];
            if !payload.analyses.is_empty() {
                lines.push("\n## Analyses".to_string());
                for analysis in payload.analyses.iter().take(16) {
                    lines.push(format!(
                        "- {} [{:?}]: {}",
                        analysis.analyzer,
                        analysis.status,
                        truncate_chars(&analysis.summary, 320)
                    ));
                }
            }
            if !payload.evidence_ids.is_empty() {
                lines.push(format!(
                    "\n## Evidence IDs\n{}",
                    format_id_list(&payload.evidence_ids, 20)
                ));
            }
            if let Some(artifact) = &payload.artifact {
                lines.push(format!("\nartifact: {}", artifact.relative_path));
            }
            lines.join("\n")
        }
        CapabilityResponse::ObjectPluginList(payload) => {
            let mut lines = vec![
                "# object_plugin_list".to_string(),
                format!("plugins: {}", payload.plugins.len()),
            ];
            for plugin in payload.plugins.iter().take(40) {
                lines.push(format!(
                    "- {}  {}  timeout_ms={:?}",
                    plugin.id,
                    plugin
                        .description
                        .as_deref()
                        .unwrap_or(plugin.name.as_str()),
                    plugin.timeout_ms
                ));
            }
            lines.join("\n")
        }
        CapabilityResponse::ObjectPluginRun(payload) => {
            let mut lines = vec![
                "# object_plugin_run".to_string(),
                format!(
                    "plugin: {}  object: {}  status: {:?}  evidence: {}",
                    payload.plugin.id, payload.object.id, payload.status, payload.evidence_id
                ),
                format!("summary: {}", truncate_chars(&payload.summary, 500)),
            ];
            if let Some(stdout) = &payload.stdout_preview {
                lines.push(format!("\n## stdout\n{}", truncate_chars(stdout, 2_000)));
            }
            if let Some(stderr) = &payload.stderr_preview {
                lines.push(format!("\n## stderr\n{}", truncate_chars(stderr, 1_000)));
            }
            if let Some(json) = &payload.output_json {
                lines.push(format!(
                    "\n## output_json\n{}",
                    truncate_chars(&json.to_string(), 2_000)
                ));
            }
            lines.join("\n")
        }
        CapabilityResponse::ObjectRegisterBinary(payload) => format!(
            "# object_register_binary\nobject: {}\nbinary: {}\npath: {}\nformat: {:?}\narch: {:?}\nentry: {:?}\nfunctions: {}\nimports: {}\nexports: {}\nstrings: {}\nevidence: {}\nsurvey_artifact: {}",
            payload.object.id,
            payload.survey.binary.id,
            payload.survey.binary.path,
            payload.survey.binary.format,
            payload.survey.binary.architecture,
            payload.survey.binary.entry,
            payload.survey.summary.function_count,
            payload.survey.summary.import_count,
            payload.survey.summary.export_count,
            payload.survey.summary.string_count,
            payload.evidence_id,
            payload.survey_artifact.relative_path
        ),
        CapabilityResponse::ObjectAnalyzeBinary(payload) => format!(
            "# object_analyze_binary\nobject: {}\nrun_id: {}\nstatus: {:?}\n{}\nevidence: {}\n{}",
            payload.object.id,
            payload.run_id,
            payload.status,
            format_analysis_summary(&payload.summary),
            payload.evidence_count,
            format_id_list(&payload.evidence_ids, 16)
        ),
        CapabilityResponse::ObjectPipeline(payload) => {
            let mut lines = vec![
                "# object_pipeline".to_string(),
                format!("pipeline_id: {}", payload.pipeline_id),
                format!(
                    "root: {}  objects: {}  edges: {}  analyzed_objects: {}  carved: {}  embedded: {}  binaries: {}  failed: {}  evidence: {}",
                    payload.root_id,
                    payload.object_count,
                    payload.edge_count,
                    payload.analyzed_object_count,
                    payload.carved_object_count,
                    payload.identified_embedded_object_count,
                    payload.analyzed_binary_count,
                    payload.failed_step_count,
                    payload.evidence_count
                ),
                format_agent_brief_section(&payload.agent_brief),
            ];
            if !payload.steps.is_empty() {
                lines.push("\n## Steps".to_string());
                for step in payload.steps.iter().take(24) {
                    lines.push(format!(
                        "- {:?} {:?} [{:?}]: {}",
                        step.stage,
                        step.object_path,
                        step.status,
                        truncate_chars(&step.summary, 200)
                    ));
                }
                if payload.steps.len() > 24 {
                    lines.push(format!("- ... {} more steps", payload.steps.len() - 24));
                }
            }
            lines.push(format!(
                "\nreport_artifact: {}\ngraph_artifact: {}",
                payload.report_artifact.relative_path, payload.graph_artifact.relative_path
            ));
            lines.join("\n")
        }
        CapabilityResponse::BinaryList(payload) => {
            let mut lines = vec![
                "# binary_list".to_string(),
                format!("binaries: {}", payload.binaries.len()),
            ];
            for binary in payload.binaries.iter().take(40) {
                lines.push(format!(
                    "- {}  path={}  {:?}/{:?}  funcs={} imports={} exports={} strings={}",
                    binary.id,
                    binary.path,
                    binary.format,
                    binary.architecture,
                    binary.function_count,
                    binary.import_count,
                    binary.export_count,
                    binary.string_count
                ));
            }
            lines.join("\n")
        }
        CapabilityResponse::AnalysisRun(payload) => format!(
            "# analysis_run\nrun_id: {}\nstatus: {:?}\n{}\nevidence_count: {}\nevidence_ids:\n{}\nnext: function_search / binary_survey / string_search",
            payload.run_id,
            payload.status,
            format_analysis_summary(&payload.summary),
            payload.evidence_count,
            format_id_list(&payload.evidence_ids, 20)
        ),
        CapabilityResponse::AnalysisStatus(payload) => format!(
            "# analysis_status\nrun_id: {}\nbinary_id: {}\nprofile: {:?}\nstatus: {:?}\ncreated_at: {}\ncompleted_at: {:?}\n{}",
            payload.run_id,
            payload.binary_id,
            payload.profile,
            payload.status,
            payload.created_at,
            payload.completed_at,
            format_analysis_summary(&payload.summary)
        ),
        CapabilityResponse::BinarySurvey(payload) => {
            let mut lines = vec![
                "# binary_survey".to_string(),
                format_analysis_summary(&payload.preview),
                format!("evidence_count: {}", payload.evidence_count),
            ];
            if let Some(survey) = &payload.survey {
                lines.push(format!(
                    "path: {}\nentry: {:?}\nimage_base: {:?}\nsize: {}\nhash: {}",
                    survey.binary.path,
                    survey.binary.entry,
                    survey.binary.image_base,
                    survey.binary.size,
                    survey.binary.hash_blake3
                ));
            }
            if !payload.evidence_ids.is_empty() {
                lines.push(format!(
                    "\n## Evidence IDs\n{}",
                    format_id_list(&payload.evidence_ids, 20)
                ));
            }
            lines.push(
                "\nnext: function_search(query) | string_search(pattern) | function_profile(name|addr)"
                    .to_string(),
            );
            lines.join("\n")
        }
        CapabilityResponse::FunctionSearch(payload) => {
            let mut lines = vec![
                "# function_search".to_string(),
                format!("matches: {}", payload.functions.len()),
            ];
            if payload.functions.is_empty() {
                lines.push("no matches".to_string());
            } else {
                for function in payload.functions.iter().take(50) {
                    lines.push(format!(
                        "- {}  0x{:x}  size={}  evidence={}",
                        function.name,
                        function.address,
                        function.size,
                        function.evidence_ids.len()
                    ));
                }
                if payload.functions.len() > 50 {
                    lines.push(format!("- ... {} more", payload.functions.len() - 50));
                }
                lines.push(
                    "\nnext: function_profile(query) | decompile_function(query) | disassemble_function(query)"
                        .to_string(),
                );
            }
            lines.join("\n")
        }
        CapabilityResponse::FunctionProfile(payload) => render_function_profile(payload),
        CapabilityResponse::DecompileFunction(payload) => {
            let mut lines = vec![
                "# decompile_function".to_string(),
                format!("name: {}", payload.function_name),
                format!("address: 0x{:x}", payload.address),
                format!("strategy: {:?}", payload.strategy_used),
                format!("cache_hit: {}", payload.cache_hit),
            ];
            if !payload.available_strategies.is_empty() {
                lines.push(format!(
                    "available_strategies: {}",
                    payload.available_strategies.join(",")
                ));
            }
            if let Some(unit) = &payload.pseudocode {
                if let Some(lattice) = &unit.semantic_lattice {
                    lines.push(String::new());
                    lines.push(revx_analysis::format_semantic_lattice(lattice));
                } else if let Some(lattice) = &payload.agent_brief.semantic_lattice {
                    lines.push(String::new());
                    lines.push(revx_analysis::format_semantic_lattice(lattice));
                }
            } else if let Some(lattice) = &payload.agent_brief.semantic_lattice {
                lines.push(String::new());
                lines.push(revx_analysis::format_semantic_lattice(lattice));
            }
            lines.push(format!(
                "\n## Digest\n{}",
                function_pseudocode_digest(payload.pseudocode.as_ref(), &[], &[])
            ));
            match &payload.pseudocode {
                Some(unit) => {
                    lines.push(format!("language: {}", unit.language));
                    lines.push(format!(
                        "regions: {}  evidence: {}",
                        unit.regions.len(),
                        unit.evidence_ids.len()
                    ));
                    lines.push("\n## Pseudocode".to_string());
                    lines.push(format!("```{}\n{}\n```", unit.language, unit.text));
                    if !unit.regions.is_empty() {
                        lines.push("\n## Regions".to_string());
                        for region in unit.regions.iter().take(24) {
                            lines.push(format!(
                                "- {} {:?}  {:x?}-{:x?}  stmts={}  {}",
                                region.id,
                                region.kind,
                                region.start_address,
                                region.end_address,
                                region.statements.len(),
                                region.header.as_deref().unwrap_or("")
                            ));
                        }
                    }
                }
                None => lines.push(
                    "pseudocode: unavailable\nnext: disassemble_function(query) | function_profile(query)"
                        .to_string(),
                ),
            }
            if !payload.evidence_ids.is_empty() {
                lines.push(format!(
                    "\n## Evidence IDs\n{}",
                    format_id_list(&payload.evidence_ids, 20)
                ));
            }
            if !payload.agent_brief.headline.is_empty()
                || !payload.agent_brief.next_actions.is_empty()
            {
                lines.push(format_agent_brief_section(&payload.agent_brief));
            }
            if let Some(artifact) = &payload.artifact {
                lines.push(format!("\nartifact: {}", artifact.relative_path));
            }
            lines.join("\n")
        }
        CapabilityResponse::DecompileCacheStatus(payload) => {
            let mut lines = vec![
                "# decompile_cache_status".to_string(),
                format!("name: {}", payload.function_name),
                format!("address: 0x{:x}", payload.address),
                format!(
                    "function_pseudocode: {} regions={} text_len={}",
                    payload.has_function_pseudocode,
                    payload.function_region_count,
                    payload.function_text_len
                ),
                format!("strategy_caches: {}", payload.strategies.len()),
            ];
            if payload.strategies.is_empty() {
                lines.push("no strategy cache entries".to_string());
            } else {
                for entry in &payload.strategies {
                    lines.push(format!(
                        "- {} regions={} text_len={} lattice={}",
                        entry.strategy, entry.region_count, entry.text_len, entry.has_lattice
                    ));
                }
            }
            lines.push(
                "
next: decompile_function(query, strategy) | function_profile(query)"
                    .to_string(),
            );
            lines.join(
                "
",
            )
        }
        CapabilityResponse::DisassembleFunction(payload) => render_disassembly(payload),
        CapabilityResponse::XrefsQuery(payload) => {
            let mut lines = vec![
                "# xrefs_query".to_string(),
                format!("references: {}", payload.references.len()),
            ];
            for reference in payload.references.iter().take(80) {
                lines.push(format!(
                    "- 0x{:x} -> 0x{:x}  {}",
                    reference.from, reference.to, reference.kind
                ));
            }
            if payload.references.len() > 80 {
                lines.push(format!("- ... {} more", payload.references.len() - 80));
            }
            if !payload.agent_brief.headline.is_empty()
                || !payload.agent_brief.next_actions.is_empty()
            {
                lines.push(format_agent_brief_section(&payload.agent_brief));
            } else if !payload.references.is_empty() {
                lines.push(
                    "\nnext: function_profile(0xaddr) | decompile_function(0xaddr) | disassemble_function(0xaddr)"
                        .to_string(),
                );
            }
            lines.join("\n")
        }
        CapabilityResponse::CallgraphSlice(payload) => {
            let mut lines = vec![
                "# callgraph_slice".to_string(),
                format!("edges: {}", payload.edges.len()),
            ];
            for edge in payload.edges.iter().take(60) {
                lines.push(format!(
                    "- {} (0x{:x}) -[{}]-> {} (0x{:x})",
                    edge.caller_name,
                    edge.caller_address,
                    edge.kind,
                    edge.callee_name.as_deref().unwrap_or("?"),
                    edge.callee_address
                ));
            }
            if payload.edges.len() > 60 {
                lines.push(format!("- ... {} more", payload.edges.len() - 60));
            }
            lines.join("\n")
        }
        CapabilityResponse::StringSearch(payload) => {
            let mut lines = vec![
                "# string_search".to_string(),
                format!("matches: {}", payload.matches.len()),
            ];
            for item in payload.matches.iter().take(60) {
                match item.address {
                    Some(address) => lines.push(format!(
                        "- 0x{:x}  {}",
                        address,
                        truncate_chars(&item.value, 200)
                    )),
                    None => lines.push(format!("- {}", truncate_chars(&item.value, 200))),
                }
            }
            if payload.matches.len() > 60 {
                lines.push(format!("- ... {} more", payload.matches.len() - 60));
            }
            if !payload.agent_brief.headline.is_empty()
                || !payload.agent_brief.next_actions.is_empty()
            {
                lines.push(format_agent_brief_section(&payload.agent_brief));
            } else if !payload.matches.is_empty() {
                lines.push(
                    "\nnext: xrefs_query(0xstring_addr) then function_profile on owning function"
                        .to_string(),
                );
            }
            lines.join("\n")
        }
        CapabilityResponse::SearchBytes(payload) => {
            let mut lines = vec![
                "# search_bytes".to_string(),
                format!("matches: {}", payload.matches.len()),
            ];
            for item in payload.matches.iter().take(40) {
                lines.push(format!(
                    "- 0x{:x}  {}",
                    item.offset,
                    truncate_chars(&item.bytes, 120)
                ));
            }
            if payload.matches.len() > 40 {
                lines.push(format!("- ... {} more", payload.matches.len() - 40));
            }
            lines.join("\n")
        }
        CapabilityResponse::ObjectContentSearch(payload) => {
            let mut lines = vec![
                "# object_search_content".to_string(),
                format!(
                    "pattern: {}  mode: {:?}  objects: {}  searched: {}  matches: {}  truncated: {}",
                    payload.pattern,
                    payload.mode,
                    payload.object_count,
                    payload.searched_object_count,
                    payload.returned_count,
                    payload.truncated
                ),
            ];
            for item in payload.matches.iter().take(40) {
                lines.push(format!(
                    "- {}  0x{:x}+{}  kind={:?}  text={}",
                    item.display_name,
                    item.offset,
                    item.length,
                    item.object_kind,
                    truncate_chars(
                        item.preview_text.as_deref().unwrap_or(&item.preview_hex),
                        160
                    )
                ));
            }
            if payload.matches.len() > 40 {
                lines.push(format!("- ... {} more", payload.matches.len() - 40));
            }
            lines.join("\n")
        }
        CapabilityResponse::ArtifactRead(payload) => {
            let mut lines = vec![
                "# artifact_read".to_string(),
                format!(
                    "path: {}  hash: {}  offset: {}  returned: {}/{}  truncated: {}",
                    payload.artifact.relative_path,
                    payload.artifact.hash_blake3,
                    payload.offset,
                    payload.returned_size,
                    payload.total_size,
                    payload.truncated
                ),
                format!("content_type: {}", payload.artifact.content_type),
            ];
            if let Some(text) = &payload.preview_text {
                lines.push(format!("\n## Text\n{}", truncate_chars(text, 8_000)));
            } else {
                lines.push(format!(
                    "\n## Hex\n{}",
                    truncate_chars(&payload.preview_hex, 2_000)
                ));
            }
            lines.join("\n")
        }
        CapabilityResponse::ArtifactList(payload) => {
            let mut lines = vec![
                "# artifact_list".to_string(),
                format!(
                    "returned: {}/{}  truncated: {}",
                    payload.returned_count, payload.total_count, payload.truncated
                ),
            ];
            for hit in payload.artifacts.iter().take(40) {
                lines.push(format!(
                    "- {}  {}  size={}  roles=[{}]  refs={}",
                    hit.artifact.relative_path,
                    hit.artifact.content_type,
                    hit.artifact.size,
                    hit.roles.join(","),
                    hit.references.len()
                ));
            }
            lines.join("\n")
        }
        CapabilityResponse::EvidencePack(payload) => {
            let mut lines = vec![
                "# evidence_pack".to_string(),
                format!("preview: {}", payload.preview.len()),
            ];
            for evidence in payload.preview.iter().take(40) {
                lines.push(format!(
                    "- [{}] {}  subject={}  {}",
                    evidence.kind,
                    evidence.id,
                    evidence.subject,
                    truncate_chars(&evidence.summary, 220)
                ));
                if !evidence.details.is_null() {
                    let details = truncate_chars(&evidence.details.to_string(), 280);
                    if details != "null" && details != "{}" {
                        lines.push(format!("  details: {details}"));
                    }
                }
            }
            if payload.preview.len() > 40 {
                lines.push(format!("- ... {} more", payload.preview.len() - 40));
            }
            if let Some(artifact) = &payload.artifact {
                lines.push(format!("\nartifact: {}", artifact.relative_path));
            }
            lines.join("\n")
        }
        CapabilityResponse::EvidenceGraph(payload) => {
            let mut lines = vec![
                "# evidence_graph".to_string(),
                format!(
                    "subject: {}  nodes: {}  edges: {}  evidence: {}",
                    payload.subject, payload.node_count, payload.edge_count, payload.evidence_count
                ),
                format!("artifact: {}", payload.artifact.relative_path),
            ];
            if !payload.nodes.is_empty() {
                lines.push("\n## Nodes".to_string());
                for node in payload.nodes.iter().take(40) {
                    lines.push(format!(
                        "- {}  kind={}  {}  {}",
                        node.id,
                        node.kind,
                        node.label,
                        truncate_chars(node.summary.as_deref().unwrap_or(""), 120)
                    ));
                }
            }
            if !payload.edges.is_empty() {
                lines.push("\n## Edges".to_string());
                for edge in payload.edges.iter().take(40) {
                    lines.push(format!(
                        "- {} -[{}/{}]-> {}",
                        edge.from, edge.kind, edge.label, edge.to
                    ));
                }
            }
            lines.join("\n")
        }
        CapabilityResponse::SymbolicSolve(payload) => {
            let mut lines = vec![
                "# symbolic_solve".to_string(),
                format!(
                    "case: {}  subject: {}  status: {:?}  constraints: {}  checked: {}",
                    payload.case_id,
                    payload.subject,
                    payload.status,
                    payload.constraint_count,
                    payload.checked_assignments
                ),
                format!("evidence: {}", payload.evidence_id),
            ];
            if !payload.solutions.is_empty() {
                lines.push("\n## Solutions".to_string());
                for (index, solution) in payload.solutions.iter().take(10).enumerate() {
                    let pairs = solution
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    lines.push(format!("- #{index}: {pairs}"));
                }
            }
            if !payload.warnings.is_empty() {
                lines.push("\n## Warnings".to_string());
                for warning in payload.warnings.iter().take(10) {
                    lines.push(format!("- {warning}"));
                }
            }
            lines.join("\n")
        }
        CapabilityResponse::AnalysisBrief(payload) => render_analysis_brief(payload),
        CapabilityResponse::InvestigationRun(payload) => {
            let mut lines = vec![
                "# investigation_run".to_string(),
                format!("id: {}", payload.investigation_id),
                format!("subject: {}", payload.subject),
                format!(
                    "evidence: {}  graph_nodes: {}  graph_edges: {}  traces: {}",
                    payload.evidence_count,
                    payload.graph.node_count,
                    payload.graph.edge_count,
                    payload.trace_count
                ),
                format_agent_brief_section(&payload.agent_brief),
                format!("\n## Summary\n{}", truncate_chars(&payload.summary, 2_000)),
            ];
            if !payload.report.body.is_empty() {
                lines.push(format!(
                    "\n## Report\n{}",
                    truncate_chars(&payload.report.body, 8_000)
                ));
            }
            lines.push(format!(
                "\nreport_artifact: {}\nartifact: {}",
                payload.report_artifact.relative_path, payload.artifact.relative_path
            ));
            lines.join("\n")
        }
        CapabilityResponse::IbcStatus(payload) => {
            let mut lines = vec![
                "# ibc_status".to_string(),
                format!("namespace: {}", payload.active_namespace),
                format!("focus: {}", payload.focus),
                format!(
                    "pc: {}  status: {}  epoch: {}",
                    payload.pc, payload.status, payload.epoch
                ),
                format!("summary: {}", payload.summary),
                format_agent_brief_section(&payload.agent_brief),
            ];
            if !payload.hypothesis_ids.is_empty() {
                lines.push(format!(
                    "
hypotheses:
{}",
                    format_id_list(&payload.hypothesis_ids, 20)
                ));
            }
            lines.join(
                "
",
            )
        }
        CapabilityResponse::IbcAdvance(payload) => {
            let mut lines = vec![
                "# ibc_advance".to_string(),
                format!("advanced: {}", payload.advanced),
                format!("namespace: {}", payload.namespace),
                format!(
                    "pc: {}  status: {}  epoch: {}",
                    payload.pc, payload.status, payload.epoch
                ),
                format!("note: {}", payload.note),
                format_agent_brief_section(&payload.agent_brief),
            ];
            if !payload.hypothesis_ids.is_empty() {
                lines.push(format!(
                    "
hypotheses:
{}",
                    format_id_list(&payload.hypothesis_ids, 20)
                ));
            }
            lines.join(
                "
",
            )
        }
        CapabilityResponse::HypothesisCreate(payload) => format!(
            "# hypothesis_create\nid: {}\ntitle: {}\nnotes:\n{}\nevidence:\n{}",
            payload.hypothesis.id,
            payload.hypothesis.title,
            truncate_chars(&payload.hypothesis.notes, 2_000),
            format_id_list(&payload.hypothesis.evidence_ids, 20)
        ),
        CapabilityResponse::HypothesisUpdate(payload) => format!(
            "# hypothesis_update\nid: {}\ntitle: {}\nnotes:\n{}\nevidence:\n{}",
            payload.hypothesis.id,
            payload.hypothesis.title,
            truncate_chars(&payload.hypothesis.notes, 2_000),
            format_id_list(&payload.hypothesis.evidence_ids, 20)
        ),
        CapabilityResponse::ReportGenerate(payload) => {
            let mut lines = vec![
                "# report_generate".to_string(),
                format!("id: {}", payload.report.id),
                format!("topic: {}", payload.report.topic),
                format!(
                    "\n## Body\n{}",
                    truncate_chars(&payload.report.body, 10_000)
                ),
            ];
            if !payload.report.evidence_ids.is_empty() {
                lines.push(format!(
                    "\n## Evidence IDs\n{}",
                    format_id_list(&payload.report.evidence_ids, 20)
                ));
            }
            if let Some(artifact) = &payload.artifact {
                lines.push(format!("\nartifact: {}", artifact.relative_path));
            }
            lines.join("\n")
        }
        CapabilityResponse::TraceImport(payload) => format!(
            "# trace_import\nimported: {}\nevidence: {}\nevidence_ids:\n{}",
            payload.imported,
            payload.evidence_count,
            format_id_list(&payload.evidence_ids, 20)
        ),
        CapabilityResponse::TraceQuery(payload) => {
            let mut lines = vec![
                "# trace_query".to_string(),
                format!("events: {}", payload.events.len()),
            ];
            for event in payload.events.iter().take(40) {
                lines.push(format!(
                    "- {}  {}/{}  kind={}  loc={:?}  {}",
                    event.timestamp,
                    event.process,
                    event.thread,
                    event.kind,
                    event.location,
                    truncate_chars(&event.payload.to_string(), 160)
                ));
            }
            if payload.events.len() > 40 {
                lines.push(format!("- ... {} more", payload.events.len() - 40));
            }
            lines.join("\n")
        }
    };
    truncate_chars(&body, MAX_CHARS)
}

pub(crate) fn truncate_chars(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    let mut out = input.chars().take(max_chars).collect::<String>();
    out.push_str("\n...[truncated]");
    out
}

pub(crate) fn format_id_list(ids: &[String], limit: usize) -> String {
    if ids.is_empty() {
        return "- none".to_string();
    }
    let mut lines = ids
        .iter()
        .take(limit)
        .map(|id| format!("- {id}"))
        .collect::<Vec<_>>();
    if ids.len() > limit {
        lines.push(format!("- ... {} more", ids.len() - limit));
    }
    lines.join("\n")
}

pub(crate) fn format_analysis_summary(summary: &revx_core::AnalysisSummary) -> String {
    let mut out = format!(
        "binary_id: {}\nformat: {:?}\narch: {:?}\nfunctions: {}\nimports: {}\nexports: {}\nstrings: {}\ntyped_functions: {}\nstructured_pseudocode: {}\nevidence: {}\ndebug: {:?} types={} fn_hints={} var_hints={}",
        summary.binary_id,
        summary.format,
        summary.architecture,
        summary.function_count,
        summary.import_count,
        summary.export_count,
        summary.string_count,
        summary.typed_function_count,
        summary.structured_pseudocode_count,
        summary.evidence_count,
        summary.debug_import_coverage.status,
        summary.debug_import_coverage.imported_type_count,
        summary.debug_import_coverage.imported_function_hint_count,
        summary.debug_import_coverage.imported_variable_hint_count
    );
    if !summary.warnings.is_empty() {
        out.push_str("\nwarnings:");
        for warning in summary.warnings.iter().take(8) {
            out.push_str(&format!("\n- {warning}"));
        }
    }
    out
}

pub(crate) fn format_agent_brief_section(brief: &AgentInteractionBrief) -> String {
    let mut lines = vec![
        "\n## Agent Brief".to_string(),
        format!(
            "headline: {}",
            if brief.headline.is_empty() {
                "-"
            } else {
                &brief.headline
            }
        ),
    ];
    if let Some(lattice) = &brief.semantic_lattice {
        lines.push(revx_analysis::format_semantic_lattice(lattice));
    }
    if !brief.key_findings.is_empty() {
        lines.push("key_findings:".to_string());
        for item in brief.key_findings.iter().take(12) {
            lines.push(format!("- {}", truncate_chars(item, 240)));
        }
    }
    if !brief.open_questions.is_empty() {
        lines.push("open_questions:".to_string());
        for item in brief.open_questions.iter().take(8) {
            lines.push(format!("- {}", truncate_chars(item, 240)));
        }
    }
    if !brief.next_actions.is_empty() {
        lines.push("next_actions:".to_string());
        for action in brief.next_actions.iter().take(8) {
            lines.push(format!(
                "- p{} `{}`{}: {}\n  args: {}",
                action.priority,
                action.tool,
                action
                    .label
                    .as_deref()
                    .map(|label| format!(" ({label})"))
                    .unwrap_or_default(),
                truncate_chars(&action.reason, 200),
                truncate_chars(&action.args.to_string(), 300)
            ));
        }
        if let Some(top) = brief.next_actions.first() {
            lines.push(format!(
                "EXECUTE NOW: `{}` args={}",
                top.tool,
                truncate_chars(&top.args.to_string(), 400)
            ));
        }
    }
    if !brief.stop_conditions.is_empty() {
        lines.push("stop_conditions:".to_string());
        for item in brief.stop_conditions.iter().take(6) {
            lines.push(format!("- {item}"));
        }
    }
    lines.join("\n")
}

pub(crate) fn render_function_profile(payload: &FunctionProfileResponse) -> String {
    let function = &payload.function;
    let mut lines = vec![
        "# function_profile".to_string(),
        format!("name: {}", function.name),
        format!("address: 0x{:x}", function.address),
        format!("size: {}", function.size),
        format!(
            "blocks: {}  callers: {}  callees: {}  xrefs_in: {}  xrefs_out: {}",
            function.blocks.len(),
            payload.callers.len(),
            payload.callees.len(),
            payload.incoming_xrefs.len(),
            payload.outgoing_xrefs.len()
        ),
    ];
    if let Some(unit) = &function.pseudocode {
        if let Some(lattice) = &unit.semantic_lattice {
            lines.push(String::new());
            lines.push(revx_analysis::format_semantic_lattice(lattice));
        }
    } else if let Some(lattice) = &payload.agent_brief.semantic_lattice {
        lines.push(String::new());
        lines.push(revx_analysis::format_semantic_lattice(lattice));
    }
    if let Some(stack) = &function.stack_summary {
        lines.push(format!(
            "stack: frame={:?} cc={:?} ret={:?} stack_args={:?}",
            stack.frame_size, stack.calling_convention, stack.return_type, stack.stack_arg_bytes
        ));
    }
    if !function.arguments.is_empty() {
        lines.push("\n## Arguments".to_string());
        for arg in function.arguments.iter().take(16) {
            lines.push(format!(
                "- {}  {:?}  {:?}  type={}  conf={:.2}  @{}",
                arg.name,
                arg.role,
                arg.storage,
                arg.type_name.as_deref().unwrap_or("?"),
                arg.confidence,
                arg.location
            ));
        }
    }
    if !function.locals.is_empty() {
        lines.push("\n## Locals".to_string());
        for local in function.locals.iter().take(24) {
            lines.push(format!(
                "- {}  {:?}  type={}  conf={:.2}  @{}",
                local.name,
                local.storage,
                local.type_name.as_deref().unwrap_or("?"),
                local.confidence,
                local.location
            ));
        }
    }
    if !payload.callers.is_empty() {
        lines.push("\n## Callers".to_string());
        for edge in payload.callers.iter().take(24) {
            lines.push(format!(
                "- {} (0x{:x}) -[{}]-> {} (0x{:x})",
                edge.caller_name,
                edge.caller_address,
                edge.kind,
                edge.callee_name.as_deref().unwrap_or(&function.name),
                edge.callee_address
            ));
        }
        if payload.callers.len() > 24 {
            lines.push(format!("- ... {} more", payload.callers.len() - 24));
        }
    }
    if !payload.callees.is_empty() {
        lines.push("\n## Callees".to_string());
        for edge in payload.callees.iter().take(24) {
            lines.push(format!(
                "- {} (0x{:x}) -[{}]-> {} (0x{:x})",
                edge.caller_name,
                edge.caller_address,
                edge.kind,
                edge.callee_name.as_deref().unwrap_or("?"),
                edge.callee_address
            ));
        }
        if payload.callees.len() > 24 {
            lines.push(format!("- ... {} more", payload.callees.len() - 24));
        }
    }
    if !payload.incoming_xrefs.is_empty() {
        lines.push("\n## Incoming xrefs".to_string());
        for reference in payload.incoming_xrefs.iter().take(30) {
            lines.push(format!(
                "- 0x{:x} -> 0x{:x}  {}",
                reference.from, reference.to, reference.kind
            ));
        }
        if payload.incoming_xrefs.len() > 30 {
            lines.push(format!("- ... {} more", payload.incoming_xrefs.len() - 30));
        }
    }
    if !payload.outgoing_xrefs.is_empty() {
        lines.push("\n## Outgoing xrefs".to_string());
        for reference in payload.outgoing_xrefs.iter().take(30) {
            lines.push(format!(
                "- 0x{:x} -> 0x{:x}  {}",
                reference.from, reference.to, reference.kind
            ));
        }
        if payload.outgoing_xrefs.len() > 30 {
            lines.push(format!("- ... {} more", payload.outgoing_xrefs.len() - 30));
        }
    }
    lines.push(format!(
        "\n## Digest\n{}",
        function_pseudocode_digest(
            function.pseudocode.as_ref(),
            &payload.callees,
            &payload.callers
        )
    ));
    if let Some(unit) = &function.pseudocode {
        lines.push("\n## Pseudocode".to_string());
        lines.push(format!(
            "```{}\n{}\n```",
            unit.language,
            truncate_chars(&unit.text, 6_000)
        ));
    }
    if !function.warnings.is_empty() {
        lines.push("\n## Warnings".to_string());
        for warning in function.warnings.iter().take(12) {
            lines.push(format!("- {warning}"));
        }
    }
    if !function.evidence_ids.is_empty() {
        lines.push(format!(
            "\n## Evidence IDs\n{}",
            format_id_list(&function.evidence_ids, 16)
        ));
    }
    if !payload.agent_brief.headline.is_empty() || !payload.agent_brief.next_actions.is_empty() {
        lines.push(format_agent_brief_section(&payload.agent_brief));
    } else {
        lines.push(format!(
            "\nnext: decompile_function({}) | disassemble_function({}) | xrefs_query(0x{:x})",
            function.name, function.name, function.address
        ));
    }
    if let Some(artifact) = &payload.artifact {
        lines.push(format!("artifact: {}", artifact.relative_path));
    }
    lines.join("\n")
}

pub(crate) fn render_disassembly(payload: &DisassembleFunctionResponse) -> String {
    let mut lines = vec![
        "# disassemble_function".to_string(),
        format!("name: {}", payload.function_name),
        format!("address: 0x{:x}", payload.address),
        format!("blocks: {}", payload.blocks.len()),
    ];
    let mut shown_insns = 0usize;
    const MAX_INSNS: usize = 220;
    for (index, block) in payload.blocks.iter().enumerate() {
        if shown_insns >= MAX_INSNS {
            lines.push(format!(
                "\n... truncated remaining blocks ({} total)",
                payload.blocks.len()
            ));
            break;
        }
        lines.push(format!(
            "\n## Block {}  0x{:x}  size={}",
            index, block.address, block.size
        ));
        for insn in &block.instructions {
            if shown_insns >= MAX_INSNS {
                lines.push(format!(
                    "... truncated ({} more insns in this block)",
                    block.instructions.len().saturating_sub(
                        block
                            .instructions
                            .iter()
                            .position(|item| item.address == insn.address)
                            .unwrap_or(0)
                    )
                ));
                break;
            }
            lines.push(format!(
                "0x{:x}:  {:<16}  {}",
                insn.address, insn.bytes, insn.text
            ));
            shown_insns += 1;
        }
    }
    if let Some(annotations) = &payload.annotations {
        lines.push(format!(
            "\nannotations_artifact: {}",
            annotations.relative_path
        ));
    }
    if let Some(artifact) = &payload.artifact {
        lines.push(format!("artifact: {}", artifact.relative_path));
    }
    lines.push(format!(
        "\nnext: decompile_function({}) | function_profile({})",
        payload.function_name, payload.function_name
    ));
    lines.join("\n")
}
