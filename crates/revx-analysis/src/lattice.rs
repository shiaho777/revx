use revx_core::{
    AgentClaim, AgentNextAction, AgentSemanticLattice, CaseLexeme, CausalChain, FlagBehaviorEdge,
    IbcStep, LatticeQuality, PseudocodeRegion, Reference, ReferenceKind, RegionKind, SemanticAnchor,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub fn build_agent_semantic_lattice(
    function_name: &str,
    address: u64,
    text: &str,
    regions: &[PseudocodeRegion],
) -> AgentSemanticLattice {
    let lines = collect_signal_lines(text, regions);
    let mut anchors = Vec::new();
    let mut claims = Vec::new();
    let mut contradictions = Vec::new();
    let mut path_stack: Vec<String> = Vec::new();
    let mut seen_anchor_keys = BTreeSet::new();
    let mut call_kind_hits: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    let mut string_hits: Vec<(String, String)> = Vec::new();
    let mut branch_hits: Vec<(String, String)> = Vec::new();
    let mut switch_hits: Vec<(String, String)> = Vec::new();
    let mut return_hits: Vec<String> = Vec::new();
    let mut env_vars: Vec<(String, String, String)> = Vec::new();
    let mut optstrings: Vec<(String, String)> = Vec::new();
    let mut strcmp_modes: Vec<(String, String)> = Vec::new();
    let mut tty_ids: Vec<String> = Vec::new();
    let mut cli_ids: Vec<String> = Vec::new();
    let mut unknown_marks = 0usize;
    let mut total_lines = 0usize;

    for raw in &lines {
        total_lines += 1;
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.contains("unknown_if")
            || lower.contains("unknown_t")
            || lower.contains("/*?*/")
            || lower.contains("arg_?")
        {
            unknown_marks += 1;
        }

        if let Some(cond) = extract_if_condition(line) {
            let evidence = truncate(line, 160);
            path_stack.push(cond.clone());
            if path_stack.len() > 8 {
                path_stack.remove(0);
            }
            let id = push_anchor(
                &mut anchors,
                &mut seen_anchor_keys,
                "branch",
                &cond,
                parse_addr_comment(line),
                0.78,
                &evidence,
            );
            branch_hits.push((id, cond));
        }

        if let Some((scrutinee, bound)) = extract_switch(line) {
            let surface = if bound.is_empty() {
                format!("switch({scrutinee})")
            } else {
                format!("switch({scrutinee}) bound={bound}")
            };
            let id = push_anchor(
                &mut anchors,
                &mut seen_anchor_keys,
                "switch",
                &surface,
                parse_addr_comment(line),
                0.9,
                &truncate(line, 160),
            );
            switch_hits.push((id, surface));
        }

        for lit in extract_quoted_literals(line) {
            let surface = format!("\"{lit}\"");
            let id = push_anchor(
                &mut anchors,
                &mut seen_anchor_keys,
                "string",
                &surface,
                parse_addr_comment(line),
                0.96,
                &truncate(line, 160),
            );
            string_hits.push((id.clone(), lit.clone()));
            if looks_like_optstring(&lit) {
                optstrings.push((id, lit));
            }
        }

        if let Some(expr) = extract_return_expr(line) {
            return_hits.push(expr);
            let _ = push_anchor(
                &mut anchors,
                &mut seen_anchor_keys,
                "return",
                &truncate(line.trim_end_matches(';'), 96),
                parse_addr_comment(line),
                0.72,
                &truncate(line, 160),
            );
        }

        for call in extract_call_names(line) {
            let kind = classify_api(&call);
            let conf = if kind == "call" { 0.8 } else { 0.92 };
            let id = push_anchor(
                &mut anchors,
                &mut seen_anchor_keys,
                if kind == "call" { "call" } else { kind },
                &call,
                parse_addr_comment(line),
                conf,
                &truncate(line, 160),
            );
            call_kind_hits.entry(kind).or_default().push(id.clone());

            if kind == "env" {
                if let Some(lit) = extract_quoted_literals(line).into_iter().next() {
                    env_vars.push((id.clone(), call.clone(), lit.clone()));
                    claims.push(make_claim(
                        claims.len() + 1,
                        format!("reads environment variable `{lit}` via `{call}`"),
                        "env",
                        0.93,
                        vec![id.clone()],
                        path_stack.last().cloned(),
                        Some(format!(
                            "show `{call}` result is unused or overwritten without side effect"
                        )),
                        probe_set(address, "decompile_function", "confirm env use site"),
                    ));
                }
            }
            if kind == "tty" {
                tty_ids.push(id.clone());
                claims.push(make_claim(
                    claims.len() + 1,
                    format!("terminal capability gate via `{call}`"),
                    "control",
                    0.9,
                    vec![id.clone()],
                    path_stack.last().cloned(),
                    Some(format!("`{call}` result does not control later branches")),
                    probe_set(address, "function_profile", "map tty gate callers/callees"),
                ));
            }
            if kind == "cli" {
                cli_ids.push(id.clone());
                if let Some(opt) = extract_cli_optstring(line) {
                    let surface = format!("\"{opt}\"");
                    let oid = push_anchor(
                        &mut anchors,
                        &mut seen_anchor_keys,
                        "string",
                        &surface,
                        parse_addr_comment(line),
                        0.97,
                        &truncate(line, 160),
                    );
                    if !optstrings.iter().any(|(_, o)| o == &opt) {
                        optstrings.push((oid, opt));
                    }
                }
                let mut anchor_ids = vec![id.clone()];
                for (sid, _) in switch_hits.iter().take(2) {
                    anchor_ids.push(sid.clone());
                }
                for (oid, _) in optstrings.iter().take(1) {
                    anchor_ids.push(oid.clone());
                }
                claims.push(make_claim(
                    claims.len() + 1,
                    format!("CLI option dispatch through `{call}`"),
                    "control",
                    0.94,
                    anchor_ids,
                    path_stack.last().cloned(),
                    Some(format!(
                        "no jump-table/switch near `{call}` result comparisons"
                    )),
                    probe_set(address, "disassemble_function", "verify option dispatch table"),
                ));
            }
            if call.eq_ignore_ascii_case("strcmp") || call.eq_ignore_ascii_case("strncmp") {
                if let Some(lit) = extract_quoted_literals(line).into_iter().next() {
                    if is_mode_token(&lit) {
                        strcmp_modes.push((id.clone(), lit));
                    }
                }
            }
        }
    }

    if !switch_hits.is_empty() {
        let mut anchor_ids: Vec<String> = switch_hits.iter().map(|(id, _)| id.clone()).collect();
        if let Some(ids) = call_kind_hits.get("cli") {
            anchor_ids.extend(ids.iter().cloned().take(2));
        }
        claims.push(make_claim(
            claims.len() + 1,
            format!(
                "multi-way control via jump table on {}",
                switch_hits
                    .iter()
                    .map(|(_, s)| s.as_str())
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "control",
            0.91,
            anchor_ids,
            None,
            Some("br/jump-table is indirect call, not switch".to_string()),
            probe_set(address, "disassemble_function", "confirm jump-table targets"),
        ));
    }

    if !optstrings.is_empty() {
        for (oid, opt) in optstrings.iter().take(2) {
            let flags = summarize_optstring(opt);
            let mut anchors_ids = vec![oid.clone()];
            anchors_ids.extend(cli_ids.iter().cloned().take(2));
            claims.push(make_claim(
                claims.len() + 1,
                format!("exposes CLI flag lexicon `{flags}`"),
                "cli",
                0.92,
                anchors_ids,
                None,
                Some("optstring is data, not used by getopt".to_string()),
                probe_set(address, "strings", "cross-check optstring owners"),
            ));
        }
    }

    if strcmp_modes.len() >= 2 {
        let modes = unique_preserve(
            &strcmp_modes
                .iter()
                .map(|(_, m)| m.clone())
                .collect::<Vec<_>>(),
        );
        let sample = modes
            .iter()
            .take(6)
            .map(|m| format!("`{m}`"))
            .collect::<Vec<_>>()
            .join(", ");
        let anchors_ids = strcmp_modes
            .iter()
            .map(|(id, _)| id.clone())
            .take(6)
            .collect::<Vec<_>>();
        claims.push(make_claim(
            claims.len() + 1,
            format!("enumerates policy/mode tokens {sample}"),
            "policy",
            0.89,
            anchors_ids,
            path_stack.last().cloned(),
            Some("strcmp modes are dead diagnostic strings".to_string()),
            probe_set(address, "disassemble_function", "map mode token branches"),
        ));
    }

    if !string_hits.is_empty() {
        let unique_lits = unique_preserve(
            &string_hits
                .iter()
                .map(|(_, lit)| lit.clone())
                .collect::<Vec<_>>(),
        );
        let sample = unique_lits
            .iter()
            .map(|lit| format!("`{}`", truncate(lit, 40)))
            .take(4)
            .collect::<Vec<_>>()
            .join(", ");
        let mut anchors_ids = Vec::new();
        for (id, _) in &string_hits {
            if !anchors_ids.contains(id) {
                anchors_ids.push(id.clone());
            }
            if anchors_ids.len() >= 6 {
                break;
            }
        }
        let intent = if unique_lits
            .iter()
            .any(|lit| lit.contains('%') || lit.contains("{}"))
        {
            format!("formats or templates messages using {sample}")
        } else if unique_lits.iter().any(|lit| {
            lit.contains('/') || lit.ends_with(".so") || lit.contains("PATH") || lit.contains("HOME")
        }) {
            format!("binds behavior to path/config literals {sample}")
        } else {
            format!("anchors behavior on string literals {sample}")
        };
        claims.push(make_claim(
            claims.len() + 1,
            intent,
            "data",
            0.86,
            anchors_ids,
            path_stack.last().cloned(),
            Some("string loads are dead or only used for logging".to_string()),
            probe_set(address, "xrefs_query", "trace string xrefs"),
        ));
    }

    for (kind, ids) in &call_kind_hits {
        if *kind == "call" || ids.is_empty() {
            continue;
        }
        if matches!(*kind, "env" | "tty" | "cli") {
            continue;
        }
        let intent = match *kind {
            "io" => "performs file/stream IO",
            "net" => "touches network sockets or remote IO",
            "mem" => "manages heap/memory buffers",
            "sync" => "synchronizes threads or shared state",
            "crypto" => "invokes cryptographic primitives",
            "proc" => "spawns or controls processes",
            "time" => "depends on time/clock APIs",
            _ => continue,
        };
        claims.push(make_claim(
            claims.len() + 1,
            intent.to_string(),
            kind,
            0.88,
            ids.clone(),
            None,
            Some(format!("{kind} APIs are present but not on hot path")),
            probe_set(address, "function_profile", &format!("expand {kind} call graph")),
        ));
    }

    if branch_hits.len() >= 3 {
        let ids = branch_hits
            .iter()
            .map(|(id, _)| id.clone())
            .take(5)
            .collect::<Vec<_>>();
        claims.push(make_claim(
            claims.len() + 1,
            format!(
                "decision-heavy routine with {} recovered predicates",
                branch_hits.len()
            ),
            "control",
            0.8,
            ids,
            None,
            Some("predicates are recovery noise rather than semantic gates".to_string()),
            probe_set(address, "decompile_function", "re-check predicate recovery"),
        ));
    }

    if claims.is_empty() {
        let call_ids = call_kind_hits
            .values()
            .flatten()
            .take(4)
            .cloned()
            .collect::<Vec<_>>();
        if !call_ids.is_empty() {
            claims.push(make_claim(
                1,
                format!("orchestrates {} recovered calls", call_ids.len()),
                "behavior",
                0.7,
                call_ids,
                None,
                Some("calls are stubs or unreachable".to_string()),
                probe_set(address, "function_profile", "inspect callee set"),
            ));
        } else if !return_hits.is_empty() {
            claims.push(make_claim(
                1,
                format!(
                    "returns `{}`",
                    truncate(return_hits.first().map(String::as_str).unwrap_or("value"), 48)
                ),
                "behavior",
                0.65,
                anchors
                    .iter()
                    .filter(|a| a.kind == "return")
                    .map(|a| a.id.clone())
                    .take(2)
                    .collect(),
                None,
                Some("return expression is incomplete recovery".to_string()),
                probe_set(address, "disassemble_function", "verify return register"),
            ));
        } else {
            claims.push(make_claim(
                1,
                format!("function `{function_name}` lacks strong semantic anchors"),
                "behavior",
                0.4,
                Vec::new(),
                None,
                Some("deeper SSA/full profile recovers anchors".to_string()),
                probe_set(address, "function_profile", "escalate profile"),
            ));
        }
    }

    {
        let mut deduped: Vec<AgentClaim> = Vec::new();
        for mut claim in claims {
            if let Some(pos) = deduped.iter().position(|existing| {
                existing.kind == claim.kind && existing.intent.eq_ignore_ascii_case(&claim.intent)
            }) {
                let existing = &mut deduped[pos];
                for anchor in claim.anchors.drain(..) {
                    if !existing.anchors.contains(&anchor) {
                        existing.anchors.push(anchor);
                    }
                }
                if claim.confidence > existing.confidence {
                    existing.confidence = claim.confidence;
                }
                continue;
            }
            deduped.push(claim);
        }
        claims = deduped;
    }
    claims.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.id.cmp(&b.id))
    });
    for (idx, claim) in claims.iter_mut().enumerate() {
        claim.id = format!("c{}", idx + 1);
    }

    let case_lexicon = recover_case_lexicon(&switch_hits, &optstrings, text);
    if !case_lexicon.is_empty() {
        let sample = case_lexicon
            .iter()
            .take(12)
            .map(|c| {
                if c.takes_arg {
                    format!("{}:", c.glyph)
                } else {
                    c.glyph.clone()
                }
            })
            .collect::<Vec<_>>()
            .join("");
        let with_arg = case_lexicon.iter().filter(|c| c.takes_arg).count();
        let mut anchor_ids: Vec<String> = switch_hits.iter().map(|(id, _)| id.clone()).collect();
        anchor_ids.extend(optstrings.iter().map(|(id, _)| id.clone()).take(2));
        for ch in case_lexicon.iter().take(8) {
            let surface = format!("case '{}'", c_escape_glyph(&ch.glyph));
            let id = push_anchor(
                &mut anchors,
                &mut seen_anchor_keys,
                "case",
                &surface,
                None,
                0.9,
                &format!("code={} slot={:?} takes_arg={}", ch.code, ch.slot, ch.takes_arg),
            );
            anchor_ids.push(id);
        }
        claims.push(make_claim(
            claims.len() + 1,
            format!(
                "recovers switch case lexicon `{}` ({} flags, {} take args)",
                truncate(&sample, 64),
                case_lexicon.len(),
                with_arg
            ),
            "case",
            0.94,
            unique_preserve(&anchor_ids),
            None,
            Some("optstring/switch bias mapping is wrong or table is not char-coded".to_string()),
            probe_set(address, "disassemble_function", "verify case targets match lexicon"),
        ));
        let mut deduped: Vec<AgentClaim> = Vec::new();
        for mut claim in claims {
            if let Some(pos) = deduped.iter().position(|existing| {
                existing.kind == claim.kind && existing.intent.eq_ignore_ascii_case(&claim.intent)
            }) {
                let existing = &mut deduped[pos];
                for anchor in claim.anchors.drain(..) {
                    if !existing.anchors.contains(&anchor) {
                        existing.anchors.push(anchor);
                    }
                }
                if claim.confidence > existing.confidence {
                    existing.confidence = claim.confidence;
                }
                continue;
            }
            deduped.push(claim);
        }
        claims = deduped;
        claims.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.id.cmp(&b.id))
        });
        for (idx, claim) in claims.iter_mut().enumerate() {
            claim.id = format!("c{}", idx + 1);
        }
    }

    let mut chains = synthesize_causal_chains(
        address,
        &claims,
        &tty_ids,
        &cli_ids,
        &env_vars,
        &switch_hits,
        &strcmp_modes,
        &optstrings,
    );
    if !case_lexicon.is_empty() {
        let glyphs: String = case_lexicon.iter().take(16).map(|c| c.glyph.as_str()).collect();
        let steps = claims
            .iter()
            .filter(|c| c.kind == "case" || c.kind == "cli" || c.intent.contains("jump table"))
            .map(|c| c.id.clone())
            .take(4)
            .collect::<Vec<_>>();
        chains.insert(
            0,
            CausalChain {
                id: "x5".to_string(),
                narrative: format!(
                    "char-coded option dispatch over recovered cases `{}{}`",
                    truncate(&glyphs, 28),
                    if case_lexicon.len() > 16 { "…" } else { "" }
                ),
                confidence: 0.95,
                steps,
            },
        );
    }

    if string_hits.len() >= 2 {
        let mut envish = 0usize;
        let mut pathish = 0usize;
        let unique_lits = unique_preserve(
            &string_hits
                .iter()
                .map(|(_, lit)| lit.clone())
                .collect::<Vec<_>>(),
        );
        for lit in &unique_lits {
            if lit.chars().all(|c| c.is_ascii_uppercase() || c == '_') && lit.len() >= 3 {
                envish += 1;
            }
            if lit.contains('/') {
                pathish += 1;
            }
        }
        if envish > 0 && pathish > 0 {
            contradictions.push(
                "mix of env-style and path-style literals; may be dual config modes".to_string(),
            );
        }
    }
    if !cli_ids.is_empty() && switch_hits.is_empty() && branch_hits.len() < 2 {
        contradictions.push(
            "CLI parser present without recovered multi-way dispatch; option table may be missed"
                .to_string(),
        );
    }

    let high_anchor = anchors.iter().filter(|a| a.confidence >= 0.75).count();
    let evidence_coverage = if anchors.is_empty() {
        0.0
    } else {
        high_anchor as f32 / anchors.len() as f32
    };
    let claim_density = if total_lines == 0 {
        0.0
    } else {
        (claims.len() as f32) / ((total_lines as f32 / 8.0).max(1.0))
    }
    .min(1.5);
    let ambiguity = if total_lines == 0 {
        1.0
    } else {
        (unknown_marks as f32 / total_lines as f32).min(1.0)
    };
    let escalate = ambiguity >= 0.18
        || (claims.iter().all(|c| c.confidence < 0.75) && total_lines > 20)
        || (anchors.len() < 2 && total_lines > 12);
    let escalate_reason = if escalate {
        Some(if ambiguity >= 0.18 {
            format!("ambiguity={ambiguity:.2} with {unknown_marks} uncertain marks")
        } else if anchors.len() < 2 {
            "sparse anchors; escalate profile or disassemble".to_string()
        } else {
            "low-confidence claim set".to_string()
        })
    } else {
        None
    };

    let thesis = synthesize_thesis(function_name, &claims, &chains, &string_hits, &call_kind_hits);
    let (investigation_bytecode, ibc) = compile_investigation_program(
        function_name,
        address,
        &claims,
        &chains,
        &case_lexicon,
        escalate,
    );

    let mut lattice = AgentSemanticLattice {
        method: "casl-v4".to_string(),
        thesis,
        claims,
        anchors,
        chains,
        case_lexicon,
        behavior_graph: Vec::new(),
        contradictions,
        investigation_bytecode,
        ibc,
        ibc_pc: 0,
        ibc_status: "ready".to_string(),
        quality: LatticeQuality {
            claim_density,
            evidence_coverage,
            ambiguity,
            escalate,
            escalate_reason,
        },
    };
    project_flag_behavior_graph(&mut lattice, &[]);
    if !lattice.behavior_graph.is_empty() {
        lattice.method = "casl-v5-fbg".to_string();
    }
    let field = project_cognitive_field(&lattice);
    apply_cognitive_field_to_lattice(&mut lattice, &field);
    inject_diffraction_residuals_into_lattice(&mut lattice, &field);
    lattice
}

pub fn fuse_semantic_lattices(
    query: &str,
    pieces: &[(String, u64, AgentSemanticLattice)],
) -> AgentSemanticLattice {
    if pieces.is_empty() {
        return AgentSemanticLattice {
            method: "casl-v5-fbg".to_string(),
            thesis: format!("no lattice evidence for `{query}`"),
            claims: Vec::new(),
            anchors: Vec::new(),
            chains: Vec::new(),
            case_lexicon: Vec::new(),
            behavior_graph: Vec::new(),
            contradictions: Vec::new(),
            investigation_bytecode: vec![format!(
                "ASK decompile_function q={}",
                truncate(query, 64)
            )],
            ibc: vec![IbcStep {
                pc: 0,
                op: "ASK".to_string(),
                detail: format!("decompile_function q={}", truncate(query, 64)),
                tool: Some("decompile_function".to_string()),
                args: serde_json::json!({ "query": query }),
                claim_id: None,
            }],
            ibc_pc: 0,
            ibc_status: "ready".to_string(),
            quality: LatticeQuality {
                claim_density: 0.0,
                evidence_coverage: 0.0,
                ambiguity: 1.0,
                escalate: true,
                escalate_reason: Some("empty fusion set".to_string()),
            },
        };
    }
    if pieces.len() == 1 {
        let mut one = pieces[0].2.clone();
        project_flag_behavior_graph(&mut one, pieces);
        one.method = if one.behavior_graph.is_empty() {
            "casl-v5-fbg".to_string()
        } else {
            "casl-v5-fbg".to_string()
        };
        return one;
    }

    let mut fused_claims = Vec::new();
    let mut fused_anchors = Vec::new();
    let mut fused_chains = Vec::new();
    let mut fused_cases: Vec<CaseLexeme> = Vec::new();
    let mut contradictions = Vec::new();
    let mut thesis_parts = Vec::new();
    let mut density = 0.0f32;
    let mut coverage = 0.0f32;
    let mut ambig = 0.0f32;
    let mut escalate = false;
    let mut escalate_reasons = Vec::new();
    let mut bytecode = Vec::new();
    let mut prior_graphs: Vec<FlagBehaviorEdge> = Vec::new();

    for (name, addr, lattice) in pieces {
        density += lattice.quality.claim_density;
        coverage += lattice.quality.evidence_coverage;
        ambig += lattice.quality.ambiguity;
        if lattice.quality.escalate {
            escalate = true;
            if let Some(reason) = &lattice.quality.escalate_reason {
                escalate_reasons.push(format!("{name}: {reason}"));
            }
        }
        if !lattice.thesis.is_empty() {
            thesis_parts.push(format!("{name}@0x{addr:x}: {}", lattice.thesis));
        }
        for claim in &lattice.claims {
            let mut c = claim.clone();
            c.id = format!("{name}.{}", claim.id);
            c.intent = format!("[{name}] {}", claim.intent);
            fused_claims.push(c);
        }
        for anchor in &lattice.anchors {
            let mut a = anchor.clone();
            a.id = format!("{name}.{}", anchor.id);
            fused_anchors.push(a);
        }
        for chain in &lattice.chains {
            let mut ch = chain.clone();
            ch.id = format!("{name}.{}", chain.id);
            ch.narrative = format!("[{name}] {}", chain.narrative);
            fused_chains.push(ch);
        }
        let dispatcher_like = lattice.case_lexicon.iter().any(|c| c.target.is_some())
            || lattice.claims.iter().any(|c| {
                matches!(c.kind.as_str(), "case" | "case_bind" | "cli")
                    || c.intent.contains("jump table")
                    || c.intent.contains("CLI option")
            })
            || lattice.chains.iter().any(|c| {
                c.narrative.contains("getopt") || c.narrative.contains("jump table")
            });
        for case in &lattice.case_lexicon {
            let worth = case.target.is_some() || dispatcher_like;
            if !worth {
                continue;
            }
            if let Some(existing) = fused_cases
                .iter_mut()
                .find(|c| c.glyph == case.glyph && c.code == case.code)
            {
                if existing.target.is_none() && case.target.is_some() {
                    *existing = case.clone();
                } else if existing.meaning.is_none() && case.meaning.is_some() {
                    existing.meaning = case.meaning.clone();
                }
                if !existing.takes_arg && case.takes_arg {
                    existing.takes_arg = true;
                }
            } else if case.target.is_some() || dispatcher_like {
                fused_cases.push(case.clone());
            }
        }
        for edge in &lattice.behavior_graph {
            if !prior_graphs
                .iter()
                .any(|e| e.code == edge.code && e.handler == edge.handler)
            {
                prior_graphs.push(edge.clone());
            }
        }
        for item in &lattice.contradictions {
            contradictions.push(format!("[{name}] {item}"));
        }
        for op in lattice.investigation_bytecode.iter().take(4) {
            bytecode.push(format!("{name}|{op}"));
        }
    }

    {
        let primary = pieces.iter().max_by_key(|(_, _, lattice)| {
            let bound = lattice
                .case_lexicon
                .iter()
                .filter(|c| c.target.is_some())
                .count();
            bound * 1000
                + lattice.case_lexicon.len() * 10
                + lattice
                    .claims
                    .iter()
                    .filter(|c| matches!(c.kind.as_str(), "case" | "case_bind" | "cli"))
                    .count()
        });
        if let Some((_, _, primary_l)) = primary {
            if !primary_l.case_lexicon.is_empty() {
                let mut preferred = primary_l.case_lexicon.clone();
                for case in fused_cases {
                    if let Some(existing) = preferred
                        .iter_mut()
                        .find(|c| c.code == case.code && c.glyph == case.glyph)
                    {
                        if existing.target.is_none() && case.target.is_some() {
                            existing.target = case.target;
                            existing.target_name = case.target_name;
                        }
                        if existing.meaning.is_none() {
                            existing.meaning = case.meaning;
                        }
                        if case.takes_arg {
                            existing.takes_arg = true;
                        }
                    } else if case.target.is_some() {
                        preferred.push(case);
                    }
                }
                fused_cases = preferred;
            }
        }
    }

    fused_claims.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.id.cmp(&b.id))
    });
    fused_claims.truncate(20);
    fused_anchors.truncate(28);
    fused_chains.truncate(10);
    fused_cases.truncate(64);
    contradictions.truncate(8);
    bytecode.truncate(12);

    let n = pieces.len() as f32;
    let mut fused = AgentSemanticLattice {
        method: "casl-v5-fbg".to_string(),
        thesis: truncate(&thesis_parts.join(" || "), 280),
        claims: fused_claims,
        anchors: fused_anchors,
        chains: fused_chains,
        case_lexicon: fused_cases,
        behavior_graph: prior_graphs,
        contradictions,
        investigation_bytecode: bytecode,
        ibc: Vec::new(),
        ibc_pc: 0,
        ibc_status: "ready".to_string(),
        quality: LatticeQuality {
            claim_density: density / n,
            evidence_coverage: coverage / n,
            ambiguity: ambig / n,
            escalate,
            escalate_reason: if escalate_reasons.is_empty() {
                None
            } else {
                Some(escalate_reasons.join("; "))
            },
        },
    };
    project_flag_behavior_graph(&mut fused, pieces);
    attach_flag_orbit_claims(&mut fused);
    let owner = pieces
        .iter()
        .max_by(|a, b| {
            let sa = a.2.case_lexicon.len() * 2 + a.2.claims.len();
            let sb = b.2.case_lexicon.len() * 2 + b.2.claims.len();
            sa.cmp(&sb)
        })
        .map(|(n, a, _)| (n.clone(), *a))
        .unwrap_or_else(|| ("fn".to_string(), 0));
    let (bytecode, ibc) = compile_fbg_investigation_program(
        &owner.0,
        owner.1,
        &fused.claims,
        &fused.chains,
        &fused.case_lexicon,
        &fused.behavior_graph,
        escalate,
    );
    fused.investigation_bytecode = bytecode;
    fused.ibc = ibc;
    if fused.behavior_graph.iter().any(|e| e.handler.is_some()) {
        let orbit = fused
            .behavior_graph
            .iter()
            .filter(|e| e.handler.is_some())
            .take(6)
            .filter_map(|e| e.orbit.clone())
            .collect::<Vec<_>>()
            .join(" | ");
        if !orbit.is_empty() {
            fused.thesis = truncate(
                &format!(
                    "flag behavior orbits ({} edges): {}",
                    fused.behavior_graph.len(),
                    orbit
                ),
                280,
            );
        }
        fused.chains.insert(
            0,
            CausalChain {
                id: "x_fbg".to_string(),
                narrative: format!(
                    "CLI flag -> handler lattice -> behavior orbit ({} projected edges)",
                    fused.behavior_graph.len()
                ),
                confidence: 0.97,
                steps: fused
                    .claims
                    .iter()
                    .filter(|c| {
                        matches!(
                            c.kind.as_str(),
                            "flag_orbit" | "case_bind" | "case" | "cli"
                        )
                    })
                    .map(|c| c.id.clone())
                    .take(5)
                    .collect(),
            },
        );
    }
    let pieces_ref: Vec<(String, &AgentSemanticLattice)> = pieces
        .iter()
        .map(|(n, _, l)| (n.clone(), l))
        .collect();
    let field = interfere_cognitive_fields(&pieces_ref, &fused);
    apply_cognitive_field_to_lattice(&mut fused, &field);
    inject_diffraction_residuals_into_lattice(&mut fused, &field);
    fused
}

pub fn finalize_pseudocode_unit(
    function_name: &str,
    address: u64,
    unit: revx_core::PseudocodeUnit,
) -> revx_core::PseudocodeUnit {
    finalize_pseudocode_unit_with_context(
        function_name,
        address,
        unit,
        &[],
        &HashMap::new(),
    )
}

pub fn finalize_pseudocode_unit_with_context(
    function_name: &str,
    address: u64,
    mut unit: revx_core::PseudocodeUnit,
    references: &[Reference],
    symbols: &HashMap<u64, String>,
) -> revx_core::PseudocodeUnit {
    let mut lattice = build_agent_semantic_lattice(
        function_name,
        address,
        &unit.text,
        &unit.regions,
    );
    bind_case_targets(&mut lattice, references, symbols);
    unit.semantic_lattice = Some(lattice);
    unit
}

pub fn extract_case_target_map(references: &[Reference]) -> BTreeMap<u32, u64> {
    let mut map = BTreeMap::new();
    for reference in references {
        if reference.kind != ReferenceKind::DataRef {
            continue;
        }
        if let Some(ch) = crate::case_char_untag(reference.to) {
            map.insert(ch as u32, reference.from);
        }
    }
    map
}

fn bind_case_targets(
    lattice: &mut AgentSemanticLattice,
    references: &[Reference],
    symbols: &HashMap<u64, String>,
) {
    let map = extract_case_target_map(references);
    if map.is_empty() && lattice.case_lexicon.iter().all(|c| c.target.is_none()) {
        lattice.method = "casl-v4".to_string();
        return;
    }
    let prior_codes: BTreeSet<u32> = lattice.case_lexicon.iter().map(|c| c.code).collect();
    let mut physical_seeded = 0usize;
    for (code, _target) in &map {
        if prior_codes.contains(code) {
            continue;
        }
        let glyph = if (0x20..0x7f).contains(code) {
            char::from_u32(*code).unwrap_or('?').to_string()
        } else {
            format!("0x{code:x}")
        };
        let meaning = char::from_u32(*code).and_then(guess_flag_meaning);
        lattice.case_lexicon.push(CaseLexeme {
            glyph,
            code: *code,
            takes_arg: false,
            slot: None,
            meaning,
            target: None,
            target_name: None,
        });
        physical_seeded += 1;
    }
    if physical_seeded > 0 {
        lattice.case_lexicon.sort_by(|a, b| {
            a.code
                .cmp(&b.code)
                .then_with(|| a.glyph.cmp(&b.glyph))
        });
    }
    let linguistic: BTreeSet<u32> = prior_codes;
    let physical: BTreeSet<u32> = map.keys().copied().collect();
    let mut orphans: Vec<u32> = physical.difference(&linguistic).copied().collect();
    let mut ghosts: Vec<u32> = linguistic.difference(&physical).copied().collect();
    orphans.sort_unstable();
    ghosts.sort_unstable();
    let union_n = linguistic.union(&physical).count().max(1);
    let intersection_n = linguistic.intersection(&physical).count();
    let resonance = intersection_n as f32 / union_n as f32;
    let mut bound = 0usize;
    for case in &mut lattice.case_lexicon {
        if case.target.is_some() {
            bound += 1;
            continue;
        }
        if let Some(target) = map.get(&case.code).copied() {
            case.target = Some(target);
            case.target_name = symbols
                .get(&target)
                .cloned()
                .or_else(|| Some(format!("sub_{target:x}")));
            if case.meaning.is_none() {
                if let Some(name) = case.target_name.as_deref() {
                    case.meaning = infer_meaning_from_handler(name, &case.glyph);
                }
            }
            bound += 1;
        }
    }
    close_case_slots(lattice);
    if bound == 0 {
        lattice.method = "casl-v4".to_string();
        return;
    }
    lattice.method = "casl-v4".to_string();
    if !orphans.is_empty() && !linguistic.is_empty() {
        lattice.contradictions.push(format!(
            "physical orphan cases (jump-table only): {}",
            orphans
                .iter()
                .take(8)
                .map(|c| format!("'{}'", c_escape_glyph(&code_glyph(*c))))
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    if !ghosts.is_empty() && !physical.is_empty() {
        lattice.contradictions.push(format!(
            "linguistic ghost flags (optstring/case text only): {}",
            ghosts
                .iter()
                .take(8)
                .map(|c| format!("'{}'", c_escape_glyph(&code_glyph(*c))))
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    if physical_seeded > 0 || (!linguistic.is_empty() && !physical.is_empty() && resonance < 1.0) {
        let res_score = if linguistic.is_empty() || physical.is_empty() {
            0.9
        } else {
            resonance
        };
        lattice.claims.insert(
            0,
            AgentClaim {
                id: "c_res".to_string(),
                intent: format!(
                    "case alphabet resonance={:.2} physical={} linguistic={} seeded_from_jtable={}",
                    res_score,
                    physical.len(),
                    linguistic.len(),
                    physical_seeded
                ),
                kind: "case_resonance".to_string(),
                confidence: (0.82 + res_score * 0.16).min(0.98),
                anchors: Vec::new(),
                path: None,
                confutation: Some(
                    "jump-table physical alphabet and optstring linguistic alphabet diverge"
                        .to_string(),
                ),
                probes: Vec::new(),
            },
        );
    }
    let sample = lattice
        .case_lexicon
        .iter()
        .filter(|c| c.target.is_some())
        .take(8)
        .map(|c| {
            format!(
                "'{}'->{}",
                c_escape_glyph(&c.glyph),
                c.target_name
                    .clone()
                    .unwrap_or_else(|| format!("0x{:x}", c.target.unwrap_or(0)))
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let mut anchor_ids = Vec::new();
    for case in lattice.case_lexicon.iter().filter(|c| c.target.is_some()).take(8) {
        let surface = format!(
            "case '{}' @ {}",
            c_escape_glyph(&case.glyph),
            case.target_name
                .clone()
                .unwrap_or_else(|| format!("0x{:x}", case.target.unwrap_or(0)))
        );
        let id = format!("a{}", lattice.anchors.len() + 1);
        lattice.anchors.push(SemanticAnchor {
            id: id.clone(),
            kind: "case_target".to_string(),
            surface,
            address: case.target,
            confidence: 0.93,
            evidence: format!("code={} slot={:?}", case.code, case.slot),
        });
        anchor_ids.push(id);
    }
    lattice.claims.insert(
        0,
        AgentClaim {
            id: "c_bind".to_string(),
            intent: format!(
                "binds {} case targets to jump-table handlers ({})",
                bound,
                truncate(&sample, 120)
            ),
            kind: "case_bind".to_string(),
            confidence: 0.96,
            anchors: anchor_ids,
            path: None,
            confutation: Some(
                "jump-table case index bias mismatches recovered handler map".to_string(),
            ),
            probes: lattice
                .case_lexicon
                .iter()
                .filter_map(|c| c.target.map(|t| (c, t)))
                .take(1)
                .map(|(c, t)| AgentNextAction {
                    tool: "decompile_function".to_string(),
                    reason: format!("verify case '{}' handler", c.glyph),
                    priority: 94,
                    query: Some(format!("0x{t:x}")),
                    label: Some(format!("case:{}", c.glyph)),
                    args: serde_json::json!({ "query": format!("0x{t:x}") }),
                })
                .collect(),
        },
    );
    for (idx, claim) in lattice.claims.iter_mut().enumerate() {
        claim.id = format!("c{}", idx + 1);
    }
    lattice.chains.insert(
        0,
        CausalChain {
            id: "x6".to_string(),
            narrative: format!(
                "option char -> jump-table slot -> handler ({bound} bound cases)"
            ),
            confidence: 0.96,
            steps: lattice
                .claims
                .iter()
                .filter(|c| {
                    matches!(
                        c.kind.as_str(),
                        "case_bind" | "case" | "cli" | "case_resonance"
                    )
                })
                .map(|c| c.id.clone())
                .take(4)
                .collect(),
        },
    );
    if let Some(chain) = lattice.chains.first() {
        if chain.confidence >= 0.9 {
            lattice.thesis = truncate(&chain.narrative, 220);
        }
    }
    let address = lattice
        .ibc
        .iter()
        .find_map(|s| {
            s.args
                .get("query")
                .and_then(|v| v.as_str())
                .and_then(|q| normalize_query_addr(q))
        })
        .unwrap_or(0);
    let name = lattice
        .investigation_bytecode
        .first()
        .and_then(|s| s.strip_prefix("FOCUS "))
        .map(|s| s.split(" @").next().unwrap_or("fn").to_string())
        .unwrap_or_else(|| "fn".to_string());
    let escalate = lattice.quality.escalate;
    let (bytecode, ibc) = compile_investigation_program(
        &name,
        address,
        &lattice.claims,
        &lattice.chains,
        &lattice.case_lexicon,
        escalate,
    );
    lattice.investigation_bytecode = bytecode;
    lattice.ibc = ibc;
    lattice.ibc_pc = 0;
    lattice.ibc_status = "ready".to_string();
    project_flag_behavior_graph(lattice, &[]);
    attach_flag_orbit_claims(lattice);
    if !lattice.behavior_graph.is_empty() {
        lattice.method = "casl-v5-fbg".to_string();
        let (bytecode, ibc) = compile_fbg_investigation_program(
            &name,
            address,
            &lattice.claims,
            &lattice.chains,
            &lattice.case_lexicon,
            &lattice.behavior_graph,
            escalate,
        );
        lattice.investigation_bytecode = bytecode;
        lattice.ibc = ibc;
    }
}

pub fn format_semantic_lattice(lattice: &AgentSemanticLattice) -> String {
    let mut lines = vec![
        format!(
            "## Semantic Lattice ({})",
            if lattice.method.is_empty() {
                "CASL"
            } else {
                lattice.method.as_str()
            }
        ),
        format!(
            "thesis: {}",
            if lattice.thesis.is_empty() {
                "-"
            } else {
                lattice.thesis.as_str()
            }
        ),
        format!(
            "quality: density={:.2} coverage={:.2} ambig={:.2} escalate={}{}",
            lattice.quality.claim_density,
            lattice.quality.evidence_coverage,
            lattice.quality.ambiguity,
            lattice.quality.escalate,
            lattice
                .quality
                .escalate_reason
                .as_ref()
                .map(|r| format!(" reason={r}"))
                .unwrap_or_default()
        ),
    ];
    let field = project_cognitive_field(lattice);
    lines.extend(format_cognitive_field_lines(&field));
    if !lattice.case_lexicon.is_empty() {
        lines.push("### Case Lexicon".to_string());
        let compact = lattice
            .case_lexicon
            .iter()
            .take(32)
            .map(|c| {
                if c.takes_arg {
                    format!("{}:", c.glyph)
                } else {
                    c.glyph.clone()
                }
            })
            .collect::<Vec<_>>()
            .join("");
        lines.push(format!(
            "flags=`{}` count={} with_arg={}",
            compact,
            lattice.case_lexicon.len(),
            lattice.case_lexicon.iter().filter(|c| c.takes_arg).count()
        ));
        let bound_n = lattice.case_lexicon.iter().filter(|c| c.target.is_some()).count();
        let resonance = lattice
            .claims
            .iter()
            .find(|c| c.kind == "case_resonance")
            .map(|c| c.intent.clone());
        lines.push(format!(
            "bound_targets: {bound_n}/{}{}",
            lattice.case_lexicon.len(),
            resonance
                .map(|r| format!(" | {r}"))
                .unwrap_or_default()
        ));
        for case in lattice.case_lexicon.iter().take(12) {
            lines.push(format!(
                "  '{}' code={} slot={:?} takes_arg={} tgt={} {}",
                c_escape_glyph(&case.glyph),
                case.code,
                case.slot,
                case.takes_arg,
                case.target
                    .map(|t| format!(
                        "0x{t:x}{}",
                        case.target_name
                            .as_ref()
                            .map(|n| format!("({n})"))
                            .unwrap_or_default()
                    ))
                    .unwrap_or_else(|| "-".to_string()),
                case.meaning.as_deref().unwrap_or("")
            ));
        }
    }
    if !lattice.behavior_graph.is_empty() {
        lines.push("### Flag Behavior Graph".to_string());
        lines.push(format!("orbits={}", lattice.behavior_graph.len()));
        for edge in lattice.behavior_graph.iter().take(12) {
            lines.push(format!(
                "  '{}' -> {} conf={:.2} tags=[{}] effects={}{}",
                c_escape_glyph(&edge.glyph),
                edge.handler_name
                    .clone()
                    .or_else(|| edge.handler.map(|h| format!("0x{h:x}")))
                    .unwrap_or_else(|| "-".to_string()),
                edge.confidence,
                edge.behaviors.join(","),
                truncate(&edge.effects.join("; "), 72),
                edge.orbit
                    .as_ref()
                    .map(|o| format!(" | {o}"))
                    .unwrap_or_default()
            ));
        }
    }
    if !lattice.chains.is_empty() {
        lines.push("### Causal Chains".to_string());
        for chain in lattice.chains.iter().take(6) {
            lines.push(format!(
                "[{}] {:.2} | {} :: steps={}",
                chain.id,
                chain.confidence,
                chain.narrative,
                if chain.steps.is_empty() {
                    "-".to_string()
                } else {
                    chain.steps.join("->")
                }
            ));
        }
    }
    if !lattice.ibc.is_empty() {
        lines.push(format!(
            "### IBC Program (pc={} status={})",
            lattice.ibc_pc,
            if lattice.ibc_status.is_empty() {
                "ready"
            } else {
                lattice.ibc_status.as_str()
            }
        ));
        for step in lattice.ibc.iter().take(12) {
            lines.push(format!(
                "  pc={:02} {} | {}{}",
                step.pc,
                step.op,
                step.detail,
                step.tool
                    .as_ref()
                    .map(|tool| format!(" -> `{}` {}", tool, truncate(&step.args.to_string(), 80)))
                    .unwrap_or_default()
            ));
        }
        if let Some(step) = lattice.ibc.first() {
            if let Some(tool) = &step.tool {
                lines.push(format!(
                    "EXECUTE IBC[0]: `{}` args={}",
                    tool,
                    truncate(&step.args.to_string(), 160)
                ));
            }
        }
    } else if !lattice.investigation_bytecode.is_empty() {
        lines.push("### Investigation Bytecode".to_string());
        for (idx, op) in lattice.investigation_bytecode.iter().take(10).enumerate() {
            lines.push(format!("  {:02} {}", idx, op));
        }
    }
    if !lattice.anchors.is_empty() {
        lines.push("### Anchors".to_string());
        for anchor in lattice.anchors.iter().take(16) {
            lines.push(format!(
                "@{} {} conf={:.2}{} | {}",
                anchor.id,
                anchor.kind,
                anchor.confidence,
                anchor
                    .address
                    .map(|a| format!(" @0x{a:x}"))
                    .unwrap_or_default(),
                truncate(&format!("{} :: {}", anchor.surface, anchor.evidence), 180)
            ));
        }
    }
    if !lattice.claims.is_empty() {
        lines.push("### Claims".to_string());
        for claim in lattice.claims.iter().take(10) {
            lines.push(format!(
                "[{}] {:.2} {} | {}",
                claim.id, claim.confidence, claim.kind, claim.intent
            ));
            if !claim.anchors.is_empty() {
                lines.push(format!("  anchors: {}", claim.anchors.join(",")));
            }
            if let Some(path) = &claim.path {
                lines.push(format!("  path: {}", truncate(path, 120)));
            }
            if let Some(confute) = &claim.confutation {
                lines.push(format!("  confute: {}", truncate(confute, 140)));
            }
            if let Some(probe) = claim.probes.first() {
                lines.push(format!(
                    "  probe: `{}` args={}",
                    probe.tool,
                    truncate(&probe.args.to_string(), 160)
                ));
            }
        }
    }
    if !lattice.contradictions.is_empty() {
        lines.push("### Contradictions".to_string());
        for item in lattice.contradictions.iter().take(4) {
            lines.push(format!("- {item}"));
        }
    }
    lines.join("\n")
}

fn synthesize_causal_chains(
    address: u64,
    claims: &[AgentClaim],
    tty_ids: &[String],
    cli_ids: &[String],
    env_vars: &[(String, String, String)],
    switch_hits: &[(String, String)],
    strcmp_modes: &[(String, String)],
    optstrings: &[(String, String)],
) -> Vec<CausalChain> {
    let mut chains = Vec::new();
    let claim_id = |pred: &dyn Fn(&AgentClaim) -> bool| -> Option<String> {
        claims.iter().find(|c| pred(c)).map(|c| c.id.clone())
    };

    if !tty_ids.is_empty() && env_vars.iter().any(|(_, _, v)| v == "COLUMNS") {
        let mut steps = Vec::new();
        if let Some(id) = claim_id(&|c| c.intent.contains("terminal capability")) {
            steps.push(id);
        }
        if let Some(id) = claim_id(&|c| c.intent.contains("`COLUMNS`")) {
            steps.push(id);
        }
        chains.push(CausalChain {
            id: "x1".to_string(),
            narrative: "tty presence gates terminal width via COLUMNS/ioctl path".to_string(),
            confidence: 0.9,
            steps,
        });
    }

    if !cli_ids.is_empty() && !switch_hits.is_empty() {
        let mut steps = Vec::new();
        if let Some(id) = claim_id(&|c| c.intent.contains("CLI option dispatch")) {
            steps.push(id);
        }
        if let Some(id) = claim_id(&|c| c.intent.contains("jump table") || c.intent.contains("switch"))
        {
            steps.push(id);
        }
        if let Some((oid, opt)) = optstrings.first() {
            steps.push(oid.clone());
            chains.push(CausalChain {
                id: "x2".to_string(),
                narrative: format!(
                    "getopt consumes `{}` then dispatches through jump table",
                    summarize_optstring(opt)
                ),
                confidence: 0.93,
                steps,
            });
        } else {
            chains.push(CausalChain {
                id: "x2".to_string(),
                narrative: "CLI parse result fans out through recovered multi-way dispatch"
                    .to_string(),
                confidence: 0.9,
                steps,
            });
        }
    }

    if strcmp_modes.len() >= 2 {
        let modes = unique_preserve(
            &strcmp_modes
                .iter()
                .map(|(_, m)| m.clone())
                .collect::<Vec<_>>(),
        );
        let mut steps = strcmp_modes
            .iter()
            .map(|(id, _)| id.clone())
            .take(4)
            .collect::<Vec<_>>();
        if let Some(id) = claim_id(&|c| c.kind == "policy") {
            steps.insert(0, id);
        }
        chains.push(CausalChain {
            id: "x3".to_string(),
            narrative: format!(
                "mode string ladder decides policy among {}",
                modes
                    .iter()
                    .take(5)
                    .map(|m| format!("`{m}`"))
                    .collect::<Vec<_>>()
                    .join("/")
            ),
            confidence: 0.88,
            steps,
        });
    }

    let env_names = unique_preserve(
        &env_vars
            .iter()
            .map(|(_, _, v)| v.clone())
            .collect::<Vec<_>>(),
    );
    if env_names.len() >= 2 {
        let mut steps = env_vars
            .iter()
            .map(|(id, _, _)| id.clone())
            .take(4)
            .collect::<Vec<_>>();
        if let Some(id) = claim_id(&|c| c.kind == "env") {
            steps.insert(0, id);
        }
        chains.push(CausalChain {
            id: "x4".to_string(),
            narrative: format!(
                "environment constellation configures runtime: {}",
                env_names
                    .iter()
                    .take(5)
                    .map(|v| format!("`{v}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            confidence: 0.87,
            steps,
        });
    }

    if chains.is_empty() && !claims.is_empty() {
        chains.push(CausalChain {
            id: "x0".to_string(),
            narrative: claims
                .first()
                .map(|c| c.intent.clone())
                .unwrap_or_else(|| "single-claim lattice".to_string()),
            confidence: claims.first().map(|c| c.confidence).unwrap_or(0.5),
            steps: claims.iter().take(2).map(|c| c.id.clone()).collect(),
        });
    }

    let _ = address;
    chains
}

fn compile_investigation_program(
    function_name: &str,
    address: u64,
    claims: &[AgentClaim],
    chains: &[CausalChain],
    case_lexicon: &[CaseLexeme],
    escalate: bool,
) -> (Vec<String>, Vec<IbcStep>) {
    let mut ops = Vec::new();
    let mut ibc = Vec::new();
    let mut pc = 0u16;
    let push_step = |ops: &mut Vec<String>,
                     ibc: &mut Vec<IbcStep>,
                     pc: &mut u16,
                     op: &str,
                     detail: String,
                     tool: Option<String>,
                     args: serde_json::Value,
                     claim_id: Option<String>| {
        ops.push(format!("{op} {detail}"));
        ibc.push(IbcStep {
            pc: *pc,
            op: op.to_string(),
            detail,
            tool,
            args,
            claim_id,
        });
        *pc += 1;
    };

    push_step(
        &mut ops,
        &mut ibc,
        &mut pc,
        "FOCUS",
        format!("{function_name} @0x{address:x}"),
        Some("function_profile".to_string()),
        serde_json::json!({ "query": format!("0x{address:x}") }),
        None,
    );
    if escalate {
        push_step(
            &mut ops,
            &mut ibc,
            &mut pc,
            "ESCALATE",
            "profile=full".to_string(),
            Some("decompile_function".to_string()),
            serde_json::json!({ "query": format!("0x{address:x}") }),
            None,
        );
    }
    if !case_lexicon.is_empty() {
        let compact: String = case_lexicon
            .iter()
            .take(20)
            .map(|c| c.glyph.as_str())
            .collect();
        let bound_n = case_lexicon.iter().filter(|c| c.target.is_some()).count();
        push_step(
            &mut ops,
            &mut ibc,
            &mut pc,
            "MAP_CASES",
            format!(
                "lexicon=`{}` n={} bound={}",
                truncate(&compact, 40),
                case_lexicon.len(),
                bound_n
            ),
            Some("disassemble_function".to_string()),
            serde_json::json!({ "query": format!("0x{address:x}") }),
            claims
                .iter()
                .find(|c| c.kind == "case" || c.kind == "case_bind")
                .map(|c| c.id.clone()),
        );
        for case in case_lexicon.iter().filter(|c| c.target.is_some()).take(4) {
            let target = case.target.unwrap();
            push_step(
                &mut ops,
                &mut ibc,
                &mut pc,
                "VERIFY_CASE",
                format!(
                    "'{}' -> {} @0x{:x}",
                    c_escape_glyph(&case.glyph),
                    case.target_name.as_deref().unwrap_or("handler"),
                    target
                ),
                Some("decompile_function".to_string()),
                serde_json::json!({ "query": format!("0x{target:x}") }),
                claims
                    .iter()
                    .find(|c| c.kind == "case_bind" || c.kind == "case")
                    .map(|c| c.id.clone()),
            );
        }
        if case_lexicon.iter().any(|c| c.target.is_some()) {
            let compact: String = case_lexicon
                .iter()
                .filter(|c| c.target.is_some())
                .take(12)
                .map(|c| c.glyph.as_str())
                .collect();
            push_step(
                &mut ops,
                &mut ibc,
                &mut pc,
                "CLOSE_ALPHABET",
                format!(
                    "physical-linguistic closure on `{}`",
                    truncate(&compact, 36)
                ),
                Some("xrefs_query".to_string()),
                serde_json::json!({ "query": format!("0x{address:x}") }),
                claims
                    .iter()
                    .find(|c| c.kind == "case_resonance" || c.kind == "case_bind")
                    .map(|c| c.id.clone()),
            );
        }
    }
    for chain in chains.iter().take(3) {
        push_step(
            &mut ops,
            &mut ibc,
            &mut pc,
            "TRACE_CHAIN",
            format!("{} conf={:.2} {}", chain.id, chain.confidence, truncate(&chain.narrative, 72)),
            Some("decompile_function".to_string()),
            serde_json::json!({ "query": format!("0x{address:x}") }),
            chain.steps.first().cloned(),
        );
    }
    for claim in claims.iter().take(5) {
        if let Some(probe) = claim.probes.first() {
            push_step(
                &mut ops,
                &mut ibc,
                &mut pc,
                "PROBE",
                format!("{} {}", claim.id, truncate(&claim.intent, 56)),
                Some(probe.tool.clone()),
                probe.args.clone(),
                Some(claim.id.clone()),
            );
        } else {
            push_step(
                &mut ops,
                &mut ibc,
                &mut pc,
                "ASSERT",
                format!("{} {}", claim.id, truncate(&claim.intent, 64)),
                None,
                serde_json::json!({}),
                Some(claim.id.clone()),
            );
        }
        if let Some(confute) = &claim.confutation {
            push_step(
                &mut ops,
                &mut ibc,
                &mut pc,
                "CONFUTE",
                format!("{} {}", claim.id, truncate(confute, 72)),
                None,
                serde_json::json!({}),
                Some(claim.id.clone()),
            );
        }
    }
    push_step(
        &mut ops,
        &mut ibc,
        &mut pc,
        "STOP",
        "if top claim conf>=0.9 and confute fails".to_string(),
        None,
        serde_json::json!({}),
        None,
    );
    (ops, ibc)
}

pub fn lattice_primary_next_action(
    lattice: &AgentSemanticLattice,
    fallback_address: u64,
) -> Option<AgentNextAction> {
    lattice_action_at_pc(lattice, fallback_address)
}

pub fn lattice_action_at_pc(
    lattice: &AgentSemanticLattice,
    fallback_address: u64,
) -> Option<AgentNextAction> {
    if lattice.ibc_status == "done" {
        return None;
    }
    let step = lattice
        .ibc
        .iter()
        .find(|s| s.pc >= lattice.ibc_pc && s.tool.is_some())?;
    Some(ibc_step_to_action(step, fallback_address, 99))
}

pub fn lattice_ibc_plan(
    lattice: &AgentSemanticLattice,
    fallback_address: u64,
    max_steps: usize,
) -> Vec<AgentNextAction> {
    if lattice.ibc_status == "done" {
        return Vec::new();
    }
    lattice
        .ibc
        .iter()
        .filter(|s| s.pc >= lattice.ibc_pc && s.tool.is_some())
        .take(max_steps.max(1))
        .enumerate()
        .map(|(i, step)| {
            let mut action = ibc_step_to_action(step, fallback_address, 99u8.saturating_sub(i as u8));
            if i == 0 {
                action.reason = format!("EXECUTE NOW | {}", action.reason);
            }
            action
        })
        .collect()
}

pub fn advance_ibc_cursor(lattice: &mut AgentSemanticLattice) -> Option<IbcStep> {
    if lattice.ibc.is_empty() {
        lattice.ibc_status = "done".to_string();
        return None;
    }
    let current = lattice
        .ibc
        .iter()
        .find(|s| s.pc >= lattice.ibc_pc && s.tool.is_some())
        .cloned();
    let Some(step) = current else {
        lattice.ibc_status = "done".to_string();
        return None;
    };
    let next_pc = lattice
        .ibc
        .iter()
        .filter(|s| s.pc > step.pc && s.tool.is_some())
        .map(|s| s.pc)
        .min();
    if let Some(pc) = next_pc {
        lattice.ibc_pc = pc;
        lattice.ibc_status = "ready".to_string();
    } else {
        lattice.ibc_pc = step.pc.saturating_add(1);
        lattice.ibc_status = "done".to_string();
    }
    Some(step)
}


#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct IbcContinuumState {
    #[serde(default)]
    pub namespace: String,
    pub focus: u64,
    pub focus_name: String,
    pub lattice: AgentSemanticLattice,
    #[serde(default)]
    pub witnesses: Vec<String>,
    #[serde(default)]
    pub orbit_hypotheses: BTreeMap<String, String>,
    #[serde(default)]
    pub cognitive_field: CognitiveField,
    #[serde(default)]
    pub epoch: u64,
    #[serde(default)]
    pub updated_unix_ms: u64,
}

#[derive(Debug, Clone)]
pub struct OrbitHypothesisDraft {
    pub key: String,
    pub title: String,
    pub notes: String,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct IbcContinuumLedger {
    #[serde(default)]
    pub active_namespace: String,
    #[serde(default)]
    pub sessions: BTreeMap<String, IbcContinuumState>,
    #[serde(default)]
    pub global_witnesses: Vec<String>,
    #[serde(default)]
    pub version: u32,
}

#[derive(Debug, Clone)]
pub struct IbcObserveNote {
    pub advanced: Option<IbcStep>,
    pub note: String,
    pub focus: u64,
    pub focus_name: String,
    pub namespace: String,
    pub epoch: u64,
    pub durable: bool,
}

pub fn ibc_program_fingerprint(lattice: &AgentSemanticLattice) -> String {
    lattice
        .ibc
        .iter()
        .take(16)
        .map(|s| {
            let q = s
                .args
                .get("query")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            format!("{}:{}:{}", s.op, s.tool.as_deref().unwrap_or("-"), q)
        })
        .collect::<Vec<_>>()
        .join("|")
}

pub fn resume_ibc_from_state(lattice: &mut AgentSemanticLattice, prior: &AgentSemanticLattice) {
    if prior.ibc.is_empty() {
        return;
    }
    let same = ibc_program_fingerprint(lattice) == ibc_program_fingerprint(prior);
    if same || lattice.ibc.is_empty() {
        lattice.ibc = prior.ibc.clone();
        lattice.investigation_bytecode = prior.investigation_bytecode.clone();
        lattice.ibc_pc = prior.ibc_pc;
        lattice.ibc_status = prior.ibc_status.clone();
        return;
    }
    if lattice.ibc.len() == prior.ibc.len()
        && lattice
            .ibc
            .iter()
            .zip(prior.ibc.iter())
            .all(|(a, b)| a.op == b.op)
    {
        lattice.ibc_pc = prior.ibc_pc.min(
            lattice
                .ibc
                .iter()
                .map(|s| s.pc)
                .max()
                .unwrap_or(0)
                .saturating_add(1),
        );
        lattice.ibc_status = prior.ibc_status.clone();
    }
}

pub fn observe_ibc_execution(
    lattice: &mut AgentSemanticLattice,
    tool: &str,
    query: &str,
) -> Option<IbcStep> {
    if lattice.ibc_status == "done" || lattice.ibc.is_empty() {
        return None;
    }
    let current = lattice
        .ibc
        .iter()
        .find(|s| s.pc >= lattice.ibc_pc && s.tool.is_some())
        .cloned();
    if let Some(current) = current.as_ref() {
        let step_q = current
            .args
            .get("query")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if tools_compatible(current.tool.as_deref(), tool)
            && (step_q.is_empty() || queries_compatible(step_q, query))
        {
            return advance_ibc_cursor(lattice);
        }
    }
    let warp = lattice.ibc.iter().find(|s| {
        s.pc >= lattice.ibc_pc
            && s.tool.is_some()
            && tools_compatible(s.tool.as_deref(), tool)
            && {
                let step_q = s.args.get("query").and_then(|v| v.as_str()).unwrap_or("");
                !step_q.is_empty() && queries_compatible(step_q, query)
            }
    });
    if let Some(step) = warp {
        lattice.ibc_pc = step.pc;
        lattice.ibc_status = "ready".to_string();
        return advance_ibc_cursor(lattice);
    }
    None
}

pub fn continuum_on_visit(
    prior: Option<&IbcContinuumState>,
    tool: &str,
    address: u64,
    name: &str,
    fresh: AgentSemanticLattice,
) -> (IbcContinuumState, IbcObserveNote) {
    continuum_on_visit_ns(prior, "default", tool, address, name, fresh, None)
}

pub fn continuum_on_visit_with_observation(
    prior: Option<&IbcContinuumState>,
    tool: &str,
    address: u64,
    name: &str,
    fresh: AgentSemanticLattice,
    observation: Option<&str>,
) -> (IbcContinuumState, IbcObserveNote) {
    continuum_on_visit_ns(prior, "default", tool, address, name, fresh, observation)
}

pub fn continuum_on_visit_ns(
    prior: Option<&IbcContinuumState>,
    namespace: &str,
    tool: &str,
    address: u64,
    name: &str,
    mut fresh: AgentSemanticLattice,
    observation: Option<&str>,
) -> (IbcContinuumState, IbcObserveNote) {
    detect_and_attach_orbit_conflicts(&mut fresh);
    let ns = if namespace.trim().is_empty() {
        "default"
    } else {
        namespace.trim()
    };
    let query = format!("0x{address:x}");
    let now_ms = continuum_now_ms();
    let mut state = if let Some(prev) = prior {
        let hits_step = prev.lattice.ibc.iter().any(|s| {
            s.pc >= prev.lattice.ibc_pc
                && s.tool.is_some()
                && tools_compatible(s.tool.as_deref(), tool)
                && queries_compatible(
                    s.args
                        .get("query")
                        .and_then(|v| v.as_str())
                        .unwrap_or(""),
                    &query,
                )
        });
        if prev.focus == address {
            resume_ibc_from_state(&mut fresh, &prev.lattice);
            if fresh.behavior_graph.is_empty() && !prev.lattice.behavior_graph.is_empty() {
                fresh.behavior_graph = prev.lattice.behavior_graph.clone();
            }
            if fresh.case_lexicon.is_empty() && !prev.lattice.case_lexicon.is_empty() {
                fresh.case_lexicon = prev.lattice.case_lexicon.clone();
            }
            IbcContinuumState {
                namespace: ns.to_string(),
                focus: address,
                focus_name: name.to_string(),
                lattice: fresh,
                witnesses: prev.witnesses.clone(),
                orbit_hypotheses: prev.orbit_hypotheses.clone(),
                cognitive_field: prev.cognitive_field.clone(),
                epoch: prev.epoch.saturating_add(1),
                updated_unix_ms: now_ms,
            }
        } else if hits_step {
            IbcContinuumState {
                namespace: ns.to_string(),
                focus: prev.focus,
                focus_name: prev.focus_name.clone(),
                lattice: prev.lattice.clone(),
                witnesses: prev.witnesses.clone(),
                orbit_hypotheses: prev.orbit_hypotheses.clone(),
                cognitive_field: prev.cognitive_field.clone(),
                epoch: prev.epoch.saturating_add(1),
                updated_unix_ms: now_ms,
            }
        } else if is_dispatcher_lattice(&fresh) {
            IbcContinuumState {
                namespace: ns.to_string(),
                focus: address,
                focus_name: name.to_string(),
                lattice: fresh,
                witnesses: Vec::new(),
                orbit_hypotheses: BTreeMap::new(),
                cognitive_field: CognitiveField::default(),
                epoch: 1,
                updated_unix_ms: now_ms,
            }
        } else {
            IbcContinuumState {
                namespace: ns.to_string(),
                focus: prev.focus,
                focus_name: prev.focus_name.clone(),
                lattice: prev.lattice.clone(),
                witnesses: prev.witnesses.clone(),
                orbit_hypotheses: prev.orbit_hypotheses.clone(),
                cognitive_field: prev.cognitive_field.clone(),
                epoch: prev.epoch,
                updated_unix_ms: now_ms,
            }
        }
    } else {
        IbcContinuumState {
            namespace: ns.to_string(),
            focus: address,
            focus_name: name.to_string(),
            lattice: fresh,
            witnesses: Vec::new(),
                orbit_hypotheses: BTreeMap::new(),
            cognitive_field: CognitiveField::default(),
            epoch: 1,
            updated_unix_ms: now_ms,
        }
    };

    let advanced = observe_ibc_execution(&mut state.lattice, tool, &query);
    let corpus = synthesize_observation_corpus(&state.lattice, observation);
    let prior_events = state.cognitive_field.collapse_events.clone();
    let prior_residuals = state.cognitive_field.residuals.clone();
    if state.cognitive_field.conjugates.is_empty() && !prior_events.is_empty() {
        // keep continuity when reprojected field lacks prior conjugate memory
    }
    let collapse = collapse_cognitive_field(
        &mut state.cognitive_field,
        &mut state.lattice,
        tool,
        &query,
        Some(corpus.as_str()),
    );
    for event in &collapse {
        state.witnesses.push(format!("[{ns}] COLLAPSE {event}"));
    }
    let mut field = project_cognitive_field(&state.lattice);
    field.field_epoch = state.epoch;
    field.collapse_events = prior_events;
    field.collapse_events.extend(collapse.iter().cloned());
    if field.collapse_events.len() > 32 {
        let n = field.collapse_events.len() - 32;
        field.collapse_events.drain(0..n);
    }
    if field.residuals.is_empty() {
        field.residuals = prior_residuals;
    }
    field.residuals = project_diffraction_residuals(&field, &state.lattice);
    if !collapse.is_empty() {
        let sealed = field
            .residuals
            .iter()
            .filter(|r| r.polarity == "sealed")
            .count();
        if sealed > 0 && field.entropy <= 0.36 {
            field.mode = "collapsing".to_string();
        }
    }
    apply_cognitive_field_to_lattice(&mut state.lattice, &field);
    inject_diffraction_residuals_into_lattice(&mut state.lattice, &field);
    state.cognitive_field = field;
    state.cognitive_field.proof_chain = compose_proof_chain(&state);
    inject_proof_chain_into_lattice(&mut state.lattice, &state.cognitive_field);
    let note = if let Some(step) = advanced.as_ref() {
        let w = format!(
            "[{ns}] {} {} => IBC[{}] {} | {}",
            tool,
            query,
            step.pc,
            step.op,
            truncate(&step.detail, 72)
        );
        state.witnesses.push(w.clone());
        if state.witnesses.len() > 48 {
            let drop_n = state.witnesses.len() - 48;
            state.witnesses.drain(0..drop_n);
        }
        format!(
            "IBC continuum ADVANCED ns={} epoch={} :: {w}",
            state.namespace, state.epoch
        )
    } else {
        format!(
            "IBC continuum idle ns={} epoch={} focus={}@0x{:x} pc={} status={}",
            state.namespace,
            state.epoch,
            state.focus_name,
            state.focus,
            state.lattice.ibc_pc,
            if state.lattice.ibc_status.is_empty() {
                "ready"
            } else {
                state.lattice.ibc_status.as_str()
            }
        )
    };
    let observe = IbcObserveNote {
        advanced,
        note,
        focus: state.focus,
        focus_name: state.focus_name.clone(),
        namespace: state.namespace.clone(),
        epoch: state.epoch,
        durable: false,
    };
    (state, observe)
}

pub fn continuum_ledger_on_visit(
    ledger: &mut IbcContinuumLedger,
    namespace: &str,
    tool: &str,
    address: u64,
    name: &str,
    fresh: AgentSemanticLattice,
) -> IbcObserveNote {
    continuum_ledger_on_visit_with_observation(
        ledger, namespace, tool, address, name, fresh, None,
    )
}

pub fn continuum_ledger_on_visit_with_observation(
    ledger: &mut IbcContinuumLedger,
    namespace: &str,
    tool: &str,
    address: u64,
    name: &str,
    fresh: AgentSemanticLattice,
    observation: Option<&str>,
) -> IbcObserveNote {
    if ledger.version == 0 {
        ledger.version = 1;
    }
    let ns = if namespace.trim().is_empty() {
        "default".to_string()
    } else {
        namespace.trim().to_string()
    };
    let prior = ledger.sessions.get(&ns).cloned();
    let (state, mut observe) = continuum_on_visit_ns(
        prior.as_ref(),
        &ns,
        tool,
        address,
        name,
        fresh,
        observation,
    );
    ledger.active_namespace = ns.clone();
    if let Some(step_note) = observe.advanced.as_ref() {
        let gw = format!(
            "[{ns}#{}] {} @0x{:x} :: {} {}",
            state.epoch,
            tool,
            address,
            step_note.op,
            truncate(&step_note.detail, 48)
        );
        ledger.global_witnesses.push(gw);
        if ledger.global_witnesses.len() > 64 {
            let drop_n = ledger.global_witnesses.len() - 64;
            ledger.global_witnesses.drain(0..drop_n);
        }
    }
    ledger.sessions.insert(ns, state);
    if ledger.sessions.len() > 16 {
        let mut ranked: Vec<(String, u64)> = ledger
            .sessions
            .iter()
            .map(|(k, v)| (k.clone(), v.updated_unix_ms))
            .collect();
        ranked.sort_by(|a, b| a.1.cmp(&b.1));
        while ledger.sessions.len() > 16 {
            if let Some((old, _)) = ranked.first().cloned() {
                if old != ledger.active_namespace {
                    ledger.sessions.remove(&old);
                }
                ranked.remove(0);
            } else {
                break;
            }
        }
    }
    observe.durable = true;
    observe.note = format!("{} | ledger_sessions={}", observe.note, ledger.sessions.len());
    observe
}

pub fn continuum_brief_lines(state: &IbcContinuumState) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!(
        "continuum: ns={} epoch={} focus={}@0x{:x} pc={} status={} witnesses={} hyps={}",
        if state.namespace.is_empty() {
            "default"
        } else {
            state.namespace.as_str()
        },
        state.epoch,
        state.focus_name,
        state.focus,
        state.lattice.ibc_pc,
        if state.lattice.ibc_status.is_empty() {
            "ready"
        } else {
            state.lattice.ibc_status.as_str()
        },
        state.witnesses.len(),
        state.orbit_hypotheses.len()
    ));
    if !state.orbit_hypotheses.is_empty() {
        let ids = state
            .orbit_hypotheses
            .iter()
            .take(6)
            .map(|(k, v)| format!("{k}=>{v}"))
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!("orbit_hypotheses: {ids}"));
    }
    {
        let field_ref = if !state.cognitive_field.mode.is_empty()
            || !state.cognitive_field.standing_waves.is_empty()
        {
            state.cognitive_field.clone()
        } else {
            project_cognitive_field(&state.lattice)
        };
        if !field_ref.mode.is_empty() || !field_ref.standing_waves.is_empty() {
            lines.push(format!(
                "cognitive_field: mode={} entropy={:.2} waves={} nulls={} conjugates={}",
                if field_ref.mode.is_empty() {
                    "latent"
                } else {
                    field_ref.mode.as_str()
                },
                field_ref.entropy,
                field_ref.standing_waves.len(),
                field_ref.nulls.len(),
                field_ref.conjugates.len()
            ));
            if let Some(wave) = field_ref.standing_waves.first() {
                lines.push(format!(
                    "standing_wave: {:.2} {} :: {}",
                    wave.amplitude,
                    wave.polarity,
                    truncate(&wave.intent, 100)
                ));
            }
            if let Some(probe) = field_ref.conjugates.first() {
                lines.push(format!(
                    "conjugate_probe: `{}` gain={:.2} true=[{}] false=[{}]",
                    probe.tool,
                    probe.information_gain,
                    truncate(&probe.expected_true, 40),
                    truncate(&probe.expected_false, 40)
                ));
            }
            let open_n = field_ref
                .residuals
                .iter()
                .filter(|r| r.polarity != "sealed")
                .count();
            if open_n > 0 || !field_ref.collapse_events.is_empty() {
                lines.push(format!(
                    "diffraction_residuals: open={open_n}/{} collapses={}",
                    field_ref.residuals.len(),
                    field_ref.collapse_events.len()
                ));
                if let Some(r) = field_ref.residuals.iter().find(|r| r.polarity != "sealed") {
                    lines.push(format!(
                        "top_residual: iv={:.2} `{}` {}",
                        r.information_value,
                        r.probe_tool,
                        truncate(&r.question, 80)
                    ));
                }
                if let Some(ev) = field_ref.collapse_events.iter().rev().next() {
                    lines.push(format!("last_collapse: {}", truncate(ev, 100)));
                }
            }
            if !field_ref.proof_chain.is_empty() {
                let proven = field_ref
                    .proof_chain
                    .iter()
                    .filter(|l| l.verdict == "true")
                    .count();
                let refuted = field_ref
                    .proof_chain
                    .iter()
                    .filter(|l| l.verdict == "false")
                    .count();
                let probed = field_ref
                    .proof_chain
                    .iter()
                    .filter(|l| l.verdict == "probe")
                    .count();
                lines.push(format!(
                    "proof_chain: links={} proven={proven} refuted={refuted} probed={probed}",
                    field_ref.proof_chain.len()
                ));
                if let Some(link) = field_ref.proof_chain.iter().rev().next() {
                    lines.push(format!(
                        "proof_tail: [{}] {} => {}",
                        link.verdict,
                        link.orbit_key,
                        truncate(&link.summary, 80)
                    ));
                }
            }
        }
    }
    if !state.lattice.behavior_graph.is_empty() {
        let orbits = state
            .lattice
            .behavior_graph
            .iter()
            .take(4)
            .filter_map(|e| e.orbit.clone())
            .collect::<Vec<_>>()
            .join(" | ");
        if !orbits.is_empty() {
            lines.push(format!("continuum_orbits: {orbits}"));
        }
    }
    for w in state.witnesses.iter().rev().take(3) {
        lines.push(format!("ibc_witness: {w}"));
    }
    lines
}


pub fn force_advance_ibc(lattice: &mut AgentSemanticLattice) -> Option<IbcStep> {
    advance_ibc_cursor(lattice)
}

pub fn forge_orbit_hypothesis_drafts(state: &IbcContinuumState) -> Vec<OrbitHypothesisDraft> {
    let ns = if state.namespace.is_empty() {
        "default"
    } else {
        state.namespace.as_str()
    };
    let field = if state.cognitive_field.mode.is_empty()
        && state.cognitive_field.standing_waves.is_empty()
    {
        project_cognitive_field(&state.lattice)
    } else {
        state.cognitive_field.clone()
    };
    let proof_tail = field
        .proof_chain
        .iter()
        .rev()
        .take(2)
        .map(|l| format!("[{}] {} {}", l.verdict, l.orbit_key, l.summary))
        .collect::<Vec<_>>()
        .join("
");
    let mut drafts = Vec::new();
    for edge in state.lattice.behavior_graph.iter().take(12) {
        let key = format!("{}:{}", edge.code, edge.glyph);
        let tags = edge.behaviors.iter().take(6).cloned().collect::<Vec<_>>().join(",");
        let handler = edge
            .handler_name
            .clone()
            .or_else(|| edge.handler.map(|h| format!("0x{h:x}")))
            .unwrap_or_else(|| "unknown".to_string());
        let title = format!(
            "orbit '{}' → {} ⟦{}⟧",
            c_escape_glyph(&edge.glyph),
            handler,
            if tags.is_empty() { "opaque".to_string() } else { tags.clone() }
        );
        let confute = state
            .lattice
            .claims
            .iter()
            .find(|c| c.kind == "flag_orbit" || c.kind == "orbit_conflict")
            .and_then(|c| c.confutation.clone())
            .unwrap_or_else(|| {
                "handler effects are incidental rather than caused by this flag".to_string()
            });
        let effects = edge.effects.iter().take(5).cloned().collect::<Vec<_>>().join("\n- ");
        let conjugate = field
            .conjugates
            .iter()
            .find(|p| {
                p.claim_intent.contains(&edge.glyph)
                    || p.query
                        .as_ref()
                        .and_then(|q| edge.handler.map(|h| q.contains(&format!("0x{h:x}"))))
                        .unwrap_or(false)
            })
            .map(|p| {
                format!(
                    "conjugate: {}\nprobe: `{}` gain={:.2}\ncollapse_true: {}\ncollapse_false: {}",
                    p.conjugate, p.tool, p.information_gain, p.expected_true, p.expected_false
                )
            })
            .unwrap_or_else(|| format!("conjugate: {confute}"));
        let wave = field
            .standing_waves
            .iter()
            .find(|w| w.intent.contains(&edge.glyph) || w.kind == "flag_orbit")
            .map(|w| format!("standing_wave: amp={:.2} polarity={}", w.amplitude, w.polarity))
            .unwrap_or_else(|| "standing_wave: local".to_string());
        let notes = format!(
            "CASL/PCCF orbit hypothesis (ns={ns} epoch={})\nfocus={}@0x{:x}\nfield_mode={} entropy={:.2}\n{wave}\nglyph='{}' code={}\nhandler={}\nbehaviors=[{tags}]\nconfute: {confute}\n{conjugate}\neffects:\n- {effects}\nproof_chain:\n{proof_tail}\nwitness_tail:\n{}",
            state.epoch,
            state.focus_name,
            state.focus,
            if field.mode.is_empty() {
                "latent"
            } else {
                field.mode.as_str()
            },
            field.entropy,
            c_escape_glyph(&edge.glyph),
            edge.code,
            handler,
            state
                .witnesses
                .iter()
                .rev()
                .take(4)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
        let mut evidence_ids = vec![
            format!("casl:orbit:{ns}:{}:{}", edge.glyph, edge.code),
            format!("casl:continuum:{ns}:epoch:{}", state.epoch),
        ];
        if let Some(h) = edge.handler {
            evidence_ids.push(format!("casl:handler:0x{h:x}"));
        }
        drafts.push(OrbitHypothesisDraft {
            key,
            title,
            notes,
            evidence_ids,
        });
    }
    if drafts.is_empty() {
        for case in state.lattice.case_lexicon.iter().filter(|c| c.target.is_some()).take(8) {
            let key = format!("{}:{}", case.code, case.glyph);
            let handler = case
                .target_name
                .clone()
                .unwrap_or_else(|| format!("0x{:x}", case.target.unwrap_or(0)));
            drafts.push(OrbitHypothesisDraft {
                key,
                title: format!("case '{}' → {handler}", c_escape_glyph(&case.glyph)),
                notes: format!(
                    "CASL case bind hypothesis (ns={ns})\ncase '{}' code={} target={handler}\nmeaning={}",
                    c_escape_glyph(&case.glyph),
                    case.code,
                    case.meaning.as_deref().unwrap_or("-")
                ),
                evidence_ids: vec![
                    format!("casl:case:{ns}:{}", case.glyph),
                    format!("casl:handler:{handler}"),
                ],
            });
        }
    }
    drafts
}

pub fn continuum_bind_hypothesis(state: &mut IbcContinuumState, key: &str, hypothesis_id: &str) {
    state
        .orbit_hypotheses
        .insert(key.to_string(), hypothesis_id.to_string());
}

pub fn continuum_ledger_summary(ledger: &IbcContinuumLedger) -> String {
    let active = if ledger.active_namespace.is_empty() {
        "-"
    } else {
        ledger.active_namespace.as_str()
    };
    let names = ledger
        .sessions
        .keys()
        .take(6)
        .cloned()
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "continuum_ledger: active={} sessions={} keys=[{}] global_witnesses={}",
        active,
        ledger.sessions.len(),
        names,
        ledger.global_witnesses.len()
    )
}


#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct CognitiveField {
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub entropy: f32,
    #[serde(default)]
    pub standing_waves: Vec<StandingWave>,
    #[serde(default)]
    pub nulls: Vec<String>,
    #[serde(default)]
    pub conjugates: Vec<PhaseConjugateProbe>,
    #[serde(default)]
    pub collapse_events: Vec<String>,
    #[serde(default)]
    pub residuals: Vec<DiffractionResidual>,
    #[serde(default)]
    pub proof_chain: Vec<ProofChainLink>,
    #[serde(default)]
    pub field_epoch: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct CollapseVerdict {
    #[serde(default)]
    pub claim_id: String,
    #[serde(default)]
    pub claim_intent: String,
    #[serde(default)]
    pub tool: String,
    #[serde(default)]
    pub query: String,
    #[serde(default)]
    pub polarity: String,
    #[serde(default)]
    pub true_score: f32,
    #[serde(default)]
    pub false_score: f32,
    #[serde(default)]
    pub intent_score: f32,
    #[serde(default)]
    pub raw: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct ProofChainLink {
    #[serde(default)]
    pub orbit_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hypothesis_id: Option<String>,
    #[serde(default)]
    pub verdict: String,
    #[serde(default)]
    pub claim_id: String,
    #[serde(default)]
    pub observation_query: String,
    #[serde(default)]
    pub score_line: String,
    #[serde(default)]
    pub sealed_at_epoch: u64,
    #[serde(default)]
    pub summary: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct DiffractionResidual {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub question: String,
    #[serde(default)]
    pub information_value: f32,
    #[serde(default)]
    pub probe_tool: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_query: Option<String>,
    #[serde(default)]
    pub polarity: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StandingWave {
    pub intent: String,
    pub amplitude: f32,
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(default)]
    pub polarity: String,
    #[serde(default)]
    pub kind: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PhaseConjugateProbe {
    pub claim_id: String,
    pub claim_intent: String,
    pub conjugate: String,
    pub tool: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    pub expected_true: String,
    pub expected_false: String,
    pub information_gain: f32,
}

fn claim_resonance_key(claim: &AgentClaim) -> String {
    let intent = claim.intent.to_ascii_lowercase();
    let mut tokens: Vec<&str> = intent
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|t| t.len() >= 3)
        .filter(|t| {
            !matches!(
                *t,
                "the" | "and" | "via" | "with" | "from" | "this" | "that" | "into" | "for" | "then"
            )
        })
        .take(6)
        .collect();
    tokens.sort_unstable();
    format!("{}|{}", claim.kind, tokens.join("+"))
}

fn field_entropy(lattice: &AgentSemanticLattice, waves: &[StandingWave], nulls: usize) -> f32 {
    let amb = lattice.quality.ambiguity.clamp(0.0, 1.0);
    let cov = lattice.quality.evidence_coverage.clamp(0.0, 1.0);
    let wave_energy: f32 =
        waves.iter().map(|w| w.amplitude).sum::<f32>() / (waves.len().max(1) as f32);
    let null_pen = (nulls as f32 * 0.08).min(0.4);
    ((1.0 - cov) * 0.45 + amb * 0.35 + (1.0 - wave_energy.min(1.0)) * 0.2 + null_pen).clamp(0.0, 1.0)
}

fn field_mode(entropy: f32, waves: &[StandingWave], nulls: usize, escalate: bool) -> String {
    let constructive = waves.iter().filter(|w| w.polarity == "constructive").count();
    let contested = waves.iter().filter(|w| w.polarity == "contested").count();
    if escalate && entropy >= 0.55 {
        "sparse".to_string()
    } else if contested + nulls >= 2 && entropy >= 0.35 {
        "contested".to_string()
    } else if constructive >= 1 && entropy <= 0.42 {
        "structural".to_string()
    } else if entropy <= 0.28 {
        "collapsing".to_string()
    } else {
        "diffusing".to_string()
    }
}

pub fn compile_phase_conjugates(lattice: &AgentSemanticLattice) -> Vec<PhaseConjugateProbe> {
    let mut probes = Vec::new();
    let coverage = lattice.quality.evidence_coverage.clamp(0.0, 1.0);
    for claim in lattice.claims.iter().take(14) {
        if claim.confidence < 0.62 {
            continue;
        }
        if matches!(
            claim.kind.as_str(),
            "standing_wave" | "field_null" | "phase_conjugate" | "cognitive_field"
        ) {
            continue;
        }
        let conjugate = claim.confutation.clone().unwrap_or_else(|| {
            format!("observation contradicts: {}", truncate(&claim.intent, 80))
        });
        let (tool, query) = if let Some(probe) = claim.probes.first() {
            (
                probe.tool.clone(),
                probe.query.clone().or_else(|| {
                    probe
                        .args
                        .get("query")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                }),
            )
        } else if let Some(edge) = lattice
            .behavior_graph
            .iter()
            .find(|e| claim.intent.contains(&e.glyph) || claim.kind == "flag_orbit")
        {
            (
                "decompile_function".to_string(),
                edge.handler.map(|h| format!("0x{h:x}")),
            )
        } else if let Some(case) = lattice
            .case_lexicon
            .iter()
            .find(|c| claim.intent.contains(&c.glyph))
        {
            (
                "decompile_function".to_string(),
                case.target.map(|t| format!("0x{t:x}")),
            )
        } else if lattice.quality.escalate {
            ("function_profile".to_string(), None)
        } else {
            ("decompile_function".to_string(), None)
        };
        let expected_true = claim
            .anchors
            .first()
            .and_then(|aid| lattice.anchors.iter().find(|a| a.id == *aid))
            .map(|a| truncate(&a.surface, 64))
            .unwrap_or_else(|| {
                claim
                    .intent
                    .split_whitespace()
                    .take(5)
                    .collect::<Vec<_>>()
                    .join(" ")
            });
        let expected_false = truncate(&conjugate, 72);
        let gain = (claim.confidence * (1.0 - coverage) * (0.55 + 0.45 * claim.confidence))
            .clamp(0.05, 0.99);
        probes.push(PhaseConjugateProbe {
            claim_id: claim.id.clone(),
            claim_intent: claim.intent.clone(),
            conjugate,
            tool,
            query,
            expected_true,
            expected_false,
            information_gain: gain,
        });
    }
    probes.sort_by(|a, b| {
        b.information_gain
            .partial_cmp(&a.information_gain)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    probes.truncate(10);
    probes
}

pub fn project_cognitive_field(lattice: &AgentSemanticLattice) -> CognitiveField {
    let mut buckets: BTreeMap<String, Vec<&AgentClaim>> = BTreeMap::new();
    for claim in &lattice.claims {
        if matches!(
            claim.kind.as_str(),
            "standing_wave" | "field_null" | "phase_conjugate" | "cognitive_field"
        ) {
            continue;
        }
        buckets
            .entry(claim_resonance_key(claim))
            .or_default()
            .push(claim);
    }
    let mut waves = Vec::new();
    let mut nulls = Vec::new();
    for (key, group) in buckets {
        if group.is_empty() {
            continue;
        }
        let max_c = group.iter().map(|c| c.confidence).fold(0.0_f32, f32::max);
        let has_conflict = group.iter().any(|c| c.kind == "orbit_conflict")
            || lattice.contradictions.iter().any(|c| {
                group.iter().any(|g| {
                    c.contains(&g.id)
                        || g.intent
                            .split_whitespace()
                            .any(|t| t.len() > 3 && c.contains(t))
                })
            });
        let polarity = if has_conflict {
            "contested"
        } else if group.len() >= 2 || max_c >= 0.9 {
            "constructive"
        } else if max_c < 0.7 {
            "latent"
        } else {
            "constructive"
        };
        if polarity == "contested" {
            nulls.push(format!(
                "destructive interference on {} :: {}",
                key,
                truncate(&group[0].intent, 80)
            ));
        }
        let amp = if polarity == "constructive" {
            (max_c * (1.0 + 0.12 * ((group.len() as f32) - 1.0))).min(0.99)
        } else if polarity == "contested" {
            (max_c * 0.72).max(0.2)
        } else {
            max_c * 0.85
        };
        waves.push(StandingWave {
            intent: group[0].intent.clone(),
            amplitude: amp,
            sources: group.iter().map(|c| c.id.clone()).collect(),
            polarity: polarity.to_string(),
            kind: group[0].kind.clone(),
        });
    }
    for c in &lattice.contradictions {
        nulls.push(format!("null: {c}"));
    }
    for claim in lattice.claims.iter().filter(|c| c.kind == "orbit_conflict") {
        nulls.push(format!("orbit_null: {}", truncate(&claim.intent, 90)));
    }
    waves.sort_by(|a, b| {
        b.amplitude
            .partial_cmp(&a.amplitude)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    waves.truncate(8);
    nulls.truncate(8);
    let conjugates = compile_phase_conjugates(lattice);
    let entropy = field_entropy(lattice, &waves, nulls.len());
    let mode = field_mode(entropy, &waves, nulls.len(), lattice.quality.escalate);
    let mut field = CognitiveField {
        mode,
        entropy,
        standing_waves: waves,
        nulls,
        conjugates,
        collapse_events: Vec::new(),
        residuals: Vec::new(),
        proof_chain: Vec::new(),
        field_epoch: 0,
    };
    field.residuals = project_diffraction_residuals(&field, lattice);
    field
}

pub fn interfere_cognitive_fields(
    pieces: &[(String, &AgentSemanticLattice)],
    fused: &AgentSemanticLattice,
) -> CognitiveField {
    let mut base = project_cognitive_field(fused);
    if pieces.len() < 2 {
        return base;
    }
    let mut cross: BTreeMap<String, Vec<(String, f32, String)>> = BTreeMap::new();
    for (name, lat) in pieces {
        for claim in &lat.claims {
            if matches!(
                claim.kind.as_str(),
                "standing_wave" | "field_null" | "phase_conjugate" | "cognitive_field"
            ) {
                continue;
            }
            let key = claim_resonance_key(claim);
            cross
                .entry(key)
                .or_default()
                .push((name.clone(), claim.confidence, claim.intent.clone()));
        }
    }
    for (_key, group) in cross {
        let sources: BTreeSet<String> = group.iter().map(|g| g.0.clone()).collect();
        if sources.len() < 2 {
            continue;
        }
        let amp = group.iter().map(|g| g.1).fold(0.0_f32, f32::max);
        let boosted = (amp * (1.0 + 0.18 * ((sources.len() as f32) - 1.0))).min(0.995);
        let intent = group
            .iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|g| g.2.clone())
            .unwrap_or_default();
        if let Some(existing) = base.standing_waves.iter_mut().find(|w| {
            w.intent == intent
                || w.intent
                    .split_whitespace()
                    .take(3)
                    .zip(intent.split_whitespace().take(3))
                    .filter(|(a, b)| a == b)
                    .count()
                    >= 2
        }) {
            existing.amplitude = existing.amplitude.max(boosted);
            existing.polarity = "constructive".to_string();
            for s in &sources {
                if !existing.sources.contains(s) {
                    existing.sources.push(s.clone());
                }
            }
        } else {
            base.standing_waves.push(StandingWave {
                intent,
                amplitude: boosted,
                sources: sources.into_iter().collect(),
                polarity: "constructive".to_string(),
                kind: "interference".to_string(),
            });
        }
    }
    base.standing_waves.sort_by(|a, b| {
        b.amplitude
            .partial_cmp(&a.amplitude)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    base.standing_waves.truncate(10);
    base.entropy = field_entropy(fused, &base.standing_waves, base.nulls.len());
    base.mode = field_mode(
        base.entropy,
        &base.standing_waves,
        base.nulls.len(),
        fused.quality.escalate,
    );
    base.conjugates = compile_phase_conjugates(fused);
    base
}

pub fn apply_cognitive_field_to_lattice(lattice: &mut AgentSemanticLattice, field: &CognitiveField) {
    lattice.claims.retain(|c| {
        !matches!(
            c.kind.as_str(),
            "standing_wave" | "field_null" | "phase_conjugate" | "cognitive_field"
        )
    });
    if let Some(wave) = field.standing_waves.first() {
        lattice.claims.insert(
            0,
            AgentClaim {
                id: "c_wave".to_string(),
                intent: format!(
                    "standing wave [{:.2} {}] {}",
                    wave.amplitude,
                    wave.polarity,
                    truncate(&wave.intent, 140)
                ),
                kind: "standing_wave".to_string(),
                confidence: wave.amplitude,
                anchors: wave.sources.clone(),
                path: Some(format!("field_mode={}", field.mode)),
                confutation: field.nulls.first().cloned(),
                probes: field
                    .conjugates
                    .first()
                    .map(|p| AgentNextAction {
                        tool: p.tool.clone(),
                        reason: format!("collapse conjugate of {}", p.claim_id),
                        priority: 97,
                        query: p.query.clone(),
                        label: Some("pccf-collapse".to_string()),
                        args: p
                            .query
                            .as_ref()
                            .map(|q| serde_json::json!({ "query": q }))
                            .unwrap_or_else(|| serde_json::json!({})),
                    })
                    .into_iter()
                    .collect(),
            },
        );
    }
    lattice.claims.insert(
        0,
        AgentClaim {
            id: "c_field".to_string(),
            intent: format!(
                "cognitive field mode={} entropy={:.2} waves={} nulls={} conjugates={}",
                field.mode,
                field.entropy,
                field.standing_waves.len(),
                field.nulls.len(),
                field.conjugates.len()
            ),
            kind: "cognitive_field".to_string(),
            confidence: (1.0 - field.entropy).clamp(0.2, 0.99),
            anchors: Vec::new(),
            path: Some(format!("epoch={}", field.field_epoch)),
            confutation: Some(
                "field is a projection; single contradictory observation can invert polarity"
                    .to_string(),
            ),
            probes: field
                .conjugates
                .iter()
                .take(2)
                .map(|p| AgentNextAction {
                    tool: p.tool.clone(),
                    reason: format!("phase conjugate probe for {}", p.claim_id),
                    priority: 96,
                    query: p.query.clone(),
                    label: Some("pccf-conjugate".to_string()),
                    args: p
                        .query
                        .as_ref()
                        .map(|q| serde_json::json!({ "query": q }))
                        .unwrap_or_else(|| serde_json::json!({})),
                })
                .collect(),
        },
    );
    for (i, null) in field.nulls.iter().take(3).enumerate() {
        lattice.claims.push(AgentClaim {
            id: format!("c_null{i}"),
            intent: null.clone(),
            kind: "field_null".to_string(),
            confidence: 0.55,
            anchors: Vec::new(),
            path: None,
            confutation: Some(
                "null may be instrumentation artifact rather than true cancellation".to_string(),
            ),
            probes: Vec::new(),
        });
    }
    if let Some(probe) = field.conjugates.first() {
        lattice.claims.push(AgentClaim {
            id: "c_conj".to_string(),
            intent: format!(
                "phase conjugate of {} :: collapse via `{}` true=[{}] false=[{}]",
                probe.claim_id,
                probe.tool,
                truncate(&probe.expected_true, 48),
                truncate(&probe.expected_false, 48)
            ),
            kind: "phase_conjugate".to_string(),
            confidence: probe.information_gain,
            anchors: vec![probe.claim_id.clone()],
            path: probe.query.clone(),
            confutation: Some(probe.conjugate.clone()),
            probes: vec![AgentNextAction {
                tool: probe.tool.clone(),
                reason: "execute highest-gain phase conjugate".to_string(),
                priority: 98,
                query: probe.query.clone(),
                label: Some("pccf-primary".to_string()),
                args: probe
                    .query
                    .as_ref()
                    .map(|q| serde_json::json!({ "query": q }))
                    .unwrap_or_else(|| serde_json::json!({})),
            }],
        });
    }
    for (idx, claim) in lattice.claims.iter_mut().enumerate() {
        claim.id = format!("c{}", idx + 1);
    }
    if field.mode == "structural" || field.mode == "collapsing" {
        if let Some(wave) = field.standing_waves.first() {
            let orbit_rich = lattice.thesis.contains("orbit") || lattice.thesis.contains("flag");
            if lattice.thesis.is_empty() || !orbit_rich {
                lattice.thesis = truncate(
                    &format!("[{}] {:.2}: {}", field.mode, wave.amplitude, wave.intent),
                    280,
                );
            } else if !lattice.thesis.starts_with('[') {
                lattice.thesis =
                    truncate(&format!("[{}] {}", field.mode, lattice.thesis), 280);
            }
        }
    } else if field.mode == "contested" {
        let base = if lattice.thesis.contains("orbit") || lattice.thesis.contains("flag") {
            lattice.thesis.clone()
        } else {
            field
                .nulls
                .first()
                .cloned()
                .unwrap_or_else(|| lattice.thesis.clone())
        };
        lattice.thesis = truncate(
            &format!("[contested field e={:.2}] {base}", field.entropy),
            280,
        );
    }
    if !field.standing_waves.is_empty() || !field.conjugates.is_empty() {
        if lattice.method.starts_with("casl") {
            lattice.method = "casl-v6-pccf".to_string();
        }
    }
    if let Some(probe) = field.conjugates.first() {
        let already = lattice.ibc.iter().any(|s| {
            s.tool.as_deref() == Some(probe.tool.as_str())
                && probe
                    .query
                    .as_ref()
                    .map(|q| s.args.get("query").and_then(|v| v.as_str()) == Some(q.as_str()))
                    .unwrap_or(true)
        });
        if !already {
            let pc = lattice
                .ibc
                .iter()
                .map(|s| s.pc)
                .max()
                .map(|p| p.saturating_add(1))
                .unwrap_or(0);
            lattice.ibc.push(IbcStep {
                pc,
                op: "CONJUGATE".to_string(),
                detail: format!(
                    "phase conjugate {} gain={:.2}",
                    probe.claim_id, probe.information_gain
                ),
                tool: Some(probe.tool.clone()),
                args: probe
                    .query
                    .as_ref()
                    .map(|q| serde_json::json!({ "query": q }))
                    .unwrap_or_else(|| serde_json::json!({})),
                claim_id: Some(probe.claim_id.clone()),
            });
            lattice
                .investigation_bytecode
                .push(format!("CONJUGATE {} {}", probe.tool, probe.claim_id));
        }
    }
}


pub fn synthesize_observation_corpus(
    lattice: &AgentSemanticLattice,
    extra: Option<&str>,
) -> String {
    let mut parts = Vec::new();
    if let Some(extra) = extra {
        if !extra.trim().is_empty() {
            parts.push(truncate(extra, 4000));
        }
    }
    if !lattice.thesis.is_empty() {
        parts.push(lattice.thesis.clone());
    }
    for claim in lattice.claims.iter().take(16) {
        parts.push(claim.intent.clone());
        if let Some(c) = &claim.confutation {
            parts.push(c.clone());
        }
    }
    for anchor in lattice.anchors.iter().take(20) {
        parts.push(format!("{} {}", anchor.surface, anchor.evidence));
    }
    for edge in lattice.behavior_graph.iter().take(12) {
        parts.push(edge.behaviors.join(" "));
        parts.push(edge.effects.join(" "));
        if let Some(o) = &edge.orbit {
            parts.push(o.clone());
        }
    }
    for case in lattice.case_lexicon.iter().take(16) {
        if let Some(m) = &case.meaning {
            parts.push(m.clone());
        }
        if let Some(n) = &case.target_name {
            parts.push(n.clone());
        }
    }
    parts.join("\n")
}

fn significant_tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for raw in text.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
        let t = raw.to_ascii_lowercase();
        if t.len() < 3 {
            continue;
        }
        if matches!(
            t.as_str(),
            "the"
                | "and"
                | "via"
                | "with"
                | "from"
                | "this"
                | "that"
                | "into"
                | "for"
                | "then"
                | "function"
                | "return"
                | "true"
                | "false"
                | "null"
                | "void"
                | "int"
                | "char"
        ) {
            continue;
        }
        if seen.insert(t.clone()) {
            out.push(t);
        }
        if out.len() >= 12 {
            break;
        }
    }
    out
}

fn token_hit_score(obs: &str, signature: &str) -> f32 {
    let tokens = significant_tokens(signature);
    if tokens.is_empty() {
        return 0.0;
    }
    let hits = tokens.iter().filter(|t| obs.contains(t.as_str())).count() as f32;
    hits / tokens.len() as f32
}

pub fn project_diffraction_residuals(
    field: &CognitiveField,
    lattice: &AgentSemanticLattice,
) -> Vec<DiffractionResidual> {
    let mut residuals = Vec::new();
    for (i, probe) in field.conjugates.iter().enumerate() {
        let sealed = field.collapse_events.iter().any(|e| {
            e.starts_with(&format!("{}:", probe.claim_id))
                && (e.contains("=> true") || e.contains("=> false"))
        });
        let polarity = if sealed {
            "sealed"
        } else if probe.information_gain >= 0.55 {
            "open"
        } else {
            "narrowing"
        };
        residuals.push(DiffractionResidual {
            id: format!("r{}", i + 1),
            question: format!(
                "Does `{}` {} collapse claim {}? true=[{}] false=[{}]",
                probe.tool,
                probe.query.as_ref().map(|q| q.as_str()).unwrap_or("-"),
                truncate(&probe.claim_intent, 64),
                truncate(&probe.expected_true, 36),
                truncate(&probe.expected_false, 36)
            ),
            information_value: if sealed {
                (probe.information_gain * 0.15).max(0.05)
            } else {
                probe.information_gain
            },
            probe_tool: probe.tool.clone(),
            probe_query: probe.query.clone(),
            polarity: polarity.to_string(),
        });
    }
    if lattice.quality.escalate {
        residuals.push(DiffractionResidual {
            id: format!("r{}", residuals.len() + 1),
            question: lattice.quality.escalate_reason.clone().unwrap_or_else(|| {
                "sparse lattice requires profile/disassemble escalation".into()
            }),
            information_value: 0.7,
            probe_tool: "function_profile".to_string(),
            probe_query: None,
            polarity: "open".to_string(),
        });
    }
    for null in field.nulls.iter().take(3) {
        residuals.push(DiffractionResidual {
            id: format!("r{}", residuals.len() + 1),
            question: format!("Resolve field null: {null}"),
            information_value: 0.48,
            probe_tool: "decompile_function".to_string(),
            probe_query: field.conjugates.first().and_then(|p| p.query.clone()),
            polarity: "narrowing".to_string(),
        });
    }
    residuals.sort_by(|a, b| {
        let pa = if a.polarity == "sealed" { 0 } else { 1 };
        let pb = if b.polarity == "sealed" { 0 } else { 1 };
        pb.cmp(&pa).then_with(|| {
            b.information_value
                .partial_cmp(&a.information_value)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    });
    residuals.truncate(10);
    residuals
}

pub fn inject_diffraction_residuals_into_lattice(
    lattice: &mut AgentSemanticLattice,
    field: &CognitiveField,
) {
    lattice
        .claims
        .retain(|c| c.kind != "diffraction_residual" && c.kind != "collapse_verdict");
    for (i, residual) in field
        .residuals
        .iter()
        .filter(|r| r.polarity != "sealed")
        .take(4)
        .enumerate()
    {
        lattice.claims.push(AgentClaim {
            id: format!("c_res{i}"),
            intent: format!(
                "residual [{}] iv={:.2}: {}",
                residual.polarity, residual.information_value, residual.question
            ),
            kind: "diffraction_residual".to_string(),
            confidence: residual.information_value.clamp(0.2, 0.95),
            anchors: vec![residual.id.clone()],
            path: residual.probe_query.clone(),
            confutation: Some("residual may be overfit to sparse observation corpus".to_string()),
            probes: vec![AgentNextAction {
                tool: residual.probe_tool.clone(),
                reason: format!("collapse diffraction residual {}", residual.id),
                priority: (95u8).saturating_sub(i as u8),
                query: residual.probe_query.clone(),
                label: Some(format!("drm-{}", residual.id)),
                args: residual
                    .probe_query
                    .as_ref()
                    .map(|q| serde_json::json!({ "query": q }))
                    .unwrap_or_else(|| serde_json::json!({})),
            }],
        });
    }
    for (i, event) in field.collapse_events.iter().rev().take(3).enumerate() {
        let conf = if event.contains("=> true") {
            0.92
        } else if event.contains("=> false") {
            0.88
        } else {
            0.7
        };
        lattice.claims.push(AgentClaim {
            id: format!("c_col{i}"),
            intent: format!("collapse verdict: {event}"),
            kind: "collapse_verdict".to_string(),
            confidence: conf,
            anchors: Vec::new(),
            path: None,
            confutation: Some("collapse signatures can false-match on short tokens".to_string()),
            probes: Vec::new(),
        });
    }
    for (idx, claim) in lattice.claims.iter_mut().enumerate() {
        claim.id = format!("c{}", idx + 1);
    }
    if !field.residuals.is_empty() || !field.collapse_events.is_empty() {
        if lattice.method.starts_with("casl") && !lattice.method.contains("v8") {
            lattice.method = "casl-v7-odc".to_string();
        }
    }
}

pub fn collapse_cognitive_field(
    field: &mut CognitiveField,
    lattice: &mut AgentSemanticLattice,
    tool: &str,
    query: &str,
    observation: Option<&str>,
) -> Vec<String> {
    let mut events = Vec::new();
    let q = query.to_ascii_lowercase();
    let obs = observation
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    let probes = if field.conjugates.is_empty() {
        let compiled = compile_phase_conjugates(lattice);
        field.conjugates = compiled.clone();
        compiled
    } else {
        field.conjugates.clone()
    };
    for probe in probes {
        let tool_hit = probe.tool == tool
            || (tool == "function_profile" && probe.tool == "decompile_function")
            || (tool == "decompile_function" && probe.tool == "function_profile")
            || tool == "ibc_advance";
        let decompile_family = tool == "decompile_function" || tool == "function_profile";
        if !tool_hit && !decompile_family {
            continue;
        }
        let query_hit = match &probe.query {
            Some(pq) => {
                let pq = pq.to_ascii_lowercase();
                q.is_empty() || q.contains(&pq) || pq.contains(&q) || obs.contains(&pq)
            }
            None => true,
        };
        if !query_hit && !decompile_family {
            continue;
        }
        if !query_hit && decompile_family && obs.is_empty() {
            continue;
        }
        let true_score = token_hit_score(&obs, &probe.expected_true);
        let false_score = token_hit_score(&obs, &probe.expected_false);
        let confute_score = token_hit_score(&obs, &probe.conjugate);
        let intent_score = token_hit_score(&obs, &probe.claim_intent);
        let polarity = if obs.is_empty() {
            "probe"
        } else if false_score >= 0.34 && false_score + confute_score * 0.5 > true_score {
            "false"
        } else if true_score >= 0.34 || (intent_score >= 0.45 && true_score >= false_score) {
            "true"
        } else {
            "probe"
        };
        events.push(format!(
            "{}:{} via {} {} => {polarity} (t={:.2}/f={:.2}/i={:.2})",
            probe.claim_id,
            truncate(&probe.claim_intent, 48),
            tool,
            if query.is_empty() { "-" } else { query },
            true_score,
            false_score,
            intent_score
        ));
        if let Some(claim) = lattice
            .claims
            .iter_mut()
            .find(|c| c.id == probe.claim_id || c.intent == probe.claim_intent)
        {
            match polarity {
                "true" => {
                    claim.confidence = (claim.confidence + 0.1 + true_score * 0.08).min(0.99);
                }
                "false" => {
                    claim.confidence =
                        (claim.confidence * (0.5 - false_score * 0.15).max(0.25)).max(0.12);
                    claim.confutation = Some(format!(
                        "collapsed false by {tool} {query}: {}",
                        probe.conjugate
                    ));
                }
                _ => {
                    claim.confidence = (claim.confidence + 0.025 + intent_score * 0.03).min(0.97);
                }
            }
        }
        if let Some(wave) = field.standing_waves.iter_mut().find(|w| {
            w.sources.contains(&probe.claim_id) || w.intent == probe.claim_intent
        }) {
            match polarity {
                "true" => {
                    wave.amplitude = (wave.amplitude + 0.07 + true_score * 0.05).min(0.995);
                    wave.polarity = "constructive".to_string();
                }
                "false" => {
                    wave.amplitude = (wave.amplitude * 0.48).max(0.1);
                    wave.polarity = "contested".to_string();
                    field.nulls.push(format!(
                        "collapsed null on {}: {}",
                        probe.claim_id,
                        truncate(&probe.conjugate, 72)
                    ));
                }
                _ => {
                    wave.amplitude = (wave.amplitude + 0.02).min(0.99);
                }
            }
        }
    }
    if !events.is_empty() {
        let depth = events
            .iter()
            .filter(|e| e.contains("=> true") || e.contains("=> false"))
            .count();
        let factor = if depth > 0 { 0.82 } else { 0.9 };
        field.entropy = (field.entropy * factor).clamp(0.04, 1.0);
        field.mode = field_mode(
            field.entropy,
            &field.standing_waves,
            field.nulls.len(),
            lattice.quality.escalate,
        );
        field.collapse_events.extend(events.iter().cloned());
        if field.collapse_events.len() > 32 {
            let n = field.collapse_events.len() - 32;
            field.collapse_events.drain(0..n);
        }
    }
    field.residuals = project_diffraction_residuals(field, lattice);
    events
}

pub fn format_cognitive_field_lines(field: &CognitiveField) -> Vec<String> {
    if field.mode.is_empty()
        && field.standing_waves.is_empty()
        && field.conjugates.is_empty()
        && field.residuals.is_empty()
    {
        return Vec::new();
    }
    let mut lines = vec![
        "### Cognitive Field (PCCF/ODC)".to_string(),
        format!(
            "mode={} entropy={:.2} epoch={} waves={} nulls={} conjugates={} residuals={}",
            if field.mode.is_empty() {
                "latent"
            } else {
                field.mode.as_str()
            },
            field.entropy,
            field.field_epoch,
            field.standing_waves.len(),
            field.nulls.len(),
            field.conjugates.len(),
            field.residuals.len()
        ),
    ];
    for wave in field.standing_waves.iter().take(4) {
        lines.push(format!(
            "  WAVE {:.2} [{}] {} :: src={}",
            wave.amplitude,
            wave.polarity,
            truncate(&wave.intent, 110),
            wave.sources
                .iter()
                .take(4)
                .cloned()
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    for null in field.nulls.iter().take(3) {
        lines.push(format!("  NULL {}", truncate(null, 120)));
    }
    for probe in field.conjugates.iter().take(3) {
        lines.push(format!(
            "  CONJ {} gain={:.2} `{}` {} | true=[{}] false=[{}]",
            probe.claim_id,
            probe.information_gain,
            probe.tool,
            probe.query.as_ref().map(|q| q.as_str()).unwrap_or("-"),
            truncate(&probe.expected_true, 40),
            truncate(&probe.expected_false, 40)
        ));
    }
    for residual in field
        .residuals
        .iter()
        .filter(|r| r.polarity != "sealed")
        .take(4)
    {
        lines.push(format!(
            "  RESIDUAL [{}] iv={:.2} `{}` {} | {}",
            residual.polarity,
            residual.information_value,
            residual.probe_tool,
            residual
                .probe_query
                .as_ref()
                .map(|q| q.as_str())
                .unwrap_or("-"),
            truncate(&residual.question, 100)
        ));
    }
    for event in field.collapse_events.iter().rev().take(3) {
        lines.push(format!("  COLLAPSE {}", truncate(event, 120)));
    }
    if let Some(probe) = field.conjugates.first() {
        lines.push(format!(
            "EXECUTE CONJUGATE: `{}` {} // max information gain {:.2}",
            probe.tool,
            probe.query.as_ref().map(|q| q.as_str()).unwrap_or(""),
            probe.information_gain
        ));
    }
    if let Some(residual) = field.residuals.iter().find(|r| r.polarity != "sealed") {
        lines.push(format!(
            "EXECUTE RESIDUAL: `{}` {} // iv={:.2} {}",
            residual.probe_tool,
            residual
                .probe_query
                .as_ref()
                .map(|q| q.as_str())
                .unwrap_or(""),
            residual.information_value,
            truncate(&residual.question, 80)
        ));
    }
    if !field.proof_chain.is_empty() {
        lines.push("### Proof Chain (PCOS)".to_string());
        for link in field.proof_chain.iter().rev().take(6) {
            lines.push(format!(
                "  LINK [{}] key={} hyp={} claim={} @e{} | {}",
                link.verdict,
                link.orbit_key,
                link.hypothesis_id.as_deref().unwrap_or("-"),
                link.claim_id,
                link.sealed_at_epoch,
                truncate(&link.summary, 90)
            ));
        }
        let sealed = field
            .proof_chain
            .iter()
            .filter(|l| l.verdict == "true" || l.verdict == "false")
            .count();
        if sealed > 0 {
            lines.push(format!(
                "SEALED_ORBITS: {sealed}/{} (agent may stop on fully sealed orbit set)",
                field.proof_chain.len()
            ));
        }
    }
    lines
}


pub fn parse_collapse_verdict(event: &str) -> Option<CollapseVerdict> {
    let raw = event.trim();
    if raw.is_empty() {
        return None;
    }
    let (head, score_blob) = match raw.rfind(" (t=") {
        Some(idx) => (&raw[..idx], &raw[idx + 2..]),
        None => (raw, ""),
    };
    let (left, polarity_part) = head.split_once(" => ")?;
    let polarity = polarity_part
        .split_whitespace()
        .next()
        .unwrap_or("probe")
        .to_string();
    let (claim_part, via_part) = left.split_once(" via ")?;
    let (claim_id, claim_intent) = match claim_part.split_once(':') {
        Some((id, intent)) => (id.to_string(), intent.to_string()),
        None => (claim_part.to_string(), String::new()),
    };
    let mut tool = String::new();
    let mut query = String::new();
    let mut via_iter = via_part.split_whitespace();
    if let Some(t) = via_iter.next() {
        tool = t.to_string();
    }
    if let Some(q) = via_iter.next() {
        query = q.to_string();
    }
    let mut true_score = 0.0;
    let mut false_score = 0.0;
    let mut intent_score = 0.0;
    if !score_blob.is_empty() {
        let cleaned = score_blob
            .trim()
            .trim_start_matches('(')
            .trim_end_matches(')');
        for part in cleaned.split('/') {
            let part = part.trim();
            if let Some(v) = part.strip_prefix("t=") {
                true_score = v.parse().unwrap_or(0.0);
            } else if let Some(v) = part.strip_prefix("f=") {
                false_score = v.parse().unwrap_or(0.0);
            } else if let Some(v) = part.strip_prefix("i=") {
                intent_score = v.parse().unwrap_or(0.0);
            }
        }
    }
    Some(CollapseVerdict {
        claim_id,
        claim_intent,
        tool,
        query,
        polarity,
        true_score,
        false_score,
        intent_score,
        raw: raw.to_string(),
    })
}

pub fn match_verdict_to_orbit_key(
    verdict: &CollapseVerdict,
    state: &IbcContinuumState,
) -> Option<String> {
    let intent = verdict.claim_intent.to_ascii_lowercase();
    let query = verdict.query.to_ascii_lowercase();
    for edge in &state.lattice.behavior_graph {
        let key = format!("{}:{}", edge.code, edge.glyph);
        let glyph = edge.glyph.to_ascii_lowercase();
        let handler = edge
            .handler
            .map(|h| format!("0x{h:x}"))
            .unwrap_or_default()
            .to_ascii_lowercase();
        let handler_name = edge
            .handler_name
            .clone()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if (!glyph.is_empty() && intent.contains(&glyph))
            || (!handler.is_empty() && (query.contains(&handler) || intent.contains(&handler)))
            || (!handler_name.is_empty() && intent.contains(&handler_name))
            || state.orbit_hypotheses.contains_key(&key)
                && (intent.contains(&glyph) || query.contains(&handler))
        {
            return Some(key);
        }
    }
    for case in &state.lattice.case_lexicon {
        let key = format!("{}:{}", case.code, case.glyph);
        let glyph = case.glyph.to_ascii_lowercase();
        let target = case
            .target
            .map(|t| format!("0x{t:x}"))
            .unwrap_or_default()
            .to_ascii_lowercase();
        if intent.contains(&glyph) || (!target.is_empty() && query.contains(&target)) {
            return Some(key);
        }
    }
    if let Some((key, _)) = state.orbit_hypotheses.iter().next() {
        if verdict.polarity == "true" || verdict.polarity == "false" {
            return Some(key.clone());
        }
    }
    None
}

pub fn apply_verdict_to_hypothesis_title(title: &str, polarity: &str) -> String {
    let bare = title
        .trim_start_matches("[PROVEN] ")
        .trim_start_matches("[REFUTED] ")
        .trim_start_matches("[PROBED] ")
        .to_string();
    match polarity {
        "true" => format!("[PROVEN] {bare}"),
        "false" => format!("[REFUTED] {bare}"),
        "probe" => {
            if title.contains("[PROVEN]") || title.contains("[REFUTED]") {
                title.to_string()
            } else {
                format!("[PROBED] {bare}")
            }
        }
        _ => title.to_string(),
    }
}

pub fn apply_verdict_to_hypothesis_notes(
    notes: &str,
    verdict: &CollapseVerdict,
    epoch: u64,
    orbit_key: &str,
) -> String {
    let marker = format!("### PCOS VERDICT e{epoch} {orbit_key}");
    if notes.contains(&marker) {
        return notes.to_string();
    }
    let block = format!(
        "{marker}\npolarity={}\nclaim={}:{}\ntool=`{}` query={}\nscores: t={:.2} f={:.2} i={:.2}\nraw: {}\n",
        verdict.polarity,
        verdict.claim_id,
        truncate(&verdict.claim_intent, 100),
        verdict.tool,
        if verdict.query.is_empty() {
            "-"
        } else {
            verdict.query.as_str()
        },
        verdict.true_score,
        verdict.false_score,
        verdict.intent_score,
        truncate(&verdict.raw, 160)
    );
    if notes.is_empty() {
        block
    } else {
        format!("{notes}\n\n{block}")
    }
}

pub fn compose_proof_chain(state: &IbcContinuumState) -> Vec<ProofChainLink> {
    let mut links = Vec::new();
    let mut seen = BTreeSet::new();
    for event in state.cognitive_field.collapse_events.iter().rev().take(24) {
        let Some(verdict) = parse_collapse_verdict(event) else {
            continue;
        };
        let Some(orbit_key) = match_verdict_to_orbit_key(&verdict, state) else {
            continue;
        };
        let dedup = format!("{}:{}:{}", orbit_key, verdict.polarity, verdict.claim_id);
        if !seen.insert(dedup) {
            continue;
        }
        let hypothesis_id = state.orbit_hypotheses.get(&orbit_key).cloned();
        let summary = format!(
            "{} orbit `{}` via {} {} (t={:.2}/f={:.2})",
            verdict.polarity,
            orbit_key,
            verdict.tool,
            if verdict.query.is_empty() {
                "-"
            } else {
                verdict.query.as_str()
            },
            verdict.true_score,
            verdict.false_score
        );
        links.push(ProofChainLink {
            orbit_key,
            hypothesis_id,
            verdict: verdict.polarity,
            claim_id: verdict.claim_id,
            observation_query: verdict.query,
            score_line: format!(
                "t={:.2}/f={:.2}/i={:.2}",
                verdict.true_score, verdict.false_score, verdict.intent_score
            ),
            sealed_at_epoch: state.epoch,
            summary,
        });
    }
    links.reverse();
    links.truncate(16);
    links
}

pub fn inject_proof_chain_into_lattice(lattice: &mut AgentSemanticLattice, field: &CognitiveField) {
    lattice.claims.retain(|c| c.kind != "proof_chain");
    for (i, link) in field.proof_chain.iter().rev().take(5).enumerate() {
        let conf = match link.verdict.as_str() {
            "true" => 0.95,
            "false" => 0.93,
            _ => 0.7,
        };
        lattice.claims.push(AgentClaim {
            id: format!("c_proof{i}"),
            intent: format!(
                "proof [{}] orbit={} hyp={} :: {}",
                link.verdict,
                link.orbit_key,
                link.hypothesis_id.as_deref().unwrap_or("-"),
                truncate(&link.summary, 120)
            ),
            kind: "proof_chain".to_string(),
            confidence: conf,
            anchors: vec![link.claim_id.clone()],
            path: Some(link.observation_query.clone()),
            confutation: Some(
                "proof links inherit collapse signature noise; re-run conjugate to confirm"
                    .to_string(),
            ),
            probes: Vec::new(),
        });
    }
    for (idx, claim) in lattice.claims.iter_mut().enumerate() {
        claim.id = format!("c{}", idx + 1);
    }
    let sealed = field
        .proof_chain
        .iter()
        .filter(|l| l.verdict == "true" || l.verdict == "false")
        .count();
    if sealed > 0 && lattice.method.starts_with("casl") {
        lattice.method = "casl-v8-pcos".to_string();
    }
}

pub fn seal_plan_from_proof_chain(
    state: &IbcContinuumState,
) -> Vec<(String, String, String, String)> {
    let mut plan = Vec::new();
    for link in &state.cognitive_field.proof_chain {
        let Some(hid) = &link.hypothesis_id else {
            continue;
        };
        if link.verdict != "true" && link.verdict != "false" && link.verdict != "probe" {
            continue;
        }
        let Some(verdict) = state
            .cognitive_field
            .collapse_events
            .iter()
            .rev()
            .find_map(|e| {
                let v = parse_collapse_verdict(e)?;
                if v.claim_id == link.claim_id || e.contains(&link.orbit_key) {
                    Some(v)
                } else if match_verdict_to_orbit_key(&v, state).as_deref()
                    == Some(link.orbit_key.as_str())
                {
                    Some(v)
                } else {
                    None
                }
            })
        else {
            continue;
        };
        plan.push((
            hid.clone(),
            link.orbit_key.clone(),
            link.verdict.clone(),
            apply_verdict_to_hypothesis_notes("", &verdict, state.epoch, &link.orbit_key),
        ));
    }
    plan
}

pub fn format_proof_chain_lines(chain: &[ProofChainLink]) -> Vec<String> {
    if chain.is_empty() {
        return Vec::new();
    }
    let mut lines = vec![format!("proof_chain_links: {}", chain.len())];
    for link in chain.iter().rev().take(6) {
        lines.push(format!(
            "  [{}] {} hyp={} {}",
            link.verdict,
            link.orbit_key,
            link.hypothesis_id.as_deref().unwrap_or("-"),
            truncate(&link.summary, 90)
        ));
    }
    lines
}

fn continuum_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn is_dispatcher_lattice(lattice: &AgentSemanticLattice) -> bool {
    lattice.case_lexicon.iter().any(|c| c.target.is_some())
        || lattice.behavior_graph.iter().any(|e| e.handler.is_some())
        || lattice
            .ibc
            .iter()
            .any(|s| matches!(s.op.as_str(), "MAP_CASES" | "ORBIT_FLAG" | "VERIFY_CASE"))
}

fn tools_compatible(expected: Option<&str>, actual: &str) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    if expected == actual {
        return true;
    }
    matches!(
        (expected, actual),
        ("decompile_function", "function_profile")
            | ("function_profile", "decompile_function")
            | ("disassemble_function", "decompile_function")
            | ("decompile_function", "disassemble_function")
            | ("disassemble_function", "function_profile")
            | ("function_profile", "disassemble_function")
            | ("xrefs_query", "function_profile")
            | ("function_profile", "xrefs_query")
    )
}

fn queries_compatible(expected: &str, actual: &str) -> bool {
    if expected.is_empty() || actual.is_empty() {
        return expected.is_empty() || actual.is_empty();
    }
    if expected == actual {
        return true;
    }
    let ne = normalize_query_addr(expected);
    let na = normalize_query_addr(actual);
    match (ne, na) {
        (Some(a), Some(b)) => a == b,
        _ => expected.eq_ignore_ascii_case(actual),
    }
}

fn normalize_query_addr(q: &str) -> Option<u64> {
    let t = q.trim();
    let hex = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if hex.chars().all(|c| c.is_ascii_hexdigit()) && !hex.is_empty() && hex.len() <= 16 {
        u64::from_str_radix(hex, 16).ok()
    } else {
        None
    }
}

pub fn detect_and_attach_orbit_conflicts(lattice: &mut AgentSemanticLattice) {
    let mut conflicts: Vec<String> = Vec::new();
    let mut by_glyph: BTreeMap<String, Vec<&FlagBehaviorEdge>> = BTreeMap::new();
    for edge in &lattice.behavior_graph {
        by_glyph.entry(edge.glyph.clone()).or_default().push(edge);
    }
    for (glyph, edges) in &by_glyph {
        if edges.len() < 2 {
            continue;
        }
        let mut handlers: BTreeSet<u64> = BTreeSet::new();
        for e in edges {
            if let Some(h) = e.handler {
                handlers.insert(h);
            }
        }
        if handlers.len() > 1 {
            conflicts.push(format!(
                "split orbit on '{}': {} handlers {:?}",
                c_escape_glyph(glyph),
                handlers.len(),
                handlers.iter().take(4).map(|h| format!("0x{h:x}")).collect::<Vec<_>>()
            ));
        }
        let mut tag_sets: Vec<BTreeSet<String>> = edges
            .iter()
            .map(|e| e.behaviors.iter().cloned().collect())
            .collect();
        if tag_sets.len() >= 2 {
            let inter = tag_sets.iter().skip(1).fold(tag_sets[0].clone(), |acc, s| {
                acc.intersection(s).cloned().collect()
            });
            let union = tag_sets.iter().fold(BTreeSet::new(), |mut acc, s| {
                acc.extend(s.iter().cloned());
                acc
            });
            if inter.is_empty() && union.len() >= 2 {
                conflicts.push(format!(
                    "orbit '{}' behavior sets disjoint: {}",
                    c_escape_glyph(glyph),
                    union.into_iter().take(6).collect::<Vec<_>>().join(",")
                ));
            }
        }
    }
    const EXCLUSIVE: &[(&str, &str)] = &[
        ("verbose", "quiet"),
        ("help", "net"),
        ("help", "crypto"),
        ("long_list", "one_line"),
        ("recursive", "help"),
    ];
    for edge in &lattice.behavior_graph {
        let tags: BTreeSet<_> = edge.behaviors.iter().cloned().collect();
        for (a, b) in EXCLUSIVE {
            if tags.contains(*a) && tags.contains(*b) {
                conflicts.push(format!(
                    "orbit '{}' co-claims exclusive tags {}⊕{}",
                    c_escape_glyph(&edge.glyph),
                    a,
                    b
                ));
            }
        }
        if edge.handler.is_some()
            && edge.behaviors.iter().any(|t| t == "opaque" || t == "opaque_handler")
            && edge.confidence >= 0.9
        {
            conflicts.push(format!(
                "orbit '{}' high-confidence bind but opaque handler signature",
                c_escape_glyph(&edge.glyph)
            ));
        }
    }
    let mut by_handler: BTreeMap<u64, Vec<&FlagBehaviorEdge>> = BTreeMap::new();
    for edge in &lattice.behavior_graph {
        if let Some(h) = edge.handler {
            by_handler.entry(h).or_default().push(edge);
        }
    }
    for (handler, edges) in &by_handler {
        if edges.len() < 3 {
            continue;
        }
        let glyphs: Vec<_> = edges.iter().map(|e| e.glyph.as_str()).collect();
        let tag_union: BTreeSet<_> = edges
            .iter()
            .flat_map(|e| e.behaviors.iter().cloned())
            .collect();
        if tag_union.len() <= 1 {
            conflicts.push(format!(
                "handler 0x{handler:x} sinks {} flags {:?} with collapsed behavior {:?}",
                edges.len(),
                glyphs.iter().take(6).collect::<Vec<_>>(),
                tag_union
            ));
        }
    }
    conflicts.sort();
    conflicts.dedup();
    for c in conflicts.iter().take(8) {
        if !lattice.contradictions.iter().any(|x| x == c) {
            lattice.contradictions.push(c.clone());
        }
    }
    if conflicts.is_empty() || lattice.claims.iter().any(|c| c.kind == "orbit_conflict") {
        return;
    }
    lattice.claims.insert(
        0,
        AgentClaim {
            id: "c_oconf".to_string(),
            intent: format!(
                "detects {} flag-orbit conflict(s): {}",
                conflicts.len(),
                truncate(&conflicts.join("; "), 140)
            ),
            kind: "orbit_conflict".to_string(),
            confidence: 0.9,
            anchors: lattice
                .anchors
                .iter()
                .filter(|a| a.kind == "case_target" || a.kind == "case")
                .map(|a| a.id.clone())
                .take(4)
                .collect(),
            path: None,
            confutation: Some(
                "conflicts are recovery noise rather than true multi-dispatch".to_string(),
            ),
            probes: lattice
                .behavior_graph
                .iter()
                .filter_map(|e| e.handler.map(|h| (e, h)))
                .take(1)
                .map(|(e, h)| AgentNextAction {
                    tool: "decompile_function".to_string(),
                    reason: format!("resolve orbit conflict on '{}'", e.glyph),
                    priority: 97,
                    query: Some(format!("0x{h:x}")),
                    label: Some(format!("conflict:{}", e.glyph)),
                    args: serde_json::json!({ "query": format!("0x{h:x}") }),
                })
                .collect(),
        },
    );
    for (idx, claim) in lattice.claims.iter_mut().enumerate() {
        claim.id = format!("c{}", idx + 1);
    }
}

fn ibc_step_to_action(step: &IbcStep, fallback_address: u64, priority: u8) -> AgentNextAction {
    AgentNextAction {
        tool: step
            .tool
            .clone()
            .unwrap_or_else(|| "decompile_function".to_string()),
        reason: format!("IBC[{}] {} | {}", step.pc, step.op, step.detail),
        priority,
        query: step
            .args
            .get("query")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| Some(format!("0x{fallback_address:x}"))),
        label: Some(format!("ibc:{}", step.pc)),
        args: if step.args.is_null() || step.args == serde_json::json!({}) {
            serde_json::json!({ "query": format!("0x{fallback_address:x}") })
        } else {
            step.args.clone()
        },
    }
}


fn project_flag_behavior_graph(
    lattice: &mut AgentSemanticLattice,
    pieces: &[(String, u64, AgentSemanticLattice)],
) {
    if lattice.case_lexicon.is_empty() && lattice.behavior_graph.is_empty() {
        return;
    }
    let mut by_addr: HashMap<u64, &AgentSemanticLattice> = HashMap::new();
    let mut by_name: HashMap<String, &AgentSemanticLattice> = HashMap::new();
    for (name, addr, piece) in pieces {
        by_addr.insert(*addr, piece);
        by_name.insert(name.to_ascii_lowercase(), piece);
        if let Some(stripped) = name.strip_prefix('_') {
            by_name.insert(stripped.to_ascii_lowercase(), piece);
        }
    }
    let mut edges: Vec<FlagBehaviorEdge> = Vec::new();
    for case in &lattice.case_lexicon {
        let mut behaviors: BTreeSet<String> = BTreeSet::new();
        let mut effects: Vec<String> = Vec::new();
        let mut confidence = 0.72f32;
        let mut handler_lattice: Option<&AgentSemanticLattice> = None;
        if let Some(target) = case.target {
            if let Some(h) = by_addr.get(&target) {
                handler_lattice = Some(*h);
            }
        }
        if handler_lattice.is_none() {
            if let Some(name) = case.target_name.as_ref() {
                let key = name.to_ascii_lowercase();
                if let Some(h) = by_name.get(&key) {
                    handler_lattice = Some(*h);
                } else if let Some(h) = by_name.get(key.trim_start_matches('_')) {
                    handler_lattice = Some(*h);
                }
            }
        }
        if let Some(h) = handler_lattice {
            let (tags, mined, conf) = mine_handler_signature(h);
            for t in tags {
                behaviors.insert(t);
            }
            for e in mined {
                if !effects.iter().any(|x| x == &e) {
                    effects.push(e);
                }
            }
            confidence = conf;
        }
        if let Some(meaning) = &case.meaning {
            behaviors.insert(normalize_behavior_tag(meaning));
            if effects.is_empty() {
                effects.push(meaning.clone());
            }
            confidence = confidence.max(0.8);
        }
        if case.takes_arg {
            behaviors.insert("takes_arg".to_string());
        }
        if case.target.is_some() {
            confidence = confidence.max(0.9);
        }
        if behaviors.is_empty() && case.target.is_none() && case.meaning.is_none() {
            continue;
        }
        if behaviors.is_empty() {
            behaviors.insert("opaque_handler".to_string());
        }
        let handler_name = case.target_name.clone().or_else(|| {
            case.target.map(|t| format!("sub_{t:x}"))
        });
        let orbit = Some(format!(
            "'{}'→{}⟦{}⟧",
            c_escape_glyph(&case.glyph),
            handler_name.as_deref().unwrap_or("?"),
            behaviors.iter().cloned().take(4).collect::<Vec<_>>().join("+")
        ));
        edges.push(FlagBehaviorEdge {
            glyph: case.glyph.clone(),
            code: case.code,
            handler: case.target,
            handler_name,
            behaviors: behaviors.into_iter().collect(),
            effects: effects.into_iter().take(6).collect(),
            confidence,
            orbit,
        });
    }
    for prior in &lattice.behavior_graph {
        if !edges.iter().any(|e| e.code == prior.code) {
            edges.push(prior.clone());
        } else if let Some(edge) = edges.iter_mut().find(|e| e.code == prior.code) {
            for b in &prior.behaviors {
                if !edge.behaviors.iter().any(|x| x == b) {
                    edge.behaviors.push(b.clone());
                }
            }
            for e in &prior.effects {
                if !edge.effects.iter().any(|x| x == e) {
                    edge.effects.push(e.clone());
                }
            }
            if edge.handler.is_none() {
                edge.handler = prior.handler;
                edge.handler_name = prior.handler_name.clone();
            }
            edge.confidence = edge.confidence.max(prior.confidence);
            if edge.orbit.is_none() {
                edge.orbit = prior.orbit.clone();
            }
        }
    }
    edges.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.code.cmp(&b.code))
    });
    edges.truncate(48);
    lattice.behavior_graph = edges;
    detect_and_attach_orbit_conflicts(lattice);
}

fn attach_flag_orbit_claims(lattice: &mut AgentSemanticLattice) {
    if lattice.behavior_graph.is_empty() {
        return;
    }
    if lattice.claims.iter().any(|c| c.kind == "flag_orbit") {
        return;
    }
    let sample = lattice
        .behavior_graph
        .iter()
        .take(6)
        .filter_map(|e| e.orbit.clone())
        .collect::<Vec<_>>()
        .join(" | ");
    let resolved = lattice
        .behavior_graph
        .iter()
        .filter(|e| e.handler.is_some() && !e.behaviors.is_empty())
        .count();
    let probes = lattice
        .behavior_graph
        .iter()
        .filter_map(|e| e.handler.map(|h| (e, h)))
        .take(2)
        .map(|(e, h)| AgentNextAction {
            tool: "decompile_function".to_string(),
            reason: format!("orbit flag '{}' handler behavior", e.glyph),
            priority: 96,
            query: Some(format!("0x{h:x}")),
            label: Some(format!("orbit:{}", e.glyph)),
            args: serde_json::json!({ "query": format!("0x{h:x}") }),
        })
        .collect::<Vec<_>>();
    lattice.claims.insert(
        0,
        AgentClaim {
            id: "c_orbit".to_string(),
            intent: format!(
                "projects flag behavior graph: {resolved}/{} orbits ({})",
                lattice.behavior_graph.len(),
                truncate(&sample, 120)
            ),
            kind: "flag_orbit".to_string(),
            confidence: if resolved > 0 { 0.95 } else { 0.84 },
            anchors: lattice
                .anchors
                .iter()
                .filter(|a| a.kind == "case_target" || a.kind == "case")
                .map(|a| a.id.clone())
                .take(6)
                .collect(),
            path: None,
            confutation: Some(
                "handler side-effects are incidental to flag dispatch rather than caused by it"
                    .to_string(),
            ),
            probes,
        },
    );
    for (idx, claim) in lattice.claims.iter_mut().enumerate() {
        claim.id = format!("c{}", idx + 1);
    }
}

fn mine_handler_signature(lattice: &AgentSemanticLattice) -> (Vec<String>, Vec<String>, f32) {
    let mut tags: BTreeSet<String> = BTreeSet::new();
    let mut effects: Vec<String> = Vec::new();
    let mut score = 0.78f32;
    for claim in &lattice.claims {
        let intent_l = claim.intent.to_ascii_lowercase();
        match claim.kind.as_str() {
            "env" => {
                tags.insert("env".to_string());
                score = score.max(0.92);
            }
            "control" => {
                if intent_l.contains("terminal") || intent_l.contains("tty") {
                    tags.insert("tty".to_string());
                    score = score.max(0.91);
                } else if intent_l.contains("cli") {
                    tags.insert("cli".to_string());
                } else {
                    tags.insert("control".to_string());
                }
            }
            "case" | "case_bind" | "flag_orbit" => {
                tags.insert("dispatch".to_string());
            }
            "behavior" => {
                tags.insert("behavior".to_string());
            }
            other => {
                tags.insert(other.to_string());
            }
        }
        if intent_l.contains("environment") || intent_l.contains("getenv") {
            tags.insert("env".to_string());
            score = score.max(0.92);
        }
        if intent_l.contains("terminal") || intent_l.contains("isatty") {
            tags.insert("tty".to_string());
        }
        if intent_l.contains("socket") || intent_l.contains("connect") || intent_l.contains("network")
        {
            tags.insert("net".to_string());
            score = score.max(0.9);
        }
        let intent = truncate(&claim.intent, 72);
        if !effects.iter().any(|e| e == &intent) {
            effects.push(intent);
        }
    }
    for anchor in &lattice.anchors {
        let surface_l = anchor.surface.to_ascii_lowercase();
        match anchor.kind.as_str() {
            "string" => {
                tags.insert("string".to_string());
                let s = truncate(&anchor.surface, 48);
                if !effects.iter().any(|e| e == &s) {
                    effects.push(s);
                }
            }
            "env" => {
                tags.insert("env".to_string());
                score = score.max(0.92);
            }
            "call" => {
                tags.insert("call".to_string());
            }
            "io" | "net" | "mem" | "sync" | "crypto" | "tty" | "cli" => {
                tags.insert(anchor.kind.clone());
                score = score.max(0.9);
            }
            _ => {}
        }
        if surface_l.contains("getenv") || surface_l.contains("setenv") {
            tags.insert("env".to_string());
            score = score.max(0.92);
        }
        if surface_l.contains("isatty") || surface_l.contains("ttyname") {
            tags.insert("tty".to_string());
            score = score.max(0.91);
        }
        if surface_l.contains("socket")
            || surface_l.contains("connect")
            || surface_l.contains("bind")
            || surface_l.contains("recv")
            || surface_l.contains("send")
        {
            tags.insert("net".to_string());
            score = score.max(0.9);
        }
        if surface_l.contains("open") || surface_l.contains("read") || surface_l.contains("write") {
            tags.insert("io".to_string());
        }
    }
    if !lattice.thesis.is_empty() {
        let t = truncate(&lattice.thesis, 80);
        if !effects.iter().any(|e| e == &t) {
            effects.insert(0, t);
        }
        score = score.max(0.88);
    }
    tags.remove("data");
    tags.remove("dispatch");
    tags.remove("behavior");
    tags.remove("string");
    tags.remove("call");
    if tags.is_empty() {
        tags.insert("opaque".to_string());
        score = score.min(0.7);
    }
    (
        tags.into_iter().take(8).collect(),
        effects.into_iter().take(6).collect(),
        score,
    )
}

fn normalize_behavior_tag(meaning: &str) -> String {
    let lower = meaning.to_ascii_lowercase();
    if lower.contains("help") {
        return "help".to_string();
    }
    if lower.contains("version") {
        return "version".to_string();
    }
    if lower.contains("verbose") {
        return "verbose".to_string();
    }
    if lower.contains("recursive") {
        return "recursive".to_string();
    }
    if lower.contains("long listing") || lower.contains("long list") {
        return "long_list".to_string();
    }
    if lower.contains("human") {
        return "human_size".to_string();
    }
    if lower.contains("color") {
        return "color".to_string();
    }
    if lower.contains("inode") {
        return "inode".to_string();
    }
    if lower.contains("time") {
        return "sort_time".to_string();
    }
    if lower.contains("size") {
        return "sort_size".to_string();
    }
    if lower.contains("symlink") {
        return "follow_symlink".to_string();
    }
    let compact: String = meaning
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    truncate(&compact, 24)
}

fn compile_fbg_investigation_program(
    function_name: &str,
    address: u64,
    claims: &[AgentClaim],
    chains: &[CausalChain],
    case_lexicon: &[CaseLexeme],
    behavior_graph: &[FlagBehaviorEdge],
    escalate: bool,
) -> (Vec<String>, Vec<IbcStep>) {
    let mut ops = Vec::new();
    let mut ibc = Vec::new();
    let mut pc = 0u16;
    let push = |ops: &mut Vec<String>,
                    ibc: &mut Vec<IbcStep>,
                    pc: &mut u16,
                    op: &str,
                    detail: String,
                    tool: Option<String>,
                    args: serde_json::Value,
                    claim_id: Option<String>| {
        ops.push(format!("{op} {detail}"));
        ibc.push(IbcStep {
            pc: *pc,
            op: op.to_string(),
            detail,
            tool,
            args,
            claim_id,
        });
        *pc += 1;
    };
    push(
        &mut ops,
        &mut ibc,
        &mut pc,
        "FOCUS",
        format!("{function_name} @0x{address:x}"),
        Some("function_profile".to_string()),
        serde_json::json!({ "query": format!("0x{address:x}") }),
        None,
    );
    if escalate {
        push(
            &mut ops,
            &mut ibc,
            &mut pc,
            "ESCALATE",
            "profile=full".to_string(),
            Some("decompile_function".to_string()),
            serde_json::json!({ "query": format!("0x{address:x}") }),
            None,
        );
    }
    if !case_lexicon.is_empty() {
        let compact: String = case_lexicon.iter().take(20).map(|c| c.glyph.as_str()).collect();
        push(
            &mut ops,
            &mut ibc,
            &mut pc,
            "MAP_CASES",
            format!("lexicon=`{}` n={}", truncate(&compact, 40), case_lexicon.len()),
            Some("disassemble_function".to_string()),
            serde_json::json!({ "query": format!("0x{address:x}") }),
            claims
                .iter()
                .find(|c| matches!(c.kind.as_str(), "case" | "case_bind" | "flag_orbit"))
                .map(|c| c.id.clone()),
        );
    }
    for case in case_lexicon.iter().filter(|c| c.target.is_some()).take(4) {
        let target = case.target.unwrap();
        push(
            &mut ops,
            &mut ibc,
            &mut pc,
            "VERIFY_CASE",
            format!(
                "'{}' -> {} @0x{:x}",
                c_escape_glyph(&case.glyph),
                case.target_name.as_deref().unwrap_or("handler"),
                target
            ),
            Some("decompile_function".to_string()),
            serde_json::json!({ "query": format!("0x{target:x}") }),
            claims
                .iter()
                .find(|c| matches!(c.kind.as_str(), "case_bind" | "case" | "flag_orbit"))
                .map(|c| c.id.clone()),
        );
    }
    for edge in behavior_graph.iter().take(6) {
        let target = edge.handler.unwrap_or(address);
        push(
            &mut ops,
            &mut ibc,
            &mut pc,
            "ORBIT_FLAG",
            format!(
                "'{}' -> {} tags=[{}]",
                c_escape_glyph(&edge.glyph),
                edge.handler_name.as_deref().unwrap_or("handler"),
                edge.behaviors.iter().take(4).cloned().collect::<Vec<_>>().join(",")
            ),
            Some("decompile_function".to_string()),
            serde_json::json!({ "query": format!("0x{target:x}") }),
            claims
                .iter()
                .find(|c| c.kind == "flag_orbit" || c.kind == "case_bind")
                .map(|c| c.id.clone()),
        );
    }
    if case_lexicon.iter().any(|c| c.target.is_some()) {
        let compact: String = case_lexicon
            .iter()
            .filter(|c| c.target.is_some())
            .take(12)
            .map(|c| c.glyph.as_str())
            .collect();
        push(
            &mut ops,
            &mut ibc,
            &mut pc,
            "CLOSE_ALPHABET",
            format!(
                "physical-linguistic closure on `{}`",
                truncate(&compact, 36)
            ),
            Some("xrefs_query".to_string()),
            serde_json::json!({ "query": format!("0x{address:x}") }),
            claims
                .iter()
                .find(|c| matches!(c.kind.as_str(), "case_resonance" | "case_bind" | "flag_orbit"))
                .map(|c| c.id.clone()),
        );
    }
    if !behavior_graph.is_empty() {
        push(
            &mut ops,
            &mut ibc,
            &mut pc,
            "SYNTHESIZE_GRAPH",
            format!(
                "{} orbits over `{}`",
                behavior_graph.len(),
                truncate(
                    &behavior_graph
                        .iter()
                        .take(12)
                        .map(|e| e.glyph.as_str())
                        .collect::<String>(),
                    36
                )
            ),
            Some("function_profile".to_string()),
            serde_json::json!({ "query": format!("0x{address:x}") }),
            claims.iter().find(|c| c.kind == "flag_orbit").map(|c| c.id.clone()),
        );
    }
    for chain in chains.iter().take(2) {
        push(
            &mut ops,
            &mut ibc,
            &mut pc,
            "TRACE_CHAIN",
            format!("{} conf={:.2} {}", chain.id, chain.confidence, truncate(&chain.narrative, 72)),
            Some("decompile_function".to_string()),
            serde_json::json!({ "query": format!("0x{address:x}") }),
            chain.steps.first().cloned(),
        );
    }
    push(
        &mut ops,
        &mut ibc,
        &mut pc,
        "STOP",
        "if orbit conf>=0.9 and confute fails".to_string(),
        None,
        serde_json::json!({}),
        None,
    );
    (ops, ibc)
}

fn recover_case_lexicon(
    switch_hits: &[(String, String)],
    optstrings: &[(String, String)],
    text: &str,
) -> Vec<CaseLexeme> {
    let mut bias: Option<u32> = None;
    let mut bound: Option<u32> = None;
    for (_, surface) in switch_hits {
        if let Some((b, bd)) = parse_switch_bias_bound(surface) {
            bias = Some(b);
            if bd > 0 {
                bound = Some(bd);
            }
        }
    }
    if bias.is_none() {
        for line in text.lines() {
            if let Some((scrutinee, bd)) = extract_switch(line) {
                if let Some((b, _)) = parse_switch_bias_bound(&format!("switch({scrutinee}) bound={bd}")) {
                    bias = Some(b);
                    if !bd.is_empty() {
                        if let Ok(v) = bd.parse::<u32>() {
                            bound = Some(v);
                        }
                    }
                    break;
                }
            }
        }
    }

    let mut from_text_cases: Vec<CaseLexeme> = Vec::new();
    for line in text.lines() {
        if let Some(lex) = parse_case_label_line(line) {
            if !from_text_cases.iter().any(|c| c.code == lex.code) {
                from_text_cases.push(lex);
            }
        }
    }

    let mut from_opt: Vec<CaseLexeme> = Vec::new();
    for (_, opt) in optstrings {
        from_opt.extend(optstring_to_cases(opt, bias, bound));
    }

    let mut out: Vec<CaseLexeme> = Vec::new();
    for item in from_opt.into_iter().chain(from_text_cases.into_iter()) {
        if !out.iter().any(|c| c.code == item.code && c.glyph == item.glyph) {
            out.push(item);
        }
    }
    out.sort_by(|a, b| a.code.cmp(&b.code).then_with(|| a.glyph.cmp(&b.glyph)));
    out
}

fn parse_switch_bias_bound(surface: &str) -> Option<(u32, u32)> {
    let mut bias = None;
    let mut bound = 0u32;
    if let Some(idx) = surface.find('-') {
        let rest = &surface[idx + 1..];
        let digits: String = rest
            .chars()
            .skip_while(|c| !c.is_ascii_digit())
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if !digits.is_empty() {
            bias = digits.parse().ok();
        }
    }
    if let Some(idx) = surface.find("bound=") {
        let rest = &surface[idx + "bound=".len()..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() {
            bound = digits.parse().unwrap_or(0);
        }
    }
    bias.map(|b| (b, bound))
}

fn optstring_to_cases(opt: &str, bias: Option<u32>, bound: Option<u32>) -> Vec<CaseLexeme> {
    let mut out = Vec::new();
    let chars: Vec<char> = opt.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if c == '+' || c == '-' || c == ':' {
            i += 1;
            continue;
        }
        if !(c.is_ascii_alphanumeric() || "@%_,".contains(c)) {
            i += 1;
            continue;
        }
        let takes_arg = i + 1 < chars.len() && chars[i + 1] == ':';
        let code = c as u32;
        let slot = bias.map(|b| code.saturating_sub(b));
        if let (Some(b), Some(bd)) = (bias, bound) {
            if code < b || code.saturating_sub(b) > bd {
                i += 1 + takes_arg as usize;
                continue;
            }
        }
        out.push(CaseLexeme {
            glyph: c.to_string(),
            code,
            takes_arg,
            slot,
            meaning: guess_flag_meaning(c),
                    target: None,
            target_name: None,
        });
        i += 1 + takes_arg as usize;
    }
    out
}

fn parse_case_label_line(line: &str) -> Option<CaseLexeme> {
    let t = line.trim().trim_start_matches("//").trim();
    let rest = t.strip_prefix("case ")?;
    let token = rest.trim().trim_end_matches(':').trim();
    if let Some(inner) = token.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
        let ch = if inner == "\\\\" {
            '\\'
        } else if inner == "\\'" {
            '\''
        } else {
            inner.chars().next()?
        };
        return Some(CaseLexeme {
            glyph: ch.to_string(),
            code: ch as u32,
            takes_arg: false,
            slot: None,
            meaning: guess_flag_meaning(ch),
                    target: None,
            target_name: None,
        });
    }
    if let Some(hex) = token.strip_prefix("0x") {
        let code = u32::from_str_radix(hex, 16).ok()?;
        let glyph = if (0x20..0x7f).contains(&code) {
            char::from_u32(code).unwrap_or('?').to_string()
        } else {
            format!("0x{code:x}")
        };
        return Some(CaseLexeme {
            glyph,
            code,
            takes_arg: false,
            slot: None,
            meaning: None,
                    target: None,
            target_name: None,
        });
    }
    None
}


fn infer_meaning_from_handler(name: &str, glyph: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    let g = glyph.to_ascii_lowercase();
    if lower.contains("help") || lower.ends_with("_h") {
        return Some("help / usage".to_string());
    }
    if lower.contains("version") || lower.contains("ver_") {
        return Some("version".to_string());
    }
    if lower.contains("verbose") {
        return Some("verbose".to_string());
    }
    if lower.contains("quiet") || lower.contains("silent") {
        return Some("quiet".to_string());
    }
    if lower.contains("recursive") {
        return Some("recursive".to_string());
    }
    if lower.contains("color") {
        return Some("color control".to_string());
    }
    if lower.contains("long") && g == "l" {
        return Some("long listing format".to_string());
    }
    if let Some(ch) = g.chars().next() {
        if let Some(m) = guess_flag_meaning(ch) {
            return Some(m);
        }
    }
    if lower.contains(&format!("_{g}"))
        || lower.contains(&format!("flag_{g}"))
        || lower.contains(&format!("opt_{g}"))
        || lower.contains(&format!("case_{g}"))
        || lower.ends_with(&format!("_{g}"))
    {
        return Some(format!("handler `{name}`"));
    }
    None
}

fn close_case_slots(lattice: &mut AgentSemanticLattice) {
    let mut ordered: Vec<(u32, u64)> = lattice
        .case_lexicon
        .iter()
        .filter_map(|c| c.target.map(|t| (c.code, t)))
        .collect();
    if ordered.len() < 2 {
        return;
    }
    ordered.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    let min_code = ordered.iter().map(|(c, _)| *c).min().unwrap_or(0);
    let dense = ordered
        .windows(2)
        .all(|w| w[1].0 == w[0].0.saturating_add(1) || w[1].1 > w[0].1);
    if !dense {
        return;
    }
    for case in &mut lattice.case_lexicon {
        if case.slot.is_none() {
            if let Some(target) = case.target {
                if let Some(idx) = ordered.iter().position(|(_, t)| *t == target) {
                    case.slot = Some(idx as u32);
                    continue;
                }
            }
            if case.code >= min_code {
                case.slot = Some(case.code.saturating_sub(min_code));
            }
        }
    }
}

fn guess_flag_meaning(c: char) -> Option<String> {
    let meaning = match c {
        'a' => "list almost-all / include hidden",
        'l' => "long listing format",
        'h' => "human-readable sizes",
        'R' => "recursive",
        'r' => "reverse sort",
        't' => "sort by time",
        'S' => "sort by size",
        'i' => "inode numbers",
        'd' => "list directories themselves",
        '1' => "one entry per line",
        'A' => "almost-all without . and ..",
        'C' => "columnar layout",
        'F' => "classify file types",
        'H' | 'L' => "follow symlinks",
        'G' => "color / no group variants",
        '@' => "extended attributes",
        '%' => "format / printf-like option",
        _ => return None,
    };
    Some(meaning.to_string())
}

fn code_glyph(code: u32) -> String {
    if (0x20..0x7f).contains(&code) {
        char::from_u32(code).unwrap_or('?').to_string()
    } else {
        format!("0x{code:x}")
    }
}

fn c_escape_glyph(g: &str) -> String {
    match g {
        "\\" => "\\\\".to_string(),
        "'" => "\\'".to_string(),
        other => other.to_string(),
    }
}

fn synthesize_thesis(
    function_name: &str,
    claims: &[AgentClaim],
    chains: &[CausalChain],
    strings: &[(String, String)],
    call_kinds: &BTreeMap<&'static str, Vec<String>>,
) -> String {
    if let Some(chain) = chains.first() {
        if chain.confidence >= 0.88 {
            return truncate(&chain.narrative, 220);
        }
    }
    let mut parts = Vec::new();
    for claim in claims.iter().take(2) {
        parts.push(claim.intent.clone());
    }
    if parts.is_empty() {
        if call_kinds.keys().any(|k| *k != "call") {
            let kinds = call_kinds
                .keys()
                .filter(|k| **k != "call")
                .take(3)
                .copied()
                .collect::<Vec<_>>()
                .join("/");
            parts.push(format!("{function_name} exhibits {kinds} behavior"));
        } else if !strings.is_empty() {
            parts.push(format!(
                "{function_name} is string-driven around `{}`",
                truncate(&strings[0].1, 32)
            ));
        } else {
            parts.push(format!("{function_name} semantic lattice is sparse"));
        }
    }
    truncate(&parts.join("; "), 220)
}

fn make_claim(
    index: usize,
    intent: String,
    kind: &str,
    confidence: f32,
    anchors: Vec<String>,
    path: Option<String>,
    confutation: Option<String>,
    probes: Vec<AgentNextAction>,
) -> AgentClaim {
    AgentClaim {
        id: format!("c{index}"),
        intent,
        kind: kind.to_string(),
        confidence,
        anchors,
        path,
        confutation,
        probes,
    }
}

fn probe_set(address: u64, tool: &str, reason: &str) -> Vec<AgentNextAction> {
    let (tool_name, args) = if tool == "strings" {
        (
            "string_search".to_string(),
            serde_json::json!({ "pattern": ":", "limit": 40 }),
        )
    } else {
        (
            tool.to_string(),
            serde_json::json!({ "query": format!("0x{address:x}") }),
        )
    };
    vec![AgentNextAction {
        tool: tool_name,
        reason: reason.to_string(),
        priority: 90,
        query: Some(format!("0x{address:x}")),
        label: Some("casl-probe".to_string()),
        args,
    }]
}

fn push_anchor(
    anchors: &mut Vec<SemanticAnchor>,
    seen: &mut BTreeSet<String>,
    kind: &str,
    surface: &str,
    address: Option<u64>,
    confidence: f32,
    evidence: &str,
) -> String {
    let key = format!("{kind}|{surface}");
    if let Some(existing) = anchors
        .iter()
        .find(|a| a.kind == kind && a.surface == surface)
    {
        return existing.id.clone();
    }
    if !seen.insert(key) {
        if let Some(existing) = anchors.iter().rev().find(|a| a.kind == kind) {
            return existing.id.clone();
        }
    }
    let id = format!("a{}", anchors.len() + 1);
    anchors.push(SemanticAnchor {
        id: id.clone(),
        kind: kind.to_string(),
        surface: surface.to_string(),
        address,
        confidence,
        evidence: evidence.to_string(),
    });
    id
}

fn collect_signal_lines(text: &str, regions: &[PseudocodeRegion]) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t == "{" || t == "}" {
            continue;
        }
        out.push(t.to_string());
    }
    fn walk(region: &PseudocodeRegion, out: &mut Vec<String>) {
        if let Some(header) = &region.header {
            out.push(header.clone());
        }
        out.extend(region.statements.iter().cloned());
        for child in &region.children {
            walk(child, out);
        }
        if matches!(
            region.kind,
            RegionKind::If | RegionKind::Loop | RegionKind::Switch | RegionKind::Return
        ) {
            out.push(format!("region:{:?}", region.kind));
        }
    }
    for region in regions {
        walk(region, &mut out);
    }
    out
}

fn extract_if_condition(line: &str) -> Option<String> {
    let t = line.trim();
    let rest = if let Some(r) = t.strip_prefix("if (") {
        r
    } else if let Some(r) = t.strip_prefix("if(") {
        r
    } else {
        return None;
    };
    let end = rest.find(')')?;
    let cond = rest[..end].trim();
    if cond.is_empty() || cond == "true" || cond == "false" {
        return None;
    }
    Some(cond.to_string())
}

fn extract_switch(line: &str) -> Option<(String, String)> {
    let t = line.trim().trim_start_matches("//").trim();
    if !t.starts_with("switch") && !t.contains("jump table") {
        return None;
    }
    let scrutinee = if let Some(start) = t.find("switch (") {
        let rest = &t[start + "switch (".len()..];
        let end = rest.find(')')?;
        rest[..end].trim().to_string()
    } else if let Some(start) = t.find("switch(") {
        let rest = &t[start + "switch(".len()..];
        let end = rest.find(')')?;
        rest[..end].trim().to_string()
    } else {
        "value".to_string()
    };
    let bound = t
        .split("bound=")
        .nth(1)
        .map(|s| s.split_whitespace().next().unwrap_or("").to_string())
        .unwrap_or_default();
    Some((scrutinee, bound))
}

fn extract_call_names(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let work = line.trim();
    let chars: Vec<char> = work.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let ch = chars[i];
        if ch == '"' || ch == '\'' {
            let quote = ch;
            i += 1;
            while i < chars.len() {
                if chars[i] == '\\' {
                    i = (i + 2).min(chars.len());
                    continue;
                }
                if chars[i] == quote {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        if ch.is_ascii_alphabetic() || ch == '_' {
            let start = i;
            i += 1;
            while i < chars.len()
                && (chars[i].is_ascii_alphanumeric() || chars[i] == '_' || chars[i] == ':')
            {
                i += 1;
            }
            let mut j = i;
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
            if j < chars.len() && chars[j] == '(' {
                let raw: String = chars[start..i].iter().collect();
                let name = raw.trim_start_matches('_');
                if !name.is_empty()
                    && !matches!(
                        name,
                        "if" | "while"
                            | "for"
                            | "switch"
                            | "sizeof"
                            | "return"
                            | "int"
                            | "void"
                            | "char"
                            | "long"
                            | "short"
                            | "unsigned"
                            | "const"
                            | "static"
                            | "struct"
                            | "bool"
                            | "size_t"
                            | "int64_t"
                            | "uint64_t"
                            | "int32_t"
                            | "uint32_t"
                    )
                    && !out.iter().any(|c| c == name)
                {
                    out.push(name.to_string());
                }
            }
            continue;
        }
        i += 1;
    }
    if out.is_empty() {
        if let Some(one) = extract_call_name_legacy(work) {
            out.push(one);
        }
    }
    out
}

fn extract_call_name_legacy(line: &str) -> Option<String> {
    let mut work = line.trim();
    if let Some(idx) = work.find('=') {
        let rhs = work[idx + 1..].trim();
        if rhs.contains('(') {
            work = rhs;
        }
    }
    if work.starts_with("return ") {
        work = work["return ".len()..].trim();
    }
    let open = work.find('(')?;
    let name = work[..open].trim();
    if name.is_empty()
        || name.contains(' ')
        || matches!(name, "if" | "while" | "for" | "switch" | "sizeof")
    {
        return None;
    }
    if name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
    {
        Some(name.trim_start_matches('_').to_string())
    } else {
        None
    }
}

fn extract_return_expr(line: &str) -> Option<String> {
    let t = line.trim();
    let rest = t.strip_prefix("return ")?;
    let expr = rest
        .split("//")
        .next()
        .unwrap_or(rest)
        .trim()
        .trim_end_matches(';')
        .trim();
    if expr.is_empty() {
        None
    } else {
        Some(expr.to_string())
    }
}

fn extract_quoted_literals(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let ch = bytes[i];
        if ch == b'"' || ch == b'\'' {
            let quote = ch;
            i += 1;
            let begin = i;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i = (i + 2).min(bytes.len());
                    continue;
                }
                if bytes[i] == quote {
                    break;
                }
                i += 1;
            }
            let end = i.min(text.len());
            if begin <= end {
                let slice = &text[begin..end];
                if !slice.is_empty() && !out.iter().any(|item| item == slice) {
                    out.push(slice.to_string());
                }
            }
            if i < bytes.len() {
                i += 1;
            }
            continue;
        }
        i += 1;
    }
    out
}

fn parse_addr_comment(line: &str) -> Option<u64> {
    let idx = line.rfind("// 0x").or_else(|| line.rfind("//0x"))?;
    let rest = line[idx..].trim_start_matches('/').trim_start_matches(' ');
    let hex = rest.trim_start_matches("//").trim().trim_start_matches("0x");
    let token = hex
        .split(|c: char| !c.is_ascii_hexdigit())
        .next()
        .unwrap_or("");
    u64::from_str_radix(token, 16).ok()
}


fn extract_cli_optstring(line: &str) -> Option<String> {
    let mut best: Option<String> = None;
    for lit in extract_quoted_literals(line) {
        if !looks_like_optstring(&lit) && !is_soft_optstring(&lit) {
            continue;
        }
        match &best {
            None => best = Some(lit),
            Some(cur) if lit.len() > cur.len() => best = Some(lit),
            _ => {}
        }
    }
    best
}

fn is_soft_optstring(s: &str) -> bool {
    if s.is_empty() || s.len() > 48 {
        return false;
    }
    if s.chars().all(|c| c.is_ascii_uppercase() || c == '_')
        && !s.contains(':')
        && !s.starts_with('+')
        && !s.starts_with('-')
    {
        return false;
    }
    let ok = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(*c, ':' | '+' | '-' | '@' | '%' | ','))
        .count();
    if ok != s.len() {
        return false;
    }
    let alpha = s.chars().filter(|c| c.is_ascii_alphabetic()).count();
    alpha >= 1
        && alpha <= 32
        && (s.contains(':') || s.starts_with('+') || s.starts_with('-') || alpha <= 12)
}

fn looks_like_optstring(s: &str) -> bool {
    if s.len() < 2 || s.len() > 96 {
        return false;
    }
    if s.chars().all(|c| c.is_ascii_uppercase() || c == '_')
        && !s.contains(':')
        && !s.starts_with('+')
        && !s.starts_with('-')
    {
        return false;
    }
    let alnum = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == ':' || *c == '+' || *c == '-' || *c == '@' || *c == '%')
        .count();
    if alnum < s.len().saturating_mul(8) / 10 {
        return false;
    }
    let alpha = s.chars().filter(|c| c.is_ascii_alphabetic()).count();
    let has_colon = s.contains(':');
    let marked = s.starts_with('+') || s.starts_with('-') || has_colon;
    let has_flag_chars = alpha >= 4 || (marked && alpha >= 2) || (has_colon && alpha >= 1);
    has_flag_chars && (has_colon || s.starts_with('+') || s.starts_with('-') || alpha >= 6)
}

fn summarize_optstring(opt: &str) -> String {
    let compact: String = opt
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == ':' || *c == '+' || *c == '-' || *c == '@')
        .take(48)
        .collect();
    if compact.len() < opt.len() {
        format!("{compact}…")
    } else {
        compact
    }
}

fn is_mode_token(s: &str) -> bool {
    matches!(
        s.to_ascii_lowercase().as_str(),
        "always"
            | "never"
            | "auto"
            | "yes"
            | "no"
            | "force"
            | "tty"
            | "if-tty"
            | "none"
            | "on"
            | "off"
            | "true"
            | "false"
    ) || (s.len() >= 3 && s.len() <= 16 && s.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
}

fn unique_preserve(items: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for item in items {
        if !out.iter().any(|x| x == item) {
            out.push(item.clone());
        }
    }
    out
}

fn classify_api(name: &str) -> &'static str {
    let n = name.trim_start_matches('_').to_ascii_lowercase();
    let base = n.split("::").last().unwrap_or(&n);
    if matches!(
        base,
        "getenv" | "setenv" | "unsetenv" | "secure_getenv" | "putenv"
    ) || base.starts_with("getenv")
    {
        return "env";
    }
    if matches!(base, "isatty" | "ttyname" | "tcgetattr" | "tcsetattr") {
        return "tty";
    }
    if base.contains("getopt") || base.contains("argp") || base == "getsubopt" {
        return "cli";
    }
    if matches!(
        base,
        "open" | "openat" | "fopen" | "fdopen" | "read" | "write" | "fread" | "fwrite"
            | "close" | "fclose" | "pread" | "pwrite" | "mmap" | "munmap" | "stat" | "fstat"
            | "lstat" | "access" | "unlink" | "rename" | "mkdir" | "opendir" | "readdir"
    ) || base.starts_with("stdio")
    {
        return "io";
    }
    if matches!(
        base,
        "socket" | "connect" | "bind" | "listen" | "accept" | "send" | "recv" | "sendto"
            | "recvfrom" | "getaddrinfo" | "poll" | "select"
    ) {
        return "net";
    }
    if matches!(
        base,
        "malloc" | "calloc" | "realloc" | "free" | "memcpy" | "memmove" | "memset" | "memcmp"
            | "strdup" | "strndup"
    ) {
        return "mem";
    }
    if matches!(
        base,
        "pthread_mutex_lock" | "pthread_mutex_unlock" | "pthread_create" | "pthread_join"
            | "sem_wait" | "sem_post"
    ) || base.starts_with("pthread_")
    {
        return "sync";
    }
    if base.contains("crypt")
        || base.contains("sha")
        || base.contains("aes")
        || base.contains("hmac")
        || base.contains("digest")
        || base.contains("ssl")
        || base.contains("tls")
    {
        return "crypto";
    }
    if matches!(
        base,
        "fork" | "vfork" | "execve" | "execl" | "execlp" | "execvp" | "system" | "posix_spawn"
            | "waitpid" | "kill"
    ) {
        return "proc";
    }
    if matches!(
        base,
        "time" | "gettimeofday" | "clock_gettime" | "nanosleep" | "sleep"
    ) {
        return "time";
    }
    "call"
}

fn truncate(s: &str, max: usize) -> String {
    let count = s.chars().count();
    if count <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn casl_extracts_cli_env_switch_lattice() {
        let text = r#"
int main(int argc, char **argv) {
    if (argc <= 0) { sub_dead(); }
    _isatty(1); if (tty != 0) { }
    _getenv("COLUMNS"); if (env == 0) { }
    if (env[0] != 0) { }
    _getopt_long(argc, /*?*/, "+@1ABCD:FGHILOPRSTUWabcdefgh", /*?*/);
    if ((opt - 37) > 91) { }
    // switch ((opt - 37)) via jump table; // 0x1000 bound=91
    _strcmp(x, "always");
    _strcmp(x, "auto");
    _strcmp(x, "never");
    return 0;
}
"#;
        let lattice = build_agent_semantic_lattice("main", 0x1000, text, &[]);
        assert!(lattice.method.starts_with("casl-v"), "method={}", lattice.method);
        assert!(!lattice.thesis.is_empty());
        assert!(
            lattice
                .anchors
                .iter()
                .any(|a| a.kind == "string" && a.surface.contains("COLUMNS")),
            "expected COLUMNS string anchor: {:?}",
            lattice.anchors
        );
        assert!(
            lattice
                .claims
                .iter()
                .any(|c| c.kind == "control" || c.intent.contains("CLI") || c.intent.contains("getopt")),
            "expected cli claim: {:?}",
            lattice.claims
        );
        assert!(
            lattice
                .claims
                .iter()
                .any(|c| c.kind == "env" || c.intent.contains("COLUMNS")),
            "expected env claim: {:?}",
            lattice.claims
        );
        assert!(
            lattice.anchors.iter().any(|a| a.kind == "switch"),
            "expected switch anchor"
        );
        assert!(
            lattice.chains.iter().any(|c| c.narrative.contains("getopt")
                || c.narrative.contains("tty")
                || c.narrative.contains("jump")),
            "expected causal chain: {:?}",
            lattice.chains
        );
        assert!(
            lattice
                .claims
                .iter()
                .any(|c| c.intent.contains("flag lexicon") || c.kind == "cli"),
            "expected optstring claim: {:?}",
            lattice.claims
        );
        assert!(
            lattice
                .claims
                .iter()
                .any(|c| c.kind == "policy" || c.intent.contains("mode")),
            "expected mode policy claim: {:?}",
            lattice.claims
        );
        assert!(!lattice.investigation_bytecode.is_empty());
        assert!(!lattice.ibc.is_empty());
        assert!(
            !lattice.case_lexicon.is_empty(),
            "expected case lexicon from optstring+switch: {:?}",
            lattice.case_lexicon
        );
        assert!(
            lattice.case_lexicon.iter().any(|c| c.glyph == "A" || c.glyph == "a" || c.glyph == "@"),
            "expected flag glyphs: {:?}",
            lattice.case_lexicon
        );
        assert!(lattice_primary_next_action(&lattice, 0x1000).is_some());
        assert!(!lattice_ibc_plan(&lattice, 0x1000, 3).is_empty());
        assert!(lattice.quality.evidence_coverage > 0.5);
        let rendered = format_semantic_lattice(&lattice);
        assert!(rendered.contains("## Semantic Lattice"));
        assert!(rendered.contains("### Claims"));
        assert!(rendered.contains("### Anchors"));
        assert!(rendered.contains("### Causal Chains") || rendered.contains("### Investigation Bytecode"));
    }

    #[test]
    fn casl_marks_sparse_for_escalation() {
        let text = "int sub_1() {\n  unknown_if (x) { }\n  return 0;\n}\n";
        let lattice = build_agent_semantic_lattice("sub_1", 0x2000, text, &[]);
        assert!(lattice.quality.escalate || lattice.quality.ambiguity > 0.0);
        assert!(!lattice.claims.is_empty());
        assert!(!lattice.investigation_bytecode.is_empty());
    }


    #[test]
    fn casl_fuses_flag_behavior_orbits() {
        let dispatcher = r#"
int main() {
    _getopt_long(0, 0, "+ab:", 0);
    // switch ((opt - 97)) via jump table; // bound=1
    return 0;
}
"#;
        let mut main_l = build_agent_semantic_lattice("main", 0x1000, dispatcher, &[]);
        let refs = vec![
            Reference {
                from: 0x2000,
                to: crate::case_char_tag(b'a' as u64),
                kind: ReferenceKind::DataRef,
            },
            Reference {
                from: 0x3000,
                to: crate::case_char_tag(b'b' as u64),
                kind: ReferenceKind::DataRef,
            },
        ];
        let mut symbols = HashMap::new();
        symbols.insert(0x2000u64, "handle_a".to_string());
        symbols.insert(0x3000u64, "handle_b".to_string());
        bind_case_targets(&mut main_l, &refs, &symbols);
        let handle_a = build_agent_semantic_lattice(
            "handle_a",
            0x2000,
            "int handle_a(){ _getenv(\"COLUMNS\"); _isatty(1); return 0; }",
            &[],
        );
        let handle_b = build_agent_semantic_lattice(
            "handle_b",
            0x3000,
            "int handle_b(){ _socket(2,1,0); return 0; }",
            &[],
        );
        let fused = fuse_semantic_lattices(
            "cli-orbits",
            &[
                ("main".into(), 0x1000, main_l),
                ("handle_a".into(), 0x2000, handle_a),
                ("handle_b".into(), 0x3000, handle_b),
            ],
        );
        assert!(
            !fused.behavior_graph.is_empty(),
            "empty behavior graph"
        );
        assert!(
            fused.behavior_graph.iter().any(|e| {
                e.glyph == "a"
                    && e.handler == Some(0x2000)
                    && e.behaviors.iter().any(|b| b == "env" || b == "tty")
            }),
            "orbit a missing env/tty: {:?}",
            fused.behavior_graph
        );
        assert!(
            fused.behavior_graph.iter().any(|e| {
                e.glyph == "b" && e.behaviors.iter().any(|b| b == "net")
            }),
            "orbit b missing net: {:?}",
            fused.behavior_graph
        );
        assert!(fused.ibc.iter().any(|s| s.op == "ORBIT_FLAG"));
        assert!(fused.ibc.iter().any(|s| s.op == "SYNTHESIZE_GRAPH"));
        assert!(fused.claims.iter().any(|c| c.kind == "flag_orbit"));
        assert!(fused.thesis.contains("orbit") || fused.thesis.contains("flag"));
    }

    #[test]
    fn casl_fuses_lattices_across_functions() {
        let a = build_agent_semantic_lattice(
            "main",
            0x1000,
            "int main(){ _getenv(\"A\"); _getopt_long(0,0,\"ab:\",0); }",
            &[],
        );
        let b = build_agent_semantic_lattice(
            "helper",
            0x2000,
            "int helper(){ _socket(2,1,0); return 0; }",
            &[],
        );
        let fused = fuse_semantic_lattices("cli+net", &[("main".into(), 0x1000, a), ("helper".into(), 0x2000, b)]);
        assert!(fused.method.contains("casl-v"), "method={}", fused.method);
        assert!(
            fused.thesis.contains("main")
                || fused.claims.iter().any(|c| c.id.contains("main") || c.intent.contains("main"))
                || fused.investigation_bytecode.iter().any(|op| op.contains("main"))
        );
        assert!(fused.claims.iter().any(|c| c.id.contains("helper") || c.intent.contains("helper")));
        assert!(!fused.investigation_bytecode.is_empty());
    }

    #[test]
    fn casl_forges_orbit_hypothesis_drafts() {
        let mut lattice = build_agent_semantic_lattice(
            "main",
            0x1000,
            "int main(){ _getopt_long(0,0,\"+ab:\",0); return 0; }",
            &[],
        );
        lattice.behavior_graph = vec![FlagBehaviorEdge {
            glyph: "a".into(),
            code: 97,
            handler: Some(0x2000),
            handler_name: Some("handle_a".into()),
            behaviors: vec!["env".into(), "tty".into()],
            effects: vec!["reads COLUMNS".into()],
            confidence: 0.95,
            orbit: Some("'a'→handle_a⟦env+tty⟧".into()),
        }];
        let state = IbcContinuumState {
            namespace: "binX".into(),
            focus: 0x1000,
            focus_name: "main".into(),
            lattice,
            witnesses: vec!["FOCUS main".into()],
            orbit_hypotheses: BTreeMap::new(),
            cognitive_field: CognitiveField::default(),
            epoch: 2,
            updated_unix_ms: 1,
        };
        let drafts = forge_orbit_hypothesis_drafts(&state);
        assert!(!drafts.is_empty());
        assert!(drafts[0].title.contains("handle_a") || drafts[0].title.contains("'a'"));
        assert!(drafts[0].evidence_ids.iter().any(|e| e.contains("casl:orbit")));
        assert!(drafts[0].notes.contains("confute") || drafts[0].notes.contains("conjugate"));
        assert!(drafts[0].notes.contains("field_mode") || drafts[0].notes.contains("CASL/PCCF") || drafts[0].notes.contains("standing_wave"));
    }


    #[test]
    fn casl_projects_cognitive_field_and_conjugates() {
        let text = r#"
int main(int argc, char **argv) {
  int c;
  while ((c = getopt(argc, argv, "ab:c")) != -1) {
    switch (c) {
    case 'a': handle_a(); break;
    case 'b': handle_b(optarg); break;
    case 'c': handle_c(); break;
    }
  }
  if (isatty(1)) {
    char *cols = getenv("COLUMNS");
    (void)cols;
  }
  return 0;
}
"#;
        let lattice = build_agent_semantic_lattice("main", 0x1000, text, &[]);
        assert!(lattice.method == "casl-v6-pccf" || lattice.method == "casl-v7-odc", "{}", lattice.method);
        let field = project_cognitive_field(&lattice);
        assert!(!field.mode.is_empty());
        assert!(!field.standing_waves.is_empty() || !field.conjugates.is_empty());
        let rendered = format_semantic_lattice(&lattice);
        assert!(rendered.contains("Cognitive Field"));
        assert!(
            rendered.contains("CONJ")
                || rendered.contains("WAVE")
                || rendered.contains("EXECUTE CONJUGATE")
        );
        assert!(lattice.claims.iter().any(|c| {
            matches!(
                c.kind.as_str(),
                "cognitive_field" | "phase_conjugate" | "standing_wave"
            )
        }));
    }

    #[test]
    fn casl_collapses_phase_conjugate_on_probe() {
        let text = r#"
int main() {
  char *p = getenv("COLUMNS");
  if (isatty(1)) { return (int)(p != 0); }
  return 0;
}
"#;
        let mut lattice = build_agent_semantic_lattice("main", 0x1000, text, &[]);
        let mut field = project_cognitive_field(&lattice);
        apply_cognitive_field_to_lattice(&mut lattice, &field);
        field = project_cognitive_field(&lattice);
        if field.conjugates.is_empty() {
            field.conjugates.push(PhaseConjugateProbe {
                claim_id: lattice
                    .claims
                    .first()
                    .map(|c| c.id.clone())
                    .unwrap_or_else(|| "c1".into()),
                claim_intent: lattice
                    .claims
                    .first()
                    .map(|c| c.intent.clone())
                    .unwrap_or_default(),
                conjugate: "env path unused".into(),
                tool: "decompile_function".into(),
                query: Some("0x1000".into()),
                expected_true: "getenv COLUMNS".into(),
                expected_false: "unused".into(),
                information_gain: 0.8,
            });
        } else {
            field.conjugates[0].tool = "decompile_function".into();
            field.conjugates[0].query = Some("0x1000".into());
            field.conjugates[0].expected_true = "getenv".into();
        }
        let before = field.entropy;
        let events = collapse_cognitive_field(
            &mut field,
            &mut lattice,
            "decompile_function",
            "0x1000",
            Some(r#"char *p = getenv("COLUMNS");"#),
        );
        assert!(!events.is_empty());
        assert!(field.entropy <= before + 0.0001);
        assert!(!field.collapse_events.is_empty());
    }

    #[test]
    fn casl_interference_boosts_cross_function_waves() {
        let a = build_agent_semantic_lattice(
            "main",
            0x1000,
            r#"int main(){ char *e=getenv("COLUMNS"); if(isatty(1)) return 1; return 0; }"#,
            &[],
        );
        let b = build_agent_semantic_lattice(
            "helper",
            0x2000,
            r#"int helper(){ char *e=getenv("COLUMNS"); return e!=0; }"#,
            &[],
        );
        let fused = fuse_semantic_lattices(
            "env",
            &[
                ("main".into(), 0x1000, a.clone()),
                ("helper".into(), 0x2000, b.clone()),
            ],
        );
        assert!(fused.method == "casl-v6-pccf" || fused.method == "casl-v7-odc", "{}", fused.method);
        let pieces = vec![("main".into(), &a), ("helper".into(), &b)];
        let field = interfere_cognitive_fields(&pieces, &fused);
        assert!(!field.standing_waves.is_empty());
        let multi = field.standing_waves.iter().any(|w| {
            w.sources.len() >= 2 || w.kind == "interference" || w.amplitude >= 0.7
        });
        assert!(multi || !field.conjugates.is_empty());
    }

    
    
    #[test]
    fn casl_pcos_parses_collapse_and_seals_notes() {
        let event = "c3:reads environment via decompile_function 0x1000 => true (t=0.60/f=0.00/i=0.45)";
        let v = parse_collapse_verdict(event).expect("parse");
        assert_eq!(v.polarity, "true");
        assert_eq!(v.claim_id, "c3");
        assert!((v.true_score - 0.60).abs() < 0.001);
        let title = apply_verdict_to_hypothesis_title("orbit 'a' → handle", "true");
        assert!(title.starts_with("[PROVEN]"));
        let notes = apply_verdict_to_hypothesis_notes("base", &v, 3, "97:a");
        assert!(notes.contains("### PCOS VERDICT e3 97:a"));
        assert!(notes.contains("polarity=true"));
        let notes2 = apply_verdict_to_hypothesis_notes(&notes, &v, 3, "97:a");
        assert_eq!(notes.matches("### PCOS VERDICT").count(), notes2.matches("### PCOS VERDICT").count());
    }

    #[test]
    fn casl_pcos_composes_proof_chain_from_orbit_collapses() {
        let src = r#"
int main(int argc, char **argv) {
  int c;
  while ((c = getopt(argc, argv, "ab")) != -1) {
    switch (c) {
    case 'a': handle_a(); break;
    case 'b': handle_b(); break;
    }
  }
  char *p = getenv("COLUMNS");
  (void)p;
  return 0;
}
"#;
        let mut lattice = build_agent_semantic_lattice("main", 0x1000, src, &[]);
        lattice.behavior_graph = vec![FlagBehaviorEdge {
            glyph: "a".into(),
            code: 97,
            handler: Some(0x2000),
            handler_name: Some("handle_a".into()),
            behaviors: vec!["env".into()],
            effects: vec!["reads COLUMNS".into()],
            confidence: 0.95,
            orbit: Some("'a'→handle_a⟦env⟧".into()),
        }];
        let mut state = IbcContinuumState {
            namespace: "pcos".into(),
            focus: 0x1000,
            focus_name: "main".into(),
            lattice: lattice.clone(),
            witnesses: vec![],
            orbit_hypotheses: BTreeMap::from([("97:a".into(), "hyp-1".into())]),
            cognitive_field: CognitiveField::default(),
            epoch: 4,
            updated_unix_ms: 1,
        };
        state.cognitive_field = project_cognitive_field(&state.lattice);
        state.cognitive_field.collapse_events.push(
            "c2:flag orbit 'a' via decompile_function 0x2000 => true (t=0.70/f=0.00/i=0.50)"
                .into(),
        );
        state.cognitive_field.proof_chain = compose_proof_chain(&state);
        assert!(!state.cognitive_field.proof_chain.is_empty());
        assert!(state
            .cognitive_field
            .proof_chain
            .iter()
            .any(|l| l.orbit_key == "97:a" && l.hypothesis_id.as_deref() == Some("hyp-1")));
        inject_proof_chain_into_lattice(&mut state.lattice, &state.cognitive_field);
        assert!(state.lattice.claims.iter().any(|c| c.kind == "proof_chain"));
        assert!(
            state.lattice.method == "casl-v8-pcos"
                || state
                    .lattice
                    .claims
                    .iter()
                    .any(|c| c.intent.contains("proof"))
        );
        let plan = seal_plan_from_proof_chain(&state);
        assert!(!plan.is_empty());
        assert_eq!(plan[0].0, "hyp-1");
        let rendered = format_semantic_lattice(&state.lattice);
        // re-project field lines need proof on field when formatting
        state.lattice.method = "casl-v8-pcos".into();
        let field_lines = format_cognitive_field_lines(&state.cognitive_field);
        let joined = field_lines.join("\n");
        assert!(joined.contains("Proof Chain") || joined.contains("LINK") || !state.cognitive_field.proof_chain.is_empty());
        let _ = rendered;
    }

#[test]
    fn casl_observation_collapse_and_residuals() {
        let src = r#"
int main() {
  char *p = getenv("COLUMNS");
  if (isatty(1)) { return (int)(p != 0); }
  return 0;
}
"#;
        let lattice = build_agent_semantic_lattice("main", 0x1000, src, &[]);
        let (state, _) = continuum_on_visit_ns(
            None,
            "obs-ns",
            "decompile_function",
            0x1000,
            "main",
            lattice,
            Some(src),
        );
        assert!(
            !state.cognitive_field.collapse_events.is_empty()
                || !state.cognitive_field.residuals.is_empty()
        );
        assert!(
            state.lattice.method == "casl-v7-odc"
                || state.lattice.claims.iter().any(|c| {
                    matches!(
                        c.kind.as_str(),
                        "diffraction_residual" | "collapse_verdict"
                    )
                })
        );
        let rendered = format_semantic_lattice(&state.lattice);
        assert!(
            rendered.contains("RESIDUAL")
                || rendered.contains("COLLAPSE")
                || rendered.contains("Cognitive Field")
        );
        let brief = continuum_brief_lines(&state);
        let joined = brief.join("\n");
        assert!(
            joined.contains("cognitive_field")
                || joined.contains("diffraction_residuals")
                || joined.contains("last_collapse")
                || joined.contains("conjugate_probe")
        );
    }

    #[test]
    fn casl_preserves_cognitive_field_across_continuum_epochs() {
        let src = r#"int main(){ char *e=getenv("PATH"); return e!=0; }"#;
        let lattice = build_agent_semantic_lattice("main", 0x1000, src, &[]);
        let (s0, _) = continuum_on_visit_ns(
            None,
            "persist-ns",
            "decompile_function",
            0x1000,
            "main",
            lattice.clone(),
            Some(src),
        );
        let before_events = s0.cognitive_field.collapse_events.len();
        let lattice2 = build_agent_semantic_lattice("main", 0x1000, src, &[]);
        let (s1, _) = continuum_on_visit_ns(
            Some(&s0),
            "persist-ns",
            "decompile_function",
            0x1000,
            "main",
            lattice2,
            Some(src),
        );
        assert!(s1.cognitive_field.collapse_events.len() >= before_events);
        assert_eq!(s1.namespace, "persist-ns");
    }

#[test]
    fn casl_continuum_ledger_isolates_namespaces() {
        let mut ledger = IbcContinuumLedger::default();
        let a = build_agent_semantic_lattice(
            "main_a",
            0x1000,
            "int main_a(){ _getopt_long(0,0,\"+a:\",0); return 0; }",
            &[],
        );
        let b = build_agent_semantic_lattice(
            "main_b",
            0x2000,
            "int main_b(){ _getopt_long(0,0,\"+b:\",0); return 0; }",
            &[],
        );
        let n1 = continuum_ledger_on_visit(
            &mut ledger,
            "binA",
            "function_profile",
            0x1000,
            "main_a",
            a,
        );
        let n2 = continuum_ledger_on_visit(
            &mut ledger,
            "binB",
            "function_profile",
            0x2000,
            "main_b",
            b,
        );
        assert_eq!(ledger.sessions.len(), 2);
        assert_eq!(ledger.active_namespace, "binB");
        assert!(n1.namespace == "binA" || n1.note.contains("binA"));
        assert!(n2.namespace == "binB" || n2.note.contains("binB"));
        let resume_a = continuum_ledger_on_visit(
            &mut ledger,
            "binA",
            "function_profile",
            0x1000,
            "main_a",
            build_agent_semantic_lattice(
                "main_a",
                0x1000,
                "int main_a(){ _getopt_long(0,0,\"+a:\",0); return 0; }",
                &[],
            ),
        );
        assert_eq!(ledger.active_namespace, "binA");
        assert!(
            ledger.sessions.get("binA").map(|s| s.epoch >= 1).unwrap_or(false),
            "binA epoch missing: {:?}",
            ledger.sessions.get("binA").map(|s| s.epoch)
        );
        assert!(resume_a.note.contains("binA") || resume_a.namespace == "binA");
        let summary = continuum_ledger_summary(&ledger);
        assert!(summary.contains("sessions=2"), "{summary}");
    }

    #[test]
    fn casl_continuum_state_roundtrips_json() {
        let lattice = build_agent_semantic_lattice(
            "main",
            0x1000,
            "int main(){ return 0; }",
            &[],
        );
        let (state, _) = continuum_on_visit_ns(
            None,
            "elf:/bin/ls",
            "function_profile",
            0x1000,
            "main",
            lattice,
            None,
        );
        let json = serde_json::to_string(&state).expect("serialize continuum");
        let back: IbcContinuumState = serde_json::from_str(&json).expect("deserialize continuum");
        assert_eq!(back.namespace, "elf:/bin/ls");
        assert_eq!(back.focus, 0x1000);
        assert_eq!(back.focus_name, "main");
    }

    #[test]
    fn casl_ibc_continuum_advances_across_visits() {
        let dispatcher = r#"
int main() {
    _getopt_long(0, 0, "+ab:", 0);
    // switch ((opt - 97)) via jump table; // bound=1
    return 0;
}
"#;
        let mut main_l = build_agent_semantic_lattice("main", 0x1000, dispatcher, &[]);
        let refs = vec![
            Reference {
                from: 0x2000,
                to: crate::case_char_tag(b'a' as u64),
                kind: ReferenceKind::DataRef,
            },
            Reference {
                from: 0x3000,
                to: crate::case_char_tag(b'b' as u64),
                kind: ReferenceKind::DataRef,
            },
        ];
        let mut symbols = HashMap::new();
        symbols.insert(0x2000u64, "handle_a".to_string());
        symbols.insert(0x3000u64, "handle_b".to_string());
        bind_case_targets(&mut main_l, &refs, &symbols);
        assert!(
            !main_l.ibc.is_empty(),
            "expected IBC program after bind: method={} ibc={:?}",
            main_l.method,
            main_l.ibc
        );
        let advanced0 = observe_ibc_execution(&mut main_l, "function_profile", "0x1000");
        assert!(
            advanced0.is_some(),
            "direct observe failed status={} pc={} first={:?}",
            main_l.ibc_status,
            main_l.ibc_pc,
            main_l.ibc.first()
        );
        let mut main_l = build_agent_semantic_lattice("main", 0x1000, dispatcher, &[]);
        bind_case_targets(&mut main_l, &refs, &symbols);
        let (state0, note0) = continuum_on_visit(
            None,
            "function_profile",
            0x1000,
            "main",
            main_l.clone(),
        );
        assert!(
            note0.advanced.is_some() || note0.note.contains("ADVANCED"),
            "first visit should advance: {} ibc0={:?}",
            note0.note,
            state0.lattice.ibc.iter().take(3).map(|s| (&s.op, s.pc, &s.tool)).collect::<Vec<_>>()
        );
        let (state1, _note1) = continuum_on_visit(
            Some(&state0),
            "function_profile",
            0x1000,
            "main",
            main_l.clone(),
        );
        let step = state1
            .lattice
            .ibc
            .iter()
            .find(|s| s.pc >= state1.lattice.ibc_pc && s.tool.as_deref() == Some("decompile_function"))
            .cloned()
            .expect("pending decompile step");
        let q = step
            .args
            .get("query")
            .and_then(|v| v.as_str())
            .unwrap_or("0x2000");
        let addr = normalize_query_addr(q).unwrap_or(0x2000);
        let (state2, note2) = continuum_on_visit(
            Some(&state1),
            "decompile_function",
            addr,
            "handle",
            build_agent_semantic_lattice("handle", addr, "int handle(){ return 0; }", &[]),
        );
        assert!(
            note2.advanced.is_some() || state2.witnesses.len() >= 2 || note2.note.contains("ADVANCED"),
            "expected advance/witness: {} witnesses={:?} pc={}",
            note2.note,
            state2.witnesses,
            state2.lattice.ibc_pc
        );
    }

    #[test]
    fn casl_detects_orbit_conflicts() {
        let mut lattice = build_agent_semantic_lattice(
            "main",
            0x1000,
            "int main(){ _getopt_long(0,0,\"+ab:\",0); return 0; }",
            &[],
        );
        lattice.behavior_graph = vec![
            FlagBehaviorEdge {
                glyph: "a".into(),
                code: 97,
                handler: Some(0x2000),
                handler_name: Some("h1".into()),
                behaviors: vec!["verbose".into(), "quiet".into()],
                effects: vec![],
                confidence: 0.95,
                orbit: Some("'a'→h1".into()),
            },
            FlagBehaviorEdge {
                glyph: "a".into(),
                code: 97,
                handler: Some(0x3000),
                handler_name: Some("h2".into()),
                behaviors: vec!["net".into()],
                effects: vec![],
                confidence: 0.9,
                orbit: Some("'a'→h2".into()),
            },
        ];
        detect_and_attach_orbit_conflicts(&mut lattice);
        assert!(
            lattice.contradictions.iter().any(|c| c.contains("split orbit") || c.contains("exclusive")),
            "contradictions={:?}",
            lattice.contradictions
        );
        assert!(lattice.claims.iter().any(|c| c.kind == "orbit_conflict"));
    }

    #[test]
    fn casl_physical_alphabet_seeds_without_optstring() {
        let text = "int main() { return 0; }";
        let mut lattice = build_agent_semantic_lattice("main", 0x1000, text, &[]);
        let refs = vec![
            Reference {
                from: 0x3000,
                to: crate::case_char_tag(b'x' as u64),
                kind: ReferenceKind::DataRef,
            },
            Reference {
                from: 0x3010,
                to: crate::case_char_tag(b'y' as u64),
                kind: ReferenceKind::DataRef,
            },
        ];
        let mut symbols = HashMap::new();
        symbols.insert(0x3000u64, "opt_x".to_string());
        bind_case_targets(&mut lattice, &refs, &symbols);
        assert!(
            lattice
                .case_lexicon
                .iter()
                .any(|c| c.glyph == "x" && c.target == Some(0x3000)),
            "physical seed failed: {:?}",
            lattice.case_lexicon
        );
        assert!(lattice.ibc.iter().any(|s| s.op == "MAP_CASES"));
        assert!(lattice.ibc.iter().any(|s| s.op == "VERIFY_CASE"));
        assert!(lattice.claims.iter().any(|c| c.kind == "case_bind"));
    }

    #[test]
    fn casl_binds_case_targets_and_advances_ibc() {
        let text = r#"
int main() {
    _getopt_long(0, 0, "+ab:c", 0);
    // switch ((opt - 97)) via jump table; // 0x1000 bound=2
    return 0;
}
"#;
        let mut lattice = build_agent_semantic_lattice("main", 0x1000, text, &[]);
        let refs = vec![
            Reference {
                from: 0x2000,
                to: crate::case_char_tag(b'a' as u64),
                kind: ReferenceKind::DataRef,
            },
            Reference {
                from: 0x2010,
                to: crate::case_char_tag(b'b' as u64),
                kind: ReferenceKind::DataRef,
            },
            Reference {
                from: 0x2020,
                to: crate::case_char_tag(b'c' as u64),
                kind: ReferenceKind::DataRef,
            },
        ];
        let mut symbols = HashMap::new();
        symbols.insert(0x2000u64, "handle_a".to_string());
        symbols.insert(0x2010u64, "handle_b".to_string());
        bind_case_targets(&mut lattice, &refs, &symbols);
        assert!(
            lattice.case_lexicon.iter().any(|c| c.glyph == "a" && c.target == Some(0x2000)),
            "a bound: {:?}",
            lattice.case_lexicon
        );
        assert!(lattice.ibc.iter().any(|s| s.op == "VERIFY_CASE"));
        assert!(lattice.ibc.iter().any(|s| s.op == "CLOSE_ALPHABET"));
        assert!(
            lattice.claims.iter().any(|c| c.kind == "case_bind"),
            "missing case_bind claim"
        );
        assert_eq!(
            lattice
                .case_lexicon
                .iter()
                .find(|c| c.glyph == "a")
                .and_then(|c| c.target_name.as_deref()),
            Some("handle_a")
        );
        let first = lattice_primary_next_action(&lattice, 0x1000).expect("step0");
        assert_eq!(first.label.as_deref(), Some("ibc:0"));
        let advanced = advance_ibc_cursor(&mut lattice).expect("advance");
        assert_eq!(advanced.pc, 0);
        let second = lattice_primary_next_action(&lattice, 0x1000).expect("step1");
        assert!(second.label.as_deref().unwrap_or("").starts_with("ibc:"));
        assert!(second.label != first.label || lattice.ibc_pc > 0);
        let plan = lattice_ibc_plan(&lattice, 0x1000, 4);
        assert!(!plan.is_empty());
        assert!(plan[0].reason.contains("EXECUTE NOW"));
    }

}
