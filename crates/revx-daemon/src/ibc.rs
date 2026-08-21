use super::*;

impl CapabilityService {
    pub(crate) fn run_ibc_status(&self, request: IbcStatusRequest) -> Result<IbcStatusResponse> {
        let ws = self.workspace()?;
        self.ensure_ibc_ledger_loaded(&ws);
        let namespace = self.continuum_namespace(&ws, request.namespace.as_deref());
        let (summary, focus, pc, status, epoch, witnesses, hyp_ids, lattice, next_actions) = {
            let guard = self
                .ibc_ledger
                .lock()
                .map_err(|_| anyhow::anyhow!("ibc ledger lock poisoned"))?;
            let summary = revx_analysis::continuum_ledger_summary(&guard);
            if let Some(state) = guard.sessions.get(&namespace) {
                let plan = revx_analysis::lattice_ibc_plan(&state.lattice, state.focus, 6);
                (
                    summary,
                    format!("{}@0x{:x}", state.focus_name, state.focus),
                    state.lattice.ibc_pc,
                    if state.lattice.ibc_status.is_empty() {
                        "ready".to_string()
                    } else {
                        state.lattice.ibc_status.clone()
                    },
                    state.epoch,
                    state.witnesses.clone(),
                    state.orbit_hypotheses.values().cloned().collect::<Vec<_>>(),
                    Some(state.lattice.clone()),
                    plan,
                )
            } else {
                (
                    summary,
                    String::new(),
                    0,
                    "empty".to_string(),
                    0,
                    Vec::new(),
                    Vec::new(),
                    None,
                    Vec::new(),
                )
            }
        };
        let mut key_findings = vec![
            summary.clone(),
            format!("continuum_ns: {namespace}"),
            format!("ibc_status: pc={pc} status={status} epoch={epoch}"),
        ];
        if !focus.is_empty() {
            key_findings.push(format!("focus: {focus}"));
        }
        for w in witnesses.iter().rev().take(6) {
            key_findings.push(format!("ibc_witness: {w}"));
        }
        if !hyp_ids.is_empty() {
            key_findings.push(format!(
                "orbit_hypotheses: {}",
                hyp_ids
                    .iter()
                    .take(8)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
        if let Ok(guard) = self.ibc_ledger.lock()
            && let Some(state) = guard.sessions.get(&namespace)
        {
            for line in revx_analysis::format_proof_chain_lines(&state.cognitive_field.proof_chain)
                .into_iter()
                .take(5)
            {
                key_findings.push(line);
            }
            let sealed = state
                .cognitive_field
                .proof_chain
                .iter()
                .filter(|l| l.verdict == "true" || l.verdict == "false")
                .count();
            if sealed > 0 {
                key_findings.push(format!("pcos_sealed_links: {sealed}"));
            }
        }
        let mut next = next_actions;
        next.insert(
            0,
            AgentNextAction {
                tool: "ibc_advance".to_string(),
                reason: "advance IBC continuum one step (or warp via tool+query)".to_string(),
                priority: 99,
                query: None,
                label: Some("ibc-advance".to_string()),
                args: serde_json::json!({
                    "namespace": namespace,
                    "force_next": true
                }),
            },
        );
        if let Some(id) = hyp_ids.first() {
            next.push(AgentNextAction {
                tool: "hypothesis_update".to_string(),
                reason: "edit confutation/status of bound orbit hypothesis".to_string(),
                priority: 80,
                query: Some(id.clone()),
                label: Some("orbit-hyp".to_string()),
                args: serde_json::json!({ "id": id }),
            });
        }
        let agent_brief = AgentInteractionBrief {
            headline: format!("IBC status ns={namespace} pc={pc} status={status}"),
            key_findings,
            open_questions: vec![
                "Execute ibc_advance force_next or run the recommended tool+query".to_string(),
            ],
            next_actions: next.clone(),
            stop_conditions: vec![
                "Stop when PCOS proof_chain seals top orbits (true/false) and open residuals=0"
                    .to_string(),
                "Prefer residual probes over re-decompile of sealed orbits".to_string(),
            ],
            semantic_lattice: lattice.clone(),
        };
        Ok(IbcStatusResponse {
            summary,
            active_namespace: namespace,
            focus,
            pc,
            status,
            epoch,
            witnesses,
            hypothesis_ids: hyp_ids,
            next_actions: next,
            agent_brief,
            semantic_lattice: lattice,
        })
    }

    pub(crate) fn run_ibc_advance(&self, request: IbcAdvanceRequest) -> Result<IbcAdvanceResponse> {
        let ws = self.workspace()?;
        self.ensure_ibc_ledger_loaded(&ws);
        let namespace = self.continuum_namespace(&ws, request.namespace.as_deref());
        let tool = request
            .tool
            .clone()
            .unwrap_or_else(|| "function_profile".to_string());
        let (advanced, note, pc, status, epoch, hyp_ids, lattice, next_actions) = {
            let mut guard = self
                .ibc_ledger
                .lock()
                .map_err(|_| anyhow::anyhow!("ibc ledger lock poisoned"))?;
            if !guard.sessions.contains_key(&namespace) {
                guard.sessions.insert(
                    namespace.clone(),
                    revx_analysis::IbcContinuumState {
                        namespace: namespace.clone(),
                        focus: 0,
                        focus_name: "unknown".to_string(),
                        lattice: revx_core::AgentSemanticLattice::default(),
                        witnesses: Vec::new(),
                        orbit_hypotheses: std::collections::BTreeMap::new(),
                        cognitive_field: revx_analysis::CognitiveField::default(),
                        epoch: 0,
                        updated_unix_ms: 0,
                    },
                );
            }
            let query_default_focus = guard.sessions.get(&namespace).map(|s| s.focus).unwrap_or(0);
            let query = request
                .query
                .clone()
                .unwrap_or_else(|| format!("0x{query_default_focus:x}"));
            let mut global_w = None;
            let result = {
                let state = guard.sessions.get_mut(&namespace).unwrap();
                let step = if request.force_next {
                    revx_analysis::force_advance_ibc(&mut state.lattice)
                } else {
                    revx_analysis::observe_ibc_execution(&mut state.lattice, &tool, &query)
                };
                let corpus = revx_analysis::synthesize_observation_corpus(&state.lattice, None);
                let collapse = revx_analysis::collapse_cognitive_field(
                    &mut state.cognitive_field,
                    &mut state.lattice,
                    &tool,
                    &query,
                    Some(corpus.as_str()),
                );
                for event in &collapse {
                    state
                        .witnesses
                        .push(format!("[{namespace}] COLLAPSE {event}"));
                }
                let mut field = revx_analysis::project_cognitive_field(&state.lattice);
                field.field_epoch = state.epoch;
                field.collapse_events = state.cognitive_field.collapse_events.clone();
                field.collapse_events.extend(collapse.iter().cloned());
                if field.collapse_events.len() > 24 {
                    let n = field.collapse_events.len() - 24;
                    field.collapse_events.drain(0..n);
                }
                field.residuals =
                    revx_analysis::project_diffraction_residuals(&field, &state.lattice);
                revx_analysis::apply_cognitive_field_to_lattice(&mut state.lattice, &field);
                revx_analysis::inject_diffraction_residuals_into_lattice(
                    &mut state.lattice,
                    &field,
                );
                state.cognitive_field = field;
                state.cognitive_field.proof_chain = revx_analysis::compose_proof_chain(state);
                revx_analysis::inject_proof_chain_into_lattice(
                    &mut state.lattice,
                    &state.cognitive_field,
                );
                let advanced = step.is_some() || !collapse.is_empty();
                if let Some(step) = step.as_ref() {
                    state.epoch = state.epoch.saturating_add(1);
                    let w = format!(
                        "[{namespace}] {} {} => IBC[{}] {} | {}",
                        tool, query, step.pc, step.op, step.detail
                    );
                    state.witnesses.push(w.clone());
                    if state.witnesses.len() > 48 {
                        let n = state.witnesses.len() - 48;
                        state.witnesses.drain(0..n);
                    }
                    global_w = Some(w);
                }
                let note = if advanced {
                    format!(
                        "IBC continuum ADVANCED ns={namespace} epoch={} pc={}",
                        state.epoch, state.lattice.ibc_pc
                    )
                } else {
                    format!(
                        "IBC continuum idle ns={namespace} pc={} status={}",
                        state.lattice.ibc_pc,
                        if state.lattice.ibc_status.is_empty() {
                            "ready"
                        } else {
                            state.lattice.ibc_status.as_str()
                        }
                    )
                };
                let plan = revx_analysis::lattice_ibc_plan(&state.lattice, state.focus, 6);
                (
                    advanced,
                    note,
                    state.lattice.ibc_pc,
                    if state.lattice.ibc_status.is_empty() {
                        "ready".to_string()
                    } else {
                        state.lattice.ibc_status.clone()
                    },
                    state.epoch,
                    state.orbit_hypotheses.values().cloned().collect::<Vec<_>>(),
                    Some(state.lattice.clone()),
                    plan,
                )
            };
            if let Some(w) = global_w {
                guard.global_witnesses.push(w);
                if guard.global_witnesses.len() > 64 {
                    let n = guard.global_witnesses.len() - 64;
                    guard.global_witnesses.drain(0..n);
                }
            }
            guard.active_namespace = namespace.clone();
            result
        };
        self.persist_ibc_ledger(&ws);
        let hyp_ids = {
            let mut ids = hyp_ids;
            let forged = self.forge_and_bind_orbit_hypotheses(&ws, &namespace);
            for id in forged {
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
            let sealed = self.seal_orbit_hypotheses_from_collapses(&ws, &namespace);
            for id in sealed {
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
            ids
        };
        let mut next = next_actions;
        next.insert(
            0,
            AgentNextAction {
                tool: "ibc_status".to_string(),
                reason: "inspect durable continuum after advance".to_string(),
                priority: 95,
                query: None,
                label: Some("ibc-status".to_string()),
                args: serde_json::json!({ "namespace": namespace }),
            },
        );
        let field_lines = lattice
            .as_ref()
            .map(|l| {
                let f = revx_analysis::project_cognitive_field(l);
                format!(
                    "odc_field: mode={} entropy={:.2} residuals={} collapses={}",
                    f.mode,
                    f.entropy,
                    f.residuals.len(),
                    f.collapse_events.len()
                )
            })
            .unwrap_or_else(|| "odc_field: -".to_string());
        let agent_brief = AgentInteractionBrief {
            headline: format!("IBC advance ns={namespace} advanced={advanced} pc={pc}"),
            key_findings: vec![
                note.clone(),
                format!("continuum_ns: {namespace}"),
                format!("ibc_status: pc={pc} status={status} epoch={epoch}"),
                field_lines,
                format!(
                    "orbit_hypotheses: {}",
                    hyp_ids
                        .iter()
                        .take(8)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(",")
                ),
                format!("pcos_hypotheses_touched: {}", hyp_ids.len()),
            ],
            open_questions: vec![if advanced {
                "Continue with next_actions[0] to follow IBC plan".to_string()
            } else {
                "No step matched; supply tool+query for warp or force_next=true".to_string()
            }],
            next_actions: next.clone(),
            stop_conditions: vec![
                "Prefer ibc_status after each advance before branching".to_string(),
            ],
            semantic_lattice: lattice.clone(),
        };
        Ok(IbcAdvanceResponse {
            advanced,
            note,
            namespace,
            pc,
            status,
            epoch,
            hypothesis_ids: hyp_ids,
            next_actions: next,
            agent_brief,
            semantic_lattice: lattice,
        })
    }
}
