use anyhow::{Context, Result};
use revx_analysis::analyze_streaming;
use revx_core::{
    AgentInteractionBrief, AgentNextAction, AnalysisBriefRequest, AnalysisBriefResponse,
    AnalysisHotFunction, AnalysisImportHit, AnalysisRunRequest, AnalysisRunResponse, AnalysisStatusRequest,
    AnalysisStringHit, BinaryListResponse,
    BinarySurveyRequest, BinarySurveyResponse, CallgraphSliceRequest, CallgraphSliceResponse,
    CapabilityEnvelope, CapabilityError, CapabilityReply, CapabilityRequest, CapabilityResponse,
    DecompileCacheEntry, DecompileCacheStatusRequest, DecompileCacheStatusResponse, DecompileFunctionRequest, DecompileFunctionResponse, DecompileStrategy, DisassembleFunctionRequest,
    DisassembleFunctionResponse, Evidence, EvidenceGraphRequest, EvidencePackRequest,
    EvidencePackResponse, EvidenceProvenance, FunctionProfileRequest, FunctionProfileResponse,
    FunctionSearchHit, FunctionSearchRequest, FunctionSearchResponse, HypothesisCreateRequest,
    HypothesisCreateResponse, HypothesisUpdateRequest, HypothesisUpdateResponse,
    IbcAdvanceRequest, IbcAdvanceResponse, IbcStatusRequest, IbcStatusResponse,
    AnalysisProfile, InvestigationRunRequest, InvestigationRunResponse, ObjectAnalysisStatus,
    ObjectAnalysisSummary, ObjectAnalyzeBinaryRequest, ObjectAnalyzeBinaryResponse, ObjectAnalyzeRequest,
    ObjectAnalyzeResponse, ObjectCarveIdentifyRequest, ObjectCarveIdentifyResponse,
    ObjectCarveIdentifyResult, ObjectCarveSignaturesRequest, ObjectCarveSignaturesResponse,
    ObjectExtractRangeRequest, ObjectExtractRangeResponse, ObjectIdentifyRequest,
    ObjectIdentifyResponse, ObjectKind, ObjectMaterializeRequest, ObjectMaterializeResponse,
    ObjectPipelineRequest, ObjectPipelineResponse, ObjectPipelineStage, ObjectPipelineStep,
    ObjectPluginListRequest, ObjectPluginListResponse, ObjectPluginRunRequest,
    ObjectPluginRunResponse, ObjectProfileRequest, ObjectProfileResponse,
    ObjectRegisterBinaryRequest, ObjectRegisterBinaryResponse, ObjectSearchRequest,
    ObjectSearchResponse, ObjectSignatureScanRequest, ObjectSignatureScanResponse,
    ProjectOpenRequest, ProjectOpenResponse, ProjectStatusRequest, ProjectStatusResponse, Report,
    ReportGenerateRequest, ReportGenerateResponse, SearchBytesRequest, StringSearchRequest,
    StringSearchResponse, SymbolicConstraint, SymbolicConstraintOp, SymbolicDomain,
    SymbolicLinearExpr, SymbolicSolveRequest, SymbolicSolveResponse, SymbolicSolveStatus,
    TraceImportRequest, TraceImportResponse, TraceQueryRequest, TraceQueryResponse,
    UniversalObject, XrefsQueryRequest, XrefsQueryResponse,
};
use revx_loader::{identify_object_graph, load_binary};
use revx_workspace::Workspace;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(all(not(unix), not(windows)))]
use tokio::net::TcpStream;
use tracing::warn;

mod mcp_http;
pub use mcp_http::serve_mcp_http;

const IBC_CONTINUUM_LEDGER_CACHE: &str = "ibc_continuum_ledger.json";

#[derive(Clone)]
pub struct CapabilityService {
    workspace_root: PathBuf,
    workspace: std::sync::OnceLock<Workspace>,
    ibc_ledger: std::sync::Arc<std::sync::Mutex<revx_analysis::IbcContinuumLedger>>,
    ibc_ledger_loaded: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl CapabilityService {
    pub fn new(workspace_root: PathBuf) -> Self {
        Self {
            workspace_root,
            workspace: std::sync::OnceLock::new(),
            ibc_ledger: std::sync::Arc::new(std::sync::Mutex::new(
                revx_analysis::IbcContinuumLedger {
                    version: 1,
                    ..Default::default()
                },
            )),
            ibc_ledger_loaded: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    pub fn workspace(&self) -> Result<Workspace> {
        if let Some(ws) = self.workspace.get() {
            return Ok(ws.clone());
        }
        let opened = Workspace::open(&self.workspace_root)?;
        let _ = self.workspace.set(opened.clone());
        Ok(self.workspace.get().cloned().unwrap_or(opened))
    }

    fn ensure_ibc_ledger_loaded(&self, ws: &Workspace) {
        if self
            .ibc_ledger_loaded
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return;
        }
        if let Ok(Some(loaded)) = ws.read_cache_json::<revx_analysis::IbcContinuumLedger>(
            IBC_CONTINUUM_LEDGER_CACHE,
        ) {
            if let Ok(mut guard) = self.ibc_ledger.lock() {
                *guard = loaded;
            }
        }
        self.ibc_ledger_loaded
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    fn persist_ibc_ledger(&self, ws: &Workspace) {
        if let Ok(guard) = self.ibc_ledger.lock() {
            let _ = ws.write_cache_json(IBC_CONTINUUM_LEDGER_CACHE, &*guard);
        }
    }

    fn continuum_namespace(&self, ws: &Workspace, hint: Option<&str>) -> String {
        if let Some(h) = hint {
            let t = h.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
        if let Ok(Some(id)) = ws.latest_binary_id() {
            if !id.is_empty() {
                return id;
            }
        }
        if let Ok(cfg) = ws.project_config() {
            if let Some(primary) = cfg.primary_binary {
                if !primary.is_empty() {
                    return primary;
                }
            }
        }
        "default".to_string()
    }

    fn sync_ibc_continuum(
        &self,
        ws: &Workspace,
        tool: &str,
        address: u64,
        name: &str,
        lattice: revx_core::AgentSemanticLattice,
        namespace_hint: Option<&str>,
        observation: Option<&str>,
    ) -> (revx_core::AgentSemanticLattice, String, Vec<String>, String) {
        self.ensure_ibc_ledger_loaded(ws);
        let namespace = self.continuum_namespace(ws, namespace_hint);
        let observe = {
            let mut guard = match self.ibc_ledger.lock() {
                Ok(g) => g,
                Err(_) => {
                    return (
                        lattice,
                        "IBC continuum unavailable (lock poisoned)".to_string(),
                        Vec::new(),
                        namespace,
                    );
                }
            };
            revx_analysis::continuum_ledger_on_visit_with_observation(
                &mut guard,
                &namespace,
                tool,
                address,
                name,
                lattice,
                observation,
            )
        };
        self.persist_ibc_ledger(ws);
        let (out_lattice, witnesses, brief_lines) = {
            let guard = self.ibc_ledger.lock().ok();
            if let Some(guard) = guard {
                if let Some(state) = guard.sessions.get(&namespace) {
                    (
                        state.lattice.clone(),
                        state.witnesses.clone(),
                        revx_analysis::continuum_brief_lines(state),
                    )
                } else {
                    (
                        revx_core::AgentSemanticLattice::default(),
                        Vec::new(),
                        Vec::new(),
                    )
                }
            } else {
                (
                    revx_core::AgentSemanticLattice::default(),
                    Vec::new(),
                    Vec::new(),
                )
            }
        };
        let mut note = observe.note;
        if let Ok(guard) = self.ibc_ledger.lock() {
            note = format!(
                "{} | {}",
                note,
                revx_analysis::continuum_ledger_summary(&guard)
            );
        }
        let _ = brief_lines;
        (out_lattice, note, witnesses, namespace)
    }

    fn apply_continuum_to_brief(
        &self,
        ws: &Workspace,
        tool: &str,
        address: u64,
        name: &str,
        agent_brief: &mut revx_core::AgentInteractionBrief,
        namespace_hint: Option<&str>,
        observation: Option<&str>,
    ) {
        let Some(lattice) = agent_brief.semantic_lattice.take() else {
            return;
        };
        let (synced, note, witnesses, namespace) = self.sync_ibc_continuum(
            ws,
            tool,
            address,
            name,
            lattice,
            namespace_hint,
            observation,
        );
        agent_brief.key_findings.insert(0, note);
        agent_brief
            .key_findings
            .insert(1, format!("continuum_ns: {namespace}"));
        for w in witnesses.iter().rev().take(4) {
            agent_brief
                .key_findings
                .insert(2, format!("ibc_witness: {w}"));
        }
        if let Ok(guard) = self.ibc_ledger.lock() {
            if let Some(state) = guard.sessions.get(&namespace) {
                for line in revx_analysis::continuum_brief_lines(state)
                    .into_iter()
                    .take(4)
                    .rev()
                {
                    if !agent_brief.key_findings.iter().any(|k| k == &line) {
                        agent_brief.key_findings.insert(1, line);
                    }
                }
            }
            for gw in guard.global_witnesses.iter().rev().take(2) {
                let line = format!("ledger_witness: {gw}");
                if !agent_brief.key_findings.iter().any(|k| k == &line) {
                    agent_brief.key_findings.insert(1, line);
                }
            }
        }
        let plan = revx_analysis::lattice_ibc_plan(&synced, address, 4);
        if !plan.is_empty() {
            for (i, mut action) in plan.into_iter().enumerate() {
                action.priority = 99u8.saturating_sub(i as u8);
                action.reason = format!("IBC continuum[{namespace}]: {}", action.reason);
                agent_brief.next_actions.insert(i, action);
            }
            agent_brief
                .next_actions
                .sort_by(|a, b| b.priority.cmp(&a.priority));
            let mut seen = std::collections::BTreeSet::new();
            agent_brief.next_actions.retain(|action| {
                let key = format!("{}:{}", action.tool, action.args);
                seen.insert(key)
            });
            agent_brief.next_actions.truncate(8);
        }
        let hyp_ids = self.forge_and_bind_orbit_hypotheses(ws, &namespace);
        let sealed_ids = self.seal_orbit_hypotheses_from_collapses(ws, &namespace);
        if !hyp_ids.is_empty() {
            agent_brief.key_findings.insert(
                1,
                format!(
                    "orbit_hypotheses_bound: {}",
                    hyp_ids.iter().take(6).cloned().collect::<Vec<_>>().join(",")
                ),
            );
            agent_brief.next_actions.push(AgentNextAction {
                tool: "hypothesis_update".to_string(),
                reason: "refine confutation for top orbit hypothesis".to_string(),
                priority: 70,
                query: hyp_ids.first().cloned(),
                label: Some("orbit-hyp".to_string()),
                args: serde_json::json!({ "id": hyp_ids.first().cloned().unwrap_or_default() }),
            });
        }
        if !sealed_ids.is_empty() {
            agent_brief.key_findings.insert(
                1,
                format!(
                    "pcos_sealed_hypotheses: {}",
                    sealed_ids.iter().take(6).cloned().collect::<Vec<_>>().join(",")
                ),
            );
            agent_brief.stop_conditions.insert(
                0,
                format!(
                    "PCOS sealed {} orbit hypotheses under ns=`{namespace}`; prefer residual probes for unsealed orbits only",
                    sealed_ids.len()
                ),
            );
        }
        if let Ok(guard) = self.ibc_ledger.lock() {
            if let Some(state) = guard.sessions.get(&namespace) {
                for residual in state
                    .cognitive_field
                    .residuals
                    .iter()
                    .filter(|r| r.polarity != "sealed")
                    .take(3)
                {
                    agent_brief.open_questions.push(residual.question.clone());
                    agent_brief.next_actions.insert(
                        0,
                        AgentNextAction {
                            tool: residual.probe_tool.clone(),
                            reason: format!(
                                "ODC residual [{}] iv={:.2}",
                                residual.polarity, residual.information_value
                            ),
                            priority: 98,
                            query: residual.probe_query.clone(),
                            label: Some(format!("odc-{}", residual.id)),
                            args: residual
                                .probe_query
                                .as_ref()
                                .map(|q| serde_json::json!({ "query": q }))
                                .unwrap_or_else(|| serde_json::json!({})),
                        },
                    );
                }
                if let Some(ev) = state.cognitive_field.collapse_events.iter().rev().next() {
                    agent_brief.key_findings.insert(
                        1,
                        format!("odc_collapse: {}", ev.chars().take(140).collect::<String>()),
                    );
                }
                for line in revx_analysis::format_proof_chain_lines(
                    &state.cognitive_field.proof_chain,
                )
                .into_iter()
                .take(4)
                .rev()
                {
                    if !agent_brief.key_findings.iter().any(|k| k == &line) {
                        agent_brief.key_findings.insert(1, line);
                    }
                }
                let sealed = state
                    .cognitive_field
                    .proof_chain
                    .iter()
                    .filter(|l| l.verdict == "true" || l.verdict == "false")
                    .count();
                let open = state
                    .cognitive_field
                    .residuals
                    .iter()
                    .filter(|r| r.polarity != "sealed")
                    .count();
                if sealed > 0 && open == 0 {
                    agent_brief.stop_conditions.insert(
                        0,
                        format!(
                            "PCOS orbit set fully sealed ({sealed}); agent may conclude this continuum focus"
                        ),
                    );
                }
                agent_brief.next_actions.sort_by(|a, b| b.priority.cmp(&a.priority));
                let mut seen = std::collections::BTreeSet::new();
                agent_brief.next_actions.retain(|action| {
                    let key = format!("{}:{}", action.tool, action.args);
                    seen.insert(key)
                });
                agent_brief.next_actions.truncate(8);
            }
        }
        agent_brief.stop_conditions.insert(
            0,
            format!(
                "IBC continuum durable under ns=`{namespace}`; resume with next_actions[0] or ibc_status"
            ),
        );
        agent_brief.semantic_lattice = Some(synced);
    }


    fn seal_orbit_hypotheses_from_collapses(
        &self,
        ws: &Workspace,
        namespace: &str,
    ) -> Vec<String> {
        self.ensure_ibc_ledger_loaded(ws);
        let (plan, epoch, proof_lines) = {
            let mut guard = match self.ibc_ledger.lock() {
                Ok(g) => g,
                Err(_) => return Vec::new(),
            };
            let Some(state) = guard.sessions.get_mut(namespace) else {
                return Vec::new();
            };
            state.cognitive_field.proof_chain = revx_analysis::compose_proof_chain(state);
            revx_analysis::inject_proof_chain_into_lattice(
                &mut state.lattice,
                &state.cognitive_field,
            );
            let plan = revx_analysis::seal_plan_from_proof_chain(state);
            let epoch = state.epoch;
            let proof_lines = revx_analysis::format_proof_chain_lines(&state.cognitive_field.proof_chain);
            (plan, epoch, proof_lines)
        };
        if plan.is_empty() {
            let _ = proof_lines;
            return Vec::new();
        }
        let mut sealed_ids = Vec::new();
        for (hid, orbit_key, polarity, verdict_block) in plan {
            let Ok(Some(existing)) = ws.get_hypothesis(&hid) else {
                continue;
            };
            let title =
                revx_analysis::apply_verdict_to_hypothesis_title(&existing.title, &polarity);
            let notes = if existing.notes.contains("### PCOS VERDICT")
                && existing.notes.contains(&format!(" {orbit_key}"))
                && existing.notes.contains(&format!("polarity={polarity}"))
            {
                existing.notes.clone()
            } else {
                if existing.notes.is_empty() {
                    verdict_block
                } else {
                    format!("{}

{verdict_block}", existing.notes)
                }
            };
            let mut evidence = existing.evidence_ids.clone();
            let evid = format!("casl:pcos:{namespace}:{orbit_key}:{polarity}:e{epoch}");
            if !evidence.iter().any(|e| e == &evid) {
                evidence.push(evid);
            }
            if let Ok(h) = ws.update_hypothesis(&hid, Some(&title), Some(&notes), Some(evidence)) {
                sealed_ids.push(h.id);
            }
        }
        self.persist_ibc_ledger(ws);
        let _ = proof_lines;
        sealed_ids
    }

    fn forge_and_bind_orbit_hypotheses(&self, ws: &Workspace, namespace: &str) -> Vec<String> {
        self.ensure_ibc_ledger_loaded(ws);
        let drafts = {
            let guard = match self.ibc_ledger.lock() {
                Ok(g) => g,
                Err(_) => return Vec::new(),
            };
            let Some(state) = guard.sessions.get(namespace) else {
                return Vec::new();
            };
            revx_analysis::forge_orbit_hypothesis_drafts(state)
        };
        if drafts.is_empty() {
            return Vec::new();
        }
        let mut bound_ids = Vec::new();
        let mut guard = match self.ibc_ledger.lock() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let Some(state) = guard.sessions.get_mut(namespace) else {
            return Vec::new();
        };
        for draft in drafts.into_iter().take(8) {
            if let Some(existing) = state.orbit_hypotheses.get(&draft.key).cloned() {
                if let Ok(h) = ws.update_hypothesis(
                    &existing,
                    Some(&draft.title),
                    Some(&draft.notes),
                    Some(draft.evidence_ids.clone()),
                ) {
                    bound_ids.push(h.id);
                }
                continue;
            }
            if let Ok(h) = ws.create_hypothesis(&draft.title, &draft.notes, &draft.evidence_ids) {
                revx_analysis::continuum_bind_hypothesis(state, &draft.key, &h.id);
                bound_ids.push(h.id);
            }
        }
        drop(guard);
        self.persist_ibc_ledger(ws);
        bound_ids
    }

    fn run_ibc_status(
        &self,
        request: IbcStatusRequest,
    ) -> Result<IbcStatusResponse> {
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
                hyp_ids.iter().take(8).cloned().collect::<Vec<_>>().join(",")
            ));
        }
        if let Ok(guard) = self.ibc_ledger.lock() {
            if let Some(state) = guard.sessions.get(&namespace) {
                for line in revx_analysis::format_proof_chain_lines(
                    &state.cognitive_field.proof_chain,
                )
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

    fn run_ibc_advance(
        &self,
        request: IbcAdvanceRequest,
    ) -> Result<IbcAdvanceResponse> {
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
            let query_default_focus = guard
                .sessions
                .get(&namespace)
                .map(|s| s.focus)
                .unwrap_or(0);
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
                let corpus = revx_analysis::synthesize_observation_corpus(
                    &state.lattice,
                    None,
                );
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
                state.cognitive_field.proof_chain =
                    revx_analysis::compose_proof_chain(state);
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
                    hyp_ids.iter().take(8).cloned().collect::<Vec<_>>().join(",")
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

    pub fn dispatch(&self, request: CapabilityRequest) -> Result<CapabilityResponse> {
        match request {
            CapabilityRequest::ProjectOpen(ProjectOpenRequest { path }) => {
                let ws = Workspace::open(Path::new(&path))?;
                Ok(CapabilityResponse::ProjectOpen(ProjectOpenResponse {
                    workspace_root: ws.root().display().to_string(),
                    project: ws.project_config()?,
                }))
            }
            CapabilityRequest::ProjectStatus(ProjectStatusRequest) => {
                let ws = self.workspace()?;
                let project = ws.project_config()?;
                let binaries = ws.binary_record_list()?;
                Ok(CapabilityResponse::ProjectStatus(ProjectStatusResponse {
                    workspace_root: ws.root().display().to_string(),
                    project,
                    binary_count: binaries.len(),
                    binaries,
                }))
            }
            CapabilityRequest::ObjectIdentify(ObjectIdentifyRequest {
                path,
                max_depth,
                max_children,
                include_graph,
            }) => {
                let ws = self.workspace()?;
                let graph = identify_object_graph(
                    Path::new(&path),
                    max_depth.unwrap_or(2),
                    max_children.unwrap_or(256),
                )?;
                let root_id = graph.root_id.clone();
                let object_count = graph.objects.len();
                let edge_count = graph.edges.len();
                let (artifact, evidence_ids) = ws.save_object_graph(&graph)?;
                Ok(CapabilityResponse::ObjectIdentify(ObjectIdentifyResponse {
                    root_id,
                    object_count,
                    edge_count,
                    evidence_count: evidence_ids.len(),
                    evidence_ids,
                    graph: include_graph.unwrap_or(true).then_some(graph),
                    artifact: Some(artifact),
                }))
            }
            CapabilityRequest::ObjectSearch(ObjectSearchRequest { query, kind, limit }) => {
                let ws = self.workspace()?;
                Ok(CapabilityResponse::ObjectSearch(ObjectSearchResponse {
                    objects: ws.search_objects(&query, kind, limit.unwrap_or(200))?,
                }))
            }
            CapabilityRequest::ObjectProfile(ObjectProfileRequest { query }) => {
                let ws = self.workspace()?;
                let profile = ws
                    .object_profile(&query)?
                    .ok_or_else(|| object_lookup_error(&ws, &query))?;
                Ok(CapabilityResponse::ObjectProfile(ObjectProfileResponse {
                    object: profile.object,
                    incoming_edges: profile.incoming_edges,
                    outgoing_edges: profile.outgoing_edges,
                    evidence_ids: profile.evidence_ids,
                    artifact: profile.artifact,
                }))
            }
            CapabilityRequest::ObjectMaterialize(ObjectMaterializeRequest {
                query,
                preview_bytes,
            }) => {
                let ws = self.workspace()?;
                let materialized = ws
                    .materialize_object(&query, preview_bytes.unwrap_or(256))?
                    .ok_or_else(|| object_lookup_error(&ws, &query))?;
                Ok(CapabilityResponse::ObjectMaterialize(
                    ObjectMaterializeResponse {
                        object: materialized.object,
                        artifact: materialized.artifact,
                        content_type: materialized.content_type,
                        evidence_id: materialized.evidence_id,
                        source: materialized.source,
                        preview_hex: materialized.preview_hex,
                        preview_text: materialized.preview_text,
                    },
                ))
            }
            CapabilityRequest::ObjectExtractRange(ObjectExtractRangeRequest {
                query,
                offset,
                length,
                context_bytes,
                preview_bytes,
            }) => {
                let ws = self.workspace()?;
                let extracted = ws
                    .extract_object_range(
                        &query,
                        offset,
                        length,
                        context_bytes.unwrap_or(0),
                        preview_bytes.unwrap_or(256),
                    )?
                    .ok_or_else(|| object_lookup_error(&ws, &query))?;
                Ok(CapabilityResponse::ObjectExtractRange(
                    ObjectExtractRangeResponse {
                        object: extracted.object,
                        offset: extracted.offset,
                        requested_length: extracted.requested_length,
                        extracted_offset: extracted.extracted_offset,
                        extracted_size: extracted.extracted_size,
                        artifact: extracted.artifact,
                        content_type: extracted.content_type,
                        evidence_id: extracted.evidence_id,
                        source: extracted.source,
                        preview_hex: extracted.preview_hex,
                        preview_text: extracted.preview_text,
                    },
                ))
            }
            CapabilityRequest::ObjectSignatureScan(ObjectSignatureScanRequest {
                query,
                limit,
                max_object_bytes,
                preview_bytes,
            }) => {
                let ws = self.workspace()?;
                let scanned = ws
                    .scan_object_signatures(
                        &query,
                        limit.unwrap_or(200),
                        max_object_bytes.unwrap_or(64 * 1024 * 1024),
                        preview_bytes.unwrap_or(64),
                    )?
                    .ok_or_else(|| object_lookup_error(&ws, &query))?;
                Ok(CapabilityResponse::ObjectSignatureScan(
                    ObjectSignatureScanResponse {
                        object: scanned.object,
                        source: scanned.source,
                        scanned_size: scanned.scanned_size,
                        returned_count: scanned.returned_count,
                        truncated: scanned.truncated,
                        signatures: scanned.signatures,
                        evidence_id: scanned.evidence_id,
                        artifact: scanned.artifact,
                    },
                ))
            }
            CapabilityRequest::ObjectCarveSignatures(ObjectCarveSignaturesRequest {
                query,
                limit,
                max_object_bytes,
                max_carve_bytes,
                min_confidence,
                preview_bytes,
            }) => {
                let ws = self.workspace()?;
                let carved = ws
                    .carve_object_signatures(
                        &query,
                        limit.unwrap_or(100),
                        max_object_bytes.unwrap_or(64 * 1024 * 1024),
                        max_carve_bytes.unwrap_or(64 * 1024 * 1024),
                        min_confidence.unwrap_or(0.9),
                        preview_bytes.unwrap_or(64),
                    )?
                    .ok_or_else(|| object_lookup_error(&ws, &query))?;
                Ok(CapabilityResponse::ObjectCarveSignatures(
                    ObjectCarveSignaturesResponse {
                        object: carved.object,
                        source: carved.source,
                        scanned_size: carved.scanned_size,
                        scanned_count: carved.scanned_count,
                        carved_count: carved.carved_count,
                        skipped_count: carved.skipped_count,
                        truncated: carved.truncated,
                        scan_evidence_id: carved.scan_evidence_id,
                        carve_evidence_id: carved.carve_evidence_id,
                        artifact: carved.artifact,
                        carves: carved.carves,
                    },
                ))
            }
            CapabilityRequest::ObjectCarveIdentify(request) => {
                let ws = self.workspace()?;
                Ok(CapabilityResponse::ObjectCarveIdentify(
                    run_object_carve_identify(&ws, request)?,
                ))
            }
            CapabilityRequest::ObjectAnalyze(ObjectAnalyzeRequest { query, analyzers }) => {
                let ws = self.workspace()?;
                let mut analyzed = ws
                    .analyze_object(&query, analyzers.as_deref())?
                    .ok_or_else(|| object_lookup_error(&ws, &query))?;
                let binary_followups = promote_dug_native_binaries(
                    &ws,
                    &analyzed.analyses,
                    AnalysisProfile::Fast,
                    "object_analyze_auto_binary",
                    4,
                )?;
                if let Some(followup) = binary_followups {
                    analyzed.evidence_ids.extend(followup.evidence_ids.iter().cloned());
                    analyzed.evidence_ids.sort();
                    analyzed.evidence_ids.dedup();
                    analyzed.analyses.push(followup.analysis);
                }
                let next_actions = if analyzed.next_actions.is_empty() {
                    derive_daemon_object_next_actions(&analyzed.object, &analyzed.analyses)
                } else {
                    analyzed.next_actions
                };
                let agent_brief = if analyzed.agent_brief.headline.is_empty() {
                    derive_daemon_object_agent_brief(
                        &analyzed.object,
                        &analyzed.analyses,
                        &next_actions,
                    )
                } else {
                    analyzed.agent_brief
                };
                Ok(CapabilityResponse::ObjectAnalyze(ObjectAnalyzeResponse {
                    object: analyzed.object,
                    analyses: analyzed.analyses,
                    evidence_ids: analyzed.evidence_ids,
                    artifact: analyzed.artifact,
                    next_actions,
                    agent_brief,
                }))
            }
            CapabilityRequest::ObjectPluginList(ObjectPluginListRequest) => {
                let ws = self.workspace()?;
                let plugins = ws.list_object_plugins()?;
                let artifact = (!plugins.is_empty())
                    .then(|| ws.write_json_artifact("application/json", &plugins))
                    .transpose()?;
                Ok(CapabilityResponse::ObjectPluginList(
                    ObjectPluginListResponse { plugins, artifact },
                ))
            }
            CapabilityRequest::ObjectPluginRun(ObjectPluginRunRequest {
                plugin_id,
                query,
                timeout_ms,
            }) => {
                let ws = self.workspace()?;
                Ok(CapabilityResponse::ObjectPluginRun(run_object_plugin(
                    &ws, &plugin_id, &query, timeout_ms,
                )?))
            }
            CapabilityRequest::ObjectRegisterBinary(ObjectRegisterBinaryRequest { query }) => {
                let ws = self.workspace()?;
                let materialized = ws
                    .materialize_object(&query, 0)?
                    .ok_or_else(|| object_lookup_error(&ws, &query))?;
                let artifact_path = ws.root().join(&materialized.artifact.relative_path);
                let image = load_binary(&artifact_path).with_context(|| {
                    format!(
                        "failed to parse materialized object {} as binary",
                        materialized.object.display_name
                    )
                })?;
                let survey = ws.register_binary(&image)?;
                let survey_artifact = ws
                    .survey_for_binary(Some(&survey.binary.id))?
                    .map(|(_, artifact)| artifact)
                    .ok_or_else(|| {
                        anyhow::anyhow!("registered binary survey artifact not found")
                    })?;
                let evidence_id = format!(
                    "object_binary:{}:{}",
                    materialized.object.id, survey.binary.id
                );
                ws.insert_evidence(Evidence {
                    id: evidence_id.clone(),
                    subject: materialized
                        .object
                        .path
                        .clone()
                        .unwrap_or_else(|| materialized.object.id.clone()),
                    summary: format!(
                        "Registered object {} as binary {}",
                        materialized.object.display_name, survey.binary.id
                    ),
                    kind: "object_binary_registration".to_string(),
                    details: serde_json::json!({
                        "object": &materialized.object,
                        "materialized_artifact": &materialized.artifact,
                        "binary_id": &survey.binary.id,
                        "binary_path": &survey.binary.path,
                        "survey_artifact": &survey_artifact,
                    }),
                    provenance: EvidenceProvenance {
                        source: "object_register_binary".to_string(),
                        binary_id: Some(survey.binary.id.clone()),
                        function_address: None,
                        instruction_address: None,
                        profile: None,
                    },
                })?;
                Ok(CapabilityResponse::ObjectRegisterBinary(
                    ObjectRegisterBinaryResponse {
                        object: materialized.object,
                        materialized_artifact: materialized.artifact,
                        survey,
                        survey_artifact,
                        evidence_id,
                    },
                ))
            }
            CapabilityRequest::ObjectAnalyzeBinary(ObjectAnalyzeBinaryRequest {
                query,
                profile,
            }) => {
                let ws = self.workspace()?;
                Ok(CapabilityResponse::ObjectAnalyzeBinary(
                    analyze_object_as_binary(&ws, &query, profile, "object_analyze_binary")?,
                ))
            }
            CapabilityRequest::ObjectPipeline(request) => {
                let ws = self.workspace()?;
                Ok(CapabilityResponse::ObjectPipeline(run_object_pipeline(
                    &ws, request,
                )?))
            }
            CapabilityRequest::BinaryList(_) => {
                let ws = self.workspace()?;
                Ok(CapabilityResponse::BinaryList(BinaryListResponse {
                    binaries: ws.binary_record_list()?,
                }))
            }
            CapabilityRequest::AnalysisRun(AnalysisRunRequest {
                binary_path,
                profile,
            }) => {
                let ws = self.workspace()?;
                let image = load_binary(Path::new(&binary_path))?;
                let (run_id, summary, evidence_export) = run_binary_analysis(&ws, image, profile)?;
                Ok(CapabilityResponse::AnalysisRun(AnalysisRunResponse {
                    run_id,
                    status: revx_core::AnalysisRunState::Completed,
                    summary,
                    evidence_count: evidence_export.count,
                    evidence_ids: evidence_export.preview_ids,
                    evidence_artifact: Some(evidence_export.artifact),
                }))
            }
            CapabilityRequest::AnalysisStatus(AnalysisStatusRequest { run_id }) => {
                let ws = self.workspace()?;
                let status = ws
                    .analysis_status(run_id.as_deref())?
                    .ok_or_else(|| anyhow::anyhow!("analysis run not found"))?;
                Ok(CapabilityResponse::AnalysisStatus(status))
            }
            CapabilityRequest::BinarySurvey(BinarySurveyRequest { binary_id }) => {
                let ws = self.workspace()?;
                let survey = ws
                    .survey_preview_for_binary(binary_id.as_deref())?
                    .ok_or_else(|| anyhow::anyhow!("survey not found"))?;
                let evidence_export = ws.export_evidence_ids_by_subject(&survey.binary_path, 32)?;
                let mut preview = survey.summary;
                preview.evidence_count = evidence_export.count;
                Ok(CapabilityResponse::BinarySurvey(BinarySurveyResponse {
                    preview,
                    survey: None,
                    evidence_count: evidence_export.count,
                    evidence_ids: evidence_export.preview_ids,
                    evidence_artifact: Some(evidence_export.artifact),
                    artifact: Some(survey.artifact),
                }))
            }
            CapabilityRequest::FunctionSearch(FunctionSearchRequest { query, limit, offset }) => {
                let ws = self.workspace()?;
                let lim = limit.unwrap_or(200);
                let off = offset.unwrap_or(0);
                Ok(CapabilityResponse::FunctionSearch(FunctionSearchResponse {
                    functions: ws.search_functions_paged(&query, lim, off)?,
                }))
            }
            CapabilityRequest::FunctionProfile(FunctionProfileRequest { query }) => {
                let ws = self.workspace()?;
                let function = ws
                    .resolve_function(&query)?
                    .ok_or_else(|| function_lookup_error(&ws, &query))?;
                let function_query = format!("0x{:x}", function.address);
                let xrefs = ws.find_references(&function_query)?;
                let callgraph = ws.callgraph_slice(&function_query)?;
                let function_ranges = ws.function_ranges()?;
                let function_start = function.address;
                let function_end = function.address + function.size;
                let mut incoming_xrefs = Vec::new();
                let mut outgoing_xrefs = Vec::new();
                for reference in xrefs {
                    let is_control = matches!(
                        reference.kind.as_str(),
                        "call" | "jump" | "branch_true" | "branch_false"
                    );
                    let is_incoming = !is_control
                        && reference.to >= function_start
                        && reference.to < function_end
                        && (reference.from < function_start || reference.from >= function_end)
                        && !address_in_any_range(reference.from, &function_ranges);
                    let is_outgoing = !is_control
                        && reference.from >= function_start
                        && reference.from < function_end
                        && (reference.to < function_start || reference.to >= function_end)
                        && !address_in_any_range(reference.to, &function_ranges);
                    if is_incoming && is_outgoing {
                        incoming_xrefs.push(reference.clone());
                        outgoing_xrefs.push(reference);
                    } else if is_incoming {
                        incoming_xrefs.push(reference);
                    } else if is_outgoing {
                        outgoing_xrefs.push(reference);
                    }
                }
                dedupe_references_in_place(&mut incoming_xrefs);
                dedupe_references_in_place(&mut outgoing_xrefs);

                let mut callers = Vec::new();
                let mut callees = Vec::new();
                for edge in callgraph {
                    let is_caller =
                        edge.callee_address >= function_start && edge.callee_address < function_end;
                    let is_callee = edge.caller_address == function.address
                        && edge.callee_address != function.address;
                    if is_caller && is_callee {
                        callers.push(edge.clone());
                        callees.push(edge);
                    } else if is_caller {
                        callers.push(edge);
                    } else if is_callee {
                        callees.push(edge);
                    }
                }
                dedupe_call_edges_in_place(&mut callers);
                dedupe_call_edges_in_place(&mut callees);
                let artifact = ws.write_json_artifact(
                    "application/json",
                    &serde_json::json!({
                        "function": function,
                        "incoming_xrefs": incoming_xrefs,
                        "outgoing_xrefs": outgoing_xrefs,
                        "callers": callers,
                        "callees": callees,
                    }),
                )?;
                let mut agent_brief = derive_function_profile_agent_brief(
                    &function,
                    &callers,
                    &callees,
                    &incoming_xrefs,
                    &outgoing_xrefs,
                );
                self.apply_continuum_to_brief(
                    &ws,
                    "function_profile",
                    function.address,
                    &function.name,
                    &mut agent_brief,
                    None,
                    function
                        .pseudocode
                        .as_ref()
                        .map(|unit| unit.text.as_str()),
                );
                Ok(CapabilityResponse::FunctionProfile(
                    FunctionProfileResponse {
                        function,
                        incoming_xrefs,
                        outgoing_xrefs,
                        callers,
                        callees,
                        artifact: Some(artifact),
                        agent_brief,
                    },
                ))
            }
            CapabilityRequest::DecompileFunction(DecompileFunctionRequest {
                query,
                strategy,
                force_refresh,
            }) => {
                let ws = self.workspace()?;
                let mut function = ws
                    .resolve_function(&query)?
                    .ok_or_else(|| function_lookup_error(&ws, &query))?;
                let inst_count = function
                    .blocks
                    .iter()
                    .map(|b| b.instructions.len())
                    .sum::<usize>();
                let requested = strategy.unwrap_or(DecompileStrategy::Auto);
                let force = force_refresh.unwrap_or(false);
                let strategy_used = revx_analysis::resolve_decompile_strategy(
                    requested,
                    force,
                    function.pseudocode.is_some(),
                    inst_count,
                );
                let mut cache_hit = false;
                let use_cached = matches!(strategy_used, DecompileStrategy::Cached)
                    && function.pseudocode.is_some();
                if use_cached {
                    cache_hit = true;
                } else {
                    let recompose_strategy = if matches!(strategy_used, DecompileStrategy::Cached) {
                        DecompileStrategy::Auto
                    } else {
                        strategy_used
                    };
                    let strategy_key = format!("{recompose_strategy:?}").to_ascii_lowercase();
                    let cached_strategy = if !force {
                        ws.load_strategy_pseudocode(function.address, &strategy_key)
                            .ok()
                            .flatten()
                    } else {
                        None
                    };
                    if let Some(unit) = cached_strategy {
                        cache_hit = true;
                        function.pseudocode = Some(unit);
                    } else {
                        let architecture =
                            revx_analysis::guess_architecture_from_blocks(&function.blocks);
                        let imports = ws.search_imports_paged("", 512, 0).unwrap_or_default();
                        let strings = ws.search_strings_paged("", 800, 0).unwrap_or_default();
                        let unit = revx_analysis::recompose_function_pseudocode_ctx(
                            &function,
                            architecture,
                            recompose_strategy,
                            &imports,
                            &strings,
                        );
                        if let Err(err) = ws.store_function_pseudocode(function.address, &unit) {
                            tracing::warn!("pseudocode write-back failed: {err:#}");
                        }
                        if let Err(err) =
                            ws.store_strategy_pseudocode(function.address, &strategy_key, &unit)
                        {
                            tracing::warn!("strategy pseudocode cache failed: {err:#}");
                        }
                        function.pseudocode = Some(unit);
                    }
                }
                let available_strategies = ws
                    .list_strategy_pseudocode(function.address)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>();
                let artifact = function
                    .pseudocode
                    .as_ref()
                    .map(|unit| ws.write_json_artifact("application/json", unit))
                    .transpose()?;
                let mut agent_brief = derive_decompile_agent_brief(
                    &function.name,
                    function.address,
                    function.pseudocode.as_ref(),
                );
                self.apply_continuum_to_brief(
                    &ws,
                    "decompile_function",
                    function.address,
                    &function.name,
                    &mut agent_brief,
                    None,
                    function
                        .pseudocode
                        .as_ref()
                        .map(|unit| unit.text.as_str()),
                );
                Ok(CapabilityResponse::DecompileFunction(
                    DecompileFunctionResponse {
                        function_name: function.name,
                        address: function.address,
                        pseudocode: function.pseudocode,
                        evidence_ids: function.evidence_ids,
                        artifact,
                        strategy_used,
                        cache_hit,
                        available_strategies,
                        agent_brief,
                    },
                ))
            }
            CapabilityRequest::DecompileCacheStatus(DecompileCacheStatusRequest { query }) => {
                let ws = self.workspace()?;
                let function = ws
                    .resolve_function(&query)?
                    .ok_or_else(|| function_lookup_error(&ws, &query))?;
                let strategies = ws
                    .list_strategy_pseudocode(function.address)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(strategy, unit)| DecompileCacheEntry {
                        strategy,
                        region_count: unit.regions.len(),
                        text_len: unit.text.len(),
                        has_lattice: unit.semantic_lattice.is_some(),
                    })
                    .collect::<Vec<_>>();
                let (function_region_count, function_text_len) = function
                    .pseudocode
                    .as_ref()
                    .map(|unit| (unit.regions.len(), unit.text.len()))
                    .unwrap_or((0, 0));
                Ok(CapabilityResponse::DecompileCacheStatus(
                    DecompileCacheStatusResponse {
                        function_name: function.name,
                        address: function.address,
                        has_function_pseudocode: function.pseudocode.is_some(),
                        function_region_count,
                        function_text_len,
                        strategies,
                    },
                ))
            }
            CapabilityRequest::DisassembleFunction(DisassembleFunctionRequest { query }) => {
                let ws = self.workspace()?;
                let function = ws
                    .resolve_function(&query)?
                    .ok_or_else(|| function_lookup_error(&ws, &query))?;
                let artifact = ws.write_json_artifact("application/json", &function.blocks)?;
                let annotations = ws.write_json_artifact(
                    "application/json",
                    &serde_json::json!({
                        "arguments": function.arguments,
                        "locals": function.locals,
                        "stack_summary": function.stack_summary,
                    }),
                )?;
                Ok(CapabilityResponse::DisassembleFunction(
                    DisassembleFunctionResponse {
                        function_name: function.name,
                        address: function.address,
                        blocks: function.blocks,
                        annotations: Some(annotations),
                        artifact: Some(artifact),
                    },
                ))
            }
            CapabilityRequest::XrefsQuery(XrefsQueryRequest { query }) => {
                let ws = self.workspace()?;
                let references = ws.find_references(&query)?;
                let agent_brief = derive_xrefs_agent_brief(&query, &references);
                Ok(CapabilityResponse::XrefsQuery(XrefsQueryResponse {
                    references,
                    agent_brief,
                }))
            }
            CapabilityRequest::CallgraphSlice(CallgraphSliceRequest { query }) => {
                let ws = self.workspace()?;
                Ok(CapabilityResponse::CallgraphSlice(CallgraphSliceResponse {
                    edges: ws.callgraph_slice(&query)?,
                }))
            }
            CapabilityRequest::StringSearch(StringSearchRequest { pattern, limit, offset }) => {
                let ws = self.workspace()?;
                let lim = limit.unwrap_or(200);
                let off = offset.unwrap_or(0);
                let matches = ws.search_strings_paged(&pattern, lim, off)?;
                let agent_brief = derive_string_search_agent_brief(&pattern, &matches);
                Ok(CapabilityResponse::StringSearch(StringSearchResponse {
                    matches,
                    agent_brief,
                }))
            }
            CapabilityRequest::SearchBytes(SearchBytesRequest { pattern }) => {
                let ws = self.workspace()?;
                Ok(CapabilityResponse::SearchBytes(ws.search_bytes(&pattern)?))
            }
            CapabilityRequest::ObjectContentSearch(request) => {
                let ws = self.workspace()?;
                Ok(CapabilityResponse::ObjectContentSearch(
                    ws.search_object_content(
                        &request.pattern,
                        request
                            .mode
                            .unwrap_or(revx_core::ObjectContentSearchMode::Text),
                        request.query.as_deref(),
                        request.limit.unwrap_or(200),
                        request.per_object_limit.unwrap_or(20),
                        request.max_object_bytes.unwrap_or(16 * 1024 * 1024),
                    )?,
                ))
            }
            CapabilityRequest::ArtifactRead(request) => {
                let ws = self.workspace()?;
                Ok(CapabilityResponse::ArtifactRead(ws.read_artifact_preview(
                    request.relative_path.as_deref(),
                    request.hash_blake3.as_deref(),
                    request.offset.unwrap_or(0),
                    request.max_bytes.unwrap_or(64 * 1024),
                )?))
            }
            CapabilityRequest::ArtifactList(request) => {
                let ws = self.workspace()?;
                Ok(CapabilityResponse::ArtifactList(ws.list_artifacts(
                    request.query.as_deref(),
                    request.content_type.as_deref(),
                    request.role.as_deref(),
                    request.limit.unwrap_or(200),
                    request.include_unreferenced.unwrap_or(false),
                )?))
            }
            CapabilityRequest::EvidencePack(EvidencePackRequest { subject }) => {
                let ws = self.workspace()?;
                let evidence_export =
                    if let Some(evidence_ids) = ws.function_evidence_ids(&subject)? {
                        ws.export_evidence_by_ids(&evidence_ids, 50)?
                    } else {
                        ws.export_evidence_by_subject(&subject, 50)?
                    };
                Ok(CapabilityResponse::EvidencePack(EvidencePackResponse {
                    preview: evidence_export.preview,
                    artifact: evidence_export.artifact,
                }))
            }
            CapabilityRequest::EvidenceGraph(EvidenceGraphRequest {
                subject,
                depth,
                limit,
            }) => {
                let ws = self.workspace()?;
                Ok(CapabilityResponse::EvidenceGraph(ws.evidence_graph(
                    &subject,
                    depth.unwrap_or(2),
                    limit.unwrap_or(200),
                )?))
            }
            CapabilityRequest::SymbolicSolve(request) => {
                let ws = self.workspace()?;
                Ok(CapabilityResponse::SymbolicSolve(run_symbolic_solve(
                    &ws, request,
                )?))
            }
            CapabilityRequest::AnalysisBrief(request) => {
                Ok(CapabilityResponse::AnalysisBrief(run_analysis_brief(
                    &self.workspace()?,
                    request,
                )?))
            }
            CapabilityRequest::InvestigationRun(request) => {
                let ws = self.workspace()?;
                Ok(CapabilityResponse::InvestigationRun(run_investigation(
                    &ws, request,
                )?))
            }
            CapabilityRequest::IbcStatus(request) => {
                Ok(CapabilityResponse::IbcStatus(self.run_ibc_status(request)?))
            }
            CapabilityRequest::IbcAdvance(request) => {
                Ok(CapabilityResponse::IbcAdvance(self.run_ibc_advance(request)?))
            }
            CapabilityRequest::HypothesisCreate(HypothesisCreateRequest {
                title,
                notes,
                evidence_ids,
            }) => {
                let ws = self.workspace()?;
                Ok(CapabilityResponse::HypothesisCreate(
                    HypothesisCreateResponse {
                        hypothesis: ws.create_hypothesis(&title, &notes, &evidence_ids)?,
                    },
                ))
            }
            CapabilityRequest::HypothesisUpdate(HypothesisUpdateRequest {
                id,
                title,
                notes,
                evidence_ids,
            }) => {
                let ws = self.workspace()?;
                Ok(CapabilityResponse::HypothesisUpdate(
                    HypothesisUpdateResponse {
                        hypothesis: ws.update_hypothesis(
                            &id,
                            title.as_deref(),
                            notes.as_deref(),
                            evidence_ids,
                        )?,
                    },
                ))
            }
            CapabilityRequest::ReportGenerate(ReportGenerateRequest { topic }) => {
                let ws = self.workspace()?;
                let evidence = ws.collect_report_evidence_by_subject(&topic, 8)?;
                let report = Report {
                    id: uuid::Uuid::new_v4().to_string(),
                    topic: topic.clone(),
                    body: format!(
                        "# {topic}\n\n## Summary\n\n- Evidence count: {}\n- Function evidence: {}\n- Variable/stack evidence: {}\n- Type/debug evidence: {}\n- Structured pseudocode evidence: {}\n\n## Functions\n{}\n\n## Variables And Stack\n{}\n\n## Types And Debug Import\n{}\n\n## Structured Pseudocode\n{}\n",
                        evidence.count,
                        evidence.function_summaries.len(),
                        evidence.variable_summaries.len(),
                        evidence.type_summaries.len(),
                        evidence.pseudocode_summaries.len(),
                        if evidence.function_summaries.is_empty() {
                            "- None".to_string()
                        } else {
                            evidence.function_summaries.join("\n")
                        },
                        if evidence.variable_summaries.is_empty() {
                            "- None".to_string()
                        } else {
                            evidence.variable_summaries.join("\n")
                        },
                        if evidence.type_summaries.is_empty() {
                            "- None".to_string()
                        } else {
                            evidence.type_summaries.join("\n")
                        },
                        if evidence.pseudocode_summaries.is_empty() {
                            "- None".to_string()
                        } else {
                            evidence.pseudocode_summaries.join("\n")
                        }
                    ),
                    evidence_ids: evidence.evidence_ids,
                };
                let artifact = ws.save_report(&report)?;
                Ok(CapabilityResponse::ReportGenerate(ReportGenerateResponse {
                    report,
                    artifact: Some(artifact),
                }))
            }
            CapabilityRequest::TraceImport(TraceImportRequest { events }) => {
                let ws = self.workspace()?;
                let imported = events.len();
                let material = ws.save_trace_events(&events)?;
                Ok(CapabilityResponse::TraceImport(TraceImportResponse {
                    imported,
                    evidence_count: material.evidence_ids.len(),
                    evidence_ids: material.evidence_ids,
                    artifact: Some(material.artifact),
                }))
            }
            CapabilityRequest::TraceQuery(TraceQueryRequest { kind, limit }) => {
                let ws = self.workspace()?;
                let events = ws.query_traces(kind.as_deref(), limit.unwrap_or(100))?;
                let artifact = if events.len() > 50 {
                    Some(ws.write_json_artifact("application/json", &events)?)
                } else {
                    None
                };
                Ok(CapabilityResponse::TraceQuery(TraceQueryResponse {
                    events,
                    artifact,
                }))
            }
        }
    }
}

pub async fn serve_ipc(workspace_root: PathBuf) -> Result<()> {
    let _ = revx_analysis::resource::ensure_process_resource_limits();
    let endpoint = socket_path(&workspace_root);
    #[cfg(unix)]
    {
        if endpoint.exists() {
            let _ = std::fs::remove_file(&endpoint);
        }
        let listener = tokio::net::UnixListener::bind(&endpoint)
            .with_context(|| format!("failed to bind {}", endpoint.display()))?;
        let service = CapabilityService::new(workspace_root);
        loop {
            let (stream, _) = listener.accept().await?;
            let service = service.clone();
            tokio::spawn(async move {
                if let Err(err) = handle_unix_stream(service, stream).await {
                    warn!("capability stream failed: {err:#}");
                }
            });
        }
    }
    #[cfg(windows)]
    {
        serve_windows_named_pipe(workspace_root, &endpoint).await
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        let _ = endpoint;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:43179").await?;
        let service = CapabilityService::new(workspace_root);
        loop {
            let (stream, _) = listener.accept().await?;
            let service = service.clone();
            tokio::spawn(async move {
                if let Err(err) = handle_tcp_stream(service, stream).await {
                    warn!("capability stream failed: {err:#}");
                }
            });
        }
    }
}

pub async fn serve_stdio(workspace_root: PathBuf) -> Result<()> {
    let service = CapabilityService::new(workspace_root);
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin).lines();
    let mut writer = tokio::io::BufWriter::new(stdout);

    while let Some(line) = reader.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let envelope: CapabilityEnvelope = serde_json::from_str(&line)
            .with_context(|| "failed to parse capability envelope from stdio")?;
        let reply = dispatch_envelope(&service, envelope);
        writer
            .write_all(serde_json::to_string(&reply)?.as_bytes())
            .await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }

    Ok(())
}

pub fn socket_path(workspace_root: &Path) -> PathBuf {
    #[cfg(unix)]
    {
        workspace_root.join(".revx").join("daemon.sock")
    }
    #[cfg(windows)]
    {
        workspace_root.join(".revx").join("daemon.pipe")
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        workspace_root.join(".revx").join("daemon.tcp")
    }
}

pub fn windows_pipe_name(workspace_root: &Path) -> String {
    let key = workspace_root
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.to_path_buf());
    let digest = blake3::hash(key.to_string_lossy().as_bytes()).to_hex();
    format!(r"\.\pipe
evx-{}", &digest[..16])
}

pub async fn send_ipc_request(
    workspace_root: &Path,
    request: CapabilityRequest,
) -> Result<CapabilityResponse> {
    let envelope = CapabilityEnvelope {
        id: Some(uuid::Uuid::new_v4().to_string()),
        request,
    };

    #[cfg(unix)]
    {
        let stream = tokio::net::UnixStream::connect(socket_path(workspace_root)).await?;
        send_stream_request(stream, envelope).await
    }
    #[cfg(windows)]
    {
        let name = read_windows_pipe_name(workspace_root)?;
        let stream = tokio::net::windows::named_pipe::ClientOptions::new().open(name)?;
        send_stream_request(stream, envelope).await
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        let stream = TcpStream::connect("127.0.0.1:43179").await?;
        send_stream_request(stream, envelope).await
    }
}

#[cfg(windows)]
fn read_windows_pipe_name(workspace_root: &Path) -> Result<String> {
    let marker = socket_path(workspace_root);
    if marker.exists() {
        let raw = std::fs::read_to_string(&marker).unwrap_or_default();
        let name = raw.trim();
        if !name.is_empty() {
            return Ok(name.to_string());
        }
    }
    Ok(windows_pipe_name(workspace_root))
}

#[cfg(windows)]
async fn serve_windows_named_pipe(workspace_root: PathBuf, marker: &Path) -> Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;
    if let Some(parent) = marker.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let pipe_name = windows_pipe_name(&workspace_root);
    std::fs::write(marker, format!("{pipe_name}
"))
        .with_context(|| format!("failed to write {}", marker.display()))?;
    let service = CapabilityService::new(workspace_root);
    let mut first = true;
    loop {
        let server = if first {
            first = false;
            ServerOptions::new()
                .first_pipe_instance(true)
                .create(&pipe_name)
        } else {
            ServerOptions::new().create(&pipe_name)
        }
        .with_context(|| format!("failed to create named pipe {pipe_name}"))?;
        server.connect().await?;
        let service = service.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_stream(service, server).await {
                warn!("capability named-pipe stream failed: {err:#}");
            }
        });
    }
}

pub fn dispatch_envelope(
    service: &CapabilityService,
    envelope: CapabilityEnvelope,
) -> CapabilityReply {
    match service.dispatch(envelope.request) {
        Ok(response) => CapabilityReply {
            id: envelope.id,
            response: Some(response),
            error: None,
        },
        Err(err) => CapabilityReply {
            id: envelope.id,
            response: None,
            error: Some(CapabilityError {
                code: "capability_error".to_string(),
                message: err.to_string(),
            }),
        },
    }
}

pub async fn serve_mcp_stdio(workspace_root: PathBuf) -> Result<()> {
    let _ = revx_analysis::resource::ensure_process_resource_limits();
    let service = CapabilityService::new(workspace_root);
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin).lines();
    let mut writer = tokio::io::BufWriter::new(stdout);

    while let Some(line) = reader.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let request: serde_json::Value = serde_json::from_str(&line)?;
        let response = handle_mcp_jsonrpc(&service, request);
        if let Some(response) = response {
            writer
                .write_all(serde_json::to_string(&response)?.as_bytes())
                .await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
        }
    }

    Ok(())
}

#[cfg(unix)]
async fn handle_unix_stream(
    service: CapabilityService,
    stream: tokio::net::UnixStream,
) -> Result<()> {
    handle_stream(service, stream).await
}

#[cfg(all(not(unix), not(windows)))]
async fn handle_tcp_stream(service: CapabilityService, stream: TcpStream) -> Result<()> {
    handle_stream(service, stream).await
}

async fn handle_stream<S>(service: CapabilityService, stream: S) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let envelope: CapabilityEnvelope = serde_json::from_str(&line)?;
        let reply = dispatch_envelope(&service, envelope);
        writer
            .write_all(serde_json::to_string(&reply)?.as_bytes())
            .await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }
    Ok(())
}

async fn send_stream_request<S>(
    stream: S,
    envelope: CapabilityEnvelope,
) -> Result<CapabilityResponse>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    writer
        .write_all(format!("{}\n", serde_json::to_string(&envelope)?).as_bytes())
        .await?;
    writer.flush().await?;

    let mut lines = BufReader::new(reader).lines();
    let line = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow::anyhow!("daemon closed connection without reply"))?;
    let reply: CapabilityReply = serde_json::from_str(&line)?;
    if let Some(error) = reply.error {
        anyhow::bail!("{}: {}", error.code, error.message);
    }
    reply
        .response
        .ok_or_else(|| anyhow::anyhow!("missing capability response"))
}

fn handle_mcp_jsonrpc(
    service: &CapabilityService,
    request: serde_json::Value,
) -> Option<serde_json::Value> {
    let request_id = request
        .get("id")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let method = request.get("method")?.as_str()?.to_string();
    let params = request
        .get("params")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    match method.as_str() {
        "initialize" => Some(jsonrpc_result(
            request_id,
            serde_json::json!({
                "protocolVersion": "2024-11-05",
                "serverInfo": {
                    "name": "revx",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "capabilities": {
                    "tools": {}
                }
            }),
        )),
        "ping" => Some(jsonrpc_result(
            request_id,
            serde_json::json!({ "ok": true }),
        )),
        "notifications/initialized" => None,
        "tools/list" => Some(jsonrpc_result(
            request_id,
            serde_json::json!({
                "tools": mcp_tools_manifest(),
            }),
        )),
        "tools/call" => {
            let tool_name = params
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));
            let capability_request = match tool_name_to_request(tool_name, arguments) {
                Ok(value) => value,
                Err(err) => return Some(jsonrpc_error(request_id, -32602, &err.to_string())),
            };
            match service.dispatch(capability_request) {
                Ok(response) => Some(jsonrpc_result(
                    request_id,
                    serde_json::json!({
                        "content": [
                            {
                                "type": "text",
                                "text": mcp_response_summary(&response),
                            }
                        ],
                        "structuredContent": response,
                        "isError": false,
                    }),
                )),
                Err(err) => Some(jsonrpc_result(
                    request_id,
                    serde_json::json!({
                        "content": [
                            {
                                "type": "text",
                                "text": err.to_string(),
                            }
                        ],
                        "isError": true,
                    }),
                )),
            }
        }
        "resources/list" => Some(jsonrpc_result(
            request_id,
            serde_json::json!({ "resources": [] }),
        )),
        "resourceTemplates/list" => Some(jsonrpc_result(
            request_id,
            serde_json::json!({ "resourceTemplates": [] }),
        )),
        "prompts/list" => Some(jsonrpc_result(
            request_id,
            serde_json::json!({ "prompts": [] }),
        )),
        _ => Some(jsonrpc_error(request_id, -32601, "method not found")),
    }
}

fn jsonrpc_result(id: serde_json::Value, result: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })
}

fn jsonrpc_error(id: serde_json::Value, code: i64, message: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        }
    })
}

fn tool_name_to_request(name: &str, arguments: serde_json::Value) -> Result<CapabilityRequest> {
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

fn parse_empty_or_default<T>(arguments: serde_json::Value) -> Result<T>
where
    T: serde::de::DeserializeOwned + Default,
{
    match arguments {
        serde_json::Value::Null => Ok(T::default()),
        serde_json::Value::Object(map) if map.is_empty() => Ok(T::default()),
        other => Ok(serde_json::from_value(other)?),
    }
}

fn mcp_response_summary(response: &CapabilityResponse) -> String {
    const MAX_CHARS: usize = 24_000;
    let body = match response {
        CapabilityResponse::ProjectOpen(payload) => format!(
            "# project_open\nworkspace: {}\nproject: {}\nschema: {}",
            payload.workspace_root,
            payload.project.name,
            payload.project.schema_version
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
                    plugin.description.as_deref().unwrap_or(plugin.name.as_str()),
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
            if !payload.agent_brief.headline.is_empty() || !payload.agent_brief.next_actions.is_empty()
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
                        entry.strategy,
                        entry.region_count,
                        entry.text_len,
                        entry.has_lattice
                    ));
                }
            }
            lines.push(
                "
next: decompile_function(query, strategy) | function_profile(query)".to_string(),
            );
            lines.join("
")
        }
        CapabilityResponse::DisassembleFunction(payload) => {
            render_disassembly(payload)
        }
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
            if !payload.agent_brief.headline.is_empty() || !payload.agent_brief.next_actions.is_empty()
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
            if !payload.agent_brief.headline.is_empty() || !payload.agent_brief.next_actions.is_empty()
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
                    truncate_chars(item.preview_text.as_deref().unwrap_or(&item.preview_hex), 160)
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
            lines.join("
")
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
            lines.join("
")
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
                format!("\n## Body\n{}", truncate_chars(&payload.report.body, 10_000)),
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

fn truncate_chars(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    let mut out = input.chars().take(max_chars).collect::<String>();
    out.push_str("\n...[truncated]");
    out
}

fn format_id_list(ids: &[String], limit: usize) -> String {
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

fn format_analysis_summary(summary: &revx_core::AnalysisSummary) -> String {
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

fn format_agent_brief_section(brief: &AgentInteractionBrief) -> String {
    let mut lines = vec![
        "\n## Agent Brief".to_string(),
        format!("headline: {}", if brief.headline.is_empty() { "-" } else { &brief.headline }),
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

fn render_function_profile(payload: &FunctionProfileResponse) -> String {
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
        function_pseudocode_digest(function.pseudocode.as_ref(), &payload.callees, &payload.callers)
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

fn render_disassembly(payload: &DisassembleFunctionResponse) -> String {
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
        lines.push(format!("\nannotations_artifact: {}", annotations.relative_path));
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


fn mcp_tools_manifest() -> Vec<serde_json::Value> {
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

fn tool_manifest(
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

fn run_symbolic_solve(
    ws: &Workspace,
    request: SymbolicSolveRequest,
) -> Result<SymbolicSolveResponse> {
    let mut warnings = Vec::new();
    let mut names = BTreeSet::new();
    for variable in &request.variables {
        if variable.name.trim().is_empty() {
            anyhow::bail!("symbolic variable name cannot be empty");
        }
        if !names.insert(variable.name.clone()) {
            anyhow::bail!("duplicate symbolic variable: {}", variable.name);
        }
    }
    for constraint in &request.constraints {
        validate_symbolic_expr(&constraint.left, &names)?;
        validate_symbolic_expr(&constraint.right, &names)?;
    }

    let mut domains = Vec::new();
    for variable in &request.variables {
        let values = symbolic_domain_values(&variable.domain)?;
        if values.is_empty() {
            warnings.push(format!("variable {} has an empty domain", variable.name));
        }
        domains.push((variable.name.clone(), values));
    }

    let max_solutions = request.max_solutions.unwrap_or(1).clamp(1, 100);
    let iteration_limit = request
        .iteration_limit
        .unwrap_or(100_000)
        .clamp(1, 5_000_000);
    let mut checked_assignments = 0usize;
    let mut solutions = Vec::new();
    let mut assignment = BTreeMap::new();
    let mut stopped_by_limit = false;
    enumerate_symbolic_assignments(
        &domains,
        0,
        &mut assignment,
        &request.constraints,
        max_solutions,
        iteration_limit,
        &mut checked_assignments,
        &mut solutions,
        &mut stopped_by_limit,
    )?;
    if stopped_by_limit {
        warnings.push(format!(
            "iteration limit {iteration_limit} reached before the search space was exhausted"
        ));
    }

    let status = if !solutions.is_empty() {
        SymbolicSolveStatus::Sat
    } else if stopped_by_limit {
        SymbolicSolveStatus::Unknown
    } else {
        SymbolicSolveStatus::Unsat
    };
    let case_id = symbolic_case_id(&request)?;
    let placeholder_artifact = revx_core::ArtifactHandle {
        hash_blake3: String::new(),
        relative_path: String::new(),
        size: 0,
        content_type: "application/json".to_string(),
    };
    let response = SymbolicSolveResponse {
        case_id,
        subject: request.subject.clone(),
        status,
        constraint_count: request.constraints.len(),
        checked_assignments,
        solutions,
        warnings,
        evidence_id: String::new(),
        artifact: placeholder_artifact,
    };
    ws.save_symbolic_solution(response, &request.variables, &request.constraints)
}

fn symbolic_domain_values(domain: &SymbolicDomain) -> Result<Vec<i64>> {
    match domain {
        SymbolicDomain::IntRange { min, max } => {
            if min > max {
                anyhow::bail!("invalid int_range domain: min {min} > max {max}");
            }
            let len = (*max as i128 - *min as i128 + 1) as usize;
            if len > 100_000 {
                anyhow::bail!("int_range domain is too large for bounded solver: {min}..={max}");
            }
            Ok((*min..=*max).collect())
        }
        SymbolicDomain::IntValues { values } => {
            let mut deduped = values.clone();
            deduped.sort();
            deduped.dedup();
            Ok(deduped)
        }
    }
}

fn validate_symbolic_expr(expr: &SymbolicLinearExpr, variables: &BTreeSet<String>) -> Result<()> {
    for term in &expr.terms {
        if !variables.contains(&term.variable) {
            anyhow::bail!("constraint references unknown variable: {}", term.variable);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn enumerate_symbolic_assignments(
    domains: &[(String, Vec<i64>)],
    index: usize,
    assignment: &mut BTreeMap<String, i64>,
    constraints: &[SymbolicConstraint],
    max_solutions: usize,
    iteration_limit: usize,
    checked_assignments: &mut usize,
    solutions: &mut Vec<BTreeMap<String, i64>>,
    stopped_by_limit: &mut bool,
) -> Result<()> {
    if solutions.len() >= max_solutions || *stopped_by_limit {
        return Ok(());
    }
    if index == domains.len() {
        if *checked_assignments >= iteration_limit {
            *stopped_by_limit = true;
            return Ok(());
        }
        *checked_assignments += 1;
        if constraints
            .iter()
            .all(|constraint| symbolic_constraint_holds(constraint, assignment))
        {
            solutions.push(assignment.clone());
        }
        return Ok(());
    }

    let (name, values) = &domains[index];
    for value in values {
        assignment.insert(name.clone(), *value);
        enumerate_symbolic_assignments(
            domains,
            index + 1,
            assignment,
            constraints,
            max_solutions,
            iteration_limit,
            checked_assignments,
            solutions,
            stopped_by_limit,
        )?;
        if solutions.len() >= max_solutions || *stopped_by_limit {
            break;
        }
    }
    assignment.remove(name);
    Ok(())
}

fn symbolic_constraint_holds(
    constraint: &SymbolicConstraint,
    assignment: &BTreeMap<String, i64>,
) -> bool {
    let left = evaluate_symbolic_expr(&constraint.left, assignment);
    let right = evaluate_symbolic_expr(&constraint.right, assignment);
    match constraint.op {
        SymbolicConstraintOp::Eq => left == right,
        SymbolicConstraintOp::Ne => left != right,
        SymbolicConstraintOp::Lt => left < right,
        SymbolicConstraintOp::Le => left <= right,
        SymbolicConstraintOp::Gt => left > right,
        SymbolicConstraintOp::Ge => left >= right,
    }
}

fn evaluate_symbolic_expr(expr: &SymbolicLinearExpr, assignment: &BTreeMap<String, i64>) -> i64 {
    expr.terms.iter().fold(expr.constant, |acc, term| {
        acc + term.coefficient * assignment.get(&term.variable).copied().unwrap_or_default()
    })
}

fn symbolic_case_id(request: &SymbolicSolveRequest) -> Result<String> {
    let bytes = serde_json::to_vec(request)?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}


fn daemon_agent_next_action(
    tool: &str,
    reason: impl Into<String>,
    priority: u8,
    query: Option<String>,
    label: Option<&str>,
    args: serde_json::Value,
) -> AgentNextAction {
    AgentNextAction {
        tool: tool.to_string(),
        reason: reason.into(),
        priority,
        query,
        label: label.map(ToOwned::to_owned),
        args,
    }
}

fn derive_daemon_object_next_actions(
    object: &UniversalObject,
    analyses: &[ObjectAnalysisSummary],
) -> Vec<AgentNextAction> {
    let query = object
        .path
        .clone()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| object.id.clone());
    let mut actions = Vec::new();
    let mut seen = BTreeSet::<String>::new();
    let mut push = |action: AgentNextAction| {
        let key = format!(
            "{}|{}|{}",
            action.tool,
            action.query.as_deref().unwrap_or(""),
            action.reason
        );
        if seen.insert(key) {
            actions.push(action);
        }
    };
    for analysis in analyses {
        match analysis.analyzer.as_str() {
            "auto_expand" => {
                let count = analysis
                    .details
                    .get("expanded_count")
                    .and_then(|value| value.as_u64())
                    .unwrap_or(0);
                if count > 0 {
                    push(daemon_agent_next_action(
                        "object_analyze",
                        format!("Inspect {count} auto-expanded child object(s)"),
                        90,
                        Some(query.clone()),
                        Some("inspect expanded children"),
                        serde_json::json!({ "query": query, "analyzers": ["auto"] }),
                    ));
                }
            }
            "auto_dig" => push(daemon_agent_next_action(
                "object_carve_identify",
                "Identify carved embedded signatures as first-class objects",
                84,
                Some(query.clone()),
                Some("carve+identify"),
                serde_json::json!({ "query": query }),
            )),
            "dotnet_metadata" => push(daemon_agent_next_action(
                "evidence_pack",
                "Collect .NET metadata/risk evidence for agent reasoning",
                78,
                Some(query.clone()),
                Some("package .NET evidence"),
                serde_json::json!({ "subject": query, "limit": 50 }),
            )),
            "unknown_blob" => {
                for followup in analysis
                    .details
                    .get("suggested_followups")
                    .and_then(|value| value.as_array())
                    .into_iter()
                    .flatten()
                    .filter_map(|value| value.as_str())
                    .take(3)
                {
                    match followup {
                        "object_carve_signatures" => push(daemon_agent_next_action(
                            "object_carve_signatures",
                            "Carve high-confidence embedded signatures from opaque blob",
                            85,
                            Some(query.clone()),
                            Some("carve embeds"),
                            serde_json::json!({ "query": query, "limit": 16, "min_confidence": 0.9 }),
                        )),
                        "object_scan_signatures" => push(daemon_agent_next_action(
                            "object_scan_signatures",
                            "Map embedded signature offsets before carving",
                            70,
                            Some(query.clone()),
                            Some("scan signatures"),
                            serde_json::json!({ "query": query, "limit": 32 }),
                        )),
                        "structured_text" => push(daemon_agent_next_action(
                            "object_analyze",
                            "Object looks text-like; run structured text analyzer",
                            72,
                            Some(query.clone()),
                            Some("structured text pass"),
                            serde_json::json!({ "query": query, "analyzers": ["structured_text"] }),
                        )),
                        "entropy_review" => push(daemon_agent_next_action(
                            "object_analyze",
                            "High entropy region warrants histogram/strings review",
                            60,
                            Some(query.clone()),
                            Some("entropy review"),
                            serde_json::json!({
                                "query": query,
                                "analyzers": ["byte_histogram", "strings"]
                            }),
                        )),
                        "object_analyze"
                        | "object_carve_identify"
                        | "object_analyze_binary"
                        | "object_pipeline"
                        | "evidence_pack"
                        | "evidence_graph"
                        | "string_search"
                        | "function_search"
                        | "trace_query" => push(daemon_agent_next_action(
                            followup,
                            format!("Unknown blob suggested follow-up: {followup}"),
                            55,
                            Some(query.clone()),
                            Some("blob follow-up"),
                            serde_json::json!({ "query": query, "subject": query }),
                        )),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    drop(push);
    if actions.is_empty() {
        actions.push(daemon_agent_next_action(
            "evidence_graph",
            "Review evidence graph around this object",
            40,
            Some(query.clone()),
            Some("review graph"),
            serde_json::json!({ "subject": query, "depth": 2, "limit": 100 }),
        ));
    }
    actions.sort_by(|a, b| b.priority.cmp(&a.priority));
    actions.truncate(8);
    actions
}

fn derive_daemon_object_agent_brief(
    object: &UniversalObject,
    analyses: &[ObjectAnalysisSummary],
    next_actions: &[AgentNextAction],
) -> AgentInteractionBrief {
    let key_findings = analyses
        .iter()
        .filter(|item| item.status != ObjectAnalysisStatus::Skipped)
        .take(8)
        .map(|item| format!("{}: {}", item.analyzer, item.summary))
        .collect::<Vec<_>>();
    let headline = next_actions
        .first()
        .map(|action| {
            format!(
                "{} → {}",
                object.display_name,
                action.label.as_deref().unwrap_or(action.tool.as_str())
            )
        })
        .unwrap_or_else(|| format!("{} analyzed", object.display_name));
    AgentInteractionBrief {
        headline,
        key_findings,
        open_questions: next_actions
            .iter()
            .filter(|action| action.priority >= 80)
            .take(3)
            .map(|action| action.reason.clone())
            .collect(),
        next_actions: next_actions.to_vec(),
        stop_conditions: vec![
            "Execute exactly one top next_action, then reassess".to_string(),
            "Stop after top action if no new child evidence is created".to_string(),
            "Prefer next_actions[0].args over inventing tool parameters".to_string(),
        ],
        semantic_lattice: None,
    }
}

fn derive_pipeline_next_actions(
    root_id: &str,
    object_count: usize,
    carved_object_count: usize,
    identified_embedded_object_count: usize,
    binary_candidate_count: usize,
    analyzed_binary_count: usize,
    failed_step_count: usize,
    steps: &[ObjectPipelineStep],
) -> Vec<AgentNextAction> {
    let mut actions = Vec::new();
    if binary_candidate_count > analyzed_binary_count {
        actions.push(daemon_agent_next_action(
            "object_analyze_binary",
            format!(
                "{} native binary candidate(s) remain after pipeline",
                binary_candidate_count.saturating_sub(analyzed_binary_count)
            ),
            92,
            Some(root_id.to_string()),
            Some("analyze remaining binaries"),
            serde_json::json!({ "query": root_id, "profile": "fast" }),
        ));
    }
    if carved_object_count > 0 || identified_embedded_object_count > 0 {
        actions.push(daemon_agent_next_action(
            "evidence_graph",
            format!(
                "Pipeline discovered {object_count} object(s); traverse evidence graph for child focus"
            ),
            85,
            Some(root_id.to_string()),
            Some("graph triage children"),
            serde_json::json!({ "subject": root_id, "depth": 3, "limit": 200 }),
        ));
    }
    if failed_step_count > 0 {
        actions.push(daemon_agent_next_action(
            "object_analyze",
            format!("{failed_step_count} pipeline step(s) failed; re-run focused object analysis"),
            70,
            Some(root_id.to_string()),
            Some("retry failed steps"),
            serde_json::json!({ "query": root_id, "analyzers": ["auto"] }),
        ));
    }
    if actions.is_empty() {
        let partial = steps
            .iter()
            .filter(|step| step.status == ObjectAnalysisStatus::Partial)
            .count();
        if partial > 0 {
            actions.push(daemon_agent_next_action(
                "object_analyze",
                format!("{partial} partial step(s); deepen analysis on root/children"),
                60,
                Some(root_id.to_string()),
                Some("deepen partial results"),
                serde_json::json!({ "query": root_id }),
            ));
        } else {
            actions.push(daemon_agent_next_action(
                "investigation_run",
                "Pipeline complete; package investigation brief for agent handoff",
                55,
                Some(root_id.to_string()),
                Some("package investigation"),
                serde_json::json!({ "subject": root_id }),
            ));
        }
    }
    actions.truncate(8);
    actions
}

fn derive_pipeline_agent_brief(
    root_id: &str,
    object_count: usize,
    analyzed_object_count: usize,
    carved_object_count: usize,
    binary_candidate_count: usize,
    analyzed_binary_count: usize,
    failed_step_count: usize,
    next_actions: &[AgentNextAction],
) -> AgentInteractionBrief {
    let headline = if let Some(top) = next_actions.first() {
        format!(
            "pipeline {root_id} p{} → {} (`{}`)",
            top.priority,
            top.label.as_deref().unwrap_or(top.tool.as_str()),
            top.tool
        )
    } else {
        format!(
            "pipeline {root_id}: objects={object_count} analyzed={analyzed_object_count} carved={carved_object_count} binaries={analyzed_binary_count}/{binary_candidate_count}"
        )
    };
    AgentInteractionBrief {
        headline,
        key_findings: vec![
            format!("objects_total={object_count}"),
            format!("objects_analyzed={analyzed_object_count}"),
            format!("carved_objects={carved_object_count}"),
            format!("binaries_analyzed={analyzed_binary_count}/{binary_candidate_count}"),
            format!("failed_steps={failed_step_count}"),
        ],
        open_questions: next_actions
            .iter()
            .filter(|action| action.priority >= 70)
            .take(3)
            .map(|action| action.reason.clone())
            .collect(),
        next_actions: next_actions.to_vec(),
        stop_conditions: vec![
            "Execute next_actions[0] once, then reassess children/binaries".to_string(),
            "Stop if failed_steps==0 and no binary candidates remain unanalyzed".to_string(),
            "Do not re-run full pipeline unless inputs or depth budget change".to_string(),
        ],
        semantic_lattice: None,
    }
}

fn derive_investigation_next_actions(
    subject: &str,
    pipeline: Option<&ObjectPipelineResponse>,
    evidence_count: usize,
    graph_nodes: usize,
    trace_count: usize,
) -> Vec<AgentNextAction> {
    let mut actions = Vec::new();
    if let Some(pipeline) = pipeline {
        actions.extend(pipeline.next_actions.iter().cloned());
        if pipeline.binary_candidate_count > pipeline.analyzed_binary_count {
            actions.push(daemon_agent_next_action(
                "object_analyze_binary",
                "Investigation pipeline left native binary candidates unanalyzed",
                93,
                Some(subject.to_string()),
                Some("finish binary analysis"),
                serde_json::json!({ "query": subject, "profile": "fast" }),
            ));
        }
        if pipeline.carved_object_count > 0 {
            actions.push(daemon_agent_next_action(
                "object_analyze",
                "Review carved/expanded children discovered by pipeline",
                88,
                Some(subject.to_string()),
                Some("inspect children"),
                serde_json::json!({ "query": subject, "analyzers": ["auto"] }),
            ));
        }
    }
    if evidence_count > 0 {
        actions.push(daemon_agent_next_action(
            "evidence_pack",
            format!("Package top evidence for subject ({evidence_count} item(s))"),
            75,
            Some(subject.to_string()),
            Some("build evidence pack"),
            serde_json::json!({ "subject": subject, "limit": 50 }),
        ));
    }
    if graph_nodes > 0 {
        actions.push(daemon_agent_next_action(
            "evidence_graph",
            format!("Traverse evidence graph ({graph_nodes} node(s)) for pivot points"),
            72,
            Some(subject.to_string()),
            Some("graph pivot"),
            serde_json::json!({ "subject": subject, "depth": 3, "limit": 200 }),
        ));
    }
    if trace_count > 0 {
        actions.push(daemon_agent_next_action(
            "trace_query",
            format!("Correlate {trace_count} runtime trace event(s) with static findings"),
            70,
            Some(subject.to_string()),
            Some("trace correlation"),
            serde_json::json!({ "limit": 50 }),
        ));
    }
    if actions.is_empty() {
        actions.push(daemon_agent_next_action(
            "object_pipeline",
            "No dense findings yet; run object pipeline to discover children and embeds",
            65,
            Some(subject.to_string()),
            Some("run discovery pipeline"),
            serde_json::json!({ "path": subject }),
        ));
    }
    actions.sort_by(|a, b| b.priority.cmp(&a.priority).then_with(|| a.tool.cmp(&b.tool)));
    let mut dedup = BTreeSet::new();
    actions.retain(|action| {
        dedup.insert(format!(
            "{}|{}|{}",
            action.tool,
            action.query.as_deref().unwrap_or(""),
            action.reason
        ))
    });
    actions.truncate(8);
    actions
}

fn derive_investigation_agent_brief(
    subject: &str,
    summary: &str,
    pipeline: Option<&ObjectPipelineResponse>,
    evidence_preview: &[Evidence],
    next_actions: &[AgentNextAction],
    evidence_count: usize,
    graph_nodes: usize,
    trace_count: usize,
) -> AgentInteractionBrief {
    let mut key_findings = vec![
        format!("evidence_count={evidence_count}"),
        format!("graph_nodes={graph_nodes}"),
        format!("trace_events={trace_count}"),
    ];
    if let Some(pipeline) = pipeline {
        key_findings.push(format!(
            "pipeline objects={} carved={} binaries={}/{}",
            pipeline.object_count,
            pipeline.carved_object_count,
            pipeline.analyzed_binary_count,
            pipeline.binary_candidate_count
        ));
    }
    for evidence in evidence_preview.iter().take(5) {
        key_findings.push(format!("{}: {}", evidence.kind, evidence.summary));
    }
    key_findings.truncate(10);
    AgentInteractionBrief {
        headline: next_actions
            .first()
            .map(|action| {
                format!(
                    "{subject} p{} → {} (`{}`)",
                    action.priority,
                    action.label.as_deref().unwrap_or(action.tool.as_str()),
                    action.tool
                )
            })
            .unwrap_or_else(|| format!("{subject} investigation ready")),
        key_findings,
        open_questions: next_actions
            .iter()
            .filter(|action| action.priority >= 75)
            .take(4)
            .map(|action| action.reason.clone())
            .collect(),
        next_actions: next_actions.to_vec(),
        stop_conditions: vec![
            "Execute next_actions[0] with its args, then reassess once".to_string(),
            "Stop when top next_action priority < 60 and no new pipeline children appear".to_string(),
            "Prefer one high-priority action over breadth-first tool spam".to_string(),
            "Do not re-run investigation_run unless inputs or child objects changed".to_string(),
            summary.to_string(),
        ],
        semantic_lattice: None,
    }
}



fn run_analysis_brief(
    ws: &Workspace,
    request: AnalysisBriefRequest,
) -> Result<AnalysisBriefResponse> {
    let query = request.query.trim().to_string();
    if query.is_empty() {
        anyhow::bail!("analysis_brief query must not be empty");
    }
    let string_limit = request.string_limit.unwrap_or(12).clamp(1, 40);
    let function_limit = request.function_limit.unwrap_or(12).clamp(1, 40);
    let hot_limit = request.hot_function_limit.unwrap_or(6).clamp(1, 16);
    let xref_limit = request.xref_limit.unwrap_or(24).clamp(1, 80);
    let include_pseudocode = request.include_pseudocode.unwrap_or(true);
    let query_tokens = analysis_query_tokens(&query);

    let mut function_hits = Vec::new();
    let mut seen_fn = BTreeSet::new();
    for token in std::iter::once(query.as_str()).chain(query_tokens.iter().map(String::as_str)) {
        for hit in ws.search_functions_paged(token, function_limit, 0)? {
            if seen_fn.insert(hit.address) {
                function_hits.push(hit);
            }
        }
    }
    function_hits.truncate(function_limit);

    let mut raw_strings = Vec::new();
    let mut seen_str = BTreeSet::new();
    for token in std::iter::once(query.as_str()).chain(query_tokens.iter().map(String::as_str)) {
        for item in ws.search_strings_paged(token, string_limit, 0)? {
            let key = (item.address.unwrap_or(0), item.value.clone());
            if seen_str.insert(key) {
                raw_strings.push(item);
            }
        }
    }
    raw_strings.truncate(string_limit);

    let mut import_hits = Vec::new();
    let mut seen_import = BTreeSet::new();
    for token in std::iter::once(query.as_str()).chain(query_tokens.iter().map(String::as_str)) {
        for item in ws.search_imports_paged(token, 12, 0)? {
            if seen_import.insert(item.name.clone()) {
                import_hits.push(AnalysisImportHit {
                    name: item.name,
                    address: item.address,
                    library: item.library,
                });
            }
        }
    }
    import_hits.truncate(12);

    let mut string_hits = Vec::new();
    let mut xref_samples = Vec::new();
    let mut hot_map: BTreeMap<u64, HotFunctionAccum> = BTreeMap::new();

    for function in &function_hits {
        let entry = hot_map.entry(function.address).or_insert_with(|| HotFunctionAccum {
            name: function.name.clone(),
            address: function.address,
            size: function.size,
            score: 2_000,
            reasons: vec![format!("function name match: {}", function.name)],
            string_hits: Vec::new(),
            evidence_ids: function.evidence_ids.clone(),
        });
        entry.score = entry.score.saturating_add(1_500);
        if !function.name.to_ascii_lowercase().contains("sub_") {
            entry.score = entry.score.saturating_add(800);
        }
        if !entry.reasons.iter().any(|item| item.starts_with("function name match")) {
            entry.reasons.push(format!("function name match: {}", function.name));
        }
    }

    for string in raw_strings {
        let mut owning = Vec::new();
        let mut xref_count = 0usize;
        if let Some(address) = string.address {
            let refs = ws.find_references(&format!("0x{address:x}"))?;
            xref_count = refs.len();
            for reference in refs.iter().take(xref_limit) {
                if xref_samples.len() < xref_limit {
                    xref_samples.push(*reference);
                }
                let owner_addr = if reference.to == address {
                    reference.from
                } else {
                    reference.to
                };
                if let Some(owner) = ws.resolve_function(&format!("0x{owner_addr:x}"))? {
                    owning.push(FunctionSearchHit {
                        name: owner.name.clone(),
                        address: owner.address,
                        size: owner.size,
                        evidence_ids: owner.evidence_ids.clone(),
                    });
                    let entry = hot_map.entry(owner.address).or_insert_with(|| HotFunctionAccum {
                        name: owner.name.clone(),
                        address: owner.address,
                        size: owner.size,
                        score: 0,
                        reasons: Vec::new(),
                        string_hits: Vec::new(),
                        evidence_ids: owner.evidence_ids.clone(),
                    });
                    entry.score = entry
                        .score
                        .saturating_add(1_200 + xref_count.min(20) as u32 * 20);
                    let snip = truncate_chars(&string.value, 80);
                    if !entry.string_hits.iter().any(|item| item == &snip) {
                        entry.string_hits.push(snip.clone());
                    }
                    let reason = format!("xref from string `{snip}` via 0x{address:x}");
                    if !entry.reasons.iter().any(|item| item == &reason) {
                        entry.reasons.push(reason);
                    }
                }
            }
            owning.sort_by_key(|item| item.address);
            owning.dedup_by_key(|item| item.address);
        }
        string_hits.push(AnalysisStringHit {
            address: string.address,
            value: string.value,
            xref_count,
            owning_functions: owning.into_iter().take(8).collect(),
        });
    }

    if let Ok(Some(direct)) = ws.resolve_function(&query) {
        let entry = hot_map.entry(direct.address).or_insert_with(|| HotFunctionAccum {
            name: direct.name.clone(),
            address: direct.address,
            size: direct.size,
            score: 0,
            reasons: Vec::new(),
            string_hits: Vec::new(),
            evidence_ids: direct.evidence_ids.clone(),
        });
        entry.score = entry.score.saturating_add(5_000);
        entry.reasons.push("direct function resolve".to_string());
    }

    for import in &import_hits {
        if let Some(address) = import.address {
            let refs = ws.find_references(&format!("0x{address:x}")).unwrap_or_default();
            for reference in refs.iter().take(8) {
                let owner_addr = if reference.to == address {
                    reference.from
                } else {
                    reference.to
                };
                if let Ok(Some(owner)) = ws.resolve_function(&format!("0x{owner_addr:x}")) {
                    let entry = hot_map.entry(owner.address).or_insert_with(|| HotFunctionAccum {
                        name: owner.name.clone(),
                        address: owner.address,
                        size: owner.size,
                        score: 0,
                        reasons: Vec::new(),
                        string_hits: Vec::new(),
                        evidence_ids: owner.evidence_ids.clone(),
                    });
                    entry.score = entry.score.saturating_add(900);
                    let reason = format!("calls/imports `{}`", import.name);
                    if !entry.reasons.iter().any(|item| item == &reason) {
                        entry.reasons.push(reason);
                    }
                }
            }
        }
    }

    let mut hot_sorted = hot_map.into_values().collect::<Vec<_>>();
    hot_sorted.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.address.cmp(&right.address))
    });
    hot_sorted.truncate(hot_limit);

    let mut hot_functions = Vec::new();
    let mut lattice_pieces: Vec<(String, u64, revx_core::AgentSemanticLattice)> = Vec::new();
    for mut item in hot_sorted {
        let query_addr = format!("0x{:x}", item.address);
        let callgraph = ws.callgraph_slice(&query_addr).unwrap_or_default();
        let mut caller_count = 0usize;
        let mut callee_count = 0usize;
        let mut caller_samples = Vec::new();
        let mut callee_samples = Vec::new();
        for edge in &callgraph {
            if edge.callee_address == item.address {
                caller_count += 1;
                if caller_samples.len() < 6 {
                    caller_samples.push(format!(
                        "{}@0x{:x}",
                        edge.caller_name, edge.caller_address
                    ));
                }
            }
            if edge.caller_address == item.address {
                callee_count += 1;
                if callee_samples.len() < 6 {
                    callee_samples.push(format!(
                        "{}@0x{:x}",
                        edge.callee_name.as_deref().unwrap_or("?"),
                        edge.callee_address
                    ));
                }
            }
        }

        let mut pseudocode_preview = None;
        let mut quality_tags = Vec::new();
        if !item.name.to_ascii_lowercase().starts_with("sub_")
            && !item.name.to_ascii_lowercase().starts_with("fun_")
        {
            quality_tags.push("named".to_string());
        }
        if !item.string_hits.is_empty() {
            quality_tags.push("string_backed".to_string());
        }
        if caller_count > 0 {
            quality_tags.push("has_callers".to_string());
        }
        if callee_count > 0 {
            quality_tags.push("has_callees".to_string());
        }

        if let Ok(Some(function)) = ws.resolve_function(&query_addr) {
            if let Some(unit) = &function.pseudocode {
                if include_pseudocode {
                    pseudocode_preview = Some(truncate_chars(&unit.text, 1_200));
                    if !unit.regions.is_empty() {
                        quality_tags.push("structured_pseudocode".to_string());
                    } else {
                        quality_tags.push("linear_pseudocode".to_string());
                    }
                    if unit.text.contains('"') || unit.text.contains('\'') {
                        quality_tags.push("string_literals".to_string());
                    }
                }
                if lattice_pieces.len() < 6 {
                    let lattice = unit.semantic_lattice.clone().unwrap_or_else(|| {
                        revx_analysis::build_agent_semantic_lattice(
                            &function.name,
                            function.address,
                            &unit.text,
                            &unit.regions,
                        )
                    });
                    quality_tags.push("casl".to_string());
                    lattice_pieces.push((function.name.clone(), function.address, lattice));
                }
            }
            if item.evidence_ids.is_empty() {
                item.evidence_ids = function.evidence_ids.clone();
            }
            item.size = function.size;
            item.name = function.name;
            if function.arguments.len() >= 3 {
                quality_tags.push("rich_args".to_string());
            }
            if callee_count <= 1 && function.blocks.len() <= 2 {
                quality_tags.push("wrapper_like".to_string());
            }
        }

        let confidence = hot_function_confidence(item.score, &quality_tags, caller_count, callee_count);
        let digest = format!(
            "score={} conf={:.2} callers={} callees={} tags=[{}] strings=[{}]",
            item.score,
            confidence,
            caller_count,
            callee_count,
            quality_tags.join(","),
            item.string_hits
                .iter()
                .take(3)
                .map(|value| truncate_chars(value, 40))
                .collect::<Vec<_>>()
                .join(" | ")
        );

        hot_functions.push(AnalysisHotFunction {
            name: item.name,
            address: item.address,
            size: item.size,
            reason: item.reasons.join("; "),
            score: item.score,
            confidence,
            caller_count,
            callee_count,
            caller_samples,
            callee_samples,
            quality_tags,
            digest,
            string_hits: item.string_hits,
            pseudocode_preview,
            evidence_ids: item.evidence_ids,
        });
    }

    let mut key_findings = Vec::new();
    if !query_tokens.is_empty() {
        key_findings.push(format!("query tokens: {}", query_tokens.join(", ")));
    }
    if !string_hits.is_empty() {
        key_findings.push(format!(
            "{} ranked string hit(s); top=`{}` xrefs={}",
            string_hits.len(),
            truncate_chars(&string_hits[0].value, 100),
            string_hits[0].xref_count
        ));
    }
    if !function_hits.is_empty() {
        key_findings.push(format!(
            "{} ranked function hit(s); top={} @ 0x{:x}",
            function_hits.len(),
            function_hits[0].name,
            function_hits[0].address
        ));
    }
    if !import_hits.is_empty() {
        key_findings.push(format!(
            "{} import hit(s); top={}",
            import_hits.len(),
            import_hits[0].name
        ));
    }
    for hot in hot_functions.iter().take(4) {
        key_findings.push(format!(
            "hot {} @ 0x{:x} conf={:.2} {} reason={}",
            hot.name,
            hot.address,
            hot.confidence,
            hot.digest,
            truncate_chars(&hot.reason, 120)
        ));
    }
    if key_findings.is_empty() {
        key_findings.push(format!(
            "no string/function/import hits for `{query}`; try broader pattern or run analysis_run first"
        ));
    }

    let next_actions =
        derive_analysis_brief_next_actions(&query, &string_hits, &hot_functions, &import_hits);
    let headline = if let Some(top) = hot_functions.first() {
        format!(
            "`{query}` → prioritize {} @ 0x{:x} (conf={:.2}, {})",
            top.name,
            top.address,
            top.confidence,
            truncate_chars(&top.reason, 70)
        )
    } else if let Some(top) = string_hits.first() {
        format!(
            "`{query}` → inspect string `{}` then xrefs",
            truncate_chars(&top.value, 80)
        )
    } else if let Some(top) = import_hits.first() {
        format!("`{query}` → inspect import `{}` callers", top.name)
    } else {
        format!("`{query}` → no dense hits; broaden search")
    };

    if lattice_pieces.is_empty() {
        let mut fallback_addrs: Vec<(String, u64)> = Vec::new();
        for hit in function_hits.iter().take(4) {
            fallback_addrs.push((hit.name.clone(), hit.address));
        }
        for hit in string_hits.iter().take(6) {
            for owner in hit.owning_functions.iter().take(2) {
                if !fallback_addrs.iter().any(|(_, a)| *a == owner.address) {
                    fallback_addrs.push((owner.name.clone(), owner.address));
                }
            }
        }
        for seed in ["main", "Main", "_main", "start"] {
            if let Ok(Some(function)) = ws.resolve_function(seed) {
                if !fallback_addrs.iter().any(|(_, a)| *a == function.address) {
                    fallback_addrs.push((function.name.clone(), function.address));
                }
            }
        }
        for (name, address) in fallback_addrs.into_iter().take(6) {
            let q = format!("0x{address:x}");
            if let Ok(Some(function)) = ws.resolve_function(&q) {
                if let Some(unit) = &function.pseudocode {
                    let lattice = unit.semantic_lattice.clone().unwrap_or_else(|| {
                        revx_analysis::build_agent_semantic_lattice(
                            &function.name,
                            function.address,
                            &unit.text,
                            &unit.regions,
                        )
                    });
                    let related = unit.text.contains(&query)
                        || query_tokens.iter().any(|token| {
                            !token.is_empty() && unit.text.to_ascii_lowercase().contains(&token.to_ascii_lowercase())
                        })
                        || string_hits.iter().any(|hit| unit.text.contains(&hit.value));
                    if related || lattice_pieces.is_empty() {
                        lattice_pieces.push((
                            if name.is_empty() {
                                function.name.clone()
                            } else {
                                name
                            },
                            function.address,
                            lattice,
                        ));
                    }
                }
            }
            if lattice_pieces.len() >= 4 {
                break;
            }
        }
    }

    let fused_lattice = if lattice_pieces.is_empty() {
        None
    } else {
        Some(revx_analysis::fuse_semantic_lattices(&query, &lattice_pieces))
    };
    let mut key_findings = key_findings;
    let mut next_actions = next_actions;
    let mut headline = headline;
    if let Some(lattice) = fused_lattice.as_ref() {
        if !lattice.thesis.is_empty() {
            headline = format!("CASL `{query}` → {}", truncate_chars(&lattice.thesis, 160));
            key_findings.insert(0, format!("casl_fusion_thesis: {}", lattice.thesis));
        }
        key_findings.insert(
            1.min(key_findings.len()),
            format!(
                "casl_fusion_quality: density={:.2} coverage={:.2} ambig={:.2} escalate={} pieces={}",
                lattice.quality.claim_density,
                lattice.quality.evidence_coverage,
                lattice.quality.ambiguity,
                lattice.quality.escalate,
                lattice_pieces.len()
            ),
        );
        for chain in lattice.chains.iter().take(3) {
            key_findings.push(format!(
                "chain[{}] {:.2}: {}",
                chain.id, chain.confidence, chain.narrative
            ));
        }
        for claim in lattice.claims.iter().take(5) {
            key_findings.push(format!(
                "claim[{}] {:.2} {}: {}",
                claim.id, claim.confidence, claim.kind, claim.intent
            ));
        }
        if let Some((name, addr, piece)) = lattice_pieces.first() {
            let plan = revx_analysis::lattice_ibc_plan(lattice, *addr, 3);
            if plan.is_empty() {
                next_actions.insert(
                    0,
                    AgentNextAction {
                        tool: "decompile_function".to_string(),
                        reason: format!("CASL fusion top owner {name}"),
                        priority: 97,
                        query: Some(format!("0x{addr:x}")),
                        label: Some("casl-fusion".to_string()),
                        args: serde_json::json!({ "query": format!("0x{addr:x}") }),
                    },
                );
            } else {
                for (i, mut action) in plan.into_iter().enumerate() {
                    action.priority = 99u8.saturating_sub(i as u8);
                    action.reason = format!("CASL fusion/{name}: {}", action.reason);
                    next_actions.insert(i, action);
                }
            }
            let _ = piece;
        }
        if !lattice.case_lexicon.is_empty() {
            let compact = lattice
                .case_lexicon
                .iter()
                .take(20)
                .map(|c| c.glyph.as_str())
                .collect::<Vec<_>>()
                .join("");
            let bound_n = lattice.case_lexicon.iter().filter(|c| c.target.is_some()).count();
            key_findings.push(format!(
                "case_lexicon: `{}` n={} bound={}/{}",
                compact,
                lattice.case_lexicon.len(),
                bound_n,
                lattice.case_lexicon.len()
            ));
            let sample = lattice
                .case_lexicon
                .iter()
                .filter(|c| c.target.is_some())
                .take(6)
                .map(|c| {
                    format!(
                        "'{}'->{}",
                        c.glyph,
                        c.target_name
                            .clone()
                            .unwrap_or_else(|| format!("0x{:x}", c.target.unwrap_or(0)))
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            if !sample.is_empty() {
                key_findings.push(format!("case_targets: {sample}"));
            }
            if !lattice.behavior_graph.is_empty() {
                let orbits = lattice
                    .behavior_graph
                    .iter()
                    .take(6)
                    .filter_map(|e| e.orbit.clone())
                    .collect::<Vec<_>>()
                    .join(" | ");
                key_findings.push(format!(
                    "flag_graph: edges={} {}",
                    lattice.behavior_graph.len(),
                    orbits
                ));
            }
            key_findings.push(format!(
                "ibc_cursor: pc={} status={}",
                lattice.ibc_pc,
                if lattice.ibc_status.is_empty() {
                    "ready"
                } else {
                    lattice.ibc_status.as_str()
                }
            ));
        }
        next_actions.sort_by(|a, b| b.priority.cmp(&a.priority));
        let mut seen = std::collections::BTreeSet::new();
        next_actions.retain(|action| {
            let key = format!("{}:{}", action.tool, action.args);
            seen.insert(key)
        });
        next_actions.truncate(8);
    }

    let open_questions = if let Some(lattice) = fused_lattice.as_ref() {
        let mut qs = lattice
            .claims
            .iter()
            .filter_map(|c| c.confutation.clone())
            .take(3)
            .collect::<Vec<_>>();
        for chain in lattice.chains.iter().take(2) {
            qs.push(format!("verify chain {}: {}", chain.id, chain.narrative));
        }
        if qs.is_empty() {
            next_actions
                .iter()
                .filter(|action| action.priority >= 80)
                .take(4)
                .map(|action| action.reason.clone())
                .collect()
        } else {
            qs
        }
    } else {
        next_actions
            .iter()
            .filter(|action| action.priority >= 80)
            .take(4)
            .map(|action| action.reason.clone())
            .collect()
    };

    let agent_brief = AgentInteractionBrief {
        headline: headline.clone(),
        key_findings: key_findings.clone(),
        open_questions,
        next_actions: next_actions.clone(),
        stop_conditions: vec![
            "Prefer CASL fusion claims/chains before raw listing".to_string(),
            "Execute exactly one next_actions[0] with provided args".to_string(),
            "Stop if hot_functions/string_hits/import_hits are all empty".to_string(),
            "If CASL escalate=true, deepen analysis on top claim owners".to_string(),
        ],
        semantic_lattice: fused_lattice,
    };

    let summary = format!(
        "analysis_brief for `{query}`: tokens={} strings={} functions={} imports={} hot={} xrefs_sampled={}",
        query_tokens.len(),
        string_hits.len(),
        function_hits.len(),
        import_hits.len(),
        hot_functions.len(),
        xref_samples.len()
    );

    let artifact = ws.write_json_artifact(
        "application/json",
        &serde_json::json!({
            "query": query,
            "query_tokens": query_tokens,
            "headline": headline,
            "summary": summary,
            "string_hits": string_hits,
            "function_hits": function_hits,
            "import_hits": import_hits,
            "hot_functions": hot_functions,
            "xref_samples": xref_samples,
            "key_findings": key_findings,
            "next_actions": next_actions,
            "agent_brief": agent_brief,
        }),
    )?;

    Ok(AnalysisBriefResponse {
        query,
        query_tokens,
        headline,
        summary,
        string_hits,
        function_hits,
        import_hits,
        hot_functions,
        xref_samples,
        key_findings,
        next_actions,
        agent_brief,
        artifact: Some(artifact),
    })
}

#[derive(Clone)]
struct HotFunctionAccum {
    name: String,
    address: u64,
    size: u64,
    score: u32,
    reasons: Vec<String>,
    string_hits: Vec<String>,
    evidence_ids: Vec<String>,
}

fn analysis_query_tokens(query: &str) -> Vec<String> {
    let mut tokens = query
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == ':'))
        .filter(|token| token.len() >= 3)
        .map(|token| token.trim_matches(':').to_string())
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    tokens.sort();
    tokens.dedup();
    if tokens.len() == 1 && tokens[0].eq_ignore_ascii_case(query) {
        tokens.clear();
    }
    tokens.truncate(6);
    tokens
}

fn hot_function_confidence(
    score: u32,
    tags: &[String],
    caller_count: usize,
    callee_count: usize,
) -> f32 {
    let mut conf = (score as f32 / 8_000.0).clamp(0.15, 0.95);
    if tags.iter().any(|tag| tag == "named") {
        conf += 0.08;
    }
    if tags.iter().any(|tag| tag == "string_backed") {
        conf += 0.1;
    }
    if tags.iter().any(|tag| tag == "structured_pseudocode") {
        conf += 0.06;
    }
    if tags.iter().any(|tag| tag == "wrapper_like") {
        conf -= 0.05;
    }
    if caller_count + callee_count > 0 {
        conf += 0.04;
    }
    conf.clamp(0.1, 0.99)
}

fn derive_analysis_brief_next_actions(
    query: &str,
    string_hits: &[AnalysisStringHit],
    hot_functions: &[AnalysisHotFunction],
    import_hits: &[AnalysisImportHit],
) -> Vec<AgentNextAction> {
    let mut actions = Vec::new();
    let mut push = |action: AgentNextAction| {
        if actions.iter().any(|existing: &AgentNextAction| {
            existing.tool == action.tool && existing.args == action.args
        }) {
            return;
        }
        actions.push(action);
    };

    if let Some(hot) = hot_functions.first() {
        let q = format!("0x{:x}", hot.address);
        push(AgentNextAction {
            tool: "decompile_function".to_string(),
            reason: format!(
                "decompile top hot function {} conf={:.2} ({})",
                hot.name, hot.confidence, hot.reason
            ),
            priority: 100,
            query: Some(q.clone()),
            label: Some(format!("decompile {}", hot.name)),
            args: serde_json::json!({ "query": q.clone() }),
        });
        push(AgentNextAction {
            tool: "function_profile".to_string(),
            reason: format!(
                "inspect callers/callees/xrefs for {} (callers={} callees={})",
                hot.name, hot.caller_count, hot.callee_count
            ),
            priority: 92,
            query: Some(q.clone()),
            label: Some(format!("profile {}", hot.name)),
            args: serde_json::json!({ "query": q }),
        });
    }

    if let Some(string) = string_hits.first() {
        if let Some(address) = string.address {
            let q = format!("0x{address:x}");
            push(AgentNextAction {
                tool: "xrefs_query".to_string(),
                reason: format!(
                    "expand all xrefs for top string `{}`",
                    truncate_chars(&string.value, 80)
                ),
                priority: 88,
                query: Some(q.clone()),
                label: Some("xrefs top string".to_string()),
                args: serde_json::json!({ "query": q }),
            });
        }
    }

    if let Some(import) = import_hits.first() {
        if let Some(address) = import.address {
            let q = format!("0x{address:x}");
            push(AgentNextAction {
                tool: "xrefs_query".to_string(),
                reason: format!("find callers of import `{}`", import.name),
                priority: 80,
                query: Some(q.clone()),
                label: Some(format!("xrefs {}", import.name)),
                args: serde_json::json!({ "query": q }),
            });
        }
    }

    if hot_functions.len() > 1 {
        let second = &hot_functions[1];
        let q = format!("0x{:x}", second.address);
        push(AgentNextAction {
            tool: "disassemble_function".to_string(),
            reason: format!(
                "compare second hot function {} @ 0x{:x} conf={:.2}",
                second.name, second.address, second.confidence
            ),
            priority: 74,
            query: Some(q.clone()),
            label: Some(format!("disasm {}", second.name)),
            args: serde_json::json!({ "query": q }),
        });
    }

    if hot_functions.is_empty() && string_hits.is_empty() && import_hits.is_empty() {
        push(AgentNextAction {
            tool: "string_search".to_string(),
            reason: "no dense hits; broaden string search with shorter token".to_string(),
            priority: 70,
            query: Some(query.to_string()),
            label: Some("broader string search".to_string()),
            args: serde_json::json!({ "pattern": query, "limit": 40 }),
        });
        push(AgentNextAction {
            tool: "function_search".to_string(),
            reason: "no dense hits; try function name search".to_string(),
            priority: 68,
            query: Some(query.to_string()),
            label: Some("function search".to_string()),
            args: serde_json::json!({ "query": query, "limit": 40 }),
        });
        push(AgentNextAction {
            tool: "binary_survey".to_string(),
            reason: "confirm analysis coverage before deeper probing".to_string(),
            priority: 60,
            query: None,
            label: Some("survey coverage".to_string()),
            args: serde_json::json!({}),
        });
    } else {
        push(AgentNextAction {
            tool: "evidence_pack".to_string(),
            reason: "collect persisted evidence around the query subject".to_string(),
            priority: 55,
            query: Some(query.to_string()),
            label: Some("evidence pack".to_string()),
            args: serde_json::json!({ "subject": query }),
        });
    }

    actions.sort_by(|left, right| right.priority.cmp(&left.priority));
    actions.truncate(8);
    actions
}

fn render_analysis_brief(payload: &AnalysisBriefResponse) -> String {
    let mut lines = vec![
        "# analysis_brief".to_string(),
        format!("query: {}", payload.query),
        format!(
            "tokens: {}",
            if payload.query_tokens.is_empty() {
                "-".to_string()
            } else {
                payload.query_tokens.join(", ")
            }
        ),
        format!("headline: {}", payload.headline),
        format!("summary: {}", payload.summary),
        format_agent_brief_section(&payload.agent_brief),
    ];
    if !payload.string_hits.is_empty() {
        lines.push("\\n## String Hits".to_string());
        for item in payload.string_hits.iter().take(16) {
            let owners = item
                .owning_functions
                .iter()
                .take(4)
                .map(|function| format!("{}@0x{:x}", function.name, function.address))
                .collect::<Vec<_>>()
                .join(", ");
            lines.push(format!(
                "- {}  `{}`  xrefs={}  owners=[{}]",
                item.address
                    .map(|address| format!("0x{address:x}"))
                    .unwrap_or_else(|| "-".to_string()),
                truncate_chars(&item.value, 120),
                item.xref_count,
                owners
            ));
        }
    }
    if !payload.function_hits.is_empty() {
        lines.push("\\n## Function Hits".to_string());
        for item in payload.function_hits.iter().take(16) {
            lines.push(format!(
                "- {}  0x{:x}  size={}",
                item.name, item.address, item.size
            ));
        }
    }
    if !payload.import_hits.is_empty() {
        lines.push("\\n## Import Hits".to_string());
        for item in payload.import_hits.iter().take(12) {
            lines.push(format!(
                "- {}  addr={}  lib={}",
                item.name,
                item.address
                    .map(|address| format!("0x{address:x}"))
                    .unwrap_or_else(|| "-".to_string()),
                item.library.as_deref().unwrap_or("-")
            ));
        }
    }
    if !payload.hot_functions.is_empty() {
        lines.push("\\n## Hot Functions".to_string());
        for item in payload.hot_functions.iter().take(10) {
            lines.push(format!(
                "- score={} conf={:.2}  {} @ 0x{:x}  size={}\\n  digest: {}\\n  reason: {}\\n  callers: {}\\n  callees: {}\\n  strings: {}",
                item.score,
                item.confidence,
                item.name,
                item.address,
                item.size,
                item.digest,
                truncate_chars(&item.reason, 180),
                if item.caller_samples.is_empty() {
                    format!("count={}", item.caller_count)
                } else {
                    item.caller_samples.join(", ")
                },
                if item.callee_samples.is_empty() {
                    format!("count={}", item.callee_count)
                } else {
                    item.callee_samples.join(", ")
                },
                if item.string_hits.is_empty() {
                    "-".to_string()
                } else {
                    item.string_hits
                        .iter()
                        .take(4)
                        .map(|value| format!("`{}`", truncate_chars(value, 60)))
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ));
            if let Some(preview) = &item.pseudocode_preview {
                lines.push(format!(
                    "  pseudocode:\\n```\\n{}\\n```",
                    truncate_chars(preview, 900)
                ));
            }
        }
    }
    if !payload.xref_samples.is_empty() {
        lines.push("\\n## Xref Samples".to_string());
        for reference in payload.xref_samples.iter().take(24) {
            lines.push(format!(
                "- 0x{:x} -> 0x{:x}  {}",
                reference.from, reference.to, reference.kind
            ));
        }
    }
    if let Some(artifact) = &payload.artifact {
        lines.push(format!("\\nartifact: {}", artifact.relative_path));
    }
    lines.join("\\n")
}

fn function_pseudocode_digest(
    unit: Option<&revx_core::PseudocodeUnit>,
    callees: &[revx_core::CallEdge],
    callers: &[revx_core::CallEdge],
) -> String {
    let mut parts = Vec::new();
    parts.push(format!("callers={} callees={}", callers.len(), callees.len()));
    if !callees.is_empty() {
        let names = callees
            .iter()
            .take(8)
            .map(|edge| {
                edge.callee_name
                    .clone()
                    .unwrap_or_else(|| format!("0x{:x}", edge.callee_address))
            })
            .collect::<Vec<_>>();
        parts.push(format!("calls: {}", names.join(", ")));
    }
    if !callers.is_empty() {
        let names = callers
            .iter()
            .take(6)
            .map(|edge| edge.caller_name.clone())
            .collect::<Vec<_>>();
        parts.push(format!("called_by: {}", names.join(", ")));
    }
    match unit {
        Some(unit) => {
            let lines = unit.text.lines().count();
            let mut ifs = 0usize;
            let mut loops = 0usize;
            let mut returns = 0usize;
            for region in &unit.regions {
                match region.kind {
                    revx_core::RegionKind::If => ifs += 1,
                    revx_core::RegionKind::Loop => loops += 1,
                    revx_core::RegionKind::Return => returns += 1,
                    _ => {}
                }
            }
            parts.push(format!(
                "pseudocode_lines={} regions={} if={} loop={} return={}",
                lines,
                unit.regions.len(),
                ifs,
                loops,
                returns
            ));
            let literals = extract_quoted_literals(&unit.text);
            if !literals.is_empty() {
                parts.push(format!(
                    "string_literals: {}",
                    literals
                        .into_iter()
                        .take(6)
                        .map(|item| format!("`{}`", truncate_chars(&item, 40)))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if callees.is_empty() {
                let calls = extract_call_names_from_pseudocode(&unit.text);
                if !calls.is_empty() {
                    parts.push(format!(
                        "calls: {}",
                        calls.into_iter().take(8).collect::<Vec<_>>().join(", ")
                    ));
                }
            }
            let returns = extract_return_exprs(&unit.text);
            if !returns.is_empty() {
                parts.push(format!(
                    "returns: {}",
                    returns
                        .into_iter()
                        .take(4)
                        .map(|item| truncate_chars(&item, 48))
                        .collect::<Vec<_>>()
                        .join(" | ")
                ));
            }
            if unit.regions.is_empty() {
                parts.push("shape=linear".to_string());
            } else {
                parts.push("shape=structured".to_string());
            }
            if unit.text.contains("if (") {
                parts.push("has_if".to_string());
            }
        }
        None => parts.push("pseudocode=unavailable".to_string()),
    }
    parts.join("\n")
}
fn extract_call_names_from_pseudocode(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("//") || line.starts_with("/*") {
            continue;
        }
        let work = line.strip_prefix("return ").unwrap_or(line);
        let Some(open) = work.find('(') else {
            continue;
        };
        let name = work[..open].trim();
        if name.is_empty()
            || name.contains(' ')
            || name.contains('=')
            || name == "if"
            || name == "while"
            || name == "for"
            || name == "switch"
        {
            continue;
        }
        if name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
        {
            if seen.insert(name.to_string()) {
                out.push(name.to_string());
            }
        }
    }
    out
}

fn extract_return_exprs(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("return ") else {
            continue;
        };
        let expr = rest
            .split("//")
            .next()
            .unwrap_or(rest)
            .trim()
            .trim_end_matches(';')
            .trim();
        if !expr.is_empty() && !out.iter().any(|item| item == expr) {
            out.push(expr.to_string());
        }
    }
    out
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
                if slice.len() >= 3 && !out.iter().any(|item| item == slice) {
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


fn derive_function_profile_agent_brief(
    function: &revx_core::Function,
    callers: &[revx_core::CallEdge],
    callees: &[revx_core::CallEdge],
    incoming: &[revx_core::Reference],
    outgoing: &[revx_core::Reference],
) -> AgentInteractionBrief {
    let q = format!("0x{:x}", function.address);
    let digest = function_pseudocode_digest(function.pseudocode.as_ref(), callees, callers);
    let mut key_findings = vec![
        format!(
            "{} @ 0x{:x} size={} blocks={}",
            function.name,
            function.address,
            function.size,
            function.blocks.len()
        ),
        digest.replace("\n", "; "),
    ];
    if !function.arguments.is_empty() {
        key_findings.push(format!(
            "args: {}",
            function
                .arguments
                .iter()
                .take(6)
                .map(|arg| format!(
                    "{}:{}",
                    arg.name,
                    arg.type_name.as_deref().unwrap_or("?")
                ))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let mut next_actions = vec![
        AgentNextAction {
            tool: "decompile_function".to_string(),
            reason: "read full pseudocode for this function".to_string(),
            priority: 95,
            query: Some(q.clone()),
            label: Some("decompile".to_string()),
            args: serde_json::json!({ "query": q.clone() }),
        },
        AgentNextAction {
            tool: "disassemble_function".to_string(),
            reason: "inspect instruction-level control flow".to_string(),
            priority: 78,
            query: Some(q.clone()),
            label: Some("disassemble".to_string()),
            args: serde_json::json!({ "query": q.clone() }),
        },
    ];
    if let Some(edge) = callees.first() {
        let target = format!("0x{:x}", edge.callee_address);
        next_actions.push(AgentNextAction {
            tool: "function_profile".to_string(),
            reason: format!(
                "follow callee {}",
                edge.callee_name.as_deref().unwrap_or("?")
            ),
            priority: 84,
            query: Some(target.clone()),
            label: Some("profile callee".to_string()),
            args: serde_json::json!({ "query": target }),
        });
    } else if let Some(edge) = callers.first() {
        let target = format!("0x{:x}", edge.caller_address);
        next_actions.push(AgentNextAction {
            tool: "function_profile".to_string(),
            reason: format!("inspect caller {}", edge.caller_name),
            priority: 82,
            query: Some(target.clone()),
            label: Some("profile caller".to_string()),
            args: serde_json::json!({ "query": target }),
        });
    }
    if !incoming.is_empty() || !outgoing.is_empty() {
        next_actions.push(AgentNextAction {
            tool: "xrefs_query".to_string(),
            reason: format!(
                "expand raw xrefs (in={} out={})",
                incoming.len(),
                outgoing.len()
            ),
            priority: 70,
            query: Some(q.clone()),
            label: Some("xrefs".to_string()),
            args: serde_json::json!({ "query": q }),
        });
    }
    next_actions.sort_by(|a, b| b.priority.cmp(&a.priority));
    AgentInteractionBrief {
        headline: format!(
            "profile {} @ 0x{:x}: callers={} callees={}",
            function.name,
            function.address,
            callers.len(),
            callees.len()
        ),
        key_findings,
        open_questions: next_actions
            .iter()
            .take(3)
            .map(|action| action.reason.clone())
            .collect(),
        next_actions,
        stop_conditions: vec![
            "Execute next_actions[0] with provided args".to_string(),
            "Stop after one hop unless new high-value callee/caller appears".to_string(),
        ],
        semantic_lattice: function.pseudocode.as_ref().map(|unit| {
            unit.semantic_lattice.clone().unwrap_or_else(|| {
                revx_analysis::build_agent_semantic_lattice(
                    &function.name,
                    function.address,
                    &unit.text,
                    &unit.regions,
                )
            })
        }),
    }
}

fn derive_decompile_agent_brief(
    name: &str,
    address: u64,
    unit: Option<&revx_core::PseudocodeUnit>,
) -> AgentInteractionBrief {
    let q = format!("0x{address:x}");
    let lattice = unit.and_then(|unit| unit.semantic_lattice.clone()).or_else(|| {
        unit.map(|unit| {
            revx_analysis::build_agent_semantic_lattice(name, address, &unit.text, &unit.regions)
        })
    });
    let digest = function_pseudocode_digest(unit, &[], &[]);
    let mut next_actions = Vec::new();
    if let Some(lattice) = lattice.as_ref() {
        for action in revx_analysis::lattice_ibc_plan(lattice, address, 4) {
            next_actions.push(action);
        }
        for claim in lattice.claims.iter().take(4) {
            if let Some(probe) = claim.probes.first() {
                let mut action = probe.clone();
                action.priority = action.priority.saturating_sub(claim.id[1..].parse::<u8>().unwrap_or(0));
                action.reason = format!("{} | {}", claim.intent, action.reason);
                if action.label.is_none() {
                    action.label = Some(format!("casl-{}", claim.id));
                }
                next_actions.push(action);
            }
        }
        if lattice.quality.escalate {
            next_actions.insert(
                0,
                AgentNextAction {
                    tool: "function_profile".to_string(),
                    reason: lattice
                        .quality
                        .escalate_reason
                        .clone()
                        .unwrap_or_else(|| "CASL quality gate requests escalation".to_string()),
                    priority: 98,
                    query: Some(q.clone()),
                    label: Some("casl-escalate".to_string()),
                    args: serde_json::json!({ "query": q.clone() }),
                },
            );
        }
    }
    next_actions.push(AgentNextAction {
        tool: "function_profile".to_string(),
        reason: "collect callers/callees and xrefs around this decompilation".to_string(),
        priority: 90,
        query: Some(q.clone()),
        label: Some("profile".to_string()),
        args: serde_json::json!({ "query": q.clone() }),
    });
    next_actions.push(AgentNextAction {
        tool: "disassemble_function".to_string(),
        reason: "verify ambiguous statements against instructions".to_string(),
        priority: 75,
        query: Some(q.clone()),
        label: Some("disassemble".to_string()),
        args: serde_json::json!({ "query": q.clone() }),
    });
    if unit.is_none() {
        next_actions.insert(
            0,
            AgentNextAction {
                tool: "disassemble_function".to_string(),
                reason: "pseudocode unavailable; fall back to disassembly".to_string(),
                priority: 99,
                query: Some(q.clone()),
                label: Some("fallback-disasm".to_string()),
                args: serde_json::json!({ "query": format!("0x{address:x}") }),
            },
        );
    }
    let mut key_findings = Vec::new();
    if let Some(lattice) = lattice.as_ref() {
        if !lattice.thesis.is_empty() {
            key_findings.push(format!("casl_thesis: {}", lattice.thesis));
        }
        key_findings.push(format!(
            "casl_quality: density={:.2} coverage={:.2} ambig={:.2} escalate={}",
            lattice.quality.claim_density,
            lattice.quality.evidence_coverage,
            lattice.quality.ambiguity,
            lattice.quality.escalate
        ));
        if !lattice.case_lexicon.is_empty() {
            let compact = lattice
                .case_lexicon
                .iter()
                .take(24)
                .map(|c| {
                    if c.takes_arg {
                        format!("{}:", c.glyph)
                    } else {
                        c.glyph.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join("");
            let bound_n = lattice.case_lexicon.iter().filter(|c| c.target.is_some()).count();
            key_findings.push(format!(
                "case_lexicon: `{}` (n={}, with_arg={}, bound={})",
                compact,
                lattice.case_lexicon.len(),
                lattice.case_lexicon.iter().filter(|c| c.takes_arg).count(),
                bound_n
            ));
            let sample = lattice
                .case_lexicon
                .iter()
                .filter(|c| c.target.is_some())
                .take(6)
                .map(|c| {
                    format!(
                        "'{}'->{}",
                        c.glyph,
                        c.target_name
                            .clone()
                            .unwrap_or_else(|| format!("0x{:x}", c.target.unwrap_or(0)))
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            if !sample.is_empty() {
                key_findings.push(format!("case_targets: {sample}"));
            }
            if !lattice.behavior_graph.is_empty() {
                let orbits = lattice
                    .behavior_graph
                    .iter()
                    .take(6)
                    .filter_map(|e| e.orbit.clone())
                    .collect::<Vec<_>>()
                    .join(" | ");
                key_findings.push(format!(
                    "flag_graph: edges={} {}",
                    lattice.behavior_graph.len(),
                    orbits
                ));
            }
            key_findings.push(format!(
                "ibc_cursor: pc={} status={}",
                lattice.ibc_pc,
                if lattice.ibc_status.is_empty() {
                    "ready"
                } else {
                    lattice.ibc_status.as_str()
                }
            ));
        }
        for chain in lattice.chains.iter().take(3) {
            key_findings.push(format!(
                "chain[{}] {:.2}: {}",
                chain.id, chain.confidence, chain.narrative
            ));
        }
        for claim in lattice.claims.iter().take(6) {
            key_findings.push(format!(
                "claim[{}] {:.2} {}: {}",
                claim.id, claim.confidence, claim.kind, claim.intent
            ));
        }
        for step in lattice.ibc.iter().take(4) {
            key_findings.push(format!(
                "ibc[{}] {} {}",
                step.pc, step.op, step.detail
            ));
        }
        for anchor in lattice.anchors.iter().take(6) {
            key_findings.push(format!(
                "anchor[@{}] {} {}",
                anchor.id, anchor.kind, anchor.surface
            ));
        }
        for item in lattice.contradictions.iter().take(2) {
            key_findings.push(format!("contradiction: {item}"));
        }
    } else {
        key_findings.push(digest.replace("\n", "; "));
    }
    if let Some(unit) = unit {
        let calls = extract_call_names_from_pseudocode(&unit.text);
        if !calls.is_empty() {
            key_findings.push(format!(
                "recovered_calls: {}",
                calls.into_iter().take(10).collect::<Vec<_>>().join(", ")
            ));
        }
        let literals = extract_quoted_literals(&unit.text);
        if !literals.is_empty() {
            key_findings.push(format!(
                "string_literals: {}",
                literals
                    .into_iter()
                    .take(6)
                    .map(|item| format!("`{}`", truncate_chars(&item, 48)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        let preview = unit
            .text
            .lines()
            .filter(|line| {
                let t = line.trim();
                !t.is_empty()
                    && !t.starts_with('{')
                    && !t.starts_with('}')
                    && !t.starts_with("// args:")
            })
            .take(8)
            .map(str::trim)
            .collect::<Vec<_>>()
            .join(" | ");
        if !preview.is_empty() {
            key_findings.push(format!("preview: {}", truncate_chars(&preview, 280)));
        }
    }
    next_actions.sort_by(|a, b| b.priority.cmp(&a.priority));
    let mut seen = std::collections::BTreeSet::new();
    next_actions.retain(|action| {
        let key = format!("{}:{}", action.tool, action.args);
        seen.insert(key)
    });
    let headline = lattice
        .as_ref()
        .map(|lattice| {
            if lattice.thesis.is_empty() {
                format!("decompile {name} @ 0x{address:x}")
            } else {
                format!("CASL {name} @ 0x{address:x}: {}", truncate_chars(&lattice.thesis, 140))
            }
        })
        .unwrap_or_else(|| format!("decompile {name} @ 0x{address:x}"));
    let open_questions = lattice
        .as_ref()
        .map(|lattice| {
            let mut qs = lattice
                .claims
                .iter()
                .filter_map(|claim| claim.confutation.clone())
                .take(3)
                .collect::<Vec<_>>();
            if lattice.quality.escalate {
                if let Some(reason) = &lattice.quality.escalate_reason {
                    qs.insert(0, reason.clone());
                }
            }
            if qs.is_empty() {
                next_actions
                    .iter()
                    .take(2)
                    .map(|action| action.reason.clone())
                    .collect()
            } else {
                qs
            }
        })
        .unwrap_or_else(|| {
            next_actions
                .iter()
                .take(2)
                .map(|action| action.reason.clone())
                .collect()
        });
    AgentInteractionBrief {
        headline,
        key_findings,
        open_questions,
        next_actions,
        stop_conditions: vec![
            "Prefer CASL claims/anchors before raw pseudocode".to_string(),
            "Execute next_actions[0].args exactly".to_string(),
            "If CASL escalate=true, raise analysis depth before concluding".to_string(),
        ],
        semantic_lattice: lattice,
    }
}


fn derive_string_search_agent_brief(
    pattern: &str,
    matches: &[revx_core::StringLiteral],
) -> AgentInteractionBrief {
    let mut next_actions = Vec::new();
    if let Some(item) = matches.first() {
        if let Some(address) = item.address {
            let q = format!("0x{address:x}");
            next_actions.push(AgentNextAction {
                tool: "xrefs_query".to_string(),
                reason: format!(
                    "resolve xrefs for top match `{}`",
                    truncate_chars(&item.value, 80)
                ),
                priority: 100,
                query: Some(q.clone()),
                label: Some("xrefs top string".to_string()),
                args: serde_json::json!({ "query": q }),
            });
            next_actions.push(AgentNextAction {
                tool: "analysis_brief".to_string(),
                reason: "build multi-hop brief around this string/topic".to_string(),
                priority: 88,
                query: Some(pattern.to_string()),
                label: Some("analysis brief".to_string()),
                args: serde_json::json!({ "query": pattern }),
            });
        }
    } else {
        next_actions.push(AgentNextAction {
            tool: "function_search".to_string(),
            reason: "no string hits; try function names with same pattern".to_string(),
            priority: 70,
            query: Some(pattern.to_string()),
            label: Some("function search".to_string()),
            args: serde_json::json!({ "query": pattern, "limit": 40 }),
        });
    }
    AgentInteractionBrief {
        headline: format!(
            "string_search `{}`: {} match(es)",
            pattern,
            matches.len()
        ),
        key_findings: matches
            .iter()
            .take(5)
            .map(|item| {
                format!(
                    "{} `{}`",
                    item.address
                        .map(|address| format!("0x{address:x}"))
                        .unwrap_or_else(|| "-".to_string()),
                    truncate_chars(&item.value, 100)
                )
            })
            .collect(),
        open_questions: next_actions
            .iter()
            .take(2)
            .map(|action| action.reason.clone())
            .collect(),
        next_actions,
        stop_conditions: vec![
            "Execute next_actions[0] once, then reassess owning functions".to_string(),
        ],
        semantic_lattice: None,
    }
}

fn derive_xrefs_agent_brief(
    query: &str,
    references: &[revx_core::Reference],
) -> AgentInteractionBrief {
    let mut next_actions = Vec::new();
    if let Some(reference) = references.first() {
        let target = format!("0x{:x}", reference.from);
        next_actions.push(AgentNextAction {
            tool: "function_profile".to_string(),
            reason: format!(
                "profile function owning xref 0x{:x} -> 0x{:x}",
                reference.from, reference.to
            ),
            priority: 100,
            query: Some(target.clone()),
            label: Some("profile xref source".to_string()),
            args: serde_json::json!({ "query": target.clone() }),
        });
        next_actions.push(AgentNextAction {
            tool: "decompile_function".to_string(),
            reason: "decompile xref source function".to_string(),
            priority: 90,
            query: Some(target.clone()),
            label: Some("decompile xref source".to_string()),
            args: serde_json::json!({ "query": target }),
        });
    } else {
        next_actions.push(AgentNextAction {
            tool: "string_search".to_string(),
            reason: "no xrefs; confirm subject via string/function search".to_string(),
            priority: 70,
            query: Some(query.to_string()),
            label: Some("fallback search".to_string()),
            args: serde_json::json!({ "pattern": query }),
        });
    }
    let kind_counts = {
        let mut map = BTreeMap::new();
        for reference in references {
            *map.entry(reference.kind.as_str().to_string()).or_insert(0usize) += 1;
        }
        map
    };
    AgentInteractionBrief {
        headline: format!("xrefs `{}`: {} reference(s)", query, references.len()),
        key_findings: kind_counts
            .into_iter()
            .map(|(kind, count)| format!("{kind}={count}"))
            .collect(),
        open_questions: next_actions
            .iter()
            .take(2)
            .map(|action| action.reason.clone())
            .collect(),
        next_actions,
        stop_conditions: vec!["Follow top xref owner with function_profile/decompile".to_string()],
        semantic_lattice: None,
    }
}



fn run_investigation(
    ws: &Workspace,
    request: InvestigationRunRequest,
) -> Result<InvestigationRunResponse> {
    let subject = request.subject.trim();
    if subject.is_empty() {
        anyhow::bail!("investigation subject cannot be empty");
    }
    let investigation_id = uuid::Uuid::new_v4().to_string();
    let pipeline = if request
        .run_object_pipeline
        .unwrap_or(request.path.is_some())
    {
        let path = request
            .path
            .clone()
            .ok_or_else(|| anyhow::anyhow!("path is required when run_object_pipeline is true"))?;
        Some(run_object_pipeline(
            ws,
            ObjectPipelineRequest {
                path,
                max_depth: request.max_depth.or(Some(4)),
                max_children: request.max_children.or(Some(512)),
                object_limit: request.object_limit.or(Some(256)),
                analyze_objects: Some(true),
                carve_embedded: Some(true),
                carve_limit: Some(32),
                max_carve_object_bytes: Some(64 * 1024 * 1024),
                max_carve_bytes: Some(64 * 1024 * 1024),
                min_carve_confidence: Some(0.9),
                carve_max_depth: request.carve_max_depth.or(Some(2)),
                carve_max_children: request.carve_max_children.or(Some(512)),
                plugin_ids: request.plugin_ids.clone(),
                analyze_binaries: Some(request.analyze_binaries.unwrap_or(true)),
                binary_profile: request.binary_profile,
            },
        )?)
    } else {
        None
    };

    let pipeline_evidence_ids = pipeline
        .as_ref()
        .map(|payload| payload.evidence_ids.clone())
        .unwrap_or_default();
    let graph = ws.evidence_graph_with_seed_evidence_ids(
        subject,
        request.graph_depth.unwrap_or(3),
        request.graph_limit.unwrap_or(300),
        &pipeline_evidence_ids,
    )?;
    let mut evidence_export = ws.export_evidence_by_subject(subject, 200)?;
    if !pipeline_evidence_ids.is_empty() {
        let pipeline_evidence_export = ws.export_evidence_by_ids(&pipeline_evidence_ids, 200)?;
        evidence_export.count += pipeline_evidence_export.count;
        let mut seen_preview_ids = evidence_export
            .preview
            .iter()
            .map(|evidence| evidence.id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        for evidence in pipeline_evidence_export.preview {
            if seen_preview_ids.insert(evidence.id.clone()) {
                evidence_export.preview.push(evidence);
            }
        }
        evidence_export.preview.truncate(200);
        if evidence_export.artifact.is_none() {
            evidence_export.artifact = pipeline_evidence_export.artifact;
        }
        evidence_export.count = seen_preview_ids.len();
    }
    let trace_events = ws.query_traces(
        request.trace_kind.as_deref(),
        request.trace_limit.unwrap_or(50),
    )?;
    let evidence_ids = evidence_export
        .preview
        .iter()
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    let summary = format!(
        "Investigation {} over {} found {} evidence item(s), {} graph node(s), {} graph edge(s), {} trace event(s), and {} pipeline step(s)",
        investigation_id,
        subject,
        evidence_export.count,
        graph.node_count,
        graph.edge_count,
        trace_events.len(),
        pipeline
            .as_ref()
            .map(|payload| payload.steps.len())
            .unwrap_or(0)
    );
    let next_actions = derive_investigation_next_actions(
        subject,
        pipeline.as_ref(),
        evidence_export.count,
        graph.node_count,
        trace_events.len(),
    );
    let agent_brief = derive_investigation_agent_brief(
        subject,
        &summary,
        pipeline.as_ref(),
        &evidence_export.preview,
        &next_actions,
        evidence_export.count,
        graph.node_count,
        trace_events.len(),
    );
    let report = Report {
        id: investigation_id.clone(),
        topic: subject.to_string(),
        body: investigation_report_body(
            subject,
            &summary,
            evidence_export.count,
            &evidence_export.preview,
            &graph,
            pipeline.as_ref(),
            trace_events.len(),
            &next_actions,
            &agent_brief,
        ),
        evidence_ids: evidence_ids.clone(),
    };
    let report_artifact = ws.save_report(&report)?;
    let artifact = ws.write_json_artifact(
        "application/json",
        &serde_json::json!({
            "investigation_id": &investigation_id,
            "subject": subject,
            "summary": &summary,
            "evidence_ids": &evidence_ids,
            "evidence_count": evidence_export.count,
            "graph": &graph,
            "pipeline": &pipeline,
            "trace_count": trace_events.len(),
            "next_actions": &next_actions,
            "agent_brief": &agent_brief,
            "report": &report,
            "report_artifact": &report_artifact,
        }),
    )?;

    Ok(InvestigationRunResponse {
        investigation_id,
        subject: subject.to_string(),
        summary,
        evidence_ids,
        evidence_count: evidence_export.count,
        graph,
        pipeline,
        trace_count: trace_events.len(),
        report,
        report_artifact,
        artifact,
        next_actions,
        agent_brief,
    })
}

fn investigation_report_body(
    subject: &str,
    summary: &str,
    evidence_count: usize,
    evidence_preview: &[Evidence],
    graph: &revx_core::EvidenceGraphResponse,
    pipeline: Option<&ObjectPipelineResponse>,
    trace_count: usize,
    next_actions: &[AgentNextAction],
    agent_brief: &AgentInteractionBrief,
) -> String {
    let evidence_lines = if evidence_preview.is_empty() {
        "- None".to_string()
    } else {
        evidence_preview
            .iter()
            .take(20)
            .map(|item| format!("- [{}] {}: {}", item.kind, item.id, item.summary))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let pipeline_lines = if let Some(pipeline) = pipeline {
        pipeline
            .steps
            .iter()
            .take(20)
            .map(|step| {
                format!(
                    "- {:?} {:?}: {:?} - {}",
                    step.stage, step.object_path, step.status, step.summary
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        "- Not run".to_string()
    };
    let finding_lines = if agent_brief.key_findings.is_empty() {
        "- None".to_string()
    } else {
        agent_brief
            .key_findings
            .iter()
            .map(|item| format!("- {item}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let action_lines = if next_actions.is_empty() {
        "- None".to_string()
    } else {
        next_actions
            .iter()
            .take(8)
            .map(|action| {
                format!(
                    "- p{} `{}`{}: {}",
                    action.priority,
                    action.tool,
                    action
                        .label
                        .as_deref()
                        .map(|label| format!(" ({label})"))
                        .unwrap_or_default(),
                    action.reason
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let question_lines = if agent_brief.open_questions.is_empty() {
        "- None".to_string()
    } else {
        agent_brief
            .open_questions
            .iter()
            .map(|item| format!("- {item}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let stop_lines = if agent_brief.stop_conditions.is_empty() {
        "- None".to_string()
    } else {
        agent_brief
            .stop_conditions
            .iter()
            .map(|item| format!("- {item}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let top_action_line = next_actions
        .first()
        .map(|action| {
            format!(
                "- EXECUTE NOW: p{} `{}` {}\n  args: {}",
                action.priority,
                action.tool,
                action.label.as_deref().unwrap_or(""),
                action.args
            )
        })
        .unwrap_or_else(|| "- None".to_string());
    format!(
        "# Investigation: {subject}\n\n## Agent Brief\n\n{}\n\n## Top Action\n\n{top_action_line}\n\n## Summary\n\n{summary}\n\n## Coverage\n\n- Evidence count: {evidence_count}\n- Evidence graph nodes: {}\n- Evidence graph edges: {}\n- Trace events considered: {trace_count}\n\n## Key Findings\n\n{finding_lines}\n\n## Next Actions\n\n{action_lines}\n\n## Open Questions\n\n{question_lines}\n\n## Stop Conditions\n\n{stop_lines}\n\n## Evidence Preview\n\n{evidence_lines}\n\n## Pipeline Steps\n\n{pipeline_lines}\n",
        agent_brief.headline,
        graph.node_count,
        graph.edge_count
    )
}


fn run_object_plugin(
    ws: &Workspace,
    plugin_id: &str,
    query: &str,
    timeout_ms: Option<u64>,
) -> Result<ObjectPluginRunResponse> {
    let plugin = ws
        .resolve_object_plugin(plugin_id)?
        .ok_or_else(|| anyhow::anyhow!("object plugin not found: {plugin_id}"))?;
    let materialized = ws
        .materialize_object_artifact(query)?
        .ok_or_else(|| object_lookup_error(ws, query))?;
    if !plugin_accepts_object(&plugin, &materialized.object) {
        anyhow::bail!(
            "plugin {} does not accept object kind {:?} format {:?}",
            plugin.id,
            materialized.object.kind,
            materialized.object.format
        );
    }
    let timeout_ms = timeout_ms.or(plugin.timeout_ms).unwrap_or(30_000);
    let artifact_path = ws.root().join(&materialized.artifact.relative_path);
    let command = expand_plugin_command(&plugin.command, ws, &materialized, timeout_ms)?;
    let (program, args) = command
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("plugin {} has an empty command", plugin.id))?;
    let output = run_command_with_timeout(program, args, Duration::from_millis(timeout_ms))
        .with_context(|| format!("failed to run object plugin {}", plugin.id))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let output_json = serde_json::from_str::<serde_json::Value>(&stdout).ok();
    let status = if output.status.success() {
        ObjectAnalysisStatus::Completed
    } else {
        ObjectAnalysisStatus::Failed
    };
    let summary = output_json
        .as_ref()
        .and_then(|value| value.get("summary"))
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            if output.status.success() {
                format!("Plugin {} completed", plugin.id)
            } else {
                format!(
                    "Plugin {} failed with status {}",
                    plugin.id,
                    output
                        .status
                        .code()
                        .map(|code| code.to_string())
                        .unwrap_or_else(|| "signal".to_string())
                )
            }
        });
    let artifact = ws.write_json_artifact(
        "application/json",
        &serde_json::json!({
            "plugin": &plugin,
            "object": &materialized.object,
            "materialized_artifact": &materialized.artifact,
            "artifact_path": artifact_path,
            "command": &command,
            "timeout_ms": timeout_ms,
            "status": &status,
            "exit_code": output.status.code(),
            "stdout": &stdout,
            "stderr": &stderr,
            "output_json": &output_json,
        }),
    )?;
    let evidence_id = format!(
        "object_plugin:{}:{}:{}",
        plugin.id, materialized.object.id, artifact.hash_blake3
    );
    ws.insert_evidence(Evidence {
        id: evidence_id.clone(),
        subject: materialized
            .object
            .path
            .clone()
            .unwrap_or_else(|| materialized.object.id.clone()),
        summary: format!("plugin {}: {summary}", plugin.id),
        kind: "object_plugin_analysis".to_string(),
        details: serde_json::json!({
            "plugin": &plugin,
            "object": &materialized.object,
            "materialized_artifact": &materialized.artifact,
            "artifact": &artifact,
            "status": &status,
            "summary": &summary,
            "exit_code": output.status.code(),
            "output_json": &output_json,
        }),
        provenance: EvidenceProvenance {
            source: format!("object_plugin:{}", plugin.id),
            binary_id: None,
            function_address: None,
            instruction_address: None,
            profile: None,
        },
    })?;

    Ok(ObjectPluginRunResponse {
        plugin,
        object: materialized.object,
        materialized_artifact: materialized.artifact,
        status,
        summary,
        evidence_id,
        artifact,
        stdout_preview: text_preview(&stdout, 4096),
        stderr_preview: text_preview(&stderr, 4096),
        output_json,
    })
}

fn plugin_accepts_object(
    plugin: &revx_core::ObjectPluginDefinition,
    object: &UniversalObject,
) -> bool {
    let kind_ok = plugin.accepted_kinds.is_empty() || plugin.accepted_kinds.contains(&object.kind);
    let format_ok = plugin.accepted_formats.is_empty()
        || object
            .format
            .as_deref()
            .is_some_and(|format| plugin.accepted_formats.iter().any(|item| item == format));
    kind_ok && format_ok
}

fn run_command_with_timeout(program: &str, args: &[String], timeout: Duration) -> Result<Output> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let started = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            return child.wait_with_output().map_err(Into::into);
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let mut output = child.wait_with_output()?;
            output.stderr.extend_from_slice(
                format!(
                    "\nrevx: plugin command exceeded timeout of {} ms",
                    timeout.as_millis()
                )
                .as_bytes(),
            );
            return Ok(output);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn expand_plugin_command(
    command: &[String],
    ws: &Workspace,
    materialized: &ObjectMaterializeResponse,
    timeout_ms: u64,
) -> Result<Vec<String>> {
    let artifact_path = ws
        .root()
        .join(&materialized.artifact.relative_path)
        .canonicalize()
        .unwrap_or_else(|_| ws.root().join(&materialized.artifact.relative_path));
    let workspace_root = ws
        .root()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let object_path = materialized.object.path.as_deref().unwrap_or("");
    Ok(command
        .iter()
        .map(|part| {
            part.replace("{artifact_path}", &artifact_path.display().to_string())
                .replace(
                    "{artifact_relative_path}",
                    &materialized.artifact.relative_path,
                )
                .replace("{object_id}", &materialized.object.id)
                .replace("{object_path}", object_path)
                .replace(
                    "{object_format}",
                    materialized.object.format.as_deref().unwrap_or(""),
                )
                .replace("{workspace_root}", &workspace_root.display().to_string())
                .replace("{timeout_ms}", &timeout_ms.to_string())
        })
        .collect())
}

fn text_preview(text: &str, limit: usize) -> Option<String> {
    if text.is_empty() {
        return None;
    }
    Some(text.chars().take(limit).collect())
}

struct DugBinaryPromotion {
    analysis: ObjectAnalysisSummary,
    evidence_ids: Vec<String>,
    artifact: Option<revx_core::ArtifactHandle>,
    analyzed_count: usize,
    candidate_count: usize,
}

fn promote_dug_native_binaries(
    ws: &Workspace,
    analyses: &[ObjectAnalysisSummary],
    profile: revx_core::AnalysisProfile,
    source: &str,
    limit: usize,
) -> Result<Option<DugBinaryPromotion>> {
    promote_dug_native_binaries_tracked(ws, analyses, profile, source, limit, None)
}

fn promote_dug_native_binaries_tracked(
    ws: &Workspace,
    analyses: &[ObjectAnalysisSummary],
    profile: revx_core::AnalysisProfile,
    source: &str,
    limit: usize,
    mut already_analyzed: Option<&mut std::collections::BTreeSet<String>>,
) -> Result<Option<DugBinaryPromotion>> {
    let candidates = ws.dug_native_binary_candidates(analyses, limit);
    if candidates.is_empty() {
        return Ok(None);
    }
    let mut results = Vec::new();
    let mut evidence_ids = Vec::new();
    let mut analyzed_count = 0usize;
    let mut skipped_count = 0usize;
    let mut warnings = Vec::new();
    for candidate_id in &candidates {
        if let Ok(Some(object)) = ws.resolve_object(candidate_id) {
            if object.size == 0 || object.size > 32 * 1024 * 1024 {
                skipped_count += 1;
                results.push(serde_json::json!({
                    "object_id": candidate_id,
                    "status": "skipped",
                    "reason": "size_out_of_bounds",
                    "size": object.size,
                }));
                continue;
            }
            if let Some(hash) = object.hash_blake3.as_deref() {
                if already_analyzed
                    .as_ref()
                    .is_some_and(|seen| seen.contains(hash))
                    || ws.binary_analysis_exists(hash).unwrap_or(false)
                {
                    skipped_count += 1;
                    if let Some(seen) = already_analyzed.as_mut() {
                        seen.insert(hash.to_string());
                    }
                    results.push(serde_json::json!({
                        "object_id": candidate_id,
                        "status": "skipped",
                        "reason": "already_analyzed",
                        "binary_id": hash,
                    }));
                    continue;
                }
            }
        }
        match analyze_object_as_binary(ws, candidate_id, profile, source) {
            Ok(payload) => {
                analyzed_count += 1;
                if let Some(seen) = already_analyzed.as_mut() {
                    seen.insert(payload.summary.binary_id.clone());
                }
                evidence_ids.push(payload.link_evidence_id.clone());
                evidence_ids.extend(payload.evidence_ids.iter().cloned());
                results.push(serde_json::json!({
                    "object_id": payload.object.id,
                    "display_name": payload.object.display_name,
                    "format": payload.object.format,
                    "binary_run_id": payload.run_id,
                    "binary_id": payload.summary.binary_id,
                    "function_count": payload.summary.function_count,
                    "status": payload.status,
                    "link_evidence_id": payload.link_evidence_id,
                    "evidence_artifact": payload.evidence_artifact,
                    "materialized_artifact": payload.materialized_artifact,
                }));
            }
            Err(err) => {
                warnings.push(format!("{candidate_id}: {err}"));
                results.push(serde_json::json!({
                    "object_id": candidate_id,
                    "status": "failed",
                    "error": err.to_string(),
                }));
            }
        }
    }
    if results.is_empty() {
        return Ok(None);
    }
    evidence_ids.sort();
    evidence_ids.dedup();
    let artifact = ws.write_json_artifact(
        "application/json",
        &serde_json::json!({
            "source": source,
            "profile": profile,
            "candidate_count": candidates.len(),
            "analyzed_count": analyzed_count,
            "skipped_count": skipped_count,
            "results": &results,
            "warnings": &warnings,
        }),
    )?;
    let analysis_id = format!(
        "analysis:auto_binary:{}:{}",
        source,
        artifact.hash_blake3
    );
    let status = if analyzed_count == 0 && warnings.is_empty() && skipped_count > 0 {
        ObjectAnalysisStatus::Skipped
    } else if analyzed_count == 0 {
        ObjectAnalysisStatus::Failed
    } else if warnings.is_empty() {
        ObjectAnalysisStatus::Completed
    } else {
        ObjectAnalysisStatus::Partial
    };
    let analysis = ObjectAnalysisSummary {
        analyzer: "auto_binary".to_string(),
        status,
        summary: format!(
            "Auto-analyzed {analyzed_count}/{} dug native binary candidate(s) with {profile:?} (skipped {skipped_count})",
            candidates.len()
        ),
        details: serde_json::json!({
            "source": source,
            "profile": profile,
            "candidate_count": candidates.len(),
            "analyzed_count": analyzed_count,
            "skipped_count": skipped_count,
            "candidate_ids": candidates,
            "results": results,
            "warnings": warnings,
            "artifact": &artifact,
        }),
        evidence_ids: {
            let mut ids = evidence_ids.clone();
            ids.push(analysis_id.clone());
            ids
        },
    };
    ws.insert_evidence(Evidence {
        id: analysis_id,
        subject: source.to_string(),
        summary: analysis.summary.clone(),
        kind: "object_auto_binary".to_string(),
        details: analysis.details.clone(),
        provenance: EvidenceProvenance {
            source: source.to_string(),
            binary_id: None,
            function_address: None,
            instruction_address: None,
            profile: Some(profile),
        },
    })?;
    Ok(Some(DugBinaryPromotion {
        analysis,
        evidence_ids,
        artifact: Some(artifact),
        analyzed_count,
        candidate_count: candidates.len(),
    }))
}

fn analyze_object_as_binary(
    ws: &Workspace,
    query: &str,
    profile: revx_core::AnalysisProfile,
    source: &str,
) -> Result<ObjectAnalyzeBinaryResponse> {
    let materialized = ws
        .materialize_object(query, 0)?
        .ok_or_else(|| object_lookup_error(ws, query))?;
    let artifact_path = ws.root().join(&materialized.artifact.relative_path);
    let image = load_binary(&artifact_path).with_context(|| {
        format!(
            "failed to parse materialized object {} as binary",
            materialized.object.display_name
        )
    })?;
    let binary_id = image.id.clone();
    let (run_id, summary, evidence_export) = run_binary_analysis(ws, image, profile)?;
    let link_evidence_id = format!(
        "object_binary_analysis:{}:{}:{}",
        materialized.object.id, binary_id, run_id
    );
    ws.insert_evidence(Evidence {
        id: link_evidence_id.clone(),
        subject: materialized
            .object
            .path
            .clone()
            .unwrap_or_else(|| materialized.object.id.clone()),
        summary: format!(
            "Analyzed object {} as binary {} in run {}",
            materialized.object.display_name, binary_id, run_id
        ),
        kind: "object_binary_analysis".to_string(),
        details: serde_json::json!({
            "object": &materialized.object,
            "materialized_artifact": &materialized.artifact,
            "binary_id": &binary_id,
            "run_id": &run_id,
            "summary": &summary,
            "evidence_artifact": &evidence_export.artifact,
        }),
        provenance: EvidenceProvenance {
            source: source.to_string(),
            binary_id: Some(binary_id),
            function_address: None,
            instruction_address: None,
            profile: Some(profile),
        },
    })?;
    Ok(ObjectAnalyzeBinaryResponse {
        object: materialized.object,
        materialized_artifact: materialized.artifact,
        run_id,
        status: revx_core::AnalysisRunState::Completed,
        summary,
        evidence_count: evidence_export.count,
        evidence_ids: evidence_export.preview_ids,
        evidence_artifact: Some(evidence_export.artifact),
        link_evidence_id,
    })
}

fn run_object_carve_identify(
    ws: &Workspace,
    request: ObjectCarveIdentifyRequest,
) -> Result<ObjectCarveIdentifyResponse> {
    let max_depth = request.max_depth.unwrap_or(2);
    let max_children = request.max_children.unwrap_or(256);
    let carved = ws
        .carve_object_signatures(
            &request.query,
            request.limit.unwrap_or(100),
            request.max_object_bytes.unwrap_or(64 * 1024 * 1024),
            request.max_carve_bytes.unwrap_or(64 * 1024 * 1024),
            request.min_confidence.unwrap_or(0.9),
            request.preview_bytes.unwrap_or(64),
        )?
        .ok_or_else(|| object_lookup_error(ws, &request.query))?;

    let mut results = Vec::new();
    let mut evidence_ids = vec![
        carved.scan_evidence_id.clone(),
        carved.carve_evidence_id.clone(),
    ];
    let mut identified_count = 0usize;
    let mut failed_count = 0usize;

    for carve in carved.carves {
        let artifact_path = ws.root().join(&carve.artifact.relative_path);
        match identify_object_graph(&artifact_path, max_depth, max_children).and_then(|graph| {
            let root_id = graph.root_id.clone();
            let object_ids = graph
                .objects
                .iter()
                .map(|object| object.id.clone())
                .collect::<Vec<_>>();
            let object_count = graph.objects.len();
            let edge_count = graph.edges.len();
            let (graph_artifact, graph_evidence_ids) = ws.save_object_graph(&graph)?;
            Ok((
                root_id,
                object_ids,
                object_count,
                edge_count,
                graph_artifact,
                graph_evidence_ids,
            ))
        }) {
            Ok((
                root_id,
                object_ids,
                object_count,
                edge_count,
                graph_artifact,
                mut graph_evidence_ids,
            )) => {
                identified_count += 1;
                let derived_edge = revx_core::ObjectEdge {
                    from: carved.object.id.clone(),
                    to: root_id.clone(),
                    kind: revx_core::ObjectEdgeKind::DerivedFrom,
                    metadata: serde_json::json!({
                        "source": "object_carve_identify",
                        "carve": &carve,
                        "carve_artifact": &carve.artifact,
                        "graph_artifact": &graph_artifact,
                    }),
                };
                let derived_edge_evidence_id =
                    ws.insert_object_edge(&root_id, derived_edge, "object_carve_identify")?;
                graph_evidence_ids.push(derived_edge_evidence_id);
                evidence_ids.extend(graph_evidence_ids.iter().cloned());
                results.push(ObjectCarveIdentifyResult {
                    carve,
                    root_id: Some(root_id),
                    object_ids,
                    object_count,
                    edge_count,
                    evidence_ids: graph_evidence_ids,
                    graph_artifact: Some(graph_artifact),
                    error: None,
                });
            }
            Err(err) => {
                failed_count += 1;
                results.push(ObjectCarveIdentifyResult {
                    carve,
                    root_id: None,
                    object_ids: Vec::new(),
                    object_count: 0,
                    edge_count: 0,
                    evidence_ids: Vec::new(),
                    graph_artifact: None,
                    error: Some(err.to_string()),
                });
            }
        }
    }

    evidence_ids.sort();
    evidence_ids.dedup();
    let report_artifact = ws.write_json_artifact(
        "application/json",
        &serde_json::json!({
            "request": &request,
            "object": &carved.object,
            "source": &carved.source,
            "scanned_size": carved.scanned_size,
            "carved_count": carved.carved_count,
            "identified_count": identified_count,
            "failed_count": failed_count,
            "carve_evidence_id": &carved.carve_evidence_id,
            "carve_artifact": &carved.artifact,
            "results": &results,
            "evidence_ids": &evidence_ids,
        }),
    )?;
    let identify_evidence_id = format!(
        "object_carve_identify:{}:{}",
        carved.object.id, report_artifact.hash_blake3
    );
    evidence_ids.push(identify_evidence_id.clone());
    evidence_ids.sort();
    evidence_ids.dedup();
    ws.insert_evidence(Evidence {
        id: identify_evidence_id.clone(),
        subject: carved
            .object
            .path
            .clone()
            .unwrap_or_else(|| carved.object.id.clone()),
        summary: format!(
            "Identified {} of {} carved embedded object candidate(s)",
            identified_count, carved.carved_count
        ),
        kind: "object_carve_identify".to_string(),
        details: serde_json::json!({
            "object": &carved.object,
            "source": &carved.source,
            "artifact": &report_artifact,
            "carve_artifact": &carved.artifact,
            "carve_evidence_id": &carved.carve_evidence_id,
            "identified_count": identified_count,
            "failed_count": failed_count,
            "results": &results,
            "evidence_ids": &evidence_ids,
        }),
        provenance: EvidenceProvenance {
            source: "object_carve_identify".to_string(),
            binary_id: None,
            function_address: None,
            instruction_address: None,
            profile: None,
        },
    })?;

    Ok(ObjectCarveIdentifyResponse {
        object: carved.object,
        source: carved.source,
        scanned_size: carved.scanned_size,
        carved_count: carved.carved_count,
        identified_count,
        failed_count,
        scan_evidence_id: carved.scan_evidence_id,
        carve_evidence_id: carved.carve_evidence_id,
        identify_evidence_id,
        artifact: report_artifact,
        carves: results,
    })
}

fn run_object_pipeline(
    ws: &Workspace,
    request: ObjectPipelineRequest,
) -> Result<ObjectPipelineResponse> {
    let max_depth = request.max_depth.unwrap_or(4);
    let max_children = request.max_children.unwrap_or(512);
    let object_limit = request.object_limit.unwrap_or(256).clamp(1, 4096);
    let analyze_objects = request.analyze_objects.unwrap_or(true);
    let carve_embedded = request.carve_embedded.unwrap_or(true);
    let analyze_binaries = request.analyze_binaries.unwrap_or(true);
    let binary_profile = request
        .binary_profile
        .unwrap_or(revx_core::AnalysisProfile::Fast);
    let pipeline_plugins = request
        .plugin_ids
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|plugin_id| {
            ws.resolve_object_plugin(plugin_id)?
                .ok_or_else(|| anyhow::anyhow!("object plugin not found: {plugin_id}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let pipeline_id = uuid::Uuid::new_v4().to_string();

    let graph = identify_object_graph(Path::new(&request.path), max_depth, max_children)?;
    let root_id = graph.root_id.clone();
    let initial_object_count = graph.objects.len();
    let mut edge_count = graph.edges.len();
    let (graph_artifact, mut evidence_ids) = ws.save_object_graph(&graph)?;
    let mut steps = vec![ObjectPipelineStep {
        stage: ObjectPipelineStage::Identify,
        object_id: Some(root_id.clone()),
        object_path: Some(request.path.clone()),
        status: ObjectAnalysisStatus::Completed,
        summary: format!(
            "Identified object graph with {initial_object_count} objects and {edge_count} edges"
        ),
        evidence_ids: evidence_ids.clone(),
        artifact: Some(graph_artifact.clone()),
    }];

    let mut known_object_ids = graph
        .objects
        .iter()
        .map(|object| object.id.clone())
        .collect::<BTreeSet<_>>();
    let mut queued_object_ids = BTreeSet::new();
    let mut processed_object_ids = BTreeSet::new();
    let mut counted_graph_roots = BTreeSet::from([root_id.clone()]);
    let mut pending_objects = VecDeque::new();
    for object in &graph.objects {
        if queued_object_ids.insert(object.id.clone()) {
            pending_objects.push_back(object.id.clone());
        }
    }

    let mut analyzed_object_count = 0usize;
    let mut carved_object_count = 0usize;
    let mut identified_embedded_object_count = 0usize;
    let mut failed_embedded_identify_count = 0usize;
    let mut binary_candidate_count = 0usize;
    let mut analyzed_binary_count = 0usize;
    let mut failed_step_count = 0usize;
    let mut analyzed_binary_ids = std::collections::BTreeSet::new();

    while processed_object_ids.len() < object_limit {
        let Some(object_id) = pending_objects.pop_front() else {
            break;
        };
        if !processed_object_ids.insert(object_id.clone()) {
            continue;
        }
        let object = match ws.resolve_object(&object_id) {
            Ok(Some(object)) => object,
            Ok(None) => {
                failed_step_count += 1;
                steps.push(ObjectPipelineStep {
                    stage: ObjectPipelineStage::ObjectAnalyze,
                    object_id: Some(object_id),
                    object_path: None,
                    status: ObjectAnalysisStatus::Failed,
                    summary: "Object disappeared from workspace index during pipeline".to_string(),
                    evidence_ids: Vec::new(),
                    artifact: None,
                });
                continue;
            }
            Err(err) => {
                failed_step_count += 1;
                steps.push(ObjectPipelineStep {
                    stage: ObjectPipelineStage::ObjectAnalyze,
                    object_id: Some(object_id),
                    object_path: None,
                    status: ObjectAnalysisStatus::Failed,
                    summary: err.to_string(),
                    evidence_ids: Vec::new(),
                    artifact: None,
                });
                continue;
            }
        };

        if analyze_objects {
            if matches!(object.kind, ObjectKind::Directory) {
                steps.push(ObjectPipelineStep {
                    stage: ObjectPipelineStage::ObjectAnalyze,
                    object_id: Some(object.id.clone()),
                    object_path: object.path.clone(),
                    status: ObjectAnalysisStatus::Skipped,
                    summary: "Directory structure is represented by object graph edges".to_string(),
                    evidence_ids: Vec::new(),
                    artifact: None,
                });
            } else {
                match ws.analyze_object(&object.id, None) {
                    Ok(Some(mut analysis)) => {
                        analyzed_object_count += 1;
                        if let Some(followup) = promote_dug_native_binaries_tracked(
                            ws,
                            &analysis.analyses,
                            binary_profile,
                            "object_pipeline_auto_binary",
                            4,
                            Some(&mut analyzed_binary_ids),
                        )? {
                            analyzed_binary_count += followup.analyzed_count;
                            binary_candidate_count += followup.candidate_count;
                            evidence_ids.extend(followup.evidence_ids.iter().cloned());
                            analysis.evidence_ids.extend(followup.evidence_ids.iter().cloned());
                            analysis.evidence_ids.sort();
                            analysis.evidence_ids.dedup();
                            analysis.analyses.push(followup.analysis);
                            steps.push(ObjectPipelineStep {
                                stage: ObjectPipelineStage::BinaryAnalyze,
                                object_id: Some(analysis.object.id.clone()),
                                object_path: analysis.object.path.clone(),
                                status: ObjectAnalysisStatus::Completed,
                                summary: format!(
                                    "Auto Fast-analyzed {} dug native binary candidate(s)",
                                    followup.analyzed_count
                                ),
                                evidence_ids: followup.evidence_ids.clone(),
                                artifact: followup.artifact.clone(),
                            });
                        }
                        for analysis_item in &analysis.analyses {
                            if !matches!(
                                analysis_item.analyzer.as_str(),
                                "auto_dig" | "auto_expand"
                            ) {
                                continue;
                            }
                            if let Some(children) = analysis_item
                                .details
                                .get("child_object_ids")
                                .and_then(|value| value.as_array())
                            {
                                for child in children {
                                    let Some(child_id) = child.as_str() else {
                                        continue;
                                    };
                                    known_object_ids.insert(child_id.to_string());
                                    if queued_object_ids.insert(child_id.to_string()) {
                                        pending_objects.push_back(child_id.to_string());
                                    }
                                }
                            }
                        }
                        evidence_ids.extend(analysis.evidence_ids.iter().cloned());
                        steps.push(ObjectPipelineStep {
                            stage: ObjectPipelineStage::ObjectAnalyze,
                            object_id: Some(analysis.object.id.clone()),
                            object_path: analysis.object.path.clone(),
                            status: object_analysis_rollup_status(&analysis.analyses),
                            summary: format!(
                                "Ran {} generic object analyzer(s)",
                                analysis.analyses.len()
                            ),
                            evidence_ids: analysis.evidence_ids,
                            artifact: analysis.artifact,
                        });
                    }
                    Ok(None) => {
                        failed_step_count += 1;
                        steps.push(ObjectPipelineStep {
                            stage: ObjectPipelineStage::ObjectAnalyze,
                            object_id: Some(object.id.clone()),
                            object_path: object.path.clone(),
                            status: ObjectAnalysisStatus::Failed,
                            summary: "Object disappeared from workspace index during pipeline"
                                .to_string(),
                            evidence_ids: Vec::new(),
                            artifact: None,
                        });
                    }
                    Err(err) => {
                        failed_step_count += 1;
                        steps.push(ObjectPipelineStep {
                            stage: ObjectPipelineStage::ObjectAnalyze,
                            object_id: Some(object.id.clone()),
                            object_path: object.path.clone(),
                            status: ObjectAnalysisStatus::Failed,
                            summary: err.to_string(),
                            evidence_ids: Vec::new(),
                            artifact: None,
                        });
                    }
                }
            }
        }

        if carve_embedded && should_pipeline_carve_embedded(&object) {
            match run_object_carve_identify(
                ws,
                ObjectCarveIdentifyRequest {
                    query: object.id.clone(),
                    limit: request.carve_limit.or(Some(32)),
                    max_object_bytes: request.max_carve_object_bytes.or(Some(64 * 1024 * 1024)),
                    max_carve_bytes: request.max_carve_bytes.or(Some(64 * 1024 * 1024)),
                    min_confidence: request.min_carve_confidence.or(Some(0.9)),
                    preview_bytes: Some(64),
                    max_depth: request.carve_max_depth.or(Some(2)),
                    max_children: request.carve_max_children.or(Some(max_children)),
                },
            ) {
                Ok(carved) => {
                    carved_object_count += carved.carved_count;
                    identified_embedded_object_count += carved.identified_count;
                    failed_embedded_identify_count += carved.failed_count;
                    if carved.failed_count > 0 {
                        failed_step_count += carved.failed_count;
                    }
                    evidence_ids.push(carved.scan_evidence_id.clone());
                    evidence_ids.push(carved.carve_evidence_id.clone());
                    evidence_ids.push(carved.identify_evidence_id.clone());
                    let mut discovered_object_count = 0usize;
                    let mut queued_embedded_object_count = 0usize;
                    let mut discovered_edge_count = 0usize;
                    for result in &carved.carves {
                        evidence_ids.extend(result.evidence_ids.iter().cloned());
                        if let Some(root_id) = &result.root_id {
                            if counted_graph_roots.insert(root_id.clone()) {
                                edge_count += result.edge_count;
                                discovered_edge_count += result.edge_count;
                            }
                        }
                        for object_id in &result.object_ids {
                            if known_object_ids.insert(object_id.clone()) {
                                discovered_object_count += 1;
                            }
                            if queued_object_ids.insert(object_id.clone()) {
                                pending_objects.push_back(object_id.clone());
                                queued_embedded_object_count += 1;
                            }
                        }
                    }
                    steps.push(ObjectPipelineStep {
                        stage: ObjectPipelineStage::CarveIdentify,
                        object_id: Some(carved.object.id.clone()),
                        object_path: carved.object.path.clone(),
                        status: if carved.failed_count == 0 {
                            ObjectAnalysisStatus::Completed
                        } else if carved.identified_count > 0 {
                            ObjectAnalysisStatus::Partial
                        } else {
                            ObjectAnalysisStatus::Failed
                        },
                        summary: format!(
                            "Carved {} embedded candidate(s), identified {} object graph(s), discovered {} object(s)/{} edge(s), and queued {} object(s)",
                            carved.carved_count,
                            carved.identified_count,
                            discovered_object_count,
                            discovered_edge_count,
                            queued_embedded_object_count
                        ),
                        evidence_ids: vec![
                            carved.scan_evidence_id,
                            carved.carve_evidence_id,
                            carved.identify_evidence_id,
                        ],
                        artifact: Some(carved.artifact),
                    });
                }
                Err(err) => {
                    failed_step_count += 1;
                    steps.push(ObjectPipelineStep {
                        stage: ObjectPipelineStage::CarveIdentify,
                        object_id: Some(object.id.clone()),
                        object_path: object.path.clone(),
                        status: ObjectAnalysisStatus::Failed,
                        summary: err.to_string(),
                        evidence_ids: Vec::new(),
                        artifact: None,
                    });
                }
            }
        }

        if !pipeline_plugins.is_empty() && !matches!(object.kind, ObjectKind::Directory) {
            for plugin in &pipeline_plugins {
                if !plugin_accepts_object(plugin, &object) {
                    continue;
                }
                match run_object_plugin(ws, &plugin.id, &object.id, plugin.timeout_ms) {
                    Ok(plugin_result) => {
                        evidence_ids.push(plugin_result.evidence_id.clone());
                        steps.push(ObjectPipelineStep {
                            stage: ObjectPipelineStage::PluginAnalyze,
                            object_id: Some(plugin_result.object.id.clone()),
                            object_path: plugin_result.object.path.clone(),
                            status: plugin_result.status,
                            summary: format!(
                                "Plugin {}: {}",
                                plugin_result.plugin.id, plugin_result.summary
                            ),
                            evidence_ids: vec![plugin_result.evidence_id],
                            artifact: Some(plugin_result.artifact),
                        });
                    }
                    Err(err) => {
                        failed_step_count += 1;
                        steps.push(ObjectPipelineStep {
                            stage: ObjectPipelineStage::PluginAnalyze,
                            object_id: Some(object.id.clone()),
                            object_path: object.path.clone(),
                            status: ObjectAnalysisStatus::Failed,
                            summary: format!("Plugin {} failed: {err}", plugin.id),
                            evidence_ids: Vec::new(),
                            artifact: None,
                        });
                    }
                }
            }
        }

        if analyze_binaries && is_native_binary_candidate(&object) {
            binary_candidate_count += 1;
            let already = object
                .hash_blake3
                .as_deref()
                .is_some_and(|hash| analyzed_binary_ids.contains(hash))
                || object
                    .hash_blake3
                    .as_deref()
                    .is_some_and(|hash| ws.binary_analysis_exists(hash).unwrap_or(false));
            if already {
                steps.push(ObjectPipelineStep {
                    stage: ObjectPipelineStage::BinaryAnalyze,
                    object_id: Some(object.id.clone()),
                    object_path: object.path.clone(),
                    status: ObjectAnalysisStatus::Skipped,
                    summary: "Skipped native binary analysis: already analyzed".to_string(),
                    evidence_ids: Vec::new(),
                    artifact: None,
                });
            } else {
                match analyze_object_as_binary(ws, &object.id, binary_profile, "object_pipeline") {
                    Ok(binary) => {
                        analyzed_binary_count += 1;
                        analyzed_binary_ids.insert(binary.summary.binary_id.clone());
                        evidence_ids.push(binary.link_evidence_id.clone());
                        evidence_ids.extend(binary.evidence_ids.iter().cloned());
                        steps.push(ObjectPipelineStep {
                            stage: ObjectPipelineStage::BinaryAnalyze,
                            object_id: Some(binary.object.id.clone()),
                            object_path: binary.object.path.clone(),
                            status: ObjectAnalysisStatus::Completed,
                            summary: format!(
                                "Analyzed as {:?}/{:?}: {} functions, {} strings",
                                binary.summary.format,
                                binary.summary.architecture,
                                binary.summary.function_count,
                                binary.summary.string_count
                            ),
                            evidence_ids: {
                                let mut ids = binary.evidence_ids;
                                ids.push(binary.link_evidence_id);
                                ids
                            },
                            artifact: binary.evidence_artifact,
                        });
                    }
                    Err(err) => {
                        failed_step_count += 1;
                        steps.push(ObjectPipelineStep {
                            stage: ObjectPipelineStage::BinaryAnalyze,
                            object_id: Some(object.id.clone()),
                            object_path: object.path.clone(),
                            status: ObjectAnalysisStatus::Failed,
                            summary: err.to_string(),
                            evidence_ids: Vec::new(),
                            artifact: None,
                        });
                    }
                }
            }
        }
    }

    let object_count = known_object_ids.len();
    evidence_ids.sort();
    evidence_ids.dedup();
    let summary_evidence_id = format!("object_pipeline:{pipeline_id}:summary");
    let summary = format!(
        "Pipeline analyzed {analyzed_object_count}/{object_count} objects, carved {carved_object_count} embedded candidate(s), identified {identified_embedded_object_count} embedded graph(s), and analyzed {analyzed_binary_count}/{binary_candidate_count} native binary candidates"
    );
    steps.push(ObjectPipelineStep {
        stage: ObjectPipelineStage::PipelineSummary,
        object_id: Some(root_id.clone()),
        object_path: Some(request.path.clone()),
        status: if failed_step_count == 0 {
            ObjectAnalysisStatus::Completed
        } else {
            ObjectAnalysisStatus::Partial
        },
        summary: summary.clone(),
        evidence_ids: vec![summary_evidence_id.clone()],
        artifact: None,
    });
    evidence_ids.push(summary_evidence_id.clone());
    evidence_ids.sort();
    evidence_ids.dedup();

    let report_artifact = ws.write_json_artifact(
        "application/json",
        &serde_json::json!({
            "pipeline_id": &pipeline_id,
            "request": &request,
            "root_id": &root_id,
            "graph_artifact": &graph_artifact,
            "object_count": object_count,
            "edge_count": edge_count,
            "analyzed_object_count": analyzed_object_count,
            "carved_object_count": carved_object_count,
            "identified_embedded_object_count": identified_embedded_object_count,
            "failed_embedded_identify_count": failed_embedded_identify_count,
            "binary_candidate_count": binary_candidate_count,
            "analyzed_binary_count": analyzed_binary_count,
            "failed_step_count": failed_step_count,
            "evidence_ids": &evidence_ids,
            "steps": &steps,
        }),
    )?;
    ws.insert_evidence(Evidence {
        id: summary_evidence_id,
        subject: request.path.clone(),
        summary,
        kind: "object_pipeline_summary".to_string(),
        details: serde_json::json!({
            "pipeline_id": &pipeline_id,
            "root_id": &root_id,
            "graph_artifact": &graph_artifact,
            "report_artifact": &report_artifact,
            "object_count": object_count,
            "edge_count": edge_count,
            "analyzed_object_count": analyzed_object_count,
            "carved_object_count": carved_object_count,
            "identified_embedded_object_count": identified_embedded_object_count,
            "failed_embedded_identify_count": failed_embedded_identify_count,
            "binary_candidate_count": binary_candidate_count,
            "analyzed_binary_count": analyzed_binary_count,
            "failed_step_count": failed_step_count,
        }),
        provenance: EvidenceProvenance {
            source: "object_pipeline".to_string(),
            binary_id: None,
            function_address: None,
            instruction_address: None,
            profile: Some(binary_profile),
        },
    })?;

    let next_actions = derive_pipeline_next_actions(
        &root_id,
        object_count,
        carved_object_count,
        identified_embedded_object_count,
        binary_candidate_count,
        analyzed_binary_count,
        failed_step_count,
        &steps,
    );
    let agent_brief = derive_pipeline_agent_brief(
        &root_id,
        object_count,
        analyzed_object_count,
        carved_object_count,
        binary_candidate_count,
        analyzed_binary_count,
        failed_step_count,
        &next_actions,
    );
    Ok(ObjectPipelineResponse {
        pipeline_id,
        root_id,
        object_count,
        edge_count,
        analyzed_object_count,
        carved_object_count,
        identified_embedded_object_count,
        failed_embedded_identify_count,
        binary_candidate_count,
        analyzed_binary_count,
        failed_step_count,
        evidence_count: evidence_ids.len(),
        evidence_ids,
        graph_artifact,
        report_artifact,
        steps,
        next_actions,
        agent_brief,
    })
}

fn object_analysis_rollup_status(
    analyses: &[revx_core::ObjectAnalysisSummary],
) -> ObjectAnalysisStatus {
    if analyses
        .iter()
        .any(|analysis| analysis.status == ObjectAnalysisStatus::Failed)
    {
        ObjectAnalysisStatus::Failed
    } else if analyses
        .iter()
        .any(|analysis| analysis.status == ObjectAnalysisStatus::Partial)
    {
        ObjectAnalysisStatus::Partial
    } else {
        ObjectAnalysisStatus::Completed
    }
}

fn should_pipeline_carve_embedded(object: &UniversalObject) -> bool {
    if matches!(object.kind, ObjectKind::Directory) || object.size == 0 {
        return false;
    }
    if matches!(object.kind, ObjectKind::Text) {
        return false;
    }
    match object.format.as_deref() {
        Some("unknown" | "bin" | "raw") | None => true,
        Some("elf" | "pe" | "macho" | "macho_fat" | "dex" | "wasm") => true,
        Some(
            "pdf" | "png" | "jpeg" | "gif" | "bmp" | "dib" | "tiff" | "ico" | "webp" | "heif"
                | "heic" | "avif",
        ) => true,
        Some(
            "mp4" | "m4a" | "m4v" | "mov" | "avi" | "wav" | "flac" | "ogg" | "mp3" | "riff",
        ) => true,
        Some(
            "cab" | "ar" | "7z" | "rar" | "gzip" | "xz" | "zstd" | "bzip2" | "zip" | "tar"
                | "tar.gz" | "tar.bz2" | "tar.xz" | "tar.zst",
        ) => true,
        Some("qcow2" | "iso" | "dmg" | "vmdk" | "img") => true,
        Some("woff" | "woff2" | "ttf" | "otf") => true,
        Some("sqlite" | "pcap" | "pcapng" | "ole" | "doc" | "xls" | "ppt" | "msi" | "msg") => true,
        _ => matches!(
            object.kind,
            ObjectKind::File
                | ObjectKind::Archive
                | ObjectKind::Package
                | ObjectKind::Image
                | ObjectKind::Document
                | ObjectKind::FilesystemImage
                | ObjectKind::MemoryDump
                | ObjectKind::NetworkCapture
                | ObjectKind::Unknown
        ),
    }
}

fn is_native_binary_candidate(object: &UniversalObject) -> bool {
    matches!(object.kind, ObjectKind::Binary)
        && matches!(
            object.format.as_deref(),
            Some("elf" | "pe" | "macho" | "macho_fat")
        )
}

fn run_binary_analysis(
    ws: &Workspace,
    image: revx_core::BinaryImage,
    profile: revx_core::AnalysisProfile,
) -> Result<(
    String,
    revx_core::AnalysisSummary,
    revx_workspace::EvidenceIdExport,
)> {
    let mut ingest = ws.begin_analysis_run(&image, profile)?;
    // Move image into streaming analysis; image data will not be needed afterwards.
    let streamed = analyze_streaming(image, profile, |function| ingest.ingest_function(function))?;
    let binary_path_for_evidence = streamed.survey.binary.path.clone();
    let summary = streamed.survey.summary.clone();
    let run_id = ingest.finalize(
        streamed.survey,
        streamed.references,
        streamed.types,
        &streamed.strings,
    )?;
    let evidence_export = ws.export_evidence_ids_by_subject(&binary_path_for_evidence, 32)?;
    Ok((run_id, summary, evidence_export))
}

fn address_in_any_range(address: u64, ranges: &[(u64, u64)]) -> bool {
    ranges
        .iter()
        .any(|(start, end)| address >= *start && address < *end)
}

fn dedupe_references_in_place(refs: &mut Vec<revx_core::Reference>) {
    let mut seen = BTreeSet::new();
    refs.retain(|reference| seen.insert((reference.from, reference.to, reference.kind.clone())));
}

fn dedupe_call_edges_in_place(edges: &mut Vec<revx_core::CallEdge>) {
    let mut seen = BTreeSet::new();
    edges.retain(|edge| {
        seen.insert((
            edge.caller_address,
            edge.callee_address,
            edge.kind.clone(),
            edge.callee_name.clone(),
        ))
    });
}

fn function_lookup_error(ws: &Workspace, query: &str) -> anyhow::Error {
    match ws.search_functions(query) {
        Ok(candidates) if !candidates.is_empty() => {
            let preview = candidates
                .into_iter()
                .take(5)
                .map(|hit| format!("{}@0x{:x}", hit.name, hit.address))
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::anyhow!("function not found: {query}. candidates: {preview}")
        }
        _ => anyhow::anyhow!("function not found: {query}"),
    }
}

fn object_lookup_error(ws: &Workspace, query: &str) -> anyhow::Error {
    match ws.search_objects(query, None, 5) {
        Ok(candidates) if !candidates.is_empty() => {
            let preview = candidates
                .into_iter()
                .map(|hit| {
                    let locator = hit.path.unwrap_or(hit.id);
                    format!(
                        "{} ({:?}/{})",
                        locator,
                        hit.kind,
                        hit.format.unwrap_or_default()
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::anyhow!("object not found: {query}. candidates: {preview}")
        }
        _ => anyhow::anyhow!("object not found: {query}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CapabilityService, address_in_any_range, function_lookup_error, mcp_response_summary,
        mcp_tools_manifest, tool_name_to_request,
    };
    use revx_core::{
        AnalysisBundle, AnalysisProfile, AnalysisSummary, Architecture, BasicBlock, BinaryFormat,
        CapabilityRequest, CapabilityResponse, DebugCoverageSummary, DebugImportStatus,
        DebugImportSummary, Function, Instruction, ObjectAnalyzeRequest, PROJECT_SCHEMA_VERSION,
        AgentInteractionBrief, PseudocodeRegion, PseudocodeUnit, RegionKind, StackSummary, StringLiteral, Survey, TypeDef,
        TypeSource, Variable, VariableRole, VariableStorage,
    };
    use revx_workspace::Workspace;
    use tempfile::tempdir;

    #[test]
    fn mcp_response_summary_includes_decompile_text() {
        let response = CapabilityResponse::DecompileFunction(revx_core::DecompileFunctionResponse {
            function_name: "main".to_string(),
            address: 0x1000,
            pseudocode: Some(PseudocodeUnit {
                language: "c".to_string(),
                text: "int main() {\n  return 0;\n}".to_string(),
                regions: vec![PseudocodeRegion {
                    id: "r0".to_string(),
                    kind: RegionKind::Block,
                    start_address: Some(0x1000),
                    end_address: Some(0x1010),
                    header: Some("entry".to_string()),
                    statements: vec!["return 0;".to_string()],
                    children: Vec::new(),
                    evidence_ids: Vec::new(),
                }],
                region_artifact: None,
                evidence_ids: vec!["ev1".to_string()],
                semantic_lattice: None,
            }),
            evidence_ids: vec!["ev1".to_string()],
            artifact: None,
            strategy_used: Default::default(),
            cache_hit: false,
            available_strategies: Vec::new(),
                        agent_brief: Default::default(),
        });
        let text = mcp_response_summary(&response);
        assert!(text.contains("# decompile_function"));
        assert!(text.contains("int main()"));
        assert!(text.contains("return 0;"));
        assert!(text.contains("## Regions"));
    }

    #[test]
    fn mcp_response_summary_surfaces_casl_lattice_before_pseudocode() {
        let lattice = revx_analysis::build_agent_semantic_lattice(
            "main",
            0x1000,
            r#"
int main(int argc, char **argv) {
    _isatty(1);
    _getenv("COLUMNS");
    _getopt_long(argc, argv, "abcd", /*?*/);
    // switch ((opt - 37)) via jump table; // 0x1100 bound=91
    return 0;
}
"#,
            &[],
        );
        assert!(!lattice.claims.is_empty());
        let response = CapabilityResponse::DecompileFunction(revx_core::DecompileFunctionResponse {
            function_name: "main".to_string(),
            address: 0x1000,
            pseudocode: Some(PseudocodeUnit {
                language: "c".to_string(),
                text: "int main() {\n  _getopt_long(argc, argv, \"abcd\");\n  return 0;\n}".to_string(),
                regions: Vec::new(),
                region_artifact: None,
                evidence_ids: vec!["ev1".to_string()],
                semantic_lattice: Some(lattice.clone()),
            }),
            evidence_ids: vec!["ev1".to_string()],
            artifact: None,
            strategy_used: Default::default(),
            cache_hit: false,
            available_strategies: Vec::new(),
            agent_brief: AgentInteractionBrief {
                headline: "CASL main".to_string(),
                key_findings: vec!["casl_thesis: test".to_string()],
                open_questions: Vec::new(),
                next_actions: Vec::new(),
                stop_conditions: Vec::new(),
                semantic_lattice: Some(lattice),
            },
        });
        let text = mcp_response_summary(&response);
        let lattice_pos = text.find("## Semantic Lattice").expect("casl section");
        let pseudo_pos = text.find("## Pseudocode").expect("pseudocode section");
        assert!(lattice_pos < pseudo_pos, "CASL must precede raw pseudocode");
        assert!(text.contains("### Claims"));
        assert!(text.contains("### Anchors"));
        assert!(text.contains("getopt") || text.contains("CLI") || text.contains("COLUMNS"));
    }


    #[test]
    fn mcp_response_summary_includes_function_profile_graph() {
        let response = CapabilityResponse::FunctionProfile(revx_core::FunctionProfileResponse {
            function: Function {
                name: "foo".to_string(),
                address: 0x2000,
                size: 32,
                blocks: vec![BasicBlock {
                    address: 0x2000,
                    size: 8,
                    instructions: vec![Instruction {
                        address: 0x2000,
                        bytes: "d503201f".into(),
                        text: "nop".into(),
                    }],
                }],
                stack_summary: Some(StackSummary {
                    frame_size: Some(0x20),
                    calling_convention: Some("aarch64".to_string()),
                    return_type: Some("int".to_string()),
                    stack_arg_bytes: Some(0),
                    evidence_ids: Vec::new(),
                }),
                arguments: vec![Variable {
                    name: "arg0".to_string(),
                    role: VariableRole::Argument,
                    storage: VariableStorage::Register,
                    type_name: Some("int".to_string()),
                    confidence: 0.9,
                    location: "x0".to_string(),
                    evidence_ids: Vec::new(),
                }],
                locals: Vec::new(),
                pseudocode: Some(PseudocodeUnit {
                    language: "c".to_string(),
                    text: "int foo(int arg0) { return arg0; }".to_string(),
                    regions: Vec::new(),
                    region_artifact: None,
                    evidence_ids: Vec::new(),
                    semantic_lattice: None,
                }),
                evidence_ids: vec!["fn:foo".to_string()],
                warnings: Vec::new(),
            },
            incoming_xrefs: vec![revx_core::Reference {
                from: 0x1500,
                to: 0x2000,
                kind: revx_core::ReferenceKind::Call,
            }],
            outgoing_xrefs: vec![revx_core::Reference {
                from: 0x2008,
                to: 0x3000,
                kind: revx_core::ReferenceKind::Call,
            }],
            callers: vec![revx_core::CallEdge {
                caller_name: "bar".to_string(),
                caller_address: 0x1500,
                callee_name: Some("foo".to_string()),
                callee_address: 0x2000,
                kind: "call".to_string(),
            }],
            callees: vec![revx_core::CallEdge {
                caller_name: "foo".to_string(),
                caller_address: 0x2000,
                callee_name: Some("baz".to_string()),
                callee_address: 0x3000,
                kind: "call".to_string(),
            }],
            artifact: None,
            agent_brief: Default::default(),
        });
        let text = mcp_response_summary(&response);
        assert!(text.contains("# function_profile"));
        assert!(text.contains("name: foo"));
        assert!(text.contains("## Callers"));
        assert!(text.contains("bar"));
        assert!(text.contains("## Callees"));
        assert!(text.contains("baz"));
        assert!(text.contains("int foo(int arg0)"));
        assert!(text.contains("## Arguments"));
        assert!(text.contains("arg0"));
    }

    #[test]
    fn mcp_response_summary_lists_string_matches() {
        let response = CapabilityResponse::StringSearch(revx_core::StringSearchResponse {
            matches: vec![
                StringLiteral {
                    address: Some(0x4000),
                    value: "GameRoot::ActiveDesk".to_string(),
                },
                StringLiteral {
                    address: Some(0x4010),
                    value: "Camera".to_string(),
                },
            ],
            agent_brief: Default::default(),
        });
        let text = mcp_response_summary(&response);
        assert!(text.contains("# string_search"));
        assert!(text.contains("GameRoot::ActiveDesk"));
        assert!(text.contains("0x4000"));
        assert!(text.contains("xrefs_query"));
    }

    #[test]
    fn mcp_response_summary_truncates_very_large_text() {
        let huge = "A".repeat(30_000);
        let response = CapabilityResponse::DecompileFunction(revx_core::DecompileFunctionResponse {
            function_name: "big".to_string(),
            address: 0x1,
            pseudocode: Some(PseudocodeUnit {
                language: "c".to_string(),
                text: huge,
                regions: Vec::new(),
                region_artifact: None,
                evidence_ids: Vec::new(),
                    semantic_lattice: None,
                }),
            evidence_ids: Vec::new(),
            artifact: None,
            strategy_used: Default::default(),
            cache_hit: false,
            available_strategies: Vec::new(),
            agent_brief: Default::default(),
        });
        let text = mcp_response_summary(&response);
        assert!(text.contains("...[truncated]"));
        assert!(text.chars().count() < 30_000);
    }

    #[test]
    fn address_range_match_is_half_open() {

        let ranges = vec![(0x1000, 0x1100), (0x2000, 0x2100)];
        assert!(address_in_any_range(0x1000, &ranges));
        assert!(address_in_any_range(0x10ff, &ranges));
        assert!(!address_in_any_range(0x1100, &ranges));
        assert!(address_in_any_range(0x2008, &ranges));
        assert!(!address_in_any_range(0x1fff, &ranges));
    }

    #[test]
    fn function_lookup_error_includes_candidates() {
        let dir = tempdir().unwrap();
        let ws = Workspace::init(dir.path(), "test", None).unwrap();
        ws.save_analysis(
            sample_bundle("binary-1", "/tmp/test.bin"),
            AnalysisProfile::Fast,
        )
        .unwrap();

        let error = function_lookup_error(&ws, "tp2_sdk_ioctl");
        let message = error.to_string();
        assert!(message.contains("function not found: tp2_sdk_ioctl"));
        assert!(message.contains("tss_sdk_ioctl@0x401000"));
        let cfg = ws.project_config().unwrap();
        assert_eq!(cfg.schema_version, PROJECT_SCHEMA_VERSION);
    }

    #[test]
    fn mcp_manifest_exposes_object_navigation_tools() {
        let tools = mcp_tools_manifest();
        let names = tools
            .iter()
            .filter_map(|tool| tool["name"].as_str().map(str::to_string))
            .collect::<Vec<_>>();
        assert!(names.iter().any(|name| name == "object_identify"));
        assert!(names.iter().any(|name| name == "object_search"));
        assert!(names.iter().any(|name| name == "object_profile"));
        assert!(names.iter().any(|name| name == "object_materialize"));
        assert!(names.iter().any(|name| name == "object_extract_range"));
        assert!(names.iter().any(|name| name == "object_scan_signatures"));
        assert!(names.iter().any(|name| name == "object_carve_signatures"));
        assert!(names.iter().any(|name| name == "object_carve_identify"));
        assert!(names.iter().any(|name| name == "object_analyze"));
        assert!(names.iter().any(|name| name == "object_plugin_list"));
        assert!(names.iter().any(|name| name == "object_plugin_run"));
        assert!(names.iter().any(|name| name == "object_register_binary"));
        assert!(names.iter().any(|name| name == "object_analyze_binary"));
        assert!(names.iter().any(|name| name == "object_pipeline"));
        assert!(names.iter().any(|name| name == "evidence_graph"));
        assert!(names.iter().any(|name| name == "symbolic_solve"));
        assert!(names.iter().any(|name| name == "investigation_run"));
        assert!(names.iter().any(|name| name == "analysis_brief"));
        assert!(names.iter().any(|name| name == "ibc_status"));
        assert!(names.iter().any(|name| name == "ibc_advance"));
        assert!(names.iter().any(|name| name == "artifact_read"));
        assert!(names.iter().any(|name| name == "artifact_list"));
        assert!(names.iter().any(|name| name == "search_bytes"));
        assert!(names.iter().any(|name| name == "object_search_content"));

        let object_analyze = tools
            .iter()
            .find(|tool| tool["name"] == serde_json::json!("object_analyze"))
            .expect("object_analyze tool manifest");
        let analyzer_enum =
            object_analyze["inputSchema"]["properties"]["analyzers"]["items"]["enum"]
                .as_array()
                .expect("analyzer enum");
        assert!(analyzer_enum.iter().any(|value| value == "structured_text"));
        assert!(
            analyzer_enum
                .iter()
                .any(|value| value == "open_xml_document")
        );
        assert!(analyzer_enum.iter().any(|value| value == "android_package"));
        assert!(analyzer_enum.iter().any(|value| value == "dex_bytecode"));
        assert!(analyzer_enum.iter().any(|value| value == "ios_package"));
        assert!(analyzer_enum.iter().any(|value| value == "java_archive"));
        assert!(analyzer_enum.iter().any(|value| value == "jvm_class"));
        assert!(analyzer_enum.iter().any(|value| value == "python_bytecode"));
        assert!(analyzer_enum.iter().any(|value| value == "shell_link"));
        assert!(
            analyzer_enum
                .iter()
                .any(|value| value == "portable_executable")
        );
        assert!(analyzer_enum.iter().any(|value| value == "dotnet_metadata"));
        assert!(analyzer_enum.iter().any(|value| value == "elf_binary"));
        assert!(analyzer_enum.iter().any(|value| value == "macho_binary"));
        assert!(analyzer_enum.iter().any(|value| value == "sqlite_schema"));
        assert!(analyzer_enum.iter().any(|value| value == "wasm_module"));
        assert!(analyzer_enum.iter().any(|value| value == "pdf_document"));
        assert!(analyzer_enum.iter().any(|value| value == "png_image"));
        assert!(analyzer_enum.iter().any(|value| value == "jpeg_image"));
        assert!(analyzer_enum.iter().any(|value| value == "gif_image"));
        assert!(analyzer_enum.iter().any(|value| value == "bmp_image"));
        assert!(analyzer_enum.iter().any(|value| value == "riff_container"));
        assert!(analyzer_enum.iter().any(|value| value == "pcap_capture"));
        assert!(analyzer_enum.iter().any(|value| value == "ole_compound"));
        assert!(
            analyzer_enum
                .iter()
                .any(|value| value == "safe_tensors_model")
        );
        assert!(analyzer_enum.iter().any(|value| value == "gguf_model"));
        assert!(analyzer_enum.iter().any(|value| value == "pytorch_model"));
        assert!(analyzer_enum.iter().any(|value| value == "iso_bmff"));
        assert!(analyzer_enum.iter().any(|value| value == "cab_archive"));
        assert!(analyzer_enum.iter().any(|value| value == "unknown_blob"));
    }

    #[test]
    fn mcp_tool_names_parse_to_object_capabilities() {
        let search = tool_name_to_request(
            "object_search",
            serde_json::json!({
                "query": "classes.dex",
                "kind": "binary",
                "limit": 5
            }),
        )
        .unwrap();
        assert!(matches!(search, CapabilityRequest::ObjectSearch(_)));

        let profile = tool_name_to_request(
            "object_profile",
            serde_json::json!({ "query": "classes.dex" }),
        )
        .unwrap();
        assert!(matches!(profile, CapabilityRequest::ObjectProfile(_)));

        let materialize = tool_name_to_request(
            "object_materialize",
            serde_json::json!({ "query": "classes.dex", "preview_bytes": 16 }),
        )
        .unwrap();
        assert!(matches!(
            materialize,
            CapabilityRequest::ObjectMaterialize(_)
        ));

        let extract_range = tool_name_to_request(
            "object_extract_range",
            serde_json::json!({
                "query": "payload.bin",
                "offset": 1,
                "length": 4,
                "context_bytes": 1,
                "preview_bytes": 16
            }),
        )
        .unwrap();
        assert!(matches!(
            extract_range,
            CapabilityRequest::ObjectExtractRange(_)
        ));

        let scan_signatures = tool_name_to_request(
            "object_scan_signatures",
            serde_json::json!({
                "query": "firmware.blob",
                "limit": 20,
                "max_object_bytes": 1048576,
                "preview_bytes": 16
            }),
        )
        .unwrap();
        assert!(matches!(
            scan_signatures,
            CapabilityRequest::ObjectSignatureScan(_)
        ));

        let carve_signatures = tool_name_to_request(
            "object_carve_signatures",
            serde_json::json!({
                "query": "firmware.blob",
                "limit": 20,
                "max_object_bytes": 1048576,
                "max_carve_bytes": 1048576,
                "min_confidence": 0.9,
                "preview_bytes": 16
            }),
        )
        .unwrap();
        assert!(matches!(
            carve_signatures,
            CapabilityRequest::ObjectCarveSignatures(_)
        ));

        let carve_identify = tool_name_to_request(
            "object_carve_identify",
            serde_json::json!({
                "query": "firmware.blob",
                "limit": 20,
                "max_object_bytes": 1048576,
                "max_carve_bytes": 1048576,
                "min_confidence": 0.9,
                "preview_bytes": 16,
                "max_depth": 2,
                "max_children": 32
            }),
        )
        .unwrap();
        assert!(matches!(
            carve_identify,
            CapabilityRequest::ObjectCarveIdentify(_)
        ));

        let analyze = tool_name_to_request(
            "object_analyze",
            serde_json::json!({
                "query": "classes.dex",
                "analyzers": ["byte_histogram", "strings", "structured_text"]
            }),
        )
        .unwrap();
        assert!(matches!(analyze, CapabilityRequest::ObjectAnalyze(_)));

        let plugin_list =
            tool_name_to_request("object_plugin_list", serde_json::json!({})).unwrap();
        assert!(matches!(
            plugin_list,
            CapabilityRequest::ObjectPluginList(_)
        ));

        let plugin_run = tool_name_to_request(
            "object_plugin_run",
            serde_json::json!({
                "plugin_id": "json-shape",
                "query": "assets/config.json",
                "timeout_ms": 1000
            }),
        )
        .unwrap();
        assert!(matches!(plugin_run, CapabilityRequest::ObjectPluginRun(_)));

        let register_binary = tool_name_to_request(
            "object_register_binary",
            serde_json::json!({ "query": "lib/arm64-v8a/libdemo.so" }),
        )
        .unwrap();
        assert!(matches!(
            register_binary,
            CapabilityRequest::ObjectRegisterBinary(_)
        ));

        let analyze_binary = tool_name_to_request(
            "object_analyze_binary",
            serde_json::json!({
                "query": "lib/arm64-v8a/libdemo.so",
                "profile": "fast"
            }),
        )
        .unwrap();
        assert!(matches!(
            analyze_binary,
            CapabilityRequest::ObjectAnalyzeBinary(_)
        ));

        let pipeline = tool_name_to_request(
            "object_pipeline",
            serde_json::json!({
                "path": "/tmp/payload.apk",
                "max_depth": 3,
                "carve_embedded": true,
                "carve_limit": 8,
                "analyze_binaries": false,
                "binary_profile": "fast"
            }),
        )
        .unwrap();
        assert!(matches!(pipeline, CapabilityRequest::ObjectPipeline(_)));

        let bytes = tool_name_to_request(
            "search_bytes",
            serde_json::json!({ "pattern": "7f 45 4c 46" }),
        )
        .unwrap();
        assert!(matches!(bytes, CapabilityRequest::SearchBytes(_)));

        let object_content = tool_name_to_request(
            "object_search_content",
            serde_json::json!({
                "pattern": "NEEDLE_TOKEN",
                "mode": "text",
                "query": "config.json",
                "limit": 5,
                "per_object_limit": 2,
                "max_object_bytes": 1048576
            }),
        )
        .unwrap();
        assert!(matches!(
            object_content,
            CapabilityRequest::ObjectContentSearch(_)
        ));

        let artifact = tool_name_to_request(
            "artifact_read",
            serde_json::json!({
                "relative_path": "artifacts/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "offset": 0,
                "max_bytes": 64
            }),
        )
        .unwrap();
        assert!(matches!(artifact, CapabilityRequest::ArtifactRead(_)));

        let artifact_list = tool_name_to_request(
            "artifact_list",
            serde_json::json!({
                "query": "report",
                "content_type": "json",
                "role": "evidence_detail",
                "limit": 5,
                "include_unreferenced": true
            }),
        )
        .unwrap();
        assert!(matches!(artifact_list, CapabilityRequest::ArtifactList(_)));

        let evidence_graph = tool_name_to_request(
            "evidence_graph",
            serde_json::json!({
                "subject": "classes.dex",
                "depth": 2,
                "limit": 25
            }),
        )
        .unwrap();
        assert!(matches!(
            evidence_graph,
            CapabilityRequest::EvidenceGraph(_)
        ));

        let symbolic = tool_name_to_request(
            "symbolic_solve",
            serde_json::json!({
                "subject": "auth-branch",
                "variables": [
                    { "name": "x", "domain": { "kind": "int_range", "min": 0, "max": 10 } }
                ],
                "constraints": [
                    {
                        "id": "x_eq_7",
                        "left": { "terms": [{ "variable": "x", "coefficient": 1 }], "constant": 0 },
                        "op": "eq",
                        "right": { "terms": [], "constant": 7 }
                    }
                ]
            }),
        )
        .unwrap();
        assert!(matches!(symbolic, CapabilityRequest::SymbolicSolve(_)));

        let investigation = tool_name_to_request(
            "investigation_run",
            serde_json::json!({
                "subject": "config.json",
                "path": "/tmp/config.json",
                "run_object_pipeline": true,
                "graph_depth": 2,
                "graph_limit": 100,
                "analyze_binaries": false
            }),
        )
        .unwrap();
        assert!(matches!(
            investigation,
            CapabilityRequest::InvestigationRun(_)
        ));

        let brief = tool_name_to_request(
            "analysis_brief",
            serde_json::json!({
                "query": "ActiveDesk",
                "string_limit": 8,
                "function_limit": 8,
                "hot_function_limit": 4
            }),
        )
        .unwrap();
        assert!(matches!(brief, CapabilityRequest::AnalysisBrief(_)));
    }

    #[test]
    fn dispatches_evidence_graph_for_object_evidence() {
        let dir = tempdir().unwrap();
        let ws = Workspace::init(dir.path(), "test", None).unwrap();
        let sample = dir.path().join("config.json");
        std::fs::write(&sample, br#"{"feature":"graph","agent":true}"#).unwrap();
        let graph = revx_loader::identify_object_graph(&sample, 0, 16).unwrap();
        ws.save_object_graph(&graph).unwrap();
        ws.analyze_object(
            "config.json",
            Some(&[revx_core::ObjectAnalyzerKind::Strings]),
        )
        .unwrap()
        .expect("object analysis");

        let service = CapabilityService::new(dir.path().to_path_buf());
        let response = service
            .dispatch(CapabilityRequest::EvidenceGraph(
                revx_core::EvidenceGraphRequest {
                    subject: "config.json".to_string(),
                    depth: Some(2),
                    limit: Some(100),
                },
            ))
            .unwrap();
        let CapabilityResponse::EvidenceGraph(payload) = response else {
            panic!("unexpected response");
        };
        assert_eq!(payload.subject, "config.json");
        assert!(payload.node_count >= 5);
        assert!(payload.edge_count >= 4);
        assert!(
            payload
                .nodes
                .iter()
                .any(|node| node.kind == "object" && node.label == "config.json")
        );
        assert!(payload.edges.iter().any(|edge| edge.kind == "has_artifact"));
    }

    #[test]
    fn trace_import_returns_evidence_ids_for_agent_followup() {
        let dir = tempdir().unwrap();
        let _ws = Workspace::init(dir.path(), "test", None).unwrap();
        let service = CapabilityService::new(dir.path().to_path_buf());
        let response = service
            .dispatch(CapabilityRequest::TraceImport(
                revx_core::TraceImportRequest {
                    events: vec![revx_core::TraceEvent {
                        timestamp: chrono::DateTime::parse_from_rfc3339("2026-06-09T12:00:00Z")
                            .unwrap()
                            .with_timezone(&chrono::Utc),
                        process: "demo".to_string(),
                        thread: "worker".to_string(),
                        kind: "syscall".to_string(),
                        location: Some(0x401000),
                        payload: serde_json::json!({
                            "name": "openat",
                            "path": "config.json"
                        }),
                    }],
                },
            ))
            .unwrap();
        let CapabilityResponse::TraceImport(payload) = response else {
            panic!("unexpected response");
        };
        assert_eq!(payload.imported, 1);
        assert_eq!(payload.evidence_count, 1);
        assert_eq!(payload.evidence_ids.len(), 1);
        assert!(payload.evidence_ids[0].starts_with("trace_event:"));
        assert!(payload.artifact.is_some());
    }

    #[test]
    fn symbolic_solve_persists_witness_as_evidence() {
        let dir = tempdir().unwrap();
        let ws = Workspace::init(dir.path(), "test", None).unwrap();
        let service = CapabilityService::new(dir.path().to_path_buf());
        let response = service
            .dispatch(CapabilityRequest::SymbolicSolve(
                revx_core::SymbolicSolveRequest {
                    subject: "auth-branch".to_string(),
                    variables: vec![
                        revx_core::SymbolicVariable {
                            name: "x".to_string(),
                            domain: revx_core::SymbolicDomain::IntRange { min: 0, max: 10 },
                        },
                        revx_core::SymbolicVariable {
                            name: "y".to_string(),
                            domain: revx_core::SymbolicDomain::IntValues {
                                values: vec![1, 2, 3],
                            },
                        },
                    ],
                    constraints: vec![
                        revx_core::SymbolicConstraint {
                            id: Some("sum".to_string()),
                            left: revx_core::SymbolicLinearExpr {
                                terms: vec![
                                    revx_core::SymbolicTerm {
                                        variable: "x".to_string(),
                                        coefficient: 1,
                                    },
                                    revx_core::SymbolicTerm {
                                        variable: "y".to_string(),
                                        coefficient: 1,
                                    },
                                ],
                                constant: 0,
                            },
                            op: revx_core::SymbolicConstraintOp::Eq,
                            right: revx_core::SymbolicLinearExpr {
                                terms: Vec::new(),
                                constant: 7,
                            },
                        },
                        revx_core::SymbolicConstraint {
                            id: Some("ordered".to_string()),
                            left: revx_core::SymbolicLinearExpr {
                                terms: vec![revx_core::SymbolicTerm {
                                    variable: "x".to_string(),
                                    coefficient: 1,
                                }],
                                constant: 0,
                            },
                            op: revx_core::SymbolicConstraintOp::Gt,
                            right: revx_core::SymbolicLinearExpr {
                                terms: vec![revx_core::SymbolicTerm {
                                    variable: "y".to_string(),
                                    coefficient: 1,
                                }],
                                constant: 0,
                            },
                        },
                    ],
                    max_solutions: Some(2),
                    iteration_limit: Some(100),
                },
            ))
            .unwrap();
        let CapabilityResponse::SymbolicSolve(payload) = response else {
            panic!("unexpected response");
        };
        assert_eq!(payload.status, revx_core::SymbolicSolveStatus::Sat);
        assert!(!payload.solutions.is_empty());
        assert!(payload.evidence_id.starts_with("symbolic:"));
        let evidence = ws.export_evidence_by_subject("auth-branch", 10).unwrap();
        assert!(
            evidence
                .preview
                .iter()
                .any(|item| item.kind == "symbolic_analysis")
        );

        let graph = ws.evidence_graph("auth-branch", 2, 100).unwrap();
        assert!(
            graph
                .nodes
                .iter()
                .any(|node| node.kind == "symbolic_solution")
        );
    }

    #[test]
    fn investigation_run_builds_agent_ready_analysis_pack() {
        let dir = tempdir().unwrap();
        let _ws = Workspace::init(dir.path(), "test", None).unwrap();
        let sample = dir.path().join("config.json");
        std::fs::write(&sample, br#"{"feature":"investigation","agent":true}"#).unwrap();

        let service = CapabilityService::new(dir.path().to_path_buf());
        let response = service
            .dispatch(CapabilityRequest::InvestigationRun(
                revx_core::InvestigationRunRequest {
                    subject: "config.json".to_string(),
                    path: Some(sample.display().to_string()),
                    run_object_pipeline: Some(true),
                    max_depth: Some(0),
                    max_children: Some(16),
                    object_limit: Some(8),
                    carve_max_depth: Some(2),
                    carve_max_children: Some(16),
                    plugin_ids: None,
                    analyze_binaries: Some(false),
                    binary_profile: Some(AnalysisProfile::Fast),
                    graph_depth: Some(2),
                    graph_limit: Some(100),
                    trace_kind: None,
                    trace_limit: Some(10),
                },
            ))
            .unwrap();
        let CapabilityResponse::InvestigationRun(payload) = response else {
            panic!("unexpected response");
        };
        assert_eq!(payload.subject, "config.json");
        assert!(payload.evidence_count >= 1);
        assert!(payload.graph.node_count >= 3);
        assert!(payload.pipeline.is_some());
        assert!(payload.summary.contains("Investigation"));
        assert!(
            !payload.next_actions.is_empty(),
            "investigation should emit ranked next_actions"
        );
        assert!(
            !payload.agent_brief.headline.is_empty(),
            "investigation should emit agent_brief.headline"
        );
        assert_eq!(
            payload.agent_brief.next_actions.len(),
            payload.next_actions.len()
        );
        assert!(
            payload
                .agent_brief
                .stop_conditions
                .iter()
                .any(|item| item.contains("next_actions[0]") || item.contains("one high-priority"))
        );
        assert!(
            payload.report.body.contains("Agent Brief")
                && (payload.report.body.contains("Next Actions")
                    || payload.report.body.contains("Top Action"))
                && payload.report.body.contains("Stop Conditions")
        );
        let top = &payload.next_actions[0];
        assert!(!top.tool.is_empty());
        assert!(top.priority > 0);
        assert!(
            std::fs::metadata(
                dir.path()
                    .join(".revx")
                    .join(&payload.report_artifact.relative_path)
            )
            .unwrap()
            .is_file()
        );
        assert!(
            std::fs::metadata(
                dir.path()
                    .join(".revx")
                    .join(&payload.artifact.relative_path)
            )
            .unwrap()
            .is_file()
        );
    }

    #[test]
    fn investigation_run_graph_includes_pipeline_discovered_objects() {
        let dir = tempdir().unwrap();
        let _ws = Workspace::init(dir.path(), "test", None).unwrap();
        let sample = dir.path().join("carrier.blob");
        let embedded_zip = {
            let mut bytes = Vec::new();
            {
                let cursor = std::io::Cursor::new(&mut bytes);
                let mut zip = zip::ZipWriter::new(cursor);
                let options = zip::write::SimpleFileOptions::default();
                use std::io::Write;
                zip.start_file("inner.txt", options).unwrap();
                zip.write_all(b"investigation-pipeline").unwrap();
                zip.finish().unwrap();
            }
            bytes
        };
        let mut bytes = b"prefix".to_vec();
        bytes.extend_from_slice(&embedded_zip);
        bytes.extend_from_slice(b"suffix");
        std::fs::write(&sample, &bytes).unwrap();

        let service = CapabilityService::new(dir.path().to_path_buf());
        let response = service
            .dispatch(CapabilityRequest::InvestigationRun(
                revx_core::InvestigationRunRequest {
                    subject: "carrier.blob".to_string(),
                    path: Some(sample.display().to_string()),
                    run_object_pipeline: Some(true),
                    max_depth: Some(0),
                    max_children: Some(16),
                    object_limit: Some(8),
                    carve_max_depth: Some(2),
                    carve_max_children: Some(16),
                    plugin_ids: None,
                    analyze_binaries: Some(false),
                    binary_profile: Some(AnalysisProfile::Fast),
                    graph_depth: Some(3),
                    graph_limit: Some(160),
                    trace_kind: None,
                    trace_limit: Some(10),
                },
            ))
            .unwrap();
        let CapabilityResponse::InvestigationRun(payload) = response else {
            panic!("unexpected response");
        };
        let pipeline = payload.pipeline.as_ref().expect("pipeline");
        assert_eq!(pipeline.carved_object_count, 1);
        assert_eq!(pipeline.identified_embedded_object_count, 1);
        assert!(
            payload
                .evidence_ids
                .iter()
                .any(|id| { id.starts_with("object_pipeline:") && id.ends_with(":summary") })
        );
        assert!(
            payload
                .evidence_ids
                .iter()
                .any(|id| id.starts_with("object_edge:"))
        );
        assert!(
            payload
                .graph
                .nodes
                .iter()
                .any(|node| node.kind == "object" && node.label == "inner.txt")
        );
        assert!(payload.graph.edges.iter().any(|edge| {
            edge.kind == "derived_from"
                && edge
                    .data
                    .get("edge")
                    .and_then(|value| value.get("metadata"))
                    .and_then(|value| value.get("source"))
                    .and_then(|value| value.as_str())
                    == Some("object_carve_identify")
        }));
        assert!(payload.report.body.contains("inner.txt"));
    }

    #[test]
    fn object_search_content_finds_persisted_object_bytes() {
        let dir = tempdir().unwrap();
        let _ws = Workspace::init(dir.path(), "test", None).unwrap();
        let sample = dir.path().join("config.json");
        std::fs::write(&sample, br#"{"token":"NEEDLE_TOKEN","agent":true}"#).unwrap();

        let service = CapabilityService::new(dir.path().to_path_buf());
        service
            .dispatch(CapabilityRequest::ObjectIdentify(
                revx_core::ObjectIdentifyRequest {
                    path: sample.display().to_string(),
                    max_depth: Some(0),
                    max_children: Some(16),
                    include_graph: Some(false),
                },
            ))
            .unwrap();
        let response = service
            .dispatch(CapabilityRequest::ObjectContentSearch(
                revx_core::ObjectContentSearchRequest {
                    pattern: "NEEDLE_TOKEN".to_string(),
                    mode: Some(revx_core::ObjectContentSearchMode::Text),
                    query: Some("config.json".to_string()),
                    limit: Some(10),
                    per_object_limit: Some(5),
                    max_object_bytes: Some(1024 * 1024),
                },
            ))
            .unwrap();
        let CapabilityResponse::ObjectContentSearch(payload) = response else {
            panic!("unexpected response");
        };
        assert_eq!(payload.returned_count, 1);
        assert_eq!(payload.matches[0].display_name, "config.json");
        assert!(
            payload.matches[0]
                .preview_text
                .as_deref()
                .is_some_and(|preview| preview.contains("NEEDLE_TOKEN"))
        );
    }

    #[test]
    fn object_extract_range_persists_range_artifact() {
        let dir = tempdir().unwrap();
        let _ws = Workspace::init(dir.path(), "test", None).unwrap();
        let sample = dir.path().join("payload.bin");
        std::fs::write(&sample, &[0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xff]).unwrap();

        let service = CapabilityService::new(dir.path().to_path_buf());
        service
            .dispatch(CapabilityRequest::ObjectIdentify(
                revx_core::ObjectIdentifyRequest {
                    path: sample.display().to_string(),
                    max_depth: Some(0),
                    max_children: Some(16),
                    include_graph: Some(false),
                },
            ))
            .unwrap();
        let response = service
            .dispatch(CapabilityRequest::ObjectExtractRange(
                revx_core::ObjectExtractRangeRequest {
                    query: "payload.bin".to_string(),
                    offset: 1,
                    length: 3,
                    context_bytes: Some(1),
                    preview_bytes: Some(16),
                },
            ))
            .unwrap();
        let CapabilityResponse::ObjectExtractRange(payload) = response else {
            panic!("unexpected response");
        };
        assert_eq!(payload.object.display_name, "payload.bin");
        assert_eq!(payload.extracted_offset, 0);
        assert_eq!(payload.extracted_size, 5);
        assert_eq!(payload.preview_hex.as_deref(), Some("00aabbccdd"));
        let artifact_bytes = std::fs::read(
            dir.path()
                .join(".revx")
                .join(&payload.artifact.relative_path),
        )
        .unwrap();
        assert_eq!(artifact_bytes, vec![0x00, 0xaa, 0xbb, 0xcc, 0xdd]);
    }

    #[test]
    fn object_scan_signatures_finds_embedded_offsets() {
        let dir = tempdir().unwrap();
        let _ws = Workspace::init(dir.path(), "test", None).unwrap();
        let sample = dir.path().join("firmware.blob");
        let mut bytes = b"prefix-data".to_vec();
        bytes.extend_from_slice(b"\x7fELF\x02\x01\x01\0payload");
        bytes.extend_from_slice(b"tailPK\x03\x04zip");
        std::fs::write(&sample, &bytes).unwrap();

        let service = CapabilityService::new(dir.path().to_path_buf());
        service
            .dispatch(CapabilityRequest::ObjectIdentify(
                revx_core::ObjectIdentifyRequest {
                    path: sample.display().to_string(),
                    max_depth: Some(0),
                    max_children: Some(16),
                    include_graph: Some(false),
                },
            ))
            .unwrap();
        let response = service
            .dispatch(CapabilityRequest::ObjectSignatureScan(
                revx_core::ObjectSignatureScanRequest {
                    query: "firmware.blob".to_string(),
                    limit: Some(10),
                    max_object_bytes: Some(1024 * 1024),
                    preview_bytes: Some(16),
                },
            ))
            .unwrap();
        let CapabilityResponse::ObjectSignatureScan(payload) = response else {
            panic!("unexpected response");
        };
        assert_eq!(payload.object.display_name, "firmware.blob");
        assert_eq!(payload.returned_count, 2);
        assert!(
            payload
                .signatures
                .iter()
                .any(|hit| { hit.format == "elf" && hit.offset == b"prefix-data".len() as u64 })
        );
        assert!(payload.signatures.iter().any(|hit| hit.format == "zip"));
        assert!(
            std::fs::metadata(
                dir.path()
                    .join(".revx")
                    .join(&payload.artifact.relative_path)
            )
            .unwrap()
            .is_file()
        );
    }

    #[test]
    fn object_carve_signatures_persists_carved_artifacts() {
        let dir = tempdir().unwrap();
        let _ws = Workspace::init(dir.path(), "test", None).unwrap();
        let sample = dir.path().join("carrier.blob");
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
        let mut bytes = b"prefix".to_vec();
        let zip_offset = bytes.len() as u64;
        bytes.extend_from_slice(&embedded_zip);
        bytes.extend_from_slice(b"suffix");
        std::fs::write(&sample, &bytes).unwrap();

        let service = CapabilityService::new(dir.path().to_path_buf());
        service
            .dispatch(CapabilityRequest::ObjectIdentify(
                revx_core::ObjectIdentifyRequest {
                    path: sample.display().to_string(),
                    max_depth: Some(0),
                    max_children: Some(16),
                    include_graph: Some(false),
                },
            ))
            .unwrap();
        let response = service
            .dispatch(CapabilityRequest::ObjectCarveSignatures(
                revx_core::ObjectCarveSignaturesRequest {
                    query: "carrier.blob".to_string(),
                    limit: Some(10),
                    max_object_bytes: Some(1024 * 1024),
                    max_carve_bytes: Some(1024 * 1024),
                    min_confidence: Some(0.9),
                    preview_bytes: Some(16),
                },
            ))
            .unwrap();
        let CapabilityResponse::ObjectCarveSignatures(payload) = response else {
            panic!("unexpected response");
        };
        assert_eq!(payload.object.display_name, "carrier.blob");
        assert_eq!(payload.carved_count, 1);
        let carve = &payload.carves[0];
        assert_eq!(carve.format, "zip");
        assert_eq!(carve.offset, zip_offset);
        assert_eq!(carve.length, embedded_zip.len() as u64);
        let artifact_bytes =
            std::fs::read(dir.path().join(".revx").join(&carve.artifact.relative_path)).unwrap();
        assert_eq!(artifact_bytes, embedded_zip);
    }

    #[test]
    fn object_carve_identify_persists_carved_object_graphs() {
        let dir = tempdir().unwrap();
        let _ws = Workspace::init(dir.path(), "test", None).unwrap();
        let sample = dir.path().join("carrier.blob");
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
        let mut bytes = b"prefix".to_vec();
        bytes.extend_from_slice(&embedded_zip);
        bytes.extend_from_slice(b"suffix");
        std::fs::write(&sample, &bytes).unwrap();

        let service = CapabilityService::new(dir.path().to_path_buf());
        service
            .dispatch(CapabilityRequest::ObjectIdentify(
                revx_core::ObjectIdentifyRequest {
                    path: sample.display().to_string(),
                    max_depth: Some(0),
                    max_children: Some(16),
                    include_graph: Some(false),
                },
            ))
            .unwrap();
        let response = service
            .dispatch(CapabilityRequest::ObjectCarveIdentify(
                revx_core::ObjectCarveIdentifyRequest {
                    query: "carrier.blob".to_string(),
                    limit: Some(10),
                    max_object_bytes: Some(1024 * 1024),
                    max_carve_bytes: Some(1024 * 1024),
                    min_confidence: Some(0.9),
                    preview_bytes: Some(16),
                    max_depth: Some(1),
                    max_children: Some(16),
                },
            ))
            .unwrap();
        let CapabilityResponse::ObjectCarveIdentify(payload) = response else {
            panic!("unexpected response");
        };
        assert_eq!(payload.object.display_name, "carrier.blob");
        assert_eq!(payload.carved_count, 1);
        assert_eq!(payload.identified_count, 1);
        assert_eq!(payload.failed_count, 0);
        let result = &payload.carves[0];
        assert_eq!(result.carve.format, "zip");
        assert!(result.root_id.is_some());
        assert!(result.evidence_ids.iter().any(|id| {
            id.starts_with("object_edge:")
                && id.contains(&payload.object.id)
                && id.contains(result.root_id.as_deref().unwrap())
        }));
        assert_eq!(result.object_count, result.object_ids.len());
        assert!(!result.object_ids.is_empty());
        assert!(result.object_count >= 2);
        assert!(result.edge_count >= 1);
        assert!(result.graph_artifact.is_some());
        assert!(result.error.is_none());

        let ws = Workspace::open(dir.path()).unwrap();
        let hits = ws.search_objects("inner.txt", None, 10).unwrap();
        assert!(hits.iter().any(
            |hit| hit.display_name == "inner.txt" && hit.flags.contains(&"virtual".to_string())
        ));
        let profile = ws
            .object_profile(result.root_id.as_deref().unwrap())
            .unwrap()
            .expect("carved root profile");
        assert!(profile.incoming_edges.iter().any(|edge| {
            edge.from == payload.object.id
                && edge.to == result.root_id.as_deref().unwrap()
                && edge.kind == revx_core::ObjectEdgeKind::DerivedFrom
        }));

        let graph = ws
            .evidence_graph("inner.txt", 3, 100)
            .expect("evidence graph");
        assert!(graph.edges.iter().any(|edge| {
            edge.kind == "derived_from"
                && edge
                    .data
                    .get("edge")
                    .and_then(|value| value.get("from"))
                    .and_then(|value| value.as_str())
                    == Some(payload.object.id.as_str())
                && edge
                    .data
                    .get("edge")
                    .and_then(|value| value.get("to"))
                    .and_then(|value| value.as_str())
                    == result.root_id.as_deref()
        }));
    }

    #[test]
    fn pipeline_carves_and_identifies_embedded_objects_by_default() {
        let dir = tempdir().unwrap();
        let _ws = Workspace::init(dir.path(), "test", None).unwrap();
        let sample = dir.path().join("carrier.blob");
        let embedded_zip = {
            let mut bytes = Vec::new();
            {
                let cursor = std::io::Cursor::new(&mut bytes);
                let mut zip = zip::ZipWriter::new(cursor);
                let options = zip::write::SimpleFileOptions::default();
                use std::io::Write;
                zip.start_file("inner.txt", options).unwrap();
                zip.write_all(b"pipeline-carve").unwrap();
                zip.finish().unwrap();
            }
            bytes
        };
        let mut bytes = b"prefix".to_vec();
        bytes.extend_from_slice(&embedded_zip);
        bytes.extend_from_slice(b"suffix");
        std::fs::write(&sample, &bytes).unwrap();

        let service = CapabilityService::new(dir.path().to_path_buf());
        let response = service
            .dispatch(CapabilityRequest::ObjectPipeline(
                revx_core::ObjectPipelineRequest {
                    path: sample.display().to_string(),
                    max_depth: Some(0),
                    max_children: Some(16),
                    object_limit: Some(8),
                    analyze_objects: Some(true),
                    carve_embedded: Some(true),
                    carve_limit: Some(8),
                    max_carve_object_bytes: Some(1024 * 1024),
                    max_carve_bytes: Some(1024 * 1024),
                    min_carve_confidence: Some(0.9),
                    carve_max_depth: Some(1),
                    carve_max_children: Some(16),
                    plugin_ids: None,
                    analyze_binaries: Some(false),
                    binary_profile: Some(AnalysisProfile::Fast),
                },
            ))
            .unwrap();
        let CapabilityResponse::ObjectPipeline(payload) = response else {
            panic!("unexpected response");
        };
        assert!(payload.object_count >= 3);
        assert!(payload.analyzed_object_count >= 3);
        assert_eq!(payload.carved_object_count, 1);
        assert_eq!(payload.identified_embedded_object_count, 1);
        assert_eq!(payload.failed_embedded_identify_count, 0);
        assert!(payload.steps.iter().any(|step| {
            step.stage == revx_core::ObjectPipelineStage::CarveIdentify
                && step.status == revx_core::ObjectAnalysisStatus::Completed
        }));
        assert!(payload.steps.iter().any(|step| {
            step.stage == revx_core::ObjectPipelineStage::ObjectAnalyze
                && step
                    .object_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("inner.txt"))
                && step.status == revx_core::ObjectAnalysisStatus::Completed
        }));

        let ws = Workspace::open(dir.path()).unwrap();
        let hits = ws.search_objects("inner.txt", None, 10).unwrap();
        assert!(hits.iter().any(
            |hit| hit.display_name == "inner.txt" && hit.flags.contains(&"virtual".to_string())
        ));
    }

    #[test]
    fn pipeline_carves_embedded_signatures_inside_virtual_objects() {
        let dir = tempdir().unwrap();
        let _ws = Workspace::init(dir.path(), "test", None).unwrap();
        let archive = dir.path().join("outer.zip");
        let embedded_zip = {
            let mut bytes = Vec::new();
            {
                let cursor = std::io::Cursor::new(&mut bytes);
                let mut zip = zip::ZipWriter::new(cursor);
                let options = zip::write::SimpleFileOptions::default();
                use std::io::Write;
                zip.start_file("deep/inner.txt", options).unwrap();
                zip.write_all(b"virtual-carve").unwrap();
                zip.finish().unwrap();
            }
            bytes
        };
        let mut carrier = b"virtual-prefix".to_vec();
        carrier.extend_from_slice(&embedded_zip);
        carrier.extend_from_slice(b"virtual-suffix");
        {
            let file = std::fs::File::create(&archive).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let options = zip::write::SimpleFileOptions::default();
            use std::io::Write;
            zip.start_file("carrier.bin", options).unwrap();
            zip.write_all(&carrier).unwrap();
            zip.finish().unwrap();
        }

        let service = CapabilityService::new(dir.path().to_path_buf());
        let response = service
            .dispatch(CapabilityRequest::ObjectPipeline(
                revx_core::ObjectPipelineRequest {
                    path: archive.display().to_string(),
                    max_depth: Some(1),
                    max_children: Some(16),
                    object_limit: Some(12),
                    analyze_objects: Some(true),
                    carve_embedded: Some(true),
                    carve_limit: Some(8),
                    max_carve_object_bytes: Some(1024 * 1024),
                    max_carve_bytes: Some(1024 * 1024),
                    min_carve_confidence: Some(0.9),
                    carve_max_depth: Some(2),
                    carve_max_children: Some(16),
                    plugin_ids: None,
                    analyze_binaries: Some(false),
                    binary_profile: Some(AnalysisProfile::Fast),
                },
            ))
            .unwrap();
        let CapabilityResponse::ObjectPipeline(payload) = response else {
            panic!("unexpected response");
        };
        assert!(payload.object_count >= 4);
        assert!(payload.analyzed_object_count >= 4);
        assert_eq!(payload.carved_object_count, 1);
        assert_eq!(payload.identified_embedded_object_count, 1);
        assert_eq!(payload.failed_embedded_identify_count, 0);
        assert!(
            payload.steps.iter().any(|step| {
                step.stage == revx_core::ObjectPipelineStage::CarveIdentify
                    && step.status == revx_core::ObjectAnalysisStatus::Completed
                    && step.summary.contains("Carved 1 embedded candidate")
            }),
            "steps={:#?}",
            payload
                .steps
                .iter()
                .map(|step| {
                    (
                        step.stage,
                        step.object_path.clone(),
                        step.status,
                        step.summary.clone(),
                    )
                })
                .collect::<Vec<_>>()
        );
        assert!(payload.steps.iter().any(|step| {
            step.stage == revx_core::ObjectPipelineStage::ObjectAnalyze
                && step
                    .object_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("deep/inner.txt"))
                && step.status == revx_core::ObjectAnalysisStatus::Completed
        }));

        let ws = Workspace::open(dir.path()).unwrap();
        let hits = ws.search_objects("inner.txt", None, 10).unwrap();
        assert!(hits.iter().any(|hit| {
            hit.display_name == "deep/inner.txt" && hit.flags.contains(&"virtual".to_string())
        }));
    }

    #[test]
    fn artifact_read_returns_bounded_preview() {
        let dir = tempdir().unwrap();
        let ws = Workspace::init(dir.path(), "test", None).unwrap();
        let artifact = ws
            .write_json_artifact(
                "application/json",
                &serde_json::json!({ "feature": "artifact-read", "agent": true }),
            )
            .unwrap();
        let service = CapabilityService::new(dir.path().to_path_buf());
        let response = service
            .dispatch(CapabilityRequest::ArtifactRead(
                revx_core::ArtifactReadRequest {
                    relative_path: Some(artifact.relative_path.clone()),
                    hash_blake3: None,
                    offset: Some(0),
                    max_bytes: Some(128),
                },
            ))
            .unwrap();
        let CapabilityResponse::ArtifactRead(payload) = response else {
            panic!("unexpected response");
        };
        assert_eq!(payload.artifact.hash_blake3, artifact.hash_blake3);
        assert!(
            payload
                .preview_text
                .as_deref()
                .is_some_and(|text| text.contains("artifact-read"))
        );
        assert!(!payload.preview_hex.is_empty());
    }

    #[test]
    fn artifact_list_returns_agent_navigation_handles() {
        let dir = tempdir().unwrap();
        let ws = Workspace::init(dir.path(), "test", None).unwrap();
        let artifact = ws
            .write_json_artifact(
                "application/json",
                &serde_json::json!({ "feature": "artifact-list", "agent": true }),
            )
            .unwrap();
        ws.insert_evidence(revx_core::Evidence {
            id: "evidence:artifact-list".to_string(),
            subject: "artifact-list-subject".to_string(),
            summary: "Evidence with navigable artifact".to_string(),
            kind: "artifact_catalog".to_string(),
            details: serde_json::json!({ "artifact": artifact.clone() }),
            provenance: revx_core::EvidenceProvenance {
                source: "unit_test".to_string(),
                binary_id: None,
                function_address: None,
                instruction_address: None,
                profile: None,
            },
        })
        .unwrap();

        let service = CapabilityService::new(dir.path().to_path_buf());
        let response = service
            .dispatch(CapabilityRequest::ArtifactList(
                revx_core::ArtifactListRequest {
                    query: Some("artifact-list-subject".to_string()),
                    content_type: Some("json".to_string()),
                    role: Some("artifact_catalog".to_string()),
                    limit: Some(10),
                    include_unreferenced: Some(false),
                },
            ))
            .unwrap();
        let CapabilityResponse::ArtifactList(payload) = response else {
            panic!("unexpected response");
        };
        assert_eq!(payload.returned_count, 1);
        assert_eq!(
            payload.artifacts[0].artifact.hash_blake3,
            artifact.hash_blake3
        );
        assert!(
            payload.artifacts[0]
                .references
                .iter()
                .any(|reference| reference.id == "evidence:artifact-list")
        );
    }

    #[test]
    fn runs_workspace_object_plugin_as_evidence() {
        let dir = tempdir().unwrap();
        let ws = Workspace::init(dir.path(), "test", None).unwrap();
        let sample = dir.path().join("config.json");
        std::fs::write(&sample, br#"{"feature":"plugin","agent":true}"#).unwrap();
        let graph = revx_loader::identify_object_graph(&sample, 0, 16).unwrap();
        ws.save_object_graph(&graph).unwrap();

        let plugin_script = dir.path().join("json_shape.py");
        std::fs::write(
            &plugin_script,
            r#"import json, sys
from pathlib import Path
path = Path(sys.argv[1])
data = json.loads(path.read_text())
print(json.dumps({
    "summary": f"JSON object with {len(data)} keys",
    "keys": sorted(data.keys()),
    "size": path.stat().st_size,
}))
"#,
        )
        .unwrap();
        std::fs::write(
            ws.root().join("plugins").join("json-shape.json"),
            serde_json::json!({
                "id": "json-shape",
                "name": "JSON Shape",
                "description": "Summarize JSON keys",
                "command": ["python3", plugin_script.display().to_string(), "{artifact_path}"],
                "accepted_kinds": ["text"],
                "accepted_formats": ["json"],
                "timeout_ms": 5000
            })
            .to_string(),
        )
        .unwrap();

        let service = CapabilityService::new(dir.path().to_path_buf());
        let listed = service
            .dispatch(CapabilityRequest::ObjectPluginList(
                revx_core::ObjectPluginListRequest,
            ))
            .unwrap();
        let CapabilityResponse::ObjectPluginList(listed) = listed else {
            panic!("unexpected response");
        };
        assert_eq!(listed.plugins.len(), 1);
        assert_eq!(listed.plugins[0].id, "json-shape");

        let response = service
            .dispatch(CapabilityRequest::ObjectPluginRun(
                revx_core::ObjectPluginRunRequest {
                    plugin_id: "json-shape".to_string(),
                    query: "config.json".to_string(),
                    timeout_ms: Some(5000),
                },
            ))
            .unwrap();
        let CapabilityResponse::ObjectPluginRun(payload) = response else {
            panic!("unexpected response");
        };
        assert_eq!(payload.plugin.id, "json-shape");
        assert_eq!(payload.object.display_name, "config.json");
        assert_eq!(payload.status, revx_core::ObjectAnalysisStatus::Completed);
        assert_eq!(payload.summary, "JSON object with 2 keys");
        assert_eq!(
            payload.output_json.as_ref().unwrap()["keys"],
            serde_json::json!(["agent", "feature"])
        );
        assert!(
            std::fs::metadata(
                dir.path()
                    .join(".revx")
                    .join(&payload.artifact.relative_path)
            )
            .unwrap()
            .is_file()
        );

        let evidence = ws.export_evidence_by_subject("json-shape", 10).unwrap();
        assert!(evidence.preview.iter().any(|item| {
            item.kind == "object_plugin_analysis"
                && item.provenance.source == "object_plugin:json-shape"
                && item.id == payload.evidence_id
        }));
    }

    #[test]
    fn pipeline_runs_requested_object_plugins() {
        let dir = tempdir().unwrap();
        let ws = Workspace::init(dir.path(), "test", None).unwrap();
        let sample = dir.path().join("config.json");
        std::fs::write(&sample, br#"{"feature":"pipeline-plugin","agent":true}"#).unwrap();

        let plugin_script = dir.path().join("json_shape.py");
        std::fs::write(
            &plugin_script,
            r#"import json, sys
from pathlib import Path
path = Path(sys.argv[1])
data = json.loads(path.read_text())
print(json.dumps({
    "summary": "pipeline plugin saw " + ",".join(sorted(data.keys())),
    "keys": sorted(data.keys()),
}))
"#,
        )
        .unwrap();
        std::fs::write(
            ws.root().join("plugins").join("json-shape.json"),
            serde_json::json!({
                "id": "json-shape",
                "name": "JSON Shape",
                "command": ["python3", plugin_script.display().to_string(), "{artifact_path}"],
                "accepted_kinds": ["text"],
                "accepted_formats": ["json"],
                "timeout_ms": 5000
            })
            .to_string(),
        )
        .unwrap();

        let service = CapabilityService::new(dir.path().to_path_buf());
        let response = service
            .dispatch(CapabilityRequest::ObjectPipeline(
                revx_core::ObjectPipelineRequest {
                    path: sample.display().to_string(),
                    max_depth: Some(0),
                    max_children: Some(16),
                    object_limit: Some(8),
                    analyze_objects: Some(true),
                    carve_embedded: Some(false),
                    carve_limit: None,
                    max_carve_object_bytes: None,
                    max_carve_bytes: None,
                    min_carve_confidence: None,
                    carve_max_depth: None,
                    carve_max_children: None,
                    plugin_ids: Some(vec!["json-shape".to_string()]),
                    analyze_binaries: Some(false),
                    binary_profile: Some(AnalysisProfile::Fast),
                },
            ))
            .unwrap();
        let CapabilityResponse::ObjectPipeline(payload) = response else {
            panic!("unexpected response");
        };
        assert_eq!(payload.object_count, 1);
        assert_eq!(payload.failed_step_count, 0);
        let plugin_step = payload
            .steps
            .iter()
            .find(|step| step.stage == revx_core::ObjectPipelineStage::PluginAnalyze)
            .expect("plugin step");
        assert_eq!(
            plugin_step.status,
            revx_core::ObjectAnalysisStatus::Completed
        );
        assert!(plugin_step.summary.contains("json-shape"));
        assert!(plugin_step.summary.contains("agent,feature"));
        assert!(
            plugin_step
                .evidence_ids
                .iter()
                .any(|id| id.starts_with("object_plugin:json-shape:"))
        );
    }

    #[test]
    fn runs_universal_object_pipeline_over_nested_archive() {
        let dir = tempdir().unwrap();
        let _ws = Workspace::init(dir.path(), "test", None).unwrap();
        let archive = dir.path().join("outer.zip");
        let nested_bytes = {
            let mut bytes = Vec::new();
            {
                let cursor = std::io::Cursor::new(&mut bytes);
                let mut zip = zip::ZipWriter::new(cursor);
                let options = zip::write::SimpleFileOptions::default();
                use std::io::Write;
                zip.start_file("deep/config.json", options).unwrap();
                zip.write_all(br#"{"pipeline":true,"agent":"revx"}"#)
                    .unwrap();
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

        let service = CapabilityService::new(dir.path().to_path_buf());
        let response = service
            .dispatch(CapabilityRequest::ObjectPipeline(
                revx_core::ObjectPipelineRequest {
                    path: archive.display().to_string(),
                    max_depth: Some(2),
                    max_children: Some(16),
                    object_limit: Some(16),
                    analyze_objects: Some(true),
                    carve_embedded: Some(false),
                    carve_limit: None,
                    max_carve_object_bytes: None,
                    max_carve_bytes: None,
                    min_carve_confidence: None,
                    carve_max_depth: None,
                    carve_max_children: None,
                    plugin_ids: None,
                    analyze_binaries: Some(false),
                    binary_profile: Some(AnalysisProfile::Fast),
                },
            ))
            .unwrap();
        let CapabilityResponse::ObjectPipeline(payload) = response else {
            panic!("unexpected response");
        };
        assert_eq!(payload.object_count, 3);
        assert_eq!(payload.edge_count, 2);
        assert!(payload.analyzed_object_count >= 3);
        assert_eq!(payload.binary_candidate_count, 0);
        assert_eq!(payload.analyzed_binary_count, 0);
        assert_eq!(payload.failed_step_count, 0);
        assert!(!payload.pipeline_id.is_empty());
        assert!(
            payload
                .evidence_ids
                .iter()
                .any(|id| { id.starts_with("object_pipeline:") && id.ends_with(":summary") })
        );
        assert!(payload.steps.iter().any(|step| {
            step.stage == revx_core::ObjectPipelineStage::ObjectAnalyze
                && step
                    .object_path
                    .as_deref()
                    .is_some_and(|path| path.contains("deep/config.json"))
                && step.status == revx_core::ObjectAnalysisStatus::Completed
        }));
        assert!(
            std::fs::metadata(
                dir.path()
                    .join(".revx")
                    .join(&payload.report_artifact.relative_path)
            )
            .unwrap()
            .is_file()
        );

        let ws = Workspace::open(dir.path()).unwrap();
        let evidence = ws
            .export_evidence_by_subject("object_pipeline", 10)
            .unwrap();
        assert!(evidence.preview.iter().any(|item| {
            item.kind == "object_pipeline_summary" && item.provenance.source == "object_pipeline"
        }));
    }

    #[test]
    fn runs_universal_object_pipeline_over_tar_archive() {
        let dir = tempdir().unwrap();
        let _ws = Workspace::init(dir.path(), "test", None).unwrap();
        let archive = dir.path().join("bundle.tar");
        {
            let file = std::fs::File::create(&archive).unwrap();
            let mut tar = tar::Builder::new(file);
            let config = br#"{"pipeline":true,"agent":"revx"}"#;
            let mut config_header = tar::Header::new_gnu();
            config_header.set_size(config.len() as u64);
            config_header.set_cksum();
            tar.append_data(&mut config_header, "config.json", &config[..])
                .unwrap();
            let payload = b"tar pipeline payload";
            let mut payload_header = tar::Header::new_gnu();
            payload_header.set_size(payload.len() as u64);
            payload_header.set_cksum();
            tar.append_data(&mut payload_header, "bin/payload.txt", &payload[..])
                .unwrap();
            tar.finish().unwrap();
        }

        let service = CapabilityService::new(dir.path().to_path_buf());
        let response = service
            .dispatch(CapabilityRequest::ObjectPipeline(
                revx_core::ObjectPipelineRequest {
                    path: archive.display().to_string(),
                    max_depth: Some(1),
                    max_children: Some(16),
                    object_limit: Some(16),
                    analyze_objects: Some(true),
                    carve_embedded: Some(false),
                    carve_limit: None,
                    max_carve_object_bytes: None,
                    max_carve_bytes: None,
                    min_carve_confidence: None,
                    carve_max_depth: None,
                    carve_max_children: None,
                    plugin_ids: None,
                    analyze_binaries: Some(false),
                    binary_profile: Some(AnalysisProfile::Fast),
                },
            ))
            .unwrap();
        let CapabilityResponse::ObjectPipeline(payload) = response else {
            panic!("unexpected response");
        };
        assert_eq!(payload.object_count, 3);
        assert_eq!(payload.edge_count, 2);
        assert!(payload.analyzed_object_count >= 3);
        assert_eq!(payload.failed_step_count, 0);
        assert!(payload.steps.iter().any(|step| {
            step.stage == revx_core::ObjectPipelineStage::ObjectAnalyze
                && step
                    .object_path
                    .as_deref()
                    .is_some_and(|path| path.contains("config.json"))
                && step.status == revx_core::ObjectAnalysisStatus::Completed
        }));

        let ws = Workspace::open(dir.path()).unwrap();
        let profile = ws
            .object_profile("config.json")
            .unwrap()
            .expect("tar object profile");
        assert_eq!(profile.object.format.as_deref(), Some("json"));
        assert!(
            profile
                .incoming_edges
                .iter()
                .any(|edge| edge.from == payload.root_id)
        );
    }

    #[test]
    fn registers_virtual_elf_object_as_binary() {
        let dir = tempdir().unwrap();
        let ws = Workspace::init(dir.path(), "test", None).unwrap();
        let fixture = std::path::PathBuf::from("/Users/shiaho/Desktop/ida-mini-mcp/libtersafe.so");
        if !fixture.exists() {
            return;
        }

        let archive = dir.path().join("payload.apk");
        {
            let file = std::fs::File::create(&archive).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let options = zip::write::SimpleFileOptions::default();
            use std::io::Write;
            zip.start_file("lib/arm64-v8a/libdemo.so", options).unwrap();
            zip.write_all(&std::fs::read(&fixture).unwrap()).unwrap();
            zip.finish().unwrap();
        }
        let graph = revx_loader::identify_object_graph(&archive, 1, 16).unwrap();
        ws.save_object_graph(&graph).unwrap();

        let service = CapabilityService::new(dir.path().to_path_buf());
        let response = service
            .dispatch(CapabilityRequest::ObjectRegisterBinary(
                revx_core::ObjectRegisterBinaryRequest {
                    query: "libdemo.so".to_string(),
                },
            ))
            .unwrap();
        let CapabilityResponse::ObjectRegisterBinary(payload) = response else {
            panic!("unexpected response");
        };
        assert_eq!(payload.object.display_name, "lib/arm64-v8a/libdemo.so");
        assert_eq!(payload.survey.binary.format, BinaryFormat::Elf);
        assert_eq!(payload.survey.binary.architecture, Architecture::Arm64);
        assert!(payload.materialized_artifact.size > 0);
        assert!(payload.evidence_id.starts_with("object_binary:"));

        let binaries = ws.binary_record_list().unwrap();
        assert_eq!(binaries.len(), 1);
        assert_eq!(binaries[0].id, payload.survey.binary.id);
        let evidence = ws.export_evidence_by_subject("libdemo.so", 10).unwrap();
        assert!(evidence.preview.iter().any(|item| {
            item.kind == "object_binary_registration"
                && item.provenance.source == "object_register_binary"
        }));
    }

    
    #[test]
    fn auto_analyzes_native_from_apk_package_expand() {
        let dir = tempdir().unwrap();
        let ws = Workspace::init(dir.path(), "test", None).unwrap();
        let mut elf = sample_native_elf_blob();
        if elf.len() < 64 {
            elf.resize(64, 0);
            elf[0..4].copy_from_slice(b"\x7fELF");
        }
        let apk = dir.path().join("demo.apk");
        {
            let file = std::fs::File::create(&apk).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let options = zip::write::SimpleFileOptions::default();
            use std::io::Write;
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

        let service = CapabilityService::new(dir.path().to_path_buf());
        let response = service
            .dispatch(CapabilityRequest::ObjectAnalyze(ObjectAnalyzeRequest {
                query: "demo.apk".to_string(),
                analyzers: None,
            }))
            .unwrap();
        let CapabilityResponse::ObjectAnalyze(payload) = response else {
            panic!("unexpected response");
        };
        assert!(
            payload
                .analyses
                .iter()
                .any(|analysis| analysis.analyzer == "auto_expand"),
            "missing auto_expand: {:?}",
            payload
                .analyses
                .iter()
                .map(|a| &a.analyzer)
                .collect::<Vec<_>>()
        );
        let auto_binary = payload
            .analyses
            .iter()
            .find(|analysis| analysis.analyzer == "auto_binary");
        if let Some(auto_binary) = auto_binary {
            assert!(
                auto_binary.details["analyzed_count"]
                    .as_u64()
                    .unwrap_or(0)
                    >= 1
                    || auto_binary.details["skipped_count"]
                        .as_u64()
                        .unwrap_or(0)
                        >= 1
                    || auto_binary.details["candidate_count"]
                        .as_u64()
                        .unwrap_or(0)
                        >= 1,
                "details={}",
                auto_binary.details
            );
        } else {
            // Fallback: at least expansion produced a native candidate object.
            let expand = payload
                .analyses
                .iter()
                .find(|analysis| analysis.analyzer == "auto_expand")
                .expect("auto_expand");
            let expanded = expand.details["expanded"].as_array().cloned().unwrap_or_default();
            assert!(
                expanded.iter().any(|item| item
                    .get("binary_candidate")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false)
                    || item
                        .get("object_format")
                        .and_then(|value| value.as_str())
                        == Some("elf")),
                "details={}",
                expand.details
            );
        }
    }

#[test]
    fn auto_analyzes_dug_native_binary_from_unknown_blob() {
        let dir = tempdir().unwrap();
        let ws = Workspace::init(dir.path(), "test", None).unwrap();
        let mut blob = vec![0x90u8; 64];
        blob.extend_from_slice(&sample_native_elf_blob());
        blob.extend_from_slice(&[0x91u8; 32]);
        let path = dir.path().join("packed.bin");
        std::fs::write(&path, &blob).unwrap();
        let graph = revx_loader::identify_object_graph(&path, 0, 8).unwrap();
        ws.save_object_graph(&graph).unwrap();

        let service = CapabilityService::new(dir.path().to_path_buf());
        let response = service
            .dispatch(CapabilityRequest::ObjectAnalyze(ObjectAnalyzeRequest {
                query: "packed.bin".to_string(),
                analyzers: Some(vec![revx_core::ObjectAnalyzerKind::UnknownBlob]),
            }))
            .unwrap();
        let CapabilityResponse::ObjectAnalyze(payload) = response else {
            panic!("unexpected response");
        };
        assert!(
            payload
                .analyses
                .iter()
                .any(|analysis| analysis.analyzer == "auto_dig"),
            "missing auto_dig: {:?}",
            payload
                .analyses
                .iter()
                .map(|a| &a.analyzer)
                .collect::<Vec<_>>()
        );
        let auto_binary = payload
            .analyses
            .iter()
            .find(|analysis| analysis.analyzer == "auto_binary")
            .expect("auto_binary analysis");
        assert!(
            auto_binary.details["analyzed_count"]
                .as_u64()
                .unwrap_or(0)
                >= 1,
            "details={}",
            auto_binary.details
        );
        assert!(
            payload
                .evidence_ids
                .iter()
                .any(|id| id.contains("object_binary_analysis") || id.contains("auto_binary")),
            "evidence_ids={:?}",
            payload.evidence_ids
        );
    }

    fn sample_native_elf_blob() -> Vec<u8> {
        let candidates = [
            std::path::PathBuf::from("/Users/shiaho/Desktop/ida-mini-mcp/arm64-v8a/libmain.so"),
            std::path::PathBuf::from("/Users/shiaho/Desktop/ida-mini-mcp/arm64-v8a/libgetjvm.so"),
            std::path::PathBuf::from("/Users/shiaho/Desktop/ida-mini-mcp/arm64-v8a/libCrashAdapter.so"),
            std::path::PathBuf::from("/Users/shiaho/Desktop/ida-mini-mcp/libtersafe.so"),
        ];
        for fixture in candidates {
            if fixture.exists() {
                return std::fs::read(fixture).unwrap();
            }
        }
        let mut bytes = vec![0u8; 0x200];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16] = 3;
        bytes[18] = 0xb7;
        bytes[19] = 0x00;
        bytes
    }

    #[test]
    fn analyzes_virtual_elf_object_as_binary() {
        let dir = tempdir().unwrap();
        let ws = Workspace::init(dir.path(), "test", None).unwrap();
        let fixture = std::path::PathBuf::from("/Users/shiaho/Desktop/ida-mini-mcp/libtersafe.so");
        if !fixture.exists() {
            return;
        }

        let archive = dir.path().join("payload.apk");
        {
            let file = std::fs::File::create(&archive).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let options = zip::write::SimpleFileOptions::default();
            use std::io::Write;
            zip.start_file("lib/arm64-v8a/libdemo.so", options).unwrap();
            zip.write_all(&std::fs::read(&fixture).unwrap()).unwrap();
            zip.finish().unwrap();
        }
        let graph = revx_loader::identify_object_graph(&archive, 1, 16).unwrap();
        ws.save_object_graph(&graph).unwrap();

        let service = CapabilityService::new(dir.path().to_path_buf());
        let response = service
            .dispatch(CapabilityRequest::ObjectAnalyzeBinary(
                revx_core::ObjectAnalyzeBinaryRequest {
                    query: "libdemo.so".to_string(),
                    profile: AnalysisProfile::Fast,
                },
            ))
            .unwrap();
        let CapabilityResponse::ObjectAnalyzeBinary(payload) = response else {
            panic!("unexpected response");
        };
        assert_eq!(payload.object.display_name, "lib/arm64-v8a/libdemo.so");
        assert_eq!(payload.summary.format, BinaryFormat::Elf);
        assert_eq!(payload.summary.architecture, Architecture::Arm64);
        assert_eq!(payload.status, revx_core::AnalysisRunState::Completed);
        assert!(!payload.run_id.is_empty());
        assert!(
            payload
                .link_evidence_id
                .starts_with("object_binary_analysis:")
        );

        let status = ws
            .analysis_status(Some(&payload.run_id))
            .unwrap()
            .expect("analysis status");
        assert_eq!(status.status, revx_core::AnalysisRunState::Completed);
        let evidence = ws
            .export_evidence_by_subject("object_analyze_binary", 10)
            .unwrap();
        assert!(evidence.preview.iter().any(|item| {
            item.kind == "object_binary_analysis"
                && item.provenance.source == "object_analyze_binary"
        }));
    }


    #[test]
    fn analysis_brief_ranks_string_and_function_hits() {
        let dir = tempdir().unwrap();
        let ws = Workspace::init(dir.path(), "test", None).unwrap();
        let mut bundle = sample_bundle("binary-brief", "/tmp/brief.bin");
        bundle.functions[0].name = "GameRoot_ActiveDesk".to_string();
        bundle.functions[0].address = 0x2000;
        bundle.functions[0].size = 0x40;
        bundle.functions[0].blocks[0].address = 0x2000;
        bundle.functions[0].blocks[0].instructions[0].address = 0x2000;
        bundle.functions[0].pseudocode = Some(PseudocodeUnit {
            language: "c".to_string(),
            text: "void *GameRoot_ActiveDesk() { return g_desk; }".to_string(),
            regions: Vec::new(),
            region_artifact: None,
            evidence_ids: Vec::new(),
                    semantic_lattice: None,
        });
        bundle.functions.push(Function {
            name: "sub_3000".to_string(),
            address: 0x3000,
            size: 0x20,
            blocks: vec![BasicBlock {
                address: 0x3000,
                size: 4,
                instructions: vec![Instruction {
                    address: 0x3000,
                    bytes: "90".into(),
                    text: "nop".into(),
                }],
            }],
            stack_summary: None,
            arguments: Vec::new(),
            locals: Vec::new(),
            pseudocode: None,
            evidence_ids: Vec::new(),
            warnings: Vec::new(),
        });
        bundle.strings = vec![StringLiteral {
            address: Some(0x4000),
            value: "GameRoot::ActiveDesk".to_string(),
        }];
        bundle.references = vec![revx_core::Reference {
            from: 0x2010,
            to: 0x4000,
            kind: revx_core::ReferenceKind::StringRef,
        }];
        bundle.survey.summary.function_count = 2;
        bundle.survey.summary.string_count = 1;
        ws.save_analysis(bundle, AnalysisProfile::Fast).unwrap();

        let service = CapabilityService::new(dir.path().to_path_buf());
        let response = service
            .dispatch(CapabilityRequest::AnalysisBrief(
                revx_core::AnalysisBriefRequest {
                    query: "ActiveDesk".to_string(),
                    string_limit: Some(8),
                    function_limit: Some(8),
                    hot_function_limit: Some(4),
                    xref_limit: Some(16),
                    include_pseudocode: Some(true),
                },
            ))
            .unwrap();
        let CapabilityResponse::AnalysisBrief(payload) = response else {
            panic!("unexpected response");
        };
        assert_eq!(payload.query, "ActiveDesk");
        assert!(!payload.string_hits.is_empty());
        assert!(payload.string_hits[0].value.contains("ActiveDesk"));
        assert!(!payload.function_hits.is_empty());
        assert_eq!(payload.function_hits[0].name, "GameRoot_ActiveDesk");
        assert!(!payload.hot_functions.is_empty());
        assert_eq!(payload.hot_functions[0].name, "GameRoot_ActiveDesk");
        assert!(
            payload.hot_functions[0]
                .pseudocode_preview
                .as_deref()
                .unwrap_or("")
                .contains("GameRoot_ActiveDesk")
        );
        assert!(!payload.next_actions.is_empty());
        assert_eq!(payload.next_actions[0].tool, "decompile_function");
        assert!(!payload.agent_brief.headline.is_empty());
        assert!(payload.hot_functions[0].confidence > 0.2);
        assert!(!payload.hot_functions[0].digest.is_empty());
        assert!(
            payload.hot_functions[0]
                .quality_tags
                .iter()
                .any(|tag| tag == "named" || tag == "string_backed" || tag == "linear_pseudocode" || tag == "structured_pseudocode")
        );
        let text = mcp_response_summary(&CapabilityResponse::AnalysisBrief(payload));
        assert!(text.contains("# analysis_brief"));
        assert!(text.contains("Hot Functions"));
        assert!(text.contains("GameRoot_ActiveDesk"));
        assert!(text.contains("conf="));
    }

    #[test]
    fn function_profile_and_string_search_emit_agent_brief() {
        let dir = tempdir().unwrap();
        let ws = Workspace::init(dir.path(), "test", None).unwrap();
        let mut bundle = sample_bundle("binary-brief2", "/tmp/brief2.bin");
        bundle.functions[0].name = "GameRoot_ActiveDesk".to_string();
        bundle.functions[0].address = 0x2000;
        bundle.functions[0].size = 0x40;
        bundle.functions[0].blocks[0].address = 0x2000;
        bundle.functions[0].blocks[0].instructions[0].address = 0x2000;
        bundle.strings = vec![StringLiteral {
            address: Some(0x4000),
            value: "GameRoot::ActiveDesk".to_string(),
        }];
        bundle.references = vec![revx_core::Reference {
            from: 0x2010,
            to: 0x4000,
            kind: revx_core::ReferenceKind::StringRef,
        }];
        ws.save_analysis(bundle, AnalysisProfile::Fast).unwrap();
        let service = CapabilityService::new(dir.path().to_path_buf());

        let profile = service
            .dispatch(CapabilityRequest::FunctionProfile(
                revx_core::FunctionProfileRequest {
                    query: "GameRoot_ActiveDesk".to_string(),
                },
            ))
            .unwrap();
        let CapabilityResponse::FunctionProfile(profile) = profile else {
            panic!("expected function profile");
        };
        assert!(!profile.agent_brief.headline.is_empty());
        assert!(!profile.agent_brief.next_actions.is_empty());
        assert_eq!(profile.agent_brief.next_actions[0].tool, "decompile_function");
        let profile_text = mcp_response_summary(&CapabilityResponse::FunctionProfile(profile));
        assert!(profile_text.contains("## Digest"));
        assert!(profile_text.contains("Agent Brief") || profile_text.contains("EXECUTE NOW"));

        let strings = service
            .dispatch(CapabilityRequest::StringSearch(
                revx_core::StringSearchRequest {
                    pattern: "ActiveDesk".to_string(),
                    limit: Some(10),
                    offset: Some(0),
                },
            ))
            .unwrap();
        let CapabilityResponse::StringSearch(strings) = strings else {
            panic!("expected string search");
        };
        assert!(!strings.agent_brief.next_actions.is_empty());
        assert_eq!(strings.agent_brief.next_actions[0].tool, "xrefs_query");
    }

    fn sample_bundle(binary_id: &str, path: &str) -> AnalysisBundle {
        let function = Function {
            name: "tss_sdk_ioctl".to_string(),
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
                return_type: Some("int".to_string()),
                stack_arg_bytes: Some(0),
                evidence_ids: vec!["stack:401000".to_string()],
            }),
            arguments: vec![Variable {
                name: "arg_0".to_string(),
                role: VariableRole::Argument,
                storage: VariableStorage::Register,
                type_name: Some("void *".to_string()),
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
                text: "int tss_sdk_ioctl(void *arg_0) {\n    return 0;\n}".to_string(),
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
                binary: revx_core::BinarySummary {
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
            references: Vec::new(),
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
}


