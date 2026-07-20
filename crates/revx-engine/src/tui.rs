use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Tabs, Wrap};
use ratatui::Terminal;
use revx_core::{
    CapabilityRequest, CapabilityResponse, DecompileCacheStatusRequest, DecompileFunctionRequest,
    DecompileStrategy, DisassembleFunctionRequest, FunctionProfileRequest, FunctionSearchRequest,
    HypothesisCreateRequest, ProjectStatusRequest, ProjectStatusResponse, StringSearchRequest,
    XrefsQueryRequest,
};
use revx_daemon::CapabilityService;
use std::io::{self, stdout};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Status,
    Functions,
    Strings,
    Xrefs,
    Detail,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DetailPane {
    Cfg,
    Disasm,
    Pseudo,
}

impl DetailPane {
    fn next(self) -> Self {
        match self {
            Self::Cfg => Self::Disasm,
            Self::Disasm => Self::Pseudo,
            Self::Pseudo => Self::Cfg,
        }
    }

    fn prev(self) -> Self {
        match self {
            Self::Cfg => Self::Pseudo,
            Self::Disasm => Self::Cfg,
            Self::Pseudo => Self::Disasm,
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::Cfg => "cfg",
            Self::Disasm => "disasm",
            Self::Pseudo => "pseudo",
        }
    }
}

impl Tab {
    fn all() -> [Tab; 5] {
        [
            Tab::Status,
            Tab::Functions,
            Tab::Strings,
            Tab::Xrefs,
            Tab::Detail,
        ]
    }

    fn title(self) -> &'static str {
        match self {
            Tab::Status => "Status",
            Tab::Functions => "Funcs",
            Tab::Strings => "Strings",
            Tab::Xrefs => "Xrefs",
            Tab::Detail => "Detail",
        }
    }
}

#[derive(Clone)]
struct AddrLine {
    text: String,
    address: Option<u64>,
    exact: bool,
}

fn parse_line_address(line: &str) -> Option<u64> {
    for token in line.split_whitespace() {
        let raw = token.trim_matches(|c: char| !c.is_ascii_hexdigit() && c != 'x' && c != 'X');
        let hex = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")).unwrap_or(raw);
        if hex.len() >= 3 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            if let Ok(v) = u64::from_str_radix(hex, 16) {
                if v > 0xff {
                    return Some(v);
                }
            }
        }
    }
    // also match @ 0x...
    if let Some(idx) = line.find("0x") {
        let rest = &line[idx + 2..];
        let hex: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        if hex.len() >= 3 {
            if let Ok(v) = u64::from_str_radix(&hex, 16) {
                return Some(v);
            }
        }
    }
    None
}

fn lines_with_addresses(text: &str) -> Vec<AddrLine> {
    let mut last = None;
    text.lines()
        .map(|line| {
            let exact = parse_line_address(line);
            if let Some(addr) = exact {
                last = Some(addr);
            }
            AddrLine {
                text: line.to_string(),
                address: exact.or(last),
                exact: exact.is_some(),
            }
        })
        .collect()
}


fn blocks_to_disasm_text(blocks: &[revx_core::BasicBlock]) -> String {
    let mut out = String::new();
    if blocks.is_empty() {
        out.push_str("(no blocks)\n");
        return out;
    }
    for (idx, block) in blocks.iter().enumerate().take(160) {
        out.push_str(&format!(
            "bb{idx} @ {:#x} size={} insts={}\n",
            block.address,
            block.size,
            block.instructions.len()
        ));
        for inst in block.instructions.iter().take(96) {
            out.push_str(&format!("  {:#x}: {}\n", inst.address, inst.text));
        }
        if block.instructions.len() > 96 {
            out.push_str("  ...\n");
        }
    }
    if blocks.len() > 160 {
        out.push_str(&format!("... {} more blocks\n", blocks.len() - 160));
    }
    out
}

fn nearest_line_index(lines: &[AddrLine], address: u64) -> Option<usize> {
    let mut best: Option<(usize, u64, bool)> = None;
    for (idx, line) in lines.iter().enumerate() {
        let Some(addr) = line.address else {
            continue;
        };
        let dist = addr.abs_diff(address);
        let exact_bonus = line.exact;
        match best {
            Some((_, best_dist, best_exact))
                if dist > best_dist || (dist == best_dist && !exact_bonus && best_exact) => {}
            _ => best = Some((idx, dist, exact_bonus)),
        }
        if dist == 0 && exact_bonus {
            break;
        }
    }
    best.map(|(idx, _, _)| idx)
}

struct App {
    service: CapabilityService,
    tab: Tab,
    status: Option<ProjectStatusResponse>,
    functions: Vec<String>,
    strings: Vec<String>,
    xrefs: Vec<String>,
    selected_fn: ListState,
    selected_str: ListState,
    selected_xref: ListState,
    detail_meta: String,
    detail_cfg: String,
    detail_disasm: String,
    detail_pseudo: String,
    cfg_lines: Vec<AddrLine>,
    disasm_lines: Vec<AddrLine>,
    pseudo_lines: Vec<AddrLine>,
    selected_cfg: ListState,
    selected_disasm: ListState,
    selected_pseudo: ListState,
    linked_address: Option<u64>,
    decompile_strategy: DecompileStrategy,
    detail_pane: DetailPane,
    notes: Vec<String>,
    filter: String,
    editing_filter: bool,
    editing_note: bool,
    note_draft: String,
    current_function: String,
    message: String,
}

impl App {
    fn new(workspace_root: PathBuf) -> Result<Self> {
        let service = CapabilityService::new(workspace_root);
        let mut app = Self {
            service,
            tab: Tab::Status,
            status: None,
            functions: Vec::new(),
            strings: Vec::new(),
            xrefs: Vec::new(),
            selected_fn: ListState::default(),
            selected_str: ListState::default(),
            selected_xref: ListState::default(),
            detail_meta: String::new(),
            detail_cfg: String::new(),
            detail_disasm: String::new(),
            detail_pseudo: String::new(),
            cfg_lines: Vec::new(),
            disasm_lines: Vec::new(),
            pseudo_lines: Vec::new(),
            selected_cfg: ListState::default(),
            selected_disasm: ListState::default(),
            selected_pseudo: ListState::default(),
            linked_address: None,
            decompile_strategy: DecompileStrategy::Auto,
            detail_pane: DetailPane::Pseudo,
            notes: Vec::new(),
            filter: String::new(),
            editing_filter: false,
            editing_note: false,
            note_draft: String::new(),
            current_function: String::new(),
            message:
                "1-5/tab  j/k link  h/l pane  s strategy  i disasm  c cache  enter open  d decompile  x xrefs  n note  q"
                    .into(),
        };
        app.reload_status()?;
        app.reload_functions()?;
        app.reload_strings()?;
        Ok(app)
    }

    fn reload_status(&mut self) -> Result<()> {
        match self
            .service
            .dispatch(CapabilityRequest::ProjectStatus(ProjectStatusRequest))
        {
            Ok(CapabilityResponse::ProjectStatus(status)) => {
                self.status = Some(status);
                self.message = "status loaded".into();
            }
            Ok(_) => self.message = "unexpected status response".into(),
            Err(err) => self.message = format!("status error: {err:#}"),
        }
        Ok(())
    }

    fn reload_functions(&mut self) -> Result<()> {
        let query = self.filter.clone();
        match self.service.dispatch(CapabilityRequest::FunctionSearch(
            FunctionSearchRequest {
                query,
                limit: Some(400),
                offset: None,
            },
        )) {
            Ok(CapabilityResponse::FunctionSearch(resp)) => {
                self.functions = resp
                    .functions
                    .into_iter()
                    .map(|hit| format!("{:#x}  {}  size={}", hit.address, hit.name, hit.size))
                    .collect();
                if self.functions.is_empty() {
                    self.selected_fn.select(None);
                } else if self.selected_fn.selected().is_none() {
                    self.selected_fn.select(Some(0));
                }
                self.message = format!("functions: {}", self.functions.len());
            }
            Ok(_) => self.message = "unexpected function response".into(),
            Err(err) => self.message = format!("funcs error: {err:#}"),
        }
        Ok(())
    }

    fn reload_strings(&mut self) -> Result<()> {
        let query = self.filter.clone();
        match self
            .service
            .dispatch(CapabilityRequest::StringSearch(StringSearchRequest {
                pattern: query,
                limit: Some(400),
                offset: None,
            })) {
            Ok(CapabilityResponse::StringSearch(resp)) => {
                self.strings = resp
                    .matches
                    .into_iter()
                    .map(|hit| {
                        let addr = hit
                            .address
                            .map(|a| format!("{a:#x}"))
                            .unwrap_or_else(|| "-".into());
                        format!("{addr}  {}", hit.value.replace('\n', "\\n"))
                    })
                    .collect();
                if self.strings.is_empty() {
                    self.selected_str.select(None);
                } else if self.selected_str.selected().is_none() {
                    self.selected_str.select(Some(0));
                }
                self.message = format!("strings: {}", self.strings.len());
            }
            Ok(_) => self.message = "unexpected string response".into(),
            Err(err) => self.message = format!("strings error: {err:#}"),
        }
        Ok(())
    }

    fn selected_function_query(&self) -> Option<String> {
        let idx = self.selected_fn.selected()?;
        let line = self.functions.get(idx)?;
        Some(
            line.split_whitespace()
                .nth(1)
                .unwrap_or(line.as_str())
                .to_string(),
        )
    }

    fn set_detail_from_function(
        &mut self,
        func: &revx_core::Function,
        incoming: &[revx_core::Reference],
        outgoing: &[revx_core::Reference],
    ) {
        self.current_function = func.name.clone();
        let mut meta = String::new();
        meta.push_str(&format!(
            "name: {}\naddr: {:#x}\nsize: {:#x}\nargs: {}\nlocals: {}\nblocks: {}\n",
            func.name,
            func.address,
            func.size,
            func.arguments.len(),
            func.locals.len(),
            func.blocks.len()
        ));
        if let Some(stack) = &func.stack_summary {
            meta.push_str(&format!(
                "frame: {:?}  cc: {:?}  ret: {:?}\n",
                stack.frame_size, stack.calling_convention, stack.return_type
            ));
        }
        for arg in &func.arguments {
            meta.push_str(&format!(
                "  arg {} @ {} : {}\n",
                arg.name,
                arg.location,
                arg.type_name.as_deref().unwrap_or("?")
            ));
        }
        for local in func.locals.iter().take(32) {
            meta.push_str(&format!(
                "  local {} @ {} : {}\n",
                local.name,
                local.location,
                local.type_name.as_deref().unwrap_or("?")
            ));
        }
        if !incoming.is_empty() {
            meta.push_str(&format!("\nincoming xrefs: {}\n", incoming.len()));
            for xref in incoming.iter().take(8) {
                meta.push_str(&format!("  {:#x} -> {:#x} {:?}\n", xref.from, xref.to, xref.kind));
            }
        }
        if !outgoing.is_empty() {
            meta.push_str(&format!("outgoing xrefs: {}\n", outgoing.len()));
            for xref in outgoing.iter().take(8) {
                meta.push_str(&format!("  {:#x} -> {:#x} {:?}\n", xref.from, xref.to, xref.kind));
            }
        }
        if !self.notes.is_empty() {
            meta.push_str("\nnotes:\n");
            for note in &self.notes {
                meta.push_str(&format!("- {note}\n"));
            }
        }

        let mut cfg = String::new();
        if func.blocks.is_empty() {
            cfg.push_str("(no cfg blocks in profile payload)\n");
        } else {
            for (idx, block) in func.blocks.iter().enumerate().take(80) {
                cfg.push_str(&format!(
                    "bb{idx} @ {:#x} size={} insts={}\n",
                    block.address,
                    block.size,
                    block.instructions.len()
                ));
                for inst in block.instructions.iter().take(6) {
                    cfg.push_str(&format!("  {:#x}: {}\n", inst.address, inst.text));
                }
                if block.instructions.len() > 6 {
                    cfg.push_str("  ...\n");
                }
            }
            if func.blocks.len() > 80 {
                cfg.push_str(&format!("... {} more blocks\n", func.blocks.len() - 80));
            }
        }

        let mut pseudo = String::new();
        if let Some(pc) = &func.pseudocode {
            pseudo.push_str(&pc.text);
            pseudo.push('\n');
            if !pc.regions.is_empty() {
                pseudo.push_str("\n/* regions */\n");
                for region in &pc.regions {
                    let span = match (region.start_address, region.end_address) {
                        (Some(s), Some(e)) => format!(" @ {s:#x}-{e:#x}"),
                        (Some(s), None) => format!(" @ {s:#x}"),
                        _ => String::new(),
                    };
                    pseudo.push_str(&format!(
                        "{:?} {}{}\n",
                        region.kind,
                        region.header.clone().unwrap_or_default(),
                        span
                    ));
                    for st in region.statements.iter().take(8) {
                        pseudo.push_str(&format!("  {st}\n"));
                    }
                }
            }
            // also put region outline into cfg pane if cfg empty of structure
            if cfg.lines().count() < 3 {
                for region in &pc.regions {
                    let span = match (region.start_address, region.end_address) {
                        (Some(s), Some(e)) => format!(" @ {s:#x}-{e:#x}"),
                        (Some(s), None) => format!(" @ {s:#x}"),
                        _ => String::new(),
                    };
                    cfg.push_str(&format!(
                        "region {:?} {}{}\n",
                        region.kind,
                        region.header.clone().unwrap_or_default(),
                        span
                    ));
                }
            }
        } else {
            pseudo.push_str("no pseudocode available\n");
        }

        self.detail_meta = meta;
        self.detail_cfg = cfg.clone();
        self.detail_pseudo = pseudo.clone();
        self.cfg_lines = lines_with_addresses(&cfg);
        self.pseudo_lines = lines_with_addresses(&pseudo);
        self.selected_cfg.select(if self.cfg_lines.is_empty() { None } else { Some(0) });
        self.selected_pseudo.select(if self.pseudo_lines.is_empty() { None } else { Some(0) });
        self.set_disasm_from_blocks(&func.blocks);
        self.linked_address = self
            .cfg_lines
            .first()
            .and_then(|l| l.address)
            .or_else(|| self.disasm_lines.first().and_then(|l| l.address))
            .or_else(|| self.pseudo_lines.first().and_then(|l| l.address));
        self.detail_pane = DetailPane::Pseudo;
        self.tab = Tab::Detail;
        self.sync_link_from_focus();
    }

    fn sync_link_from_focus(&mut self) {
        let addr = match self.detail_pane {
            DetailPane::Cfg => self
                .selected_cfg
                .selected()
                .and_then(|i| self.cfg_lines.get(i))
                .and_then(|l| l.address),
            DetailPane::Disasm => self
                .selected_disasm
                .selected()
                .and_then(|i| self.disasm_lines.get(i))
                .and_then(|l| l.address),
            DetailPane::Pseudo => self
                .selected_pseudo
                .selected()
                .and_then(|i| self.pseudo_lines.get(i))
                .and_then(|l| l.address),
        };
        self.linked_address = addr;
        if let Some(address) = addr {
            if self.detail_pane != DetailPane::Cfg {
                if let Some(idx) = nearest_line_index(&self.cfg_lines, address) {
                    self.selected_cfg.select(Some(idx));
                }
            }
            if self.detail_pane != DetailPane::Disasm {
                if let Some(idx) = nearest_line_index(&self.disasm_lines, address) {
                    self.selected_disasm.select(Some(idx));
                }
            }
            if self.detail_pane != DetailPane::Pseudo {
                if let Some(idx) = nearest_line_index(&self.pseudo_lines, address) {
                    self.selected_pseudo.select(Some(idx));
                }
            }
            self.message = format!("link {:#x} ({})", address, self.detail_pane.title());
        }
    }

    fn set_disasm_from_blocks(&mut self, blocks: &[revx_core::BasicBlock]) {
        let text = blocks_to_disasm_text(blocks);
        self.detail_disasm = text.clone();
        self.disasm_lines = lines_with_addresses(&text);
        self.selected_disasm
            .select(if self.disasm_lines.is_empty() { None } else { Some(0) });
    }

    fn load_disasm_selected(&mut self) -> Result<()> {
        let Some(query) = self.selected_function_query() else {
            self.message = "no function selected".into();
            return Ok(());
        };
        match self.service.dispatch(CapabilityRequest::DisassembleFunction(
            DisassembleFunctionRequest {
                query: query.clone(),
            },
        )) {
            Ok(CapabilityResponse::DisassembleFunction(resp)) => {
                self.current_function = resp.function_name.clone();
                self.set_disasm_from_blocks(&resp.blocks);
                if self.detail_meta.is_empty() {
                    self.detail_meta = format!("disasm: {} @ {:#x}\n", resp.function_name, resp.address);
                }
                self.detail_pane = DetailPane::Disasm;
                self.tab = Tab::Detail;
                self.sync_link_from_focus();
                self.message = format!("disasm {query} blocks={}", resp.blocks.len());
            }
            Ok(_) => self.message = "unexpected disasm response".into(),
            Err(err) => self.message = format!("disasm error: {err:#}"),
        }
        Ok(())
    }

    fn load_cache_status_selected(&mut self) -> Result<()> {
        let Some(query) = self.selected_function_query() else {
            self.message = "no function selected".into();
            return Ok(());
        };
        match self.service.dispatch(CapabilityRequest::DecompileCacheStatus(
            DecompileCacheStatusRequest {
                query: query.clone(),
            },
        )) {
            Ok(CapabilityResponse::DecompileCacheStatus(resp)) => {
                let mut lines = vec![format!(
                    "cache {} @ {:#x} func_pseudo={} regions={} text_len={}",
                    resp.function_name,
                    resp.address,
                    resp.has_function_pseudocode,
                    resp.function_region_count,
                    resp.function_text_len
                )];
                if resp.strategies.is_empty() {
                    lines.push("strategies: (none)".into());
                } else {
                    for entry in resp.strategies {
                        lines.push(format!(
                            "  {} regions={} text_len={} lattice={}",
                            entry.strategy, entry.region_count, entry.text_len, entry.has_lattice
                        ));
                    }
                }
                self.message = lines.join(" | ");
                if self.detail_meta.lines().count() < 12 {
                    self.detail_meta.push('\n');
                    self.detail_meta.push_str(&lines.join("\n"));
                    self.detail_meta.push('\n');
                }
            }
            Ok(_) => self.message = "unexpected cache status response".into(),
            Err(err) => self.message = format!("cache status error: {err:#}"),
        }
        Ok(())
    }

    fn cycle_strategy(&mut self) {
        self.decompile_strategy = match self.decompile_strategy {
            DecompileStrategy::Auto => DecompileStrategy::Cached,
            DecompileStrategy::Cached => DecompileStrategy::Fast,
            DecompileStrategy::Fast => DecompileStrategy::Full,
            DecompileStrategy::Full => DecompileStrategy::Hotblock,
            DecompileStrategy::Hotblock => DecompileStrategy::Auto,
        };
        self.message = format!("strategy: {:?}", self.decompile_strategy);
    }

    fn open_selected_function(&mut self) -> Result<()> {
        let Some(query) = self.selected_function_query() else {
            self.message = "no function selected".into();
            return Ok(());
        };
        match self
            .service
            .dispatch(CapabilityRequest::FunctionProfile(FunctionProfileRequest {
                query: query.clone(),
            })) {
            Ok(CapabilityResponse::FunctionProfile(resp)) => {
                self.set_detail_from_function(
                    &resp.function,
                    &resp.incoming_xrefs,
                    &resp.outgoing_xrefs,
                );
                self.message = format!("opened {query}");
            }
            Ok(_) => self.message = "unexpected profile response".into(),
            Err(err) => self.message = format!("profile error: {err:#}"),
        }
        Ok(())
    }

    fn decompile_selected(&mut self) -> Result<()> {
        let Some(query) = self.selected_function_query() else {
            self.message = "no function selected".into();
            return Ok(());
        };
        match self.service.dispatch(CapabilityRequest::DecompileFunction(
            DecompileFunctionRequest {
                query: query.clone(),
                strategy: Some(self.decompile_strategy),
                force_refresh: Some(!matches!(
                    self.decompile_strategy,
                    DecompileStrategy::Cached | DecompileStrategy::Auto
                )),
            },
        )) {
            Ok(CapabilityResponse::DecompileFunction(resp)) => {
                self.current_function = resp.function_name.clone();
                self.detail_meta = format!(
                    "decompile: {} @ {:#x} strategy={:?}\n",
                    resp.function_name, resp.address, resp.strategy_used
                );
                let mut cfg = String::new();
                let mut pseudo = String::new();
                if let Some(pc) = resp.pseudocode {
                    for region in &pc.regions {
                        let span = match (region.start_address, region.end_address) {
                            (Some(s), Some(e)) => format!(" @ {s:#x}-{e:#x}"),
                            (Some(s), None) => format!(" @ {s:#x}"),
                            _ => String::new(),
                        };
                        cfg.push_str(&format!(
                            "{:?} {}{}\n",
                            region.kind,
                            region.header.clone().unwrap_or_default(),
                            span
                        ));
                        for st in region.statements.iter().take(6) {
                            cfg.push_str(&format!("  {st}\n"));
                        }
                    }
                    if cfg.is_empty() {
                        cfg.push_str("(no regions; see pseudocode pane)\n");
                    }
                    pseudo.push_str(&pc.text);
                } else {
                    cfg.push_str("(no regions)\n");
                    pseudo.push_str("no pseudocode available\n");
                }
                self.detail_cfg = cfg.clone();
                self.detail_pseudo = pseudo.clone();
                self.cfg_lines = lines_with_addresses(&cfg);
                self.pseudo_lines = lines_with_addresses(&pseudo);
                self.selected_cfg.select(if self.cfg_lines.is_empty() { None } else { Some(0) });
                self.selected_pseudo
                    .select(if self.pseudo_lines.is_empty() { None } else { Some(0) });
                if self.disasm_lines.is_empty() {
                    let _ = self.load_disasm_selected();
                }
                self.detail_meta.push_str(&format!(
                    "cache_hit={} strategies={}\n",
                    resp.cache_hit,
                    resp.available_strategies.join(",")
                ));
                self.detail_pane = DetailPane::Pseudo;
                self.tab = Tab::Detail;
                self.sync_link_from_focus();
                self.message = format!(
                    "decompiled {query} strategy={:?} cache_hit={}",
                    resp.strategy_used, resp.cache_hit
                );
            }
            Ok(_) => self.message = "unexpected decompile response".into(),
            Err(err) => self.message = format!("decompile error: {err:#}"),
        }
        Ok(())
    }

    fn load_xrefs_selected(&mut self) -> Result<()> {
        let Some(query) = self.selected_function_query() else {
            self.message = "no function selected".into();
            return Ok(());
        };
        match self
            .service
            .dispatch(CapabilityRequest::XrefsQuery(XrefsQueryRequest {
                query: query.clone(),
            })) {
            Ok(CapabilityResponse::XrefsQuery(resp)) => {
                self.xrefs = resp
                    .references
                    .into_iter()
                    .map(|xref| format!("{:#x} -> {:#x} {:?}", xref.from, xref.to, xref.kind))
                    .collect();
                if self.xrefs.is_empty() {
                    self.selected_xref.select(None);
                    self.message = format!("no xrefs for {query}");
                } else {
                    self.selected_xref.select(Some(0));
                    self.message = format!("xrefs for {query}: {}", self.xrefs.len());
                }
                self.tab = Tab::Xrefs;
            }
            Ok(_) => self.message = "unexpected xrefs response".into(),
            Err(err) => self.message = format!("xrefs error: {err:#}"),
        }
        Ok(())
    }

    fn save_note(&mut self) -> Result<()> {
        let note = self.note_draft.trim().to_string();
        if note.is_empty() {
            self.message = "empty note".into();
            return Ok(());
        }
        let subject = if self.current_function.is_empty() {
            self.selected_function_query()
                .unwrap_or_else(|| "workspace".into())
        } else {
            self.current_function.clone()
        };
        match self.service.dispatch(CapabilityRequest::HypothesisCreate(
            HypothesisCreateRequest {
                title: format!("note:{subject}"),
                notes: note.clone(),
                evidence_ids: Vec::new(),
            },
        )) {
            Ok(CapabilityResponse::HypothesisCreate(resp)) => {
                self.notes
                    .push(format!("{} ({})", note, resp.hypothesis.id));
                self.note_draft.clear();
                self.editing_note = false;
                self.message = format!("saved note on {subject}");
            }
            Ok(_) => self.message = "unexpected hypothesis response".into(),
            Err(err) => self.message = format!("note error: {err:#}"),
        }
        Ok(())
    }

    fn move_list(state: &mut ListState, len: usize, delta: isize) {
        if len == 0 {
            state.select(None);
            return;
        }
        let current = state.selected().unwrap_or(0) as isize;
        let next = (current + delta).rem_euclid(len as isize) as usize;
        state.select(Some(next));
    }
}

pub fn run(workspace_root: PathBuf) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut app = App::new(workspace_root)?;
    let result = event_loop(&mut terminal, &mut app);
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<()> {
    loop {
        terminal.draw(|frame| draw(frame, app))?;
        if !event::poll(Duration::from_millis(200))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if app.editing_filter {
            match key.code {
                KeyCode::Esc => app.editing_filter = false,
                KeyCode::Enter => {
                    app.editing_filter = false;
                    app.reload_functions()?;
                    app.reload_strings()?;
                }
                KeyCode::Backspace => {
                    app.filter.pop();
                }
                KeyCode::Char(c) => app.filter.push(c),
                _ => {}
            }
            continue;
        }
        if app.editing_note {
            match key.code {
                KeyCode::Esc => {
                    app.editing_note = false;
                    app.note_draft.clear();
                }
                KeyCode::Enter => app.save_note()?,
                KeyCode::Backspace => {
                    app.note_draft.pop();
                }
                KeyCode::Char(c) => app.note_draft.push(c),
                _ => {}
            }
            continue;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => break,
            KeyCode::Char('1') => app.tab = Tab::Status,
            KeyCode::Char('2') => app.tab = Tab::Functions,
            KeyCode::Char('3') => app.tab = Tab::Strings,
            KeyCode::Char('4') => app.tab = Tab::Xrefs,
            KeyCode::Char('5') => app.tab = Tab::Detail,
            KeyCode::Tab => {
                let tabs = Tab::all();
                let idx = tabs.iter().position(|t| *t == app.tab).unwrap_or(0);
                app.tab = tabs[(idx + 1) % tabs.len()];
            }
            KeyCode::Char('/') => {
                app.editing_filter = true;
                app.message = "filter: type and enter".into();
            }
            KeyCode::Char('n') => {
                app.editing_note = true;
                app.message = "note: type and enter to save hypothesis".into();
            }
            KeyCode::Char('r') => {
                app.reload_status()?;
                app.reload_functions()?;
                app.reload_strings()?;
            }
            KeyCode::Char('d') => app.decompile_selected()?,
            KeyCode::Char('x') => app.load_xrefs_selected()?,
            KeyCode::Char('h') | KeyCode::Left => {
                if app.tab == Tab::Detail {
                    app.detail_pane = app.detail_pane.prev();
                    app.sync_link_from_focus();
                    app.message = format!("focus: {}", app.detail_pane.title());
                }
            }
            KeyCode::Char('l') | KeyCode::Right => {
                if app.tab == Tab::Detail {
                    app.detail_pane = app.detail_pane.next();
                    app.sync_link_from_focus();
                    app.message = format!("focus: {}", app.detail_pane.title());
                }
            }
            KeyCode::Char('i') => app.load_disasm_selected()?,
            KeyCode::Char('c') => app.load_cache_status_selected()?,
            KeyCode::Char('s') => {
                if app.tab == Tab::Detail || app.tab == Tab::Functions {
                    app.cycle_strategy();
                }
            }
            KeyCode::Char('j') | KeyCode::Down => match app.tab {
                Tab::Functions => App::move_list(&mut app.selected_fn, app.functions.len(), 1),
                Tab::Strings => App::move_list(&mut app.selected_str, app.strings.len(), 1),
                Tab::Xrefs => App::move_list(&mut app.selected_xref, app.xrefs.len(), 1),
                Tab::Detail => {
                    match app.detail_pane {
                        DetailPane::Cfg => {
                            App::move_list(&mut app.selected_cfg, app.cfg_lines.len(), 1)
                        }
                        DetailPane::Disasm => {
                            App::move_list(&mut app.selected_disasm, app.disasm_lines.len(), 1)
                        }
                        DetailPane::Pseudo => {
                            App::move_list(&mut app.selected_pseudo, app.pseudo_lines.len(), 1)
                        }
                    }
                    app.sync_link_from_focus();
                }
                _ => {}
            },
            KeyCode::Char('k') | KeyCode::Up => match app.tab {
                Tab::Functions => App::move_list(&mut app.selected_fn, app.functions.len(), -1),
                Tab::Strings => App::move_list(&mut app.selected_str, app.strings.len(), -1),
                Tab::Xrefs => App::move_list(&mut app.selected_xref, app.xrefs.len(), -1),
                Tab::Detail => {
                    match app.detail_pane {
                        DetailPane::Cfg => {
                            App::move_list(&mut app.selected_cfg, app.cfg_lines.len(), -1)
                        }
                        DetailPane::Disasm => {
                            App::move_list(&mut app.selected_disasm, app.disasm_lines.len(), -1)
                        }
                        DetailPane::Pseudo => {
                            App::move_list(&mut app.selected_pseudo, app.pseudo_lines.len(), -1)
                        }
                    }
                    app.sync_link_from_focus();
                }
                _ => {}
            },
            KeyCode::PageDown => {
                if app.tab == Tab::Detail {
                    for _ in 0..10 {
                        match app.detail_pane {
                            DetailPane::Cfg => {
                                App::move_list(&mut app.selected_cfg, app.cfg_lines.len(), 1)
                            }
                            DetailPane::Disasm => {
                                App::move_list(
                                    &mut app.selected_disasm,
                                    app.disasm_lines.len(),
                                    1,
                                )
                            }
                            DetailPane::Pseudo => {
                                App::move_list(
                                    &mut app.selected_pseudo,
                                    app.pseudo_lines.len(),
                                    1,
                                )
                            }
                        }
                    }
                    app.sync_link_from_focus();
                }
            }
            KeyCode::PageUp => {
                if app.tab == Tab::Detail {
                    for _ in 0..10 {
                        match app.detail_pane {
                            DetailPane::Cfg => {
                                App::move_list(&mut app.selected_cfg, app.cfg_lines.len(), -1)
                            }
                            DetailPane::Disasm => {
                                App::move_list(
                                    &mut app.selected_disasm,
                                    app.disasm_lines.len(),
                                    -1,
                                )
                            }
                            DetailPane::Pseudo => {
                                App::move_list(
                                    &mut app.selected_pseudo,
                                    app.pseudo_lines.len(),
                                    -1,
                                )
                            }
                        }
                    }
                    app.sync_link_from_focus();
                }
            }
            KeyCode::Enter => {
                if app.tab == Tab::Functions {
                    app.open_selected_function()?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn draw(frame: &mut ratatui::Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(frame.area());

    let titles = Tab::all()
        .iter()
        .map(|t| Line::from(t.title()))
        .collect::<Vec<_>>();
    let selected = Tab::all()
        .iter()
        .position(|t| *t == app.tab)
        .unwrap_or(0);
    let tabs = Tabs::new(titles)
        .select(selected)
        .block(Block::default().borders(Borders::ALL).title("revx tui"))
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(tabs, chunks[0]);

    match app.tab {
        Tab::Status => draw_status(frame, chunks[1], app),
        Tab::Functions => draw_list(frame, chunks[1], "functions", &app.functions, &app.selected_fn),
        Tab::Strings => draw_list(frame, chunks[1], "strings", &app.strings, &app.selected_str),
        Tab::Xrefs => draw_list(frame, chunks[1], "xrefs", &app.xrefs, &app.selected_xref),
        Tab::Detail => draw_detail(frame, chunks[1], app),
    }

    let filter = if app.editing_filter {
        format!("filter> {}_", app.filter)
    } else if app.editing_note {
        format!("note> {}_", app.note_draft)
    } else if app.filter.is_empty() {
        "filter: (none)".into()
    } else {
        format!("filter: {}", app.filter)
    };
    let status = Paragraph::new(Line::from(vec![
        Span::styled(filter, Style::default().fg(Color::Yellow)),
        Span::raw("  |  "),
        Span::raw(app.message.as_str()),
    ]))
    .block(Block::default().borders(Borders::ALL).title("help"));
    frame.render_widget(status, chunks[2]);
}

fn draw_detail(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(3)])
        .split(area);
    let meta = Paragraph::new(app.detail_meta.as_str())
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(
                    "function  strategy={:?}  pane={}",
                    app.decompile_strategy,
                    app.detail_pane.title()
                )),
        );
    frame.render_widget(meta, rows[0]);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(28),
            Constraint::Percentage(36),
            Constraint::Percentage(36),
        ])
        .split(rows[1]);

    let mk_items = |lines: &[AddrLine]| -> Vec<ListItem> {
        lines
            .iter()
            .map(|line| {
                let linked = app.linked_address.is_some()
                    && line.address == app.linked_address
                    && line.exact;
                let style = if linked {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                ListItem::new(Line::from(Span::styled(line.text.clone(), style)))
            })
            .collect()
    };

    let title = |base: &str, pane: DetailPane| {
        if app.detail_pane == pane {
            format!("{base} *")
        } else {
            base.to_string()
        }
    };
    let border = |pane: DetailPane| {
        if app.detail_pane == pane {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        }
    };

    let cfg = List::new(mk_items(&app.cfg_lines))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title("cfg / regions", DetailPane::Cfg))
                .border_style(border(DetailPane::Cfg)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");
    let disasm = List::new(mk_items(&app.disasm_lines))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title("disasm", DetailPane::Disasm))
                .border_style(border(DetailPane::Disasm)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");
    let pseudo = List::new(mk_items(&app.pseudo_lines))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title("pseudocode", DetailPane::Pseudo))
                .border_style(border(DetailPane::Pseudo)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    let mut cfg_state = app.selected_cfg.clone();
    let mut disasm_state = app.selected_disasm.clone();
    let mut pseudo_state = app.selected_pseudo.clone();
    frame.render_stateful_widget(cfg, cols[0], &mut cfg_state);
    frame.render_stateful_widget(disasm, cols[1], &mut disasm_state);
    frame.render_stateful_widget(pseudo, cols[2], &mut pseudo_state);
}


fn draw_status(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let text = match &app.status {
        Some(status) => {
            let mut lines = vec![
                format!("root: {}", status.workspace_root),
                format!("project: {}", status.project.name),
                format!("schema: {}", status.project.schema_version),
                format!("binaries: {}", status.binary_count),
            ];
            if let Some(primary) = &status.project.primary_binary {
                lines.push(format!("primary: {primary}"));
            }
            for binary in status.binaries.iter().take(24) {
                lines.push(format!(
                    "- {} {:?} {:?} funcs={} typed={} pseudo={} strings={} id={}",
                    binary.path,
                    binary.format,
                    binary.architecture,
                    binary.function_count,
                    binary.typed_function_count,
                    binary.structured_pseudocode_count,
                    binary.string_count,
                    binary.id
                ));
            }
            if !app.notes.is_empty() {
                lines.push(format!("session notes: {}", app.notes.len()));
            }
            lines.join("\n")
        }
        None => "no status".into(),
    };
    let p = Paragraph::new(text)
        .wrap(Wrap { trim: false })
        .block(Block::default().borders(Borders::ALL).title("project status"));
    frame.render_widget(p, area);
}

fn draw_list(
    frame: &mut ratatui::Frame,
    area: Rect,
    title: &str,
    items: &[String],
    state: &ListState,
) {
    let rows: Vec<ListItem> = items.iter().map(|s| ListItem::new(s.as_str())).collect();
    let list = List::new(rows)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");
    let mut state = state.clone();
    frame.render_stateful_widget(list, area, &mut state);
}
