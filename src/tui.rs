use std::io;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph},
};
use uuid::Uuid;

use crate::domain::{Finding, Session, Severity};
use crate::storage::save_session;

const MIN_WIDTH: u16 = 100;
const MIN_HEIGHT: u16 = 30;

/// Identifies whether the form is creating a new finding or editing an existing one.
#[derive(Debug, Clone)]
pub enum FormMode {
    New,
    Edit(Uuid),
}

// ─── Field index constants ───────────────────────────────────────────────────
//
// Layout order (14 fields total):
//   0  Title          (text)
//   1  AV             (metric)
//   2  AC             (metric)
//   3  PR             (metric)
//   4  UI             (metric)
//   5  S              (metric)
//   6  C              (metric)
//   7  I              (metric)
//   8  A              (metric)
//   9  Affected       (text)
//  10  Description    (text)
//  11  Evidence       (text)
//  12  Remediation    (text)
//  13  References     (text, optional)

pub const FIELD_TITLE: usize = 0;
pub const FIELD_AV: usize = 1;
pub const FIELD_AC: usize = 2;
pub const FIELD_PR: usize = 3;
pub const FIELD_UI: usize = 4;
pub const FIELD_S: usize = 5;
pub const FIELD_C: usize = 6;
pub const FIELD_I: usize = 7;
pub const FIELD_A: usize = 8;
pub const FIELD_AFFECTED: usize = 9;
pub const FIELD_DESCRIPTION: usize = 10;
pub const FIELD_EVIDENCE: usize = 11;
pub const FIELD_REMEDIATION: usize = 12;
pub const FIELD_REFERENCES: usize = 13;
pub const FIELD_COUNT: usize = 14;

/// Number of text-only fields (non-metric fields in `buffers`).
/// buffers covers: Title(0), Affected(1), Description(2), Evidence(3), Remediation(4), References(5)
pub const TEXT_FIELD_COUNT: usize = 6;

/// Maps a form-field index to its corresponding buffer slot index.
/// Metric fields (1–8) have no buffer — they use `metric_fields`.
/// Text fields map as: Title→0, Affected→1, Description→2, Evidence→3,
///                     Remediation→4, References→5.
fn text_buffer_index(field_idx: usize) -> Option<usize> {
    match field_idx {
        FIELD_TITLE => Some(0),
        FIELD_AFFECTED => Some(1),
        FIELD_DESCRIPTION => Some(2),
        FIELD_EVIDENCE => Some(3),
        FIELD_REMEDIATION => Some(4),
        FIELD_REFERENCES => Some(5),
        _ => None,
    }
}

/// Returns true when `field_idx` corresponds to one of the 8 CVSS metric fields.
pub fn is_metric_field(field_idx: usize) -> bool {
    (FIELD_AV..=FIELD_A).contains(&field_idx)
}

/// Maps a metric field index to its corresponding slot in `metric_fields`.
fn metric_slot(field_idx: usize) -> Option<usize> {
    if is_metric_field(field_idx) {
        Some(field_idx - FIELD_AV)
    } else {
        None
    }
}

/// Human-readable label for each form field, in field-index order.
pub const FIELD_LABELS: [&str; FIELD_COUNT] = [
    "Title",
    "AV (Attack Vector)",
    "AC (Attack Complexity)",
    "PR (Privileges Required)",
    "UI (User Interaction)",
    "S (Scope)",
    "C (Confidentiality)",
    "I (Integrity)",
    "A (Availability)",
    "Affected",
    "Description",
    "Evidence",
    "Remediation",
    "References (optional)",
];

/// Fields that must be non-empty (or always-valid) for the form to be valid.
/// References is omitted (optional). Metric fields always have a selection.
const REQUIRED_TEXT_FIELD_INDICES: [usize; 5] = [
    FIELD_TITLE,
    FIELD_AFFECTED,
    FIELD_DESCRIPTION,
    FIELD_EVIDENCE,
    FIELD_REMEDIATION,
];

// ─── Metric field definitions ─────────────────────────────────────────────────

/// Descriptor for a single CVSS metric field: its key abbreviation and the
/// ordered list of valid option codes.
pub struct MetricDescriptor {
    pub key: &'static str,
    pub options: &'static [&'static str],
    pub default_index: usize,
}

/// The 8 CVSS v3.1 base metrics in vector order, each with their valid values.
pub const CVSS_METRICS: [MetricDescriptor; 8] = [
    MetricDescriptor {
        key: "AV",
        options: &["N", "A", "L", "P"],
        default_index: 0,
    },
    MetricDescriptor {
        key: "AC",
        options: &["L", "H"],
        default_index: 0,
    },
    MetricDescriptor {
        key: "PR",
        options: &["N", "L", "H"],
        default_index: 0,
    },
    MetricDescriptor {
        key: "UI",
        options: &["N", "R"],
        default_index: 0,
    },
    MetricDescriptor {
        key: "S",
        options: &["U", "C"],
        default_index: 0,
    },
    MetricDescriptor {
        key: "C",
        options: &["N", "L", "H"],
        default_index: 0,
    },
    MetricDescriptor {
        key: "I",
        options: &["N", "L", "H"],
        default_index: 0,
    },
    MetricDescriptor {
        key: "A",
        options: &["N", "L", "H"],
        default_index: 0,
    },
];

/// Runtime selection state for a single CVSS metric field.
#[derive(Debug, Clone)]
pub struct MetricField {
    /// Index into `CVSS_METRICS[slot].options` for the currently selected value.
    pub selected: usize,
}

impl MetricField {
    fn at_default(slot: usize) -> Self {
        Self {
            selected: CVSS_METRICS[slot].default_index,
        }
    }

    pub fn current_value(&self, slot: usize) -> &'static str {
        CVSS_METRICS[slot].options[self.selected]
    }

    /// Advances selection forward, wrapping past the last option to the first.
    pub fn cycle_forward(&mut self, slot: usize) {
        let len = CVSS_METRICS[slot].options.len();
        self.selected = (self.selected + 1) % len;
    }

    /// Moves selection backward, wrapping before the first option to the last.
    pub fn cycle_backward(&mut self, slot: usize) {
        let len = CVSS_METRICS[slot].options.len();
        self.selected = self.selected.checked_sub(1).unwrap_or(len - 1);
    }

    /// Selects the option matching `letter` (case-insensitive) if it exists.
    /// Does nothing when `letter` is not a valid option for this metric.
    pub fn select_by_letter(&mut self, slot: usize, letter: char) {
        let upper = letter.to_ascii_uppercase().to_string();
        if let Some(pos) = CVSS_METRICS[slot].options.iter().position(|&v| v == upper) {
            self.selected = pos;
        }
    }

    /// Tries to select the value matching `value`. Returns false when `value`
    /// is not a valid option for this metric — selection is left unchanged.
    pub fn try_select_value(&mut self, slot: usize, value: &str) -> bool {
        if let Some(pos) = CVSS_METRICS[slot].options.iter().position(|&v| v == value) {
            self.selected = pos;
            true
        } else {
            false
        }
    }
}

// ─── FormState ────────────────────────────────────────────────────────────────

/// All runtime state for the finding form modal.
#[derive(Debug, Clone)]
pub struct FormState {
    /// Text buffers for the 6 free-text fields: Title, Affected, Description,
    /// Evidence, Remediation, References — indexed by `text_buffer_index()`.
    pub buffers: [String; TEXT_FIELD_COUNT],
    /// Selection state for the 8 CVSS metric fields, in metric-slot order (0=AV … 7=A).
    pub metric_fields: [MetricField; 8],
    /// Index of the currently focused field (0–13, uses `FIELD_*` constants).
    pub active_field: usize,
    /// Validation or save error to display inline.
    pub error: Option<String>,
    /// Whether this form creates a new finding or edits an existing one.
    pub mode: FormMode,
}

impl FormState {
    /// Creates a blank form for a new finding with all metric fields at their defaults.
    pub fn new() -> Self {
        Self {
            buffers: Default::default(),
            metric_fields: [
                MetricField::at_default(0),
                MetricField::at_default(1),
                MetricField::at_default(2),
                MetricField::at_default(3),
                MetricField::at_default(4),
                MetricField::at_default(5),
                MetricField::at_default(6),
                MetricField::at_default(7),
            ],
            active_field: FIELD_TITLE,
            error: None,
            mode: FormMode::New,
        }
    }

    /// Creates a pre-filled form for editing the given finding.
    ///
    /// Text fields are populated directly from the `Finding`. The 8 metric
    /// fields are populated by parsing `finding.cvss_vector`; any metric whose
    /// stored value is unrecognised falls back to its default.
    pub fn from_finding(finding: &Finding) -> Self {
        let mut form = Self::new();
        form.mode = FormMode::Edit(finding.id);

        form.buffers[0] = finding.title.clone();
        form.buffers[1] = finding.affected.clone();
        form.buffers[2] = finding.description.clone();
        form.buffers[3] = finding.evidence.clone();
        form.buffers[4] = finding.remediation.clone();
        form.buffers[5] = finding.references.join(", ");

        parse_cvss_vector_into_metrics(&finding.cvss_vector, &mut form.metric_fields);

        form
    }

    /// Moves focus to the next field, wrapping at the end.
    pub fn focus_next(&mut self) {
        self.active_field = (self.active_field + 1) % FIELD_COUNT;
    }

    /// Moves focus to the previous field, wrapping at the start.
    pub fn focus_prev(&mut self) {
        self.active_field = self.active_field.checked_sub(1).unwrap_or(FIELD_COUNT - 1);
    }

    /// Appends `ch` to the active text field buffer after stripping ANSI sequences.
    /// No-op when the active field is a metric field.
    pub fn push_char(&mut self, ch: char) {
        if let Some(buf_idx) = text_buffer_index(self.active_field) {
            let safe = strip_ansi(&ch.to_string());
            self.buffers[buf_idx].push_str(&safe);
        }
    }

    /// Removes the last character from the active text field buffer.
    /// No-op when the active field is a metric field.
    pub fn pop_char(&mut self) {
        if let Some(buf_idx) = text_buffer_index(self.active_field) {
            self.buffers[buf_idx].pop();
        }
    }

    /// Cycles the active metric field forward. No-op for text fields.
    pub fn cycle_active_metric_forward(&mut self) {
        if let Some(slot) = metric_slot(self.active_field) {
            self.metric_fields[slot].cycle_forward(slot);
        }
    }

    /// Cycles the active metric field backward. No-op for text fields.
    pub fn cycle_active_metric_backward(&mut self) {
        if let Some(slot) = metric_slot(self.active_field) {
            self.metric_fields[slot].cycle_backward(slot);
        }
    }

    /// Selects a metric value by letter for the active metric field.
    /// No-op for text fields or unrecognised letters.
    pub fn select_metric_by_letter(&mut self, ch: char) {
        if let Some(slot) = metric_slot(self.active_field) {
            self.metric_fields[slot].select_by_letter(slot, ch);
        }
    }

    /// Assembles the CVSS v3.1 vector string from the 8 metric selections.
    pub fn assembled_cvss_vector(&self) -> String {
        format!(
            "CVSS:3.1/AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}",
            self.metric_fields[0].current_value(0),
            self.metric_fields[1].current_value(1),
            self.metric_fields[2].current_value(2),
            self.metric_fields[3].current_value(3),
            self.metric_fields[4].current_value(4),
            self.metric_fields[5].current_value(5),
            self.metric_fields[6].current_value(6),
            self.metric_fields[7].current_value(7),
        )
    }

    /// Validates all form fields.
    ///
    /// Returns `Ok(())` when every required text field is non-empty.
    /// Metric fields always have a valid selection and are never checked for
    /// emptiness. Returns `Err(message)` for the first violation found.
    pub fn validate(&self) -> Result<(), String> {
        for &field_idx in &REQUIRED_TEXT_FIELD_INDICES {
            let buf_idx = text_buffer_index(field_idx)
                .expect("REQUIRED_TEXT_FIELD_INDICES contains only text-field indices");
            if self.buffers[buf_idx].trim().is_empty() {
                return Err(format!("⚠ {} is required", FIELD_LABELS[field_idx]));
            }
        }
        Ok(())
    }

    /// Returns the computed score and severity label for the assembled CVSS vector.
    /// Always returns `Some` because the vector is always well-formed from metric
    /// selections.
    pub fn cvss_live_feedback(&self) -> Option<String> {
        let vector = self.assembled_cvss_vector();
        match crate::cvss::base_score(&vector) {
            Ok(score) => {
                let severity = Severity::from_score(score);
                let label = severity_label(&severity);
                Some(format!("Score: {score:.1} ({label})"))
            }
            Err(_) => Some("⚠ Invalid CVSS v3.1 vector".to_string()),
        }
    }

    /// Builds a `Finding` from the current form state.
    ///
    /// Caller must have already validated the form via `validate()`.
    /// Returns `Err` if the assembled CVSS vector fails to parse — this is a
    /// bug if `validate()` was called first.
    pub fn build_finding(&self) -> Result<Finding, String> {
        let vector = self.assembled_cvss_vector();
        let score = crate::cvss::base_score(&vector).map_err(|_| {
            "build_finding: assembled CVSS vector failed to parse — this is a bug".to_string()
        })?;
        let severity = Severity::from_score(score);

        let refs_raw = strip_ansi(self.buffers[5].trim());
        let references: Vec<String> = if refs_raw.is_empty() {
            vec![]
        } else {
            refs_raw
                .split(',')
                .map(|r| strip_ansi(r.trim()))
                .filter(|r| !r.is_empty())
                .collect()
        };

        let id = match &self.mode {
            FormMode::New => Uuid::new_v4(),
            FormMode::Edit(id) => *id,
        };

        Ok(Finding {
            id,
            title: strip_ansi(self.buffers[0].trim()),
            cvss_vector: vector,
            cvss_score: score,
            severity,
            affected: strip_ansi(self.buffers[1].trim()),
            description: strip_ansi(self.buffers[2].trim()),
            evidence: strip_ansi(self.buffers[3].trim()),
            remediation: strip_ansi(self.buffers[4].trim()),
            references,
        })
    }
}

/// Parses a CVSS v3.1 vector string and populates metric selections in-place.
///
/// Format: `CVSS:3.1/AV:<v>/AC:<v>/PR:<v>/UI:<v>/S:<v>/C:<v>/I:<v>/A:<v>`
///
/// Each recognised segment updates the corresponding metric field. Segments
/// with an unrecognised value leave the field at its current selection
/// (defaults when called on a freshly-constructed `FormState`).
fn parse_cvss_vector_into_metrics(vector: &str, fields: &mut [MetricField; 8]) {
    for segment in vector.split('/') {
        let mut parts = segment.splitn(2, ':');
        let Some(key) = parts.next() else { continue };
        let Some(value) = parts.next() else { continue };

        let slot = CVSS_METRICS.iter().position(|m| m.key == key);
        if let Some(slot) = slot {
            fields[slot].try_select_value(slot, value);
        }
    }
}

// ─── RAII terminal guard ──────────────────────────────────────────────────────

/// RAII guard that restores the terminal on drop, even when an error occurs.
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

// ─── TUI runtime state ────────────────────────────────────────────────────────

/// State for the delete confirmation overlay.
#[derive(Debug, Clone)]
pub struct ConfirmDeleteState {
    /// Index into `session.findings` of the finding to delete.
    pub finding_index: usize,
    /// ANSI-stripped title of the finding, shown in the prompt.
    pub safe_title: String,
}

/// Holds the runtime state of the TUI session.
pub struct TuiState {
    /// The session being viewed and managed.
    pub session: Session,
    /// Index into `session.findings` for the currently highlighted row.
    pub selected: usize,
    /// When `Some`, the modal form is open.
    pub form: Option<FormState>,
    /// When `Some`, the delete confirmation overlay is open.
    pub confirm_delete: Option<ConfirmDeleteState>,
    /// Transient status message shown in the status bar instead of the hint line.
    pub status_message: Option<String>,
    /// Countdown in render cycles before `status_message` is cleared.
    pub message_ticks: u8,
}

impl TuiState {
    /// Creates a new `TuiState` for the given session with no finding selected.
    fn new(session: Session) -> Self {
        Self {
            session,
            selected: 0,
            form: None,
            confirm_delete: None,
            status_message: None,
            message_ticks: 0,
        }
    }

    /// Sets a transient status message that clears after `ticks` render cycles.
    fn set_status_message(&mut self, msg: impl Into<String>, ticks: u8) {
        self.status_message = Some(msg.into());
        self.message_ticks = ticks;
    }

    /// Decrements `message_ticks` and clears `status_message` when it reaches zero.
    fn tick_status_message(&mut self) {
        if self.message_ticks > 0 {
            self.message_ticks -= 1;
            if self.message_ticks == 0 {
                self.status_message = None;
            }
        }
    }

    /// Moves the selection one row down, wrapping to the start when past the end.
    fn select_next(&mut self) {
        let count = self.session.findings.len();
        if count == 0 {
            return;
        }
        self.selected = (self.selected + 1) % count;
    }

    /// Moves the selection one row up, wrapping to the end when past the start.
    fn select_prev(&mut self) {
        let count = self.session.findings.len();
        if count == 0 {
            return;
        }
        self.selected = self.selected.checked_sub(1).unwrap_or(count - 1);
    }

    /// Returns the currently selected finding, if any.
    fn selected_finding(&self) -> Option<&Finding> {
        self.session.findings.get(self.selected)
    }

    /// Opens the new-finding form with empty buffers and default metric selections.
    fn open_new_form(&mut self) {
        self.form = Some(FormState::new());
    }

    /// Opens the edit form pre-filled with the currently selected finding.
    /// Sets a status message when no finding is selected.
    fn open_edit_form(&mut self) {
        if let Some(finding) = self.selected_finding() {
            self.form = Some(FormState::from_finding(finding));
        } else {
            self.set_status_message("No finding selected — use j/k to navigate.", 5);
        }
    }

    /// Closes the modal form without saving.
    fn close_form(&mut self) {
        self.form = None;
    }

    /// Opens the delete confirmation overlay for the currently selected finding.
    /// Sets a status message when no finding is selected.
    fn open_confirm_delete(&mut self) {
        if let Some(finding) = self.selected_finding() {
            let safe_title = strip_ansi(&finding.title);
            self.confirm_delete = Some(ConfirmDeleteState {
                finding_index: self.selected,
                safe_title,
            });
        } else {
            self.set_status_message("No finding selected — use j/k to navigate.", 5);
        }
    }

    /// Closes the delete confirmation overlay without deleting.
    fn close_confirm_delete(&mut self) {
        self.confirm_delete = None;
    }

    /// Executes the deletion confirmed by the overlay: removes the finding,
    /// clamps `selected`, refreshes `updated_at`, and persists the session.
    fn execute_confirmed_delete(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let idx = match &self.confirm_delete {
            Some(c) => c.finding_index,
            None => return Ok(()),
        };
        if idx < self.session.findings.len() {
            self.session.findings.remove(idx);
            let count = self.session.findings.len();
            if count == 0 {
                self.selected = 0;
            } else if self.selected >= count {
                self.selected = count - 1;
            }
            self.session.updated_at = chrono::Utc::now();
            save_session(&self.session)?;
        }
        self.confirm_delete = None;
        Ok(())
    }

    /// Attempts to save the current form. On validation failure, sets the
    /// error message on the form and keeps it open. On success, persists the
    /// session and closes the form.
    fn try_save_form(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let form = match &mut self.form {
            Some(f) => f,
            None => return Ok(()),
        };

        match form.validate() {
            Err(msg) => {
                form.error = Some(msg);
                Ok(())
            }
            Ok(()) => {
                let finding = match form.build_finding() {
                    Ok(f) => f,
                    Err(msg) => {
                        form.error = Some(msg);
                        return Ok(());
                    }
                };
                match &form.mode {
                    FormMode::New => {
                        self.session.findings.push(finding);
                    }
                    FormMode::Edit(id) => {
                        let id = *id;
                        if let Some(existing) =
                            self.session.findings.iter_mut().find(|f| f.id == id)
                        {
                            *existing = finding;
                        }
                    }
                }
                self.session.updated_at = chrono::Utc::now();
                save_session(&self.session)?;
                self.form = None;
                Ok(())
            }
        }
    }
}

// ─── TUI entry point ──────────────────────────────────────────────────────────

/// Launches the TUI for the given session.
///
/// Enables raw mode and the alternate screen, runs the event loop, and
/// restores the terminal on exit — including on error paths.
///
/// Returns `Err` if the terminal is smaller than 100×30 or if any I/O
/// operation fails during the session.
pub fn run_tui(session: Session) -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    let _guard = TerminalGuard;

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let (width, height) = crossterm::terminal::size()?;
    if width < MIN_WIDTH || height < MIN_HEIGHT {
        return Err(
            format!("Terminal too small. Minimum size: {MIN_WIDTH}\u{d7}{MIN_HEIGHT}.").into(),
        );
    }

    let mut state = TuiState::new(session);

    loop {
        terminal.draw(|frame| render(frame, &mut state))?;

        if event::poll(std::time::Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                if state.confirm_delete.is_some() {
                    handle_confirm_delete_key(&mut state, key.code)?;
                } else if state.form.is_some() {
                    handle_form_key(&mut state, key.code, key.modifiers)?;
                } else {
                    match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Char('j') => state.select_next(),
                        KeyCode::Char('k') => state.select_prev(),
                        KeyCode::Char('n') => state.open_new_form(),
                        KeyCode::Char('e') => state.open_edit_form(),
                        KeyCode::Char('d') => state.open_confirm_delete(),
                        KeyCode::Char('r') => {} // stub: report export added in next task
                        _ => {}
                    }
                }
            }
        }
    }

    Ok(())
}

// ─── Key handlers ─────────────────────────────────────────────────────────────

/// Handles a key event while the form modal is open.
fn handle_form_key(
    state: &mut TuiState,
    code: KeyCode,
    modifiers: KeyModifiers,
) -> Result<(), Box<dyn std::error::Error>> {
    let form = match &mut state.form {
        Some(f) => f,
        None => return Ok(()),
    };

    let active = form.active_field;

    match code {
        KeyCode::Esc => {
            state.close_form();
        }
        KeyCode::Tab => {
            form.focus_next();
        }
        KeyCode::BackTab => {
            form.focus_prev();
        }
        KeyCode::Char('s') if modifiers.contains(KeyModifiers::CONTROL) => {
            state.try_save_form()?;
        }
        KeyCode::Right if is_metric_field(active) => {
            form.cycle_active_metric_forward();
        }
        KeyCode::Left if is_metric_field(active) => {
            form.cycle_active_metric_backward();
        }
        KeyCode::Backspace | KeyCode::Delete if is_metric_field(active) => {
            // metric fields do not accept backspace/delete
        }
        KeyCode::Backspace => {
            form.pop_char();
        }
        KeyCode::Char(ch) if is_metric_field(active) => {
            form.select_metric_by_letter(ch);
        }
        KeyCode::Char(ch) => {
            form.push_char(ch);
        }
        _ => {}
    }

    Ok(())
}

/// Handles a key event while the delete confirmation overlay is open.
fn handle_confirm_delete_key(
    state: &mut TuiState,
    code: KeyCode,
) -> Result<(), Box<dyn std::error::Error>> {
    match code {
        KeyCode::Char('y') => state.execute_confirmed_delete()?,
        KeyCode::Char('n') | KeyCode::Esc => state.close_confirm_delete(),
        _ => {}
    }
    Ok(())
}

// ─── Rendering ────────────────────────────────────────────────────────────────

/// Renders the full TUI frame: findings list, detail pane, status bar, and
/// the form modal overlay when active.
fn render(frame: &mut ratatui::Frame, state: &mut TuiState) {
    state.tick_status_message();

    let area = frame.area();

    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(area);

    let content_area = vertical[0];
    let status_area = vertical[1];

    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(content_area);

    let list_area = horizontal[0];
    let detail_area = horizontal[1];

    render_findings_list(frame, state, list_area);
    render_detail(frame, state, detail_area);
    render_status_bar(frame, state, status_area);

    if let Some(form) = &state.form {
        render_form_modal(frame, form, area);
    }

    if let Some(confirm) = &state.confirm_delete {
        render_confirm_delete_overlay(frame, confirm, area);
    }
}

/// Renders the left pane with the findings list.
fn render_findings_list(frame: &mut ratatui::Frame, state: &TuiState, area: ratatui::layout::Rect) {
    let block = Block::default().title("Findings").borders(Borders::ALL);

    if state.session.findings.is_empty() {
        let placeholder = Paragraph::new("No findings yet. Press 'n' to add one.").block(block);
        frame.render_widget(placeholder, area);
        return;
    }

    let items: Vec<ListItem> = state
        .session
        .findings
        .iter()
        .map(|f| {
            let severity_label = severity_label(&f.severity);
            let safe_title = strip_ansi(&f.title);
            let line = format!("[{}] {} ({:.1})", severity_label, safe_title, f.cvss_score);
            ListItem::new(line)
        })
        .collect();

    let mut list_state = ListState::default();
    list_state.select(Some(state.selected));

    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    frame.render_stateful_widget(list, area, &mut list_state);
}

/// Renders the right pane with the full details of the selected finding.
fn render_detail(frame: &mut ratatui::Frame, state: &TuiState, area: ratatui::layout::Rect) {
    let block = Block::default().title("Detail").borders(Borders::ALL);

    match state.selected_finding() {
        None => {
            let placeholder = Paragraph::new("Select a finding to view details.").block(block);
            frame.render_widget(placeholder, area);
        }
        Some(finding) => {
            let refs = if finding.references.is_empty() {
                "None".to_string()
            } else {
                finding
                    .references
                    .iter()
                    .map(|r| strip_ansi(r))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let score_str = format!("{:.1}", finding.cvss_score);
            let severity_str = severity_label(&finding.severity);

            let safe_title = strip_ansi(&finding.title);
            let safe_vector = strip_ansi(&finding.cvss_vector);
            let safe_affected = strip_ansi(&finding.affected);
            let safe_description = strip_ansi(&finding.description);
            let safe_evidence = strip_ansi(&finding.evidence);
            let safe_remediation = strip_ansi(&finding.remediation);

            let lines: Vec<Line> = vec![
                detail_line("Title", &safe_title),
                detail_line("CVSS Vector", &safe_vector),
                detail_line("Score", &score_str),
                detail_line("Severity", &severity_str),
                detail_line("Affected", &safe_affected),
                Line::raw(""),
                detail_line("Description", &safe_description),
                Line::raw(""),
                detail_line("Evidence", &safe_evidence),
                Line::raw(""),
                detail_line("Remediation", &safe_remediation),
                Line::raw(""),
                detail_line("References", &refs),
            ];

            let paragraph = Paragraph::new(Text::from(lines))
                .block(block)
                .wrap(ratatui::widgets::Wrap { trim: false });
            frame.render_widget(paragraph, area);
        }
    }
}

/// Renders the single-line status bar at the bottom of the screen.
/// Shows a transient status message when one is active, otherwise shows the hint line.
fn render_status_bar(frame: &mut ratatui::Frame, state: &TuiState, area: ratatui::layout::Rect) {
    let text = match &state.status_message {
        Some(msg) => Span::styled(msg.as_str(), Style::default().fg(Color::Yellow)),
        None => Span::raw("j/k: navigate | n: new | e: edit | d: delete | r: report | q: quit"),
    };
    let bar = Paragraph::new(text).style(Style::default().bg(Color::DarkGray).fg(Color::White));
    frame.render_widget(bar, area);
}

/// Renders the form modal as a centered overlay.
fn render_form_modal(frame: &mut ratatui::Frame, form: &FormState, area: Rect) {
    let modal_area = centered_rect(80, 90, area);

    frame.render_widget(Clear, modal_area);

    let title = match &form.mode {
        FormMode::New => "New Finding",
        FormMode::Edit(_) => "Edit Finding",
    };

    let outer_block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .style(Style::default().bg(Color::Black).fg(Color::White));

    frame.render_widget(outer_block, modal_area);

    let inner = Rect {
        x: modal_area.x + 1,
        y: modal_area.y + 1,
        width: modal_area.width.saturating_sub(2),
        height: modal_area.height.saturating_sub(2),
    };

    let mut constraints: Vec<Constraint> = Vec::new();
    for _ in 0..FIELD_COUNT {
        constraints.push(Constraint::Length(3));
    }
    // error line + hint line
    constraints.push(Constraint::Length(1));
    constraints.push(Constraint::Length(1));

    let field_areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    // Compute live CVSS feedback once for the metric block
    let cvss_feedback = form.cvss_live_feedback();

    for idx in 0..FIELD_COUNT {
        let is_active = idx == form.active_field;

        let border_style = if is_active {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let label = FIELD_LABELS[idx];

        if let Some(slot) = metric_slot(idx) {
            // Render metric field: `[CURRENT]   opt1 · opt2 · opt3`
            let descriptor = &CVSS_METRICS[slot];
            let current = form.metric_fields[slot].current_value(slot);
            let options_hint = descriptor.options.join(" · ");

            // Build content with current value highlighted
            let content = format!("[{current}]   {options_hint}");

            // Show CVSS score on the last metric field (A)
            let full_label = if slot == 7 {
                match &cvss_feedback {
                    Some(fb) => format!("{label}   {fb}"),
                    None => label.to_string(),
                }
            } else {
                label.to_string()
            };

            let field_block = Block::default()
                .title(full_label)
                .borders(Borders::ALL)
                .border_style(border_style);

            let text_style = if is_active {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let field_widget = Paragraph::new(Span::styled(content, text_style)).block(field_block);
            frame.render_widget(field_widget, field_areas[idx]);
        } else {
            // Render text field
            let buf_idx = text_buffer_index(idx)
                .expect("non-metric field must have a buffer index");
            let content = strip_ansi(&form.buffers[buf_idx]);

            let field_block = Block::default()
                .title(label)
                .borders(Borders::ALL)
                .border_style(border_style);

            let field_widget = Paragraph::new(content).block(field_block);
            frame.render_widget(field_widget, field_areas[idx]);
        }
    }

    // Error line
    if let Some(ref err) = form.error {
        let error_widget = Paragraph::new(Span::styled(
            strip_ansi(err),
            Style::default().fg(Color::Red),
        ));
        frame.render_widget(error_widget, field_areas[FIELD_COUNT]);
    }

    // Hint line
    let hint = Paragraph::new(Span::styled(
        "Tab/Shift+Tab: move | ←/→: cycle metric | letter: select metric | Ctrl+S: save | Esc: cancel",
        Style::default().fg(Color::DarkGray),
    ))
    .alignment(Alignment::Center);
    frame.render_widget(hint, field_areas[FIELD_COUNT + 1]);
}

/// Renders the delete confirmation overlay as a small centered modal.
fn render_confirm_delete_overlay(
    frame: &mut ratatui::Frame,
    confirm: &ConfirmDeleteState,
    area: Rect,
) {
    let modal_area = centered_rect(50, 20, area);

    frame.render_widget(Clear, modal_area);

    let block = Block::default()
        .title("Confirm Delete")
        .borders(Borders::ALL)
        .style(Style::default().bg(Color::Black).fg(Color::White));

    let prompt = format!("Delete '{}'? (y/n)", confirm.safe_title);
    let paragraph = Paragraph::new(Span::styled(prompt, Style::default().fg(Color::Yellow)))
        .block(block)
        .alignment(Alignment::Center);

    frame.render_widget(paragraph, modal_area);
}

// ─── Layout helpers ───────────────────────────────────────────────────────────

/// Computes a centered rectangle within `area` using percentage dimensions.
fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

// ─── Display helpers ──────────────────────────────────────────────────────────

/// Returns a short uppercase label string for a given severity.
fn severity_label(severity: &Severity) -> String {
    match severity {
        Severity::Critical => "CRITICAL".to_string(),
        Severity::High => "HIGH".to_string(),
        Severity::Medium => "MEDIUM".to_string(),
        Severity::Low => "LOW".to_string(),
        Severity::Informational => "INFO".to_string(),
    }
}

/// Builds a labelled detail line in `"Label: value"` format.
fn detail_line<'a>(label: &'a str, value: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            format!("{label}: "),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(value),
    ])
}

/// Removes ANSI/VT escape sequences from `s`.
///
/// Handles:
/// - CSI sequences: `ESC [` + parameter bytes (0x30–0x3F) + intermediate bytes (0x20–0x2F)
///   + final byte (0x40–0x7E).
/// - Simple two-byte sequences: `ESC` + any byte in range 0x40–0x5F (e.g. `ESC M`).
/// - All other characters are left unchanged.
fn strip_ansi(s: &str) -> String {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0;
    while i < len {
        if bytes[i] == b'\x1b' && i + 1 < len {
            let next = bytes[i + 1];
            if next == b'[' {
                // CSI sequence: skip ESC [, then parameter, intermediate, and final bytes
                i += 2;
                while i < len && (0x30..=0x3f).contains(&bytes[i]) {
                    i += 1;
                }
                while i < len && (0x20..=0x2f).contains(&bytes[i]) {
                    i += 1;
                }
                if i < len && (0x40..=0x7e).contains(&bytes[i]) {
                    i += 1;
                }
            } else if (0x40..=0x5f).contains(&next) {
                // Simple two-byte escape sequence
                i += 2;
            } else {
                out.push(bytes[i] as char);
                i += 1;
            }
        } else {
            // SAFETY: only ascii-range control byte handling above; push char by char
            // to stay correct for multibyte UTF-8 sequences
            let ch = s[i..].chars().next().unwrap_or('\0');
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Session;
    use chrono::Utc;

    // --- strip_ansi (existing tests preserved) ---

    #[test]
    fn strip_ansi_leaves_plain_text_unchanged() {
        assert_eq!(strip_ansi("hello world"), "hello world");
    }

    #[test]
    fn strip_ansi_removes_csi_color_sequence() {
        assert_eq!(strip_ansi("\x1b[31mred\x1b[0m"), "red");
    }

    #[test]
    fn strip_ansi_removes_csi_with_multiple_params() {
        assert_eq!(strip_ansi("\x1b[1;32mbold green\x1b[0m"), "bold green");
    }

    #[test]
    fn strip_ansi_removes_simple_two_byte_sequence() {
        // ESC M (reverse index) is a 0x4D byte — within 0x40..=0x5F
        assert_eq!(strip_ansi("\x1bMtext"), "text");
    }

    #[test]
    fn strip_ansi_preserves_lone_escape_not_followed_by_valid_byte() {
        // ESC followed by a byte outside both ranges — keep the ESC
        assert_eq!(strip_ansi("\x1b\x01plain"), "\x1b\x01plain");
    }

    #[test]
    fn strip_ansi_preserves_unicode_outside_sequences() {
        assert_eq!(strip_ansi("caf\u{e9}"), "caf\u{e9}");
    }

    #[test]
    fn strip_ansi_removes_embedded_injection_attempt() {
        let injection = "legit\x1b[2J\x1b[Hexploited";
        assert_eq!(strip_ansi(injection), "legitexploited");
    }

    // --- FormState::validate (updated for metric-based form) ---

    fn filled_form() -> FormState {
        let mut form = FormState::new();
        // Text buffers: 0=Title, 1=Affected, 2=Description, 3=Evidence, 4=Remediation, 5=References
        form.buffers[0] = "SQL Injection".to_string();
        form.buffers[1] = "api.example.com".to_string();
        form.buffers[2] = "Unsanitised user input passed to SQL query.".to_string();
        form.buffers[3] = "Payload: ' OR 1=1--".to_string();
        form.buffers[4] = "Use parameterised queries.".to_string();
        // Metric fields are at their defaults (valid)
        form
    }

    #[test]
    fn validate_returns_ok_on_fully_valid_form() {
        let form = filled_form();
        assert!(form.validate().is_ok());
    }

    #[test]
    fn validate_returns_error_when_title_empty() {
        let mut form = filled_form();
        form.buffers[0] = String::new();
        let result = form.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Title"));
    }

    #[test]
    fn validate_returns_error_when_affected_empty() {
        let mut form = filled_form();
        form.buffers[1] = String::new();
        let result = form.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Affected"));
    }

    #[test]
    fn validate_returns_error_when_description_empty() {
        let mut form = filled_form();
        form.buffers[2] = String::new();
        let result = form.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Description"));
    }

    #[test]
    fn validate_returns_error_when_evidence_empty() {
        let mut form = filled_form();
        form.buffers[3] = String::new();
        let result = form.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Evidence"));
    }

    #[test]
    fn validate_returns_error_when_remediation_empty() {
        let mut form = filled_form();
        form.buffers[4] = String::new();
        let result = form.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Remediation"));
    }

    #[test]
    fn validate_allows_empty_references_field() {
        let mut form = filled_form();
        form.buffers[5] = String::new();
        assert!(form.validate().is_ok());
    }

    // --- CVSS live feedback (always Some now — metric fields always have a value) ---

    #[test]
    fn cvss_live_feedback_returns_some_for_default_metrics() {
        let form = FormState::new();
        let feedback = form.cvss_live_feedback();
        assert!(
            feedback.is_some(),
            "feedback must be Some — metrics always have a selection"
        );
    }

    #[test]
    fn cvss_live_feedback_shows_score_and_severity_for_critical_vector() {
        let mut form = FormState::new();
        // AV:N AC:L PR:N UI:N S:U C:H I:H A:H → 9.8 Critical
        // AV slot=0: N(default), AC slot=1: L(default), PR slot=2: N(default),
        // UI slot=3: N(default), S slot=4: U(default),
        // C slot=5: H(index 2), I slot=6: H(index 2), A slot=7: H(index 2)
        form.metric_fields[5].selected = 2; // C=H
        form.metric_fields[6].selected = 2; // I=H
        form.metric_fields[7].selected = 2; // A=H
        let feedback = form
            .cvss_live_feedback()
            .expect("feedback must be Some");
        assert!(
            feedback.contains("9.8"),
            "expected score 9.8 in: {feedback}"
        );
        assert!(
            feedback.contains("CRITICAL"),
            "expected CRITICAL in: {feedback}"
        );
    }

    // --- Metric field cycling ---

    #[test]
    fn cycle_metric_field_forward_wraps() {
        let mut field = MetricField { selected: 3 }; // last option for AV (P)
        field.cycle_forward(0); // AV has 4 options: N A L P
        assert_eq!(field.selected, 0, "cycling past last option must wrap to first");
    }

    #[test]
    fn cycle_metric_field_backward_wraps() {
        let mut field = MetricField { selected: 0 }; // first option
        field.cycle_backward(0); // AV has 4 options
        assert_eq!(
            field.selected,
            3,
            "cycling before first option must wrap to last"
        );
    }

    #[test]
    fn letter_press_selects_matching_metric_value() {
        let mut field = MetricField { selected: 0 }; // AC slot=1, starts at L(0)
        field.select_by_letter(1, 'H');
        assert_eq!(
            field.selected, 1,
            "pressing H on AC field must select H (index 1)"
        );
    }

    #[test]
    fn invalid_letter_ignored_for_metric_field() {
        let mut field = MetricField { selected: 0 }; // AV slot=0, starts at N(0)
        let before = field.selected;
        field.select_by_letter(0, 'Z');
        assert_eq!(
            field.selected, before,
            "pressing Z on AV field must leave selection unchanged"
        );
    }

    // --- Vector assembly ---

    #[test]
    fn assemble_cvss_vector_from_metric_selections() {
        let mut form = FormState::new();
        // Set to AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (default for most, H for C/I/A)
        form.metric_fields[5].selected = 2; // C=H
        form.metric_fields[6].selected = 2; // I=H
        form.metric_fields[7].selected = 2; // A=H
        let vector = form.assembled_cvss_vector();
        assert_eq!(
            vector,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        );
    }

    // --- Edit pre-fill from existing vector ---

    #[test]
    fn edit_prefill_parses_existing_vector_into_metric_fields() {
        let finding = Finding {
            id: Uuid::new_v4(),
            title: "Test".to_string(),
            cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string(),
            cvss_score: 7.5,
            severity: Severity::High,
            affected: "host".to_string(),
            description: "desc".to_string(),
            evidence: "evidence".to_string(),
            remediation: "fix".to_string(),
            references: vec![],
        };

        let form = FormState::from_finding(&finding);

        // AV=N → slot 0, option index 0
        assert_eq!(form.metric_fields[0].current_value(0), "N", "AV must be N");
        // AC=L → slot 1, option index 0
        assert_eq!(form.metric_fields[1].current_value(1), "L", "AC must be L");
        // PR=N → slot 2, option index 0
        assert_eq!(form.metric_fields[2].current_value(2), "N", "PR must be N");
        // UI=N → slot 3, option index 0
        assert_eq!(form.metric_fields[3].current_value(3), "N", "UI must be N");
        // S=U → slot 4, option index 0
        assert_eq!(form.metric_fields[4].current_value(4), "U", "S must be U");
        // C=H → slot 5, option index 2
        assert_eq!(form.metric_fields[5].current_value(5), "H", "C must be H");
        // I=N → slot 6, option index 0
        assert_eq!(form.metric_fields[6].current_value(6), "N", "I must be N");
        // A=N → slot 7, option index 0
        assert_eq!(form.metric_fields[7].current_value(7), "N", "A must be N");
    }

    #[test]
    fn edit_prefill_falls_back_to_defaults_for_invalid_metric_value() {
        let finding = Finding {
            id: Uuid::new_v4(),
            title: "Test".to_string(),
            // AV:X is not a valid value for AV — should fall back to default (N, index 0)
            cvss_vector: "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N".to_string(),
            cvss_score: 0.0,
            severity: Severity::Informational,
            affected: "host".to_string(),
            description: "desc".to_string(),
            evidence: "evidence".to_string(),
            remediation: "fix".to_string(),
            references: vec![],
        };

        let form = FormState::from_finding(&finding);

        // AV should remain at default (N, index 0) because X is invalid
        assert_eq!(
            form.metric_fields[0].selected,
            CVSS_METRICS[0].default_index,
            "invalid AV value must leave field at default"
        );
    }

    // --- build_finding produces correct vector from metric selections ---

    #[test]
    fn build_finding_uses_assembled_cvss_vector() {
        let mut form = filled_form();
        // Configure metrics to produce AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical
        form.metric_fields[5].selected = 2; // C=H
        form.metric_fields[6].selected = 2; // I=H
        form.metric_fields[7].selected = 2; // A=H

        let finding = form.build_finding().expect("build_finding must succeed");
        assert_eq!(
            finding.cvss_vector,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        );
        assert_eq!(finding.cvss_score, 9.8);
        assert_eq!(finding.severity, Severity::Critical);
    }

    // --- validate: metric fields always valid ---

    #[test]
    fn validate_metric_fields_always_valid() {
        let mut form = filled_form();
        // Metric fields are at defaults — validate must pass without any CVSS-related error
        // (there is no longer a CVSS text field to be empty or malformed)
        assert!(
            form.validate().is_ok(),
            "form with default metric fields must pass validate()"
        );

        // Even with non-default metric values the form is still valid
        form.metric_fields[0].selected = 2; // AV=L
        form.metric_fields[5].selected = 2; // C=H
        assert!(
            form.validate().is_ok(),
            "form with non-default metric fields must still pass validate()"
        );
    }

    // --- round-trip new finding ---

    #[test]
    fn new_finding_round_trip_computes_correct_score_and_severity() {
        let mut form = filled_form();
        // AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical
        form.metric_fields[5].selected = 2; // C=H
        form.metric_fields[6].selected = 2; // I=H
        form.metric_fields[7].selected = 2; // A=H

        form.validate().expect("form must be valid before building");
        let finding = form
            .build_finding()
            .expect("build_finding must succeed after validate");

        assert_eq!(finding.title, "SQL Injection");
        assert_eq!(finding.cvss_score, 9.8);
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.affected, "api.example.com");
    }

    #[test]
    fn new_finding_gets_unique_uuid_each_time() {
        let form1 = filled_form();
        let form2 = filled_form();
        let f1 = form1.build_finding().expect("build_finding must succeed");
        let f2 = form2.build_finding().expect("build_finding must succeed");
        assert_ne!(f1.id, f2.id, "each new finding must get a unique UUID");
    }

    #[test]
    fn new_finding_references_empty_when_buffer_empty() {
        let form = filled_form();
        let finding = form.build_finding().expect("build_finding must succeed");
        assert!(finding.references.is_empty());
    }

    #[test]
    fn new_finding_references_parsed_from_comma_separated_buffer() {
        let mut form = filled_form();
        form.buffers[5] = "CVE-2021-1234, https://example.com".to_string();
        let finding = form.build_finding().expect("build_finding must succeed");
        assert_eq!(
            finding.references,
            vec!["CVE-2021-1234", "https://example.com"]
        );
    }

    // --- edit finding round-trip ---

    fn sample_finding() -> Finding {
        Finding {
            id: Uuid::new_v4(),
            title: "Original Title".to_string(),
            cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
            cvss_score: 9.8,
            severity: Severity::Critical,
            affected: "host.example.com".to_string(),
            description: "Original description.".to_string(),
            evidence: "Original evidence.".to_string(),
            remediation: "Original remediation.".to_string(),
            references: vec![],
        }
    }

    fn session_with_finding(finding: Finding) -> Session {
        Session {
            name: "test-session".to_string(),
            scope: vec![],
            findings: vec![finding],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn edit_form_prefills_text_fields_from_finding() {
        let finding = sample_finding();
        let form = FormState::from_finding(&finding);

        assert_eq!(form.buffers[0], finding.title);
        assert_eq!(form.buffers[1], finding.affected);
        assert_eq!(form.buffers[2], finding.description);
        assert_eq!(form.buffers[3], finding.evidence);
        assert_eq!(form.buffers[4], finding.remediation);
    }

    #[test]
    fn edit_finding_preserves_id() {
        let finding = sample_finding();
        let original_id = finding.id;
        let mut form = FormState::from_finding(&finding);
        form.buffers[0] = "Updated Title".to_string();
        let updated = form.build_finding().expect("build_finding must succeed");
        assert_eq!(updated.id, original_id);
    }

    #[test]
    fn edit_finding_updates_in_session_by_id() {
        let finding = sample_finding();
        let session = session_with_finding(finding.clone());
        let mut state = TuiState::new(session);

        // Open edit form and change the title
        state.open_edit_form();
        let form = state.form.as_mut().expect("form must be open");
        form.buffers[0] = "Updated Title".to_string();

        // Validate first, then build and update manually (save_session needs real disk)
        let updated_finding = state
            .form
            .as_ref()
            .expect("form must still be open")
            .build_finding()
            .expect("build_finding must succeed");

        let id = finding.id;
        if let Some(existing) = state.session.findings.iter_mut().find(|f| f.id == id) {
            *existing = updated_finding;
        }

        assert_eq!(state.session.findings[0].title, "Updated Title");
        assert_eq!(state.session.findings[0].id, finding.id);
    }

    #[test]
    fn edit_finding_recomputes_cvss_score_and_severity() {
        let mut finding = sample_finding();
        // Start with a medium vector (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5)
        finding.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N".to_string();
        finding.cvss_score = 6.5;
        finding.severity = Severity::Medium;

        let mut form = FormState::from_finding(&finding);
        // PR=L is slot 2, index 1
        assert_eq!(form.metric_fields[2].current_value(2), "L", "PR must be L after parse");

        // Change PR back to N (index 0) and set C=H, I=H, A=H to get 9.8
        form.metric_fields[2].selected = 0; // PR=N
        form.metric_fields[5].selected = 2; // C=H
        form.metric_fields[6].selected = 2; // I=H
        form.metric_fields[7].selected = 2; // A=H

        let updated = form.build_finding().expect("build_finding must succeed");
        assert_eq!(updated.cvss_score, 9.8);
        assert_eq!(updated.severity, Severity::Critical);
    }

    // --- Navigation ---

    #[test]
    fn focus_next_wraps_from_last_field_to_first() {
        let mut form = FormState::new();
        form.active_field = FIELD_REFERENCES;
        form.focus_next();
        assert_eq!(form.active_field, FIELD_TITLE);
    }

    #[test]
    fn focus_prev_wraps_from_first_field_to_last() {
        let mut form = FormState::new();
        form.active_field = FIELD_TITLE;
        form.focus_prev();
        assert_eq!(form.active_field, FIELD_REFERENCES);
    }

    #[test]
    fn esc_closes_form_without_saving() {
        let session = Session {
            name: "test-session".to_string(),
            scope: vec![],
            findings: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let mut state = TuiState::new(session);
        state.open_new_form();
        assert!(state.form.is_some());
        state.close_form();
        assert!(state.form.is_none());
        assert_eq!(state.session.findings.len(), 0);
    }

    #[test]
    fn push_char_appends_to_text_field_and_ignores_metric_field() {
        let mut form = FormState::new();
        // Active on Title (text field)
        form.active_field = FIELD_TITLE;
        form.push_char('h');
        assert_eq!(form.buffers[0], "h");
        form.push_char('i');
        assert_eq!(form.buffers[0], "hi");

        // Switch to a metric field — push_char must be a no-op
        form.active_field = FIELD_AV;
        let av_before = form.metric_fields[0].selected;
        form.push_char('N');
        // Buffer unchanged, metric unchanged (push_char ignores metric fields)
        assert_eq!(form.buffers[0], "hi", "title buffer must be unchanged when active is metric");
        assert_eq!(
            form.metric_fields[0].selected, av_before,
            "push_char must not change metric selection"
        );
    }

    #[test]
    fn build_finding_strips_ansi_from_form_buffers() {
        let mut form = filled_form();
        form.buffers[0] = "Evil\x1b[31mTitle\x1b[0m".to_string();
        let finding = form.build_finding().expect("build_finding must succeed");
        assert_eq!(finding.title, "EvilTitle");
    }

    #[test]
    fn ctrl_s_with_empty_required_field_sets_error_and_keeps_form_open() {
        let session = Session {
            name: "test-session".to_string(),
            scope: vec![],
            findings: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let mut state = TuiState::new(session);
        state.open_new_form();
        // All text buffers are empty — validate will fail on Title
        state
            .try_save_form()
            .expect("try_save_form must not return Err");
        assert!(
            state.form.is_some(),
            "form must stay open after validation failure"
        );
        let error = state.form.as_ref().unwrap().error.as_ref();
        assert!(
            error.is_some(),
            "error_message must be set after failed save"
        );
    }

    #[test]
    fn open_new_form_initializes_text_buffers_blank_and_metrics_at_defaults() {
        let session = Session {
            name: "test-session".to_string(),
            scope: vec![],
            findings: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let mut state = TuiState::new(session);
        state.open_new_form();
        let form = state.form.as_ref().expect("form must be open");
        assert_eq!(form.active_field, FIELD_TITLE);
        for (buf_idx, buf) in form.buffers.iter().enumerate() {
            assert!(
                buf.is_empty(),
                "buffer[{buf_idx}] must be empty on new form, got: {buf:?}"
            );
        }
        for (slot, mf) in form.metric_fields.iter().enumerate() {
            assert_eq!(
                mf.selected,
                CVSS_METRICS[slot].default_index,
                "metric_fields[{slot}] must be at default on new form"
            );
        }
    }

    // --- delete confirmation ---

    fn empty_session() -> Session {
        Session {
            name: "test-session".to_string(),
            scope: vec![],
            findings: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn session_with_two_findings() -> Session {
        let mut s = empty_session();
        s.findings.push(sample_finding());
        let mut second = sample_finding();
        second.title = "Second Finding".to_string();
        s.findings.push(second);
        s
    }

    #[test]
    fn d_key_with_no_findings_sets_status_message() {
        let mut state = TuiState::new(empty_session());
        state.open_confirm_delete();
        assert!(
            state.confirm_delete.is_none(),
            "confirm_delete must not open when no findings"
        );
        assert!(
            state.status_message.is_some(),
            "status_message must be set when no findings"
        );
        let msg = state.status_message.as_ref().unwrap();
        assert!(
            msg.contains("No finding selected"),
            "expected 'No finding selected' in: {msg}"
        );
        assert!(
            msg.contains("j/k"),
            "expected 'j/k' in status message: {msg}"
        );
    }

    #[test]
    fn confirm_y_removes_finding_from_session_and_closes_overlay() {
        let finding = sample_finding();
        let mut session = session_with_finding(finding.clone());
        session.name = format!("test-delete-{}", Uuid::new_v4());
        let mut state = TuiState::new(session);

        state.selected = 0;
        state.open_confirm_delete();
        assert!(
            state.confirm_delete.is_some(),
            "confirm_delete must be open before executing delete"
        );

        state
            .execute_confirmed_delete()
            .expect("execute_confirmed_delete must not error");

        assert_eq!(state.session.findings.len(), 0, "finding must be removed");
        assert!(
            state.confirm_delete.is_none(),
            "confirm_delete must be closed after deletion"
        );
        assert_eq!(
            state.selected, 0,
            "selected must be 0 when session is empty after deletion"
        );
    }

    #[test]
    fn confirm_n_preserves_finding_and_closes_overlay() {
        let finding = sample_finding();
        let session = session_with_finding(finding.clone());
        let mut state = TuiState::new(session);

        state.confirm_delete = Some(ConfirmDeleteState {
            finding_index: 0,
            safe_title: finding.title.clone(),
        });

        state.close_confirm_delete();

        assert_eq!(
            state.session.findings.len(),
            1,
            "finding must be preserved after 'n'"
        );
        assert!(
            state.confirm_delete.is_none(),
            "confirm_delete must be closed after 'n'"
        );
    }

    #[test]
    fn confirm_esc_preserves_finding_and_closes_overlay() {
        let finding = sample_finding();
        let session = session_with_finding(finding.clone());
        let mut state = TuiState::new(session);

        state.confirm_delete = Some(ConfirmDeleteState {
            finding_index: 0,
            safe_title: finding.title.clone(),
        });

        state.close_confirm_delete();

        assert_eq!(
            state.session.findings.len(),
            1,
            "finding must be preserved after Esc"
        );
        assert!(
            state.confirm_delete.is_none(),
            "confirm_delete must be closed after Esc"
        );
    }

    #[test]
    fn delete_only_finding_results_in_empty_session_and_selected_zero() {
        let finding = sample_finding();
        let mut session = session_with_finding(finding.clone());
        session.name = format!("test-delete-{}", Uuid::new_v4().simple());
        let mut state = TuiState::new(session);
        state.selected = 0;

        state.open_confirm_delete();
        state
            .execute_confirmed_delete()
            .expect("execute_confirmed_delete must not error");

        assert_eq!(
            state.session.findings.len(),
            0,
            "session must have 0 findings after deleting the only one"
        );
        assert_eq!(
            state.selected, 0,
            "selected must be 0 when session is empty"
        );
    }

    #[test]
    fn delete_last_item_in_multi_item_list_clamps_selected_to_new_len_minus_one() {
        let mut session = session_with_two_findings();
        session.name = format!("test-delete-{}", Uuid::new_v4().simple());
        let mut state = TuiState::new(session);
        // Select the last item (index 1)
        state.selected = 1;

        state.open_confirm_delete();
        state
            .execute_confirmed_delete()
            .expect("execute_confirmed_delete must not error");

        assert_eq!(state.session.findings.len(), 1, "one finding must remain");
        assert_eq!(
            state.selected, 0,
            "selected must be clamped to new len-1 (0)"
        );
    }

    #[test]
    fn open_confirm_delete_stores_strip_ansi_title_in_overlay() {
        let mut finding = sample_finding();
        finding.title = "Evil\x1b[31mTitle\x1b[0m".to_string();
        let session = session_with_finding(finding);
        let mut state = TuiState::new(session);

        state.open_confirm_delete();

        let confirm = state
            .confirm_delete
            .as_ref()
            .expect("confirm_delete must be open");
        assert_eq!(
            confirm.safe_title, "EvilTitle",
            "safe_title must have ANSI codes stripped"
        );
    }
}
