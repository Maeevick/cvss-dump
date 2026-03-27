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

/// Index constants for the form fields in their display order.
pub const FIELD_TITLE: usize = 0;
pub const FIELD_CVSS_VECTOR: usize = 1;
pub const FIELD_AFFECTED: usize = 2;
pub const FIELD_DESCRIPTION: usize = 3;
pub const FIELD_EVIDENCE: usize = 4;
pub const FIELD_REMEDIATION: usize = 5;
pub const FIELD_REFERENCES: usize = 6;
pub const FIELD_COUNT: usize = 7;

/// Human-readable labels for each form field, in field-index order.
pub const FIELD_LABELS: [&str; FIELD_COUNT] = [
    "Title",
    "CVSS Vector",
    "Affected",
    "Description",
    "Evidence",
    "Remediation",
    "References (optional)",
];

/// Fields that must be non-empty for the form to be valid.
const REQUIRED_FIELD_INDICES: [usize; 6] = [
    FIELD_TITLE,
    FIELD_CVSS_VECTOR,
    FIELD_AFFECTED,
    FIELD_DESCRIPTION,
    FIELD_EVIDENCE,
    FIELD_REMEDIATION,
];

/// All runtime state for the finding form modal.
#[derive(Debug, Clone)]
pub struct FormState {
    /// Text buffer for each field, indexed by the `FIELD_*` constants.
    pub buffers: [String; FIELD_COUNT],
    /// Index of the currently focused field.
    pub active_field: usize,
    /// Validation or save error to display inline.
    pub error: Option<String>,
    /// Whether this form creates a new finding or edits an existing one.
    pub mode: FormMode,
}

impl FormState {
    /// Creates a blank form for a new finding.
    pub fn new() -> Self {
        Self {
            buffers: Default::default(),
            active_field: FIELD_TITLE,
            error: None,
            mode: FormMode::New,
        }
    }

    /// Creates a pre-filled form for editing the given finding.
    pub fn from_finding(finding: &Finding) -> Self {
        let mut buffers: [String; FIELD_COUNT] = Default::default();
        buffers[FIELD_TITLE] = finding.title.clone();
        buffers[FIELD_CVSS_VECTOR] = finding.cvss_vector.clone();
        buffers[FIELD_AFFECTED] = finding.affected.clone();
        buffers[FIELD_DESCRIPTION] = finding.description.clone();
        buffers[FIELD_EVIDENCE] = finding.evidence.clone();
        buffers[FIELD_REMEDIATION] = finding.remediation.clone();
        buffers[FIELD_REFERENCES] = finding.references.join(", ");

        Self {
            buffers,
            active_field: FIELD_TITLE,
            error: None,
            mode: FormMode::Edit(finding.id),
        }
    }

    /// Moves focus to the next field, wrapping at the end.
    pub fn focus_next(&mut self) {
        self.active_field = (self.active_field + 1) % FIELD_COUNT;
    }

    /// Moves focus to the previous field, wrapping at the start.
    pub fn focus_prev(&mut self) {
        self.active_field = self.active_field.checked_sub(1).unwrap_or(FIELD_COUNT - 1);
    }

    /// Appends `ch` to the active field buffer after stripping ANSI sequences.
    pub fn push_char(&mut self, ch: char) {
        let safe = strip_ansi(&ch.to_string());
        self.buffers[self.active_field].push_str(&safe);
    }

    /// Removes the last character from the active field buffer.
    pub fn pop_char(&mut self) {
        self.buffers[self.active_field].pop();
    }

    /// Validates all form fields.
    ///
    /// Returns `Ok(())` when every required field is non-empty and the CVSS
    /// vector parses to a valid score. Returns `Err(message)` for the first
    /// violation found, giving required-field errors priority over CVSS
    /// format errors.
    pub fn validate(&self) -> Result<(), String> {
        for &idx in &REQUIRED_FIELD_INDICES {
            if self.buffers[idx].trim().is_empty() {
                return Err(format!("⚠ {} is required", FIELD_LABELS[idx]));
            }
        }
        let vector = self.buffers[FIELD_CVSS_VECTOR].trim();
        crate::cvss::base_score(vector)
            .map(|_| ())
            .map_err(|_| "⚠ Invalid CVSS v3.1 vector — cannot save.".to_string())
    }

    /// Returns the computed score and severity label for the current CVSS
    /// vector buffer, or an error string when the buffer is non-empty but
    /// malformed. Returns `None` when the buffer is empty.
    pub fn cvss_live_feedback(&self) -> Option<String> {
        let vector = self.buffers[FIELD_CVSS_VECTOR].trim();
        if vector.is_empty() {
            return None;
        }
        match crate::cvss::base_score(vector) {
            Ok(score) => {
                let severity = Severity::from_score(score);
                let label = severity_label(&severity);
                Some(format!("Score: {score:.1} ({label})"))
            }
            Err(_) => Some("⚠ Invalid CVSS v3.1 vector".to_string()),
        }
    }

    /// Builds a `Finding` from the current form buffers.
    ///
    /// Caller must have already validated the form via `validate()`.
    /// Returns `Err` if the CVSS vector fails to parse — this is a bug if
    /// `validate()` was called first, and the error message makes that explicit.
    pub fn build_finding(&self) -> Result<Finding, String> {
        let vector = strip_ansi(self.buffers[FIELD_CVSS_VECTOR].trim());
        let score = crate::cvss::base_score(&vector)
            .map_err(|_| "build_finding: CVSS parse failed after validate() — this is a bug".to_string())?;
        let severity = Severity::from_score(score);

        let refs_raw = strip_ansi(self.buffers[FIELD_REFERENCES].trim());
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
            title: strip_ansi(self.buffers[FIELD_TITLE].trim()),
            cvss_vector: vector,
            cvss_score: score,
            severity,
            affected: strip_ansi(self.buffers[FIELD_AFFECTED].trim()),
            description: strip_ansi(self.buffers[FIELD_DESCRIPTION].trim()),
            evidence: strip_ansi(self.buffers[FIELD_EVIDENCE].trim()),
            remediation: strip_ansi(self.buffers[FIELD_REMEDIATION].trim()),
            references,
        })
    }
}

/// RAII guard that restores the terminal on drop, even when an error occurs.
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

/// Holds the runtime state of the TUI session.
pub struct TuiState {
    /// The session being viewed and managed.
    pub session: Session,
    /// Index into `session.findings` for the currently highlighted row.
    pub selected: usize,
    /// When `Some`, the modal form is open.
    pub form: Option<FormState>,
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

    /// Opens the new-finding form with empty buffers.
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

                if state.form.is_some() {
                    handle_form_key(&mut state, key.code, key.modifiers)?;
                } else {
                    match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Char('j') => state.select_next(),
                        KeyCode::Char('k') => state.select_prev(),
                        KeyCode::Char('n') => state.open_new_form(),
                        KeyCode::Char('e') => state.open_edit_form(),
                        KeyCode::Char('d') => {} // stub: confirmation added in next task
                        KeyCode::Char('r') => {} // stub: report export added in next task
                        _ => {}
                    }
                }
            }
        }
    }

    Ok(())
}

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
        KeyCode::Backspace => {
            form.pop_char();
        }
        KeyCode::Char('s') if modifiers.contains(KeyModifiers::CONTROL) => {
            state.try_save_form()?;
        }
        KeyCode::Char(ch) => {
            form.push_char(ch);
        }
        _ => {}
    }

    Ok(())
}

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

    for (idx, label) in FIELD_LABELS.iter().enumerate() {
        let is_active = idx == form.active_field;

        let border_style = if is_active {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let mut content = strip_ansi(&form.buffers[idx]);

        // Append live CVSS feedback inline after the vector field
        let cvss_suffix = if idx == FIELD_CVSS_VECTOR {
            form.cvss_live_feedback()
        } else {
            None
        };

        if let Some(ref feedback) = cvss_suffix {
            content = format!("{content}  [{feedback}]");
        }

        let field_block = Block::default()
            .title(*label)
            .borders(Borders::ALL)
            .border_style(border_style);

        let field_widget = Paragraph::new(content).block(field_block);
        frame.render_widget(field_widget, field_areas[idx]);
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
        "Tab/Shift+Tab: move | Ctrl+S: save | Esc: cancel",
        Style::default().fg(Color::DarkGray),
    ))
    .alignment(Alignment::Center);
    frame.render_widget(hint, field_areas[FIELD_COUNT + 1]);
}

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

    // --- FormState::validate ---

    const VALID_VECTOR: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";

    fn filled_form() -> FormState {
        let mut form = FormState::new();
        form.buffers[FIELD_TITLE] = "SQL Injection".to_string();
        form.buffers[FIELD_CVSS_VECTOR] = VALID_VECTOR.to_string();
        form.buffers[FIELD_AFFECTED] = "api.example.com".to_string();
        form.buffers[FIELD_DESCRIPTION] = "Unsanitised user input passed to SQL query.".to_string();
        form.buffers[FIELD_EVIDENCE] = "Payload: ' OR 1=1--".to_string();
        form.buffers[FIELD_REMEDIATION] = "Use parameterised queries.".to_string();
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
        form.buffers[FIELD_TITLE] = String::new();
        let result = form.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Title"));
    }

    #[test]
    fn validate_returns_error_when_cvss_vector_empty() {
        let mut form = filled_form();
        form.buffers[FIELD_CVSS_VECTOR] = String::new();
        let result = form.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("CVSS Vector"));
    }

    #[test]
    fn validate_returns_error_when_affected_empty() {
        let mut form = filled_form();
        form.buffers[FIELD_AFFECTED] = String::new();
        let result = form.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Affected"));
    }

    #[test]
    fn validate_returns_error_when_description_empty() {
        let mut form = filled_form();
        form.buffers[FIELD_DESCRIPTION] = String::new();
        let result = form.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Description"));
    }

    #[test]
    fn validate_returns_error_when_evidence_empty() {
        let mut form = filled_form();
        form.buffers[FIELD_EVIDENCE] = String::new();
        let result = form.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Evidence"));
    }

    #[test]
    fn validate_returns_error_when_remediation_empty() {
        let mut form = filled_form();
        form.buffers[FIELD_REMEDIATION] = String::new();
        let result = form.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Remediation"));
    }

    #[test]
    fn validate_returns_error_on_invalid_cvss_vector() {
        let mut form = filled_form();
        form.buffers[FIELD_CVSS_VECTOR] = "NOT-A-VECTOR".to_string();
        let result = form.validate();
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg.contains("Invalid CVSS"),
            "expected 'Invalid CVSS' in error, got: {msg}"
        );
    }

    #[test]
    fn validate_allows_empty_references_field() {
        let mut form = filled_form();
        form.buffers[FIELD_REFERENCES] = String::new();
        assert!(form.validate().is_ok());
    }

    // --- CVSS live feedback ---

    #[test]
    fn cvss_live_feedback_empty_buffer_returns_none() {
        let mut form = FormState::new();
        form.buffers[FIELD_CVSS_VECTOR] = String::new();
        assert!(form.cvss_live_feedback().is_none());
    }

    #[test]
    fn cvss_live_feedback_valid_vector_shows_score_and_severity() {
        let mut form = FormState::new();
        form.buffers[FIELD_CVSS_VECTOR] = VALID_VECTOR.to_string();
        let feedback = form
            .cvss_live_feedback()
            .expect("feedback must be Some for valid vector");
        assert!(
            feedback.contains("9.8"),
            "expected score 9.8 in: {feedback}"
        );
        assert!(
            feedback.contains("CRITICAL"),
            "expected CRITICAL in: {feedback}"
        );
    }

    #[test]
    fn cvss_live_feedback_invalid_vector_shows_warning() {
        let mut form = FormState::new();
        form.buffers[FIELD_CVSS_VECTOR] = "INVALID".to_string();
        let feedback = form
            .cvss_live_feedback()
            .expect("feedback must be Some for non-empty buffer");
        assert!(
            feedback.contains('⚠'),
            "expected warning symbol in: {feedback}"
        );
    }

    // --- new finding round-trip ---

    #[test]
    fn new_finding_round_trip_computes_correct_score_and_severity() {
        let form = filled_form();
        form.validate().expect("form must be valid before building");
        let finding = form.build_finding().expect("build_finding must succeed after validate");

        assert_eq!(finding.title, "SQL Injection");
        assert_eq!(finding.cvss_score, 9.8);
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.affected, "api.example.com");
    }

    #[test]
    fn new_finding_gets_unique_uuid_each_time() {
        let form1 = filled_form();
        let form2 = filled_form();
        let f1 = form1.build_finding();
        let f2 = form2.build_finding();
        assert_ne!(f1.id, f2.id, "each new finding must get a unique UUID");
    }

    #[test]
    fn new_finding_references_empty_when_buffer_empty() {
        let form = filled_form();
        let finding = form.build_finding();
        assert!(finding.references.is_empty());
    }

    #[test]
    fn new_finding_references_parsed_from_comma_separated_buffer() {
        let mut form = filled_form();
        form.buffers[FIELD_REFERENCES] = "CVE-2021-1234, https://example.com".to_string();
        let finding = form.build_finding();
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
            cvss_vector: VALID_VECTOR.to_string(),
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
    fn edit_form_prefills_all_fields_from_finding() {
        let finding = sample_finding();
        let form = FormState::from_finding(&finding);

        assert_eq!(form.buffers[FIELD_TITLE], finding.title);
        assert_eq!(form.buffers[FIELD_CVSS_VECTOR], finding.cvss_vector);
        assert_eq!(form.buffers[FIELD_AFFECTED], finding.affected);
        assert_eq!(form.buffers[FIELD_DESCRIPTION], finding.description);
        assert_eq!(form.buffers[FIELD_EVIDENCE], finding.evidence);
        assert_eq!(form.buffers[FIELD_REMEDIATION], finding.remediation);
    }

    #[test]
    fn edit_finding_preserves_id() {
        let finding = sample_finding();
        let original_id = finding.id;
        let mut form = FormState::from_finding(&finding);
        form.buffers[FIELD_TITLE] = "Updated Title".to_string();
        let updated = form.build_finding();
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
        form.buffers[FIELD_TITLE] = "Updated Title".to_string();

        // Validate first, then build and update manually (save_session needs real disk)
        let updated_finding = state
            .form
            .as_ref()
            .expect("form must still be open")
            .build_finding();

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
        // Start with a medium vector
        finding.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N".to_string();
        finding.cvss_score = 6.5;
        finding.severity = Severity::Medium;

        let mut form = FormState::from_finding(&finding);
        // Change to a critical vector
        form.buffers[FIELD_CVSS_VECTOR] = VALID_VECTOR.to_string();

        let updated = form.build_finding();
        assert_eq!(updated.cvss_score, 9.8);
        assert_eq!(updated.severity, Severity::Critical);
    }
}
