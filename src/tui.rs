use std::io;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
};

use crate::domain::{Finding, Session, Severity};

const MIN_WIDTH: u16 = 100;
const MIN_HEIGHT: u16 = 30;

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
}

impl TuiState {
    /// Creates a new `TuiState` for the given session with no finding selected.
    fn new(session: Session) -> Self {
        Self { session, selected: 0 }
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
        return Err(format!(
            "Terminal too small. Minimum size: {MIN_WIDTH}\u{d7}{MIN_HEIGHT}."
        )
        .into());
    }

    let mut state = TuiState::new(session);

    loop {
        terminal.draw(|frame| render(frame, &state))?;

        if event::poll(std::time::Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('j') => state.select_next(),
                    KeyCode::Char('k') => state.select_prev(),
                    KeyCode::Char('n') => {} // stub: modal added in next task
                    KeyCode::Char('e') => {} // stub: edit modal added in next task
                    KeyCode::Char('d') => {} // stub: confirmation added in next task
                    KeyCode::Char('r') => {} // stub: report export added in next task
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

/// Renders the full TUI frame: findings list, detail pane, and status bar.
fn render(frame: &mut ratatui::Frame, state: &TuiState) {
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
    render_status_bar(frame, status_area);
}

/// Renders the left pane with the findings list.
fn render_findings_list(
    frame: &mut ratatui::Frame,
    state: &TuiState,
    area: ratatui::layout::Rect,
) {
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
            let line = format!("[{}] {} ({:.1})", severity_label, f.title, f.cvss_score);
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
                finding.references.join(", ")
            };

            let lines: Vec<Line> = vec![
                detail_line("Title", &finding.title),
                detail_line("CVSS Vector", &finding.cvss_vector),
                detail_line("Score", &format!("{:.1}", finding.cvss_score)),
                detail_line("Severity", &severity_label(&finding.severity)),
                detail_line("Affected", &finding.affected),
                Line::raw(""),
                detail_line("Description", &finding.description),
                Line::raw(""),
                detail_line("Evidence", &finding.evidence),
                Line::raw(""),
                detail_line("Remediation", &finding.remediation),
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
fn render_status_bar(frame: &mut ratatui::Frame, area: ratatui::layout::Rect) {
    let hints = Span::raw("j/k: navigate | n: new | e: edit | d: delete | r: report | q: quit");
    let bar = Paragraph::new(hints).style(Style::default().bg(Color::DarkGray).fg(Color::White));
    frame.render_widget(bar, area);
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
