//! Trust prompt for first-time senders: always pin / once / reject.

use std::io;

use super::{Key, TerminalGuard, read_key};
use ratatui::{
    Frame,
    layout::Constraint,
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustDecision {
    AlwaysPin,
    Once,
    Reject,
}

const OPTIONS: [&str; 3] = [
    "trust and pin (remember this device)",
    "accept just this share",
    "reject",
];

fn draw(
    frame: &mut Frame,
    fingerprint: &str,
    label: Option<&str>,
    cursor: usize,
    list_state: &mut ListState,
) {
    let who = match label {
        Some(l) => format!("Sender: {l} [{fingerprint}]"),
        None => format!("Unknown sender [{fingerprint}]"),
    };

    let items: Vec<ListItem> = OPTIONS
        .iter()
        .enumerate()
        .map(|(i, opt)| {
            let sel = if i == cursor { ">" } else { " " };
            ListItem::new(format!("{sel} {opt}"))
        })
        .collect();
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Trust decision"),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );

    let areas = ratatui::layout::Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(1)])
        .split(frame.area());
    frame.render_widget(Paragraph::new(who), areas[0]);
    frame.render_stateful_widget(list, areas[1], list_state);
}

/// Returns the decision, or `Err` on terminal failure.
pub fn run_trust(fingerprint: &str, label: Option<&str>) -> io::Result<TrustDecision> {
    let _guard = TerminalGuard::new()?;
    let backend = ratatui::backend::CrosstermBackend::new(io::stdout());
    let mut terminal = ratatui::Terminal::new(backend)?;

    let mut cursor = 0usize;
    let mut list_state = ListState::default();

    loop {
        terminal.draw(|f| draw(f, fingerprint, label, cursor, &mut list_state))?;
        match read_key()? {
            Key::Up => cursor = cursor.saturating_sub(1),
            Key::Down => cursor = (cursor + 1).min(OPTIONS.len() - 1),
            Key::Confirm => {
                return Ok(match cursor {
                    0 => TrustDecision::AlwaysPin,
                    1 => TrustDecision::Once,
                    _ => TrustDecision::Reject,
                });
            }
            Key::Abort | Key::Toggle => return Ok(TrustDecision::Reject),
            Key::SelectAll | Key::SelectNone | Key::Other => {}
        }
        list_state.select(Some(cursor));
    }
}
