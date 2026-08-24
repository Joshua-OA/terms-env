//! Change-review screen: checkbox list of Added/Updated/Removed with
//! j/k navigation, space to toggle, a/n select-all/none, Enter to apply.

use std::io;

use super::{Key, TerminalGuard, read_key};
use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
};
use tenv_core::envparser::Change;

pub struct ReviewState {
    pub changes: Vec<Change>,
    pub checked: Vec<bool>,
    pub cursor: usize,
}

impl ReviewState {
    pub fn new(changes: Vec<Change>) -> Self {
        Self {
            checked: vec![true; changes.len()],
            changes,
            cursor: 0,
        }
    }

    pub fn toggle(&mut self) {
        if let Some(slot) = self.checked.get_mut(self.cursor) {
            *slot = !*slot;
        }
    }

    pub fn up(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn down(&mut self) {
        if self.cursor + 1 < self.changes.len() {
            self.cursor += 1;
        }
    }

    pub fn all(&mut self) {
        self.checked.iter_mut().for_each(|c| *c = true);
    }

    pub fn none(&mut self) {
        self.checked.iter_mut().for_each(|c| *c = false);
    }

    /// The changes still checked, in list order.
    pub fn selected(&self) -> Vec<Change> {
        self.changes
            .iter()
            .zip(&self.checked)
            .filter(|(_, ok)| **ok)
            .map(|(c, _)| c.clone())
            .collect()
    }
}

fn mask(value: &str) -> String {
    if value.len() <= 6 {
        "*".repeat(value.len())
    } else {
        format!("{}{}", &value[..3], "*".repeat(value.len() - 3))
    }
}

fn row_label(change: &Change) -> String {
    match change {
        Change::Added { key, new } => format!("+ {key} = {}", mask(new)),
        Change::Updated { key, old, new } => format!("~ {key}: {} → {}", mask(old), mask(new)),
        Change::Removed { key, .. } => format!("- {key}"),
    }
}

fn row_color(change: &Change) -> Color {
    match change {
        Change::Added { .. } => Color::Green,
        Change::Updated { .. } => Color::Yellow,
        Change::Removed { .. } => Color::Red,
    }
}

fn draw(frame: &mut Frame, state: &ReviewState, list_state: &mut ListState, title: &str) {
    let items: Vec<ListItem> = state
        .changes
        .iter()
        .enumerate()
        .map(|(i, change)| {
            let box_glyph = if state.checked[i] { "[x]" } else { "[ ]" };
            let cursor = if i == state.cursor { ">" } else { " " };
            ListItem::new(format!("{cursor} {box_glyph} {}", row_label(change)))
                .style(Style::default().fg(row_color(change)))
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(ratatui::style::Modifier::BOLD),
        );

    let footer = Paragraph::new("j/k move · space toggle · a all · n none · Enter apply · q abort");

    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(frame.area());
    frame.render_stateful_widget(list, chunks[0], list_state);
    frame.render_widget(
        footer.style(Style::default().fg(Color::DarkGray)),
        chunks[1],
    );
}

/// Returns `Some(selected)` on Enter, `None` on abort.
pub fn run_review(title: &str, changes: Vec<Change>) -> io::Result<Option<Vec<Change>>> {
    if changes.is_empty() {
        return Ok(Some(Vec::new()));
    }
    let _guard = TerminalGuard::new()?;
    let backend = ratatui::backend::CrosstermBackend::new(io::stdout());
    let mut terminal = ratatui::Terminal::new(backend)?;

    let mut state = ReviewState::new(changes);
    let mut list_state = ListState::default();

    loop {
        terminal.draw(|f| draw(f, &state, &mut list_state, title))?;
        match read_key()? {
            Key::Up => state.up(),
            Key::Down => state.down(),
            Key::Toggle => state.toggle(),
            Key::SelectAll => state.all(),
            Key::SelectNone => state.none(),
            Key::Confirm => return Ok(Some(state.selected())),
            Key::Abort => return Ok(None),
            Key::Other => {}
        }
        list_state.select(Some(state.cursor));
    }
}
