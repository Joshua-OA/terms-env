//! Project picker for `tnv share` when run outside a linked directory.

use std::io;

use super::{Key, TerminalGuard, read_key};
use ratatui::{
    Frame,
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, ListState},
};

pub struct ProjectEntry {
    pub name: String,
    pub key_count: usize,
    pub linked_here: bool,
}

fn draw(frame: &mut Frame, entries: &[ProjectEntry], cursor: usize, list_state: &mut ListState) {
    let items: Vec<ListItem> = entries
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let sel = if i == cursor { ">" } else { " " };
            let here = if p.linked_here { "  ← linked" } else { "" };
            ListItem::new(format!("{sel} {} ({} keys){here}", p.name, p.key_count))
        })
        .collect();
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Choose a project to share"),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_stateful_widget(list, frame.area(), list_state);
}

/// `Ok(None)` means the user aborted.
pub fn run_picker(entries: Vec<ProjectEntry>) -> io::Result<Option<String>> {
    if entries.is_empty() {
        return Ok(None);
    }
    let _guard = TerminalGuard::new()?;
    let backend = ratatui::backend::CrosstermBackend::new(io::stdout());
    let mut terminal = ratatui::Terminal::new(backend)?;

    let mut cursor = 0usize;
    let mut list_state = ListState::default();

    loop {
        terminal.draw(|f| draw(f, &entries, cursor, &mut list_state))?;
        match read_key()? {
            Key::Up => cursor = cursor.saturating_sub(1),
            Key::Down => cursor = (cursor + 1).min(entries.len() - 1),
            Key::Confirm => return Ok(Some(entries[cursor].name.clone())),
            Key::Abort | Key::Toggle => return Ok(None),
            Key::SelectAll | Key::SelectNone | Key::Other => {}
        }
        list_state.select(Some(cursor));
    }
}
