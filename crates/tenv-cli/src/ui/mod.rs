//! Interactive terminal screens (ratatui). Every screen degrades to the
//! plain prompts in `main.rs` when stdin is not a TTY or `--yes` is set —
//! scripting and CI never require interactivity.

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use std::io::{self, IsTerminal, Stdout};

pub mod picker;
pub mod review;
pub mod trust;

pub fn is_interactive() -> bool {
    std::io::stdin().is_terminal()
}

/// Owns raw-mode + alternate-screen state; restores on drop (including
/// panics via unwinding).
struct TerminalGuard {
    _stdout: Stdout,
}

impl TerminalGuard {
    fn new() -> io::Result<Self> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;
        Ok(Self {
            _stdout: io::stdout(),
        })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

enum Key {
    Up,
    Down,
    Toggle,
    SelectAll,
    SelectNone,
    Confirm,
    Abort,
    Other,
}

fn read_key() -> io::Result<Key> {
    loop {
        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                // Ctrl+C must always work, even mid-transfer review.
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && matches!(key.code, KeyCode::Char('c'))
                {
                    return Ok(Key::Abort);
                }
                return Ok(match key.code {
                    KeyCode::Up | KeyCode::Char('k') => Key::Up,
                    KeyCode::Down | KeyCode::Char('j') => Key::Down,
                    KeyCode::Char(' ') => Key::Toggle,
                    KeyCode::Char('a') => Key::SelectAll,
                    KeyCode::Char('n') => Key::SelectNone,
                    KeyCode::Enter => Key::Confirm,
                    KeyCode::Esc | KeyCode::Char('q') => Key::Abort,
                    _ => Key::Other,
                });
            }
            _ => continue,
        }
    }
}
