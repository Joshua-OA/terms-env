use tenv_cli::ui::review::ReviewState;
use tenv_core::envparser::Change;

fn sample_changes() -> Vec<Change> {
    vec![
        Change::Added {
            key: "NEW_KEY".into(),
            new: "value-new-long".into(),
        },
        Change::Updated {
            key: "DB_URL".into(),
            old: "postgres://old".into(),
            new: "postgres://new".into(),
        },
        Change::Removed {
            key: "OLD_KEY".into(),
            old: "gone-value-long".into(),
        },
    ]
}

#[test]
fn starts_all_checked_with_cursor_at_top() {
    let state = ReviewState::new(sample_changes());
    assert_eq!(state.checked, vec![true, true, true]);
    assert_eq!(state.cursor, 0);
}

#[test]
fn toggle_flips_only_cursor_row() {
    let mut state = ReviewState::new(sample_changes());
    state.down();
    state.toggle();
    assert_eq!(state.checked, vec![true, false, true]);

    state.up();
    state.toggle();
    assert_eq!(state.checked, vec![false, false, true]);
}

#[test]
fn cursor_never_leaves_bounds() {
    let mut state = ReviewState::new(sample_changes());
    for _ in 0..10 {
        state.down();
    }
    assert_eq!(state.cursor, 2);
    for _ in 0..10 {
        state.up();
    }
    assert_eq!(state.cursor, 0);
}

#[test]
fn select_all_and_none() {
    let mut state = ReviewState::new(sample_changes());
    state.none();
    assert!(state.checked.iter().all(|c| !c));
    state.all();
    assert!(state.checked.iter().all(|c| *c));
}

#[test]
fn selected_respects_checks_and_order() {
    let mut state = ReviewState::new(sample_changes());
    // Uncheck the middle row: only rows 0 and 2 remain.
    state.down();
    state.toggle();

    let picked = state.selected();
    assert_eq!(picked.len(), 2);
    match (&picked[0], &picked[2 - 1]) {
        (Change::Added { key, .. }, Change::Removed { key: k2, .. }) => {
            assert_eq!(key, "NEW_KEY");
            assert_eq!(k2, "OLD_KEY");
        }
        other => panic!("unexpected selection {other:?}"),
    }
}

#[test]
fn empty_review_selects_nothing_without_panicking() {
    let mut state = ReviewState::new(Vec::new());
    state.down(); // must not wrap or panic
    state.up();
    state.toggle();
    assert!(state.selected().is_empty());
}
