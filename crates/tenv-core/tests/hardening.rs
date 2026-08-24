//! Hardening suite: the parser must survive arbitrary garbage without
//! panicking, and pathological inputs must be rejected cheaply.
//!
//! These are "fuzz-lite" checks — deterministic pseudo-random generation plus
//! exhaustive truncation. A real `cargo-fuzz` target is a natural follow-up
//! (see docs/PLAN.md §12) but needs nightly tooling; these run everywhere.

use tenv_core::envparser::{self, MAX_LINE_BYTES, ParseErrorKind};

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        // Numerical Recipes constants; determinism is what matters here.
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 16
    }

    fn byte(&mut self) -> u8 {
        (self.next() & 0xFF) as u8
    }
}

fn sample_env() -> Vec<u8> {
    b"# comment\nexport A=1\r\nQUOTED=\"line1\nline2\"\nSINGLE='lit #eral'\nBAD KEY=x\nTRAIL=\"unterminated\nTAIL=v # note\nDUP=1\nDUP=2\n"
        .to_vec()
}

#[test]
fn truncated_inputs_never_panic_only_error() {
    let src = sample_env();
    for cut in 0..src.len() {
        let text = String::from_utf8_lossy(&src[..cut]).into_owned();
        // Any outcome is fine as long as it's a clean Result, not a panic.
        let _ = envparser::parse(&text);
    }
}

#[test]
fn deterministic_garbage_never_panics() {
    for seed in 0..256u64 {
        let mut rng = Lcg(seed | 1);
        let len = 1 + (rng.next() % 4096) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let _ = envparser::parse(&text);
    }
}

#[test]
fn oversized_line_is_rejected_not_allocated() {
    let big = vec![b'x'; MAX_LINE_BYTES + 1];
    let input = format!("KEY={}", String::from_utf8(big).unwrap());
    match envparser::parse(&input) {
        Err(e) => assert_eq!(e.kind, ParseErrorKind::LineTooLong),
        Ok(_) => panic!("oversized line must be rejected"),
    }
}

#[test]
fn just_under_limit_still_parses() {
    let big = vec![b'a'; MAX_LINE_BYTES - 16];
    let input = format!("KEY={}", String::from_utf8(big).unwrap());
    assert!(envparser::parse(&input).is_ok());
}

#[test]
fn deep_multiline_quote_bomb_is_bounded() {
    // Many physical lines inside one double-quoted value: still one logical
    // line under the cap, or a LineTooLong rejection — never unbounded memory.
    let bomb = "A=\"".to_string() + &"x\n".repeat(2_000_000);
    match envparser::parse(&bomb) {
        Err(e) => assert_eq!(e.kind, ParseErrorKind::LineTooLong),
        Ok(_) => panic!("quote bomb must be rejected"),
    }
}
