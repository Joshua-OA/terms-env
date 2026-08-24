use tenv_core::domain::EnvFile;
use tenv_core::envparser::{Change, ParseErrorKind, diff, merge, parse, serialize};

fn parsed(input: &str) -> EnvFile {
    parse(input).expect("fixture should parse")
}

#[test]
fn parses_basic_pairs_and_ignores_comments_blanks() {
    let f = parsed("# header comment\n\nA=1\n\nB=two words # inline note\n");
    assert_eq!(f.get("A"), Some("1"));
    assert_eq!(f.get("B"), Some("two words"));
    assert_eq!(f.len(), 2);
}

#[test]
fn export_prefix_is_optional_and_stripped() {
    let f = parsed("export A=1\nexport\tB=2\nC=3\n");
    for k in ["A", "B", "C"] {
        assert!(f.contains_key(k), "missing {k}");
    }
    assert_eq!(f.get("B"), Some("2"));
}

#[test]
fn single_quotes_are_literal() {
    let f = parsed(r#"LIT='a\nb\t"c" \\ #notcomment'"#);
    assert_eq!(f.get("LIT"), Some(r#"a\nb\t"c" \\ #notcomment"#));
}

#[test]
fn double_quotes_interpret_known_escapes() {
    let f = parsed(r#"D="line1\nline2\ttabbed \"q\" end""#);
    assert_eq!(f.get("D"), Some("line1\nline2\ttabbed \"q\" end"));
}

#[test]
fn double_quotes_keep_unknown_escapes_literally() {
    let f = parsed(r#"X="a\qb""#);
    assert_eq!(f.get("X"), Some(r"a\qb"));
}

#[test]
fn double_quoted_value_spans_lines() {
    let f = parsed("CERT=\"-----BEGIN-----\nabc\ndef\n-----END-----\"\nNEXT=after\n");
    assert_eq!(
        f.get("CERT"),
        Some("-----BEGIN-----\nabc\ndef\n-----END-----")
    );
    assert_eq!(f.get("NEXT"), Some("after"));
}

#[test]
fn hash_without_space_stays_in_unquoted_value() {
    let f = parsed("COLOR=blue#green\n");
    assert_eq!(f.get("COLOR"), Some("blue#green"));
}

#[test]
fn duplicate_keys_last_wins_keeping_position() {
    let mut f = parse("A=first\nB=keep\nA=second\n").unwrap();
    assert_eq!(f.get("A"), Some("second"));
    let keys: Vec<_> = f.keys().collect();
    assert_eq!(keys, vec!["A", "B"]);
    f.set("NEW", "x");
    let keys: Vec<_> = f.keys().collect();
    assert_eq!(keys, vec!["A", "B", "NEW"]);
}

#[test]
fn crlf_and_bom_are_tolerated() {
    let f = parsed("\u{feff}A=1\r\nB=2\r\n");
    assert_eq!(f.get("A"), Some("1"));
    assert_eq!(f.get("B"), Some("2"));
}

#[test]
fn errors_carry_line_numbers() {
    let e = parse("GOOD=1\noops\n").unwrap_err();
    assert_eq!(e.line, 2);
    assert_eq!(e.kind, ParseErrorKind::MissingSeparator);

    let e = parse("1BAD=x\n").unwrap_err();
    assert_eq!(e.kind, ParseErrorKind::InvalidKey("1BAD".into()));

    let e = parse("A=\"never closed\n").unwrap_err();
    assert_eq!(e.kind, ParseErrorKind::UnterminatedQuote);

    let e = parse("A=\"v\" junk here\n").unwrap_err();
    assert_eq!(e.kind, ParseErrorKind::TrailingCharacters);
}

#[test]
fn serialize_round_trips_semantically() {
    let src = concat!(
        "# doc\n",
        "PLAIN=simple\n",
        "SPACED=  padded  \n",
        "HASHY=a #b\n",
        "MULTI=\"l1\nl2\"\n",
        "QUOTED='single inside'\n",
        "EMPTY=\n",
        "UNI=héllo→\n",
    );
    let f1 = parsed(src);
    let round_trip = parse(&serialize(&f1)).unwrap();
    assert_eq!(f1, round_trip);
}

#[test]
fn serialize_quotes_only_when_needed() {
    let mut f = EnvFile::new();
    f.set("EASY", "value");
    f.set("HARD", "needs \"quotes\" and # too");
    f.set("EMPTY", "");
    let out = serialize(&f);
    assert!(out.contains("EASY=value\n"));
    assert!(out.contains("HARD=\"needs \\\"quotes\\\" and # too\"\n"));
    assert!(out.contains("EMPTY=\n"));
}

#[test]
fn set_updates_in_place_and_remove_reports() {
    let mut f = parsed("A=1\nB=2\n");
    f.set("A", "9");
    assert_eq!(f.get("A"), Some("9"));
    let keys: Vec<_> = f.keys().collect();
    assert_eq!(keys, vec!["A", "B"]);
    assert!(f.remove("A"));
    assert!(!f.remove("A"));
}

#[test]
fn diff_reports_added_updated_removed_in_order() {
    let base = parsed("KEEP=1\nCHANGE=old\nDROP=yes\n");
    let incoming = parsed("KEEP=1\nCHANGE=new\nFRESH=hi\n");

    let changes = diff(&base, &incoming);
    assert_eq!(
        changes,
        vec![
            Change::Updated {
                key: "CHANGE".into(),
                old: "old".into(),
                new: "new".into(),
            },
            Change::Added {
                key: "FRESH".into(),
                new: "hi".into(),
            },
            Change::Removed {
                key: "DROP".into(),
                old: "yes".into(),
            },
        ]
    );
}

#[test]
fn identical_files_have_empty_diff() {
    let a = parsed("A=1\nB=2\n");
    let b = parsed("B=2\nA=1\n");
    assert!(diff(&a, &b).is_empty());
}

#[test]
fn merge_union_gives_incoming_precedence_but_keeps_base_only_keys() {
    let base = parsed("A=base\nONLY_BASE=stay\nSHARED=old\n");
    let incoming = parsed("SHARED=new\nEXTRA=add\n");
    let merged = merge(&base, &incoming);

    assert_eq!(merged.get("A"), Some("base"));
    assert_eq!(merged.get("ONLY_BASE"), Some("stay"));
    assert_eq!(merged.get("SHARED"), Some("new"));
    assert_eq!(merged.get("EXTRA"), Some("add"));
}
