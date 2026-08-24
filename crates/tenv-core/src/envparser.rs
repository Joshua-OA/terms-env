//! `.env` grammar: parsing, serialization, diff, merge.
//!
//! Grammar supported:
//! - `KEY=value`, optional leading `export `, optional surrounding whitespace
//! - keys must match `[A-Za-z_][A-Za-z0-9_]*`
//! - single-quoted values are fully literal
//! - double-quoted values span multiple physical lines and interpret
//!   `\\ \" \n \t \r`; other escapes keep their backslash literally
//! - unquoted values are right-trimmed; a ` #` sequence starts an inline comment
//! - full-line comments and blank lines are ignored
//! - duplicate keys: last occurrence wins, keeping its original position
//! - variable interpolation is intentionally NOT performed

use crate::domain::{EnvFile, EnvVar};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseErrorKind {
    MissingSeparator,
    InvalidKey(String),
    UnterminatedQuote,
    TrailingCharacters,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub kind: ParseErrorKind,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, ".env line {}: ", self.line)?;
        match &self.kind {
            ParseErrorKind::MissingSeparator => write!(f, "expected KEY=value"),
            ParseErrorKind::InvalidKey(k) => write!(f, "invalid key `{k}`"),
            ParseErrorKind::UnterminatedQuote => write!(f, "unterminated quote"),
            ParseErrorKind::TrailingCharacters => write!(f, "unexpected characters after value"),
        }
    }
}

impl std::error::Error for ParseError {}

pub fn parse(input: &str) -> Result<EnvFile, ParseError> {
    let input = input.strip_prefix('\u{feff}').unwrap_or(input);
    let mut file = EnvFile::new();
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut line_no = 1usize;

    while i < bytes.len() {
        let line_start_no = line_no;
        let mut line = read_logical_line(bytes, &mut i, &mut line_no);

        if line.contains('\r') {
            line = line.replace("\r\n", "\n");
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let var = parse_record(trimmed, line_start_no)?;
        file.set(var.key, var.value);
    }

    Ok(file)
}

fn parse_record(line: &str, line_no: usize) -> Result<EnvVar, ParseError> {
    let body = line
        .strip_prefix("export ")
        .or_else(|| line.strip_prefix("export\t"))
        .unwrap_or(line);
    let body = body.trim_start();

    let Some(eq) = body.find('=') else {
        return Err(ParseError {
            line: line_no,
            kind: ParseErrorKind::MissingSeparator,
        });
    };

    let key = body[..eq].trim();
    if !is_valid_key(key) {
        return Err(ParseError {
            line: line_no,
            kind: ParseErrorKind::InvalidKey(key.to_string()),
        });
    }

    let raw_value = body[eq + 1..].trim();
    let value = decode_value(raw_value, line_no)?;

    Ok(EnvVar {
        key: key.to_string(),
        value,
    })
}

fn decode_value(raw: &str, line_no: usize) -> Result<String, ParseError> {
    match raw.chars().next() {
        Some('\'') | Some('"') => {
            let quote = raw.chars().next().unwrap();
            let inner = &raw[1..];
            match find_closing_quote(inner, quote) {
                None => Err(ParseError {
                    line: line_no,
                    kind: ParseErrorKind::UnterminatedQuote,
                }),
                Some(end) => {
                    let rest = inner[end + 1..].trim();
                    let rest_clean = strip_inline_comment(rest);
                    if !rest_clean.is_empty() {
                        return Err(ParseError {
                            line: line_no,
                            kind: ParseErrorKind::TrailingCharacters,
                        });
                    }
                    let content = &inner[..end];
                    Ok(if quote == '\'' {
                        content.to_string()
                    } else {
                        unescape_double(content)
                    })
                }
            }
        }
        _ => {
            let cut = strip_inline_comment(raw);
            Ok(cut.trim_end().to_string())
        }
    }
}

fn find_closing_quote(haystack: &str, quote: char) -> Option<usize> {
    let bytes = haystack.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match quote {
            '"' if bytes[i] == b'\\' && i + 1 < bytes.len() => i += 2,
            _ if bytes[i] as char == quote => return Some(i),
            _ => i += 1,
        }
    }
    None
}

fn unescape_double(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('"') => out.push('"'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

fn strip_inline_comment(s: &str) -> &str {
    match s.find(" #") {
        Some(idx) => &s[..idx],
        None => s,
    }
}

fn read_logical_line(bytes: &[u8], i: &mut usize, line_no: &mut usize) -> String {
    let start = *i;
    let mut escaped = false;
    let mut in_double = false;
    let mut in_single = false;

    while *i < bytes.len() {
        let b = bytes[*i];
        if b == b'\n' && !in_double && !in_single {
            break;
        }
        if !in_single {
            if escaped {
                escaped = false;
            } else if b == b'\\' && in_double {
                escaped = true;
            } else if b == b'"' {
                in_double = !in_double;
            }
        }
        if b == b'\'' && !in_double && !escaped {
            in_single = !in_single;
        }
        *i += 1;
        if b == b'\n' {
            *line_no += 1;
        }
    }
    if *i < bytes.len() {
        *i += 1;
        *line_no += 1;
    }
    String::from_utf8_lossy(&bytes[start..*i]).into_owned()
}

fn is_valid_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub fn serialize(file: &EnvFile) -> String {
    let mut out = String::new();
    for var in file.iter() {
        out.push_str(&var.key);
        out.push('=');
        out.push_str(&encode_value(&var.value));
        out.push('\n');
    }
    out
}

fn encode_value(value: &str) -> String {
    // Quote anything whose plain form would not survive a parse unchanged.
    let needs_quotes = value.starts_with([' ', '\t'])
        || value.ends_with([' ', '\t'])
        || value.contains(['\n', '\r', '"', '\''])
        || value.contains(" #");
    if !needs_quotes {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Ordered list of differences going from `base` to `incoming`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Added {
        key: String,
        new: String,
    },
    Updated {
        key: String,
        old: String,
        new: String,
    },
    Removed {
        key: String,
        old: String,
    },
}

pub fn diff(base: &EnvFile, incoming: &EnvFile) -> Vec<Change> {
    let mut changes = Vec::new();

    for var in incoming.iter() {
        match base.get(&var.key) {
            None => changes.push(Change::Added {
                key: var.key.clone(),
                new: var.value.clone(),
            }),
            Some(old) if old != var.value => changes.push(Change::Updated {
                key: var.key.clone(),
                old: old.to_string(),
                new: var.value.clone(),
            }),
            _ => {}
        }
    }
    for var in base.iter() {
        if !incoming.contains_key(&var.key) {
            changes.push(Change::Removed {
                key: var.key.clone(),
                old: var.value.clone(),
            });
        }
    }
    changes
}

/// Union merge: everything from `incoming` overrides `base`; keys that exist
/// only in `base` survive.
pub fn merge(base: &EnvFile, incoming: &EnvFile) -> EnvFile {
    let mut out = base.clone();
    for var in incoming.iter() {
        out.set(var.key.clone(), var.value.clone());
    }
    out
}
