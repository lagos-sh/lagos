//! `${VAR}` expansion over raw configuration text.
//!
//! The gateway used to reach the environment through a `*_env` field on every
//! secret-bearing struct — `url_env`, `secret_env`, `project_id_envs`. That is
//! precise but it means a first run needs a dozen exported variables before the
//! process will start at all. Expanding `${VAR}` in the text instead keeps the
//! indirection available everywhere without making it mandatory anywhere:
//!
//! ```yaml
//! upstreams:
//!   users:  http://localhost:3000          # literal
//!   orders: ${ORDERS_URL}                  # required; unset is fatal
//!   carts:  ${CARTS_URL:-http://localhost:3001}   # optional, with a default
//! ```
//!
//! Two rules preserve the fail-closed behaviour the `*_env` fields had:
//!
//! 1. A variable that is set but **empty or whitespace-only counts as unset**.
//!    `API_KEY=` in a manifest is a mistake, not a deliberate empty credential;
//!    accepting it would inject a blank header and hand every upstream an
//!    unauthenticated request.
//! 2. A variable with no default that is unset is a **fatal error naming the
//!    line**, never a silent empty string.
//!
//! Write `$${` for a literal `${`.

/// Refuses a substitution that would change the document's structure rather
/// than fill in a value.
///
/// Expansion happens on the text before it is parsed, so a value containing a
/// newline could introduce YAML keys of its own. No URL, secret, or header
/// value legitimately contains a control character, so refusing them costs
/// nothing and closes that hole.
fn is_structurally_safe(value: &str) -> bool {
    !value.chars().any(char::is_control)
}

fn is_valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[derive(Debug, thiserror::Error)]
pub enum InterpolateError {
    #[error(
        "line {line}: `${{{name}}}` is not set.\n\
         Set the environment variable, or give it a default: `${{{name}:-some-value}}`"
    )]
    Unset { name: String, line: usize },

    #[error("line {line}: `${{` is never closed; add the matching `}}`")]
    Unterminated { line: usize },

    #[error("line {line}: `${{}}` has an empty variable name")]
    EmptyName { line: usize },

    #[error(
        "line {line}: `{name}` is not a valid environment variable name \
         (letters, digits and underscore only, not starting with a digit)"
    )]
    BadName { name: String, line: usize },

    #[error(
        "line {line}: the value of `{name}` contains a control character. \
         A newline in a substituted value would inject configuration structure, \
         so it is refused."
    )]
    ControlCharacter { name: String, line: usize },
}

/// The result of expanding a configuration document.
#[derive(Debug, Clone, Default)]
pub struct Interpolated {
    pub text: String,
    /// Names that were expanded, in first-seen order — reported by
    /// `gateway validate` so an operator can see what the file depends on.
    pub referenced: Vec<String>,
    /// Names that fell back to their default because the environment did not
    /// set them. These are the ones that differ between a laptop and a cluster.
    pub defaulted: Vec<String>,
}

/// Where a YAML comment starts on this line, if anywhere.
///
/// A `#` opens a comment only at the start of a line or after whitespace, and
/// only outside a quoted scalar — so `url: "http://x#y"` and `key: a#b` both
/// keep their `#`. Comments are excluded from expansion because a comment that
/// *documents* `${VAR}` must not be treated as a use of it.
fn comment_start(line: &str) -> Option<usize> {
    let mut in_single = false;
    let mut in_double = false;
    let mut prev_was_space = true;
    let mut escaped = false;

    for (i, c) in line.char_indices() {
        if escaped {
            escaped = false;
            prev_was_space = false;
            continue;
        }
        match c {
            '\\' if in_double => escaped = true,
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double && prev_was_space => return Some(i),
            _ => {}
        }
        prev_was_space = c == ' ' || c == '\t';
    }
    None
}

/// The indentation of a line, in characters.
fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// True if the line opens a block scalar (`key: |`, `key: >-`, …), whose body
/// is literal text where `#` is content rather than a comment.
fn opens_block_scalar(code: &str) -> bool {
    let t = code.trim_end();
    match t.rsplit_once(':') {
        Some((_, rest)) => {
            let r = rest.trim();
            !r.is_empty() && (r.starts_with('|') || r.starts_with('>'))
        }
        None => false,
    }
}

/// Expand `${VAR}` and `${VAR:-default}` in `text`, reading values through
/// `lookup`.
///
/// `lookup` returns the raw value; emptiness is judged here so every caller
/// agrees on it.
pub fn interpolate<F>(text: &str, lookup: F) -> Result<Interpolated, InterpolateError>
where
    F: Fn(&str) -> Option<String>,
{
    let mut out = String::with_capacity(text.len());
    let mut referenced: Vec<String> = Vec::new();
    let mut defaulted: Vec<String> = Vec::new();
    // Indentation of the block scalar we are inside, if any. Its body is
    // literal, so `#` there is content and gets expanded like any other text.
    let mut block: Option<usize> = None;

    let ends_with_newline = text.ends_with('\n');
    let lines: Vec<&str> = text.split('\n').collect();
    let last = lines.len().saturating_sub(1);

    for (idx, raw_line) in lines.iter().enumerate() {
        let line_no = idx + 1;

        if let Some(block_indent) = block {
            let blank = raw_line.trim().is_empty();
            if !blank && indent_of(raw_line) <= block_indent {
                block = None;
            }
        }

        let (code, comment) = match block {
            // Inside a block scalar there are no comments.
            Some(_) => (*raw_line, ""),
            None => match comment_start(raw_line) {
                Some(i) => raw_line.split_at(i),
                None => (*raw_line, ""),
            },
        };

        if block.is_none() && opens_block_scalar(code) {
            block = Some(indent_of(raw_line));
        }

        expand_into(
            code,
            line_no,
            &lookup,
            &mut out,
            &mut referenced,
            &mut defaulted,
        )?;
        out.push_str(comment);
        if idx != last || ends_with_newline {
            out.push('\n');
        }
    }

    // `split` on a trailing newline yields a final empty element, which the
    // loop already emitted; drop the newline it added after it.
    if ends_with_newline {
        out.pop();
    }

    Ok(Interpolated {
        text: out,
        referenced,
        defaulted,
    })
}

/// Expand one comment-free fragment of a single line.
fn expand_into<F>(
    fragment: &str,
    line: usize,
    lookup: &F,
    out: &mut String,
    referenced: &mut Vec<String>,
    defaulted: &mut Vec<String>,
) -> Result<(), InterpolateError>
where
    F: Fn(&str) -> Option<String>,
{
    let mut chars = fragment.chars().peekable();

    while let Some(c) = chars.next() {
        if c != '$' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            // `$$` is an escape: emit one `$` and consume both, so `$${VAR}`
            // survives as the literal text `${VAR}`.
            Some('$') => {
                chars.next();
                out.push('$');
            }
            Some('{') => {
                chars.next();
                let mut body = String::new();
                let mut closed = false;
                for c in chars.by_ref() {
                    if c == '}' {
                        closed = true;
                        break;
                    }
                    body.push(c);
                }
                if !closed {
                    return Err(InterpolateError::Unterminated { line });
                }

                let (name, default) = match body.split_once(":-") {
                    Some((n, d)) => (n.trim(), Some(d)),
                    None => (body.trim(), None),
                };

                if name.is_empty() {
                    return Err(InterpolateError::EmptyName { line });
                }
                if !is_valid_name(name) {
                    return Err(InterpolateError::BadName {
                        name: name.to_string(),
                        line,
                    });
                }
                if !referenced.iter().any(|n| n == name) {
                    referenced.push(name.to_string());
                }

                // Empty or whitespace-only is treated as unset, so a blank
                // value in a manifest falls to the default or fails loudly
                // rather than silently becoming an empty credential.
                let resolved = lookup(name)
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty());

                let value = match (resolved, default) {
                    (Some(v), _) => v,
                    (None, Some(d)) => {
                        if !defaulted.iter().any(|n| n == name) {
                            defaulted.push(name.to_string());
                        }
                        d.to_string()
                    }
                    (None, None) => {
                        return Err(InterpolateError::Unset {
                            name: name.to_string(),
                            line,
                        });
                    }
                };

                if !is_structurally_safe(&value) {
                    return Err(InterpolateError::ControlCharacter {
                        name: name.to_string(),
                        line,
                    });
                }
                out.push_str(&value);
            }
            // A bare `$` is ordinary text.
            _ => out.push('$'),
        }
    }
    Ok(())
}

/// Expand against the process environment.
pub fn interpolate_env(text: &str) -> Result<Interpolated, InterpolateError> {
    interpolate(text, |name| std::env::var(name).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn run(text: &str, pairs: &[(&str, &str)]) -> Result<Interpolated, InterpolateError> {
        let map = env(pairs);
        interpolate(text, |n| map.get(n).cloned())
    }

    #[test]
    fn substitutes_a_set_variable() {
        let r = run("url: ${UP}", &[("UP", "http://svc:1")]).expect("should expand");
        assert_eq!(r.text, "url: http://svc:1");
        assert_eq!(r.referenced, vec!["UP"]);
        assert!(r.defaulted.is_empty());
    }

    #[test]
    fn falls_back_to_the_default_when_unset() {
        let r = run("url: ${UP:-http://localhost:3000}", &[]).expect("should expand");
        assert_eq!(r.text, "url: http://localhost:3000");
        assert_eq!(r.defaulted, vec!["UP"]);
    }

    #[test]
    fn a_set_value_beats_the_default() {
        let r = run("url: ${UP:-http://localhost}", &[("UP", "http://real")]).expect("expands");
        assert_eq!(r.text, "url: http://real");
        assert!(r.defaulted.is_empty());
    }

    #[test]
    fn an_empty_value_is_treated_as_unset() {
        // `API_KEY=` is a mistake, not a deliberate empty credential.
        assert!(matches!(
            run("key: ${API_KEY}", &[("API_KEY", "")]),
            Err(InterpolateError::Unset { .. })
        ));
        let r = run("key: ${API_KEY:-dev}", &[("API_KEY", "   ")]).expect("expands");
        assert_eq!(r.text, "key: dev");
    }

    #[test]
    fn a_required_variable_that_is_unset_is_fatal_with_its_line() {
        match run("a: 1\nb: 2\nkey: ${MISSING}\n", &[]) {
            Err(InterpolateError::Unset { name, line }) => {
                assert_eq!(name, "MISSING");
                assert_eq!(line, 3, "the error points at the offending line");
            }
            other => panic!("an unset variable must be fatal, got {other:?}"),
        }
    }

    #[test]
    fn values_are_trimmed() {
        let r = run("url: ${UP}", &[("UP", "  http://svc:1  ")]).expect("expands");
        assert_eq!(r.text, "url: http://svc:1");
    }

    #[test]
    fn refuses_a_value_carrying_a_newline() {
        // Otherwise `${X}` with X="a\nadmin: true" would inject a config key.
        assert!(matches!(
            run("user: ${X}", &[("X", "a\nadmin: true")]),
            Err(InterpolateError::ControlCharacter { .. })
        ));
    }

    #[test]
    fn refuses_other_control_characters() {
        assert!(matches!(
            run("user: ${X}", &[("X", "a\rb")]),
            Err(InterpolateError::ControlCharacter { .. })
        ));
        assert!(matches!(
            run("user: ${X}", &[("X", "a\u{0}b")]),
            Err(InterpolateError::ControlCharacter { .. })
        ));
    }

    #[test]
    fn a_doubled_dollar_escapes_the_expansion() {
        let r = run("literal: $${NOT_A_VAR}", &[]).expect("no expansion attempted");
        assert_eq!(r.text, "literal: ${NOT_A_VAR}");
        assert!(r.referenced.is_empty());
    }

    #[test]
    fn a_bare_dollar_is_ordinary_text() {
        let r = run("price: $5 and 100$", &[]).expect("expands");
        assert_eq!(r.text, "price: $5 and 100$");
    }

    #[test]
    fn rejects_an_unterminated_expansion() {
        assert!(matches!(
            run("url: ${UP", &[("UP", "x")]),
            Err(InterpolateError::Unterminated { .. })
        ));
    }

    #[test]
    fn rejects_a_malformed_name() {
        assert!(matches!(
            run("url: ${}", &[]),
            Err(InterpolateError::EmptyName { .. })
        ));
        assert!(matches!(
            run("url: ${2FOO}", &[]),
            Err(InterpolateError::BadName { .. })
        ));
        assert!(matches!(
            run("url: ${FOO-BAR}", &[]),
            Err(InterpolateError::BadName { .. })
        ));
    }

    #[test]
    fn an_empty_default_is_allowed_and_means_empty() {
        // `${X:-}` is an explicit "this may be blank", unlike a bare `${X}`.
        let r = run("v: '${X:-}'", &[]).expect("expands");
        assert_eq!(r.text, "v: ''");
    }

    #[test]
    fn a_default_may_contain_a_colon() {
        let r = run("url: ${UP:-http://localhost:3000/a}", &[]).expect("expands");
        assert_eq!(r.text, "url: http://localhost:3000/a");
    }

    #[test]
    fn reports_every_referenced_name_once() {
        let r = run("a: ${X}\nb: ${Y:-2}\nc: ${X}\n", &[("X", "1")]).expect("expands");
        assert_eq!(r.referenced, vec!["X", "Y"]);
        assert_eq!(r.defaulted, vec!["Y"]);
    }

    #[test]
    fn a_variable_named_in_a_comment_is_not_an_expansion() {
        // The starter template documents `${VAR}` in a comment. Treating that
        // as a use of it would make a brand new gateway refuse to boot.
        let r = run("# set it with ${SOME_VAR}\nkey: literal\n", &[]).expect("comments are text");
        assert_eq!(r.text, "# set it with ${SOME_VAR}\nkey: literal\n");
        assert!(r.referenced.is_empty());
    }

    #[test]
    fn a_trailing_comment_is_left_alone_but_the_value_is_expanded() {
        let r = run("url: ${UP}   # or ${OTHER}", &[("UP", "http://x")]).expect("expands");
        assert_eq!(r.text, "url: http://x   # or ${OTHER}");
        assert_eq!(r.referenced, vec!["UP"]);
    }

    #[test]
    fn a_hash_inside_a_value_is_not_a_comment() {
        let r = run(r#"a: "x#y ${UP}""#, &[("UP", "1")]).expect("expands");
        assert_eq!(r.text, r#"a: "x#y 1""#);
        // Unquoted, a `#` only opens a comment after whitespace.
        let r = run("a: x#y${UP}", &[("UP", "1")]).expect("expands");
        assert_eq!(r.text, "a: x#y1");
    }

    #[test]
    fn a_hash_in_a_single_quoted_value_is_not_a_comment() {
        let r = run("a: 'k # ${UP}'", &[("UP", "1")]).expect("expands");
        assert_eq!(r.text, "a: 'k # 1'");
    }

    #[test]
    fn block_scalar_content_has_no_comments() {
        // Inside `|` a `#` is literal text, so expansion must still happen.
        let r = run("note: |\n  # heading ${UP}\nnext: 1\n", &[("UP", "v")]).expect("expands");
        assert_eq!(r.text, "note: |\n  # heading v\nnext: 1\n");
    }

    #[test]
    fn a_block_scalar_ends_at_the_next_dedent() {
        let r = run("note: |\n  body\nkey: 1 # ${UP}\n", &[]).expect("expands");
        assert_eq!(
            r.text, "note: |\n  body\nkey: 1 # ${UP}\n",
            "the comment after the block ended is a comment again"
        );
    }

    #[test]
    fn preserves_whether_the_document_ended_with_a_newline() {
        assert_eq!(run("a: 1\n", &[]).unwrap().text, "a: 1\n");
        assert_eq!(run("a: 1", &[]).unwrap().text, "a: 1");
        assert_eq!(run("a: 1\n\n", &[]).unwrap().text, "a: 1\n\n");
    }

    #[test]
    fn counts_lines_across_a_multi_line_document() {
        match run("a: ${A}\n\n\nb: ${B}", &[("A", "1")]) {
            Err(InterpolateError::Unset { line, .. }) => assert_eq!(line, 4),
            other => panic!("expected an unset error, got {other:?}"),
        }
    }

    #[test]
    fn an_expansion_may_not_span_lines() {
        assert!(matches!(
            run("a: ${UP\n  }", &[("UP", "x")]),
            Err(InterpolateError::Unterminated { .. })
        ));
    }
}
