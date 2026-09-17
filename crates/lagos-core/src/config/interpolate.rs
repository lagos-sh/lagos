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
    /// Names that were unset, had no default, and were filled with the caller's
    /// placeholder instead of failing. Only ever non-empty when a fallback was
    /// supplied — that is, under `validate --allow-unset`. Whatever they feed
    /// is **unchecked**, so every caller reports them rather than passing them
    /// over in silence.
    pub placeheld: Vec<String>,
}

/// A reference's state, using the same whitespace and control rules as runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VariableState {
    Set,
    Defaulted,
    Required,
    Invalid,
}

// Deliberately no Debug: the selected value may be a credential. Only the
// metadata is exposed by diagnostics; values are used solely to locate files.
pub(crate) struct VariableReference {
    pub name: String,
    pub line: usize,
    pub column: usize,
    pub has_default: bool,
    pub state: VariableState,
    marker: String,
    selected: Option<String>,
}

pub(crate) struct Inspection {
    pub masked: String,
    pub references: Vec<VariableReference>,
}

impl Inspection {
    pub fn contains_marker(&self, scalar: &str) -> bool {
        self.references
            .iter()
            .any(|reference| scalar.contains(&reference.marker))
    }

    /// Resolve a scalar extracted from the masked YAML, without re-expanding
    /// escaped literals or inspecting unrelated credential values.
    pub fn resolve_scalar(&self, scalar: &str) -> Option<String> {
        // Walk the original scalar once: a value containing another marker
        // must not be interpreted as a second substitution.
        let mut rest = scalar;
        let mut out = String::new();
        loop {
            let next = self
                .references
                .iter()
                .filter_map(|reference| {
                    rest.find(&reference.marker)
                        .map(|offset| (offset, reference))
                })
                .min_by_key(|(offset, _)| *offset);
            let Some((offset, reference)) = next else {
                out.push_str(rest);
                return Some(out);
            };
            let (before, after) = rest.split_at(offset);
            out.push_str(before);
            out.push_str(reference.selected.as_deref()?);
            rest = after.strip_prefix(&reference.marker)?;
        }
    }
}

/// Inspect every occurrence, even when required variables are missing. The
/// document contains markers instead of environment values or default text.
pub(crate) fn inspect<F>(text: &str, lookup: F) -> Result<Inspection, InterpolateError>
where
    F: Fn(&str) -> Option<String>,
{
    let mut prefix = "lagos-vars-placeholder-".to_string();
    while text.contains(&prefix) {
        prefix.push('x');
    }
    let (expanded, references) = process(text, lookup, None, Some(prefix))?;
    Ok(Inspection {
        masked: expanded.text,
        references,
    })
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

/// What a document referenced, carried across lines so one record covers the
/// whole file. Grouped into a struct rather than passed as four out-parameters
/// because `expand_into` is called per line and per fragment.
struct Expansion<'a> {
    /// Substituted for a variable that is unset and has no default, instead of
    /// failing. `None` is the ordinary case: unset with no default is fatal.
    fallback: Option<&'a dyn Fn(&str) -> String>,
    referenced: Vec<String>,
    defaulted: Vec<String>,
    placeheld: Vec<String>,
    inspection_prefix: Option<String>,
    occurrences: Vec<VariableReference>,
}

impl Expansion<'_> {
    fn note(list: &mut Vec<String>, name: &str) {
        if !list.iter().any(|n| n == name) {
            list.push(name.to_string());
        }
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
    interpolate_with_fallback(text, lookup, None)
}

/// As [`interpolate`], but a variable that is unset *and* has no default is
/// filled with `fallback` instead of being an error.
///
/// This exists for `validate --allow-unset`, which checks the structure of a
/// document in an environment that deliberately does not hold production
/// values — a container build, most often. It is not offered to `run` or
/// `dev`: a gateway that starts with a placeholder where a credential or an
/// upstream belongs is worse than one that refuses to start, so the fatal path
/// stays fatal everywhere traffic is served.
pub fn interpolate_with_fallback<F>(
    text: &str,
    lookup: F,
    fallback: Option<&dyn Fn(&str) -> String>,
) -> Result<Interpolated, InterpolateError>
where
    F: Fn(&str) -> Option<String>,
{
    process(text, lookup, fallback, None).map(|(expanded, _)| expanded)
}

fn process<F>(
    text: &str,
    lookup: F,
    fallback: Option<&dyn Fn(&str) -> String>,
    inspection_prefix: Option<String>,
) -> Result<(Interpolated, Vec<VariableReference>), InterpolateError>
where
    F: Fn(&str) -> Option<String>,
{
    let mut out = String::with_capacity(text.len());
    let mut exp = Expansion {
        fallback,
        referenced: Vec::new(),
        defaulted: Vec::new(),
        placeheld: Vec::new(),
        inspection_prefix,
        occurrences: Vec::new(),
    };
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

        expand_into(code, line_no, &lookup, &mut out, &mut exp)?;
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

    Ok((
        Interpolated {
            text: out,
            referenced: exp.referenced,
            defaulted: exp.defaulted,
            placeheld: exp.placeheld,
        },
        exp.occurrences,
    ))
}

/// Expand one comment-free fragment of a single line.
fn expand_into<F>(
    fragment: &str,
    line: usize,
    lookup: &F,
    out: &mut String,
    exp: &mut Expansion<'_>,
) -> Result<(), InterpolateError>
where
    F: Fn(&str) -> Option<String>,
{
    let mut chars = fragment.char_indices().peekable();

    while let Some((offset, c)) = chars.next() {
        if c != '$' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            // `$$` is an escape: emit one `$` and consume both, so `$${VAR}`
            // survives as the literal text `${VAR}`.
            Some((_, '$')) => {
                chars.next();
                out.push('$');
            }
            Some((_, '{')) => {
                chars.next();
                let mut body = String::new();
                let mut closed = false;
                for (_, c) in chars.by_ref() {
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
                Expansion::note(&mut exp.referenced, name);

                // Empty or whitespace-only is treated as unset, so a blank
                // value in a manifest falls to the default or fails loudly
                // rather than silently becoming an empty credential.
                let resolved = lookup(name)
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty());

                if let Some(prefix) = &exp.inspection_prefix {
                    let state = match (&resolved, default) {
                        (Some(_), _) => VariableState::Set,
                        (None, Some(_)) => VariableState::Defaulted,
                        (None, None) => VariableState::Required,
                    };
                    let selected = resolved.or_else(|| default.map(str::to_string));
                    let invalid = selected
                        .as_deref()
                        .is_some_and(|v| !is_structurally_safe(v));
                    let marker = format!("{prefix}{}-end", exp.occurrences.len());
                    out.push_str(&marker);
                    exp.occurrences.push(VariableReference {
                        name: name.to_string(),
                        line,
                        column: fragment.get(..offset).unwrap_or_default().chars().count() + 1,
                        has_default: default.is_some(),
                        state: if invalid {
                            VariableState::Invalid
                        } else {
                            state
                        },
                        marker,
                        selected: if invalid { None } else { selected },
                    });
                    continue;
                }

                // A declared default always wins over the fallback: the
                // document said what it wants when the variable is absent, and
                // `${PORT:-8080}` must still expand to 8080 under
                // `--allow-unset` or the check would test a config nobody runs.
                let value = match (resolved, default) {
                    (Some(v), _) => v,
                    (None, Some(d)) => {
                        Expansion::note(&mut exp.defaulted, name);
                        d.to_string()
                    }
                    (None, None) => match exp.fallback {
                        Some(f) => {
                            Expansion::note(&mut exp.placeheld, name);
                            f(name)
                        }
                        None => {
                            return Err(InterpolateError::Unset {
                                name: name.to_string(),
                                line,
                            });
                        }
                    },
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
    interpolate_env_with_fallback(text, None)
}

/// Expand against the process environment, filling anything unset and
/// defaultless with `fallback` rather than failing. See
/// [`interpolate_with_fallback`].
pub fn interpolate_env_with_fallback(
    text: &str,
    fallback: Option<&dyn Fn(&str) -> String>,
) -> Result<Interpolated, InterpolateError> {
    interpolate_with_fallback(text, |name| std::env::var(name).ok(), fallback)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn inspection_agrees_with_runtime_and_retains_occurrences() {
        let text = "é: ${ X } ${X:-secret-default} $${IGNORE} # ${COMMENT}\nblock: |\n  # ${Y}\n";
        let inspected = inspect(text, |_| None).expect("inventory works before env setup");
        assert_eq!(inspected.references.len(), 3);
        assert_eq!(inspected.references[0].column, 4);
        assert_eq!(inspected.references[0].state, VariableState::Required);
        assert_eq!(inspected.references[1].state, VariableState::Defaulted);
        assert_eq!(inspected.references[2].name, "Y");
        assert!(!inspected.masked.contains("secret-default"));
        assert!(matches!(
            interpolate(text, |_| None),
            Err(InterpolateError::Unset { line: 1, .. })
        ));
        let resolved = interpolate_with_fallback(text, |_| None, Some(&|_| "placeholder".into()))
            .expect("fallback");
        assert_eq!(resolved.referenced, ["X", "Y"]);
    }

    #[test]
    fn inspection_handles_control_values_without_exposing_them() {
        let text = "a: ${X}\nb: ${Y:-fallback}\nc: ${Z:-\tbad}\n";
        let inspected = inspect(text, |_| Some("secret\nvalue".into()))
            .expect("invalid values are inventory states");
        assert!(
            inspected
                .references
                .iter()
                .all(|r| r.state == VariableState::Invalid)
        );
        assert!(!inspected.masked.contains("secret"));
        assert!(inspected.resolve_scalar(&inspected.masked).is_none());
        let absent = inspect(text, |_| None).expect("default control value");
        assert_eq!(absent.references[2].state, VariableState::Invalid);
        assert!(matches!(
            interpolate(text, |_| Some("secret\nvalue".into())),
            Err(InterpolateError::ControlCharacter { .. })
        ));
    }

    #[test]
    fn inspection_resolution_never_expands_replacement_content_again() {
        let text = "a: ${A}\nb: ${B}\n";
        let inspected = inspect(text, |name| {
            Some(if name == "A" {
                "lagos-vars-placeholder-1-end".into()
            } else {
                "secret".into()
            })
        })
        .expect("valid references");
        assert_eq!(
            inspected
                .resolve_scalar(&inspected.references[0].marker)
                .as_deref(),
            Some("lagos-vars-placeholder-1-end")
        );
        let collision =
            inspect("a: lagos-vars-placeholder- ${X}", |_| None).expect("marker collision");
        assert!(
            collision.references[0]
                .marker
                .starts_with("lagos-vars-placeholder-x")
        );
    }

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

    fn run_allowing_unset(
        text: &str,
        pairs: &[(&str, &str)],
    ) -> Result<Interpolated, InterpolateError> {
        let map = env(pairs);
        interpolate_with_fallback(
            text,
            |n| map.get(n).cloned(),
            Some(&|_| "PLACEHOLDER".into()),
        )
    }

    #[test]
    fn a_fallback_fills_an_unset_variable_and_records_it() {
        let r = run_allowing_unset("url: ${UP}", &[]).expect("fallback should apply");
        assert_eq!(r.text, "url: PLACEHOLDER");
        assert_eq!(r.placeheld, vec!["UP"]);
        assert_eq!(r.referenced, vec!["UP"]);
        assert!(r.defaulted.is_empty());
    }

    #[test]
    fn a_declared_default_wins_over_the_fallback() {
        // The document already said what it wants when the variable is absent.
        // Taking the placeholder instead would check a config nobody runs --
        // and would break every numeric field that carries a sensible default.
        let r = run_allowing_unset("port: ${PORT:-8080}", &[]).expect("default should apply");
        assert_eq!(r.text, "port: 8080");
        assert_eq!(r.defaulted, vec!["PORT"]);
        assert!(r.placeheld.is_empty());
    }

    #[test]
    fn a_set_variable_wins_over_the_fallback() {
        let r = run_allowing_unset("url: ${UP}", &[("UP", "http://real:1")]).expect("set");
        assert_eq!(r.text, "url: http://real:1");
        assert!(r.placeheld.is_empty());
    }

    #[test]
    fn a_blank_variable_takes_the_fallback_like_an_unset_one() {
        // Blank counts as unset everywhere else; the fallback path must agree,
        // or `API_KEY=` would validate as an empty credential.
        let r = run_allowing_unset("key: ${API_KEY}", &[("API_KEY", "   ")]).expect("blank");
        assert_eq!(r.text, "key: PLACEHOLDER");
        assert_eq!(r.placeheld, vec!["API_KEY"]);
    }

    #[test]
    fn without_a_fallback_an_unset_variable_is_still_fatal() {
        assert!(matches!(
            run("url: ${UP}", &[]),
            Err(InterpolateError::Unset { .. })
        ));
        assert!(run("url: ${UP}", &[]).is_err());
    }

    #[test]
    fn a_fallback_is_still_refused_if_it_would_change_the_structure() {
        let map = env(&[]);
        assert!(matches!(
            interpolate_with_fallback(
                "url: ${UP}",
                |n| map.get(n).cloned(),
                Some(&|_| "a\nb: c".into())
            ),
            Err(InterpolateError::ControlCharacter { .. })
        ));
    }
}
