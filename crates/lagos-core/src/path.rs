//! Canonicalization of untrusted request paths.
//!
//! The deny-list and the per-route auth tier are enforced by string prefix
//! matching, but the URL that is finally sent upstream gets normalized by the
//! HTTP stack. If the matched string still contains dot-segments (`%2e%2e`,
//! `..`), a caller could match a public route yet have the request resolve to a
//! denied internal path. To prevent that we fully percent-decode (defeating
//! multi-encoding like `%252e`) and then *reject* any path containing a `.` or
//! `..` segment, a backslash, a control character, or a leftover `%`.
//!
//! Legitimate proxy sub-paths never contain dot-segments.

use percent_encoding::percent_decode_str;

/// Maximum percent-decoding passes. Mirrors the reference implementation; three
/// passes defeats `%252e`-style multi-encoding without unbounded work.
const MAX_DECODE_PASSES: usize = 3;

/// Strip leading and trailing slashes so every layer compares the same shape.
pub fn normalize_proxy_path(path: &str) -> &str {
    path.trim_matches('/')
}

/// Canonicalize an untrusted request path into the string used for both
/// deny-list/allowlist matching *and* upstream URL construction.
///
/// Returns `None` if the path is unsafe or malformed, in which case the caller
/// must reject the request (as a 404, so the deny-list is not probeable).
pub fn canonicalize_proxy_path(raw: &str) -> Option<String> {
    // Drop any query string / fragment.
    let without_query = raw.split('?').next()?.split('#').next()?;

    // Fully percent-decode, bailing on anything we cannot resolve.
    let mut decoded = without_query.to_string();
    for _ in 0..MAX_DECODE_PASSES {
        if !decoded.contains('%') {
            break;
        }
        let next = percent_decode_str(&decoded)
            .decode_utf8()
            .ok()?
            .into_owned();
        if next == decoded {
            break;
        }
        decoded = next;
    }
    // A surviving `%` means encoding we could not fully resolve — treat as hostile.
    if decoded.contains('%') {
        return None;
    }

    // Reject backslashes (Windows-style traversal), control characters, and DEL.
    if decoded
        .chars()
        .any(|c| (c as u32) < 0x20 || c == '\u{7f}' || c == '\\')
    {
        return None;
    }

    let segments: Vec<&str> = decoded.split('/').filter(|s| !s.is_empty()).collect();
    if segments.iter().any(|s| *s == "." || *s == "..") {
        return None;
    }
    Some(segments.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_surrounding_slashes() {
        assert_eq!(
            normalize_proxy_path("/loyalty/settings/"),
            "loyalty/settings"
        );
        assert_eq!(normalize_proxy_path("loyalty"), "loyalty");
        assert_eq!(normalize_proxy_path("///"), "");
    }

    #[test]
    fn passes_through_ordinary_paths() {
        assert_eq!(
            canonicalize_proxy_path("loyalty/settings/vendors/1").as_deref(),
            Some("loyalty/settings/vendors/1")
        );
    }

    #[test]
    fn collapses_empty_segments_and_drops_query() {
        assert_eq!(
            canonicalize_proxy_path("/loyalty//settings/?merchantId=4#frag").as_deref(),
            Some("loyalty/settings")
        );
    }

    #[test]
    fn decodes_ordinary_percent_escapes() {
        assert_eq!(
            canonicalize_proxy_path("legacy/pets/Mr%20Bigglesworth").as_deref(),
            Some("legacy/pets/Mr Bigglesworth")
        );
    }

    #[test]
    fn rejects_plain_dot_segments() {
        assert_eq!(canonicalize_proxy_path("loyalty/../legacy/internal"), None);
        assert_eq!(canonicalize_proxy_path("loyalty/./settings"), None);
        assert_eq!(canonicalize_proxy_path(".."), None);
    }

    #[test]
    fn rejects_single_encoded_traversal() {
        assert_eq!(
            canonicalize_proxy_path("loyalty/%2e%2e/legacy/internal"),
            None
        );
        assert_eq!(canonicalize_proxy_path("loyalty/%2E%2E/x"), None);
    }

    #[test]
    fn rejects_double_encoded_traversal() {
        // %252e decodes to %2e, which decodes to `.` — the multi-pass loop must catch it.
        assert_eq!(
            canonicalize_proxy_path("loyalty/%252e%252e/legacy/internal"),
            None
        );
    }

    #[test]
    fn rejects_encoded_separator_traversal() {
        assert_eq!(canonicalize_proxy_path("loyalty%2f..%2flegacy"), None);
    }

    #[test]
    fn rejects_backslash_and_control_characters() {
        assert_eq!(canonicalize_proxy_path("loyalty\\..\\legacy"), None);
        assert_eq!(canonicalize_proxy_path("loyalty/%00/settings"), None);
        assert_eq!(canonicalize_proxy_path("loyalty/%7f/settings"), None);
    }

    #[test]
    fn rejects_malformed_percent_encoding() {
        assert_eq!(canonicalize_proxy_path("loyalty/%zz"), None);
        assert_eq!(canonicalize_proxy_path("loyalty/%"), None);
        // Invalid UTF-8 byte sequence.
        assert_eq!(canonicalize_proxy_path("loyalty/%ff%fe"), None);
    }

    #[test]
    fn rejects_paths_that_would_reach_the_deny_list_after_normalization() {
        for probe in [
            "products/%2e%2e/products/internal/sync",
            "loyalty/me/%2e%2e/%2e%2e/loyalty/wallets/7",
            "auth/..%2finternal/mint",
        ] {
            assert_eq!(
                canonicalize_proxy_path(probe),
                None,
                "probe leaked: {probe}"
            );
        }
    }
}

/// Percent-encode a canonical path for transmission upstream.
///
/// [`canonicalize_proxy_path`] returns a *decoded* path, which is what the
/// deny-list and allowlist must match against. That string cannot be placed in
/// a URI verbatim — a legitimate segment may contain a space or a non-ASCII
/// character — so it is re-encoded here, per segment.
pub fn encode_path_segments(path: &str) -> String {
    use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};

    /// Everything outside the unreserved / sub-delim sets that may appear in a
    /// path segment. `/` is encoded because segments are joined by the caller.
    const SEGMENT: &AsciiSet = &CONTROLS
        .add(b' ')
        .add(b'"')
        .add(b'#')
        .add(b'<')
        .add(b'>')
        .add(b'?')
        .add(b'`')
        .add(b'{')
        .add(b'}')
        .add(b'%')
        .add(b'^')
        .add(b'|')
        .add(b'\\')
        .add(b'[')
        .add(b']')
        .add(b'/');

    path.split('/')
        .map(|seg| utf8_percent_encode(seg, SEGMENT).to_string())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod encode_tests {
    use super::*;

    #[test]
    fn round_trips_ordinary_paths_unchanged() {
        assert_eq!(
            encode_path_segments("loyalty/settings/vendors/1"),
            "loyalty/settings/vendors/1"
        );
    }

    #[test]
    fn preserves_characters_that_are_legal_in_a_path() {
        // Over-encoding `.` or `-` would break upstreams that match on them.
        assert_eq!(
            encode_path_segments("legacy/pets/report.pdf"),
            "legacy/pets/report.pdf"
        );
        assert_eq!(encode_path_segments("legacy/a-b_c~d"), "legacy/a-b_c~d");
    }

    #[test]
    fn encodes_spaces_and_delimiters() {
        assert_eq!(
            encode_path_segments("legacy/pets/Mr Bigglesworth"),
            "legacy/pets/Mr%20Bigglesworth"
        );
        assert_eq!(encode_path_segments("legacy/a?b"), "legacy/a%3Fb");
        assert_eq!(encode_path_segments("legacy/a#b"), "legacy/a%23b");
    }

    #[test]
    fn encoded_output_is_always_ascii() {
        let out = encode_path_segments("legacy/café/über");
        assert!(out.is_ascii(), "non-ASCII survived encoding: {out}");
    }

    #[test]
    fn re_encoding_cannot_reintroduce_traversal() {
        // canonicalize rejects dot-segments, but if one ever reached the encoder
        // it must not emerge as a live `..` separator.
        assert_eq!(encode_path_segments("a/..%2fb"), "a/..%252fb");
    }
}
