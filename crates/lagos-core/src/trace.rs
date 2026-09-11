//! W3C Trace Context.
//!
//! The gateway is a hop, so it has to *participate* in a trace rather than
//! relay one. Forwarding `traceparent` untouched — the obvious thing, and what
//! a header allowlist does by default — makes the upstream's span a child of
//! the **client's** span, and the gateway never appears in the trace at all.
//! Every bit of latency it adds then looks like the upstream's.
//!
//! So an incoming context is continued: the trace id and sampling flags are
//! kept, and a fresh span id is generated for this hop and sent upstream. A
//! request arriving with no context starts one.
//!
//! Format, from the [W3C recommendation]: `00-<32 hex trace id>-<16 hex parent
//! id>-<2 hex flags>`.
//!
//! [W3C recommendation]: https://www.w3.org/TR/trace-context/

use std::fmt::Write as _;

/// The sampling bit of `trace-flags`.
pub const FLAG_SAMPLED: u8 = 0x01;

/// An all-zero id is invalid per the specification, and treating one as valid
/// would produce a trace nothing can join.
const ZERO_TRACE: [u8; 16] = [0; 16];
const ZERO_SPAN: [u8; 8] = [0; 8];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceContext {
    pub trace_id: [u8; 16],
    /// This hop's span id — what an upstream sees as its parent.
    pub span_id: [u8; 8],
    /// The span this hop continues from, if the request arrived with one.
    pub parent_span_id: Option<[u8; 8]>,
    pub flags: u8,
}

impl TraceContext {
    /// Continue `incoming`, or start a fresh trace when it is absent or
    /// unparseable.
    ///
    /// A malformed header is treated as absent rather than as an error: a
    /// broken trace must never fail a request.
    pub fn continue_from(incoming: Option<&str>, sampled: bool) -> Self {
        match incoming.and_then(parse_traceparent) {
            Some((trace_id, parent_span_id, flags)) => Self {
                trace_id,
                span_id: random_span_id(),
                parent_span_id: Some(parent_span_id),
                // The upstream decision is honoured: re-deciding partway
                // through would produce a trace with holes in it.
                flags,
            },
            None => Self {
                trace_id: random_trace_id(),
                span_id: random_span_id(),
                parent_span_id: None,
                flags: if sampled { FLAG_SAMPLED } else { 0 },
            },
        }
    }

    pub fn sampled(&self) -> bool {
        self.flags & FLAG_SAMPLED != 0
    }

    /// The `traceparent` to send upstream, naming this hop as the parent.
    pub fn to_header(&self) -> String {
        let mut out = String::with_capacity(55);
        out.push_str("00-");
        write_hex(&mut out, &self.trace_id);
        out.push('-');
        write_hex(&mut out, &self.span_id);
        let _ = write!(out, "-{:02x}", self.flags);
        out
    }

    pub fn trace_id_hex(&self) -> String {
        let mut out = String::with_capacity(32);
        write_hex(&mut out, &self.trace_id);
        out
    }

    pub fn span_id_hex(&self) -> String {
        let mut out = String::with_capacity(16);
        write_hex(&mut out, &self.span_id);
        out
    }
}

fn write_hex(out: &mut String, bytes: &[u8]) {
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
}

/// Ids must be unpredictable, so they come from the OS CSPRNG (via `uuid`'s
/// v4 generator) rather than from a counter or a cheap PRNG.
fn random_trace_id() -> [u8; 16] {
    *uuid::Uuid::new_v4().as_bytes()
}

fn random_span_id() -> [u8; 8] {
    let bytes = *uuid::Uuid::new_v4().as_bytes();
    let mut id = [0u8; 8];
    id.copy_from_slice(bytes.get(..8).unwrap_or(&[0; 8]));
    id
}

/// Parse `00-<trace id>-<parent id>-<flags>`.
///
/// Returns `None` for anything that does not conform. Later versions are
/// accepted so long as the first four fields are well-formed — the
/// specification requires forward compatibility, and refusing an unknown
/// version would break every request once vendors move past `00`.
fn parse_traceparent(raw: &str) -> Option<([u8; 16], [u8; 8], u8)> {
    let raw = raw.trim();
    let mut parts = raw.split('-');
    let version = parts.next()?;
    let trace_id = parts.next()?;
    let parent_id = parts.next()?;
    let flags = parts.next()?;

    // `ff` is explicitly forbidden as a version.
    if version.len() != 2 || !is_hex(version) || version == "ff" {
        return None;
    }
    // Version 00 has exactly four fields; later ones may add more.
    if version == "00" && parts.next().is_some() {
        return None;
    }
    if trace_id.len() != 32 || !is_hex(trace_id) {
        return None;
    }
    if parent_id.len() != 16 || !is_hex(parent_id) {
        return None;
    }
    if flags.len() != 2 || !is_hex(flags) {
        return None;
    }

    let trace = hex16(trace_id)?;
    let parent = hex8(parent_id)?;
    if trace == ZERO_TRACE || parent == ZERO_SPAN {
        return None;
    }
    let flags = u8::from_str_radix(flags, 16).ok()?;
    Some((trace, parent, flags))
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn hex16(s: &str) -> Option<[u8; 16]> {
    let mut out = [0u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        let start = i.checked_mul(2)?;
        let byte = s.get(start..start.checked_add(2)?)?;
        *slot = u8::from_str_radix(byte, 16).ok()?;
    }
    Some(out)
}

fn hex8(s: &str) -> Option<[u8; 8]> {
    let mut out = [0u8; 8];
    for (i, slot) in out.iter_mut().enumerate() {
        let start = i.checked_mul(2)?;
        let byte = s.get(start..start.checked_add(2)?)?;
        *slot = u8::from_str_radix(byte, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    #[test]
    fn an_incoming_trace_is_continued_not_replaced() {
        let cx = TraceContext::continue_from(Some(VALID), false);
        assert_eq!(cx.trace_id_hex(), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(
            cx.parent_span_id.map(|p| {
                let mut s = String::new();
                write_hex(&mut s, &p);
                s
            }),
            Some("00f067aa0ba902b7".to_string())
        );
    }

    #[test]
    fn this_hop_gets_its_own_span_id() {
        // Relaying the header untouched is what hides the gateway from the
        // trace: the upstream would parent to the client instead of to us.
        let cx = TraceContext::continue_from(Some(VALID), false);
        assert_ne!(cx.span_id_hex(), "00f067aa0ba902b7");
        assert_ne!(cx.to_header(), VALID);
        assert!(
            cx.to_header()
                .starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-")
        );
    }

    #[test]
    fn the_sampling_decision_is_honoured() {
        // Re-deciding partway through a trace produces one with holes in it.
        let sampled = TraceContext::continue_from(Some(VALID), false);
        assert!(sampled.sampled(), "upstream said sampled");

        let not = TraceContext::continue_from(
            Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"),
            true,
        );
        assert!(!not.sampled(), "upstream said not sampled");
    }

    #[test]
    fn a_request_with_no_context_starts_one() {
        let cx = TraceContext::continue_from(None, true);
        assert!(cx.parent_span_id.is_none());
        assert!(cx.sampled());
        assert_eq!(cx.trace_id_hex().len(), 32);
        assert_eq!(cx.span_id_hex().len(), 16);
    }

    #[test]
    fn ids_are_not_predictable() {
        let a = TraceContext::continue_from(None, true);
        let b = TraceContext::continue_from(None, true);
        assert_ne!(a.trace_id, b.trace_id);
        assert_ne!(a.span_id, b.span_id);
    }

    #[test]
    fn the_header_is_well_formed() {
        let cx = TraceContext::continue_from(None, true);
        let header = cx.to_header();
        assert_eq!(header.len(), 55, "{header}");
        assert!(parse_traceparent(&header).is_some(), "must round-trip");
    }

    #[test]
    fn a_malformed_header_starts_a_fresh_trace_rather_than_failing() {
        // A broken trace must never fail a request.
        for bad in [
            "",
            "garbage",
            "00-tooshort-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-short-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-zz",
            // All-zero ids are invalid per the specification.
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            // `ff` is a forbidden version.
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            // Version 00 takes exactly four fields.
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
        ] {
            assert!(parse_traceparent(bad).is_none(), "`{bad}` should not parse");
            let cx = TraceContext::continue_from(Some(bad), true);
            assert!(cx.parent_span_id.is_none(), "`{bad}` should start fresh");
        }
    }

    #[test]
    fn a_later_version_is_still_accepted() {
        // The specification requires forward compatibility; refusing an unknown
        // version would break every request once vendors move past `00`.
        let future = "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-something";
        let cx = TraceContext::continue_from(Some(future), false);
        assert_eq!(cx.trace_id_hex(), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert!(cx.parent_span_id.is_some());
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        let cx = TraceContext::continue_from(Some(&format!("  {VALID}  ")), false);
        assert_eq!(cx.trace_id_hex(), "4bf92f3577b34da6a3ce929d0e0e4736");
    }
}
