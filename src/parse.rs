// Parsing utilities.

// TODO

const CRLF: &str = "\r\n";

// FWS = ([*WSP CRLF] 1*WSP)
pub fn strip_fws(input: &str) -> Option<&str> {
    if let Some(s) = strip_wsp(input) {
        if let Some(s) = s.strip_prefix(CRLF) {
            strip_wsp(s)
        } else {
            Some(s)
        }
    } else {
        input.strip_prefix(CRLF).and_then(strip_wsp)
    }
}

pub fn strip_suffix<'a>(s: &'a str, suffix: &str) -> &'a str {
    debug_assert!(s.ends_with(suffix));
    &s[..(s.len() - suffix.len())]
}

// RFC 5234, appendix B.1

fn strip_wsp(input: &str) -> Option<&str> {
    input
        .strip_prefix(is_wsp)
        .map(|s| s.trim_start_matches(is_wsp))
}

pub fn is_wsp(c: char) -> bool {
    matches!(c, ' ' | '\t')
}

pub fn is_hexdig(c: char) -> bool {
    c.is_ascii_hexdigit()
}
