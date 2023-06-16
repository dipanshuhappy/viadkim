//! Common parsing utilities.

pub fn strip_suffix<'a>(s: &'a str, suffix: &str) -> &'a str {
    debug_assert!(s.ends_with(suffix));
    &s[..(s.len() - suffix.len())]
}

const CRLF: &str = "\r\n";

// FWS = ([*WSP CRLF] 1*WSP)

/// Strips one occurrence of folding whitespace.
pub fn strip_fws(input: &str) -> Option<&str> {
    // Implementation note: We had considered a more eager, ‘look-ahead’
    // approach that refuses to strip `"  \r\nabc..."`. However, this would be
    // inconsistent with the usual idiom, that strip_ simply eats as many valid
    // characters as possible, and if any are possible it is a success.
    if let Some(s) = strip_wsp(input) {
        s.strip_prefix(CRLF).and_then(strip_wsp).or(Some(s))
    } else {
        input.strip_prefix(CRLF).and_then(strip_wsp)
    }
}

pub fn rstrip_fws(input: &str) -> Option<&str> {
    let s = rstrip_wsp(input)?;
    match s.strip_suffix(CRLF) {
        Some(s) => rstrip_wsp(s).or(Some(s)),
        None => Some(s),
    }
}

// RFC 5234, appendix B.1

fn strip_wsp(input: &str) -> Option<&str> {
    input
        .strip_prefix(is_wsp)
        .map(|s| s.trim_start_matches(is_wsp))
}

fn rstrip_wsp(input: &str) -> Option<&str> {
    input
        .strip_suffix(is_wsp)
        .map(|s| s.trim_end_matches(is_wsp))
}

pub fn is_wsp(c: char) -> bool {
    matches!(c, ' ' | '\t')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_fws_ok() {
        assert_eq!(strip_fws(""), None);
        assert_eq!(strip_fws("x"), None);
        assert_eq!(strip_fws(" x"), Some("x"));
        assert_eq!(strip_fws("\r\n"), None);
        assert_eq!(strip_fws(" \r\n"), Some("\r\n"));
        assert_eq!(strip_fws(" \r\nx"), Some("\r\nx"));
        assert_eq!(strip_fws(" \r\n "), Some(""));
        assert_eq!(strip_fws(" \r\n x"), Some("x"));
        assert_eq!(strip_fws("\r\nx"), None);
        assert_eq!(strip_fws("\r\n x"), Some("x"));
    }

    #[test]
    fn rstrip_fws_ok() {
        assert_eq!(rstrip_fws(""), None);
        assert_eq!(rstrip_fws("x"), None);
        assert_eq!(rstrip_fws("x "), Some("x"));
        assert_eq!(rstrip_fws("\r\n"), None);
        assert_eq!(rstrip_fws("x\r\n "), Some("x"));
        assert_eq!(rstrip_fws("x \r\n "), Some("x"));
    }
}
