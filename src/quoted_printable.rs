//! DKIM-Quoted-Printable encoding. See RFC 6376, section 2.11.

use crate::parse::{is_wsp, strip_fws, strip_suffix};
use bstr::ByteVec;
use std::fmt::Write;

/// Encodes bytes as a DKIM-Quoted-Printable string.
pub fn encode(mut bytes: &[u8], encode_bar: bool) -> String {
    let mut result = String::with_capacity(bytes.len());

    while !bytes.is_empty() {
        match bstr::decode_utf8(bytes) {
            (Some(c), len) if is_dkim_safe_char(c) && !(c == '|' && encode_bar) => {
                // Some ASCII characters (maybe including the vertical bar) and
                // all non-ASCII Unicode characters can be used as-is.
                result.push(c);
                bytes = &bytes[len..];
            }
            _ => {
                // Some ASCII, and non-UTF-8 non-ASCII characters need encoding.
                write!(result, "={:02X}", bytes[0]).unwrap();
                bytes = &bytes[1..];
            }
        }
    }

    result
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotedPrintableError;

/// Decodes the bytes in a DKIM-Quoted-Printable-encoded string.
pub fn decode(mut s: &str) -> Result<Vec<u8>, QuotedPrintableError> {
    fn strip_dkim_safe_chars(input: &str) -> Option<&str> {
        input
            .strip_prefix(is_dkim_safe_char)
            .map(|s| s.trim_start_matches(is_dkim_safe_char))
    }

    enum State { Char, Fws }

    let mut state = State::Char;
    let mut result = Vec::with_capacity(s.len());

    loop {
        match state {
            State::Char => {
                if let Some(snext) = s.strip_prefix('=') {
                    let (snext, x) = strip_hex_octet(snext).ok_or(QuotedPrintableError)?;
                    result.push(x);
                    s = snext;
                } else if let Some(snext) = strip_dkim_safe_chars(s) {
                    result.extend(strip_suffix(s, snext).bytes());
                    s = snext;
                } else if let Some(snext) = strip_fws(s) {
                    s = snext;
                    state = State::Fws;
                } else {
                    break;
                }
            }
            State::Fws => {
                if let Some(snext) = s.strip_prefix('=') {
                    let (snext, x) = strip_hex_octet(snext).ok_or(QuotedPrintableError)?;
                    result.push(x);
                    s = snext;
                    state = State::Char;
                } else if let Some(snext) = strip_dkim_safe_chars(s) {
                    result.extend(strip_suffix(s, snext).bytes());
                    s = snext;
                    state = State::Char;
                } else if strip_fws(s).is_some() {
                    return Err(QuotedPrintableError);
                } else {
                    break;
                }
            }
        }
    }

    if s.is_empty() {
        Ok(result)
    } else {
        Err(QuotedPrintableError)
    }
}

fn strip_hex_octet(s: &str) -> Option<(&str, u8)> {
    fn strip_hexdig(s: &str) -> Option<(&str, u8)> {
        let s = strip_fws(s).unwrap_or(s);
        let snext = s.strip_prefix(is_hexdig)?;
        let b = s.as_bytes()[0];
        Some((snext, b))
    }

    let (s, digit1) = strip_hexdig(s)?;
    let (s, digit2) = strip_hexdig(s)?;

    let b = u8_from_digits(digit1, digit2);

    Some((s, b))
}

// This is slightly modified from RFC 2045, section 6.7: It uses RFC 6376’s
// *dkim-safe-char*, also allowing UTF-8 content. Linear whitespace between
// tokens and at the beginning and end is accepted.

/// Decodes the bytes in an RFC 2045 *qp-section*.
pub fn decode_qp_section(s: &str) -> Result<Vec<u8>, QuotedPrintableError> {
    let mut result = Vec::with_capacity(s.len());

    let mut chars = s.chars();

    while let Some(c) = chars.next() {
        if c == '=' {
            let c1 = chars.next().filter(|&c| is_hexdig(c))
                .ok_or(QuotedPrintableError)?;
            let c2 = chars.next().filter(|&c| is_hexdig(c))
                .ok_or(QuotedPrintableError)?;

            let digit1 = u8::try_from(c1).unwrap();
            let digit2 = u8::try_from(c2).unwrap();

            let b = u8_from_digits(digit1, digit2);

            result.push(b);
        } else if is_dkim_safe_char(c) || is_wsp(c) {
            result.push_char(c);
        } else {
            return Err(QuotedPrintableError);
        }
    }

    Ok(result)
}

fn u8_from_digits(c1: u8, c2: u8) -> u8 {
    // Strictly speaking, only uppercase hex digits are allowed in (DKIM-)
    // Quoted-Printable, but there is no harm in accepting lowercase, too.
    fn to_u8(c: u8) -> u8 {
        match c {
            b'0' => 0,
            b'1' => 0x1,
            b'2' => 0x2,
            b'3' => 0x3,
            b'4' => 0x4,
            b'5' => 0x5,
            b'6' => 0x6,
            b'7' => 0x7,
            b'8' => 0x8,
            b'9' => 0x9,
            b'A' | b'a' => 0xa,
            b'B' | b'b' => 0xb,
            b'C' | b'c' => 0xc,
            b'D' | b'd' => 0xd,
            b'E' | b'e' => 0xe,
            b'F' | b'f' => 0xf,
            _ => unreachable!(),
        }
    }

    debug_assert!(c1.is_ascii_hexdigit() && c2.is_ascii_hexdigit());

    to_u8(c1) * 0x10 + to_u8(c2)
}

fn is_dkim_safe_char(c: char) -> bool {
    // printable ASCII without ; and = plus any non-ASCII UTF-8
    matches!(c, '!'..=':' | '<' | '>'..='~') || !c.is_ascii()
}

fn is_hexdig(c: char) -> bool {
    c.is_ascii_hexdigit()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bstr::ByteSlice;

    #[test]
    fn encode_basic() {
        let s = encode(b"abc|; d\xf0\x9f\x8f\xa0\xfee", true);
        assert_eq!(s, "abc=7C=3B=20d🏠=FEe");
    }

    #[test]
    fn encode_tag_list() {
        let example = b" v = \xff1;\xe6\x88\x91\r\n\ta=rsa-sha256; s=brisbane; v=|";
        assert_eq!(
            encode(example, false),
            "=20v=20=3D=20=FF1=3B我=0D=0A=09a=3Drsa-sha256=3B=20s=3Dbrisbane=3B=20v=3D|"
        );
    }

    #[test]
    fn decode_basic() {
        assert_eq!(decode(""), Ok(vec![]));
        assert_eq!(decode("\t"), Ok(vec![]));
        assert_eq!(decode("\t\r\n\t"), Ok(vec![]));
        assert_eq!(decode(" ab "), Ok(b"ab".to_vec()));
        assert_eq!(decode(" ab cd "), Ok(b"abcd".to_vec()));
        assert_eq!(decode(" ab\r\n cd "), Ok(b"abcd".to_vec()));
        assert_eq!(decode("abc我"), Ok(b"abc\xe6\x88\x91".to_vec()));

        assert_eq!(decode("\t\r\n"), Err(QuotedPrintableError));
        assert_eq!(decode("\t\r\n\t\r\n\t"), Err(QuotedPrintableError));
        assert_eq!(decode("ab;cd"), Err(QuotedPrintableError));
    }

    #[test]
    fn decode_tag_list() {
        let example = "=20v=20 =3     D=20=FF1=\r\n\t3B我=0D=0A=09a=3Drsa-sha256=3B=20s=3Dbrisbane=3B";
        assert_eq!(
            decode(example).unwrap().as_bstr(),
            &b" v = \xff1;\xe6\x88\x91\r\n\ta=rsa-sha256; s=brisbane;"[..]
        );
    }

    #[test]
    fn decode_qp_section_ok() {
        let example = " wha i☮ ef o=92fj";
        assert_eq!(decode_qp_section(example), Ok(b" wha i\xe2\x98\xae ef o\x92fj".to_vec()));
    }
}
