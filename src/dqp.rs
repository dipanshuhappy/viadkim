use crate::parse::{is_hexdig, is_wsp, strip_fws, strip_suffix};
use std::{fmt::Write, str};

// no surrounding or repeated FWS allowed (yes, thanks to tag-value)
pub fn dqp_decode(mut s: &str) -> Result<Vec<u8>, &'static str> {
    if s.is_empty() {
        return Ok(vec![]);
    }

    enum State { Fws, Char }

    let mut state = State::Fws;
    let mut result = Vec::with_capacity(s.len());

    loop {
        match state {
            State::Fws => {
                if let Some(snext) = s.strip_prefix('=') {
                    let (snextq, x) = parse_hex_octet(snext).ok_or("invalid hex octet")?;

                    result.push(x);

                    s = snextq;

                    state = State::Char;
                } else if let Some(snext) = s.strip_prefix(is_dqp_char) {
                    let x = strip_suffix(s, snext);
                    result.extend(x.as_bytes());
                    s = snext;
                    state = State::Char;
                } else {
                    break;
                }
            }
            State::Char => {
                if let Some(snext) = s.strip_prefix('=') {
                    let (snextq, x) = parse_hex_octet(snext).ok_or("invalid hex octet")?;

                    result.push(x);

                    s = snextq;
                } else if let Some(snext) = s.strip_prefix(is_dqp_char) {
                    let x = strip_suffix(s, snext);
                    result.extend(x.as_bytes());
                    s = snext;
                } else if let Some(snext) = strip_fws(s) {
                    s = snext;
                    state = State::Fws;
                } else {
                    break;
                }
            }
        }
    }

    Ok(result)
}

// qp-section := [*(ptext / SPACE / TAB) ptext]
// ptext := hex-octet / safe-char     [= is_dqp_char]
pub fn parse_qp_section(s: &str) -> Option<Vec<u8>> {
    let mut result = Vec::with_capacity(s.len());

    let mut chars = s.chars();

    while let Some(c) = chars.next() {
        if c == '=' {
            let c1 = chars.next().filter(|&c| is_hexdig(c))?;
            let c2 = chars.next().filter(|&c| is_hexdig(c))?;
            let digs = [u8::try_from(c1).unwrap(), u8::try_from(c2).unwrap()];
            let digs = str::from_utf8(&digs).unwrap();
            let b = u8::from_str_radix(digs, 16).ok()?;
            result.push(b);
        } else if is_dqp_char(c) || is_wsp(c) {
            result.push(u8::try_from(c).unwrap());
        } else {
            return None;
        }
    }

    Some(result)
}

pub fn parse_hex_octet(s: &str) -> Option<(&str, u8)> {
    fn parse_hexdig(s: &str) -> Option<(&str, u8)> {
        let s = strip_fws(s).unwrap_or(s);
        let snext = s.strip_prefix(is_hexdig)?;
        let b = s.as_bytes()[0];
        Some((snext, b))
    }

    let (s, u1) = parse_hexdig(s)?;
    let (s, u2) = parse_hexdig(s)?;

    let digs = [u1, u2];
    let digs = str::from_utf8(&digs).unwrap();
    let b = u8::from_str_radix(digs, 16).ok()?;

    Some((s, b))
}

pub fn dqp_encode(mut bytes: &[u8], encode_bar: bool) -> String {
    let mut result = String::with_capacity(bytes.len());

    while !bytes.is_empty() {
        match bstr::decode_utf8(bytes) {
            (Some(c), len) if is_dqp_char(c) && !(c == '|' && encode_bar) => {
                // Some ASCII characters and all non-ASCII Unicode characters
                // can be used as-is. The vertical bar only if it is not encoded.
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

pub fn is_dqp_char(c: char) -> bool {
    // printable ASCII without ; and = plus any non-ASCII UTF-8 sequence
    matches!(c, '!'..=':' | '<' | '>'..='~') || !c.is_ascii()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bstr::BStr;

    #[test]
    fn parse_qp_section_ok() {
        let example = "wha ief o=92fj";
        assert_eq!(parse_qp_section(example), Some(b"wha ief o\x92fj".to_vec()));
    }

    #[test]
    fn dqp_decode_ok() {
        let example =
            "=20v=20 =3     D=20=FF1=\r\n\t3B我=0D=0A=09a=3Drsa-sha256=3B=20s=3Dbrisbane=3B";
        assert_eq!(
            BStr::new(&dqp_decode(&example[..]).unwrap()),
            BStr::new(&b" v = \xff1;\xe6\x88\x91\r\n\ta=rsa-sha256; s=brisbane;"[..])
        );
    }

    #[test]
    fn dqp_encode_ok() {
        let example = b" v = \xff1;\xe6\x88\x91\r\n\ta=rsa-sha256; s=brisbane; v=|";
        assert_eq!(
            BStr::new(&dqp_encode(&example[..], false)),
            BStr::new("=20v=20=3D=20=FF1=3B我=0D=0A=09a=3Drsa-sha256=3B=20s=3Dbrisbane=3B=20v=3D|")
        );
    }
}
