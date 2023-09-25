// viadkim – implementation of the DKIM specification
// Copyright © 2022–2023 David Bürgin <dbuergin@gluet.ch>
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.

use base64ct::{Base64, Encoding};
use std::{
    error::Error,
    fmt::{self, Display, Formatter, Write},
    str,
};

/// A trait for entities that have a canonical string representation in the DKIM
/// specification.
pub trait CanonicalStr {
    /// Returns the canonical representation as a static string slice.
    fn canonical_str(&self) -> &'static str;
}

/// Encodes binary data as a Base64 string.
pub fn encode_base64<T: AsRef<[u8]>>(input: T) -> String {
    Base64::encode_string(input.as_ref())
}

/// An error that occurs when decoding Base64-encoded data.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Base64Error;

impl Display for Base64Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "failed to decode Base64 data")
    }
}

impl Error for Base64Error {}

/// Decodes binary data from a Base64-encoded string.
pub fn decode_base64(input: &str) -> Result<Vec<u8>, Base64Error> {
    Base64::decode_vec(input).map_err(|_| Base64Error)
}

/// Helper for Base64 `fmt::Debug` implementations for byte slices.
pub struct Base64Debug<'a>(pub &'a [u8]);

impl fmt::Debug for Base64Debug<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // This displays the byte slice as Base64, without the surrounding
        // double quotes usually used for strings.
        //
        // The awkward implementation is due to the possibility of empty byte
        // slices. In these cases, `write!(f, "{}", …)` prints nothing at all,
        // which looks unpleasant. This implementation introduces a wrapping
        // `Base64(…)` pseudo-tuple, and `Empty` for empty slices.

        struct Base64DebugHelper<'a>(&'a str);

        impl fmt::Debug for Base64DebugHelper<'_> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        let s = encode_base64(self.0);

        if s.is_empty() {
            write!(f, "Empty")
        } else {
            f.debug_tuple("Base64")
                .field(&Base64DebugHelper(&s))
                .finish()
        }
    }
}

/// Helper for string-like `fmt::Debug` implementations for byte slices.
pub struct BytesDebug<'a>(pub &'a [u8]);

impl fmt::Debug for BytesDebug<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut bytes = self.0;

        f.write_char('"')?;

        while !bytes.is_empty() {
            if let Some(chunk) = next_utf8_chunk(bytes) {
                // Unfortunately, `str::escape_debug` is different from `str`’s
                // Debug implementation in its unnecessary escaping of single
                // quotes. This is the standard library’s fault, not ours.
                for c in chunk.escape_debug() {
                    f.write_char(c)?;
                }
                bytes = &bytes[chunk.len()..];
            } else {
                write!(f, "\\x{:02x}", bytes[0])?;
                bytes = &bytes[1..];
            }
        }

        f.write_char('"')?;

        Ok(())
    }
}

/// Returns the longest non-empty string that can be decoded from valid UTF-8 at
/// the start of the input.
pub fn next_utf8_chunk(input: &[u8]) -> Option<&str> {
    match str::from_utf8(input) {
        Ok(s) => {
            if !s.is_empty() {
                return Some(s);
            }
        }
        Err(e) => {
            let i = e.valid_up_to();
            if i > 0 {
                return Some(str::from_utf8(&input[..i]).unwrap());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_debug_ok() {
        assert_eq!(format!("{:?}", Base64Debug(&[])), "Empty");
        assert_eq!(format!("{:?}", Base64Debug(&[1, 2, 3])), "Base64(AQID)");
    }

    #[test]
    fn bytes_debug_string() {
        // `BytesDebug` formatting should generally match `str`’s Debug output.
        let examples = [
            ("", r#""""#),
            ("hoi du", r#""hoi du""#),
            ("x\ny", r#""x\ny""#),
            ("\t\r", r#""\t\r""#),
            ("你好", r#""你好""#),
        ];

        for (input, expected) in examples {
            assert_eq!(format!("{:?}", input), expected);
            assert_eq!(format!("{:?}", BytesDebug(input.as_bytes())), expected);
        }

        // Notable exception: `str::escape_debug` escapes single quotes. It
        // really shouldn’t.
        assert_eq!(format!("{:?}", "\"'"), r#""\"'""#);
        assert_eq!(format!("{:?}", BytesDebug(b"\"'")), r#""\"\'""#);
    }

    #[test]
    fn bytes_debug_bytes() {
        assert_eq!(
            format!("{:?}", BytesDebug(b"a\x00\xfe\xc3\xbc")),
            r#""a\0\xfeü""#
        );
    }
}
