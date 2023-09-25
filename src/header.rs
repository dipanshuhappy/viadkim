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

//! Representation of email header data.
//!
//! See RFC 5322, section 2.2. The obsolete syntax (eg header field names with
//! trailing whitespace before the colon) is not supported.
//!
//! API documentation in viadkim uses the term *header* in various places.
//! *Header* is an ambiguous term: it can refer to the entire header section
//! (‘the header is separated from the body by an empty line’), or to an entry
//! in the header section, ie a header field (‘a header that spans multiple
//! lines’), or also to a particular well-known header field by name (‘the
//! *From* header must be present’). Context should make clear which
//! interpretation is appropriate in each case, else the term is disambiguated
//! in some way. See also the note at the end of RFC 5322, section 2.1.

use crate::util::BytesDebug;
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    hash::{Hash, Hasher},
    iter, mem,
    str::FromStr,
    vec::IntoIter,
};

/// A pair of header field name and body.
pub type HeaderField = (FieldName, FieldBody);

/// An error that occurs when parsing a header field.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct HeaderFieldError;

impl Display for HeaderFieldError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "failed to process header field")
    }
}

impl Error for HeaderFieldError {}

// Our `FieldName` allows RFC 5322 header field names (minus the obsolete
// syntax); but note that ‘;’ is not practical in DKIM.

/// A header field name.
///
/// # Examples
///
/// ```
/// use viadkim::header::FieldName;
///
/// let name = FieldName::new("From")?;
///
/// assert_eq!(name, "from");
/// assert_ne!(name.as_ref(), "from");
/// # Ok::<_, viadkim::header::HeaderFieldError>(())
/// ```
#[derive(Clone, Eq)]
pub struct FieldName(Box<str>);

impl FieldName {
    /// Creates a new header field name containing the given string.
    ///
    /// # Examples
    ///
    /// ```
    /// use viadkim::header::FieldName;
    ///
    /// assert!(FieldName::new("From").is_ok());
    /// assert!(FieldName::new("From!?#$;").is_ok());
    /// assert!(FieldName::new("From ").is_err());
    /// ```
    pub fn new(value: impl Into<Box<str>>) -> Result<Self, HeaderFieldError> {
        let value = value.into();

        // The name must be composed of printable ASCII except colon.
        if value.is_empty() || !value.chars().all(|c| c.is_ascii_graphic() && c != ':') {
            return Err(HeaderFieldError);
        }

        Ok(Self(value))
    }
}

impl AsRef<str> for FieldName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Display for FieldName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for FieldName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl PartialEq for FieldName {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl PartialEq<&str> for FieldName {
    fn eq(&self, other: &&str) -> bool {
        self.0.eq_ignore_ascii_case(other)
    }
}

impl Hash for FieldName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_ascii_lowercase().hash(state);
    }
}

/// A header field body, colloquially known as a ‘header value’.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct FieldBody(Box<[u8]>);

impl FieldBody {
    /// Creates a new header field body containing the given bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use viadkim::header::FieldBody;
    ///
    /// assert!(FieldBody::new(*b" Hey!").is_ok());
    /// assert!(FieldBody::new(*b" Hey\nyou!").is_err());
    /// assert!(FieldBody::new(*b" Hey\n\tyou!").is_err());
    /// assert!(FieldBody::new(*b" Hey\r\n\tyou!").is_ok());
    /// ```
    pub fn new(value: impl Into<Box<[u8]>>) -> Result<Self, HeaderFieldError> {
        let value = value.into();

        for (i, line) in split_crlf(&value).enumerate() {
            // If there are any control characters in the line, including stray
            // CR and LF, return error. All other bytes (including Latin 1, or
            // malformed UTF-8) are allowed.
            if line.iter().any(|b| b.is_ascii_control() && *b != b'\t') {
                return Err(HeaderFieldError);
            }

            if i != 0 {
                // Continuation lines must be ‘folded’, ie start with WSP.
                if !line.starts_with(b" ") && !line.starts_with(b"\t") {
                    return Err(HeaderFieldError);
                }
                // The rest of the continuation line must not be WSP-only.
                if line.iter().all(|b| matches!(b, b' ' | b'\t')) {
                    return Err(HeaderFieldError);
                }
            }
        }

        Ok(Self(value))
    }
}

impl AsRef<[u8]> for FieldBody {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for FieldBody {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &BytesDebug(&self.0))
    }
}

fn split_crlf(mut value: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut done = false;

    iter::from_fn(move || {
        if done {
            None
        } else if let Some(i) = value.windows(2).position(|b| b == b"\r\n") {
            let (chunk, rest) = value.split_at(i);
            value = &rest[2..];
            Some(chunk)
        } else {
            done = true;
            Some(value)
        }
    })
}

/// A collection of header fields that can be used for DKIM processing.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct HeaderFields(Vec<HeaderField>);

impl HeaderFields {
    pub fn new(value: impl Into<Vec<HeaderField>>) -> Result<Self, HeaderFieldError> {
        let value = value.into();
        if value.is_empty() {
            return Err(HeaderFieldError);
        }
        Ok(Self(value))
    }

    pub fn from_vec(value: Vec<(String, Vec<u8>)>) -> Result<Self, HeaderFieldError> {
        let value: Vec<_> = value
            .into_iter()
            .map(|(name, value)| {
                let name = FieldName::new(name)?;
                let body = FieldBody::new(value)?;
                Ok((name, body))
            })
            .collect::<Result<_, _>>()?;
        Self::new(value)
    }
}

impl AsRef<[HeaderField]> for HeaderFields {
    fn as_ref(&self) -> &[HeaderField] {
        &self.0
    }
}

impl From<HeaderFields> for Vec<HeaderField> {
    fn from(header_fields: HeaderFields) -> Self {
        header_fields.0
    }
}

impl IntoIterator for HeaderFields {
    type Item = HeaderField;
    type IntoIter = IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl FromStr for HeaderFields {
    type Err = HeaderFieldError;

    /// Parses a header block into header fields.
    ///
    /// This function uses [`str::lines`] to split the input into lines, and
    /// therefore accepts both LF and CRLF line breaks.
    ///
    /// # Examples
    ///
    /// ```
    /// use viadkim::header::HeaderFields;
    ///
    /// let headers: HeaderFields = "\
    /// Date: Thu, 22 Jun 2023 09:29:22 +0200
    /// From: me <me@example.com>
    /// To: you <you@example.com>
    /// Subject: hi
    ///   dear!
    /// ".parse()?;
    ///
    /// assert_eq!(headers.as_ref().len(), 4);
    /// # Ok::<_, viadkim::header::HeaderFieldError>(())
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut lines = s.lines();

        let first_line = lines.next()
            .filter(|l| !is_continuation_line(l))
            .ok_or(HeaderFieldError)?;

        let (mut name, mut value) = split_header_field(first_line)?;

        let mut headers = vec![];

        for line in lines {
            if is_continuation_line(line) {
                value.extend(b"\r\n");
                value.extend(line.bytes());
            } else {
                let (next_name, next_value) = split_header_field(line)?;
                let name = mem::replace(&mut name, next_name);
                let value = mem::replace(&mut value, next_value);
                let value = FieldBody::new(value)?;
                headers.push((name, value));
            }
        }

        let value = FieldBody::new(value)?;
        headers.push((name, value));

        Self::new(headers)
    }
}

fn is_continuation_line(s: &str) -> bool {
    s.starts_with(' ') || s.starts_with('\t')
}

fn split_header_field(s: &str) -> Result<(FieldName, Vec<u8>), HeaderFieldError> {
    let (name, value) = s.split_once(':').ok_or(HeaderFieldError)?;

    let name = FieldName::new(name)?;
    let value = value.bytes().collect();

    Ok((name, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_name_ok() {
        assert!(FieldName::new("abc").is_ok());

        assert!(FieldName::new("").is_err());
        assert!(FieldName::new("abc ").is_err());
        assert!(FieldName::new("a:c").is_err());
    }

    #[test]
    fn field_body_ok() {
        assert!(FieldBody::new(*b"").is_ok());
        assert!(FieldBody::new(*b"abc").is_ok());
        assert!(FieldBody::new(*b" ab\r\n\tcd ").is_ok());
        assert!(FieldBody::new(*b"\r\n\ta").is_ok());
        assert!(FieldBody::new(*b"  ").is_ok());

        assert!(FieldBody::new(*b" \r\na").is_err());
        assert!(FieldBody::new(*b" \r\n\r\n a").is_err());
        assert!(FieldBody::new(*b" \r\n \r\n a").is_err());
        assert!(FieldBody::new(*b" \ra").is_err());
        assert!(FieldBody::new(*b" \na").is_err());
        assert!(FieldBody::new(*b" abc\r\n").is_err());
    }

    #[test]
    fn split_crlf_ok() {
        assert!(split_crlf(b"").eq([b""]));
        assert!(split_crlf(b"a").eq([b"a"]));
        assert!(split_crlf(b"\r").eq([b"\r"]));
        assert!(split_crlf(b"\rb").eq([b"\rb"]));
        assert!(split_crlf(b"\r\n").eq([b"", b""]));
        assert!(split_crlf(b"a\r\n").eq([&b"a"[..], &b""[..]]));
        assert!(split_crlf(b"\r\nb").eq([&b""[..], &b"b"[..]]));
        assert!(split_crlf(b"\r\n\r\n").eq([b"", b"", b""]));

        assert!(split_crlf(b"ab\r\n\r\nc\r\r\n\rde\r").eq([
            &b"ab"[..],
            &b""[..],
            &b"c\r"[..],
            &b"\rde\r"[..]
        ]));
    }

    #[test]
    fn header_fields_ok() {
        assert!(HeaderFields::new([
            (
                FieldName::new("From").unwrap(),
                FieldBody::new(*b" me").unwrap()
            ),
            (
                FieldName::new("To").unwrap(),
                FieldBody::new(*b" you (yes,\r\n\t you!)").unwrap()
            ),
        ])
        .is_ok());
    }
}
