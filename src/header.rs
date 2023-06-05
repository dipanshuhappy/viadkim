//! Representation of email header data.
//!
//! See RFC 5322, section 2.2.
//!
//! API documentation in viadkim uses the term *header* in various places.
//! *Header* is an ambiguous term: it can refer to the entire header section
//! (‘the header is separated from the body by an empty line’), or to an entry
//! in the header section, ie a header field (‘a header that spans multiple
//! lines’), or also to a particular well-known header field by name (‘the
//! *From* header must be present’). Context should make clear which
//! interpretation is appropriate in each case, else the term is disambiguated
//! in some way. See also the note at the end of RFC 5322, section 2.1.

use bstr::ByteSlice;
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    hash::{Hash, Hasher},
    mem,
};

pub type HeaderField = (FieldName, FieldBody);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderFieldError;

/// A collection of header fields that can be used for DKIM processing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderFields(Box<[HeaderField]>);

impl HeaderFields {
    pub fn new(value: impl Into<Box<[HeaderField]>>) -> Result<Self, HeaderFieldError> {
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

// Our `FieldName` allows RFC 5322 header field names; but note that ‘;’ is not
// practical in DKIM.
/// A header field name.
#[derive(Clone, Eq)]
pub struct FieldName(Box<str>);

impl FieldName {
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

impl fmt::Debug for FieldName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
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
    pub fn new(value: impl Into<Box<[u8]>>) -> Result<Self, HeaderFieldError> {
        let value = value.into();

        for (i, line) in value.split_str("\r\n").enumerate() {
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
        write!(f, "{:?}", self.0.as_bstr())
    }
}

/// Parses a header block into header fields. Convenience function.
pub fn parse_header(s: &str) -> Result<HeaderFields, HeaderFieldError> {
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

    HeaderFields::new(headers)
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

// The header validation utility here allows partial checking for RFC 5322
// conformance; see DKIM §3.8: ‘Signers and Verifiers SHOULD take reasonable
// steps to ensure that the messages they are processing are valid according to
// RFC5322, RFC2045, and any other relevant message format standards.’

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HeaderValidationError {
    NoSingleDate,
    NoSingleFrom,
    MultipleSender,
    MultipleReplyTo,
    MultipleTo,
    MultipleCc,
    MultipleBcc,
    MultipleMessageId,
    MultipleInReplyTo,
    MultipleReferences,
    MultipleSubject,
}

impl Display for HeaderValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSingleDate => write!(f, "not exactly one Date header"),
            Self::NoSingleFrom => write!(f, "not exactly one From header"),
            Self::MultipleSender => write!(f, "more than one Sender header"),
            Self::MultipleReplyTo => write!(f, "more than one Reply-To header"),
            Self::MultipleTo => write!(f, "more than one To header"),
            Self::MultipleCc => write!(f, "more than one Cc header"),
            Self::MultipleBcc => write!(f, "more than one Bcc header"),
            Self::MultipleMessageId => write!(f, "more than one Message-ID header"),
            Self::MultipleInReplyTo => write!(f, "more than one In-Reply-To header"),
            Self::MultipleReferences => write!(f, "more than one References header"),
            Self::MultipleSubject => write!(f, "more than one Subject header"),
        }
    }
}

impl Error for HeaderValidationError {}

/// Validates the given header according to RFC 5322, 3.6.
pub fn validate_rfc5322(header: impl AsRef<[HeaderField]>) -> Result<(), HeaderValidationError> {
    fn count_names(header: &[HeaderField], name: &str) -> usize {
        header.iter().filter(|(n, _)| *n == name).count()
    }

    let header = header.as_ref();

    if count_names(header, "Date") != 1 {
        return Err(HeaderValidationError::NoSingleDate);
    }
    if count_names(header, "From") != 1 {
        return Err(HeaderValidationError::NoSingleFrom);
    }
    if count_names(header, "Sender") > 1 {
        return Err(HeaderValidationError::MultipleSender);
    }
    if count_names(header, "Reply-To") > 1 {
        return Err(HeaderValidationError::MultipleReplyTo);
    }
    if count_names(header, "To") > 1 {
        return Err(HeaderValidationError::MultipleTo);
    }
    if count_names(header, "Cc") > 1 {
        return Err(HeaderValidationError::MultipleCc);
    }
    if count_names(header, "Bcc") > 1 {
        return Err(HeaderValidationError::MultipleBcc);
    }
    if count_names(header, "Message-ID") > 1 {
        return Err(HeaderValidationError::MultipleMessageId);
    }
    if count_names(header, "In-Reply-To") > 1 {
        return Err(HeaderValidationError::MultipleInReplyTo);
    }
    if count_names(header, "References") > 1 {
        return Err(HeaderValidationError::MultipleReferences);
    }
    if count_names(header, "Subject") > 1 {
        return Err(HeaderValidationError::MultipleSubject);
    }

    // TODO additional checks? eg MUST have Sender if multiple mailboxes in From

    Ok(())
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
        assert!(FieldBody::new(*b" \na").is_err());
        assert!(FieldBody::new(*b" abc\r\n").is_err());
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

    #[test]
    fn validate_rfc5322_ok() {
        let mut header = vec![
            (
                FieldName::new("Date").unwrap(),
                FieldBody::new(*b" Mon, 22 May 2023 11:59:28 +0200").unwrap(),
            ),
            (
                FieldName::new("From").unwrap(),
                FieldBody::new(*b" me").unwrap(),
            ),
            (
                FieldName::new("To").unwrap(),
                FieldBody::new(*b" you").unwrap(),
            ),
        ];

        assert_eq!(validate_rfc5322(&header), Ok(()));

        header.push((
            FieldName::new("fRom").unwrap(),
            FieldBody::new(*b" me too").unwrap(),
        ));

        assert_eq!(validate_rfc5322(&header), Err(HeaderValidationError::NoSingleFrom));
    }
}
