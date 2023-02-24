//! Representation of email header data.

use bstr::ByteSlice;
use std::{
    fmt::{self, Debug, Formatter},
    hash::{Hash, Hasher},
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

// TODO FieldName allows RFC 5322 header field names; but note that ';' is not practical in DKIM
// the only place where ';' in FieldName is a problem is when constructing the
// SigningRequest (and to some degree when manually constructing DkimSignature)
#[derive(Clone, Eq)]
pub struct FieldName(Box<str>);

impl FieldName {
    pub fn new(value: impl Into<Box<str>>) -> Result<Self, HeaderFieldError> {
        let value = value.into();
        if value.is_empty() {
            return Err(HeaderFieldError);
        }
        if !value.chars().all(|c| c.is_ascii_graphic() && c != ':') {
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

impl Debug for FieldName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
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

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct FieldBody(Box<[u8]>);

impl FieldBody {
    pub fn new(value: impl Into<Box<[u8]>>) -> Result<Self, HeaderFieldError> {
        let value = value.into();
        // only folded continuation lines:
        if !(value.split_str("\r\n").skip(1).all(|line| line.starts_with(b" ") || line.starts_with(b"\t"))) {
            return Err(HeaderFieldError);
        }
        // no empty or blank lines past the first one, no trailing CRLF:
        if !(value.split_str("\r\n").skip(1).all(|line| !line.trim_with(|c| matches!(c, ' ' | '\t')).is_empty())) {
            return Err(HeaderFieldError);
        }
        // no stray CR and LF
        if !(value.split_str("\r\n").all(|line| !line.contains(&b'\r') && !line.contains(&b'\n'))) {
            return Err(HeaderFieldError);
        }
        // allow all other bytes, UTF-8 not required to accomodate eg mistaken Latin 1 bytes
        Ok(Self(value))
    }
}

impl AsRef<[u8]> for FieldBody {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for FieldBody {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("FieldBody")
            .field(&self.0.as_bstr())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_name_ok() {
        assert!(FieldName::new("abc").is_ok());

        assert!(FieldName::new("abc ").is_err());
        assert!(FieldName::new("a:c").is_err());
    }

    #[test]
    fn field_body_ok() {
        assert!(FieldBody::new(*b" ab\r\n\tcd ").is_ok());
        assert!(FieldBody::new(*b"\r\n\ta").is_ok());
        assert!(FieldBody::new(*b"  ").is_ok());

        assert!(FieldBody::new(*b" \r\na").is_err());
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
}
