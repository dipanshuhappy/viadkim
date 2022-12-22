use bstr::{BStr, ByteSlice};
use std::fmt::{self, Debug, Formatter};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderFieldError;

/// A collection of header fields that can be used for DKIM processing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderFields(Vec<(FieldName, FieldBody)>);

impl HeaderFields {
    pub fn new(value: impl Into<Vec<(FieldName, FieldBody)>>) -> Result<Self, HeaderFieldError> {
        let value = value.into();
        // no empty vec or vec without "From" (TODO ?)
        if !(value.iter().any(|(name, _)| name.0.eq_ignore_ascii_case("From"))) {
            return Err(HeaderFieldError);
        }
        // TODO...
        Ok(Self(value))
    }

    pub fn from_vec(value: Vec<(String, Vec<u8>)>) -> Result<Self, HeaderFieldError> {
        let v = value.into_iter()
            .map(|(name, value)| {
                let name = FieldName::new(name)?;
                let body = FieldBody::new(value)?;
                Ok((name, body))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self(v))
    }
}

impl AsRef<[(FieldName, FieldBody)]> for HeaderFields {
    fn as_ref(&self) -> &[(FieldName, FieldBody)] {
        &self.0
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct FieldName(String);

impl FieldName {
    pub fn new(value: impl Into<String>) -> Result<Self, HeaderFieldError> {
        let value = value.into();
        if value.is_empty() {
            return Err(HeaderFieldError);
        }
        if !(value.chars().all(|c| c.is_ascii_graphic() && !matches!(c, ':' | ';'))) {
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

#[derive(Clone, PartialEq, Eq)]
pub struct FieldBody(Vec<u8>);

impl FieldBody {
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, HeaderFieldError> {
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
            .field(&BStr::new(&self.0))
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
        assert!(FieldBody::new(b" ab\r\n\tcd ".to_vec()).is_ok());
        assert!(FieldBody::new(b"\r\n\ta".to_vec()).is_ok());
        assert!(FieldBody::new(b"  ".to_vec()).is_ok());

        assert!(FieldBody::new(b" \r\na".to_vec()).is_err());
        assert!(FieldBody::new(b" \r\n \r\n a".to_vec()).is_err());
        assert!(FieldBody::new(b" \na".to_vec()).is_err());
        assert!(FieldBody::new(b" abc\r\n".to_vec()).is_err());
    }

    #[test]
    fn header_fields_ok() {
        assert!(HeaderFields::new(vec![
            (FieldName::new("From").unwrap(), FieldBody::new(b" me".to_vec()).unwrap()),
            (FieldName::new("To").unwrap(), FieldBody::new(b" you (yes,\r\n\t you!)".to_vec()).unwrap()),
        ]).is_ok());
    }
}
