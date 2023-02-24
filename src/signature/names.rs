use crate::tag_list;
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    hash::{Hash, Hasher},
    str,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseDomainError;

impl Display for ParseDomainError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "could not parse domain name")
    }
}

impl Error for ParseDomainError {}

/// An agent or user identifier.
///
/// This type is used to wrap addresses as used in the i= tags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    // for i= tag:
    // [ Local-part ] "@" domain-name
    // email address where local-part is optional
    pub local_part: Option<Box<str>>,
    pub domain_part: DomainName,
}

impl Identity {
    // TODO error type
    pub fn new(ident: &str) -> Result<Self, ParseDomainError> {
        let (local_part, domain) = if let Some((local_part, domain)) = ident.rsplit_once('@') {
            if local_part.is_empty() {
                (None, domain)
            } else {
                if !is_local_part(local_part) {
                    return Err(ParseDomainError);
                }
                (Some(local_part.into()), domain)
            }
        } else {
            return Err(ParseDomainError);
        };

        DomainName::new(domain).map(|domain_part| Self {
            local_part,
            domain_part,
        })
    }

    pub fn from_domain(domain_part: DomainName) -> Self {
        Self {
            local_part: None,
            domain_part,
        }
    }
}

// Note: for now copied from viaspf

// ‘local-part’ is defined in RFC 5321, §4.1.2. Modifications for
// internationalisation are in RFC 6531, §3.3.
fn is_local_part(s: &str) -> bool {
    // See RFC 5321, §4.5.3.1.1.
    if s.len() > 64 {
        return false;
    }

    if s.starts_with('"') {
        is_quoted_string(s)
    } else {
        is_dot_string(s)
    }
}

fn is_quoted_string(s: &str) -> bool {
    fn is_qtext_smtp(c: char) -> bool {
        c == ' ' || c.is_ascii_graphic() && !matches!(c, '"' | '\\') || !c.is_ascii()
    }

    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        let mut quoted = false;
        for c in s[1..(s.len() - 1)].chars() {
            if quoted {
                if c == ' ' || c.is_ascii_graphic() {
                    quoted = false;
                } else {
                    return false;
                }
            } else if c == '\\' {
                quoted = true;
            } else if !is_qtext_smtp(c) {
                return false;
            }
        }
        !quoted
    } else {
        false
    }
}

fn is_dot_string(s: &str) -> bool {
    // See RFC 5322, §3.2.3, with the modifications in RFC 6531, §3.3.
    fn is_atext(c: char) -> bool {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '/' | '=' | '?' | '^' | '_'
                | '`' | '{' | '|' | '}' | '~'
            )
            || !c.is_ascii()
    }

    let mut dot = true;
    for c in s.chars() {
        if dot {
            if is_atext(c) {
                dot = false;
            } else {
                return false;
            }
        } else if c == '.' {
            dot = true;
        } else if !is_atext(c) {
            return false;
        }
    }
    !dot
}

/// A domain name.
///
/// This type is used to wrap domain names as used in the d= and i= tags.
#[derive(Clone, Eq)]
pub struct DomainName(Box<str>);

impl DomainName {
    /// Creates a new domain name from the given string.
    ///
    /// Note that the string is validated and then encapsulated as-is.
    /// Equivalence comparison is case-insensitive; IDNA-equivalence comparisons
    /// are done in viadkim where necessary but are not part of the type’s own
    /// equivalence relations.
    pub fn new(s: &str) -> Result<Self, ParseDomainError> {
        if s.ends_with('.') {
            return Err(ParseDomainError);
        }

        if is_valid_dns_name(s) {
            Ok(Self(s.into()))
        } else {
            Err(ParseDomainError)
        }
    }

    /// Compares this and the given domain for equivalence, in case-insensitive
    /// and IDNA-aware manner.
    pub fn eq_or_subdomain_of(&self, other: &DomainName) -> bool {
        if self == other {
            return true;
        }

        let name = idna::domain_to_ascii(&self.0).unwrap();
        let other = idna::domain_to_ascii(&other.0).unwrap();

        if name.len() > other.len() {
            let len = name.len() - other.len();
            matches!(name.get(len..), Some(s) if s.eq_ignore_ascii_case(&other))
                && matches!(name.get(..len), Some(s) if s.ends_with('.'))
        } else {
            false
        }
    }
}

// TODO FromStr

impl Display for DomainName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for DomainName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &self.0)
    }
}

impl AsRef<str> for DomainName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq for DomainName {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl Hash for DomainName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_ascii_lowercase().hash(state);
    }
}

fn is_valid_dns_name(mut s: &str) -> bool {
    fn is_tld(s: &str) -> bool {
        is_label(s) && !s.chars().all(|c: char| c.is_ascii_digit())
    }

    if let Some(sx) = s.strip_suffix('.') {
        s = sx;
    }

    if !has_valid_domain_len(s) {
        return false;
    }

    let mut labels = s.split('.').rev().peekable();

    if matches!(labels.next(), Some(l) if !is_tld(l)) {
        return false;
    }
    if labels.peek().is_none() {
        return false;
    }

    labels.all(is_label)
}

// Note that tval char forbids ; as that makes no sense in DKIM signatures.
fn is_label(s: &str) -> bool {
    has_valid_label_len(s)
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.chars().all(tag_list::is_tval_char)
}

// fn is_label(s: &str) -> bool {
//     has_valid_label_len(s)
//         && s.starts_with(|c: char| c.is_ascii_alphanumeric())
//         && s.ends_with(|c: char| c.is_ascii_alphanumeric())
//         && s.chars().all(|c: char| c.is_ascii_alphanumeric() || c == '-')
// }

const MAX_DOMAIN_LENGTH: usize = 253;

fn has_valid_domain_len(s: &str) -> bool {
    matches!(s.len(), 1..=MAX_DOMAIN_LENGTH)
}

fn has_valid_label_len(s: &str) -> bool {
    matches!(s.len(), 1..=63)
}

/// A selector.
///
/// This type is used to wrap a sequence of labels as used in the s= tag.
#[derive(Clone, Eq)]
pub struct Selector(Box<str>);

impl Selector {
    // TODO error type
    /// Creates a new selector from the given string.
    ///
    /// Note that the string is validated and then encapsulated as-is.
    /// Equivalence comparison is case-insensitive; IDNA-equivalence comparisons
    /// are done in viadkim where necessary but are not part of the type’s own
    /// equivalence relations.
    pub fn new(s: &str) -> Result<Self, &'static str> {
        // lenient parsing domain name labels, allows things like "dkim_123"
        // length of the whole selector is not limited, will fail later
        if !s.split('.').all(is_label) {
            return Err("invalid selector");
        }

        // TODO revisit: ensure that inputs can be converted without error in both directions
        let _ = idna::domain_to_ascii(s).map_err(|_| "invalid selector")?;
        let (_, res) = idna::domain_to_unicode(s);
        if res.is_err() {
            return Err("invalid selector");
        }

        Ok(Selector(s.into()))
    }
}

impl Display for Selector {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for Selector {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &self.0)
    }
}

impl AsRef<str> for Selector {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq for Selector {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl Hash for Selector {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_ascii_lowercase().hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_ok() {
        assert!(Identity::new("我@☕.example.中国").is_ok());
        assert!(Identity::new("\"我\"@☕.example.中国").is_ok());

        assert!(Identity::new("me@@☕.example.中国").is_err());
    }

    #[test]
    fn domain_name_ok() {
        assert!(DomainName::new("example.com").is_ok());
        assert!(DomainName::new("example.中国").is_ok());
        assert!(DomainName::new("☕.example.中国").is_ok());

        assert!(DomainName::new("xn--53h.example.xn--fiqs8s").is_ok());

        assert!(DomainName::new("example").is_err());
        assert!(DomainName::new("example.").is_err());
        assert!(DomainName::new("example.com.").is_err());
    }

    #[test]
    fn selector_ok() {
        assert!(Selector::new("example").is_ok());
        assert!(Selector::new("x☕y").is_ok());
        assert!(Selector::new("_x☕y").is_ok());

        assert!(Selector::new("☕.example").is_ok());
        assert!(Selector::new("_☕.example").is_ok());
        assert!(Selector::new("xn--53h.example").is_ok());
        assert!(Selector::new("xn--_-2yp.example").is_ok());

        assert!(Selector::new("").is_err());
        assert!(Selector::new(".").is_err());
        assert!(Selector::new("example.").is_err());
        assert!(Selector::new("xn---x.example").is_err());
    }
}
