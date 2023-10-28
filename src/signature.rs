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

//! DKIM signature.

use crate::{
    crypto::{HashAlgorithm, KeyType},
    header::FieldName,
    tag_list::{self, TagList, TagSpec},
    util::{Base64Debug, BytesDebug, CanonicalStr},
};
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    hash::{Hash, Hasher},
    str::{self, FromStr},
};

// Design note: According to RFC 6376, bare TLDs are not allowed (see ABNF for
// d= tag). But elsewhere it does seem to assume possibility of such domains,
// see §6.1.1: ‘signatures with "d=" values such as "com" and "co.uk" could be
// ignored.’ (See also RFC 5321, section 2.3.5: ‘A domain name […] consists of
// one or more components, separated by dots if more than one appears. In the
// case of a top-level domain used by itself in an email address, a single
// string is used without any dots.’)

// Note: some of this is copied from viaspf.

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ParseDomainError;

impl Display for ParseDomainError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "could not parse domain name")
    }
}

impl Error for ParseDomainError {}

/// A domain name.
///
/// This type is used to wrap domain names as used in the *d=* and *i=* tags.
#[derive(Clone, Eq)]
pub struct DomainName(Box<str>);

impl DomainName {
    /// Creates a new domain name from the given string.
    ///
    /// Note that the string is validated and then encapsulated as-is.
    /// Equivalence comparison is case-insensitive; IDNA-equivalence comparisons
    /// are done in viadkim where necessary but are not part of the type’s own
    /// equivalence relations.
    pub fn new(s: impl Into<Box<str>>) -> Result<Self, ParseDomainError> {
        let s = s.into();
        if is_valid_domain_name(&s) {
            Ok(Self(s))
        } else {
            Err(ParseDomainError)
        }
    }

    /// Compares this and the given domain for equivalence, in case-insensitive
    /// and IDNA-aware manner.
    pub fn eq_or_subdomain_of(&self, other: &Self) -> bool {
        if self == other {
            return true;
        }

        let name = self.to_ascii();
        let other = other.to_ascii();

        if name.len() >= other.len() {
            let (left, right) = name.split_at(name.len() - other.len());
            right.eq_ignore_ascii_case(&other) && (left.is_empty() || left.ends_with('.'))
        } else {
            false
        }
    }

    /// Produces the IDNA A-label (ASCII) form of this domain name.
    pub fn to_ascii(&self) -> String {
        // Wrapped name is guaranteed to be convertible to A-label form.
        idna::domain_to_ascii(&self.0).unwrap()
    }

    /// Produces the IDNA U-label (Unicode) form of this domain name.
    pub fn to_unicode(&self) -> String {
        // Wrapped name is guaranteed to be convertible to U-label form.
        idna::domain_to_unicode(&self.0).0
    }
}

impl Display for DomainName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for DomainName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
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

impl FromStr for DomainName {
    type Err = ParseDomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if is_valid_domain_name(s) {
            Ok(Self(s.into()))
        } else {
            Err(ParseDomainError)
        }
    }
}

fn is_valid_domain_name(s: &str) -> bool {
    is_valid_domain_string(s, true)
}

/// A selector.
///
/// This type is used to wrap a sequence of labels as used in the *s=* tag.
#[derive(Clone, Eq)]
pub struct Selector(Box<str>);

impl Selector {
    /// Creates a new selector from the given string.
    ///
    /// Note that the string is validated and then encapsulated as-is.
    /// Equivalence comparison is case-insensitive; IDNA-equivalence comparisons
    /// are done in viadkim where necessary but are not part of the type’s own
    /// equivalence relations.
    pub fn new(s: impl Into<Box<str>>) -> Result<Self, ParseDomainError> {
        let s = s.into();
        if is_valid_selector(&s) {
            Ok(Self(s))
        } else {
            Err(ParseDomainError)
        }
    }

    /// Produces the IDNA A-label (ASCII) form of this selector.
    pub fn to_ascii(&self) -> String {
        // Wrapped name is guaranteed to be convertible to A-label form.
        idna::domain_to_ascii(&self.0).unwrap()
    }

    /// Produces the IDNA U-label (Unicode) form of this selector.
    pub fn to_unicode(&self) -> String {
        // Wrapped name is guaranteed to be convertible to U-label form.
        idna::domain_to_unicode(&self.0).0
    }
}

impl Display for Selector {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for Selector {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
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

impl FromStr for Selector {
    type Err = ParseDomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if is_valid_selector(s) {
            Ok(Self(s.into()))
        } else {
            Err(ParseDomainError)
        }
    }
}

fn is_valid_selector(s: &str) -> bool {
    is_valid_domain_string(s, false)
}

fn is_valid_domain_string(s: &str, check_tld: bool) -> bool {
    // For later IDNA processing, require that inputs can be converted without
    // error in both directions.
    match idna::domain_to_ascii(s) {
        Ok(ascii_s) => {
            is_valid_dns_name(&ascii_s, check_tld) && idna::domain_to_unicode(s).1.is_ok()
        }
        Err(_) => false,
    }
}

fn is_valid_dns_name(s: &str, check_tld: bool) -> bool {
    if !has_valid_domain_len(s) {
        return false;
    }

    let mut labels = s.split('.').rev();

    let final_label = labels.next().expect("failed to split string");

    // RFC 3696, section 2: ‘There is an additional rule that essentially
    // requires that top-level domain names not be all-numeric.’
    if !is_label(final_label) || (check_tld && final_label.chars().all(|c| c.is_ascii_digit())) {
        return false;
    }

    labels.all(is_label)
}

// Use a somewhat relaxed definition of DNS labels that also allows underscores,
// as seen in the wild.
fn is_label(s: &str) -> bool {
    debug_assert!(!s.contains('.'));
    has_valid_label_len(s)
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.chars()
            .all(|c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

// Note that these length checks are not definitive, as a later concatenation of
// selector, "_domainkey", and domain may still produce an invalid domain name.

fn has_valid_domain_len(s: &str) -> bool {
    matches!(s.len(), 1..=253)
}

fn has_valid_label_len(s: &str) -> bool {
    matches!(s.len(), 1..=63)
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ParseIdentityError;

impl Display for ParseIdentityError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "could not parse identity")
    }
}

impl Error for ParseIdentityError {}

/// An agent or user identifier.
///
/// This type is used to wrap addresses as used in the *i=* tag.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct Identity {
    // Note: because PartialEq and Hash are derived, the local-part will be
    // compared/hashed literally and in case-sensitive fashion.

    /// The identity’s optional local-part.
    pub local_part: Option<Box<str>>,

    /// The identity’s domain part.
    pub domain: DomainName,
}

impl Identity {
    /// Creates a new agent or user identifier from the given string.
    pub fn new(s: &str) -> Result<Self, ParseIdentityError> {
        let (local_part, domain) = s.rsplit_once('@').ok_or(ParseIdentityError)?;

        let local_part = if local_part.is_empty() {
            None
        } else {
            if !is_local_part(local_part) {
                return Err(ParseIdentityError);
            }
            Some(local_part)
        };

        let domain = domain.parse().map_err(|_| ParseIdentityError)?;

        Ok(Self {
            local_part: local_part.map(Into::into),
            domain,
        })
    }

    /// Creates a new agent or user identifier from the given domain name,
    /// without local-part.
    pub fn from_domain(domain: DomainName) -> Self {
        Self {
            local_part: None,
            domain,
        }
    }
}

// Note that local-part may include semicolon and space, which are here printed
// as-is. However, they cannot appear in a tag-list value and so must be encoded
// when formatted into a DKIM-Signature.
impl Display for Identity {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(local_part) = &self.local_part {
            write!(f, "{local_part}")?;
        }
        write!(f, "@{}", self.domain)
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl FromStr for Identity {
    type Err = ParseIdentityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

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
        c == ' ' || (c.is_ascii_graphic() && !matches!(c, '"' | '\\')) || !c.is_ascii()
    }

    if let Some(s) = s.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        let mut quoted = false;
        for c in s.chars() {
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

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ParseAlgorithmError;

impl Display for ParseAlgorithmError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "could not parse algorithm name")
    }
}

impl Error for ParseAlgorithmError {}

/// A signing algorithm.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum SigningAlgorithm {
    /// The *rsa-sha256* signing algorithm.
    RsaSha256,
    /// The *ed25519-sha256* signing algorithm.
    Ed25519Sha256,
    #[cfg(feature = "pre-rfc8301")]
    /// The *rsa-sha1* signing algorithm.
    RsaSha1,
}

impl SigningAlgorithm {
    /// Assembles a signing algorithm from the constituent key type and hash
    /// algorithm, if possible.
    pub fn from_parts(key_type: KeyType, hash_alg: HashAlgorithm) -> Option<Self> {
        match (key_type, hash_alg) {
            (KeyType::Rsa, HashAlgorithm::Sha256) => Some(Self::RsaSha256),
            (KeyType::Ed25519, HashAlgorithm::Sha256) => Some(Self::Ed25519Sha256),
            #[cfg(feature = "pre-rfc8301")]
            (KeyType::Rsa, HashAlgorithm::Sha1) => Some(Self::RsaSha1),
            #[cfg(feature = "pre-rfc8301")]
            _ => None,
        }
    }

    /// Returns this signing algorithm’s key type component.
    pub fn key_type(self) -> KeyType {
        match self {
            Self::RsaSha256 => KeyType::Rsa,
            Self::Ed25519Sha256 => KeyType::Ed25519,
            #[cfg(feature = "pre-rfc8301")]
            Self::RsaSha1 => KeyType::Rsa,
        }
    }

    /// Returns this signing algorithm’s hash algorithm component.
    pub fn hash_algorithm(self) -> HashAlgorithm {
        match self {
            Self::RsaSha256 | Self::Ed25519Sha256 => HashAlgorithm::Sha256,
            #[cfg(feature = "pre-rfc8301")]
            Self::RsaSha1 => HashAlgorithm::Sha1,
        }
    }
}

impl CanonicalStr for SigningAlgorithm {
    fn canonical_str(&self) -> &'static str {
        match self {
            Self::RsaSha256 => "rsa-sha256",
            Self::Ed25519Sha256 => "ed25519-sha256",
            #[cfg(feature = "pre-rfc8301")]
            Self::RsaSha1 => "rsa-sha1",
        }
    }
}

impl Display for SigningAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.canonical_str())
    }
}

impl fmt::Debug for SigningAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl FromStr for SigningAlgorithm {
    type Err = ParseAlgorithmError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("rsa-sha256") {
            Ok(Self::RsaSha256)
        } else if s.eq_ignore_ascii_case("ed25519-sha256") {
            Ok(Self::Ed25519Sha256)
        } else {
            #[cfg(feature = "pre-rfc8301")]
            if s.eq_ignore_ascii_case("rsa-sha1") {
                return Ok(Self::RsaSha1);
            }
            Err(ParseAlgorithmError)
        }
    }
}

impl From<SigningAlgorithm> for (KeyType, HashAlgorithm) {
    fn from(alg: SigningAlgorithm) -> Self {
        (alg.key_type(), alg.hash_algorithm())
    }
}

/// A canonicalization algorithm.
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub enum CanonicalizationAlgorithm {
    /// The *simple* canonicalization algorithm.
    #[default]
    Simple,
    /// The *relaxed* canonicalization algorithm.
    Relaxed,
}

impl CanonicalStr for CanonicalizationAlgorithm {
    fn canonical_str(&self) -> &'static str {
        match self {
            Self::Simple => "simple",
            Self::Relaxed => "relaxed",
        }
    }
}

impl Display for CanonicalizationAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.canonical_str())
    }
}

impl fmt::Debug for CanonicalizationAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl FromStr for CanonicalizationAlgorithm {
    type Err = ParseAlgorithmError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("simple") {
            Ok(Self::Simple)
        } else if s.eq_ignore_ascii_case("relaxed") {
            Ok(Self::Relaxed)
        } else {
            Err(ParseAlgorithmError)
        }
    }
}

/// A pair of header/body canonicalization algorithms.
///
/// # Examples
///
/// ```
/// use viadkim::signature::{Canonicalization, CanonicalizationAlgorithm::*};
///
/// let canon = Canonicalization::from((Relaxed, Simple));
///
/// assert_eq!(canon.to_string(), "relaxed/simple");
/// ```
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct Canonicalization {
    /// The header canonicalization.
    pub header: CanonicalizationAlgorithm,
    /// The body canonicalization.
    pub body: CanonicalizationAlgorithm,
}

impl CanonicalStr for Canonicalization {
    fn canonical_str(&self) -> &'static str {
        use CanonicalizationAlgorithm::*;

        match (self.header, self.body) {
            (Simple, Simple) => "simple/simple",
            (Simple, Relaxed) => "simple/relaxed",
            (Relaxed, Simple) => "relaxed/simple",
            (Relaxed, Relaxed) => "relaxed/relaxed",
        }
    }
}

impl Display for Canonicalization {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.canonical_str())
    }
}

impl fmt::Debug for Canonicalization {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl From<(CanonicalizationAlgorithm, CanonicalizationAlgorithm)> for Canonicalization {
    fn from((header, body): (CanonicalizationAlgorithm, CanonicalizationAlgorithm)) -> Self {
        Self { header, body }
    }
}

impl FromStr for Canonicalization {
    type Err = ParseAlgorithmError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(if let Some((header, body)) = s.split_once('/') {
            Self {
                header: header.parse()?,
                body: body.parse()?,
            }
        } else {
            Self {
                header: s.parse()?,
                body: Default::default(),
            }
        })
    }
}

/// The *DKIM-Signature* header name.
pub const DKIM_SIGNATURE_NAME: &str = "DKIM-Signature";

/// An error that occurs when parsing a DKIM signature for further processing.
///
/// The error comes with salvaged data from the failed parsing attempt, that
/// could be reported in an *Authentication-Results* header. This data is in raw
/// (string) form because it might fail to parse into a concrete type.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DkimSignatureError {
    /// The error kind that caused this error.
    pub kind: DkimSignatureErrorKind,

    /// The string value of the *a=* tag, if available.
    pub algorithm_str: Option<Box<str>>,
    /// The string value of the *b=* tag, if available.
    pub signature_data_str: Option<Box<str>>,
    /// The string value of the *d=* tag, if available.
    pub domain_str: Option<Box<str>>,
    /// The string value of the *i=* tag, if available.
    pub identity_str: Option<Box<str>>,
    /// The string value of the *s=* tag, if available.
    pub selector_str: Option<Box<str>>,
}

impl DkimSignatureError {
    /// Creates a new DKIM signature error of the given kind, with no additional
    /// data attached.
    pub fn new(kind: DkimSignatureErrorKind) -> Self {
        Self {
            kind,
            algorithm_str: None,
            signature_data_str: None,
            domain_str: None,
            identity_str: None,
            selector_str: None,
        }
    }
}

impl Display for DkimSignatureError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.kind.fmt(f)
    }
}

impl Error for DkimSignatureError {}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DkimSignatureErrorKind {
    Utf8Encoding,
    TagListFormat,
    IncompatibleVersion,
    HistoricAlgorithm,
    UnsupportedAlgorithm,
    InvalidBase64,
    EmptySignatureTag,
    EmptyBodyHashTag,
    UnsupportedCanonicalization,
    InvalidDomain,
    InvalidSignedHeaderName,
    EmptySignedHeadersTag,
    FromHeaderNotSigned,
    InvalidIdentity,
    InvalidBodyLength,
    InvalidQueryMethod,
    NoSupportedQueryMethods,
    InvalidSelector,
    InvalidTimestamp,
    InvalidExpiration,
    InvalidCopiedHeaderField,
    MissingVersionTag,
    MissingAlgorithmTag,
    MissingSignatureTag,
    MissingBodyHashTag,
    MissingDomainTag,
    MissingSignedHeadersTag,
    MissingSelectorTag,
    DomainMismatch,
    ExpirationNotAfterTimestamp,
}

impl Display for DkimSignatureErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Utf8Encoding => write!(f, "signature not UTF-8 encoded"),
            Self::TagListFormat => write!(f, "ill-formed tag list"),
            Self::IncompatibleVersion => write!(f, "incompatible version"),
            Self::HistoricAlgorithm => write!(f, "historic signature algorithm"),
            Self::UnsupportedAlgorithm => write!(f, "unsupported signature algorithm"),
            Self::InvalidBase64 => write!(f, "invalid Base64 string"),
            Self::EmptySignatureTag => write!(f, "b= tag empty"),
            Self::EmptyBodyHashTag => write!(f, "bh= tag empty"),
            Self::UnsupportedCanonicalization => write!(f, "unsupported canonicalization"),
            Self::InvalidDomain => write!(f, "invalid signing domain"),
            Self::InvalidSignedHeaderName => write!(f, "invalid signed header name"),
            Self::EmptySignedHeadersTag => write!(f, "h= tag empty"),
            Self::FromHeaderNotSigned => write!(f, "From header not signed"),
            Self::InvalidIdentity => write!(f, "invalid signing identity"),
            Self::InvalidBodyLength => write!(f, "invalid body length"),
            Self::InvalidQueryMethod => write!(f, "invalid query method"),
            Self::NoSupportedQueryMethods => write!(f, "no supported query methods"),
            Self::InvalidSelector => write!(f, "invalid selector"),
            Self::InvalidTimestamp => write!(f, "invalid timestamp"),
            Self::InvalidExpiration => write!(f, "invalid expiration"),
            Self::InvalidCopiedHeaderField => write!(f, "invalid header field in z= tag"),
            Self::MissingVersionTag => write!(f, "v= tag missing"),
            Self::MissingAlgorithmTag => write!(f, "a= tag missing"),
            Self::MissingSignatureTag => write!(f, "b= tag missing"),
            Self::MissingBodyHashTag => write!(f, "bh= tag missing"),
            Self::MissingDomainTag => write!(f, "d= tag missing"),
            Self::MissingSignedHeadersTag => write!(f, "h= tag missing"),
            Self::MissingSelectorTag => write!(f, "s= tag missing"),
            Self::DomainMismatch => write!(f, "domain mismatch"),
            Self::ExpirationNotAfterTimestamp => write!(f, "expiration not after timestamp"),
        }
    }
}

/// DKIM signature data as encoded in a *DKIM-Signature* header.
///
/// The *v=* tag (always 1) and the *q=* tag (always includes dns/txt) are not
/// included.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct DkimSignature {
    // The fields are strongly typed and have public visibility. This does allow
    // constructing an invalid `DkimSignature` (eg with empty signature, or
    // empty signed headers) but we consider this acceptable, because this is
    // mainly an ‘output’ data container.
    //
    // i= is `Option` because of §3.5: ‘the Signer might wish to assert that
    // although it is willing to go as far as signing for the domain, it is
    // unable or unwilling to commit to an individual user name within the
    // domain. It can do so by including the domain part but not the local-part
    // of the identity.’

    /// The *a=* tag.
    pub algorithm: SigningAlgorithm,
    /// The *b=* tag.
    pub signature_data: Box<[u8]>,
    /// The *bh=* tag.
    pub body_hash: Box<[u8]>,
    /// The *c=* tag.
    pub canonicalization: Canonicalization,
    /// The *d=* tag.
    pub domain: DomainName,
    /// The *h=* tag.
    pub signed_headers: Box<[FieldName]>,  // not empty, no names containing `;`
    /// The *i=* tag.
    pub identity: Option<Identity>,
    /// The *l=* tag.
    pub body_length: Option<u64>,
    /// The *s=* tag.
    pub selector: Selector,
    /// The *t=* tag.
    pub timestamp: Option<u64>,
    /// The *x=* tag.
    pub expiration: Option<u64>,
    /// The *z=* tag.
    pub copied_headers: Box<[(FieldName, Box<[u8]>)]>,  // names may contain `;`
    /// Additional, unrecognised tag name and value pairs. (For example, the RFC
    /// 6651 extension tag *r=y*.)
    pub ext_tags: Box<[(Box<str>, Box<str>)]>,
}

impl DkimSignature {
    fn from_tag_list(tag_list: &TagList<'_>) -> Result<Self, DkimSignatureError> {
        Self::from_tag_list_internal(tag_list).map_err(|kind| {
            // The error path. Extract some data in raw form.

            let mut algorithm_str = None;
            let mut signature_data_str = None;
            let mut domain_str = None;
            let mut identity_str = None;
            let mut selector_str = None;

            for &TagSpec { name, value } in tag_list.as_ref() {
                match name {
                    "a" => algorithm_str = Some(value.into()),
                    "b" => signature_data_str = Some(value.into()),
                    "d" => domain_str = Some(value.into()),
                    "i" => identity_str = Some(value.into()),
                    "s" => selector_str = Some(value.into()),
                    _ => {}
                }
            }

            DkimSignatureError {
                kind,
                algorithm_str,
                signature_data_str,
                domain_str,
                identity_str,
                selector_str,
            }
        })
    }

    fn from_tag_list_internal(tag_list: &TagList<'_>) -> Result<Self, DkimSignatureErrorKind> {
        let mut version_seen = false;
        let mut algorithm = None;
        let mut signature_data = None;
        let mut body_hash = None;
        let mut canonicalization = None;
        let mut domain = None;
        let mut signed_headers = None;
        let mut identity = None;
        let mut body_length = None;
        let mut selector = None;
        let mut timestamp = None;
        let mut expiration = None;
        let mut copied_headers = None;
        let mut ext_tags = vec![];

        for &TagSpec { name, value } in tag_list.as_ref() {
            match name {
                "v" => {
                    if value != "1" {
                        return Err(DkimSignatureErrorKind::IncompatibleVersion);
                    }

                    version_seen = true;
                }
                "a" => {
                    let value = value.parse().map_err(|_| {
                        #[cfg(not(feature = "pre-rfc8301"))]
                        if value.eq_ignore_ascii_case("rsa-sha1") {
                            // Note: special-case "rsa-sha1" as recognised but
                            // no longer supported (RFC 8301).
                            return DkimSignatureErrorKind::HistoricAlgorithm;
                        }
                        DkimSignatureErrorKind::UnsupportedAlgorithm
                    })?;

                    algorithm = Some(value);
                }
                "b" => {
                    let value = tag_list::parse_base64_value(value)
                        .map_err(|_| DkimSignatureErrorKind::InvalidBase64)?;

                    if value.is_empty() {
                        return Err(DkimSignatureErrorKind::EmptySignatureTag);
                    }

                    signature_data = Some(value.into());
                }
                "bh" => {
                    let value = tag_list::parse_base64_value(value)
                        .map_err(|_| DkimSignatureErrorKind::InvalidBase64)?;

                    if value.is_empty() {
                        return Err(DkimSignatureErrorKind::EmptyBodyHashTag);
                    }

                    body_hash = Some(value.into());
                }
                "c" => {
                    let value = value.parse()
                        .map_err(|_| DkimSignatureErrorKind::UnsupportedCanonicalization)?;

                    canonicalization = Some(value);
                }
                "d" => {
                    let value = value.parse()
                        .map_err(|_| DkimSignatureErrorKind::InvalidDomain)?;

                    domain = Some(value);
                }
                "h" => {
                    if value.is_empty() {
                        return Err(DkimSignatureErrorKind::EmptySignedHeadersTag);
                    }

                    let mut sh = vec![];

                    for s in tag_list::parse_colon_separated_value(value) {
                        let name = FieldName::new(s)
                            .map_err(|_| DkimSignatureErrorKind::InvalidSignedHeaderName)?;
                        sh.push(name);
                    }

                    if !sh.iter().any(|h| *h == "From") {
                        return Err(DkimSignatureErrorKind::FromHeaderNotSigned);
                    }

                    signed_headers = Some(sh.into());
                }
                "i" => {
                    let value = tag_list::parse_quoted_printable_value(value)
                        .map_err(|_| DkimSignatureErrorKind::InvalidIdentity)?;

                    // This identifier is expected to contain UTF-8 only.
                    let value = String::from_utf8(value)
                        .map_err(|_| DkimSignatureErrorKind::InvalidIdentity)?;

                    let value = Identity::new(&value)
                        .map_err(|_| DkimSignatureErrorKind::InvalidIdentity)?;

                    identity = Some(value);
                }
                "l" => {
                    let value = value.parse()
                        .map_err(|_| DkimSignatureErrorKind::InvalidBodyLength)?;

                    body_length = Some(value);
                }
                "q" => {
                    // Note that even though *q=* is specified as being plain
                    // text, the ABNF then allows qp-hdr-value (or rather
                    // ‘dkim-quoted-printable with colon encoded’, see erratum
                    // 4810). We skip this by simply checking for presence of
                    // `dns/txt`, the only generally supported value.

                    let mut dns_txt_seen = false;

                    for s in tag_list::parse_colon_separated_value(value) {
                        if s.is_empty() {
                            return Err(DkimSignatureErrorKind::InvalidQueryMethod);
                        }
                        if s.eq_ignore_ascii_case("dns/txt") {
                            dns_txt_seen = true;
                        }
                    }

                    if !dns_txt_seen {
                        return Err(DkimSignatureErrorKind::NoSupportedQueryMethods);
                    }
                }
                "s" => {
                    let value = value.parse()
                        .map_err(|_| DkimSignatureErrorKind::InvalidSelector)?;

                    selector = Some(value);
                }
                "t" => {
                    let value = value.parse()
                        .map_err(|_| DkimSignatureErrorKind::InvalidTimestamp)?;

                    timestamp = Some(value);
                }
                "x" => {
                    let value = value.parse()
                        .map_err(|_| DkimSignatureErrorKind::InvalidExpiration)?;

                    expiration = Some(value);
                }
                "z" => {
                    let mut headers = vec![];

                    for piece in value.split('|') {
                        let (name, value) = tag_list::parse_quoted_printable_header_field(piece)
                            .map_err(|_| DkimSignatureErrorKind::InvalidCopiedHeaderField)?;
                        headers.push((name, value));
                    }

                    copied_headers = Some(headers.into());
                }
                _ => {
                    ext_tags.push((name.into(), value.into()));
                }
            }
        }

        if !version_seen {
            return Err(DkimSignatureErrorKind::MissingVersionTag);
        }

        let algorithm = algorithm.ok_or(DkimSignatureErrorKind::MissingAlgorithmTag)?;
        let signature_data = signature_data.ok_or(DkimSignatureErrorKind::MissingSignatureTag)?;
        let body_hash = body_hash.ok_or(DkimSignatureErrorKind::MissingBodyHashTag)?;
        let domain = domain.ok_or(DkimSignatureErrorKind::MissingDomainTag)?;
        let signed_headers = signed_headers.ok_or(DkimSignatureErrorKind::MissingSignedHeadersTag)?;
        let selector = selector.ok_or(DkimSignatureErrorKind::MissingSelectorTag)?;

        if let Some(id) = &identity {
            if !id.domain.eq_or_subdomain_of(&domain) {
                return Err(DkimSignatureErrorKind::DomainMismatch);
            }
        }

        if let (Some(timestamp), Some(expiration)) = (timestamp, expiration) {
            if expiration <= timestamp {
                return Err(DkimSignatureErrorKind::ExpirationNotAfterTimestamp);
            }
        }

        let canonicalization = canonicalization.unwrap_or_default();
        let copied_headers = copied_headers.unwrap_or_default();
        let ext_tags = ext_tags.into();

        Ok(Self {
            algorithm,
            signature_data,
            body_hash,
            canonicalization,
            domain,
            signed_headers,
            identity,
            body_length,
            selector,
            timestamp,
            expiration,
            copied_headers,
            ext_tags,
        })
    }
}

impl FromStr for DkimSignature {
    type Err = DkimSignatureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let tag_list = TagList::from_str(s)
            .map_err(|_| DkimSignatureError::new(DkimSignatureErrorKind::TagListFormat))?;

        Self::from_tag_list(&tag_list)
    }
}

struct CopiedHeadersDebug<'a>(&'a [(FieldName, Box<[u8]>)]);

impl fmt::Debug for CopiedHeadersDebug<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_list();
        for (name, value) in self.0 {
            d.entry(&(name, BytesDebug(value)));
        }
        d.finish()
    }
}

impl fmt::Debug for DkimSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("DkimSignature")
            .field("algorithm", &self.algorithm)
            .field("signature_data", &Base64Debug(&self.signature_data))
            .field("body_hash", &Base64Debug(&self.body_hash))
            .field("canonicalization", &self.canonicalization)
            .field("domain", &self.domain)
            .field("signed_headers", &self.signed_headers)
            .field("identity", &self.identity)
            .field("body_length", &self.body_length)
            .field("selector", &self.selector)
            .field("timestamp", &self.timestamp)
            .field("expiration", &self.expiration)
            .field("copied_headers", &CopiedHeadersDebug(&self.copied_headers))
            .field("ext_tags", &self.ext_tags)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{tag_list::TagList, util};
    use CanonicalizationAlgorithm::*;

    #[test]
    fn domain_name_ok() {
        assert!(DomainName::new("com").is_ok());
        assert!(DomainName::new("com123").is_ok());
        assert!(DomainName::new("example.com").is_ok());
        assert!(DomainName::new("_abc.example.com").is_ok());
        assert!(DomainName::new("中国").is_ok());
        assert!(DomainName::new("example.中国").is_ok());
        assert!(DomainName::new("☕.example.中国").is_ok());
        assert!(DomainName::new("xn--53h.example.xn--fiqs8s").is_ok());

        assert!(DomainName::new("").is_err());
        assert!(DomainName::new("-com").is_err());
        assert!(DomainName::new("c,m").is_err());
        assert!(DomainName::new("c;m").is_err());
        assert!(DomainName::new("123").is_err());
        assert!(DomainName::new("com.").is_err());
        assert!(DomainName::new("example..com").is_err());
        assert!(DomainName::new("example-.com").is_err());
        assert!(DomainName::new("example.123").is_err());
        assert!(DomainName::new("_$@.example.com").is_err());
        assert!(DomainName::new("example.com.").is_err());
        assert!(DomainName::new("ex mple.com").is_err());
        assert!(DomainName::new("xn---y.example.com").is_err());
    }

    #[test]
    fn domain_name_eq_or_subdomain() {
        fn domain(s: &str) -> DomainName {
            DomainName::new(s).unwrap()
        }

        assert!(domain("eXaMpLe.CoM").eq_or_subdomain_of(&domain("example.com")));
        assert!(domain("mAiL.eXaMpLe.CoM").eq_or_subdomain_of(&domain("example.com")));
        assert!(!domain("XaMpLe.CoM").eq_or_subdomain_of(&domain("example.com")));
        assert!(!domain("meXaMpLe.CoM").eq_or_subdomain_of(&domain("example.com")));

        assert!(domain("例子.xn--fiqs8s").eq_or_subdomain_of(&domain("xn--fsqu00a.中国")));
        assert!(domain("☕.例子.xn--fiqs8s").eq_or_subdomain_of(&domain("xn--fsqu00a.中国")));
        assert!(!domain("子.xn--fiqs8s").eq_or_subdomain_of(&domain("xn--fsqu00a.中国")));
        assert!(!domain("假例子.xn--fiqs8s").eq_or_subdomain_of(&domain("xn--fsqu00a.中国")));
    }

    #[test]
    fn selector_ok() {
        assert!(Selector::new("example").is_ok());
        assert!(Selector::new("x☕y").is_ok());
        assert!(Selector::new("_x☕y").is_ok());
        assert!(Selector::new("123").is_ok());
        assert!(Selector::new("☕.example").is_ok());
        assert!(Selector::new("_☕.example").is_ok());
        assert!(Selector::new("xn--53h.example").is_ok());
        assert!(Selector::new("xn--_-2yp.example").is_ok());

        assert!(Selector::new("").is_err());
        assert!(Selector::new(".").is_err());
        assert!(Selector::new("example.").is_err());
        assert!(Selector::new("xn---x.example").is_err());
    }

    #[test]
    fn identity_ok() {
        assert!(Identity::new("我@☕.example.中国").is_ok());
        assert!(Identity::new("\"我\"@☕.example.中国").is_ok());

        assert!(Identity::new("me@@☕.example.中国").is_err());
    }

    #[test]
    fn identity_repr_ok() {
        let id1 = Identity::new("@example.org").unwrap();
        let id2 = Identity::new("Me@Example.Org").unwrap();
        let id3 = Identity::new("我.x#!@example.中国").unwrap();
        let id4 = Identity::new("\"x #$我\\\"\"@example.org").unwrap();

        assert_eq!(id1.to_string(), "@example.org");
        assert_eq!(id2.to_string(), "Me@Example.Org");
        assert_eq!(id3.to_string(), "我.x#!@example.中国");
        assert_eq!(id4.to_string(), "\"x #$我\\\"\"@example.org");

        assert_eq!(format!("{:?}", id1), "@example.org");
        assert_eq!(format!("{:?}", id2), "Me@Example.Org");
        assert_eq!(format!("{:?}", id3), "我.x#!@example.中国");
        assert_eq!(format!("{:?}", id4), "\"x #$我\\\"\"@example.org");
    }

    #[test]
    fn rfc_example_signature() {
        // See §3.5:
        let example = " v=1; a=rsa-sha256; d=example.net; s=brisbane;
   c=simple; q=dns/txt; i=@eng.example.net;
   t=1117574938; x=1118006938;
   h=from:to:subject:date;
   z=From:foo@eng.example.net|To:joe@example.com|
    Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700;
   bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;
   b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR";
        let example = example.replace('\n', "\r\n");

        let q = TagList::from_str(&example).unwrap();

        let hdr = DkimSignature::from_tag_list(&q).unwrap();

        assert_eq!(
            hdr,
            DkimSignature {
                algorithm: SigningAlgorithm::RsaSha256,
                signature_data: util::decode_base64(
                    "dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR"
                )
                .unwrap()
                .into(),
                body_hash: util::decode_base64("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
                    .unwrap()
                    .into(),
                canonicalization: (Simple, Simple).into(),
                domain: DomainName::new("example.net").unwrap(),
                signed_headers: [
                    FieldName::new("from").unwrap(),
                    FieldName::new("to").unwrap(),
                    FieldName::new("subject").unwrap(),
                    FieldName::new("date").unwrap(),
                ]
                .into(),
                identity: Some(Identity::new("@eng.example.net").unwrap()),
                selector: Selector::new("brisbane").unwrap(),
                body_length: None,
                timestamp: Some(1117574938),
                expiration: Some(1118006938),
                copied_headers: [
                    (
                        FieldName::new("From").unwrap(),
                        Box::from(*b"foo@eng.example.net")
                    ),
                    (
                        FieldName::new("To").unwrap(),
                        Box::from(*b"joe@example.com")
                    ),
                    (
                        FieldName::new("Subject").unwrap(),
                        Box::from(*b"demo run")
                    ),
                    (
                        FieldName::new("Date").unwrap(),
                        Box::from(*b"July 5, 2005 3:44:08 PM -0700")
                    ),
                ]
                .into(),
                ext_tags: [].into(),
            }
        );
    }

    #[test]
    fn complicated_example_signature() {
        // TODO revisit example
        let example = " v = 1 ; a=rsa-sha256;d=example.net; s=brisbane;
   c=simple; q=dns/txt; i=中文=40en
    g.example =2E net;
   t=1117574938; x=1118006938;  y= curious
    value; zz=;
   h=from:to:subject:date;
   bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;
   b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR";
        let example = example.replace('\n', "\r\n");

        let q = TagList::from_str(&example).unwrap();

        let hdr = DkimSignature::from_tag_list(&q).unwrap();

        assert_eq!(
            hdr,
            DkimSignature {
                algorithm: SigningAlgorithm::RsaSha256,
                signature_data: util::decode_base64(
                    "dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR"
                )
                .unwrap()
                .into(),
                body_hash: util::decode_base64("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
                    .unwrap()
                    .into(),
                canonicalization: (Simple, Simple).into(),
                domain: DomainName::new("example.net").unwrap(),
                signed_headers: [
                    FieldName::new("from").unwrap(),
                    FieldName::new("to").unwrap(),
                    FieldName::new("subject").unwrap(),
                    FieldName::new("date").unwrap(),
                ]
                .into(),
                identity: Some(Identity::new("中文@eng.example.net").unwrap()),
                selector: Selector::new("brisbane").unwrap(),
                body_length: None,
                timestamp: Some(1117574938),
                expiration: Some(1118006938),
                copied_headers: [].into(),
                ext_tags: [
                    (
                        "y".into(),
                        "curious\r\n    value".into(),
                    ),
                    (
                        "zz".into(),
                        "".into(),
                    ),
                ]
                .into(),
            }
        );
    }
}
