//! DKIM signature.

use crate::{
    crypto::{HashAlgorithm, KeyType},
    header::FieldName,
    tag_list::{
        self, parse_base64_tag_value, parse_colon_separated_tag_value, parse_dqp_header_field,
        parse_dqp_tag_value, TagList, TagSpec,
    },
    util::{self, CanonicalStr},
};
use bstr::ByteSlice;
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    hash::{Hash, Hasher},
    str::{self, FromStr},
};

// Implementation note: domain name, selector, and identity types only do very
// broad validation. More or less everything that can appear in a tag-list value
// is allowed (even when the conservative RFC 5321 disagrees).
//
// Also note that according to RFC 6376, bare TLDs are not allowed (see ABNF for
// d= tag). But elsewhere it does seem to assume possibility of such domains,
// see §6.1.1: ‘signatures with "d=" values such as "com" and "co.uk" could be
// ignored.’ (See also RFC 5321, section 2.3.5: ‘A domain name […] consists of
// one or more components, separated by dots if more than one appears. In the
// case of a top-level domain used by itself in an email address, a single
// string is used without any dots.’)

// Note: some of this is copied from viaspf.

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ParseDomainError;

impl Display for ParseDomainError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "could not parse domain name")
    }
}

impl Error for ParseDomainError {}

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

        // Wrapped name is guaranteed to be convertible to A-label form.
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
        idna::domain_to_ascii(&self.0).unwrap()
    }

    /// Produces the IDNA U-label (Unicode) form of this domain name.
    pub fn to_unicode(&self) -> String {
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
/// This type is used to wrap a sequence of labels as used in the s= tag.
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
        idna::domain_to_ascii(&self.0).unwrap()
    }

    /// Produces the IDNA U-label (Unicode) form of this selector.
    pub fn to_unicode(&self) -> String {
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

    let final_label = match labels.next() {
        Some(label) => label,
        None => return false,
    };

    if !is_label(final_label) || (check_tld && final_label.chars().all(|c| c.is_ascii_digit())) {
        return false;
    }

    labels.all(is_label)
}

// Use a very lenient definition of ‘DNS label’: Everything that can appear in a
// tag-list value may be part of a label (printable ASCII except `;` [and `.`
// and `\`], and valid UTF-8).
fn is_label(s: &str) -> bool {
    debug_assert!(!s.contains('.'));
    has_valid_label_len(s)
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.chars().all(|c| tag_list::is_tval_char(c) && c != '\\')
}

// Note that these length checks are not definitive, as a later concatenation of
// selector, "_domainkey", and domain may still produce an invalid domain name.

fn has_valid_domain_len(s: &str) -> bool {
    matches!(s.len(), 1..=253)
}

fn has_valid_label_len(s: &str) -> bool {
    matches!(s.len(), 1..=63)
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ParseIdentityError;

impl Display for ParseIdentityError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "could not parse identity")
    }
}

impl Error for ParseIdentityError {}

// TODO note terminology Identity, Identifier, SDID, AUID in sections 2.3 to 2.6

/// An agent or user identifier.
///
/// This type is used to wrap addresses as used in the i= tags.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Identity {
    // Note: because PartialEq and Hash are derived, the local-part will be
    // compared/hashed literally and in case-sensitive fashion.
    pub local_part: Option<Box<str>>,
    pub domain_part: DomainName,
}

// TODO make new take an impl Into<String>?
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
            Some(local_part.into())
        };

        let domain_part = domain.parse().map_err(|_| ParseIdentityError)?;

        Ok(Self {
            local_part,
            domain_part,
        })
    }

    /// Creates a new agent or user identifier for the given domain name,
    /// without local-part.
    pub fn from_domain(domain_part: DomainName) -> Self {
        Self {
            local_part: None,
            domain_part,
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
        write!(f, "@{}", self.domain_part)
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ParseAlgorithmError;

impl Display for ParseAlgorithmError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "could not parse algorithm name")
    }
}

impl Error for ParseAlgorithmError {}

/// A signature algorithm.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SignatureAlgorithm {
    /// The *rsa-sha256* signature algorithm.
    RsaSha256,
    /// The *ed25519-sha256* signature algorithm.
    Ed25519Sha256,
    #[cfg(feature = "sha1")]
    /// The *rsa-sha1* signature algorithm.
    RsaSha1,
}

impl SignatureAlgorithm {
    /// Assembles a signature algorithm from the constituent key type and hash
    /// algorithm, if possible.
    pub fn from_parts(key_type: KeyType, algorithm: HashAlgorithm) -> Option<Self> {
        match (key_type, algorithm) {
            (KeyType::Rsa, HashAlgorithm::Sha256) => Some(Self::RsaSha256),
            (KeyType::Ed25519, HashAlgorithm::Sha256) => Some(Self::Ed25519Sha256),
            #[cfg(feature = "sha1")]
            (KeyType::Rsa, HashAlgorithm::Sha1) => Some(Self::RsaSha1),
            #[cfg(feature = "sha1")]
            _ => None,
        }
    }

    /// Returns this signature algorithm’s key type component.
    pub fn key_type(self) -> KeyType {
        match self {
            Self::RsaSha256 => KeyType::Rsa,
            Self::Ed25519Sha256 => KeyType::Ed25519,
            #[cfg(feature = "sha1")]
            Self::RsaSha1 => KeyType::Rsa,
        }
    }

    /// Returns this signature algorithm’s hash algorithm component.
    pub fn hash_algorithm(self) -> HashAlgorithm {
        match self {
            Self::RsaSha256 | Self::Ed25519Sha256 => HashAlgorithm::Sha256,
            #[cfg(feature = "sha1")]
            Self::RsaSha1 => HashAlgorithm::Sha1,
        }
    }
}

impl CanonicalStr for SignatureAlgorithm {
    fn canonical_str(&self) -> &'static str {
        match self {
            Self::RsaSha256 => "rsa-sha256",
            Self::Ed25519Sha256 => "ed25519-sha256",
            #[cfg(feature = "sha1")]
            Self::RsaSha1 => "rsa-sha1",
        }
    }
}

impl Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.canonical_str())
    }
}

impl FromStr for SignatureAlgorithm {
    type Err = ParseAlgorithmError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("rsa-sha256") {
            Ok(Self::RsaSha256)
        } else if s.eq_ignore_ascii_case("ed25519-sha256") {
            Ok(Self::Ed25519Sha256)
        } else {
            #[cfg(feature = "sha1")]
            if s.eq_ignore_ascii_case("rsa-sha1") {
                return Ok(Self::RsaSha1);
            }
            Err(ParseAlgorithmError)
        }
    }
}

/// A canonicalization algorithm.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
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
        write!(f, "{:?}/{:?}", &self.header, &self.body)
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

pub const DKIM_SIGNATURE_NAME: &str = "DKIM-Signature";

// TODO impl `Error`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DkimSignatureError {
    pub kind: DkimSignatureErrorKind,

    // circumstantial diagnostics:
    pub domain: Option<DomainName>,  // header.d=   (a valid domain name)
    pub signature_data_base64: Option<String>,  // header.b=  (the string value!)
    // TODO more of these?
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DkimSignatureErrorKind {
    MissingVersionTag,
    UnsupportedVersion,
    HistoricAlgorithm,
    UnsupportedAlgorithm,
    MissingAlgorithmTag,
    MissingSignatureTag,
    InvalidBase64,
    MissingBodyHashTag,
    UnsupportedCanonicalization,
    InvalidDomain,
    MissingDomainTag,
    InvalidSignedHeaderName,
    SignedHeadersEmpty,
    FromHeaderNotSigned,
    MissingSignedHeadersTag,
    InvalidBodyLength,
    QueryMethodsNotSupported,
    InvalidSelector,
    MissingSelectorTag,
    InvalidTimestamp,
    InvalidExpiration,
    InvalidCopiedHeaderField,
    DomainMismatch,
    InvalidUserId,
    ExpirationNotAfterTimestamp,
    Utf8Encoding,
    InvalidTagList,
}

impl Display for DkimSignatureErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingVersionTag => write!(f, "v= tag missing"),
            Self::UnsupportedVersion=> write!(f, "unsupported version"),
            Self::HistoricAlgorithm => write!(f, "historic signature algorithm"),
            Self::UnsupportedAlgorithm => write!(f, "unsupported algorithm"),
            Self::MissingAlgorithmTag => write!(f, "a= tag missing"),
            Self::MissingSignatureTag => write!(f, "b= tag missing"),
            Self::InvalidBase64 => write!(f, "invalid Base64 string"),
            Self::MissingBodyHashTag => write!(f, "bh= tag missing"),
            Self::UnsupportedCanonicalization => write!(f, "unsupported canonicalization"),
            Self::InvalidDomain => write!(f, "invalid domain"),
            Self::MissingDomainTag => write!(f, "d= tag missing"),
            Self::InvalidSignedHeaderName => write!(f, "signed header name invalid"),
            Self::SignedHeadersEmpty => write!(f, "no signed headers"),
            Self::FromHeaderNotSigned => write!(f, "From header not signed"),
            Self::MissingSignedHeadersTag => write!(f, "h= tag missing"),
            Self::InvalidBodyLength => write!(f, "invalid body length"),
            Self::QueryMethodsNotSupported => write!(f, "query method not supported"),
            Self::InvalidSelector => write!(f, "invalid selector"),
            Self::MissingSelectorTag => write!(f, "s= tag missing"),
            Self::InvalidTimestamp => write!(f, "invalid timestamp"),
            Self::InvalidExpiration => write!(f, "invalid expiration"),
            Self::InvalidCopiedHeaderField => write!(f, "invalid header field in z= tag"),
            Self::DomainMismatch => write!(f, "domain mismatch"),
            Self::InvalidUserId => write!(f, "invalid user ID"),
            Self::ExpirationNotAfterTimestamp => write!(f, "expiration not after timestamp"),
            Self::Utf8Encoding => write!(f, "signature not UTF-8 encoded"),
            Self::InvalidTagList => write!(f, "invalid tag-list"),
        }
    }
}

/// DKIM signature data as encoded in a `DKIM-Signature` header field.
///
/// The *v=* tag (always 1), the *q=* tag (always includes dns/txt), and any
/// unknown tags are not included.
#[derive(Clone, Eq, PartialEq)]
pub struct DkimSignature {
    // The fields are strongly typed and have public visibility. This does allow
    // constructing an ‘invalid’ `DkimSignature` (eg with empty signature, or
    // empty signed headers) but we consider this acceptable, because this is
    // mainly an ‘output’ data container.
    //
    // Notes:
    // - i= is Option, because §3.5: ‘the Signer might wish to assert that
    // although it is willing to go as far as signing for the domain, it is
    // unable or unwilling to commit to an individual user name within the
    // domain. It can do so by including the domain part but not the local-part
    // of the identity.’

    /// The *a=* tag.
    pub algorithm: SignatureAlgorithm,
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
    pub user_id: Option<Identity>,  // rename "user" or "agent"?
    /// The *l=* tag.
    pub body_length: Option<u64>,
    /// The *s=* tag.
    pub selector: Selector,
    /// The *t=* tag.
    pub timestamp: Option<u64>,
    /// The *x=* tag.
    pub expiration: Option<u64>,
    /// The *z=* tag.
    pub copied_headers: Option<Box<[(FieldName, Box<[u8]>)]>>,  // not empty, name may contain `;`!

    // TODO make available "unknown" tags, especially RFC 6651 Reporting
}

impl DkimSignature {
    fn from_tag_list(tag_list: &TagList<'_>) -> Result<Self, DkimSignatureErrorKind> {
        let mut version_seen = false;
        let mut algorithm = None;
        let mut signature_data = None;
        let mut body_hash = None;
        let mut canonicalization = None;
        let mut domain = None;
        let mut signed_headers = None;
        let mut user_id = None;
        let mut body_length = None;
        let mut selector = None;
        let mut timestamp = None;
        let mut expiration = None;
        let mut copied_headers = None;

        for &TagSpec { name, value } in tag_list.as_ref() {
            match name {
                "v" => {
                    if value != "1" {
                        return Err(DkimSignatureErrorKind::UnsupportedVersion);
                    }

                    version_seen = true;
                }
                "a" => {
                    let value = value.parse().map_err(|_| {
                        #[cfg(not(feature = "sha1"))]
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
                    let value = parse_base64_tag_value(value)
                        .map_err(|_| DkimSignatureErrorKind::InvalidBase64)?;

                    signature_data = Some(value.into());
                }
                "bh" => {
                    let value = parse_base64_tag_value(value)
                        .map_err(|_| DkimSignatureErrorKind::InvalidBase64)?;

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
                    let mut sh = vec![];

                    for s in parse_colon_separated_tag_value(value) {
                        let name = FieldName::new(s)
                            .map_err(|_| DkimSignatureErrorKind::InvalidSignedHeaderName)?;
                        sh.push(name);
                    }

                    if sh.is_empty() {
                        return Err(DkimSignatureErrorKind::SignedHeadersEmpty);
                    }
                    if !sh.iter().any(|h| *h == "From") {
                        return Err(DkimSignatureErrorKind::FromHeaderNotSigned);
                    }

                    signed_headers = Some(sh.into());
                }
                "i" => {
                    let value = parse_dqp_tag_value(value)
                        .map_err(|_| DkimSignatureErrorKind::InvalidUserId)?;
                    let value = Identity::new(&value)
                        .map_err(|_| DkimSignatureErrorKind::InvalidUserId)?;

                    user_id = Some(value);
                }
                "l" => {
                    let value = value.parse()
                        .map_err(|_| DkimSignatureErrorKind::InvalidBodyLength)?;

                    body_length = Some(value);
                }
                "q" => {
                    let mut dns_txt_seen = false;

                    // TODO note that even though q= is specified as being "plain-text", the ABNF
                    // then allows dqp? see also erratum 4810
                    for s in parse_colon_separated_tag_value(value) {
                        if s.eq_ignore_ascii_case("dns/txt") {
                            dns_txt_seen = true;
                        }
                    }

                    if !dns_txt_seen {
                        return Err(DkimSignatureErrorKind::QueryMethodsNotSupported);
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
                        let (name, value) = parse_dqp_header_field(piece)
                            .map_err(|_| DkimSignatureErrorKind::InvalidCopiedHeaderField)?;
                        headers.push((name, value));
                    }

                    copied_headers = Some(headers.into());
                }
                _ => {}
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

        if let Some(id) = &user_id {
            if !id.domain_part.eq_or_subdomain_of(&domain) {
                return Err(DkimSignatureErrorKind::DomainMismatch);
            }
        }

        if let (Some(timestamp), Some(expiration)) = (timestamp, expiration) {
            if expiration <= timestamp {
                return Err(DkimSignatureErrorKind::ExpirationNotAfterTimestamp);
            }
        }

        let canonicalization = canonicalization.unwrap_or_default();

        Ok(Self {
            algorithm,
            signature_data,
            body_hash,
            canonicalization,
            domain,
            signed_headers,
            user_id,
            body_length,
            selector,
            timestamp,
            expiration,
            copied_headers,
        })
    }
}

impl FromStr for DkimSignature {
    type Err = DkimSignatureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let tag_list = match TagList::from_str(s) {
            Ok(r) => r,
            Err(_e) => {
                return Err(DkimSignatureError {
                    kind: DkimSignatureErrorKind::InvalidTagList,
                    domain: None,
                    signature_data_base64: None,
                });
            }
        };

        match DkimSignature::from_tag_list(&tag_list) {
            Ok(sig) => Ok(sig),
            Err(e) => {
                // TODO attempt to find _some_ info for diagnostics; more?
                let domain = tag_list.as_ref().iter().find(|spec| spec.name == "d")
                    .and_then(|spec| DomainName::new(spec.value).ok());
                let signature_data_base64 = tag_list.as_ref().iter().find(|spec| spec.name == "b")
                    .map(|spec| tag_list::strip_fws_from_tag_value(spec.value));
                Err(DkimSignatureError {
                    kind: e,
                    domain,
                    signature_data_base64,
                })
            }
        }
    }
}

struct CopiedHeaders<'a>(&'a [(FieldName, Box<[u8]>)]);

impl fmt::Debug for CopiedHeaders<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_list();
        for (name, value) in self.0 {
            d.entry(&(name, value.as_bstr()));
        }
        d.finish()
    }
}

impl fmt::Debug for DkimSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("DkimSignature")
            .field("algorithm", &self.algorithm)
            .field("signature_data", &util::encode_binary(&self.signature_data))
            .field("body_hash", &util::encode_binary(&self.body_hash))
            .field("canonicalization", &self.canonicalization)
            .field("domain", &self.domain)
            .field("signed_headers", &self.signed_headers)
            .field("user_id", &self.user_id)
            .field("body_length", &self.body_length)
            .field("selector", &self.selector)
            .field("timestamp", &self.timestamp)
            .field("expiration", &self.expiration)
            .field("copied_headers", &self.copied_headers.as_deref().map(CopiedHeaders))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tag_list::TagList;
    use base64ct::{Base64, Encoding};

    #[test]
    fn domain_name_ok() {
        assert!(DomainName::new("com").is_ok());
        assert!(DomainName::new("c,m").is_ok());
        assert!(DomainName::new("example.com").is_ok());
        assert!(DomainName::new("_abc.example.com").is_ok());
        assert!(DomainName::new("中国").is_ok());
        assert!(DomainName::new("example.中国").is_ok());
        assert!(DomainName::new("☕.example.中国").is_ok());
        assert!(DomainName::new("xn--53h.example.xn--fiqs8s").is_ok());

        assert!(DomainName::new("-com").is_err());
        assert!(DomainName::new("c;m").is_err());
        assert!(DomainName::new("123").is_err());
        assert!(DomainName::new("com.").is_err());
        assert!(DomainName::new("example-.com").is_err());
        assert!(DomainName::new("example.123").is_err());
        assert!(DomainName::new("example.com.").is_err());
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
                algorithm: SignatureAlgorithm::RsaSha256,
                signature_data: Base64::decode_vec(
                    "dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR"
                )
                .unwrap()
                .into(),
                body_hash: Base64::decode_vec("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
                    .unwrap()
                    .into(),
                canonicalization: Canonicalization {
                    header: CanonicalizationAlgorithm::Simple,
                    body: CanonicalizationAlgorithm::Simple,
                },
                domain: DomainName::new("example.net").unwrap(),
                signed_headers: [
                    FieldName::new("from").unwrap(),
                    FieldName::new("to").unwrap(),
                    FieldName::new("subject").unwrap(),
                    FieldName::new("date").unwrap(),
                ]
                .into(),
                user_id: Some(Identity::new("@eng.example.net").unwrap()),
                selector: Selector::new("brisbane").unwrap(),
                body_length: None,
                timestamp: Some(1117574938),
                expiration: Some(1118006938),
                copied_headers: Some(
                    [
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
                    .into()
                ),
            }
        );
    }

    #[test]
    fn complicated_example_signature() {
        // TODO
        let example = " v = 1 ; a=rsa-sha256;d=example.net; s=brisbane;
   c=simple; q=dns/txt; i=中文=40en
    g.example =2E net;
   t=1117574938; x=1118006938;
   h=from:to:subject:date;
   bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;
   b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR";
        let example = example.replace('\n', "\r\n");

        let q = TagList::from_str(&example).unwrap();

        let hdr = DkimSignature::from_tag_list(&q).unwrap();

        assert_eq!(
            hdr,
            DkimSignature {
                algorithm: SignatureAlgorithm::RsaSha256,
                signature_data: Base64::decode_vec(
                    "dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR"
                )
                .unwrap()
                .into(),
                body_hash: Base64::decode_vec("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
                    .unwrap()
                    .into(),
                canonicalization: Canonicalization {
                    header: CanonicalizationAlgorithm::Simple,
                    body: CanonicalizationAlgorithm::Simple,
                },
                domain: DomainName::new("example.net").unwrap(),
                signed_headers: [
                    FieldName::new("from").unwrap(),
                    FieldName::new("to").unwrap(),
                    FieldName::new("subject").unwrap(),
                    FieldName::new("date").unwrap(),
                ]
                .into(),
                user_id: Some(Identity::new("中文@eng.example.net").unwrap()),
                selector: Selector::new("brisbane").unwrap(),
                body_length: None,
                timestamp: Some(1117574938),
                expiration: Some(1118006938),
                copied_headers: None,
            }
        );
    }
}
