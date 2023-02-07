//! DKIM signature.

use crate::{
    canon,
    crypto::{HashAlgorithm, KeyType},
    dqp,
    header::{FieldName, HeaderFields},
    tag_list::{
        self, parse_base64_tag_value, parse_colon_separated_tag_value, parse_dqp_header_field,
        TagList, TagSpec,
    },
    util::CanonicalStr,
};
use base64ct::{Base64, Encoding};
use std::{
    collections::HashSet,
    error::Error,
    fmt::{self, Display, Formatter, Write},
    str::{self, FromStr},
};

/// A signature algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureAlgorithm {
    /// The *rsa-sha256* signature algorithm.
    RsaSha256,
    /// The *ed25519-sha256* signature algorithm.
    Ed25519Sha256,
}

impl SignatureAlgorithm {
    /// Returns this signature algorithm’s key type.
    pub fn to_key_type(self) -> KeyType {
        match self {
            Self::RsaSha256 => KeyType::Rsa,
            Self::Ed25519Sha256 => KeyType::Ed25519,
        }
    }

    /// Returns this signature algorithm’s hash algorithm.
    pub fn to_hash_algorithm(self) -> HashAlgorithm {
        match self {
            Self::RsaSha256 | Self::Ed25519Sha256 => HashAlgorithm::Sha256,
        }
    }
}

// TODO make inherent method instead?
impl From<(KeyType, HashAlgorithm)> for SignatureAlgorithm {
    fn from(input: (KeyType, HashAlgorithm)) -> Self {
        match input {
            (KeyType::Rsa, HashAlgorithm::Sha256) => Self::RsaSha256,
            (KeyType::Ed25519, HashAlgorithm::Sha256) => Self::Ed25519Sha256,
        }
    }
}

impl CanonicalStr for SignatureAlgorithm {
    fn canonical_str(&self) -> &'static str {
        match self {
            Self::RsaSha256 => "rsa-sha256",
            Self::Ed25519Sha256 => "ed25519-sha256",
        }
    }
}

impl Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.canonical_str())
    }
}

impl FromStr for SignatureAlgorithm {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("rsa-sha256") {
            Ok(Self::RsaSha256)
        } else if s.eq_ignore_ascii_case("ed25519-sha256") {
            Ok(Self::Ed25519Sha256)
        } else {
            Err("unknown signature algorithm")
        }
    }
}

/// A canonicalization algorithm.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
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
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("simple") {
            Ok(Self::Simple)
        } else if s.eq_ignore_ascii_case("relaxed") {
            Ok(Self::Relaxed)
        } else {
            Err("unknown canonicalization algorithm")
        }
    }
}

/// A pair of header/body canonicalization algorithms.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
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
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(if let Some((header, body)) = s.split_once('/') {
            Self {
                header: CanonicalizationAlgorithm::from_str(header)?,
                body: CanonicalizationAlgorithm::from_str(body)?,
            }
        } else {
            Self {
                header: CanonicalizationAlgorithm::from_str(s)?,
                body: Default::default(),
            }
        })
    }
}

// TODO all from viaspf, revise:

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseDomainError;

impl Display for ParseDomainError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "could not parse domain name")
    }
}

impl Error for ParseDomainError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ident {
    // for i= tag:
    // [ Local-part ] "@" domain-name
    // email address where local-part is optional
    pub local_part: Option<Box<str>>,
    pub domain_part: DomainName,
}

impl Ident {
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
    // TODO FromStr
    pub fn new(s: &str) -> Result<Self, ParseDomainError> {
        // Note format:
        // domain-name     = sub-domain 1*("." sub-domain)
        if s.ends_with('.') {
            return Err(ParseDomainError);
        }
        // TODO Store the domain in ASCII or Unicode form? better as-is to preserve case (cosmetic)
        // let s = idna::domain_to_ascii(s).map_err(|_| ParseDomainError)?;
        if is_valid_dns_name(s) {
            Ok(Self(s.into()))
        } else {
            Err(ParseDomainError)
        }
    }

    // TODO support IDNA domains
    pub fn eq_or_subdomain_of(&self, other: &DomainName) -> bool {
        if self == other {
            return true;
        }

        let name = &self.0;
        let other = &other.0;

        if name.len() > other.len() {
            let len = name.len() - other.len();
            matches!(name.get(len..), Some(s) if s.eq_ignore_ascii_case(other))
                && matches!(name.get(..len), Some(s) if s.ends_with('.'))
        } else {
            false
        }
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

// TODO support IDNA-equiv comparison
impl PartialEq for DomainName {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

// TODO revisit
fn is_valid_dns_name(mut s: &str) -> bool {
    fn is_tld(s: &str) -> bool {
        is_label(s) && !s.chars().all(|c: char| c.is_ascii_digit())
    }

    if let Some(sx) = s.strip_suffix('.') {
        s = sx;
    }

    // TODO no need to check this, will only be needed when <sel>._domainkey.<domain> is constructed
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

fn is_label(s: &str) -> bool {
    has_valid_label_len(s)
        && s.starts_with(|c: char| c.is_ascii_alphanumeric())
        && s.ends_with(|c: char| c.is_ascii_alphanumeric())
        && s.chars().all(|c: char| c.is_ascii_alphanumeric() || c == '-')
}

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
    pub fn new(s: &str) -> Result<Self, &'static str> {
        // TODO this check not necessary, will fail later:
        if !has_valid_domain_len(s) {
            return Err("invalid selector");
        }

        // lenient parsing domain name labels, allows things like "dkim_123"
        if !s.split('.').all(|l| {
            has_valid_label_len(l)
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(tag_list::is_tval_char)
        }) {
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

// TODO support IDNA-equiv comparison
impl PartialEq for Selector {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DkimSignatureError {
    // circumstantial diagnostics:
    pub domain: Option<DomainName>,  // header.d=   (a valid domain name)
    pub signature_data_base64: Option<String>,  // header.b=  (the string value!)

    // error:
    pub kind: DkimSignatureErrorKind,
}

// TODO differentiate between fatal (invalid domain) and unsupported (unknown algorithm) errors
// *for the purpose of parsing*
// eg if whole sig can be parsed, but alg is unknown, can still return a DkimSignature (?)
// TODO rename DkimSignatureErrorKind ?
#[derive(Debug, PartialEq, Eq)]
pub enum DkimSignatureErrorKind {
    MissingVersionTag,
    UnsupportedVersion,
    HistoricAlgorithm,
    UnsupportedAlgorithm,
    MissingAlgorithmTag,
    MissingSignatureTag,
    MissingBodyHashTag,
    UnsupportedCanonicalization,
    InvalidDomain,
    MissingDomainTag,
    SignedHeadersEmpty,
    FromHeaderNotSigned,
    MissingSignedHeadersTag,
    InvalidBodyLength,
    QueryMethodsNotSupported,
    InvalidSelector,
    MissingSelectorTag,
    InvalidTimestamp,
    InvalidExpiration,
    ValueSyntax,
    DomainMismatch,
    InvalidUserId,

    InvalidTagList,
}

impl FromStr for DkimSignature {
    type Err = DkimSignatureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let tag_list = match TagList::from_str(s) {
            Ok(r) => r,
            Err(_e) => {
                return Err(DkimSignatureError {
                    domain: None,
                    signature_data_base64: None,
                    kind: DkimSignatureErrorKind::InvalidTagList,
                });
            }
        };

        match DkimSignature::from_tag_list(&tag_list) {
            Ok(sig) => Ok(sig),
            Err(e) => {
                // attempt to find _some_ info for diagnostics
                let domain = tag_list.as_ref().iter().find(|spec| spec.name == "d")
                    .and_then(|spec| DomainName::new(spec.value).ok());
                let signature_data_base64 = tag_list.as_ref().iter().find(|spec| spec.name == "b")
                    .map(|spec| tag_list::trim_base64_tag_value(spec.value));
                Err(DkimSignatureError {
                    domain,
                    signature_data_base64,
                    kind: e,
                })
            }
        }
    }
}

impl Display for DkimSignatureErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingVersionTag => write!(f, "v= tag missing"),
            Self::UnsupportedVersion=> write!(f, "unsupported version"),
            Self::HistoricAlgorithm => write!(f, "historic signature algorithm"),
            Self::UnsupportedAlgorithm => write!(f, "unsupported algorithm"),
            Self::MissingAlgorithmTag => write!(f, "a= tag missing"),
            Self::MissingSignatureTag => write!(f, "s= tag missing"),
            Self::MissingBodyHashTag => write!(f, "bh= tag missing"),
            Self::UnsupportedCanonicalization => write!(f, "unsupported canonicalization"),
            Self::InvalidDomain => write!(f, "invalid domain"),
            Self::MissingDomainTag => write!(f, "d= tag missing"),
            Self::SignedHeadersEmpty => write!(f, "no signed headers"),
            Self::FromHeaderNotSigned => write!(f, "From header not signed"),
            Self::MissingSignedHeadersTag => write!(f, "h= tag missing"),
            Self::InvalidBodyLength => write!(f, "invalid body length"),
            Self::QueryMethodsNotSupported => write!(f, "query method not supported"),
            Self::InvalidSelector => write!(f, "invalid selector"),
            Self::MissingSelectorTag => write!(f, "s= tag missing"),
            Self::InvalidTimestamp => write!(f, "invalid timestamp"),
            Self::InvalidExpiration => write!(f, "invalid expiration"),
            Self::ValueSyntax => write!(f, "syntax error"),
            Self::DomainMismatch => write!(f, "domain mismatch"),
            Self::InvalidUserId => write!(f, "invalid user ID"),
            Self::InvalidTagList => write!(f, "invalid tag-list"),
        }
    }
}

/// A DKIM signature as encoded in a `DKIM-Signature` header field.
#[derive(Clone, Eq, PartialEq)]
pub struct DkimSignature {
    // The fields are strongly typed and have public visibility. This does allow
    // constructing an ‘invalid’ `DkimSignature` (eg with empty signature, or
    // empty signed headers) but given usage contexts this is acceptable.

    pub algorithm: SignatureAlgorithm,
    pub signature_data: Box<[u8]>,
    pub body_hash: Box<[u8]>,
    pub canonicalization: Canonicalization,
    pub domain: DomainName,
    pub signed_headers: Box<[FieldName]>,
    pub user_id: Ident,  // TODO Option?
    pub body_length: Option<u64>,
    pub selector: Selector,
    pub copied_headers: Option<Box<[(FieldName, Box<[u8]>)]>>,
    pub timestamp: Option<u64>,
    pub expiration: Option<u64>,
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
                    // TODO here and elsewhere ensure conformance to value syntax (no "a b\r\n c x..."), else ValueSyntax
                    let value = value.parse().map_err(|_| {
                        if value.eq_ignore_ascii_case("rsa-sha1") {
                            // Note: special-case rsa-sha1 as recognised but
                            // no longer supported (RFC 8301).
                            DkimSignatureErrorKind::HistoricAlgorithm
                        } else {
                            DkimSignatureErrorKind::UnsupportedAlgorithm
                        }
                    })?;
                    algorithm = Some(value);
                }
                "b" => {
                    let value = parse_base64_tag_value(value)
                        .map_err(|_| DkimSignatureErrorKind::ValueSyntax)?;
                    signature_data = Some(value.into());
                }
                "bh" => {
                    let value = parse_base64_tag_value(value)
                        .map_err(|_| DkimSignatureErrorKind::ValueSyntax)?;
                    body_hash = Some(value.into());
                }
                "c" => {
                    // TODO here and elsewhere ensure conformance to value syntax (no "a b\r\n c x..."), else ValueSyntax
                    let value = value.parse()
                        .map_err(|_| DkimSignatureErrorKind::UnsupportedCanonicalization)?;
                    canonicalization = Some(value);
                }
                "d" => {
                    let value = DomainName::new(value)
                        .map_err(|_| DkimSignatureErrorKind::InvalidDomain)?;
                    domain = Some(value);
                }
                "h" => {
                    let mut sh = vec![];
                    for v in parse_colon_separated_tag_value(value) {
                        let name = FieldName::new(v).map_err(|_| DkimSignatureErrorKind::ValueSyntax)?;
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
                    // TODO
                    let value = Ident::new(value)
                        .map_err(|_| DkimSignatureErrorKind::InvalidUserId)?;
                    user_id = Some(value);
                }
                "l" => {
                    let value: u64 = value
                        .parse()
                        .map_err(|_| DkimSignatureErrorKind::InvalidBodyLength)?;
                    body_length = Some(value);
                }
                "q" => {
                    let mut dns_txt_seen = false;
                    for v in parse_colon_separated_tag_value(value) {
                        if v.eq_ignore_ascii_case("dns/txt") {
                            dns_txt_seen = true;
                        }
                    }
                    if !dns_txt_seen {
                        return Err(DkimSignatureErrorKind::QueryMethodsNotSupported);
                    }
                }
                "s" => {
                    let value = Selector::new(value)
                        .map_err(|_| DkimSignatureErrorKind::InvalidSelector)?;
                    selector = Some(value);
                }
                "t" => {
                    let value = value
                        .parse()
                        .map_err(|_| DkimSignatureErrorKind::InvalidTimestamp)?;
                    timestamp = Some(value);
                }
                "x" => {
                    let value = value
                        .parse()
                        .map_err(|_| DkimSignatureErrorKind::InvalidExpiration)?;
                    expiration = Some(value);
                }
                "z" => {
                    let mut hs = vec![];
                    for piece in value.split('|') {
                        let (name, value) = parse_dqp_header_field(piece)
                            .map_err(|_| DkimSignatureErrorKind::ValueSyntax)?;
                        hs.push((name, value));
                    }
                    copied_headers = Some(hs.into());
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

        let user_id = match user_id {
            Some(i) => {
                let i_domain = &i.domain_part;
                if !i_domain.eq_or_subdomain_of(&domain) {
                    return Err(DkimSignatureErrorKind::DomainMismatch);
                }
                i
            }
            None => Ident::from_domain(domain.clone()),
        };

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

    pub(crate) fn format_without_signature(&self, width: usize) -> String {
        let start_i = "DKIM-Signature:".len();

        let mut result = String::new();
        let mut i = start_i;

        format_tag_into_string(&mut result, width, &mut i, "v", "1");

        format_tag_into_string(&mut result, width, &mut i, "d", self.domain.as_ref());

        format_tag_into_string(&mut result, width, &mut i, "s", self.selector.as_ref());

        format_tag_into_string(&mut result, width, &mut i, "a", self.algorithm.canonical_str());

        let canon = match (self.canonicalization.header, self.canonicalization.body) {
            (CanonicalizationAlgorithm::Simple, CanonicalizationAlgorithm::Simple) => None,
            (CanonicalizationAlgorithm::Simple, CanonicalizationAlgorithm::Relaxed) => {
                Some("simple/relaxed")
            }
            (CanonicalizationAlgorithm::Relaxed, CanonicalizationAlgorithm::Simple) => {
                Some("relaxed")
            }
            (CanonicalizationAlgorithm::Relaxed, CanonicalizationAlgorithm::Relaxed) => {
                Some("relaxed/relaxed")
            }
        };
        if let Some(canon) = canon {
            format_tag_into_string(&mut result, width, &mut i, "c", canon);
        }

        if let Some(timestamp) = &self.timestamp {
            format_tag_into_string(&mut result, width, &mut i, "t", &timestamp.to_string());
        }
        if let Some(expiration) = &self.expiration {
            format_tag_into_string(&mut result, width, &mut i, "x", &expiration.to_string());
        }

        format_colon_separated_into_string(&mut result, width, &mut i, "h", &self.signed_headers[..]);

        if let Some(z) = &self.copied_headers {
            // TODO i
            let s: Vec<_> = z.iter()
                .map(|(k, v)| format!("{}:{}", k.as_ref(), dqp::dqp_encode(v, true)))
                .collect();
            result.push_str("\r\n\tz=");
            let value = s.join("|");
            result.push_str(&value);
            result.push(';');
        }

        let bh = encode_binary(&self.body_hash);
        format_base64_into_string(&mut result, width, &mut i, "bh", &bh);

        if i + 4 <= width {  // at least one additional char behind =
            result.push_str(" b=");
        } else {
            result.push_str("\r\n\tb=");
        }

        result
    }
}

pub fn encode_binary<T: AsRef<[u8]>>(input: T) -> String {
    Base64::encode_string(input.as_ref())
}

// TODO
impl fmt::Debug for DkimSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("DkimSignature")
            .field("algorithm", &self.algorithm)
            .field("signature_data", &encode_binary(&self.signature_data))
            .field("body_hash", &encode_binary(&self.body_hash))
            .field("canonicalization", &self.canonicalization)
            .field("domain", &self.domain)
            .field("signed_headers", &self.signed_headers)
            .field("user_id", &self.user_id)
            .field("body_length", &self.body_length)
            .field("selector", &self.selector)
            .field("copied_headers", &self.copied_headers)
            .field("timestamp", &self.timestamp)
            .field("expiration", &self.expiration)
            .finish()
    }
}

pub const LINE_WIDTH: usize = 78;

fn format_tag_into_string(
    result: &mut String,
    width: usize,
    i: &mut usize,
    tag: &'static str,
    value: &str,
) {
    let taglen = tag.len() + value.chars().count() + 3;  // WSP + tag + '=' + val + ';'

    if *i + taglen <= width {
        result.push(' ');
        *i += taglen;
    } else {
        result.push_str("\r\n\t");
        *i = taglen;
    }
    write!(result, "{tag}={value};").unwrap();
}

fn format_colon_separated_into_string<I, S>(
    result: &mut String,
    width: usize,
    i: &mut usize,
    tag: &'static str,
    value: I,
)
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut iter = value.into_iter();  // not-empty!

    let first_name = iter.next().unwrap();

    let taglen = first_name.as_ref().chars().count() + 4;  // WSP + tag + '=' + name + ';'/':'
    if *i + taglen <= width {
        result.push(' ');
        *i += taglen;
    } else {
        result.push_str("\r\n\t");
        *i = taglen;
    }
    write!(result, "{}={}", tag, first_name.as_ref()).unwrap();  // don't write ;/: yet

    for name in iter {
        let name = name.as_ref();
        result.push(':');
        let elemlen = name.chars().count() + 1;  // name + ';'/':'
        if *i + elemlen <= width {
            *i += elemlen;
        } else {
            result.push_str("\r\n\t");
            *i = elemlen + 1;
        }
        write!(result, "{name}").unwrap();  // don't write ;/: yet
    }

    result.push(';');
}

fn format_base64_into_string(
    result: &mut String,
    width: usize,
    i: &mut usize,
    tag: &'static str,  // "bh" "b"
    value: &str,        // ef7AB+MIi...
) {
    let taglen = tag.len() + 3;  // WSP + tag + '=' + 1char

    if *i + taglen <= width {  // at least one additional char behind =
        write!(result, " {tag}=").unwrap();
        *i += taglen - 1;
    } else {
        write!(result, "\r\n\t{tag}=").unwrap();
        *i = taglen - 1;
    }

    let first_chunk_len = width.saturating_sub(*i).max(1);  //min len 1
    let first_chunk_len = first_chunk_len.min(value.len());
    let first_chunk = &value[..first_chunk_len];

    result.push_str(first_chunk);
    *i += first_chunk.chars().count();

    let rest = &value[first_chunk_len..];

    for chunk in rest.as_bytes().chunks(77) {  // for loop not entered if no chunks
        let s = str::from_utf8(chunk).unwrap();
        result.push_str("\r\n\t");
        result.push_str(s);
        *i = s.chars().count() + 1;
    }
    // if final chunk makes line === 78 chars long, the final ; will be appended nevertheless (=> width == 79)
    result.push(';');
    *i += 1;
}

pub(crate) fn push_signature_data(
    formatted_header: &mut String,
    signature_data: &[u8],
    line_width: usize,
) {
    let s = encode_binary(signature_data);
    // note s contains only ASCII now

    let last_line = formatted_header.rsplit("\r\n").next().unwrap_or(&formatted_header[..]);
    let len = last_line.chars().count();

    let first_chunk_len = line_width.saturating_sub(len).max(1);  //min len 1

    let first_chunk = &s[..first_chunk_len];

    formatted_header.push_str(first_chunk);

    for chunk in s[first_chunk_len..].as_bytes().chunks(77) {  // for loop not entered if no chunks
        let s = str::from_utf8(chunk).unwrap();
        formatted_header.push_str("\r\n\t");
        formatted_header.push_str(s);
    }
}

pub(crate) fn canon_dkim_header(
    canon: CanonicalizationAlgorithm,
    name: &str,  // "DKIM-Signature", but with original (upper/lower) case
    formatted_hdr_without_sig: &str,
) -> String {
    let result = match canon {
        CanonicalizationAlgorithm::Relaxed => {
            let mut field_value = b"dkim-signature:".to_vec();
            canon::canon_header_relaxed(&mut field_value, formatted_hdr_without_sig.as_bytes());
            String::from_utf8_lossy(&field_value).into_owned()
        }
        CanonicalizationAlgorithm::Simple => {
            format!("{name}:{formatted_hdr_without_sig}")
        }
    };

    //trace!("canonicalized DKIM header: {result:?}");

    result
}

pub(crate) fn get_default_signed_headers() -> Vec<FieldName> {
    let def = [
        // TODO from opendkim, revise, make configurable:
        "From",
        "Reply-To",
        "Subject",
        "Date",
        "To",
        "Cc",
        "Resent-Date",
        "Resent-From",
        "Resent-Sender",
        "Resent-To",
        "Resent-Cc",
        "In-Reply-To",
        "References",
        "List-ID",
        "List-Help",
        "List-Unsubscribe",
        "List-Subscribe",
        "List-Post",
        "List-Owner",
        "List-Archive",
        // additional, mine:
        "Message-ID",
    ];
    def.into_iter().map(|x| FieldName::new(x).unwrap()).collect()
}

pub(crate) fn select_signed_headers(
    orig_signed_headers: &[FieldName],
    orig_oversigned_headers: &[FieldName],
    headers: &HeaderFields,
) -> Vec<FieldName> {
    // TODO dedupe necessary? precondition?
    let mut tmp: HashSet<&FieldName> = HashSet::new();
    let orig_signed_headers: Vec<&FieldName> = orig_signed_headers
        .iter()
        .filter(|f| tmp.insert(f))
        .collect();
    tmp.clear();
    let orig_oversigned_headers: Vec<&FieldName> = orig_oversigned_headers
        .iter()
        .filter(|f| tmp.insert(f))
        .collect();

    let signed_headers: HashSet<_> = orig_signed_headers.iter().copied().collect();
    let oversigned_headers: HashSet<_> = orig_oversigned_headers.iter().copied().collect();

    debug_assert!({
        let from = FieldName::new("From").unwrap();
        signed_headers.contains(&from) || oversigned_headers.contains(&from)
    });

    let mut result = vec![];

    // iterate over *HeaderFields* in reverse, picking any header that is in
    // signed or oversigned headers
    // this way headers occurring multiple times are *all* selected, in verifier eval order

    let signed_headers = headers.as_ref().iter().rev().filter_map(|(field_name, _)| {
        signed_headers.get(field_name)
            .or_else(|| oversigned_headers.get(field_name))
    });

    for &h in signed_headers {
        result.push(h.clone());
    }

    // then add one more of each "oversigned" header

    for h in orig_oversigned_headers {
        result.push(h.clone());
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tag_list::TagList;

    #[test]
    fn example_signature() {
        let example = "v=1; a=rsa-sha256; d=example.net; s=brisbane;
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
                    ).unwrap().into(),
                body_hash: Base64::decode_vec("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=").unwrap().into(),
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
                ].into(),
                user_id: Ident::new("@eng.example.net").unwrap(),
                selector: Selector::new("brisbane").unwrap(),
                body_length: None,
                timestamp: Some(1117574938),
                expiration: Some(1118006938),
                copied_headers: Some([
                    (FieldName::new("From").unwrap(), Box::from(*b"foo@eng.example.net")),
                    (FieldName::new("To").unwrap(), Box::from(*b"joe@example.com")),
                    (FieldName::new("Subject").unwrap(), Box::from(*b"demo run")),
                    (FieldName::new("Date").unwrap(), Box::from(*b"July 5, 2005 3:44:08 PM -0700")),
                ].into()),
            }
        );
    }

    #[test]
    fn dkim_signature_from_tag_list_ok() {
        let example = " v = 1 ; a=rsa-sha256;d=example.net; s=brisbane;
  c=simple; q=dns/txt; i=中文@eng.example.net;
  t=1117574938; x=1118006938;
  h=from:to:subject:date;
  z=From:foo@eng.example.net|To:joe@example.com|
   Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700
   ;
  bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;
  b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR";
        let example = example.replace('\n', "\r\n");

        let q = TagList::from_str(&example).unwrap();

        let hdr = DkimSignature::from_tag_list(&q).unwrap();

        assert_eq!(
            hdr.signed_headers.as_ref(),
            [
                FieldName::new("from").unwrap(),
                FieldName::new("to").unwrap(),
                FieldName::new("subject").unwrap(),
                FieldName::new("date").unwrap(),
            ]
        );
    }

    #[test]
    fn select_signed_headers_ok() {
        let headers = HeaderFields::from_vec(vec![
            ("from".to_owned(), b"".to_vec()),
            ("aa".to_owned(), b"".to_vec()),
            ("bb".to_owned(), b"".to_vec()),
            ("cc".to_owned(), b"".to_vec()),
            ("aa".to_owned(), b"".to_vec()),
            ("ee".to_owned(), b"".to_vec()),
        ])
        .unwrap();

        let ret = select_signed_headers(
            &[
                FieldName::new("From").unwrap(),
                FieldName::new("Aa").unwrap(),
                FieldName::new("Bb").unwrap(),
            ],
            &[
                FieldName::new("Bb").unwrap(),
                FieldName::new("Cc").unwrap(),
                FieldName::new("Dd").unwrap(),
            ],
            &headers,
        );

        assert!(ret
            .iter()
            .map(|f| f.as_ref())
            .eq(["Aa", "Cc", "Bb", "Aa", "From", "Bb", "Cc", "Dd"]));
    }
}
