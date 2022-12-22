//! DKIM signature.

use crate::{
    canon,
    crypto::{HashAlgorithm, KeyType},
    dqp,
    header::{FieldName, HeaderFields},
    tag_list::{
        self,
        parse_base64_tag_value, parse_colon_separated_tag_value, parse_dqp_header_field, TagList,
        TagSpec,
    },
};
use std::{
    fmt::{self, Display, Formatter, Write},
    str,
};
use tracing::trace;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    RsaSha256,
    Ed25519Sha256,
}

impl SignatureAlgorithm {
    pub fn to_key_type(self) -> KeyType {
        match self {
            Self::RsaSha256 => KeyType::Rsa,
            Self::Ed25519Sha256 => KeyType::Ed25519,
        }
    }

    pub fn to_hash_algorithm(self) -> HashAlgorithm {
        match self {
            Self::RsaSha256 | Self::Ed25519Sha256 => HashAlgorithm::Sha256,
        }
    }
}

impl From<(KeyType, HashAlgorithm)> for SignatureAlgorithm {
    fn from(input: (KeyType, HashAlgorithm)) -> Self {
        match input {
            (KeyType::Rsa, HashAlgorithm::Sha256) => Self::RsaSha256,
            (KeyType::Ed25519, HashAlgorithm::Sha256) => Self::Ed25519Sha256,
        }
    }
}

#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub enum CanonicalizationAlgorithm {
    #[default]
    Simple,
    Relaxed,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Canonicalization {
    pub header: CanonicalizationAlgorithm,
    pub body: CanonicalizationAlgorithm,
}

// TODO all from viaspf, revise:

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseDomainError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ident {
    // for i= tag:
    // [ Local-part ] "@" domain-name
    // email address where local-part is optional
    local_part: Option<String>,
    domain_part: DomainName,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainName {
    // for d= tag:
    // domain-name     = sub-domain 1*("." sub-domain)
    name: String,
}

impl DomainName {
    pub fn new(s: &str) -> Result<Self, ParseDomainError> {
        if s.ends_with('.') {
            return Err(ParseDomainError);
        }
        // TODO no, not the case here:
        // §4.3: ‘Internationalized domain names MUST be encoded as A-labels’
        let s = idna::domain_to_ascii(s).map_err(|_| ParseDomainError)?;
        if is_valid_dns_name(&s) {
            // TODO final . needed?
            // if !s.ends_with('.') {
            //     s.push('.');
            // }
            Ok(Self { name: s })
        } else {
            Err(ParseDomainError)
        }
    }

    pub fn eq_or_subdomain_of(&self, other: &DomainName) -> bool {
        let name = &self.name;
        let other = &other.name;

        if name.eq_ignore_ascii_case(other) {
            return true;
        }

        name.len() > other.len() && {
            let len = name.len() - other.len();
            matches!(name.get(len..), Some(s) if s.eq_ignore_ascii_case(other))
                && matches!(name.get(..len), Some(s) if s.ends_with('.'))
        }
    }
}

impl Display for DomainName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // self.name[..(self.name.len() - 1)].fmt(f)
        self.name.fmt(f)
    }
}

impl AsRef<str> for DomainName {
    fn as_ref(&self) -> &str {
        &self.name
    }
}

fn is_valid_dns_name(mut s: &str) -> bool {
    const MAX_DOMAIN_LENGTH: usize = 253;

    fn has_valid_domain_len(s: &str) -> bool {
        matches!(s.len(), 1..=MAX_DOMAIN_LENGTH)
    }
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

fn is_label(s: &str) -> bool {
    fn has_valid_label_len(s: &str) -> bool {
        matches!(s.len(), 1..=63)
    }

    has_valid_label_len(s)
        && s.starts_with(|c: char| c.is_ascii_alphanumeric())
        && s.ends_with(|c: char| c.is_ascii_alphanumeric())
        && s.chars().all(|c: char| c.is_ascii_alphanumeric() || c == '-')
}

#[derive(Debug, PartialEq, Eq)]
pub struct DkimSignatureError {
    // circumstantial diagnostics:
    pub domain: Option<DomainName>,  // header.d=   (a valid domain name)
    pub signature_data_base64: Option<String>,  // header.b=  (the string value!)

    // error:
    pub cause: DkimSignatureParseError,
}

// TODO differentiate between fatal (invalid domain) and unsupported (unknown algorithm) errors
// *for the purpose of parsing*
// eg if whole sig can be parsed, but alg is unknown, can still return a DkimSignature (?)
// TODO rename *Kind ?
#[derive(Debug, PartialEq, Eq)]
pub enum DkimSignatureParseError {       // Auth-Res:
    MissingVersionTag,                   // permerror ?
    UnsupportedVersion,                  // neutral ?
    HistoricAlgorithm,                   // permerror ?
    UnsupportedAlgorithm,                // neutral ?
    MissingAlgorithmTag,                 // ...
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

// TODO make inherent method
pub fn parse_dkim_signature(s: &str) -> Result<DkimSignature, DkimSignatureError> {
    let tag_list = match TagList::from_str(s) {
        Ok(r) => r,
        Err(_e) => {
            return Err(DkimSignatureError {
                domain: None,
                signature_data_base64: None,
                cause: DkimSignatureParseError::InvalidTagList,
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
                cause: e,
            })
        }
    }
}

#[derive(PartialEq, Eq)]
pub struct DkimSignature {
    pub algorithm: SignatureAlgorithm,
    pub signature_data: Vec<u8>,
    pub body_hash: Vec<u8>,
    pub canonicalization: Canonicalization,
    pub domain: DomainName,
    pub signed_headers: Vec<FieldName>,  // not empty, must contain "From"
    pub user_id: Ident,  // 'ident'
    pub body_length: Option<usize>,  // from u64
    pub selector: String,  // TODO should be dname labels
    pub copied_headers: Option<Vec<(FieldName, Vec<u8>)>>,
    pub timestamp: Option<u64>,
    pub expiration: Option<u64>,
}

impl DkimSignature {
    pub fn from_tag_list(tag_list: &TagList<'_>) -> Result<Self, DkimSignatureParseError> {
        let mut version_seen = false;
        let mut algorithm = None;
        let mut signature_data = None;
        let mut body_hash = None;
        let mut canonicalization = Canonicalization::default();
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
                        return Err(DkimSignatureParseError::UnsupportedVersion);
                    }
                    version_seen = true;
                }
                "a" => {
                    let value = match value.split_once('-') {
                        Some((k, h)) => {
                            if k.eq_ignore_ascii_case("rsa") && h.eq_ignore_ascii_case("sha256") {
                                SignatureAlgorithm::RsaSha256
                            } else if k.eq_ignore_ascii_case("ed25519") && h.eq_ignore_ascii_case("sha256") {
                                SignatureAlgorithm::Ed25519Sha256
                            } else if k.eq_ignore_ascii_case("rsa") && h.eq_ignore_ascii_case("sha1") {
                                // Note: special-case rsa-sha1 as recognised but
                                // no longer supported (RFC 8301).
                                return Err(DkimSignatureParseError::HistoricAlgorithm);
                            } else {
                                return Err(DkimSignatureParseError::UnsupportedAlgorithm);
                            }
                        }
                        None => return Err(DkimSignatureParseError::ValueSyntax),
                    };
                    algorithm = Some(value);
                }
                "b" => {
                    let value = parse_base64_tag_value(value)
                        .map_err(|_| DkimSignatureParseError::ValueSyntax)?;
                    signature_data = Some(value);
                }
                "bh" => {
                    let value = parse_base64_tag_value(value)
                        .map_err(|_| DkimSignatureParseError::ValueSyntax)?;
                    body_hash = Some(value);
                }
                "c" => {
                    let parse_canon = |s: &str| {
                        if s.eq_ignore_ascii_case("simple") {
                            Ok(CanonicalizationAlgorithm::Simple)
                        } else if s.eq_ignore_ascii_case("relaxed") {
                            Ok(CanonicalizationAlgorithm::Relaxed)
                        } else {
                            Err(DkimSignatureParseError::UnsupportedCanonicalization)
                        }
                    };

                    match value.split_once('/') {
                        Some((h, b)) => {
                            canonicalization.header = parse_canon(h)?;
                            canonicalization.body = parse_canon(b)?;
                        }
                        None => {
                            canonicalization.header = parse_canon(value)?;
                        }
                    }
                }
                "d" => {
                    // TODO from viaspf!:
                    let value = DomainName::new(value)
                        .map_err(|_| DkimSignatureParseError::InvalidDomain)?;
                    domain = Some(value);
                }
                "h" => {
                    let mut sh = vec![];
                    for v in parse_colon_separated_tag_value(value) {
                        let name = FieldName::new(v).map_err(|_| DkimSignatureParseError::ValueSyntax)?;
                        sh.push(name);
                    }
                    if sh.is_empty() {
                        return Err(DkimSignatureParseError::SignedHeadersEmpty);
                    }
                    if !sh.iter().any(|h| h.as_ref().eq_ignore_ascii_case("From")) {
                        return Err(DkimSignatureParseError::FromHeaderNotSigned);
                    }
                    signed_headers = Some(sh);
                }
                "i" => {
                    // TODO
                    let value = Ident::new(value)
                        .map_err(|_| DkimSignatureParseError::InvalidUserId)?;
                    user_id = Some(value);
                }
                "l" => {
                    let value: u64 = value
                        .parse()
                        .map_err(|_| DkimSignatureParseError::InvalidBodyLength)?;
                    // u64-typed body length, but must be representable in usize for our convenience
                    let value = usize::try_from(value)
                        .map_err(|_| DkimSignatureParseError::InvalidBodyLength)?;
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
                        return Err(DkimSignatureParseError::QueryMethodsNotSupported);
                    }
                }
                "s" => {
                    // TODO
                    // selector =   sub-domain *( "." sub-domain )
                    if value.is_empty() || !value.split('.').all(is_label) {
                        return Err(DkimSignatureParseError::InvalidSelector);
                    }
                    selector = Some(value.into());
                }
                "t" => {
                    let value = value
                        .parse()
                        .map_err(|_| DkimSignatureParseError::InvalidTimestamp)?;
                    timestamp = Some(value);
                }
                "x" => {
                    let value = value
                        .parse()
                        .map_err(|_| DkimSignatureParseError::InvalidExpiration)?;
                    expiration = Some(value);
                }
                "z" => {
                    let mut hs = vec![];
                    for piece in value.split('|') {
                        let (name, value) = parse_dqp_header_field(piece)
                            .map_err(|_| DkimSignatureParseError::ValueSyntax)?;
                        hs.push((name, value));
                    }
                    copied_headers = Some(hs);
                }
                _ => {}
            }
        }

        if !version_seen {
            return Err(DkimSignatureParseError::MissingVersionTag);
        }

        let algorithm = algorithm.ok_or(DkimSignatureParseError::MissingAlgorithmTag)?;
        let signature_data = signature_data.ok_or(DkimSignatureParseError::MissingSignatureTag)?;
        let body_hash = body_hash.ok_or(DkimSignatureParseError::MissingBodyHashTag)?;
        let domain = domain.ok_or(DkimSignatureParseError::MissingDomainTag)?;
        let signed_headers = signed_headers.ok_or(DkimSignatureParseError::MissingSignedHeadersTag)?;
        let selector = selector.ok_or(DkimSignatureParseError::MissingSelectorTag)?;

        // TODO only allow subdomains if permitted in key record
        let user_id = match user_id {
            Some(i) => {
                let i_domain = &i.domain_part;
                if !i_domain.eq_or_subdomain_of(&domain) {
                    return Err(DkimSignatureParseError::DomainMismatch);
                }
                i
            }
            None => Ident::from_domain(domain.clone()),
        };

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

    pub fn format_without_signature(&self) -> String {
        let start_i = "DKIM-Signature:".len();

        let mut result = String::new();
        let mut i = start_i;

        format_tag_into_string(&mut result, WIDTH, &mut i, "v", "1");

        format_tag_into_string(&mut result, WIDTH, &mut i, "d", self.domain.as_ref());

        format_tag_into_string(&mut result, WIDTH, &mut i, "s", &self.selector);

        let alg = match self.algorithm {
            SignatureAlgorithm::RsaSha256 => "rsa-sha256",
            SignatureAlgorithm::Ed25519Sha256 => "ed25519-sha256",
        };
        format_tag_into_string(&mut result, WIDTH, &mut i, "a", alg);

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
            format_tag_into_string(&mut result, WIDTH, &mut i, "c", canon);
        }

        if let Some(timestamp) = &self.timestamp {
            format_tag_into_string(&mut result, WIDTH, &mut i, "t", &timestamp.to_string());
        }
        if let Some(expiration) = &self.expiration {
            format_tag_into_string(&mut result, WIDTH, &mut i, "x", &expiration.to_string());
        }

        format_colon_separated_into_string(&mut result, WIDTH, &mut i, "h", &self.signed_headers);

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

        let bh = base64::encode(&self.body_hash);
        format_base64_into_string(&mut result, WIDTH, &mut i, "bh", &bh);

        if i + 4 <= WIDTH {  // at least one additional char behind =
            result.push_str(" b=");
        } else {
            result.push_str("\r\n\tb=");
        }

        result
    }
}

// TODO
impl fmt::Debug for DkimSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("DkimSignature")
            .field("algorithm", &self.algorithm)
            .field("signature_data", &"BINARY")
            .field("body_hash", &"BINARY")
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

const WIDTH: usize = 78;

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
    write!(result, "{}={};", tag, value).unwrap();
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
        write!(result, "{}", name).unwrap();  // don't write ;/: yet
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
        write!(result, " {}=", tag).unwrap();
        *i += taglen - 1;
    } else {
        write!(result, "\r\n\t{}=", tag).unwrap();
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

pub fn push_signature_data(
    formatted_header: &mut String,
    signature_data: &[u8],
) {
    let s = base64::encode(signature_data);
    // note s contains only ASCII now

    let last_line = formatted_header.rsplit("\r\n").next().unwrap_or(&formatted_header[..]);
    let len = last_line.chars().count();

    let first_chunk_len = WIDTH.saturating_sub(len).max(1);  //min len 1

    let first_chunk = &s[..first_chunk_len];

    formatted_header.push_str(first_chunk);

    for chunk in s[first_chunk_len..].as_bytes().chunks(77) {  // for loop not entered if no chunks
        let s = str::from_utf8(chunk).unwrap();
        formatted_header.push_str("\r\n\t");
        formatted_header.push_str(s);
    }
}

pub fn canon_dkim_header(
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
            format!("{}:{}", name, formatted_hdr_without_sig)
        }
    };

    trace!("canonicalized DKIM header: {result:?}");

    result
}

pub fn get_default_signed_headers() -> Vec<FieldName> {
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

pub fn select_signed_headers(
    signed_headers: &[FieldName],
    headers: &HeaderFields,
) -> Vec<FieldName> {
    let mut result = vec![];

    for x in signed_headers {
        if headers.as_ref().iter().any(|(name, _)| name.as_ref().eq_ignore_ascii_case(x.as_ref())) {
            result.push(x.clone());
        }
    }

    let oversign = [
        "From",
    ];

    for x in oversign {
        result.push(FieldName::new(x).unwrap());
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
        let example = example.replace("\n", "\r\n");

        let q = TagList::from_str(&example).unwrap();

        let hdr = DkimSignature::from_tag_list(&q).unwrap();

        assert_eq!(
            hdr,
            DkimSignature {
                algorithm: SignatureAlgorithm::RsaSha256,
                signature_data: base64::decode(
                        "dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR"
                    ).unwrap(),
                body_hash: base64::decode("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=").unwrap(),
                canonicalization: Canonicalization {
                    header: CanonicalizationAlgorithm::Simple,
                    body: CanonicalizationAlgorithm::Simple,
                },
                domain: DomainName::new("example.net").unwrap(),
                signed_headers: vec![
                    FieldName::new("from").unwrap(),
                    FieldName::new("to").unwrap(),
                    FieldName::new("subject").unwrap(),
                    FieldName::new("date").unwrap(),
                ],
                user_id: Ident::new("@eng.example.net").unwrap(),
                selector: "brisbane".into(),
                body_length: None,
                timestamp: Some(1117574938),
                expiration: Some(1118006938),
                copied_headers: Some(vec![
                    (FieldName::new("From").unwrap(), b"foo@eng.example.net".to_vec()),
                    (FieldName::new("To").unwrap(), b"joe@example.com".to_vec()),
                    (FieldName::new("Subject").unwrap(), b"demo run".to_vec()),
                    (FieldName::new("Date").unwrap(), b"July 5, 2005 3:44:08 PM -0700".to_vec()),
                ]),
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
        let example = example.replace("\n", "\r\n");

        let q = TagList::from_str(&example).unwrap();

        let hdr = DkimSignature::from_tag_list(&q).unwrap();

        assert_eq!(
            hdr.signed_headers,
            vec![
                FieldName::new("from").unwrap(),
                FieldName::new("to").unwrap(),
                FieldName::new("subject").unwrap(),
                FieldName::new("date").unwrap(),
            ]
        );
    }
}
