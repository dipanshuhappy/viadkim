//! DKIM signature.

mod names;
mod format;

pub use names::{DomainName, Identity, Selector};

use crate::{
    canonicalize,
    crypto::{HashAlgorithm, KeyType},
    header::{FieldName, HeaderFields},
    tag_list::{
        self, parse_base64_tag_value, parse_colon_separated_tag_value, parse_dqp_header_field,
        TagList, TagSpec,
    },
    util::CanonicalStr,
};
use base64ct::{Base64, Encoding};
use bstr::ByteSlice;
use std::{
    collections::HashSet,
    fmt::{self, Display, Formatter},
    str::{self, FromStr},
};

/// A signature algorithm.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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

pub const DKIM_SIGNATURE_NAME: &str = "DKIM-Signature";

#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
    ExpirationNotAfterTimestamp,
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
            Self::MissingSignatureTag => write!(f, "b= tag missing"),
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
            Self::ExpirationNotAfterTimestamp => write!(f, "expiration not after timestamp"),
            Self::InvalidTagList => write!(f, "invalid tag-list"),
        }
    }
}

// TODO consider treating this only as an *output* type, ie don't provide methods
// for operating on manually constructed DkimSignature (due to invariants not being guaranteed)
/// A DKIM signature as encoded in a `DKIM-Signature` header field.
#[derive(Clone, Eq, PartialEq)]
pub struct DkimSignature {
    // The fields are strongly typed and have public visibility. This does allow
    // constructing an ‘invalid’ `DkimSignature` (eg with empty signature, or
    // empty signed headers) but given usage contexts this is acceptable.
    // Notes:
    // - i= is Option, because §3.5: "the Signer might wish to assert that
    // although it is willing to go as far as signing for the domain, it is
    // unable or unwilling to commit to an individual user name within the
    // domain. It can do so by including the domain part but not the local-part
    // of the identity."

    pub algorithm: SignatureAlgorithm,
    pub signature_data: Box<[u8]>,
    pub body_hash: Box<[u8]>,
    pub canonicalization: Canonicalization,
    pub domain: DomainName,
    pub signed_headers: Box<[FieldName]>,  // not empty, no fields containing ;
    pub user_id: Option<Identity>,
    pub body_length: Option<u64>,
    pub selector: Selector,
    pub copied_headers: Option<Box<[(FieldName, Box<[u8]>)]>>,  // TODO Option? vec must not be empty, no fields containing ;
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
                    let value = Identity::new(value)
                        .map_err(|_| DkimSignatureErrorKind::InvalidUserId)?;
                    user_id = Some(value);
                }
                "l" => {
                    let value = value
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
                Some(i)
            }
            None => None,
        };

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

    // Returns the formatted signature without the b= value, and the index where
    // the b= value is to be inserted.
    // width: *char-based* line width
    // b_tag_len: *char-based* b= tag value length (check)
    pub(crate) fn format_without_signature(&self, width: usize, b_tag_len: usize) -> (String, usize) {
        format::format_without_signature(self, width, b_tag_len)
    }
}

pub fn encode_binary<T: AsRef<[u8]>>(input: T) -> String {
    Base64::encode_string(input.as_ref())
}

// TODO Debug

struct CopiedHeadersDebug<'a>(&'a [(FieldName, Box<[u8]>)]);

impl fmt::Debug for CopiedHeadersDebug<'_> {
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
            .field("signature_data", &encode_binary(&self.signature_data))
            .field("body_hash", &encode_binary(&self.body_hash))
            .field("canonicalization", &self.canonicalization)
            .field("domain", &self.domain)
            .field("signed_headers", &self.signed_headers)
            .field("user_id", &self.user_id)
            .field("body_length", &self.body_length)
            .field("selector", &self.selector)
            .field("copied_headers", &self.copied_headers.as_deref().map(CopiedHeadersDebug))
            .field("timestamp", &self.timestamp)
            .field("expiration", &self.expiration)
            .finish()
    }
}

pub const LINE_WIDTH: usize = 78;

pub(crate) fn insert_signature_data(
    formatted_header: &mut String,
    insertion_index: usize,
    signature_data: &[u8],
    line_width: usize,
) {
    debug_assert!(insertion_index <= formatted_header.len());

    let s = encode_binary(signature_data);
    // note s contains only ASCII now

    let formatted_header_pre = &formatted_header[..insertion_index];

    let mut len = match formatted_header_pre.rsplit("\r\n").next() {
        Some(last_line) => last_line.chars().count(),
        None => DKIM_SIGNATURE_NAME.len() + formatted_header_pre.chars().count() + 1,
    };

    let mut result = String::with_capacity(s.len());
    format::format_chunks_into_string(&mut result, line_width, &mut len, &s);

    formatted_header.insert_str(insertion_index, &result);
}

pub(crate) fn canon_dkim_header(
    canon: CanonicalizationAlgorithm,
    name: &str,
    formatted_hdr_without_sig: &str,
) -> Vec<u8> {
    debug_assert!(name.eq_ignore_ascii_case(DKIM_SIGNATURE_NAME));

    let mut result = Vec::with_capacity(name.len() + formatted_hdr_without_sig.len() + 1);

    canonicalize::canon_header(&mut result, canon, name, formatted_hdr_without_sig);

    // tracing::trace!("canonicalized DKIM header: {:?}", &bstr::BStr::new(&result));

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
                user_id: Some(Identity::new("@eng.example.net").unwrap()),
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
