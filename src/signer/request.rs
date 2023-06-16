use crate::{
    crypto::SigningKey,
    header::{FieldName, HeaderFields},
    signature::{
        Canonicalization, DomainName, Identity, Selector, SignatureAlgorithm, DKIM_SIGNATURE_NAME,
    },
    signer::{
        format::{self, LINE_WIDTH},
        SignerError,
    },
    tag_list,
};
use std::{
    cmp::Ordering,
    collections::HashSet,
    num::{NonZeroUsize, TryFromIntError},
    time::Duration,
};

/// A generator for the body length limit tag.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum BodyLength {
    /// Do not limit the body length: no *l=* tag.
    #[default]
    All,
    /// Sign only the body as presented: set *l=* to the actual body length.
    OnlyMessageLength,
    /// Sign exactly the specified number of bytes of body content: set *l=* to
    /// the given value.
    Exact(u64),
}

// TODO make inherent method?
pub fn convert_body_length(body_length: BodyLength) -> Result<Option<usize>, TryFromIntError> {
    match body_length {
        BodyLength::All | BodyLength::OnlyMessageLength => Ok(None),
        BodyLength::Exact(n) => n.try_into().map(Some),
    }
}

/// A generator for the timestamp tag.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum Timestamp {
    #[default]
    Now,
    Exact(u64),
}

/// Selects all headers matching the predicate, in reverse (evaluation order).
pub fn select_headers<'a, 'b: 'a>(
    headers: &'a HeaderFields,
    mut pred: impl FnMut(&FieldName) -> bool + 'b,
) -> impl DoubleEndedIterator<Item = &FieldName> + 'a {
    headers
        .as_ref()
        .iter()
        .rev()
        .filter_map(move |(name, _)| if pred(name) { Some(name) } else { None })
}

// TODO derive Default?
/// Selection of headers to include in the h= tag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeaderSelection {
    /// Given some `HeaderFields`, select the headers in the default set.
    Auto,
    /// Use exactly the headers given here as contents of the h= tag.
    Manual(Vec<FieldName>),
}

/// Returns a collection of headers that should be signed.
///
/// RFC 6376 does not actually recommend a specific set of headers to be signed.
/// Instead, the collection returned here contains the so-called ‘examples’ from
/// section 5.4.1.
pub fn default_signed_headers() -> Vec<FieldName> {
    // This set is the same as in OpenDKIM (minus *Resent-Sender*: *Sender* and
    // *Resent-Sender* were removed between RFC 4871 and 6376, but the latter
    // was left in OpenDKIM possibly by mistake).
    let names = [
        "From",
        "Reply-To",
        "Subject",
        "Date",
        "To",
        "Cc",
        "Resent-Date",
        "Resent-From",
        "Resent-To",
        "Resent-Cc",
        "In-Reply-To",
        "References",
        "List-Id",
        "List-Help",
        "List-Unsubscribe",
        "List-Subscribe",
        "List-Post",
        "List-Owner",
        "List-Archive",
    ];

    names
        .into_iter()
        .map(|n| FieldName::new(n).unwrap())
        .collect()
}

/// Returns a collection of headers that should be excluded from a signature.
///
/// RFC 6376 does not actually recommend a specific set of headers to be
/// excluded. Instead, the collection returned here contains the so-called
/// ‘examples’ from section 5.4.1.
pub fn default_unsigned_headers() -> Vec<FieldName> {
    // This set is the same as in OpenDKIM.
    let names = [
        "Return-Path",
        "Received",
        "Comments",
        "Keywords",
    ];

    names
        .into_iter()
        .map(|n| FieldName::new(n).unwrap())
        .collect()
}

/// Formatting options.
pub struct OutputFormat {
    // TODO validate header_name input: ~"DKIM-Signature"
    /// The header name, must be equal to `DKIM-Signature` ignoring case.
    pub header_name: String,
    /// The maximum line width in characters to use when breaking lines. The
    /// default is 78.
    pub line_width: NonZeroUsize,
    // TODO validate indentation input: !is_empty() && all matches!(' ' | '\t')
    /// The indentation whitespace to use for continuation lines. Must be a
    /// non-empty sequence of space and tab characters. The default is `"\t"`.
    pub indentation: String,
    /// A comparator applied to tag names that determines the order of the tags
    /// included in the signature.
    pub tag_order: Option<Box<dyn Fn(&str, &str) -> Ordering + Send + Sync>>,
    // TODO ascii_compat: bool, (encode d= s= i= domain in A-label/ASCII form?)
}

impl Default for OutputFormat {
    fn default() -> Self {
        Self {
            header_name: DKIM_SIGNATURE_NAME.into(),
            line_width: LINE_WIDTH.try_into().unwrap(),
            indentation: "\t".into(),
            tag_order: None,
        }
    }
}

/// A request for creation of a DKIM signature.
pub struct SignRequest<T> {
    /// The key to use for producing the cryptographic signature.
    pub signing_key: T,

    /// The signature algorithm to use in the *a=* tag. Must be compatible with
    /// the signing key.
    pub algorithm: SignatureAlgorithm,
    /// The canonicalization to use in the *c=* tag.
    pub canonicalization: Canonicalization,
    /// The selection of headers to include in the *h=* tag.
    pub header_selection: HeaderSelection,
    /// The signing domain to use in the *d=* tag.
    pub domain: DomainName,
    /// The agent or user identifier to use in the *i=* tag.
    pub identity: Option<Identity>,
    /// The selector to use in the *s=* tag.
    pub selector: Selector,
    /// The strategy to use for generating the *l=* tag.
    pub body_length: BodyLength,
    /// Whether to record all headers used to create the signature in the *z=*
    /// tag.
    pub copy_headers: bool,
    /// The timestamp value to record in the *t=* tag.
    pub timestamp: Option<Timestamp>,
    /// The duration for which the signature will remain valid (*x=* tag).
    pub valid_duration: Option<Duration>,
    /// Additional tag/value pairs to include in the signature.
    pub extra_tags: Vec<(String, String)>,

    /// The formatting options to use for producing the formatted
    /// *DKIM-Signature* header.
    pub format: OutputFormat,
}

// TODO consider a builder instead
impl<T> SignRequest<T> {
    pub fn new(
        domain: DomainName,
        selector: Selector,
        algorithm: SignatureAlgorithm,
        signing_key: T,
    ) -> Self {
        let identity = None;
        let header_selection = HeaderSelection::Auto;

        Self {
            signing_key,

            algorithm,
            canonicalization: Default::default(),
            header_selection,
            domain,
            identity,
            selector,
            body_length: BodyLength::All,
            copy_headers: false,
            timestamp: Some(Timestamp::Now),
            valid_duration: Some(Duration::from_secs(60 * 60 * 24 * 5)),  // five days
            // note that five days is also used as duration in the example in §3.5
            extra_tags: vec![],

            format: Default::default(),
        }
    }
}

pub fn validate_request<T: AsRef<SigningKey>>(request: &SignRequest<T>) -> Result<(), SignerError> {
    if request.signing_key.as_ref().key_type() != request.algorithm.key_type() {
        return Err(SignerError::IncompatibleKeyType);
    }

    if let Some(duration) = request.valid_duration {
        if duration.as_secs() == 0 {
            return Err(SignerError::ZeroExpirationDuration);
        }
    }

    // TODO valid header selection (Manual must contain From)

    let mut tags_seen = HashSet::new();
    if request.extra_tags.iter().any(|(name, value)| {
        !tags_seen.insert(name)
            || !tag_list::is_tag_name(name)
            || !tag_list::is_tag_value(value)
            || format::is_output_tag(name)
    }) {
        return Err(SignerError::InvalidExtraTags);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::FieldBody;
    use std::collections::HashSet;

    #[test]
    fn select_headers_ok() {
        let headers = make_header_fields(["From", "Aa", "Bb", "Aa", "Dd"]);

        let names = make_field_names(["from", "aa", "bb", "cc"]);

        let selection = select_headers(&headers, move |name| names.contains(name));

        assert!(selection.map(|n| n.as_ref()).eq(["Aa", "Bb", "Aa", "From"]));
    }

    fn make_header_fields(names: impl IntoIterator<Item = &'static str>) -> HeaderFields {
        let names: Vec<_> = names
            .into_iter()
            .map(|name| (FieldName::new(name).unwrap(), FieldBody::new(*b"").unwrap()))
            .collect();
        HeaderFields::new(names).unwrap()
    }

    fn make_field_names(names: impl IntoIterator<Item = &'static str>) -> HashSet<FieldName> {
        names
            .into_iter()
            .map(|name| FieldName::new(name).unwrap())
            .collect()
    }
}
