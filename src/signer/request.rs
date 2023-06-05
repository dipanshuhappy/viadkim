use crate::{
    header::{FieldName, HeaderFields},
    signature::{
        Canonicalization, DomainName, Identity, Selector, SignatureAlgorithm, DKIM_SIGNATURE_NAME,
    },
    signer::format::LINE_WIDTH,
};
use std::{num::TryFromIntError, time::Duration};

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

pub struct SignRequest<T> {
    // Key
    pub signing_key: T,

    // Signature
    pub algorithm: SignatureAlgorithm,
    pub canonicalization: Canonicalization,
    pub header_selection: HeaderSelection,
    pub domain: DomainName,
    pub identity: Option<Identity>,
    pub selector: Selector,
    pub body_length: BodyLength,
    pub copy_headers: bool,  // copy all headers used to create the signature in z= tag
    pub timestamp: Option<Timestamp>,
    pub valid_duration: Option<Duration>,
    pub header_name: String,  // ~"DKIM-Signature"
    // TODO extra tags:
    // pub extra_tags: Vec<(String, String)>,

    // Additional config
    pub line_width: usize,
    // TODO tags_order: d=, s=, a=, bh=, b=, t=, x= ... (?)
    // TODO ascii_compat: bool, (encode d= s= i= domain in A-label/ASCII form?)
}

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
            // TODO forbid zero duration -> would create invalid signature
            valid_duration: Some(Duration::from_secs(60 * 60 * 24 * 5)),  // five days
            // note that five days is also used as duration in the example in §3.5
            header_name: DKIM_SIGNATURE_NAME.into(),

            line_width: LINE_WIDTH,
        }
    }
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
