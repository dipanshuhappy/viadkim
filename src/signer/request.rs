use crate::{
    header::FieldName,
    signature::{
        Canonicalization, DomainName, Identity, Selector, SignatureAlgorithm, DKIM_SIGNATURE_NAME,
    },
    signer::format::LINE_WIDTH,
};
use std::{collections::HashSet, num::TryFromIntError, time::Duration};

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

// TODO derive Default?
/// A strategy for selecting headers for the h= tag, given some `HeaderFields`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeaderSelection {
    /// Pick only the headers specified in `include`, if present.
    Pick {
        include: HashSet<FieldName>,
        oversign: OversignStrategy,
    },
    /// Select all headers present, except the ones specified in `exclude`.
    All {
        exclude: HashSet<FieldName>,
        oversign: OversignStrategy,
    },
    /// Use exactly the headers given here as contents of the h= tag.
    Manual(Vec<FieldName>),
}

/// A strategy to determine which headers to ‘oversign’ (sign once more than
/// actually present in the message).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum OversignStrategy {
    /// No oversigning.
    #[default]
    None,
    /// Oversign all selected headers.
    All,
    /// Oversign only these headers.
    Selected(HashSet<FieldName>),
}

pub fn get_default_signed_headers() -> Vec<FieldName> {
    // The default signed headers are listed (labelled only ‘common examples’)
    // in §5.4.1. They are the same as in OpenDKIM (minus *Resent-Sender*:
    // *Sender* and *Resent-Sender* were removed between RFC 4871 and 6376, but
    // the latter was left in OpenDKIM probably by mistake).
    let def = [
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
    def.into_iter().map(|x| FieldName::new(x).unwrap()).collect()
}

pub fn get_default_excluded_headers() -> Vec<FieldName> {
    // The default excluded headers are listed again in §5.4.1. They are the
    // same as in OpenDKIM.
    let def = [
        "Return-Path",
        "Received",
        "Comments",
        "Keywords",
    ];
    def.into_iter().map(|x| FieldName::new(x).unwrap()).collect()
}

pub struct SignRequest<T> {
    // Key
    pub signing_key: T,

    // Signature
    pub algorithm: SignatureAlgorithm,
    pub canonicalization: Canonicalization,
    pub header_selection: HeaderSelection,
    pub domain: DomainName,
    pub user_id: Option<Identity>,
    pub selector: Selector,
    pub body_length: BodyLength,
    pub copy_headers: bool,  // copy all headers used to create the signature in z= tag
    pub timestamp: Option<Timestamp>,
    pub valid_duration: Option<Duration>,
    pub header_name: String,  // ~"DKIM-Signature"

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
        let user_id = None;
        let header_selection = HeaderSelection::Pick {
            include: get_default_signed_headers().into_iter().collect(),
            oversign: OversignStrategy::None,
        };

        Self {
            signing_key,

            algorithm,
            canonicalization: Default::default(),
            header_selection,
            domain,
            user_id,
            selector,
            body_length: BodyLength::All,
            copy_headers: false,
            timestamp: Some(Timestamp::Now),
            valid_duration: Some(Duration::from_secs(60 * 60 * 24 * 5)),  // five days
            header_name: DKIM_SIGNATURE_NAME.into(),

            line_width: LINE_WIDTH,
        }
    }
}
