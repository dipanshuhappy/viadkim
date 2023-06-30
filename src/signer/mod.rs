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

//! Signer and supporting types.

mod format;
mod sign;

use crate::{
    crypto::SigningKey,
    header::{FieldBody, FieldName, HeaderField, HeaderFields},
    message_hash::{BodyHasher, BodyHasherBuilder, BodyHasherStance},
    parse,
    signature::{
        Canonicalization, DkimSignature, DomainName, Identity, Selector, SignatureAlgorithm,
        DKIM_SIGNATURE_NAME,
    },
    signer::format::LINE_WIDTH,
    tag_list,
};
use std::{
    cmp::Ordering,
    collections::HashSet,
    error::Error,
    fmt::{self, Display, Formatter},
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
fn convert_body_length(body_length: BodyLength) -> Result<Option<usize>, TryFromIntError> {
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
/// Selection of headers to include in the h= tag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeaderSelection {
    /// Given some `HeaderFields`, select the headers in the default set.
    Auto,
    /// Use exactly the headers given here as contents of the h= tag.
    Manual(Vec<FieldName>),
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
    /// The header name, must be equal to `DKIM-Signature` ignoring case.
    pub header_name: String,
    /// The maximum line width in characters to use when breaking lines. The
    /// default is 78.
    pub line_width: NonZeroUsize,
    /// The indentation whitespace to use for continuation lines. Must be a
    /// non-empty sequence of space and tab characters. The default is `"\t"`.
    pub indentation: String,
    /// A comparator applied to tag names that determines the order of the tags
    /// included in the signature.
    pub tag_order: Option<Box<dyn Fn(&str, &str) -> Ordering + Send + Sync>>,
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

// TODO SignRequest cannot derive anything? should this be clonable in some way (except for key?)
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
    pub ext_tags: Vec<(String, String)>,

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
            ext_tags: vec![],

            format: Default::default(),
        }
    }
}

fn validate_request<T: AsRef<SigningKey>>(request: &SignRequest<T>) -> Result<(), SignerError> {
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
    if request.ext_tags.iter().any(|(name, value)| {
        !tags_seen.insert(name)
            || !tag_list::is_tag_name(name)
            || !tag_list::is_tag_value(value)
            || format::is_output_tag(name)
    }) {
        return Err(SignerError::InvalidExtraTags);
    }

    if !request.format.header_name.eq_ignore_ascii_case(DKIM_SIGNATURE_NAME) {
        return Err(SignerError::InvalidDkimSignatureHeaderName);
    }

    let indent = &request.format.indentation;
    if indent.is_empty() || indent.chars().any(|c| !parse::is_wsp(c)) {
        return Err(SignerError::InvalidIndentationWhitespace);
    }

    Ok(())
}

/// An error that occurs when using a signer.
#[derive(Debug, PartialEq, Eq)]
pub enum SignerError {
    /// Conversion from or to a requested integer data type cannot be supported
    /// in this implementation or on the current platform.
    Overflow,
    TooManyRequests,
    EmptyRequests,
    ZeroExpirationDuration,
    InvalidExtraTags,
    InvalidDkimSignatureHeaderName,
    InvalidIndentationWhitespace,
    FromHeaderNotSigned,
    InvalidSignedFieldName,
    MissingFromHeader,
    IncompatibleKeyType,
    InsufficientBodyLength,
    SigningFailure,
}

// TODO
impl Display for SignerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "signer error")
    }
}

impl Error for SignerError {}

// TODO names: Sign{,er,ing}? Result/Output?
// introduce alias: type SigningResult = Result<SignResult, SignerError>;
// or still use an own type for Result<SR, SE>? Compare with VerificationStatus?

struct SignResultHeaderDisplay<'a> {
    name: &'a str,
    value: &'a str,
}

impl Display for SignResultHeaderDisplay<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.name, self.value)
    }
}

// TODO rename SigningResult? cf. VerificationResult

/// A successful signing result.
///
/// The header name and value must be concatenated with only a colon character
/// in between, no additional whitespace; use [`SignResult::format_header`].
#[derive(Debug, PartialEq)]
pub struct SignResult {
    /// The *DKIM-Signature* header name.
    pub header_name: String,
    /// The *DKIM-Signature* header value. Continuation lines use CRLF line
    /// endings.
    pub header_value: String,
    /// DKIM signature data used for producing the formatted header.
    pub signature: DkimSignature,
}

impl SignResult {
    /// Produces a formatted header, consisting of name, colon, and value. The
    /// output uses CRLF line endings.
    pub fn format_header(&self) -> impl Display + '_ {
        SignResultHeaderDisplay {
            name: &self.header_name,
            value: &self.header_value,
        }
    }

    /// Converts this result to a header field.
    ///
    /// # Panics
    ///
    /// Panics if the result’s header name and value are not a well-formed
    /// header field. (`SignResult` output produced by `Signer` is always
    /// well-formed and therefore calling this method on such values does not
    /// panic.)
    pub fn to_header_field(&self) -> HeaderField {
        (
            FieldName::new(self.header_name.as_str()).unwrap(),
            FieldBody::new(self.header_value.as_bytes()).unwrap(),
        )
    }
}

struct SignerTask<T> {
    request: SignRequest<T>,
    error: Option<SignerError>,
}

/// A signer for an email message.
///
/// `Signer` is the high-level API for signing a message. It implements a
/// three-phase, staged design that allows processing the message in chunks.
///
/// 1. [`prepare_signing`][Signer::prepare_signing]: first, a number of signing
///    requests together with the message header allow construction of a signer
/// 2. [`process_body_chunk`][Signer::process_body_chunk]: then, any number of
///    chunks of the message body are fed to the signing process
/// 3. **[`sign`][Signer::sign]** (async): finally, the initial signing requests
///    are answered by performing signing and returning the results; this is
///    where most of the actual work is done
///
/// Compare this with the similar but distinct procedure of
/// [`Verifier`][crate::verifier::Verifier].
///
/// # Examples
///
/// The following example shows how to sign a message using the high-level API.
///
/// Don’t forget to prepend the formatted *DKIM-Signature* header(s) to your
/// message when sending it out.
///
/// ```
/// # tokio::runtime::Runtime::new().unwrap().block_on(async {
/// use viadkim::*;
///
/// let header = "From: me@example.com\r\n\
///     To: you@example.org\r\n\
///     Subject: Re: Thursday 8pm\r\n\
///     Date: Thu, 22 Jun 2023 14:03:12 +0200\r\n".parse()?;
/// let body = b"Hey,\r\n\
///     \r\n\
///     Ready for tonight? ;)\r\n";
///
/// let domain = DomainName::new("example.com")?;
/// let selector = Selector::new("selector")?;
/// let algorithm = SignatureAlgorithm::Ed25519Sha256;
/// let signing_key = SigningKey::from_pkcs8_pem(
///     "-----BEGIN PRIVATE KEY-----\n\
///     MC4CAQAwBQYDK2VwBCIEIH1M+KJ5Nln5QmygpruhNrykdHC9AwB8B7ACiiWMp/tQ\n\
///     -----END PRIVATE KEY-----"
/// )?;
///
/// let request = SignRequest::new(domain, selector, algorithm, signing_key);
/// # let mut request = request;
/// # request.timestamp = Some(viadkim::signer::Timestamp::Exact(1687435395));
///
/// let mut signer = Signer::prepare_signing(header, [request])?;
///
/// let _ = signer.process_body_chunk(body);
///
/// let results = signer.sign().await;
///
/// let signature = results.into_iter().next().unwrap()?;
///
/// assert_eq!(
///     signature.format_header().to_string(),
///     "DKIM-Signature: v=1; d=example.com; s=selector; a=ed25519-sha256;\r\n\
///     \tt=1687435395; x=1687867395; h=Date:Subject:To:From; bh=1zGfaauQ3vmMhm21CGMC23\r\n\
///     \taJE1JrOoKsgT/wvw9owzE=; b=Ny5/l088Iubyzlq56ab9Xe6/9YDcIvydie0GOI6CEsaIdktjLlA\r\n\
///     \tOvKuE7wU4203PIMx0MuW7lFLpdRIcPDl3Cg=="
/// );
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// # }).unwrap();
/// ```
///
/// See [`Verifier`][crate::verifier::Verifier] for how the above example
/// message could be verified.
pub struct Signer<T> {
    tasks: Vec<SignerTask<T>>,  // non-empty
    headers: HeaderFields,
    body_hasher: BodyHasher,
}

impl<T> Signer<T>
where
    T: AsRef<SigningKey>,
{
    /// Prepares a message signing process.
    pub fn prepare_signing<I>(headers: HeaderFields, requests: I) -> Result<Self, SignerError>
    where
        I: IntoIterator<Item = SignRequest<T>>,
    {
        if !headers.as_ref().iter().any(|(name, _)| *name == "From") {
            return Err(SignerError::MissingFromHeader);
        }

        let mut tasks = vec![];
        let mut body_hasher = BodyHasherBuilder::new(false);

        for (i, request) in requests.into_iter().enumerate() {
            if i >= 10 {
                return Err(SignerError::TooManyRequests);
            }

            // eagerly validate requests and abort entire procedure if any are unusable
            validate_request(&request)?;

            // TODO check that From is in signed headers, does not contain ; here already?

            // TODO check identity domain is subdomain of signing domain

            let body_length = match convert_body_length(request.body_length) {
                Ok(b) => b,
                Err(_) => {
                    let task = SignerTask {
                        request,
                        error: Some(SignerError::Overflow),
                    };
                    tasks.push(task);
                    continue;
                }
            };
            let hash_alg = request.algorithm.hash_algorithm();
            let canon_kind = request.canonicalization.body;
            body_hasher.register_canonicalization(body_length, hash_alg, canon_kind);

            let task = SignerTask {
                request,
                error: None,
            };

            tasks.push(task);
        }

        if tasks.is_empty() {
            return Err(SignerError::EmptyRequests);
        }

        Ok(Self {
            tasks,
            headers,
            body_hasher: body_hasher.build(),
        })
    }

    /// Processes a chunk of the message body.
    ///
    /// Clients should pass the message body either whole or in chunks of
    /// arbitrary size to this method in order to calculate the body hash (the
    /// *bh=* tag). The returned [`BodyHasherStance`] instructs the client how
    /// to proceed if more chunks are outstanding. Note that the given body
    /// chunk is canonicalised and hashed, but not otherwise retained in memory.
    ///
    /// Remember that email message bodies generally use CRLF line endings; this
    /// is important for correct body hash calculation.
    ///
    /// # Examples
    ///
    /// ```
    /// # use viadkim::{crypto::SigningKey, signer::Signer};
    /// # fn f<T: AsRef<SigningKey>>(signer: &mut Signer<T>) {
    /// let _ = signer.process_body_chunk(b"\
    /// Hello friend!\r
    /// \r
    /// How are you?\r
    /// ");
    /// # }
    /// ```
    pub fn process_body_chunk(&mut self, chunk: &[u8]) -> BodyHasherStance {
        self.body_hasher.hash_chunk(chunk)
    }

    // Note: The `sign` method doesn’t actually need to be async. But it’s where
    // the work is done, so we introduce this artificial await point for every
    // signature.

    /// Performs the actual signing and returns the resulting signatures.
    ///
    /// The returned result vector is never empty.
    pub async fn sign(self) -> Vec<Result<SignResult, SignerError>> {
        let hasher_results = self.body_hasher.finish();

        let mut result = vec![];

        for task in self.tasks {
            if let Some(error) = task.error {
                result.push(Err(error));
                continue;
            }

            let request = task.request;

            let signing_result =
                sign::perform_signing(request, &self.headers, &hasher_results).await;

            result.push(signing_result);
        }

        result
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
