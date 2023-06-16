//! Signer and supporting types.

mod format;
mod request;
mod sign;

pub use crate::signer::request::{
    default_signed_headers, default_unsigned_headers, select_headers, BodyLength, HeaderSelection,
    OutputFormat, SignRequest, Timestamp,
};

use crate::{
    crypto::SigningKey,
    header::{FieldName, FieldBody, HeaderField, HeaderFields},
    message_hash::{BodyHasher, BodyHasherBuilder, BodyHasherStance},
    signature::DkimSignature,
};
use std::fmt::{self, Display, Formatter};

struct SigningTask<T> {
    request: SignRequest<T>,
    error: Option<SignerError>,
}

/// An error that occurs when using a [`Signer`].
#[derive(Debug, PartialEq, Eq)]
pub enum SignerError {
    /// Conversion from or to a requested integer data type cannot be supported
    /// in this implementation or on the current platform.
    Overflow,
    TooManyRequests,
    EmptyRequests,
    ZeroExpirationDuration,
    InvalidExtraTags,
    FromHeaderNotSigned,
    InvalidSignedFieldName,
    MissingFromHeader,
    IncompatibleKeyType,
    InsufficientBodyLength,
    SigningFailure,
}

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

/// A successful signing result.
///
/// The header name and value must be concatenated with only a colon character
/// in between, no additional whitespace; use [`SignResult::format_header`].
#[derive(Debug, PartialEq)]
pub struct SignResult {
    /// DKIM signature data used for producing the formatted header.
    pub signature: DkimSignature,
    /// The *DKIM-Signature* header name.
    pub header_name: String,
    /// The *DKIM-Signature* header value. Continuation lines use CRLF line
    /// endings.
    pub header_value: String,
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

    /// Converts this result into a header field.
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

/// A signer for an email message.
///
/// `Signer` is the high-level API for signing a message. It implements a
/// three-phase, staged design that allows processing the message in chunks.
///
/// 1. [`prepare_signing`][Signer::prepare_signing]: first, a number of signing
///    requests together with the message header allow construction of a signer
/// 2. [`body_chunk`][Signer::body_chunk]: then, any number of chunks of the
///    message body are fed to the signing process
/// 3. **[`finish`][Signer::finish]** (async): finally, the initial signing
///    requests are answered by performing signing and returning the results;
///    this is where most of the actual work is done
///
/// Compare this with the similar but distinct procedure of
/// [`Verifier`][crate::verifier::Verifier].
pub struct Signer<T> {
    tasks: Vec<SigningTask<T>>,  // non-empty
    headers: HeaderFields,
    body_hasher: BodyHasher,
}

impl<T> Signer<T>
where
    T: AsRef<SigningKey>,
{
    /// Prepares a message signing process.
    pub fn prepare_signing<I>(
        requests: I,
        headers: HeaderFields,
    ) -> Result<Self, SignerError>
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
            request::validate_request(&request)?;

            // TODO check that From is in signed headers, does not contain ; here already?

            // TODO check identity domain is subdomain of signing domain

            let body_length = match request::convert_body_length(request.body_length) {
                Ok(b) => b,
                Err(_) => {
                    let task = SigningTask {
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

            let task = SigningTask { request, error: None };

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
    /// Note that the chunk is canonicalised and hashed, but not otherwise
    /// retained in memory.
    pub fn body_chunk(&mut self, chunk: &[u8]) -> BodyHasherStance {
        self.body_hasher.hash_chunk(chunk)
    }

    // Doesn't actually need async, but may use it to introduce artificial await points?
    /// Performs the actual signing and returns the resulting signatures.
    pub async fn finish(self) -> Vec<Result<SignResult, SignerError>> {
        let hasher_results = self.body_hasher.finish();

        let mut result = vec![];

        for task in self.tasks {
            if let Some(error) = task.error {
                result.push(Err(error));
                continue;
            }

            let request = task.request;

            let signing_result = sign::perform_signing(request, &self.headers, &hasher_results).await;

            result.push(signing_result);
        }

        result
    }
}
