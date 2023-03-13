//! Signer and supporting types.

mod format;
mod request;
mod sign;

pub use crate::signer::request::{
    get_default_excluded_headers, get_default_signed_headers, BodyLength, HeaderSelection,
    OversignStrategy, SignRequest, Timestamp,
};

use crate::{
    crypto::SigningKey,
    header::HeaderFields,
    message_hash::{BodyHasher, BodyHasherBuilder, BodyHasherStance},
    signature::DkimSignature,
};

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
    FromHeaderNotSigned,
    InvalidSignedFieldName,
    MissingFromHeader,
    KeyTypeMismatch,
    InsufficientBodyLength,
    SigningFailure,
}

// TODO does this have to be a separate type? introduce `SigningResults`?
#[derive(Debug, PartialEq)]
pub struct SigningResult {
    pub status: SigningStatus,
}

// TODO revisit
#[derive(Debug, PartialEq)]
pub enum SigningStatus {
    Success {
        // boxing suggested by clippy because of of enum variant size; reconsider
        signature: Box<DkimSignature>,
        // Usage: header_name and header_value are meant to be concatenated with
        // only an intervening colon, no additional whitespace! this is vital for
        // "simple" header canonicalization where whitespace changes are not allowed
        // TODO provide a method format_header(&self) -> String { format!("{name}:{value}") }
        header_name: String,
        header_value: String,
    },
    Error {
        error: SignerError,
    },
}

/// A signer for an email message.
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

            // TODO check that From is in signed headers, does not contain ; here already?

            // TODO check user id domain is subdomain of signing domain

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
    pub async fn finish(self) -> Vec<SigningResult> {
        let hasher_results = self.body_hasher.finish();

        let mut result = vec![];

        for task in self.tasks {
            if let Some(error) = task.error {
                result.push(SigningResult {
                    status: SigningStatus::Error { error },
                });
                continue;
            }

            let request = task.request;

            let signing_result = sign::perform_signing(request, &self.headers, &hasher_results).await;

            result.push(signing_result);
        }

        result
    }
}
