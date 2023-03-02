//! Verifier and supporting types.

mod header;
mod lookup;
mod query;

pub use lookup::LookupTxt;

use crate::{
    body_hash::{body_hasher_key, BodyHasher, BodyHasherBuilder, BodyHasherError},
    canonicalize::BodyCanonStatus,
    crypto::VerificationError,
    header::{FieldName, HeaderFields},
    signature::{self, DkimSignature, DkimSignatureError, DkimSignatureErrorKind},
    util::CanonicalStr,
    verifier::{header::HeaderVerifier, query::Queries},
};
use std::{
    fmt::{self, Display, Formatter},
    time::Duration,
};
use tracing::trace;

/// Configuration for a verifier process.
pub struct Config {
    /// The maximum duration of public key record lookups. When this duration is
    /// exceeded evaluation fails (temporary error).
    pub lookup_timeout: Duration,

    /// Only validate at most this number of signatures, any extra signatures
    /// are ignored.
    pub max_signatures: usize,

    /// If given required headers are not signed in a DKIM signature, the
    /// signature will not validate. Note that the header `From` is always
    /// required by the RFC independent of this configuration setting.
    pub required_signed_headers: Vec<FieldName>,

    /// If a DKIM signature has the l= tag, and the body length given in this
    /// tag is less than the actual message body length, the signature will not
    /// validate. In other words, signatures that cover only part of the message
    /// body are not accepted.
    pub forbid_partially_signed_body: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            lookup_timeout: Duration::from_secs(10),
            max_signatures: 10,
            required_signed_headers: vec![],
            forbid_partially_signed_body: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum PolicyError {
    RequiredHeadersNotSigned,
    ForbidPartiallySignedBody,
}

impl Display for PolicyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequiredHeadersNotSigned => write!(f, "headers required to be signed were not signed"),
            Self::ForbidPartiallySignedBody => write!(f, "partial body signing not acceptable"),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct VerificationResult {
    pub index: usize,  // index in HeaderFields
    pub signature: Option<DkimSignature>,
    pub status: VerificationStatus,
    pub testing: bool,  // t=y in record
    pub key_size: Option<usize>,
}

// TODO RFC 6376 vs RFC 8601:
// Success Permfail Tempfail
#[derive(Debug, PartialEq)]
pub enum VerificationStatus {
    Success,
    Failure(VerifierError),
}

impl VerificationStatus {
    // TODO revisit
    pub fn to_auth_results_kind(&self) -> AuthResultsKind {
        use VerifierError::*;

        match self {
            VerificationStatus::Success => AuthResultsKind::Pass,
            VerificationStatus::Failure(error) => match error {
                WrongKeyType
                | KeyRecordSyntax
                | DisallowedHashAlgorithm
                | DisallowedServiceType
                | DomainMismatch
                | InsufficientBodyLength
                | InvalidKeyDomain
                | NoKeyFound => AuthResultsKind::Permerror,
                BodyHashMismatch => AuthResultsKind::Fail,
                KeyLookupTimeout | KeyLookup => AuthResultsKind::Temperror,
                DkimSignatureHeaderFormat(error) => match &error.kind {
                    DkimSignatureErrorKind::MissingVersionTag
                    | DkimSignatureErrorKind::HistoricAlgorithm
                    | DkimSignatureErrorKind::MissingAlgorithmTag
                    | DkimSignatureErrorKind::MissingSignatureTag
                    | DkimSignatureErrorKind::MissingBodyHashTag
                    | DkimSignatureErrorKind::InvalidDomain
                    | DkimSignatureErrorKind::MissingDomainTag
                    | DkimSignatureErrorKind::SignedHeadersEmpty
                    | DkimSignatureErrorKind::FromHeaderNotSigned
                    | DkimSignatureErrorKind::MissingSignedHeadersTag
                    | DkimSignatureErrorKind::InvalidBodyLength
                    | DkimSignatureErrorKind::InvalidSelector
                    | DkimSignatureErrorKind::MissingSelectorTag
                    | DkimSignatureErrorKind::InvalidTimestamp
                    | DkimSignatureErrorKind::InvalidExpiration
                    | DkimSignatureErrorKind::DomainMismatch
                    | DkimSignatureErrorKind::ExpirationNotAfterTimestamp
                    | DkimSignatureErrorKind::InvalidUserId => AuthResultsKind::Permerror,
                    DkimSignatureErrorKind::UnsupportedVersion
                    | DkimSignatureErrorKind::UnsupportedAlgorithm
                    | DkimSignatureErrorKind::UnsupportedCanonicalization
                    | DkimSignatureErrorKind::QueryMethodsNotSupported
                    | DkimSignatureErrorKind::ValueSyntax
                    | DkimSignatureErrorKind::InvalidTagList => AuthResultsKind::Neutral,
                },
                VerificationFailure(error) => match error {
                    VerificationError::InvalidKey
                    | VerificationError::InsufficientKeySize
                    | VerificationError::InvalidSignature => AuthResultsKind::Permerror,
                    VerificationError::VerificationFailure => AuthResultsKind::Fail,
                },
                Policy(_) => AuthResultsKind::Policy,
                Overflow => AuthResultsKind::Neutral,
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum VerifierError {
    DkimSignatureHeaderFormat(DkimSignatureError),
    WrongKeyType,
    KeyRecordSyntax,
    DisallowedHashAlgorithm,
    DisallowedServiceType,
    DomainMismatch,
    VerificationFailure(VerificationError),
    BodyHashMismatch,
    InsufficientBodyLength,
    NoKeyFound,
    InvalidKeyDomain,
    KeyLookupTimeout,
    KeyLookup,
    Policy(PolicyError),
    Overflow,
}

impl Display for VerifierError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::DkimSignatureHeaderFormat(error) => error.kind.fmt(f),
            Self::WrongKeyType => write!(f, "wrong key type"),
            Self::KeyRecordSyntax => write!(f, "invalid syntax in key record"),
            Self::DisallowedHashAlgorithm => write!(f, "hash algorithm not allowed"),
            Self::DisallowedServiceType => write!(f, "service type not allowed"),
            Self::DomainMismatch => write!(f, "domain mismatch"),
            Self::VerificationFailure(error) => error.fmt(f),
            Self::BodyHashMismatch => write!(f, "body hash mismatch"),
            Self::InsufficientBodyLength => write!(f, "truncated body"),
            Self::NoKeyFound => write!(f, "no key record found"),
            Self::InvalidKeyDomain => write!(f, "invalid key record domain name"),
            Self::KeyLookupTimeout => write!(f, "key record lookup timed out"),
            Self::KeyLookup => write!(f, "key record lookup failed"),
            Self::Policy(error) => error.fmt(f),
            Self::Overflow => write!(f, "integer size too large"),
        }
    }
}

/// An RFC 8601 DKIM result.
///
/// The mapping of an RFC 6376 *SUCCESS*, *PERMFAIL*, or *TEMPFAIL* result to an
/// RFC 8601 DKIM error result is not well defined. Our interpretation of each
/// result is given in detail below.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuthResultsKind {
    /// The *none* result. (Not used in this library.)
    None,

    /// The *pass* result. This result means that verification could be
    /// performed on a DKIM signature, and the verification was successful.
    Pass,

    /// The *fail* result. This result means that a DKIM signature was
    /// understood and verification could be performed, and the verification
    /// result was failure.
    ///
    /// Examples include: cryptographic verification failure, body hash
    /// mismatch.
    Fail,

    /// The *policy* result. This result means that a DKIM signature could not
    /// be or was not verified, because some aspect of it was unacceptable due
    /// to a configurable policy reason.
    ///
    /// Examples include: configuration required a header to be signed, but it
    /// was not covered by a signature.
    Policy,

    /// The *neutral* result. This result means that a DKIM signature could not
    /// be entirely understood or cannot be processed by this implementation
    /// (but might be by other implementations).
    ///
    /// Examples include: syntax errors, an unsupported cryptographic or other
    /// algorithm.
    Neutral,

    /// The *temperror* result. This result means that signature evaluation
    /// could not be performed due to a temporary reason that might be gone when
    /// evaluation is retried.
    ///
    /// Examples include: DNS lookup timeout, temporary I/O error.
    Temperror,

    /// The *permerror* result. This result means that a DKIM signature was
    /// determined to be definitely broken. The problem with the signature is
    /// understood, is permanent, and the signature must be rejected (by this
    /// and any other implementation).
    ///
    /// Examples include: missing required tag in signature, missing public key
    /// record in DNS, l= tag larger than message body length.
    Permerror,
}

impl CanonicalStr for AuthResultsKind {
    fn canonical_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Policy => "policy",
            Self::Neutral => "neutral",
            Self::Temperror => "temperror",
            Self::Permerror => "permerror",
        }
    }
}

impl Display for AuthResultsKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.canonical_str())
    }
}

struct SigTask {
    index: usize,
    sig: Option<DkimSignature>,
    status: VerificationStatus,
    testing: bool,
    key_size: Option<usize>,
}

/// A verifier validating all DKIM signatures in a message.
///
/// The verifier proceeds in three stages...
pub struct Verifier {
    tasks: Vec<SigTask>,
    body_hasher: BodyHasher,
}

impl Verifier {
    pub async fn process_headers<T>(resolver: &T, headers: &HeaderFields, config: &Config) -> Self
    where
        T: LookupTxt + Clone + 'static,
    {
        let tasks = HeaderVerifier::find_dkim_signatures(headers, config);

        let queries = Queries::spawn(&tasks.tasks, resolver, config);

        let tasks = tasks.verify_all(queries).await;

        let mut final_tasks = vec![];
        let mut body_hasher = BodyHasherBuilder::new(config.forbid_partially_signed_body);
        for task in tasks {
            let status = task.status.unwrap();
            if let Some(sig) = &task.sig {
                if status == VerificationStatus::Success {
                    let (body_len, hash_alg, canon_kind) = body_hasher_key(sig);
                    body_hasher.register_canonicalization(body_len, hash_alg, canon_kind);
                }
            }
            final_tasks.push(SigTask {
                index: task.index,
                sig: task.sig,
                status,
                testing: task.testing,
                key_size: task.key_size,
            });
        }

        Self {
            tasks: final_tasks,
            body_hasher: body_hasher.build(),
        }
    }

    pub fn body_chunk(&mut self, chunk: &[u8]) -> BodyCanonStatus {
        self.body_hasher.hash_chunk(chunk)
    }

    pub fn finish(self) -> Vec<VerificationResult> {
        let mut result = vec![];

        let hasher_results = self.body_hasher.finish();

        for task in self.tasks {
            match task.status {
                VerificationStatus::Failure(e) => {
                    result.push(VerificationResult {
                        index: task.index,
                        signature: task.sig,
                        status: VerificationStatus::Failure(e),
                        testing: task.testing,
                        key_size: task.key_size,
                    });
                }
                VerificationStatus::Success => {
                    trace!("now checking body hash for signature");

                    let sig = task.sig.unwrap();

                    let key = body_hasher_key(&sig);

                    let status = match hasher_results.get(&key).unwrap() {
                        Ok((h, _)) => {
                            if h != &sig.body_hash {
                                // downgrade status Success -> Failure!
                                trace!("body hash mismatch: {}", signature::encode_binary(h));
                                VerificationStatus::Failure(VerifierError::BodyHashMismatch)
                            } else {
                                trace!("body hash matched");
                                VerificationStatus::Success
                            }
                        }
                        Err(BodyHasherError::InsufficientInput) => {
                            // downgrade status Success -> Failure!
                            VerificationStatus::Failure(VerifierError::InsufficientBodyLength)
                        }
                        Err(BodyHasherError::ForbiddenTruncation) => {
                            // downgrade status Success -> Failure!
                            VerificationStatus::Failure(VerifierError::Policy(PolicyError::ForbidPartiallySignedBody))
                        }
                    };

                    result.push(VerificationResult {
                        index: task.index,
                        signature: Some(sig),
                        status,
                        testing: task.testing,
                        key_size: task.key_size,
                    });
                }
            }
        }

        result
    }
}
