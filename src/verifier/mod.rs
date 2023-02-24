//! Verifier and supporting types.

mod header;
mod lookup;
mod query;

pub use lookup::LookupTxt;

use crate::{
    body_hash::{canonicalizing_hasher_key, CanonicalizingHasher, CanonicalizingHasherBuilder},
    canonicalize::BodyCanonStatus,
    crypto::{InsufficientInput, VerificationError},
    header::HeaderFields,
    signature::{self, DkimSignature, DkimSignatureError},
    verifier::{header::HeaderVerifier, query::Queries},
};
use std::{
    fmt::{self, Display, Formatter},
    time::Duration,
};
use tracing::trace;

// verifier config
pub struct Config {
    pub lookup_timeout: Duration,
    pub max_signatures: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            lookup_timeout: Duration::from_secs(10),
            max_signatures: 20,
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
        }
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
    canonicalizing_hasher: CanonicalizingHasher,
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
        let mut canonicalizing_hasher = CanonicalizingHasherBuilder::new();
        for task in tasks {
            let status = task.status.unwrap();
            if let Some(sig) = &task.sig {
                if status == VerificationStatus::Success {
                    let (body_len, hash_alg, canon_kind) = canonicalizing_hasher_key(sig);
                    canonicalizing_hasher.register_canon(body_len, hash_alg, canon_kind);
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
            canonicalizing_hasher: canonicalizing_hasher.build(),
        }
    }

    pub fn body_chunk(&mut self, chunk: &[u8]) -> BodyCanonStatus {
        self.canonicalizing_hasher.hash_chunk(chunk)
    }

    pub fn finish(self) -> Vec<VerificationResult> {
        let mut result = vec![];

        let hasher_results = self.canonicalizing_hasher.finish();

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

                    let key = canonicalizing_hasher_key(&sig);

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
                        Err(InsufficientInput) => {
                            // downgrade status Success -> Failure!
                            VerificationStatus::Failure(VerifierError::InsufficientBodyLength)
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
