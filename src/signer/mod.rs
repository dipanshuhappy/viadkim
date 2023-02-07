//! Signer and supporting types.

mod key_store;

pub use key_store::{KeyId, KeyStore};

use crate::{
    body_hash::{CanonicalizingHasher, CanonicalizingHasherBuilder},
    canon::{self, BodyCanonStatus},
    crypto::{self, HashAlgorithm, InsufficientInput, KeyType, SigningKey},
    header::{FieldName, HeaderFields},
    signature::{self, Canonicalization, DkimSignature, DomainName, Ident, Selector, LINE_WIDTH},
};
use std::time::{Duration, SystemTime};
use tracing::trace;

#[derive(Debug, Default, PartialEq, Eq)]
pub enum BodyLength {
    #[default]
    All,  // no l=
    OnlyMessageLength,  // l=<msg-length>
    Exact(u64),  // l=<n>
}

#[derive(Debug, Default, PartialEq, Eq)]
pub enum Timestamp {
    #[default]
    Now,  // t=<now>
    Exact(u64),  // t=<n>
}

pub struct SigningRequest {
    // Signature
    pub key_type: KeyType,
    pub hash_alg: HashAlgorithm,
    pub canonicalization: Canonicalization,
    pub signed_headers: Vec<FieldName>,  // treated as a set
    pub oversigned_headers: Vec<FieldName>,  // treated as a set
    pub domain: DomainName,
    pub user_id: Ident,
    pub selector: Selector,
    pub body_length: BodyLength,
    pub copied_headers: Option<Vec<FieldName>>,  // which fields to copy
    pub timestamp: Option<Timestamp>,
    pub valid_duration: Option<Duration>,
    pub header_name: String,  // ~"DKIM-Signature"

    // Key
    pub signing_key_id: KeyId,

    // Additional config
    pub line_width: usize,
    //   - order of tags: d=, s=, a=, bh=, b=, t=, x= ...
    //   - header line length ...
}

impl SigningRequest {
    pub fn new(
        domain: DomainName,
        selector: Selector,
        key_type: KeyType,
        signing_key_id: KeyId,
    ) -> Self {
        let user_id = Ident::from_domain(domain.clone());
        let signed_headers = signature::get_default_signed_headers();
        let oversigned_headers = vec![];
        Self {
            key_type,
            hash_alg: HashAlgorithm::Sha256,
            canonicalization: Default::default(),
            signed_headers,
            oversigned_headers,
            domain,
            user_id,
            selector,
            body_length: BodyLength::All,
            copied_headers: None,
            timestamp: Some(Timestamp::Now),
            valid_duration: Some(Duration::from_secs(60 * 60 * 24 * 5)),  // five days
            header_name: "DKIM-Signature".into(),

            signing_key_id,

            line_width: LINE_WIDTH,
        }
    }
}

struct SigningTask {
    request: SigningRequest,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SignerError {
    MissingFromHeader,
    KeyNotAvailable,
    KeyLookupFailure,
    KeyTypeMismatch,
    InsufficientBodyLength,
    SigningFailure,
}

#[derive(Debug, PartialEq)]
pub struct SigningResult {
    pub status: SigningStatus,
    // ...
}

// TODO this is like Result? revisit
#[derive(Debug, PartialEq)]
pub enum SigningStatus {
    Success {
        signature: Box<DkimSignature>,
        header_name: String,
        header_value: String,
    },
    Error {
        error: SignerError,
    },
}

pub struct Signer {
    tasks: Vec<SigningTask>,  // non-empty (?)
    headers: HeaderFields,
    canonicalizing_hasher: CanonicalizingHasher,
}

// The Signer design is unpleasant to use, rethink

impl Signer {
    pub fn prepare_signing(
        requests: Vec<SigningRequest>,  // non-empty
        headers: HeaderFields,
        // + global config, such as timeouts
    ) -> Result<Self, SignerError> {
        assert!(matches!(requests.len(), 1..=10));

        if !headers
            .as_ref()
            .iter()
            .any(|(name, _)| *name == "From")
        {
            return Err(SignerError::MissingFromHeader);
        }

        // check signing request, eg must sign From header etc.

        let mut tasks = vec![];
        let mut canonicalizing_hasher = CanonicalizingHasherBuilder::new();

        for request in requests {
            let body_length = match request.body_length {
                BodyLength::All | BodyLength::OnlyMessageLength => None,
                BodyLength::Exact(n) => Some(n.try_into().unwrap_or(usize::MAX)),
            };
            let hash_alg = request.hash_alg;
            let canon_kind = request.canonicalization.body;
            canonicalizing_hasher.register_canon(body_length, hash_alg, canon_kind);

            let task = SigningTask { request };

            tasks.push(task);
        }

        Ok(Self {
            tasks,
            headers,
            canonicalizing_hasher: canonicalizing_hasher.build(),
        })
    }

    pub fn body_chunk(&mut self, chunk: &[u8]) -> BodyCanonStatus {
        self.canonicalizing_hasher.hash_chunk(chunk)
    }

    pub async fn finish<T>(self, key_store: &T) -> Vec<SigningResult>
    where
        T: KeyStore + 'static,
    {
        let mut result = vec![];

        let hasher_results = self.canonicalizing_hasher.finish();

        for task in self.tasks {
            let body_length = match task.request.body_length {
                BodyLength::All | BodyLength::OnlyMessageLength => None,
                BodyLength::Exact(n) => Some(n.try_into().unwrap_or(usize::MAX)),
            };
            let hash_alg = task.request.hash_alg;
            let canon_kind = task.request.canonicalization.body;
            let key = (body_length, hash_alg, canon_kind);

            let (h, &final_len) = match hasher_results.get(&key).unwrap() {
                Ok((h, final_len)) => (h, final_len),
                Err(InsufficientInput) => {
                    result.push(
                        SigningResult {
                            status: SigningStatus::Error {
                                error: SignerError::InsufficientBodyLength,
                            },
                        }
                    );
                    continue;
                }
            };

            let body_hash = h.clone();
            let body_length = match task.request.body_length {
                BodyLength::All => None,
                BodyLength::OnlyMessageLength | BodyLength::Exact(_) => Some(final_len.try_into().unwrap_or(u64::MAX)),
            };

            // TODO
            let signed_headers = signature::select_signed_headers(
                &task.request.signed_headers,
                &task.request.oversigned_headers,
                &self.headers,
            );

            let header_canonicalization = task.request.canonicalization.header;

            let headers = canon::canon_headers(
                header_canonicalization,
                &self.headers,
                signed_headers.as_slice(),
            );

            let key_type = task.request.key_type;
            let hash_alg = task.request.hash_alg;
            let algorithm = (key_type, hash_alg).into();

            // TODO
            let (timestamp, expiration) = match task.request.timestamp {
                Some(Timestamp::Now) => {
                    let now = SystemTime::now();
                    let timestamp = now
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .map_or(0, |t| t.as_secs());
                    let expiration = task.request.valid_duration.map(|e| {
                        let x = now + e;
                        x.duration_since(SystemTime::UNIX_EPOCH)
                            .map_or(0, |t| t.as_secs())
                    });
                    (Some(timestamp), expiration)
                }
                Some(Timestamp::Exact(_t)) => {
                    todo!();
                }
                _ => (None, None),
            };

            // prepare complete formatted dkim-sig header with body hash *except* with contents of b= tag
            let mut sig = DkimSignature {
                algorithm,
                signature_data: Default::default(),  // placeholder, to be replaced
                body_hash,
                canonicalization: task.request.canonicalization,
                domain: task.request.domain.clone(),
                signed_headers: signed_headers.into(),
                user_id: task.request.user_id.clone(),
                selector: task.request.selector,
                body_length,
                timestamp,
                expiration,
                copied_headers: None,
            };

            let line_width = task.request.line_width;
            let hdr_name = &task.request.header_name;
            let mut formatted_header = sig.format_without_signature(line_width);
            let canon_header =
                signature::canon_dkim_header(header_canonicalization, hdr_name, &formatted_header);

            // hash headers and formatted dkim-sig header to give data_hash:
            let data_hash = crypto::data_hash_digest(hash_alg, &headers, &canon_header);

            let key_id = task.request.signing_key_id;

            let signature_data =
                match sign_hash(key_id, key_type, hash_alg, &data_hash, key_store).await {
                    Ok(signature_data) => {
                        trace!("successfully signed");
                        signature_data.into_boxed_slice()
                    }
                    Err(_e) => {
                        trace!("signing failed");
                        result.push(
                            SigningResult {
                                status: SigningStatus::Error {
                                    error: SignerError::SigningFailure,
                                },
                            }
                        );
                        continue;
                    }
                };

            // insert signature into formatted dkim-sig header, store
            sig.signature_data = signature_data.clone();
            signature::push_signature_data(&mut formatted_header, &signature_data[..], line_width);

            result.push(SigningResult {
                status: SigningStatus::Success {
                    signature: Box::new(sig),
                    header_name: hdr_name.into(),
                    header_value: formatted_header,
                },
            });
        }

        result
    }
}

async fn sign_hash<T>(
    key_id: KeyId,
    key_type: KeyType,
    hash_alg: HashAlgorithm,
    data_hash: &[u8],
    key_store: &T,
) -> Result<Vec<u8>, SignerError>
where
    T: KeyStore + ?Sized,
{
    // TODO timeout
    let private_key = match key_store.get(key_id).await {
        Ok(Some(k)) => k,
        Ok(None) => {
            return Err(SignerError::KeyNotAvailable);
        }
        Err(_e) => {
            return Err(SignerError::KeyLookupFailure);
        }
    };

    match private_key.as_ref() {
        SigningKey::Rsa(k) => {
            if key_type != KeyType::Rsa {
                return Err(SignerError::KeyTypeMismatch);
            }

            match crypto::sign_rsa(hash_alg, k, data_hash) {
                Ok(s) => {
                    trace!("RSA signing successful");
                    Ok(s)
                }
                Err(e) => {
                    trace!("RSA signing failed: {e}");
                    Err(SignerError::SigningFailure)
                }
            }
        }
        SigningKey::Ed25519(k) => {
            if key_type != KeyType::Ed25519 {
                return Err(SignerError::KeyTypeMismatch);
            }

            match crypto::sign_ed25519(k, data_hash) {
                Ok(s) => {
                    trace!("Ed25519 signing successful");
                    Ok(s)
                }
                Err(e) => {
                    trace!("Ed25519 signing failed: {e}");
                    Err(SignerError::SigningFailure)
                }
            }
        }
    }
}
