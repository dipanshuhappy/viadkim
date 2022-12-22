mod key_store;

pub use key_store::{KeyId, KeyStore};

use crate::{
    canon::{self, BodyCanonStatus, BodyCanonicalizer},
    crypto::{
        self, CountingHasher, HashAlgorithm, HashStatus, InsufficientInput, KeyType, SigningKey,
    },
    header::{FieldName, HeaderFields},
    signature::{
        self, Canonicalization, CanonicalizationAlgorithm, DkimSignature, DomainName, Ident,
    },
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
    Exact(u64),  // l=<n>
}

pub struct SigningRequest {
    // Signature
    pub key_type: KeyType,
    pub hash_alg: HashAlgorithm,
    pub canonicalization: Canonicalization,
    pub signed_headers: Vec<FieldName>,
    pub domain: DomainName,
    pub user_id: Ident,
    pub selector: String,
    pub body_length: BodyLength,
    pub copied_headers: Option<Vec<FieldName>>,  // which fields to copy
    pub timestamp: Option<Timestamp>,
    pub valid_duration: Option<Duration>,
    pub header_name: String,  // ~"DKIM-Signature"

    // Key
    pub signing_key_id: KeyId,

    // Additional config
    //   - order of tags: d=, s=, a=, bh=, b=, t=, x= ...
    //   - header line length ...
}

impl SigningRequest {
    pub fn new(
        domain: DomainName,
        selector: String,
        key_type: KeyType,
        signing_key_id: KeyId,
    ) -> Self {
        let user_id = Ident::from_domain(domain.clone());
        let signed_headers = signature::get_default_signed_headers();
        Self {
            key_type,
            hash_alg: HashAlgorithm::Sha256,
            canonicalization: Default::default(),
            signed_headers,
            domain,
            user_id,
            selector,
            body_length: BodyLength::All,
            copied_headers: None,
            timestamp: Some(Timestamp::Now),
            valid_duration: Some(Duration::from_secs(60 * 60 * 24 * 5)),  // five days
            header_name: "DKIM-Signature".into(),

            signing_key_id,
        }
    }
}

struct SigningTask {
    request: SigningRequest,
    body_hasher: CountingHasher,
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
        signature: DkimSignature,
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
    body_canonicalizer_simple: BodyCanonicalizer,
    body_canonicalizer_relaxed: BodyCanonicalizer,
}

impl Signer {
    pub fn prepare_signing(
        requests: Vec<SigningRequest>,  // non-empty
        headers: HeaderFields,
        // + global config, such as timeouts
    ) -> Result<Self, SignerError> {
        assert!(!requests.is_empty());

        if !headers
            .as_ref()
            .iter()
            .any(|(name, _)| name.as_ref().eq_ignore_ascii_case("From"))
        {
            return Err(SignerError::MissingFromHeader);
        }

        // check signing request, eg must sign From header etc.

        let mut tasks = vec![];

        for request in requests {
            let hash_alg = request.hash_alg;
            let body_length = match request.body_length {
                BodyLength::All | BodyLength::OnlyMessageLength => None,
                BodyLength::Exact(n) => Some(n.try_into().unwrap()),
            };

            let task = SigningTask {
                request,
                body_hasher: CountingHasher::new(hash_alg, body_length),
            };

            tasks.push(task);
        }

        Ok(Self {
            tasks,
            headers,
            body_canonicalizer_simple: BodyCanonicalizer::simple(),
            body_canonicalizer_relaxed: BodyCanonicalizer::relaxed(),
        })
    }

    pub fn body_chunk(&mut self, chunk: &[u8]) -> BodyCanonStatus {
        let mut cached_canonicalized_chunk_simple = None;
        let mut cached_canonicalized_chunk_relaxed = None;

        let mut all_done = true;

        for task in &mut self.tasks {
            if !task.body_hasher.is_done() {
                let canon_kind = task.request.canonicalization.body;

                let canonicalized_chunk = match canon_kind {
                    CanonicalizationAlgorithm::Simple => cached_canonicalized_chunk_simple
                        .get_or_insert_with(|| self.body_canonicalizer_simple.canon_chunk(chunk)),
                    CanonicalizationAlgorithm::Relaxed => cached_canonicalized_chunk_relaxed
                        .get_or_insert_with(|| self.body_canonicalizer_relaxed.canon_chunk(chunk)),
                };

                if let HashStatus::NotDone = task.body_hasher.update(canonicalized_chunk) {
                    all_done = false;
                }
            }
        }

        if all_done {
            BodyCanonStatus::Done
        } else {
            BodyCanonStatus::NotDone
        }
    }

    pub async fn finish<T>(self, key_store: &T) -> Vec<SigningResult>
    where
        T: KeyStore + 'static,
    {
        let mut result = vec![];

        let cached_canonicalized_chunk_simple = self.body_canonicalizer_simple.finish_canon();
        let cached_canonicalized_chunk_relaxed = self.body_canonicalizer_relaxed.finish_canon();

        for task in self.tasks {
            let canon_kind = task.request.canonicalization.body;
            let canonicalized_chunk = match canon_kind {
                CanonicalizationAlgorithm::Simple => &cached_canonicalized_chunk_simple[..],
                CanonicalizationAlgorithm::Relaxed => &cached_canonicalized_chunk_relaxed[..],
            };

            let mut hasher = task.body_hasher;

            hasher.update(canonicalized_chunk);

            let (h, final_len) = match hasher.finish() {
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

            let body_hash = h;
            let body_length = match task.request.body_length {
                BodyLength::All => None,
                BodyLength::OnlyMessageLength => Some(final_len),
                BodyLength::Exact(n) => Some(n.try_into().unwrap()),
            };

            let signed_headers =
                signature::select_signed_headers(&task.request.signed_headers, &self.headers);

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
                signature_data: vec![],  // placeholder, to be replaced
                body_hash,
                canonicalization: task.request.canonicalization,
                domain: task.request.domain.clone(),
                signed_headers,
                user_id: task.request.user_id.clone(),
                selector: task.request.selector,
                body_length,
                timestamp,
                expiration,
                copied_headers: None,
            };

            let hdr_name = &task.request.header_name;
            let mut formatted_header = sig.format_without_signature();
            let canon_header =
                signature::canon_dkim_header(header_canonicalization, hdr_name, &formatted_header);

            // hash headers and formatted dkim-sig header to give data_hash:
            let data_hash = crypto::data_hash_digest(hash_alg, &headers, &canon_header);

            let key_id = task.request.signing_key_id;

            let signature_data =
                match sign_hash(key_id, key_type, hash_alg, &data_hash, key_store).await {
                    Ok(signature_data) => {
                        trace!("successfully signed");
                        signature_data
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
            signature::push_signature_data(&mut formatted_header, &signature_data[..]);

            result.push(SigningResult {
                status: SigningStatus::Success {
                    signature: sig,
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
