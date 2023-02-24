//! Signer and supporting types.

use crate::{
    body_hash::{CanonicalizingHasher, CanonicalizingHasherBuilder},
    canonicalize::{self, BodyCanonStatus},
    crypto::{self, HashAlgorithm, InsufficientInput, KeyType, SigningKey},
    header::{FieldName, HeaderFields},
    signature::{
        self, Canonicalization, DkimSignature, DomainName, Identity, Selector, SignatureAlgorithm,
        DKIM_SIGNATURE_NAME, LINE_WIDTH,
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
    Exact(u64),  // t=<n>
}

pub struct SigningRequest<T> {
    // Key
    pub signing_key: T,

    // Signature
    pub signature_alg: SignatureAlgorithm,
    pub canonicalization: Canonicalization,
    pub signed_headers: Vec<FieldName>,  // treated as a set, must not contain ;
    pub oversigned_headers: Vec<FieldName>,  // treated as a set, must not contain ;
    pub domain: DomainName,
    pub user_id: Option<Identity>,
    pub selector: Selector,
    pub body_length: BodyLength,
    pub copy_headers: bool,  // copy all headers used to create the signature
    pub timestamp: Option<Timestamp>,
    pub valid_duration: Option<Duration>,
    pub header_name: String,  // ~"DKIM-Signature"

    // Additional config
    pub line_width: usize,
    //   - order of tags: d=, s=, a=, bh=, b=, t=, x= ...
}

impl<T> SigningRequest<T> {
    pub fn new(
        domain: DomainName,
        selector: Selector,
        signature_alg: SignatureAlgorithm,
        signing_key: T,
    ) -> Self {
        let user_id = None;
        let signed_headers = signature::get_default_signed_headers();
        let oversigned_headers = vec![];

        Self {
            signing_key,

            signature_alg,
            canonicalization: Default::default(),
            signed_headers,
            oversigned_headers,
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

struct SigningTask<T> {
    request: SigningRequest<T>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SignerError {
    TooManyRequests,
    InvalidSignedFieldName,
    MissingFromHeader,
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

pub struct Signer<T> {
    tasks: Vec<SigningTask<T>>,  // non-empty (?)
    headers: HeaderFields,
    canonicalizing_hasher: CanonicalizingHasher,
}

impl<T> Signer<T>
where
    T: AsRef<SigningKey>,
{
    pub fn prepare_signing<I>(
        requests: I,
        headers: HeaderFields,
        // + global config, such as timeouts
    ) -> Result<Self, SignerError>
    where
        I: IntoIterator<Item = SigningRequest<T>>,
    {
        if !headers.as_ref().iter().any(|(name, _)| *name == "From") {
            return Err(SignerError::MissingFromHeader);
        }

        // check signing request, eg must sign From header etc.

        let mut tasks = vec![];
        let mut canonicalizing_hasher = CanonicalizingHasherBuilder::new();

        for (i, request) in requests.into_iter().enumerate() {
            if i >= 10 {
                return Err(SignerError::TooManyRequests);
            }

            // must not attempt to sign header names containing ';' (incompatible with DKIM-Signature)
            if request.signed_headers.iter().any(|name| name.as_ref().contains(';'))
                || request.oversigned_headers.iter().any(|name| name.as_ref().contains(';'))
            {
                return Err(SignerError::InvalidSignedFieldName);
            }

            // check user id domain is subdomain of signing domain

            let body_length = match request.body_length {
                BodyLength::All | BodyLength::OnlyMessageLength => None,
                BodyLength::Exact(n) => Some(n.try_into().unwrap_or(usize::MAX)),
            };
            let hash_alg = request.signature_alg.to_hash_algorithm();
            let canon_kind = request.canonicalization.body;
            canonicalizing_hasher.register_canon(body_length, hash_alg, canon_kind);

            let task = SigningTask { request };

            tasks.push(task);
        }

        // TODO allow empty tasks?

        Ok(Self {
            tasks,
            headers,
            canonicalizing_hasher: canonicalizing_hasher.build(),
        })
    }

    pub fn body_chunk(&mut self, chunk: &[u8]) -> BodyCanonStatus {
        self.canonicalizing_hasher.hash_chunk(chunk)
    }

    // Doesn't actually need async, but may use it to introduce artificial await points?
    pub async fn finish(self) -> Vec<SigningResult> {
        let mut result = vec![];

        let hasher_results = self.canonicalizing_hasher.finish();

        for task in self.tasks {
            let request = task.request;

            let algorithm = request.signature_alg;
            let canonicalization = request.canonicalization;

            // calculate body hash

            let body_length = match request.body_length {
                BodyLength::All | BodyLength::OnlyMessageLength => None,
                BodyLength::Exact(n) => Some(n.try_into().unwrap_or(usize::MAX)),
            };
            let hash_alg = algorithm.to_hash_algorithm();
            let key = (body_length, hash_alg, canonicalization.body);

            let (h, &final_len) = match hasher_results.get(&key).unwrap() {
                Ok((h, final_len)) => (h, final_len),
                Err(InsufficientInput) => {
                    result.push(SigningResult {
                        status: SigningStatus::Error {
                            error: SignerError::InsufficientBodyLength,
                        },
                    });
                    continue;
                }
            };

            let body_hash = h.clone();
            let body_length = match request.body_length {
                BodyLength::All => None,
                BodyLength::OnlyMessageLength | BodyLength::Exact(_) => {
                    Some(final_len.try_into().unwrap_or(u64::MAX))
                }
            };

            // select and canonicalize headers

            // TODO
            let signed_headers = signature::select_signed_headers(
                &request.signed_headers,
                &request.oversigned_headers,
                &self.headers,
            );

            let header_canonicalization = canonicalization.header;

            let headers = canonicalize::canon_headers(
                header_canonicalization,
                &self.headers,
                signed_headers.as_slice(),
            );

            // calculate timestamp and expiration

            // TODO
            let (timestamp, expiration) = match request.timestamp {
                Some(Timestamp::Now) => {
                    let now = SystemTime::now();
                    let timestamp = now
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .map_or(0, |t| t.as_secs());
                    let expiration = request.valid_duration.map(|e| {
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

            // calculate z= tag copied headers

            let copied_headers = if request.copy_headers {
                Some(Box::from(prepare_copied_headers(
                    &self.headers,
                    &request.signed_headers,
                    &request.oversigned_headers,
                )))
            } else {
                None
            };

            // prepare complete formatted signature header with body hash except with contents of b= tag

            // TODO think again about proper validation of all inputs here
            let mut sig = DkimSignature {
                algorithm,
                signature_data: Default::default(),  // placeholder, to be replaced
                body_hash,
                canonicalization: request.canonicalization,
                domain: request.domain.clone(),
                signed_headers: signed_headers.into(),
                user_id: request.user_id.clone(),
                selector: request.selector,
                body_length,
                timestamp,
                expiration,
                copied_headers,
            };

            let signing_key = request.signing_key.as_ref();

            let line_width = request.line_width;
            let hdr_name = &request.header_name;
            let b_len = estimate_b_tag_length(signing_key);

            let (mut formatted_header, insertion_index) =
                sig.format_without_signature(line_width, b_len);

            // compute data hash, consisting of hashed headers plus formatted dkim-sig header

            let canon_header =
                signature::canon_dkim_header(header_canonicalization, hdr_name, &formatted_header);

            let key_type = algorithm.to_key_type();
            let data_hash = crypto::data_hash_digest(hash_alg, &headers, &canon_header);

            // perform signing

            // note artificial await point here, yield to runtime if many signatures
            sig.signature_data = match sign_hash(signing_key, key_type, hash_alg, &data_hash).await
            {
                Ok(signature_data) => {
                    trace!("successfully signed");
                    signature_data.into_boxed_slice()
                }
                Err(_e) => {
                    trace!("signing failed");
                    result.push(SigningResult {
                        status: SigningStatus::Error {
                            error: SignerError::SigningFailure,
                        },
                    });
                    continue;
                }
            };

            // insert signature into formatted dkim-sig header, store

            signature::insert_signature_data(
                &mut formatted_header,
                insertion_index,
                &sig.signature_data[..],
                line_width,
            );

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

fn prepare_copied_headers(
    headers: &HeaderFields,
    signed_headers: &[FieldName],
    oversigned_headers: &[FieldName],
) -> Vec<(FieldName, Box<[u8]>)> {
    // TODO inefficient
    let mut v = vec![];
    for (name, value) in headers.as_ref() {
        if signed_headers.contains(name) || oversigned_headers.contains(name) {
            v.push((name.clone(), value.as_ref().into()));
        }
    }
    v
}

fn estimate_b_tag_length(signing_key: &SigningKey) -> usize {
    let n = signing_key.signature_length();
    // n is the signature length in bytes, now compute the length of the
    // base64-encoded value:
    (n + 2) / 3 * 4
}

async fn sign_hash(
    signing_key: &SigningKey,
    key_type: KeyType,
    hash_alg: HashAlgorithm,
    data_hash: &[u8],
) -> Result<Vec<u8>, SignerError> {
    match signing_key {
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
