use crate::{
    crypto::{self, HashAlgorithm, SigningKey},
    header::{FieldName, HeaderFields},
    message_hash::{self, BodyHasherError, BodyHasherResults},
    signer::{
        format::{self, UnsignedDkimSignature},
        request::{self, BodyLength, HeaderSelection, SignRequest, Timestamp},
        SignerError, SigningResult, SigningStatus,
    },
};
use std::{collections::HashSet, time::SystemTime};
use tracing::trace;

pub async fn perform_signing<T>(
    request: SignRequest<T>,
    headers: &HeaderFields,
    hasher_results: &BodyHasherResults,
) -> SigningResult
where
    T: AsRef<SigningKey>,
{
    let algorithm = request.algorithm;
    let canonicalization = request.canonicalization;

    // calculate body hash

    let body_length = request::convert_body_length(request.body_length)
        .expect("unsupported integer conversion");
    let hash_alg = algorithm.hash_algorithm();
    let key = (body_length, hash_alg, canonicalization.body);

    let (body_hash, final_len) = match hasher_results.get(&key).unwrap() {
        Ok((h, final_len)) => (h.clone(), *final_len),
        Err(BodyHasherError::InsufficientInput) => {
            return SigningResult {
                status: SigningStatus::Error {
                    error: SignerError::InsufficientBodyLength,
                },
            };
        }
        Err(BodyHasherError::InputTruncated) => {
            panic!("unexpected canonicalization error");
        }
    };

    let body_length = match request.body_length {
        BodyLength::All => None,
        BodyLength::OnlyMessageLength | BodyLength::Exact(_) => {
            match final_len.try_into() {
                Ok(n) => Some(n),
                Err(_) => {
                    return SigningResult {
                        status: SigningStatus::Error {
                            error: SignerError::Overflow,
                        },
                    };
                }
            }
        }
    };

    // select headers

    let signed_headers = match &request.header_selection {
        HeaderSelection::Auto => select_signed_headers(headers).into_iter().cloned().collect(),
        HeaderSelection::Manual(h) => h.clone(),
    };

    // signed headers must include From
    if !signed_headers.iter().any(|name| *name == "From") {
        return SigningResult {
            status: SigningStatus::Error {
                error: SignerError::FromHeaderNotSigned,
            },
        };
    }
    // must not attempt to sign header names containing ';' (incompatible with DKIM-Signature)
    if signed_headers.iter().any(|name| name.as_ref().contains(';')) {
        return SigningResult {
            status: SigningStatus::Error {
                error: SignerError::InvalidSignedFieldName,
            },
        };
    }

    // calculate timestamp and expiration

    let timestamp = request.timestamp.map(|timestamp| match timestamp {
        Timestamp::Now => now_unix_secs(),
        Timestamp::Exact(t) => t,
    });

    let expiration = request.valid_duration.map(|duration| {
        timestamp.unwrap_or_else(now_unix_secs)
            .saturating_add(duration.as_secs())
    });

    // calculate z= tag copied headers

    let copied_headers = if request.copy_headers {
        let copied_headers = prepare_copied_headers(headers, &signed_headers);
        Some(Box::from(copied_headers))
    } else {
        None
    };

    // prepare complete formatted signature header with body hash except with contents of b= tag

    // TODO think again about proper validation of all inputs here
    let sig = UnsignedDkimSignature {
        algorithm,
        body_hash,
        canonicalization: request.canonicalization,
        domain: request.domain,
        signed_headers: signed_headers.into(),
        identity: request.identity,
        body_length,
        selector: request.selector,
        timestamp,
        expiration,
        copied_headers,
    };

    produce_signature(
        sig,
        request.signing_key.as_ref(),
        request.line_width,
        &request.header_name,
        headers,
    ).await
}

fn select_signed_headers(headers: &HeaderFields) -> Vec<&FieldName> {
    let def: HashSet<_> = request::default_signed_headers().into_iter().collect();
    request::select_headers(headers, move |name| def.contains(name)).collect()
}

async fn produce_signature(
    sig: UnsignedDkimSignature,
    signing_key: &SigningKey,
    line_width: usize,
    header_name: &str,
    headers: &HeaderFields,
) -> SigningResult {
    let b_len = estimate_b_tag_length(signing_key);

    let (mut formatted_header_value, insertion_index) =
        sig.format_without_signature(header_name, line_width, b_len);

    let algorithm = sig.algorithm;
    let hash_alg = algorithm.hash_algorithm();

    let data_hash = message_hash::compute_data_hash(
        hash_alg,
        sig.canonicalization.header,
        headers,
        &sig.signed_headers,
        header_name,
        &formatted_header_value
    );

    // TODO this could be checked at the beginning
    if signing_key.key_type() != algorithm.key_type() {
        return SigningResult {
            status: SigningStatus::Error {
                error: SignerError::KeyTypeMismatch,
            },
        };
    }

    // note artificial await point here, yields to runtime if many signatures
    let signature_data = match sign_hash(signing_key, hash_alg, &data_hash).await {
        Ok(signature_data) => {
            trace!("successfully signed");
            signature_data.into_boxed_slice()
        }
        Err(_e) => {
            trace!("signing failed");
            return SigningResult {
                status: SigningStatus::Error {
                    error: SignerError::SigningFailure,
                },
            };
        }
    };

    let sig = sig.into_signature(signature_data);

    // insert signature into formatted dkim-sig header, store

    format::insert_signature_data(
        &mut formatted_header_value,
        insertion_index,
        &sig.signature_data[..],
        line_width,
    );

    SigningResult {
        status: SigningStatus::Success {
            signature: Box::new(sig),
            header_name: header_name.into(),
            header_value: formatted_header_value,
        },
    }
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |t| t.as_secs())
}

fn prepare_copied_headers(
    headers: &HeaderFields,
    selected_headers: &[FieldName],
) -> Vec<(FieldName, Box<[u8]>)> {
    // TODO inefficient
    let mut v = vec![];
    for (name, value) in headers.as_ref() {
        if selected_headers.contains(name) {
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
    hash_alg: HashAlgorithm,
    data_hash: &[u8],
) -> Result<Vec<u8>, SignerError> {
    match signing_key {
        SigningKey::Rsa(k) => match crypto::sign_rsa(hash_alg, k, data_hash) {
            Ok(s) => {
                trace!("RSA signing successful");
                Ok(s)
            }
            Err(e) => {
                trace!("RSA signing failed: {e}");
                Err(SignerError::SigningFailure)
            }
        },
        SigningKey::Ed25519(k) => match crypto::sign_ed25519(k, data_hash) {
            Ok(s) => {
                trace!("Ed25519 signing successful");
                Ok(s)
            }
            Err(e) => {
                trace!("Ed25519 signing failed: {e}");
                Err(SignerError::SigningFailure)
            }
        },
    }
}
