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

use crate::{
    crypto::{self, HashAlgorithm, SigningKey},
    header::{FieldName, HeaderFields},
    message_hash::{self, BodyHashError, BodyHashResults},
    signer::{
        self,
        format::{self, UnsignedDkimSignature},
        BodyLength, HeaderSelection, OutputFormat, SignRequest, SigningError, SigningResult,
        Timestamp,
    },
};
use std::{collections::HashSet, time::SystemTime};
use tracing::trace;

pub async fn perform_signing<T>(
    request: SignRequest<T>,
    headers: &HeaderFields,
    hasher_results: &BodyHashResults,
) -> Result<SigningResult, SigningError>
where
    T: AsRef<SigningKey>,
{
    let algorithm = request.algorithm;
    let canonicalization = request.canonicalization;

    // calculate body hash

    let body_length = request.body_length.to_usize().expect("unsupported integer conversion");
    let hash_alg = algorithm.hash_algorithm();
    let key = (body_length, hash_alg, canonicalization.body);

    let hasher_result = hasher_results.get(&key)
        .expect("requested body hash result not available");

    let (body_hash, final_len) = match hasher_result {
        Ok((h, final_len)) => (h.clone(), *final_len),
        Err(BodyHashError::InsufficientInput) => {
            return Err(SigningError::InsufficientContent);
        }
        Err(BodyHashError::InputTruncated) => {
            panic!("unexpected canonicalization error");
        }
    };

    let body_length = match request.body_length {
        BodyLength::NoLimit => None,
        BodyLength::MessageContent | BodyLength::Exact(_) => {
            match final_len.try_into() {
                Ok(n) => Some(n),
                Err(_) => {
                    return Err(SigningError::Overflow);
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
    assert!(signed_headers.iter().any(|name| *name == "From"));
    // must not attempt to sign header names containing ';' (incompatible with DKIM-Signature)
    assert!(!signed_headers.iter().any(|name| name.as_ref().contains(';')));

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
        Box::from(copied_headers)
    } else {
        [].into()
    };

    let ext_tags = request.ext_tags.into_iter()
        .map(|(k, v)| (k.into_boxed_str(), v.into_boxed_str()))
        .collect();

    // prepare complete formatted signature header with body hash except with contents of b= tag

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
        ext_tags,
    };

    produce_signature(
        sig,
        request.signing_key.as_ref(),
        &request.format,
        headers,
    ).await
}

fn select_signed_headers(headers: &HeaderFields) -> Vec<&FieldName> {
    let def: HashSet<_> = signer::default_signed_headers().into_iter().collect();
    signer::select_headers(headers, move |name| def.contains(name)).collect()
}

async fn produce_signature(
    sig: UnsignedDkimSignature,
    signing_key: &SigningKey,
    format: &OutputFormat,
    headers: &HeaderFields,
) -> Result<SigningResult, SigningError> {
    let b_len = estimate_b_tag_length(signing_key);

    let (mut formatted_header_value, insertion_index) = sig.format_without_signature(format, b_len);

    let header_name = &format.header_name;

    let algorithm = sig.algorithm;
    let hash_alg = algorithm.hash_algorithm();

    let data_hash = message_hash::compute_data_hash(
        hash_alg,
        sig.canonicalization.header,
        headers,
        &sig.signed_headers,
        header_name,
        &formatted_header_value,
    );

    assert_eq!(signing_key.key_type(), algorithm.key_type());

    // note artificial await point here, yields to runtime if many signatures
    let signature_data = sign_hash(signing_key, hash_alg, &data_hash)
        .await?
        .into_boxed_slice();

    let sig = sig.into_signature(signature_data);

    // insert signature into formatted dkim-sig header, store

    format::insert_signature_data(
        &mut formatted_header_value,
        insertion_index,
        header_name,
        &sig.signature_data[..],
        format.line_width.into(),
        &format.indentation,
    );

    Ok(SigningResult {
        header_name: header_name.into(),
        header_value: formatted_header_value,
        signature: sig,
    })
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
    let mut result = vec![];
    for (name, value) in headers.as_ref() {
        if selected_headers.contains(name) {
            result.push((name.clone(), value.as_ref().into()));
        }
    }
    result
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
) -> Result<Vec<u8>, SigningError> {
    match signing_key {
        SigningKey::Rsa(k) => match crypto::sign_rsa(hash_alg, k, data_hash) {
            Ok(s) => {
                trace!("RSA signing successful");
                Ok(s)
            }
            Err(e) => {
                trace!("RSA signing failed: {e}");
                Err(SigningError::SigningFailure)
            }
        },
        SigningKey::Ed25519(k) => match crypto::sign_ed25519(k, data_hash) {
            Ok(s) => {
                trace!("Ed25519 signing successful");
                Ok(s)
            }
            Err(e) => {
                trace!("Ed25519 signing failed: {e}");
                Err(SigningError::SigningFailure)
            }
        },
    }
}
