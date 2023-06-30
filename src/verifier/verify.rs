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
    crypto::{self, HashAlgorithm, VerifyingKey},
    header::HeaderFields,
    message_hash,
    signature::DkimSignature,
    tag_list,
    verifier::VerifierError,
};
use std::{borrow::Cow, str};
use tracing::trace;

pub fn perform_verification(
    headers: &HeaderFields,
    public_key: &VerifyingKey,
    sig: &DkimSignature,
    name: &str,
    value: &str,
) -> Result<(), VerifierError> {
    let hash_alg = sig.algorithm.hash_algorithm();

    let original_dkim_sig = make_original_dkim_sig(value);

    let data_hash = message_hash::compute_data_hash(
        hash_alg,
        sig.canonicalization.header,
        headers,
        &sig.signed_headers,
        name,
        &original_dkim_sig,
    );

    let signature_data = &sig.signature_data;

    verify_signature(public_key, hash_alg, &data_hash, signature_data)
}

fn make_original_dkim_sig(value: &str) -> Cow<'_, str> {
    fn b_tag_prefix_len(s: &str) -> Option<usize> {
        let (rest, _) = tag_list::strip_tag_name_and_equals(s).filter(|(_, name)| *name == "b")?;
        Some(s.len() - rest.len())
    }

    // First strip the b= tag value, only cloning the string if needed.

    let mut val = Cow::from(value);

    let mut last_i = 0;
    let mut ms = val.match_indices(';');

    loop {
        match ms.next() {
            Some((i, _)) => {
                if let Some(n) = b_tag_prefix_len(&val[last_i..i]) {
                    val.to_mut().drain((last_i + n)..i);
                    break;
                }
                last_i = i + 1;
            }
            None => {
                if last_i != val.len() {
                    if let Some(n) = b_tag_prefix_len(&val[last_i..]) {
                        val = value[..(last_i + n)].into();
                    }
                }
                break;
            }
        }
    }

    val
}

fn verify_signature(
    public_key: &VerifyingKey,
    hash_alg: HashAlgorithm,
    data_hash: &[u8],
    signature_data: &[u8],
) -> Result<(), VerifierError> {
    match public_key {
        VerifyingKey::Rsa(pk) => {
            match crypto::verify_rsa(hash_alg, pk, data_hash, signature_data) {
                Ok(()) => {
                    trace!("RSA public key verification successful");
                    Ok(())
                }
                Err(e) => {
                    trace!("RSA public key verification failed: {e}");
                    Err(VerifierError::VerificationFailure(e))
                }
            }
        }
        VerifyingKey::Ed25519(pk) => {
            match crypto::verify_ed25519(pk, data_hash, signature_data) {
                Ok(()) => {
                    trace!("Ed25519 public key verification successful");
                    Ok(())
                }
                Err(e) => {
                    trace!("Ed25519 public key verification failed: {e}");
                    Err(VerifierError::VerificationFailure(e))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_original_dkim_sig_basic() {
        assert_eq!(make_original_dkim_sig(" a = 1 ; b = 2 ; c = 3 "), " a = 1 ; b =; c = 3 ");
        assert_eq!(make_original_dkim_sig(" a = 1 ; b = 2 ;"), " a = 1 ; b =;");
        assert_eq!(make_original_dkim_sig(" a = 1 ; b = 2 "), " a = 1 ; b =");
        assert_eq!(make_original_dkim_sig(" a = 1 ; b ="), " a = 1 ; b =");
    }
}
