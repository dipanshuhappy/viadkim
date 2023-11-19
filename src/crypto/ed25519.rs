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

use ed25519_dalek::{
    pkcs8::DecodePublicKey, Signature, Signer, SigningKey, Verifier, VerifyingKey,
};
use std::error::Error;

/// Signs a message byte slice with an Ed25519 signature.
pub fn sign_ed25519(signing_key: &SigningKey, msg: &[u8]) -> Vec<u8> {
    let signature = signing_key.sign(msg);

    signature.to_bytes().to_vec()
}

/// Reads an Ed25519 public key from the given slice of bytes.
///
/// # Errors
///
/// Failure to read the key produces an error provided by the underlying
/// library. It is returned as a boxed `Error`. If instead a
/// [`VerificationError`][crate::crypto::VerificationError] is desired, the
/// variant `VerificationError::InvalidKey` should be used.
pub fn read_ed25519_verifying_key(
    key_data: &[u8],
) -> Result<VerifyingKey, Box<dyn Error + Send + Sync + 'static>> {
    let key = VerifyingKey::try_from(key_data).or_else(|e| {
        // Supply initial error if fallback fails, too.
        VerifyingKey::from_public_key_der(key_data).map_err(|_| e)
    })?;
    Ok(key)
}

/// Verifies an Ed25519 signature for a given message byte slice.
///
/// # Errors
///
/// A failing verification produces an error provided by the underlying library.
/// It is returned as a boxed `Error`. If instead a
/// [`VerificationError`][crate::crypto::VerificationError] is desired, the
/// variant `VerificationError::VerificationFailure` should be used.
pub fn verify_ed25519(
    verifying_key: &VerifyingKey,
    msg: &[u8],
    signature_data: &[u8],
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let signature = Signature::from_slice(signature_data)?;

    verifying_key.verify(msg, &signature)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util;
    use ed25519_dalek::pkcs8::DecodePrivateKey;

    // Output of:
    // openssl genpkey -algorithm ED25519 -out key.pem
    const PRIVKEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAgXiPH5szmdVoCcjN7r/swuGVTkWOMQLeFmoCJAcDmJ
-----END PRIVATE KEY-----";

    #[test]
    fn read_ed25519_verifying_key_spki() {
        let privkey = SigningKey::from_pkcs8_pem(PRIVKEY_PEM).unwrap();

        // Output of:
        // openssl pkey -in key.pem -pubout -outform DER | openssl base64 -A
        let pubkey_der64 = "MCowBQYDK2VwAyEA1QHCX4X6j/obHOeL7puSIFsr8Kd7XQcupCD5S2rvYdU=";

        let pubkey_bytes = util::decode_base64(pubkey_der64).unwrap();

        let pubkey = read_ed25519_verifying_key(&pubkey_bytes).unwrap();

        assert_eq!(pubkey, privkey.verifying_key());
    }

    #[test]
    fn read_ed25519_verifying_key_raw() {
        let privkey = SigningKey::from_pkcs8_pem(PRIVKEY_PEM).unwrap();

        // Output of:
        // openssl pkey -in key.pem -pubout -out pubkey.pem
        // openssl asn1parse -in pubkey.pem -offset 12 -noout -out /dev/stdout | openssl base64 -A
        let pubkey_der64 = "1QHCX4X6j/obHOeL7puSIFsr8Kd7XQcupCD5S2rvYdU=";

        let pubkey_bytes = util::decode_base64(pubkey_der64).unwrap();

        let pubkey = read_ed25519_verifying_key(&pubkey_bytes).unwrap();

        assert_eq!(pubkey, privkey.verifying_key());
    }
}
