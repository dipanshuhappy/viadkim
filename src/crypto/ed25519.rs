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

use crate::crypto::{SigningError, VerificationError};
use ed25519_dalek::{
    pkcs8::DecodePublicKey, Signature, Signer, SigningKey, Verifier, VerifyingKey,
};

pub fn read_ed25519_verifying_key(key_data: &[u8]) -> Result<VerifyingKey, VerificationError> {
    VerifyingKey::try_from(key_data)
        .or_else(|_| VerifyingKey::from_public_key_der(key_data))
        .map_err(|_| VerificationError::InvalidKey)
}

pub fn verify_ed25519(
    verifying_key: &VerifyingKey,
    msg: &[u8],
    signature_data: &[u8],
) -> Result<(), VerificationError> {
    let signature = Signature::from_slice(signature_data)
        .map_err(|_| VerificationError::InvalidSignature)?;

    verifying_key
        .verify(msg, &signature)
        .map_err(|_| VerificationError::VerificationFailure)
}

pub fn sign_ed25519(signing_key: &SigningKey, msg: &[u8]) -> Result<Vec<u8>, SigningError> {
    let signature = signing_key.sign(msg);
    Ok(signature.to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey, KeypairBytes, PublicKeyBytes};

    /*
    #[test]
    fn make_ed25519_key() {
        use rand::rngs::OsRng;
        let mut csprng = OsRng{};
        let keypair: Keypair = ed25519_dalek::Keypair::generate(&mut csprng);

        let kb: [u8; 64] = keypair.to_bytes();

        let pubkey: ed25519_dalek::PublicKey = keypair.public;
        let pb: [u8; 32] = pubkey.to_bytes();
        let seckey: ed25519_dalek::SecretKey = keypair.secret;
        let sb: [u8; 32] = seckey.to_bytes();

        let pkb = ed25519::pkcs8::PublicKeyBytes(pb);
        let s = pkb.to_public_key_pem(Default::default()).unwrap();
        eprintln!("pub: {}", s);

        let kpb = ed25519::pkcs8::KeypairBytes {
            secret_key: sb,
            public_key: Some(pb),
        };
        let s = kpb.to_pkcs8_pem(Default::default()).unwrap();
        let s: &str = s.as_ref();
        eprintln!("sec: {}", s);
    }
    */

    #[test]
    fn read_ed25519_key() {
        // TODO These two pkcs8 encoded keys generated with disabled test above:

        let public_key_pem = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA9VXMCgG0fXGIzwV7eOxKhz+Pe6DRmOBYjyvVoVrc/Dw=
-----END PUBLIC KEY-----
";
        let pkb = PublicKeyBytes::from_public_key_pem(public_key_pem).unwrap();

        let keypair_pem = "-----BEGIN PRIVATE KEY-----
MFECAQEwBQYDK2VwBCIEIJdevcQP5V+0H3FgPiT9874RoyKNRxhWceWcZWhgMSTB
gSEA9VXMCgG0fXGIzwV7eOxKhz+Pe6DRmOBYjyvVoVrc/Dw=
-----END PRIVATE KEY-----
";
        let mut kpb = KeypairBytes::from_pkcs8_pem(keypair_pem).unwrap();

        assert_eq!(pkb, kpb.public_key.unwrap());

        // bonus, PKCS#8 of private key only:

        kpb.public_key = None;

        let s = kpb.to_pkcs8_pem(Default::default()).unwrap();
        let s: &str = &s;
        let secret_key_pem = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJdevcQP5V+0H3FgPiT9874RoyKNRxhWceWcZWhgMSTB
-----END PRIVATE KEY-----
";

        assert_eq!(s, secret_key_pem);

        // alternative keys from openssl:

        // note output from `openssl genpkey -algorithm Ed25519 -out tested25519key.pem`
        // (only private key bytes w/o public key part)
        // -----BEGIN PRIVATE KEY-----
        // MC4CAQAwBQYDK2VwBCIEIHvzPSvRhWPU1VgJnRXFB8PkLebN9Bt8ZByayeWQ76iQ
        // -----END PRIVATE KEY-----
        //
        // and output from `openssl pkey -in tested25519key.pem -pubout`
        // (public key derived from private key above)
        // -----BEGIN PUBLIC KEY-----
        // MCowBQYDK2VwAyEAQJ+uTVeKqqdr+tbplMgr0ic7x7rhL0F6UlI4vbvurgI=
        // -----END PUBLIC KEY-----
    }
}
