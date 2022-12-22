//! Cryptographic utilities.
//!
//! # Pitfalls of DKIM public keys in DNS
//!
//! This library implements non-standard extensions for both RSA and Ed25519
//! public keys in DNS, and for good reason. Discussion follows.
//!
//! ## RSA
//!
//! In RFC 6376 a bad mistake was made in the description of the public key
//! creation. Section 3.6.1 states that the p= tag contains an RSA public key in
//! format RSAPublicKey (RFC 3447). However, the example in appendix C shows how
//! to install an RSA public key in format SubjectPublicKeyInfo (RFC 5280) in
//! the DNS.
//!
//! It is the second, slightly larger, format that implementers have taken as
//! authoritative and that has become widespread. In other words, the
//! SubjectPublicKeyInfo format has become the de facto standard (eg what
//! OpenDKIM uses), even though the standard mandates the RSAPublicKey format
//! (which is now apparently not universally supported).
//!
//! Several errata describing this problem in different wording have been filed
//! over the years.
//!
//! Because of this situation, viadkim first tries reading the public key in DNS
//! in the (de-iure standard) RSAPublicKey format. If this fails it falls back
//! to trying reading the public key in the (de-facto standard)
//! SubjectPublicKeyInfo format.
//!
//! ## Ed25519
//!
//! RFC 8463 mandates that the 32 bytes of an Ed25519 public key be installed
//! (in Base64) in DNS.
//!
//! However, when generating an Ed25519 key with OpenSSL, the public key is
//! generated in SubjectPublicKeyInfo format, and OpenSSL provides no built-in
//! way of generating ‘just’ the 32 public key bytes. Recall that the
//! SubjectPublicKeyInfo format is what has become the de facto standard for
//! *RSA* public keys in DNS.
//!
//! Therefore, SubjectPublicKeyInfo being both the format used for RSA and this
//! format being the default output from OpenSSL, it is not unlikely that on
//! some sites this is the format being used for the key installed in DNS.
//!
//! Because of this situation, viadkim first tries reading the public key in DNS
//! as the Base64-encoded raw bytes of an Ed25519 public key. If this fails, it
//! falls back to trying reading the public key in the (non-standard)
//! SubjectPublicKeyInfo format.

mod ed25519;
mod hash;
mod rsa;

pub use self::{
    ed25519::{
        read_ed25519_private_key, read_ed25519_private_key_file, sign_ed25519,
        verify_signature_ed25519,
    },
    rsa::{read_rsa_private_key, read_rsa_private_key_file, sign_rsa, verify_signature_rsa},
};
pub use hash::{data_hash_digest, CountingHasher, HashStatus, InsufficientInput};

use ::rsa::RsaPrivateKey;
use ed25519_dalek::Keypair as Ed25519Keypair;
use std::fmt::{self, Display, Formatter};

pub enum SigningKey {
    Rsa(RsaPrivateKey),
    Ed25519(Ed25519Keypair),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyType {
    Rsa,
    Ed25519,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
}

impl HashAlgorithm {
    pub fn all() -> Vec<Self> {
        vec![Self::Sha256]
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerificationError {
    InvalidKey,
    InsufficientKeySize,
    InvalidSignature,
    VerificationFailure,
}

impl Display for VerificationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SigningError {
    SigningFailure,
}

impl Display for SigningError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// TODO
pub fn read_signing_key(s: &str) -> std::io::Result<SigningKey> {
    use pkcs8::PrivateKeyInfo;
    use pkcs8::Document;
    use pkcs8::der::pem::PemLabel;

    let (label, private_key_der) = Document::from_pem(s).unwrap();

    PrivateKeyInfo::validate_pem_label(label).unwrap();

    // lightweight (could be Copy), therefore clonable:
    let pk = PrivateKeyInfo::try_from(private_key_der.as_bytes()).unwrap();

    if let Ok(rpk) = RsaPrivateKey::try_from(pk.clone()) {
        return Ok(SigningKey::Rsa(rpk));
    } else if let Ok(_ekp) = ::ed25519::pkcs8::KeypairBytes::try_from(pk.clone()) {
        todo!();
    } else {
        return Err(std::io::Error::from(std::io::ErrorKind::Other));
    }
}
