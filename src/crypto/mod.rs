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
//! in the (de-facto standard) SubjectPublicKeyInfo format. If this fails it
//! falls back to trying reading the public key in the (de-iure standard)
//! RSAPublicKey format.
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
    ed25519::{read_ed25519_verifying_key, sign_ed25519, verify_ed25519},
    hash::{CountingHasher, HashStatus, InsufficientInput},
    rsa::{read_rsa_public_key, sign_rsa, verify_rsa},
};
// TODO
pub(crate) use hash::data_hash_digest;

use crate::util::CanonicalStr;
use ::rsa::{RsaPrivateKey, RsaPublicKey};
use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
use pkcs8::{der::pem::PemLabel, Document, PrivateKeyInfo};
use std::{
    fmt::{self, Display, Formatter},
    io::{self, ErrorKind},
};

#[derive(Debug)]
pub enum SigningKey {
    Rsa(RsaPrivateKey),
    Ed25519(Ed25519SigningKey),
}

impl SigningKey {
    pub fn to_key_type(&self) -> KeyType {
        match self {
            Self::Rsa(_) => KeyType::Rsa,
            Self::Ed25519(_) => KeyType::Ed25519,
        }
    }

    // TODO
    pub fn from_pkcs8_pem(s: &str) -> io::Result<Self> {
        let (label, private_key_der) = Document::from_pem(s)
            .map_err(|_| io::Error::new(ErrorKind::Other, "not a PEM document"))?;

        PrivateKeyInfo::validate_pem_label(label)
            .map_err(|_| io::Error::new(ErrorKind::Other, "not a PEM document"))?;

        // lightweight (could be Copy), therefore clonable:
        let pk = PrivateKeyInfo::try_from(private_key_der.as_bytes())
            .map_err(|_| io::Error::new(ErrorKind::Other, "invalid private key format"))?;

        if let Ok(rpk) = RsaPrivateKey::try_from(pk.clone()) {
            Ok(Self::Rsa(rpk))
        } else if let Ok(esk) = Ed25519SigningKey::try_from(pk.clone()) {
            Ok(Self::Ed25519(esk))
        } else {
            Err(io::Error::new(ErrorKind::Other, "unknown private key type"))
        }
    }
}

#[derive(Debug)]
pub enum VerifyingKey {
    Rsa(RsaPublicKey),
    Ed25519(Ed25519VerifyingKey),
}

impl VerifyingKey {
    pub fn key_size(&self) -> Option<usize> {
        match self {
            Self::Rsa(public_key) => Some(self::rsa::get_public_key_size(public_key)),
            Self::Ed25519(_) => None,
        }
    }

    pub fn from_key_data(key_type: KeyType, key_data: &[u8]) -> Result<Self, VerificationError> {
        match key_type {
            KeyType::Rsa => {
                let public_key = read_rsa_public_key(key_data)?;
                Ok(VerifyingKey::Rsa(public_key))
            }
            KeyType::Ed25519 => {
                let verifying_key = read_ed25519_verifying_key(key_data)?;
                Ok(VerifyingKey::Ed25519(verifying_key))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KeyType {
    Rsa,
    Ed25519,
}

impl CanonicalStr for KeyType {
    fn canonical_str(&self) -> &'static str {
        match self {
            Self::Rsa => "rsa",
            Self::Ed25519 => "ed25519",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HashAlgorithm {
    Sha256,
}

impl CanonicalStr for HashAlgorithm {
    fn canonical_str(&self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
        }
    }
}

impl HashAlgorithm {
    pub fn all() -> Vec<Self> {
        vec![Self::Sha256]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationError {
    InvalidKey,
    InsufficientKeySize,
    InvalidSignature,
    VerificationFailure,
}

impl Display for VerificationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey => write!(f, "invalid key data"),
            Self::InsufficientKeySize => write!(f, "key too small"),
            Self::InvalidSignature => write!(f, "invalid signature data"),
            Self::VerificationFailure => write!(f, "signature verification failed"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SigningError {
    SigningFailure,
}

// TODO
impl Display for SigningError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
