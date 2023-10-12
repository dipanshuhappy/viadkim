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

//! Cryptographic utilities.
//!
//! This module’s public API includes types from third-party crates [rsa] and
//! [ed25519-dalek].
//!
//! # Pitfalls of DKIM public keys in DNS
//!
//! This library implements non-standard extensions for both RSA and Ed25519
//! public keys in DNS, and for good reason. Discussion follows.
//!
//! ## RSA
//!
//! In RFC 6376 a serious mistake was made in the description of the public key
//! creation. Section 3.6.1 states that the *p=* tag contains an RSA public key
//! in format *RSAPublicKey* (RFC 3447). However, the example in appendix C
//! shows how to install an RSA public key in format *SubjectPublicKeyInfo* (RFC
//! 5280) in the DNS.
//!
//! It is the second, slightly larger, format that implementers have taken as
//! authoritative and that has become widespread. In other words, the
//! SubjectPublicKeyInfo format has become the de facto standard (eg what
//! OpenDKIM uses), even though the standard mandates the RSAPublicKey format
//! (which is now apparently not universally supported).
//!
//! Several errata describing this problem in different wording have been filed
//! over the years ([2011], [2021], [2022]).
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
//!
//! [rsa]: https://crates.io/crates/rsa
//! [ed25519-dalek]: https://crates.io/crates/ed25519-dalek
//! [2011]: https://www.rfc-editor.org/errata/eid3017
//! [2021]: https://www.rfc-editor.org/errata/eid6674
//! [2022]: https://www.rfc-editor.org/errata/eid7001

mod ed25519;
mod hash;
mod rsa;

pub use self::{
    ed25519::{read_ed25519_verifying_key, sign_ed25519, verify_ed25519},
    hash::{digest, CountingHasher, HashStatus, InsufficientInput},
    rsa::{read_rsa_public_key, sign_rsa, verify_rsa},
};

use crate::util::CanonicalStr;
use ::rsa::{RsaPrivateKey, RsaPublicKey};
use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
use pkcs8::{der::pem::PemLabel, Document, PrivateKeyInfo};
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

/// The type of a key.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum KeyType {
    /// An RSA key.
    Rsa,
    /// An Ed25519 key.
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

impl Display for KeyType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.canonical_str())
    }
}

impl fmt::Debug for KeyType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// A hash algorithm.
///
/// When **feature `pre-rfc8301`**  is enabled, this enum will have a second
/// variant `Sha1` representing the SHA-1 hash algorithm. This variant is hidden
/// behind a feature flag, because SHA-1 is insecure and its use is strongly
/// discouraged.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum HashAlgorithm {
    /// The SHA-256 algorithm.
    Sha256,
    #[cfg(feature = "pre-rfc8301")]
    /// The SHA-1 algorithm.
    Sha1,
}

impl HashAlgorithm {
    pub fn all() -> Vec<Self> {
        vec![
            Self::Sha256,
            #[cfg(feature = "pre-rfc8301")]
            Self::Sha1,
        ]
    }
}

impl CanonicalStr for HashAlgorithm {
    fn canonical_str(&self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            #[cfg(feature = "pre-rfc8301")]
            Self::Sha1 => "sha1",
        }
    }
}

impl Display for HashAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.canonical_str())
    }
}

impl fmt::Debug for HashAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// An error that occurs when reading a signing key from PKCS#8 PEM.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DecodeSigningKeyError {
    InvalidPemDocument,
    NotAPrivateKeyInfoDocument,
    InvalidKeyData,
    UnsupportedKeyType,
}

impl Display for DecodeSigningKeyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPemDocument => write!(f, "invalid PEM document"),
            Self::NotAPrivateKeyInfoDocument => write!(f, "not a PKCS#8 PrivateKeyInfo document"),
            Self::InvalidKeyData => write!(f, "invalid private key data"),
            Self::UnsupportedKeyType => write!(f, "unsupported key type"),
        }
    }
}

impl Error for DecodeSigningKeyError {}

/// A (private) signing key.
#[derive(Debug)]
pub enum SigningKey {
    /// The RSA signing key.
    Rsa(RsaPrivateKey),
    /// The Ed25519 signing key.
    Ed25519(Ed25519SigningKey),
}

impl SigningKey {
    /// Returns this key’s key type.
    pub fn key_type(&self) -> KeyType {
        match self {
            Self::Rsa(_) => KeyType::Rsa,
            Self::Ed25519(_) => KeyType::Ed25519,
        }
    }

    /// Deserialises a signing key from the PKCS#8 PEM private key info in the
    /// given string.
    pub fn from_pkcs8_pem(s: &str) -> Result<Self, DecodeSigningKeyError> {
        let (label, doc) = Document::from_pem(s)
            .map_err(|_| DecodeSigningKeyError::InvalidPemDocument)?;

        PrivateKeyInfo::validate_pem_label(label)
            .map_err(|_| DecodeSigningKeyError::NotAPrivateKeyInfoDocument)?;

        // `PrivateKeyInfo` is not Copy, but could be, therefore nothing wrong
        // with the cloning below.
        let pk = PrivateKeyInfo::try_from(doc.as_bytes())
            .map_err(|_| DecodeSigningKeyError::InvalidKeyData)?;

        if let Ok(k) = RsaPrivateKey::try_from(pk.clone()) {
            Ok(Self::Rsa(k))
        } else if let Ok(k) = Ed25519SigningKey::try_from(pk.clone()) {
            Ok(Self::Ed25519(k))
        } else {
            Err(DecodeSigningKeyError::UnsupportedKeyType)
        }
    }

    /// Returns the length in bytes of signatures produced with this key.
    pub fn signature_length(&self) -> usize {
        match self {
            Self::Rsa(k) => {
                use ::rsa::traits::PublicKeyParts;
                k.size()
            }
            Self::Ed25519(_) => ::ed25519_dalek::SIGNATURE_LENGTH,
        }
    }
}

impl AsRef<SigningKey> for SigningKey {
    fn as_ref(&self) -> &Self {
        self
    }
}

/// A (public) verifying key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum VerifyingKey {
    /// The RSA verifying key.
    Rsa(RsaPublicKey),
    /// The Ed25519 verifying key.
    Ed25519(Ed25519VerifyingKey),
}

impl VerifyingKey {
    /// Returns this key’s size in bits, if available.
    ///
    /// Currently only the RSA verifying key provides a key size.
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
                Ok(Self::Rsa(public_key))
            }
            KeyType::Ed25519 => {
                let verifying_key = read_ed25519_verifying_key(key_data)?;
                Ok(Self::Ed25519(verifying_key))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SigningError {
    SigningFailure,
}

impl Display for SigningError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::SigningFailure => write!(f, "failed to perform signing"),
        }
    }
}

impl Error for SigningError {}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VerificationError {
    InvalidKey,
    InsufficientKeySize,
    VerificationFailure,
}

impl Display for VerificationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey => write!(f, "invalid key data"),
            Self::InsufficientKeySize => write!(f, "key too small"),
            Self::VerificationFailure => write!(f, "signature did not verify"),
        }
    }
}

impl Error for VerificationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_key_from_pkcs8_pem() {
        let key = SigningKey::from_pkcs8_pem("no PEM");
        assert_eq!(key.unwrap_err(), DecodeSigningKeyError::InvalidPemDocument);

        let key = SigningKey::from_pkcs8_pem(
            "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEALlL9HXJq+OigwEEqTS7qzyneGP55gTq55NibbL8kSI4=
-----END PUBLIC KEY-----",
        );
        assert_eq!(key.unwrap_err(), DecodeSigningKeyError::NotAPrivateKeyInfoDocument);

        let key = SigningKey::from_pkcs8_pem(
            "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJGNv5VBw2H6MV5s8LYuQp8AfYZFCn26mre1YAH2Qbmd
-----END PRIVATE KEY-----",
        );
        assert_eq!(key.unwrap().key_type(), KeyType::Ed25519);
    }
}
