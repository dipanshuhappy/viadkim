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

use crate::crypto::HashAlgorithm;
#[cfg(feature = "pre-rfc8301")]
use sha1::Sha1;
use sha2::Sha256;
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

/// Computes the hash of the given bytes.
pub fn digest(alg: HashAlgorithm, bytes: impl AsRef<[u8]>) -> Box<[u8]> {
    use digest::Digest;

    match alg {
        HashAlgorithm::Sha256 => {
            let hash = Sha256::digest(bytes);
            Box::from(&hash[..])
        }
        #[cfg(feature = "pre-rfc8301")]
        HashAlgorithm::Sha1 => {
            let hash = Sha1::digest(bytes);
            Box::from(&hash[..])
        }
    }
}

/// An error indicating that a hasher expected more input than it was fed.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct InsufficientInput;

impl Display for InsufficientInput {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "not enough input data")
    }
}

impl Error for InsufficientInput {}

/// Status returned by a hasher after digesting bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HashStatus {
    /// The given input was digested in entirety.
    AllConsumed,
    /// The given input was only partially digested, part of it was ignored.
    Truncated,
}

/// A hasher that keeps track of how many bytes it has digested.
pub struct CountingHasher {
    digest: Box<dyn digest::DynDigest + Send + Sync>,
    length: Option<usize>,
    bytes_written: usize,
}

impl CountingHasher {
    pub fn new(alg: HashAlgorithm, length: Option<usize>) -> Self {
        let digest: Box<dyn digest::DynDigest + Send + Sync> = match alg {
            HashAlgorithm::Sha256 => Box::new(Sha256::default()),
            #[cfg(feature = "pre-rfc8301")]
            HashAlgorithm::Sha1 => Box::new(Sha1::default()),
        };

        Self {
            length,
            digest,
            bytes_written: 0,
        }
    }

    pub fn update(&mut self, bytes: &[u8]) -> HashStatus {
        match self.length {
            Some(len) => {
                assert!(len >= self.bytes_written);

                let bytes_left_to_write = len - self.bytes_written;

                if bytes_left_to_write >= bytes.len() {
                    self.digest.update(bytes);
                    self.bytes_written += bytes.len();
                    HashStatus::AllConsumed
                } else {
                    let partial_bytes = &bytes[..bytes_left_to_write];
                    self.digest.update(partial_bytes);
                    self.bytes_written += partial_bytes.len();
                    HashStatus::Truncated
                }
            }
            None => {
                self.digest.update(bytes);
                self.bytes_written += bytes.len();
                HashStatus::AllConsumed
            }
        }
    }

    pub fn finish(self) -> Result<(Box<[u8]>, usize), InsufficientInput> {
        if self.length.is_some() && !self.is_done() {
            return Err(InsufficientInput);
        }

        let bytes = self.digest.finalize();

        Ok((bytes, self.bytes_written))
    }

    pub fn is_done(&self) -> bool {
        matches!(self.length, Some(len) if len == self.bytes_written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util;

    #[test]
    fn counting_hasher_ok() {
        let mut hasher = CountingHasher::new(HashAlgorithm::Sha256, None);
        assert!(!hasher.is_done());
        assert_eq!(hasher.update(b"abc"), HashStatus::AllConsumed);
        assert!(!hasher.is_done());
        assert_eq!(hasher.update(b""), HashStatus::AllConsumed);
        assert!(!hasher.is_done());
        assert_eq!(hasher.finish().unwrap().1, 3);

        let mut hasher = CountingHasher::new(HashAlgorithm::Sha256, Some(3));
        assert!(!hasher.is_done());
        assert_eq!(hasher.update(b"ab"), HashStatus::AllConsumed);
        assert!(!hasher.is_done());
        assert_eq!(hasher.update(b""), HashStatus::AllConsumed);
        assert!(!hasher.is_done());
        assert_eq!(hasher.update(b"c"), HashStatus::AllConsumed);
        assert!(hasher.is_done());
        assert_eq!(hasher.update(b""), HashStatus::AllConsumed);
        assert!(hasher.is_done());
        assert_eq!(hasher.update(b"de"), HashStatus::Truncated);
        assert_eq!(hasher.finish().unwrap().1, 3);

        let mut hasher = CountingHasher::new(HashAlgorithm::Sha256, Some(3));
        assert_eq!(hasher.update(b"ab"), HashStatus::AllConsumed);
        assert_eq!(hasher.finish(), Err(InsufficientInput));
    }

    #[test]
    fn counting_hasher_rfc_examples() {
        // See §3.4.3:
        let (hash, len) = hash_with_counting_hasher(HashAlgorithm::Sha256, b"\r\n");
        assert_eq!(util::encode_base64(&hash), "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=");
        assert_eq!(len, 2);

        // See §3.4.4:
        let (hash, len) = hash_with_counting_hasher(HashAlgorithm::Sha256, b"");
        assert_eq!(util::encode_base64(&hash), "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
        assert_eq!(len, 0);
    }

    #[cfg(feature = "pre-rfc8301")]
    #[test]
    fn counting_hasher_rfc_examples_sha1() {
        // See §3.4.3:
        let (hash, len) = hash_with_counting_hasher(HashAlgorithm::Sha1, b"\r\n");
        assert_eq!(util::encode_base64(&hash), "uoq1oCgLlTqpdDX/iUbLy7J1Wic=");
        assert_eq!(len, 2);

        // See §3.4.4:
        let (hash, len) = hash_with_counting_hasher(HashAlgorithm::Sha1, b"");
        assert_eq!(util::encode_base64(&hash), "2jmj7l5rSw0yVb/vlWAYkK/YBwk=");
        assert_eq!(len, 0);
    }

    fn hash_with_counting_hasher(alg: HashAlgorithm, bytes: &[u8]) -> (Box<[u8]>, usize) {
        let mut hasher = CountingHasher::new(alg, None);
        hasher.update(bytes);
        hasher.finish().unwrap()
    }
}
