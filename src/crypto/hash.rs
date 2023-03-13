use crate::crypto::HashAlgorithm;
use sha2::Sha256;
#[cfg(feature = "sha1")]
use sha1::Sha1;

pub fn digest_slices<I, T>(
    hash_alg: HashAlgorithm,
    slices: I,
) -> Box<[u8]>
where
    I: IntoIterator<Item = T>,
    T: AsRef<[u8]>,
{
    use digest::Digest;

    match hash_alg {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            for bytes in slices {
                hasher.update(bytes.as_ref());
            }
            Box::from(&hasher.finalize()[..])
        }
        #[cfg(feature = "sha1")]
        HashAlgorithm::Sha1 => {
            let mut hasher = Sha1::new();
            for bytes in slices {
                hasher.update(bytes.as_ref());
            }
            Box::from(&hasher.finalize()[..])
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InsufficientInput;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashStatus {
    AllConsumed,  // input was digested entirely
    Truncated,  // input was only partially digested, part of it was ignored
}

pub struct CountingHasher {
    digest: Box<dyn digest::DynDigest + Send>,
    length: Option<usize>,
    bytes_written: usize,
}

impl CountingHasher {
    pub fn new(hash_alg: HashAlgorithm, length: Option<usize>) -> Self {
        let digest: Box<dyn digest::DynDigest + Send> = match hash_alg {
            HashAlgorithm::Sha256 => Box::new(Sha256::default()),
            #[cfg(feature = "sha1")]
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
    use base64ct::{Base64, Encoding};

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
        assert_eq!(Base64::encode_string(&hash), "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=");
        assert_eq!(len, 2);

        // See §3.4.4:
        let (hash, len) = hash_with_counting_hasher(HashAlgorithm::Sha256, b"");
        assert_eq!(Base64::encode_string(&hash), "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
        assert_eq!(len, 0);
    }

    #[cfg(feature = "sha1")]
    #[test]
    fn counting_hasher_rfc_examples_sha1() {
        // See §3.4.3:
        let (hash, len) = hash_with_counting_hasher(HashAlgorithm::Sha1, b"\r\n");
        assert_eq!(Base64::encode_string(&hash), "uoq1oCgLlTqpdDX/iUbLy7J1Wic=");
        assert_eq!(len, 2);

        // See §3.4.4:
        let (hash, len) = hash_with_counting_hasher(HashAlgorithm::Sha1, b"");
        assert_eq!(Base64::encode_string(&hash), "2jmj7l5rSw0yVb/vlWAYkK/YBwk=");
        assert_eq!(len, 0);
    }

    fn hash_with_counting_hasher(alg: HashAlgorithm, bytes: &[u8]) -> (Box<[u8]>, usize) {
        let mut hasher = CountingHasher::new(alg, None);
        hasher.update(bytes);
        hasher.finish().unwrap()
    }
}
