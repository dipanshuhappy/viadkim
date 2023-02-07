use crate::crypto::HashAlgorithm;
use sha2::Sha256;

pub fn data_hash_digest(hash_alg: HashAlgorithm, headers: &[u8], dkim_header: &str) -> Box<[u8]> {
    use sha2::Digest;

    match hash_alg {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(headers);
            hasher.update(dkim_header);
            Box::from(&hasher.finalize()[..])
        }
    }
}

#[derive(Debug)]
pub struct InsufficientInput;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashStatus {
    NotDone,
    Done,
}

pub struct CountingHasher {
    digest: Box<dyn digest::DynDigest + Send>,
    length: Option<usize>,
    bytes_written: usize,
}

impl CountingHasher {
    pub fn new(hash_alg: HashAlgorithm, length: Option<usize>) -> Self {
        let digest = match hash_alg {
            HashAlgorithm::Sha256 => Box::new(Sha256::default()),
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
                if self.is_done() {
                    return HashStatus::Done;
                }

                let bytes_left_to_write = len - self.bytes_written;

                if bytes_left_to_write > bytes.len() {
                    self.digest.update(bytes);
                    self.bytes_written += bytes.len();
                    HashStatus::NotDone
                } else {
                    let subslice = &bytes[..bytes_left_to_write];
                    self.digest.update(subslice);
                    self.bytes_written += subslice.len();
                    HashStatus::Done
                }
            }
            None => {
                self.digest.update(bytes);
                self.bytes_written += bytes.len();
                HashStatus::NotDone
            }
        }
    }

    pub fn finish(self) -> Result<(Box<[u8]>, usize), InsufficientInput> {
        if self.length.is_some() && !self.is_done() {
            return Err(InsufficientInput);
        }

        let bytes = self.digest.finalize();

        Ok((Box::from(bytes), self.bytes_written))
    }

    pub fn is_done(&self) -> bool {
        matches!(self.length, Some(len) if len == self.bytes_written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canon::BodyCanonicalizer;
    use bstr::ByteSlice;
    use base64ct::{Base64, Encoding};

    #[test]
    fn hasher_crlf_body() {
        let mut hasher = CountingHasher::new(HashAlgorithm::Sha256, None);

        hasher.update(b"\r\n");

        let (hash, len) = hasher.finish().unwrap();

        assert_eq!(
            Base64::encode_string(&hash),
            "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY="
        );
        assert_eq!(len, 2);
    }

    #[test]
    fn hasher_empty_body() {
        let hasher = CountingHasher::new(HashAlgorithm::Sha256, None);

        let (hash, len) = hasher.finish().unwrap();

        assert_eq!(
            Base64::encode_string(&hash),
            "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
        );
        assert_eq!(len, 0);
    }

    #[test]
    fn hasher_canon_body_with_length() {
        let mut hasher = CountingHasher::new(HashAlgorithm::Sha256, Some(27));

        let bc = BodyCanonicalizer::simple();

        let body = canonicalize_chunks(
            bc,
            &[b"well  hello \r\n", b"\r\n what agi \r\n\r\n", b"\r\n"],
        );

        let status = hasher.update(&body);
        assert_eq!(status, HashStatus::Done);

        let (hash, _) = hasher.finish().unwrap();

        let exp_hash = hash_digest(HashAlgorithm::Sha256, b"well  hello \r\n\r\n what agi \r");

        assert_eq!(hash, exp_hash);
    }

    #[test]
    fn hasher_canon_body_sample() {
        let mut hasher = CountingHasher::new(HashAlgorithm::Sha256, None);

        let body = b"\
Hello Proff,

Let\xe2\x80\x99s try this again, with line
breaks and empty lines even.

Ciao, und bis bald


-- 
David
";
        let body = body.replace("\n", "\r\n");

        let bc = BodyCanonicalizer::relaxed();

        let body = canonicalize_chunks(bc, &[&body]);

        let status = hasher.update(&body);
        assert_eq!(status, HashStatus::NotDone);

        let (hash, _) = hasher.finish().unwrap();

        assert_eq!(
            Base64::encode_string(&hash),
            "RMSbeRTj/zCxWeWQXpEIbiqxH0Jqg5eYs4ORzOt3MT0="
        );
    }

    fn hash_digest(hash_alg: HashAlgorithm, msg: &[u8]) -> Box<[u8]> {
        use sha2::Digest;

        match hash_alg {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(msg);
                let bytes = hasher.finalize();
                Box::from(&bytes[..])
            }
        }
    }

    fn canonicalize_chunks(mut bc: BodyCanonicalizer, chunks: &[&[u8]]) -> Vec<u8> {
        let mut result = vec![];
        for c in chunks {
            result.extend(bc.canon_chunk(c));
        }
        result.extend(bc.finish_canon());
        result
    }
}
