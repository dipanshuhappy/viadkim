use crate::{
    canonicalize::{BodyCanonStatus, BodyCanonicalizer},
    crypto::{CountingHasher, HashAlgorithm, HashStatus, InsufficientInput},
    signature::{CanonicalizationAlgorithm, DkimSignature},
};
use std::collections::{HashMap, HashSet};

pub type BodyHasherKey = (Option<usize>, HashAlgorithm, CanonicalizationAlgorithm);

pub fn body_hasher_key(sig: &DkimSignature) -> BodyHasherKey {
    let body_len = sig
        .body_length
        .map(|len| len.try_into().expect("unexpected integer overflow"));
    let hash_alg = sig.algorithm.to_hash_algorithm();
    let canon_kind = sig.canonicalization.body;
    (body_len, hash_alg, canon_kind)
}

pub struct BodyHasherBuilder {
    forbid_partial: bool,  // truncated inputs must yield ForbiddenTruncation
    registrations: HashSet<BodyHasherKey>,
}

impl BodyHasherBuilder {
    pub fn new(forbid_partially_hashed_input: bool) -> Self {
        Self {
            forbid_partial: forbid_partially_hashed_input,
            registrations: HashSet::new(),
        }
    }

    pub fn register_canonicalization(
        &mut self,
        len: Option<usize>,
        alg: HashAlgorithm,
        canon: CanonicalizationAlgorithm,
    ) {
        self.registrations.insert((len, alg, canon));
    }

    pub fn build(self) -> BodyHasher {
        let hashers = self
            .registrations
            .into_iter()
            .map(|key @ (len, alg, _)| (key, (CountingHasher::new(alg, len), false)))
            .collect();

        BodyHasher {
            forbid_partial: self.forbid_partial,
            hashers,
            canonicalizer_simple: BodyCanonicalizer::simple(),
            canonicalizer_relaxed: BodyCanonicalizer::relaxed(),
        }
    }
}

/// A producer of ‘body hash’ results. The body hasher canonicalises and hashes
/// chunks of the message body, until all body hash requests can be answered.
pub struct BodyHasher {
    forbid_partial: bool,  // TODO rename fail_on_truncate ?
    // For each registration/key, map to a hasher and a flag that records
    // whether input was truncated, ie only partially consumed
    hashers: HashMap<BodyHasherKey, (CountingHasher, bool)>,
    canonicalizer_simple: BodyCanonicalizer,
    canonicalizer_relaxed: BodyCanonicalizer,
}

impl BodyHasher {
    // Note: the status returned here is not the ultimate truth: `Done` means it
    // is definitely done, but `NotDone` is not necessarily true, because the
    // `BodyCanonicalizer`s are stateful and may already have the final pieces.
    pub fn hash_chunk(&mut self, chunk: &[u8]) -> BodyCanonStatus {
        let mut canonicalized_chunk_simple = None;
        let mut canonicalized_chunk_relaxed = None;

        let mut all_done = true;

        let active_hashers = self.hashers.iter_mut().filter(|(_, (hasher, truncated))| {
            !hasher.is_done() || (self.forbid_partial && !truncated)
        });

        for ((_, _, canon), (hasher, truncated)) in active_hashers {
            let canonicalized_chunk = match canon {
                CanonicalizationAlgorithm::Simple => canonicalized_chunk_simple
                    .get_or_insert_with(|| self.canonicalizer_simple.canon_chunk(chunk)),
                CanonicalizationAlgorithm::Relaxed => canonicalized_chunk_relaxed
                    .get_or_insert_with(|| self.canonicalizer_relaxed.canon_chunk(chunk)),
            };

            match hasher.update(canonicalized_chunk) {
                HashStatus::AllConsumed => {
                    if self.forbid_partial || !hasher.is_done() {
                        all_done = false;
                    }
                }
                HashStatus::Truncated => {
                    *truncated = true;
                }
            }
        }

        if all_done {
            BodyCanonStatus::Done
        } else {
            BodyCanonStatus::NotDone
        }
    }

    pub fn finish(self) -> BodyHasherResults {
        let mut finish_canonicalization_simple = Some(|| self.canonicalizer_simple.finish_canon());
        let mut finish_canonicalization_relaxed = Some(|| self.canonicalizer_relaxed.finish_canon());
        let mut canonicalized_chunk_simple = None;
        let mut canonicalized_chunk_relaxed = None;

        let mut results = HashMap::new();

        for (key @ (_, _, canon), (mut hasher, mut truncated)) in self.hashers {
            if !hasher.is_done() || (self.forbid_partial && !truncated) {
                let canonicalized_chunk = match canon {
                    CanonicalizationAlgorithm::Simple => {
                        match finish_canonicalization_simple.take() {
                            Some(f) => canonicalized_chunk_simple.insert(f()),
                            None => canonicalized_chunk_simple.as_ref().unwrap(),
                        }
                    }
                    CanonicalizationAlgorithm::Relaxed => {
                        match finish_canonicalization_relaxed.take() {
                            Some(f) => canonicalized_chunk_relaxed.insert(f()),
                            None => canonicalized_chunk_relaxed.as_ref().unwrap(),
                        }
                    }
                };

                if let HashStatus::Truncated = hasher.update(canonicalized_chunk) {
                    truncated = true;
                }
            }

            let res = if self.forbid_partial && truncated {
                Err(BodyHasherError::ForbiddenTruncation)
            } else {
                hasher.finish().map_err(|InsufficientInput| BodyHasherError::InsufficientInput)
            };

            results.insert(key, res);
        }

        BodyHasherResults { results }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BodyHasherError {
    InsufficientInput,
    ForbiddenTruncation,
}

// pub struct BodyHashResult {
//     pub hash: Box<[u8]>,
//     pub length: usize,
// }

pub struct BodyHasherResults {
    results: HashMap<BodyHasherKey, Result<(Box<[u8]>, usize), BodyHasherError>>,
}

impl BodyHasherResults {
    pub fn get(&self, key: &BodyHasherKey) -> Option<&Result<(Box<[u8]>, usize), BodyHasherError>> {
        self.results.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::{Base64, Encoding};
    use bstr::ByteSlice;

    fn key_simple() -> BodyHasherKey {
        (None, HashAlgorithm::Sha256, CanonicalizationAlgorithm::Simple)
    }

    fn limited_key_simple(n: usize) -> BodyHasherKey {
        (Some(n), HashAlgorithm::Sha256, CanonicalizationAlgorithm::Simple)
    }

    fn key_relaxed() -> BodyHasherKey {
        (None, HashAlgorithm::Sha256, CanonicalizationAlgorithm::Relaxed)
    }

    fn limited_key_relaxed(n: usize) -> BodyHasherKey {
        (Some(n), HashAlgorithm::Sha256, CanonicalizationAlgorithm::Relaxed)
    }

    #[test]
    fn body_hasher_simple() {
        let key1 @ (_, _, canon_alg1) = key_simple();
        let key2 @ (len, hash_alg, canon_alg2) = key_relaxed();

        let mut hasher = BodyHasherBuilder::new(false);
        hasher.register_canonicalization(len, hash_alg, canon_alg1);
        hasher.register_canonicalization(len, hash_alg, canon_alg2);
        let mut hasher = hasher.build();

        assert_eq!(hasher.hash_chunk(b"abc \r\n"), BodyCanonStatus::NotDone);

        let results = hasher.finish();

        let res1 = results.get(&key1).unwrap();
        assert_eq!(res1.as_ref().unwrap().1, 6);
        let res2 = results.get(&key2).unwrap();
        assert_eq!(res2.as_ref().unwrap().1, 5);
    }

    #[test]
    fn body_hasher_fail_on_partial() {
        let key1 @ (len, hash_alg, canon_alg1) = limited_key_relaxed(4);

        let mut hasher = BodyHasherBuilder::new(true);
        hasher.register_canonicalization(len, hash_alg, canon_alg1);
        let mut hasher = hasher.build();

        assert_eq!(hasher.hash_chunk(b"ab"), BodyCanonStatus::NotDone);
        assert_eq!(hasher.hash_chunk(b"c"), BodyCanonStatus::NotDone);

        // Now canonicalization adds a final CRLF, exceeding the limit 4:
        let results = hasher.finish();

        let res1 = results.get(&key1).unwrap();
        assert_eq!(res1, &Err(BodyHasherError::ForbiddenTruncation));
    }

    #[test]
    fn body_hasher_hash_with_length() {
        let key1 @ (len, hash_alg, canon_alg1) = limited_key_simple(27);

        let mut hasher = BodyHasherBuilder::new(false);
        hasher.register_canonicalization(len, hash_alg, canon_alg1);
        let mut hasher = hasher.build();

        assert_eq!(hasher.hash_chunk(b"well  hello \r\n"), BodyCanonStatus::NotDone);
        assert_eq!(hasher.hash_chunk(b"\r\n what agi \r"), BodyCanonStatus::NotDone);
        assert_eq!(hasher.hash_chunk(b"\n\r\n"), BodyCanonStatus::Done);

        let results = hasher.finish();

        let res1 = results.get(&key1).unwrap();
        assert_eq!(
            res1.as_ref().unwrap().0,
            sha256_digest(b"well  hello \r\n\r\n what agi \r")
        );
    }

    #[test]
    fn body_hasher_known_hash_sample() {
        let key1 @ (len, hash_alg, canon_alg1) = key_relaxed();

        let mut hasher = BodyHasherBuilder::new(false);
        hasher.register_canonicalization(len, hash_alg, canon_alg1);
        let mut hasher = hasher.build();

        let body = b"\
Hello Proff,

Let\xe2\x80\x99s try this again, with line
breaks and empty lines even.

Ciao, und bis bald


-- 
David
";
        let body = body.replace("\n", "\r\n");

        assert_eq!(hasher.hash_chunk(&body), BodyCanonStatus::NotDone);

        let results = hasher.finish();

        let res1 = results.get(&key1).unwrap();
        assert_eq!(
            Base64::encode_string(&res1.as_ref().unwrap().0),
            "RMSbeRTj/zCxWeWQXpEIbiqxH0Jqg5eYs4ORzOt3MT0="
        );
    }

    fn sha256_digest(msg: &[u8]) -> Box<[u8]> {
        let mut hasher = CountingHasher::new(HashAlgorithm::Sha256, None);
        let _ = hasher.update(msg);
        hasher.finish().unwrap().0
    }
}
