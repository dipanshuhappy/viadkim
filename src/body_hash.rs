use crate::{
    canon::{BodyCanonStatus, BodyCanonicalizer},
    crypto::{CountingHasher, HashAlgorithm, HashStatus, InsufficientInput},
    signature::{CanonicalizationAlgorithm, DkimSignature},
};
use std::collections::{HashMap, HashSet};

pub type CanonicalizingHasherKey = (Option<usize>, HashAlgorithm, CanonicalizationAlgorithm);

pub fn canonicalizing_hasher_key(sig: &DkimSignature) -> CanonicalizingHasherKey {
    let body_len = sig
        .body_length
        .map(|len| len.try_into().unwrap_or(usize::MAX));
    let hash_alg = sig.algorithm.to_hash_algorithm();
    let canon_kind = sig.canonicalization.body;
    (body_len, hash_alg, canon_kind)
}

pub struct CanonicalizingHasherBuilder {
    reqs: HashSet<CanonicalizingHasherKey>,
}

impl CanonicalizingHasherBuilder {
    pub fn new() -> Self {
        Self {
            reqs: HashSet::new(),
        }
    }

    pub fn register_canon(
        &mut self,
        len: Option<usize>,
        alg: HashAlgorithm,
        canon: CanonicalizationAlgorithm,
    ) {
        // register only *active* signatures, eg not those whose verification failed!
        self.reqs.insert((len, alg, canon));
    }

    pub fn build(self) -> CanonicalizingHasher {
        let mut map = HashMap::new();
        for (len, alg, canon) in self.reqs {
            let body_len = len;
            let hash_alg = alg;
            map.insert((len, alg, canon), CountingHasher::new(hash_alg, body_len));
        }

        CanonicalizingHasher {
            reqs: map,
            body_canonicalizer_simple: BodyCanonicalizer::simple(),
            body_canonicalizer_relaxed: BodyCanonicalizer::relaxed(),
        }
    }
}

pub struct CanonicalizingHasher {
    reqs: HashMap<CanonicalizingHasherKey, CountingHasher>,
    body_canonicalizer_simple: BodyCanonicalizer,
    body_canonicalizer_relaxed: BodyCanonicalizer,
}

impl CanonicalizingHasher {
    pub fn hash_chunk(&mut self, chunk: &[u8]) -> BodyCanonStatus {
        let mut cached_canonicalized_chunk_simple = None;
        let mut cached_canonicalized_chunk_relaxed = None;

        let mut all_done = true;

        for ((_len, _alg, canon), hasher) in self.reqs.iter_mut().filter(|(_, h)| !h.is_done()) {
            let canonicalized_chunk = match canon {
                CanonicalizationAlgorithm::Simple => cached_canonicalized_chunk_simple
                    .get_or_insert_with(|| self.body_canonicalizer_simple.canon_chunk(chunk)),
                CanonicalizationAlgorithm::Relaxed => cached_canonicalized_chunk_relaxed
                    .get_or_insert_with(|| self.body_canonicalizer_relaxed.canon_chunk(chunk)),
            };

            if let HashStatus::NotDone = hasher.update(canonicalized_chunk) {
                all_done = false;
            }
        }

        if all_done {
            BodyCanonStatus::Done
        } else {
            BodyCanonStatus::NotDone
        }
    }

    pub fn finish(self) -> CanonicalizingHasherResults {
        let mut cached_canonicalized_chunk_simple_f =
            Some(|| self.body_canonicalizer_simple.finish_canon());
        let mut cached_canonicalized_chunk_relaxed_f =
            Some(|| self.body_canonicalizer_relaxed.finish_canon());
        let mut cached_canonicalized_chunk_simple = None;
        let mut cached_canonicalized_chunk_relaxed = None;

        let mut results = HashMap::new();

        for ((len, alg, canon), mut hasher) in self.reqs {
            if !hasher.is_done() {
                let canonicalized_chunk = match canon {
                    CanonicalizationAlgorithm::Simple => {
                        match cached_canonicalized_chunk_simple_f.take() {
                            Some(f) => cached_canonicalized_chunk_simple.insert(f()),
                            None => cached_canonicalized_chunk_simple.as_ref().unwrap(),
                        }
                    }
                    CanonicalizationAlgorithm::Relaxed => {
                        match cached_canonicalized_chunk_relaxed_f.take() {
                            Some(f) => cached_canonicalized_chunk_relaxed.insert(f()),
                            None => cached_canonicalized_chunk_relaxed.as_ref().unwrap(),
                        }
                    }
                };

                let _ = hasher.update(canonicalized_chunk);
            }

            let res = hasher.finish();

            results.insert((len, alg, canon), res);
        }

        CanonicalizingHasherResults { reqs: results }
    }
}

pub struct CanonicalizingHasherResults {
    reqs: HashMap<CanonicalizingHasherKey, Result<(Box<[u8]>, usize), InsufficientInput>>,
}

impl CanonicalizingHasherResults {
    pub fn get(
        &self,
        key: &CanonicalizingHasherKey,
    ) -> Option<&Result<(Box<[u8]>, usize), InsufficientInput>> {
        self.reqs.get(key)
    }
}
