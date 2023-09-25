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

//! Computation of the message hashes.

use crate::{
    canonicalize::{self, BodyCanonicalizer},
    crypto::{self, CountingHasher, HashAlgorithm, HashStatus, InsufficientInput},
    header::{FieldName, HeaderFields},
    signature::{CanonicalizationAlgorithm, DkimSignature, DKIM_SIGNATURE_NAME},
};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt::{self, Display, Formatter},
};

pub fn compute_data_hash(
    hash_alg: HashAlgorithm,
    canon_alg: CanonicalizationAlgorithm,
    headers: &HeaderFields,
    selected_headers: &[FieldName],
    dkim_sig_header_name: &str,
    formatted_dkim_sig_header_value: &str,
) -> Box<[u8]> {
    debug_assert!(dkim_sig_header_name.eq_ignore_ascii_case(DKIM_SIGNATURE_NAME));

    // canonicalize selected headers
    let mut cheaders = canonicalize::canonicalize_headers(canon_alg, headers, selected_headers);

    // canonicalize DKIM-Signature header
    canonicalize::canonicalize_header(
        &mut cheaders,
        canon_alg,
        dkim_sig_header_name,
        formatted_dkim_sig_header_value,
    );

    // produce message digest of the canonicalized value
    crypto::digest(hash_alg, &cheaders)
}

/// The stance of a body hasher regarding additional body content.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[must_use]
pub enum BodyHasherStance {
    // Note: the stance does not represent the ultimate truth: `Done` means it
    // is definitely done, but `Interested` is not necessarily true, because the
    // `BodyCanonicalizer`s are stateful and may already have the final pieces.

    /// When `Interested` is returned after digesting input, then the client
    /// should feed more inputs to the body hasher, if there are any available
    /// still.
    Interested,

    /// When `Done` is returned after digesting input, the body hasher requires
    /// no further inputs to answer all body hash requests, and the client need
    /// not feed any additional inputs to the body hasher even if there is any
    /// remaining.
    Done,
}

pub type BodyHasherKey = (Option<usize>, HashAlgorithm, CanonicalizationAlgorithm);

pub fn body_hasher_key(sig: &DkimSignature) -> BodyHasherKey {
    let body_len = sig
        .body_length
        .map(|len| len.try_into().expect("unexpected integer overflow"));
    let hash_alg = sig.algorithm.hash_algorithm();
    let canon_kind = sig.canonicalization.body;
    (body_len, hash_alg, canon_kind)
}

#[derive(Clone)]
pub struct BodyHasherBuilder {
    fail_on_truncate: bool,  // truncated inputs must yield InputTruncated
    registrations: HashSet<BodyHasherKey>,
}

impl BodyHasherBuilder {
    pub fn new(fail_on_partially_hashed_input: bool) -> Self {
        Self {
            fail_on_truncate: fail_on_partially_hashed_input,
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
        use CanonicalizationAlgorithm::*;

        let hashers = self
            .registrations
            .into_iter()
            .map(|key @ (len, alg, _)| (key, (CountingHasher::new(alg, len), false)))
            .collect();

        BodyHasher {
            fail_on_truncate: self.fail_on_truncate,
            hashers,
            canonicalizer_simple: BodyCanonicalizer::new(Simple),
            canonicalizer_relaxed: BodyCanonicalizer::new(Relaxed),
        }
    }
}

/// A producer of *body hash* results.
///
/// The body hasher canonicalises and hashes chunks of the message body, until
/// all body hash requests can be answered.
pub struct BodyHasher {
    fail_on_truncate: bool,
    // For each registration/key, map to a hasher and a flag that records
    // whether input was truncated, ie only partially consumed
    hashers: HashMap<BodyHasherKey, (CountingHasher, bool)>,
    canonicalizer_simple: BodyCanonicalizer,
    canonicalizer_relaxed: BodyCanonicalizer,
}

impl BodyHasher {
    pub fn hash_chunk(&mut self, chunk: &[u8]) -> BodyHasherStance {
        let mut canonicalized_chunk_simple = None;
        let mut canonicalized_chunk_relaxed = None;

        let mut all_done = true;

        let active_hashers = self.hashers.iter_mut().filter(|(_, (hasher, truncated))| {
            !hasher.is_done() || (self.fail_on_truncate && !truncated)
        });

        for ((_, _, canon), (hasher, truncated)) in active_hashers {
            let canonicalized_chunk = match canon {
                CanonicalizationAlgorithm::Simple => canonicalized_chunk_simple
                    .get_or_insert_with(|| self.canonicalizer_simple.canonicalize_chunk(chunk)),
                CanonicalizationAlgorithm::Relaxed => canonicalized_chunk_relaxed
                    .get_or_insert_with(|| self.canonicalizer_relaxed.canonicalize_chunk(chunk)),
            };

            match hasher.update(canonicalized_chunk) {
                HashStatus::AllConsumed => {
                    if self.fail_on_truncate || !hasher.is_done() {
                        all_done = false;
                    }
                }
                HashStatus::Truncated => {
                    *truncated = true;
                }
            }
        }

        if all_done {
            BodyHasherStance::Done
        } else {
            BodyHasherStance::Interested
        }
    }

    pub fn finish(self) -> BodyHashResults {
        let mut finish_canonicalization_simple = Some(|| self.canonicalizer_simple.finish());
        let mut finish_canonicalization_relaxed = Some(|| self.canonicalizer_relaxed.finish());
        let mut canonicalized_chunk_simple = None;
        let mut canonicalized_chunk_relaxed = None;

        let mut results = HashMap::new();

        for (key @ (_, _, canon), (mut hasher, mut truncated)) in self.hashers {
            if !hasher.is_done() || (self.fail_on_truncate && !truncated) {
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

            let res = if self.fail_on_truncate && truncated {
                Err(BodyHashError::InputTruncated)
            } else {
                hasher.finish().map_err(|InsufficientInput| BodyHashError::InsufficientInput)
            };

            results.insert(key, res);
        }

        BodyHashResults { results }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BodyHashError {
    InsufficientInput,
    InputTruncated,
}

impl Display for BodyHashError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientInput => write!(f, "insufficient input data"),
            Self::InputTruncated => write!(f, "input not digested entirely"),
        }
    }
}

impl Error for BodyHashError {}

pub type BodyHashResult = Result<(Box<[u8]>, usize), BodyHashError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BodyHashResults {
    results: HashMap<BodyHasherKey, BodyHashResult>,
}

impl BodyHashResults {
    pub fn get(&self, key: &BodyHasherKey) -> Option<&BodyHashResult> {
        self.results.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util;

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

        assert_eq!(hasher.hash_chunk(b"abc \r\n"), BodyHasherStance::Interested);

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

        assert_eq!(hasher.hash_chunk(b"ab"), BodyHasherStance::Interested);
        assert_eq!(hasher.hash_chunk(b"c"), BodyHasherStance::Interested);

        // Now canonicalization adds a final CRLF, exceeding the limit 4:
        let results = hasher.finish();

        let res1 = results.get(&key1).unwrap();
        assert_eq!(res1, &Err(BodyHashError::InputTruncated));
    }

    #[test]
    fn body_hasher_hash_with_length() {
        let key1 @ (len, hash_alg, canon_alg1) = limited_key_simple(27);

        let mut hasher = BodyHasherBuilder::new(false);
        hasher.register_canonicalization(len, hash_alg, canon_alg1);
        let mut hasher = hasher.build();

        assert_eq!(hasher.hash_chunk(b"well  hello \r\n"), BodyHasherStance::Interested);
        assert_eq!(hasher.hash_chunk(b"\r\n what agi \r"), BodyHasherStance::Interested);
        assert_eq!(hasher.hash_chunk(b"\n\r\n"), BodyHasherStance::Done);

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
Hello Proff,\r\n\
\r\n\
Let\xe2\x80\x99s try this again, with line\r\n\
breaks and empty lines even.\r\n\
\r\n\
Ciao, und bis bald\r\n\
\r\n\
\r\n\
-- \r\n\
David\r\n\
";

        assert_eq!(hasher.hash_chunk(body), BodyHasherStance::Interested);

        let results = hasher.finish();

        let res1 = results.get(&key1).unwrap();
        assert_eq!(
            util::encode_base64(&res1.as_ref().unwrap().0),
            "RMSbeRTj/zCxWeWQXpEIbiqxH0Jqg5eYs4ORzOt3MT0="
        );
    }

    fn sha256_digest(msg: &[u8]) -> Box<[u8]> {
        crypto::digest(HashAlgorithm::Sha256, msg)
    }
}
