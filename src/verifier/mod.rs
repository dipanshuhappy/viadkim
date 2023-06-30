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

//! Verifier and supporting types.

mod header;
mod lookup;
mod query;
mod verify;

pub use lookup::LookupTxt;

use crate::{
    crypto::VerificationError,
    header::{FieldName, HeaderFields},
    message_hash::{
        body_hasher_key, BodyHasher, BodyHasherBuilder, BodyHasherError, BodyHasherResults,
        BodyHasherStance,
    },
    record::DkimKeyRecord,
    signature::{DkimSignature, DkimSignatureError, DkimSignatureErrorKind},
    util::{self, CanonicalStr},
    verifier::header::{HeaderVerifier, VerifyStatus},
};
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::trace;

/// Configuration for a verifier process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    /// The maximum duration of public key record lookups. When this duration is
    /// exceeded evaluation fails (temporary error).
    pub lookup_timeout: Duration,

    /// Only validate at most this number of signatures, any extra signatures
    /// are ignored.
    pub max_signatures: usize,

    /// If given required headers are not signed in a DKIM signature, the
    /// signature will not validate. Note that the header `From` is always
    /// required by the RFC independent of this configuration setting.
    pub required_signed_headers: Vec<FieldName>,

    /// Minimum acceptable key size in bits. When the key size of an RSA public
    /// key is below this limit, the signature will not validate.
    ///
    /// Note that there is a compile-time hard lower bound of acceptable key
    /// sizes, which will lead to failure to validate independent of this
    /// setting. By default, the minimum key size is 1024; if feature
    /// `pre-rfc8301` is enabled, the minimum key size is 512.
    pub min_key_bits: usize,

    /// When this flag is set, signatures using the SHA-1 hash algorithm are
    /// acceptable.
    ///
    /// Note that the SHA-1 hash algorithm is only available when feature
    /// `pre-rfc8301` is enabled. This setting is only effective when that
    /// feature is enabled.
    pub allow_sha1: bool,

    /// If a DKIM signature has the l= tag, and the body length given in this
    /// tag is less than the actual message body length, the signature will not
    /// validate. In other words, signatures that cover only part of the message
    /// body are not accepted.
    pub forbid_partially_signed_body: bool,

    /// When this flag is set, an expired DKIM signature (x=) will not validate.
    pub fail_if_expired: bool,

    /// When this flag is set, a DKIM signature with a timestamp in the future
    /// (t=) will not validate.
    pub fail_if_in_future: bool,

    /// Tolerance applied to time values when checking signature expiration or
    /// timestamp validity, to allow for clock drift. Resolution is in seconds.
    pub time_tolerance: Duration,

    /// The `SystemTime` value to use as the instant ‘now’.
    pub fixed_system_time: Option<SystemTime>,
}

impl Config {
    fn current_timestamp(&self) -> u64 {
        self.fixed_system_time
            .unwrap_or_else(SystemTime::now)
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            lookup_timeout: Duration::from_secs(10),
            max_signatures: 10,
            required_signed_headers: vec![],
            min_key_bits: 1024,
            allow_sha1: false,
            forbid_partially_signed_body: false,
            fail_if_expired: true,
            fail_if_in_future: true,
            time_tolerance: Duration::from_secs(30),
            fixed_system_time: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum PolicyError {
    RequiredHeadersNotSigned,
    ForbidPartiallySignedBody,
    SignatureExpired,
    TimestampInFuture,
    DisallowedSha1Hash,
    KeyTooSmall,
}

impl Display for PolicyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequiredHeadersNotSigned => write!(f, "headers required to be signed were not signed"),
            Self::ForbidPartiallySignedBody => write!(f, "partial body signing not acceptable"),
            Self::SignatureExpired => write!(f, "signature expired"),
            Self::TimestampInFuture => write!(f, "timestamp in future"),
            Self::DisallowedSha1Hash => write!(f, "hash algorithm SHA-1 not acceptable"),
            Self::KeyTooSmall => write!(f, "public key size too small"),
        }
    }
}

impl Error for PolicyError {}

/// A verification result arrived at for some DKIM signature header.
#[derive(Debug, PartialEq)]
pub struct VerificationResult {
    /// The verification status.
    pub status: VerificationStatus,
    /// The index of the evaluated *DKIM-Signature* header in the original
    /// `HeaderFields` input.
    pub index: usize,
    /// The parsed DKIM signature data obtained from the *DKIM-Signature*
    /// header, if available.
    pub signature: Option<DkimSignature>,
    /// The parsed DKIM public key record data used in the verification, if
    /// available.
    ///
    /// The record is behind an `Arc` only so that it may be shared among the
    /// `VerificationResult`s returned by a call to [`Verifier::finish`].
    pub key_record: Option<Arc<DkimKeyRecord>>,
}

/// The verification status of an evaluated DKIM signature.
///
/// This type encodes the three DKIM output states described in RFC 6376,
/// section 3.9: `Success` corresponds to *SUCCESS*, `Failure` corresponds to
/// both *PERMFAIL* and *TEMPFAIL*.
#[derive(Debug, PartialEq)]
pub enum VerificationStatus {
    /// A *SUCCESS* result status.
    Success,
    /// A *PERMFAIL* or *TEMPFAIL* result status, with failure cause attached.
    Failure(VerifierError),
}

impl VerificationStatus {
    // TODO revisit
    /// Converts this verification status to an RFC 8601 DKIM result.
    pub fn to_dkim_auth_result(&self) -> DkimAuthResult {
        use VerifierError::*;

        match self {
            VerificationStatus::Success => DkimAuthResult::Pass,
            VerificationStatus::Failure(error) => match error {
                WrongKeyType
                | KeyRecordSyntax
                | KeyRevoked
                | DisallowedHashAlgorithm
                | DomainMismatch
                | InsufficientBodyLength
                | InvalidKeyDomain
                | NoKeyFound => DkimAuthResult::Permerror,
                BodyHashMismatch => DkimAuthResult::Fail,
                KeyLookupTimeout | KeyLookup => DkimAuthResult::Temperror,
                DkimSignatureHeaderFormat(error) => match &error.kind {
                    DkimSignatureErrorKind::MissingVersionTag
                    | DkimSignatureErrorKind::HistoricAlgorithm
                    | DkimSignatureErrorKind::MissingAlgorithmTag
                    | DkimSignatureErrorKind::MissingSignatureTag
                    | DkimSignatureErrorKind::EmptySignatureTag
                    | DkimSignatureErrorKind::MissingBodyHashTag
                    | DkimSignatureErrorKind::EmptyBodyHashTag
                    | DkimSignatureErrorKind::MissingDomainTag
                    | DkimSignatureErrorKind::SignedHeadersEmpty
                    | DkimSignatureErrorKind::FromHeaderNotSigned
                    | DkimSignatureErrorKind::MissingSignedHeadersTag
                    | DkimSignatureErrorKind::MissingSelectorTag
                    | DkimSignatureErrorKind::DomainMismatch
                    | DkimSignatureErrorKind::ExpirationNotAfterTimestamp => DkimAuthResult::Permerror,
                    DkimSignatureErrorKind::UnsupportedVersion
                    | DkimSignatureErrorKind::UnsupportedAlgorithm
                    | DkimSignatureErrorKind::UnsupportedCanonicalization
                    | DkimSignatureErrorKind::InvalidQueryMethod
                    | DkimSignatureErrorKind::QueryMethodsNotSupported
                    | DkimSignatureErrorKind::InvalidIdentity
                    | DkimSignatureErrorKind::InvalidDomain
                    | DkimSignatureErrorKind::InvalidBodyLength
                    | DkimSignatureErrorKind::InvalidSelector
                    | DkimSignatureErrorKind::InvalidTimestamp
                    | DkimSignatureErrorKind::InvalidExpiration
                    | DkimSignatureErrorKind::InvalidBase64
                    | DkimSignatureErrorKind::InvalidSignedHeaderName
                    | DkimSignatureErrorKind::InvalidCopiedHeaderField
                    | DkimSignatureErrorKind::Utf8Encoding
                    | DkimSignatureErrorKind::InvalidTagList => DkimAuthResult::Neutral,
                },
                VerificationFailure(error) => match error {
                    VerificationError::InvalidKey
                    | VerificationError::InsufficientKeySize
                    | VerificationError::InvalidSignature => DkimAuthResult::Permerror,
                    VerificationError::VerificationFailure => DkimAuthResult::Fail,
                },
                Policy(_) => DkimAuthResult::Policy,
                Overflow => DkimAuthResult::Neutral,
            },
        }
    }
}

// TODO rename, not a verifier error but a verification error (but conflicts with different VerificationError)
/// An error that occurs when using a verifier.
#[derive(Clone, Debug, PartialEq)]
pub enum VerifierError {
    DkimSignatureHeaderFormat(DkimSignatureError),  // TODO rename DkimSignatureFormat
    WrongKeyType,
    KeyRecordSyntax,  // TODO rename KeyRecordFormat
    KeyRevoked,
    DisallowedHashAlgorithm,
    DomainMismatch,
    VerificationFailure(VerificationError),
    BodyHashMismatch,
    InsufficientBodyLength,
    NoKeyFound,
    InvalidKeyDomain,
    KeyLookupTimeout,
    KeyLookup,
    Policy(PolicyError),
    Overflow,
}

impl Display for VerifierError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::DkimSignatureHeaderFormat(error) => error.kind.fmt(f),
            Self::WrongKeyType => write!(f, "wrong key type"),
            Self::KeyRecordSyntax => write!(f, "invalid syntax in key record"),
            Self::KeyRevoked => write!(f, "key in key record revoked"),
            Self::DisallowedHashAlgorithm => write!(f, "hash algorithm not allowed"),
            Self::DomainMismatch => write!(f, "domain mismatch"),
            Self::VerificationFailure(error) => error.fmt(f),
            Self::BodyHashMismatch => write!(f, "body hash mismatch"),
            Self::InsufficientBodyLength => write!(f, "truncated body"),
            Self::NoKeyFound => write!(f, "no key record found"),
            Self::InvalidKeyDomain => write!(f, "invalid key record domain name"),
            Self::KeyLookupTimeout => write!(f, "key record lookup timed out"),
            Self::KeyLookup => write!(f, "key record lookup failed"),
            Self::Policy(error) => error.fmt(f),
            Self::Overflow => write!(f, "integer size too large"),
        }
    }
}

/// An RFC 8601 DKIM result.
///
/// The mapping of an RFC 6376 *SUCCESS*, *PERMFAIL*, or *TEMPFAIL* result to an
/// RFC 8601 DKIM result is not well defined. Our interpretation of each result
/// is given in detail below.
///
/// As a general rule, of the error result kinds `Neutral` is the early bail-out
/// error type, which signals that verification didn’t proceed past a basic
/// attempt at parsing a signature, while `Fail`, `Policy`, `Temperror`, and
/// `Permerror` are error types that are used for more concrete problems
/// concerning a well-understood signature.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DkimAuthResult {
    /// The *none* result. This result indicates that a message was not signed.
    /// (Not used in this library.)
    None,

    /// The *pass* result. This result means that verification could be
    /// performed on a DKIM signature, and the verification was successful.
    Pass,

    /// The *fail* result. This result means that a DKIM signature was
    /// understood and verification could be performed, and the verification
    /// result was failure.
    ///
    /// Examples include: cryptographic verification failure, body hash
    /// mismatch.
    Fail,

    /// The *policy* result. This result means that a DKIM signature could not
    /// be or was not verified, because some aspect of it was unacceptable due
    /// to a configurable policy reason.
    ///
    /// Examples include: signature expired, configuration required a header to
    /// be signed, but it wasn’t.
    Policy,

    /// The *neutral* result. This result means that a DKIM signature could not
    /// be entirely understood or cannot be processed by this implementation
    /// (but might be by other implementations).
    ///
    /// Examples include: syntax errors, an unsupported cryptographic or other
    /// algorithm.
    Neutral,

    /// The *temperror* result. This result means that signature evaluation
    /// could not be performed due to a temporary reason that might be gone when
    /// evaluation is retried.
    ///
    /// Examples include: DNS lookup timeout, temporary I/O error.
    Temperror,

    /// The *permerror* result. This result means that a DKIM signature was
    /// determined to be definitely broken or not verifiable. The problem with
    /// the signature is understood, is permanent, and the signature must be
    /// rejected (by this and any other implementation).
    ///
    /// Examples include: missing required tag in signature, missing public key
    /// record in DNS, l= tag larger than message body length.
    Permerror,
}

impl CanonicalStr for DkimAuthResult {
    fn canonical_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Policy => "policy",
            Self::Neutral => "neutral",
            Self::Temperror => "temperror",
            Self::Permerror => "permerror",
        }
    }
}

impl Display for DkimAuthResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.canonical_str())
    }
}

struct VerifierTask {
    status: VerificationStatus,
    index: usize,
    signature: Option<DkimSignature>,
    key_record: Option<Arc<DkimKeyRecord>>,
}

/// A verifier of DKIM signatures in an email message.
///
/// `Verifier` is the high-level API for verifying a message. It implements a
/// three-phase, staged design that allows processing the message in chunks, and
/// shortcutting unnecessary body processing.
///
/// 1. **[`verify_header`][Verifier::verify_header]** (async): first, perform
///    signature verification on the message header and return a verifier that
///    carries the preliminary results; this is where most of the actual work is
///    done
/// 2. [`process_body_chunk`][Verifier::process_body_chunk]: then, any number of
///    chunks of the message body are fed to the verification process
/// 3. [`finish`][Verifier::finish]: finally, the body hashes are computed and
///    the final verification results are returned
///
/// Compare this with the similar but distinct procedure of
/// [`Signer`][crate::signer::Signer].
///
/// # Examples
///
/// The following example shows how to verify a message’s signatures using the
/// high-level API.
///
/// ```
/// # use std::{future::Future, io::{self, ErrorKind}, pin::Pin};
/// # #[derive(Clone)]
/// # struct MockLookupTxt;
/// # impl viadkim::verifier::LookupTxt for MockLookupTxt {
/// #     type Answer = Vec<io::Result<Vec<u8>>>;
/// #     type Query<'a> = Pin<Box<dyn Future<Output = io::Result<Self::Answer>> + Send + 'a>>;
/// #
/// #     fn lookup_txt(&self, domain: &str) -> Self::Query<'_> {
/// #         let domain = domain.to_owned();
/// #         Box::pin(async move {
/// #             match domain.as_str() {
/// #                 "selector._domainkey.example.com." => {
/// #                     Ok(vec![
/// #                         Ok(b"v=DKIM1; k=ed25519; p=f8IRGiRaCQ83GCI56F77ueW0l5hinwOG31ZmlSyReBk=".to_vec()),
/// #                     ])
/// #                 }
/// #                 _ => unimplemented!(),
/// #             }
/// #         })
/// #     }
/// # }
/// # tokio::runtime::Runtime::new().unwrap().block_on(async {
/// use viadkim::*;
///
/// let header = "DKIM-Signature: v=1; d=example.com; s=selector; a=ed25519-sha256;\r\n\
///     \tt=1687435395; x=1687867395; h=Date:Subject:To:From; bh=1zGfaauQ3vmMhm21CGMC23\r\n\
///     \taJE1JrOoKsgT/wvw9owzE=; b=Ny5/l088Iubyzlq56ab9Xe6/9YDcIvydie0GOI6CEsaIdktjLlA\r\n\
///     \tOvKuE7wU4203PIMx0MuW7lFLpdRIcPDl3Cg==\r\n\
///     Received: from smtp.example.com by mail.example.org\r\n\
///     \twith ESMTPS id A6DE7475; Thu, 22 Jun 2023 14:03:29 +0200\r\n\
///     From: me@example.com\r\n\
///     To: you@example.org\r\n\
///     Subject: Re: Thursday 8pm\r\n\
///     Date: Thu, 22 Jun 2023 14:03:12 +0200\r\n".parse()?;
/// let body = b"Hey,\r\n\
///     \r\n\
///     Ready for tonight? ;)\r\n";
///
/// // Note: Enable Cargo feature `trust-dns-resolver` to make an implementation
/// // of trait `LookupTxt` available for Trust-DNS’s `TokioAsyncResolver`.
/// let resolver;  // = TokioAsyncResolver::tokio(...);
/// # resolver = MockLookupTxt;
///
/// let config = Config::default();
/// # let mut config = config;
/// # config.fixed_system_time =
/// #     Some(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1687435411));
///
/// let mut verifier = Verifier::verify_header(&resolver, &header, &config)
///     .await
///     .unwrap();
///
/// let _ = verifier.process_body_chunk(body);
///
/// let results = verifier.finish();
///
/// let signature = results.into_iter().next().unwrap();
///
/// assert_eq!(signature.status, VerificationStatus::Success);
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// # }).unwrap();
/// ```
///
/// See [`Signer`][crate::signer::Signer] for how the above example message was
/// signed.
pub struct Verifier {
    tasks: Vec<VerifierTask>,
    body_hasher: BodyHasher,
}

impl Verifier {
    /// Initiates a message verification process by verifying the header of a
    /// message.
    ///
    /// Returns a verifier for all signatures in the given header, or `None` if
    /// the header contains no signatures.
    pub async fn verify_header<T>(
        resolver: &T,
        headers: &HeaderFields,
        config: &Config,
    ) -> Option<Self>
    where
        T: LookupTxt + Clone + 'static,
    {
        let verifier = HeaderVerifier::find_signatures(headers, config)?;

        let verified_tasks = verifier.verify_all(resolver).await;

        let mut tasks = vec![];
        let mut body_hasher = BodyHasherBuilder::new(config.forbid_partially_signed_body);

        for task in verified_tasks {
            let status = match task.status {
                VerifyStatus::InProgress => panic!("verification unexpectedly skipped"),
                VerifyStatus::Failed(e) => VerificationStatus::Failure(e),
                VerifyStatus::Successful => {
                    // For successfully verified signatures, register a body
                    // hasher request for verification of the body hash.
                    let sig = task.signature.as_ref().unwrap();
                    let (body_len, hash_alg, canon_alg) = body_hasher_key(sig);
                    body_hasher.register_canonicalization(body_len, hash_alg, canon_alg);

                    // Mark this task as a (preliminary) success, later body
                    // hash verification can still result in failure.
                    VerificationStatus::Success
                }
            };

            tasks.push(VerifierTask {
                status,
                index: task.index,
                signature: task.signature,
                key_record: task.key_record,
            });
        }

        let body_hasher = body_hasher.build();

        Some(Self { tasks, body_hasher })
    }

    /// Processes a chunk of the message body.
    ///
    /// Clients should pass the message body either whole or in chunks of
    /// arbitrary size to this method in order to calculate the body hash (the
    /// *bh=* tag). The returned [`BodyHasherStance`] instructs the client how
    /// to proceed if more chunks are outstanding. Note that the given body
    /// chunk is canonicalised and hashed, but not otherwise retained in memory.
    ///
    /// Remember that email message bodies generally use CRLF line endings; this
    /// is important for correct body hash calculation.
    ///
    /// # Examples
    ///
    /// ```
    /// # use viadkim::verifier::Verifier;
    /// # fn f(verifier: &mut Verifier) {
    /// let _ = verifier.process_body_chunk(b"\
    /// Hello friend!\r
    /// \r
    /// How are you?\r
    /// ");
    /// # }
    /// ```
    pub fn process_body_chunk(&mut self, chunk: &[u8]) -> BodyHasherStance {
        self.body_hasher.hash_chunk(chunk)
    }

    /// Finishes the verification process and returns the results.
    ///
    /// The returned result vector is never empty.
    pub fn finish(self) -> Vec<VerificationResult> {
        let mut result = vec![];

        let hasher_results = self.body_hasher.finish();

        for task in self.tasks {
            // To obtain the final VerificationStatus, those tasks that did
            // verify successfully, now must have their body hashes verify, too.
            let final_status = match task.status {
                VerificationStatus::Success => {
                    let sig = task.signature.as_ref()
                        .expect("successful verification missing signature");
                    verify_body_hash(sig, &hasher_results)
                }
                status @ VerificationStatus::Failure(_) => status,
            };

            result.push(VerificationResult {
                status: final_status,
                index: task.index,
                signature: task.signature,
                key_record: task.key_record,
            });
        }

        result
    }
}

fn verify_body_hash(sig: &DkimSignature, hasher_results: &BodyHasherResults) -> VerificationStatus {
    trace!("now checking body hash for signature");

    let key = body_hasher_key(sig);

    let hasher_result = hasher_results.get(&key)
        .expect("requested body hash result not available");

    match hasher_result {
        Ok((h, _)) => {
            if h != &sig.body_hash {
                trace!("body hash mismatch: {}", util::encode_base64(h));
                VerificationStatus::Failure(VerifierError::BodyHashMismatch)
            } else {
                trace!("body hash matched");
                VerificationStatus::Success
            }
        }
        Err(BodyHasherError::InsufficientInput) => {
            VerificationStatus::Failure(VerifierError::InsufficientBodyLength)
        }
        Err(BodyHasherError::InputTruncated) => {
            VerificationStatus::Failure(
                VerifierError::Policy(PolicyError::ForbidPartiallySignedBody)
            )
        }
    }
}
