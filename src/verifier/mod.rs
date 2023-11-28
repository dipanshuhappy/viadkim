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
    crypto,
    header::{FieldName, HeaderFields},
    message_hash::{
        body_hasher_key, BodyHashError, BodyHashResults, BodyHasher, BodyHasherBuilder,
        BodyHasherStance,
    },
    record::{DkimKeyRecord, DkimKeyRecordError},
    signature::{DkimSignature, DkimSignatureError, DkimSignatureErrorKind},
    util::CanonicalStr,
    verifier::header::{HeaderVerifier, VerifyStatus},
};
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::trace;

/// Configuration for a verifier.
///
/// The configuration settings to do with verification policy map to a
/// [`PolicyError`] variant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    /// The maximum duration of public key record lookups. When this duration is
    /// exceeded evaluation fails with a temporary error.
    ///
    /// The default is 10 seconds.
    pub lookup_timeout: Duration,

    /// Only validate at most this number of signatures, any extra signatures
    /// are ignored. Signatures are selected starting at the top of the header.
    ///
    /// The default is 10.
    pub max_signatures: usize,

    /// If any of the given header names is not included in a DKIM signature’s
    /// *h=* tag, the signature will not validate. Note that the header *From*
    /// is always required to be included by RFC 6376 independent of this
    /// configuration setting.
    ///
    /// By default, no additional headers are required to be included in a
    /// signature.
    pub headers_required_in_signature: Vec<FieldName>,

    /// If any of the given header names appears in the message header, but not
    /// all occurrences of like-named headers are included in the DKIM
    /// signature, then the signature will not validate.
    ///
    /// The default includes the *From* header. (This default setting renders
    /// the attack in RFC 6376, section 8.15 ineffective, as an added *From*
    /// header would invalidate the signature. In other words it makes the
    /// common ‘oversigning’ mitigation applied to the *From* header
    /// unnecessary.)
    pub headers_forbidden_to_be_unsigned: Vec<FieldName>,

    /// Minimum acceptable key size in bits. This limit is applied to keys that
    /// provide a key size in
    /// [`VerifyingKey::key_size`][crate::crypto::VerifyingKey::key_size]
    /// (currently RSA keys only). When the key size of a verifying key is below
    /// this value, the signature will not validate.
    ///
    /// Note that there is a compile-time hard lower bound of acceptable key
    /// sizes, which will lead to failure to validate independent of this
    /// setting. By default, the absolute minimum key size is 1024; if feature
    /// `pre-rfc8301` is enabled, the absolute minimum key size is 512.
    ///
    /// The default is 1024 bits.
    pub min_key_bits: usize,

    /// When this flag is set, signatures using the SHA-1 hash algorithm are
    /// acceptable.
    ///
    /// Note that the SHA-1 hash algorithm is only available when feature
    /// `pre-rfc8301` is enabled. This setting is only effective when that
    /// feature is enabled.
    ///
    /// The default is false.
    pub allow_sha1: bool,

    /// If a DKIM signature has the *l=* tag, and the body length given in this
    /// tag is less than the actual message body length, the signature will not
    /// validate. In other words, signatures that cover only part of the message
    /// body are not accepted.
    ///
    /// The default is false.
    pub forbid_unsigned_content: bool,

    /// When this flag is set, an expired DKIM signature (*x=*) is acceptable.
    ///
    /// The default is false.
    pub allow_expired: bool,

    /// When this flag is set, a DKIM signature with a timestamp in the future
    /// (*t=*) is acceptable.
    ///
    /// The default is false.
    pub allow_timestamp_in_future: bool,

    /// Tolerance applied to time values when checking signature expiration or
    /// timestamp validity, to allow for clock drift. Resolution is in seconds.
    ///
    /// The default is 5 minutes.
    pub time_tolerance: Duration,

    /// The `SystemTime` value to use as the instant ‘now’. If `None`, the value
    /// of `SystemTime::now()` is used for the instant ‘now’.
    ///
    /// The default is `None`.
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
            headers_required_in_signature: vec![],
            headers_forbidden_to_be_unsigned: vec![FieldName::new("From").unwrap()],
            min_key_bits: 1024,
            allow_sha1: false,
            forbid_unsigned_content: false,
            allow_expired: false,
            allow_timestamp_in_future: false,
            time_tolerance: Duration::from_secs(5 * 60),
            fixed_system_time: None,
        }
    }
}

/// A verification result arrived at for some DKIM signature header.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct VerificationResult {
    /// The verification status.
    pub status: VerificationStatus,
    /// The index of the evaluated *DKIM-Signature* header in the original
    /// `HeaderFields` input. This value is unique among the
    /// `VerificationResult`s returned by a call to [`Verifier::finish`].
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
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum VerificationStatus {
    /// A *SUCCESS* result status.
    Success,
    /// A *PERMFAIL* or *TEMPFAIL* result status, with failure cause attached.
    Failure(VerificationError),
}

impl VerificationStatus {
    /// Converts this verification status to an RFC 8601 DKIM result.
    pub fn to_dkim_result(&self) -> DkimResult {
        use VerificationError::*;

        match self {
            Self::Success => DkimResult::Pass,
            Self::Failure(error) => match error {
                DkimSignatureFormat(error) => match error.kind {
                    DkimSignatureErrorKind::Utf8Encoding
                    | DkimSignatureErrorKind::TagListFormat
                    | DkimSignatureErrorKind::IncompatibleVersion
                    | DkimSignatureErrorKind::UnsupportedAlgorithm
                    | DkimSignatureErrorKind::InvalidBase64
                    | DkimSignatureErrorKind::UnsupportedCanonicalization
                    | DkimSignatureErrorKind::InvalidDomain
                    | DkimSignatureErrorKind::InvalidSignedHeaderName
                    | DkimSignatureErrorKind::InvalidIdentity
                    | DkimSignatureErrorKind::InvalidBodyLength
                    | DkimSignatureErrorKind::InvalidQueryMethod
                    | DkimSignatureErrorKind::NoSupportedQueryMethods
                    | DkimSignatureErrorKind::InvalidSelector
                    | DkimSignatureErrorKind::InvalidTimestamp
                    | DkimSignatureErrorKind::InvalidExpiration
                    | DkimSignatureErrorKind::InvalidCopiedHeaderField => DkimResult::Neutral,
                    DkimSignatureErrorKind::HistoricAlgorithm
                    | DkimSignatureErrorKind::EmptySignatureTag
                    | DkimSignatureErrorKind::EmptyBodyHashTag
                    | DkimSignatureErrorKind::EmptySignedHeadersTag
                    | DkimSignatureErrorKind::FromHeaderNotSigned
                    | DkimSignatureErrorKind::MissingVersionTag
                    | DkimSignatureErrorKind::MissingAlgorithmTag
                    | DkimSignatureErrorKind::MissingSignatureTag
                    | DkimSignatureErrorKind::MissingBodyHashTag
                    | DkimSignatureErrorKind::MissingDomainTag
                    | DkimSignatureErrorKind::MissingSignedHeadersTag
                    | DkimSignatureErrorKind::MissingSelectorTag
                    | DkimSignatureErrorKind::DomainMismatch
                    | DkimSignatureErrorKind::ExpirationNotAfterTimestamp => DkimResult::Permerror,
                },
                Overflow => DkimResult::Neutral,
                NoKeyFound
                | InvalidKeyDomain
                | WrongKeyType
                | KeyRevoked
                | DisallowedHashAlgorithm
                | DomainMismatch
                | InsufficientContent => DkimResult::Permerror,
                Timeout | KeyLookup => DkimResult::Temperror,
                KeyRecordFormat(error) => match error {
                    DkimKeyRecordError::RecordFormat
                    | DkimKeyRecordError::TagListFormat
                    | DkimKeyRecordError::IncompatibleVersion
                    | DkimKeyRecordError::InvalidHashAlgorithm
                    | DkimKeyRecordError::NoSupportedHashAlgorithms
                    | DkimKeyRecordError::UnsupportedKeyType
                    | DkimKeyRecordError::InvalidQuotedPrintable
                    | DkimKeyRecordError::InvalidBase64
                    | DkimKeyRecordError::InvalidServiceType
                    | DkimKeyRecordError::NoSupportedServiceTypes
                    | DkimKeyRecordError::InvalidFlag => DkimResult::Neutral,
                    DkimKeyRecordError::MisplacedVersionTag
                    | DkimKeyRecordError::MissingKeyTag => DkimResult::Permerror,
                },
                VerificationFailure(error) => match error {
                    crypto::VerificationError::InvalidKey
                    | crypto::VerificationError::InsufficientKeySize => DkimResult::Permerror,
                    crypto::VerificationError::VerificationFailure => DkimResult::Fail,
                },
                BodyHashMismatch => DkimResult::Fail,
                Policy(_) => DkimResult::Policy,
            },
        }
    }
}

/// An error that occurs due to a policy violation.
///
/// All policy errors can be disabled via [`Config`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PolicyError {
    /// A header required to be signed is not included in the signature.
    ///
    /// Configurable through [`Config::headers_required_in_signature`].
    RequiredHeaderNotSigned,

    /// Not all instances of a particular header name included in the signature
    /// are signed.
    ///
    /// Configurable through [`Config::headers_forbidden_to_be_unsigned`].
    UnsignedHeaderOccurrence,

    /// A signature using the *l=* tag covered only part of the message body.
    ///
    /// Configurable through [`Config::forbid_unsigned_content`].
    UnsignedContent,

    /// Signature is expired.
    ///
    /// Configurable through [`Config::allow_expired`].
    SignatureExpired,

    /// A signature’s timestamp is in the future.
    ///
    /// Configurable through [`Config::allow_timestamp_in_future`].
    TimestampInFuture,

    /// Signature algorithm using SHA-1 hash algorithm.
    ///
    /// Configurable through [`Config::allow_sha1`].
    Sha1HashAlgorithm,

    /// Public key of smaller than acceptable key size.
    ///
    /// Configurable through [`Config::min_key_bits`].
    KeyTooSmall,
}

impl Display for PolicyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequiredHeaderNotSigned => write!(f, "required header not signed"),
            Self::UnsignedHeaderOccurrence => write!(f, "unsigned occurrence of signed header"),
            Self::UnsignedContent => write!(f, "unsigned content in message body"),
            Self::SignatureExpired => write!(f, "signature expired"),
            Self::TimestampInFuture => write!(f, "timestamp in future"),
            Self::Sha1HashAlgorithm => write!(f, "SHA-1 hash algorithm not acceptable"),
            Self::KeyTooSmall => write!(f, "public key too small"),
        }
    }
}

impl Error for PolicyError {}

/// An error that occurs when performing verification.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum VerificationError {
    DkimSignatureFormat(DkimSignatureError),
    Overflow,
    NoKeyFound,
    InvalidKeyDomain,
    Timeout,
    KeyLookup,
    KeyRecordFormat(DkimKeyRecordError),
    WrongKeyType,
    KeyRevoked,
    DisallowedHashAlgorithm,
    DomainMismatch,
    VerificationFailure(crypto::VerificationError),
    InsufficientContent,
    BodyHashMismatch,
    Policy(PolicyError),
}

impl Display for VerificationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::DkimSignatureFormat(_) => write!(f, "unusable DKIM signature header"),
            Self::Overflow => write!(f, "integer too large"),
            Self::NoKeyFound => write!(f, "no key record found"),
            Self::InvalidKeyDomain => write!(f, "invalid key record domain name"),
            Self::Timeout => write!(f, "key record lookup timed out"),
            Self::KeyLookup => write!(f, "key record lookup failed"),
            Self::KeyRecordFormat(_) => write!(f, "unusable public key record"),
            Self::WrongKeyType => write!(f, "wrong key type in key record"),
            Self::KeyRevoked => write!(f, "key revoked"),
            Self::DisallowedHashAlgorithm => write!(f, "hash algorithm disallowed in key record"),
            Self::DomainMismatch => write!(f, "domain mismatch"),
            Self::VerificationFailure(_) => write!(f, "signature verification failed"),
            Self::InsufficientContent => write!(f, "not enough message body content"),
            Self::BodyHashMismatch => write!(f, "body hash did not verify"),
            Self::Policy(_) => write!(f, "local policy violation"),
        }
    }
}

impl Error for VerificationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Overflow
            | Self::NoKeyFound
            | Self::InvalidKeyDomain
            | Self::Timeout
            | Self::KeyLookup
            | Self::WrongKeyType
            | Self::KeyRevoked
            | Self::DisallowedHashAlgorithm
            | Self::DomainMismatch
            | Self::InsufficientContent
            | Self::BodyHashMismatch => None,
            Self::DkimSignatureFormat(error) => Some(error),
            Self::KeyRecordFormat(error) => Some(error),
            Self::VerificationFailure(error) => Some(error),
            Self::Policy(error) => Some(error),
        }
    }
}

/// An RFC 8601 DKIM result.
///
/// The mapping of an RFC 6376 *SUCCESS*, *PERMFAIL*, or *TEMPFAIL* result to an
/// [RFC 8601] DKIM result is not well defined. Our interpretation of each
/// result is given in detail below.
///
/// As a general rule, of the error results `Neutral` is the early bail-out
/// error result, which signals that verification didn’t proceed past a basic
/// attempt at parsing a DKIM signature (or DKIM public key record), while
/// `Fail`, `Policy`, `Temperror`, and `Permerror` are error results that are
/// used for more concrete problems concerning a well-understood DKIM signature
/// (or DKIM public key record).
///
/// [RFC 8601]: https://www.rfc-editor.org/rfc/rfc8601
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum DkimResult {
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
    /// could not be performed due to a temporary reason. Retrying evaluation
    /// might produce a different, definitive result.
    ///
    /// Examples include: DNS lookup timeout.
    Temperror,

    /// The *permerror* result. This result means that a DKIM signature was
    /// determined to be definitely broken or not verifiable. The problem with
    /// the signature is understood, is permanent, and the signature must be
    /// rejected (by this and any other implementation).
    ///
    /// Examples include: missing required tag in signature, missing public key
    /// record in DNS, *l=* tag larger than message body length.
    Permerror,
}

impl CanonicalStr for DkimResult {
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

impl Display for DkimResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.canonical_str())
    }
}

impl fmt::Debug for DkimResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
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
/// let header =
///     "DKIM-Signature: v=1; d=example.com; s=selector; a=ed25519-sha256; c=relaxed;\r\n\
///     \tt=1687435395; x=1687867395; h=Date:Subject:To:From; bh=1zGfaauQ3vmMhm21CGMC23\r\n\
///     \taJE1JrOoKsgT/wvw9owzE=; b=neMHc/e6jrqSscL1pc/fTxOU/CjuvYzvnGbTABQvYkzlIvazqp3\r\n\
///     \tiR7RXUZi0CbOAq13IEUZPc6S0/63cfAO4CA==\r\n\
///     Received: from submit.example.com by mail.example.com\r\n\
///     \twith ESMTPSA id A6DE7475; Thu, 22 Jun 2023 14:03:14 +0200\r\n\
///     From: me@example.com\r\n\
///     To: you@example.org\r\n\
///     Subject: Re: Thursday 8pm\r\n\
///     Date: Thu, 22 Jun 2023 14:03:12 +0200\r\n".parse()?;
/// let body = b"Hey,\r\n\
///     \r\n\
///     Ready for tonight? ;)\r\n";
///
/// // Note: Enable Cargo feature `hickory-resolver` to make an implementation
/// // of trait `LookupTxt` available for Hickory DNS’s `TokioAsyncResolver`.
/// let resolver /* = TokioAsyncResolver::tokio(...) */;
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
/// assert_eq!(signature.status.to_dkim_result(), DkimResult::Pass);
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
    /// message. Returns a verifier for all signatures in the given header, or
    /// `None` if the header contains no signatures.
    ///
    /// The `resolver` parameter is a reference to a type that implements
    /// [`LookupTxt`]; the trait `LookupTxt` is an abstraction for DNS
    /// resolution. The parameter is also `Clone`, in order to share the
    /// resolver among concurrent key record lookup tasks.
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
        let mut body_hasher = BodyHasherBuilder::new(config.forbid_unsigned_content);

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
        let body_hash_results = self.body_hasher.finish();

        let mut result = vec![];

        for task in self.tasks {
            // To obtain the final VerificationStatus, those tasks that did
            // verify successfully, now must have their body hashes verify, too.
            let final_status = match task.status {
                VerificationStatus::Success => {
                    let sig = task.signature.as_ref()
                        .expect("successful verification missing signature");
                    verify_body_hash(sig, &body_hash_results)
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

fn verify_body_hash(
    sig: &DkimSignature,
    body_hash_results: &BodyHashResults,
) -> VerificationStatus {
    trace!(domain = %sig.domain, selector = %sig.selector, "checking body hash for signature");

    let key = body_hasher_key(sig);

    let body_hash_result = body_hash_results.get(&key)
        .expect("requested body hash result not available");

    match body_hash_result {
        Ok((h, _)) => {
            if h == &sig.body_hash {
                trace!("body hash matched");
                VerificationStatus::Success
            } else {
                trace!("body hash did not match");
                VerificationStatus::Failure(VerificationError::BodyHashMismatch)
            }
        }
        Err(BodyHashError::InsufficientInput) => {
            trace!("insufficient message body content for body hash");
            VerificationStatus::Failure(VerificationError::InsufficientContent)
        }
        Err(BodyHashError::InputTruncated) => {
            trace!("unsigned content in message body not allowed due to local policy");
            VerificationStatus::Failure(VerificationError::Policy(PolicyError::UnsignedContent))
        }
    }
}
