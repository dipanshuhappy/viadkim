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

use crate::{
    crypto::{self, HashAlgorithm, KeyType, VerifyingKey},
    header::{FieldName, HeaderField, HeaderFields},
    record::{DkimKeyRecord, DkimKeyRecordError, SelectorFlag},
    signature::{
        DkimSignature, DkimSignatureError, DkimSignatureErrorKind, DomainName, Identity,
        DKIM_SIGNATURE_NAME,
    },
    verifier::{
        query::{Queries, QueryResult},
        verify, Config, LookupTxt, PolicyError, VerificationError,
    },
};
use std::{
    io::{self, ErrorKind},
    str::{self, FromStr},
    sync::Arc,
};
use tracing::trace;

/// Progress of a signature verification task. Each verification starts with
/// `InProgress` and must at the end be either `Failed` or `Successful`.
#[derive(Debug, PartialEq)]
pub enum VerifyStatus {
    InProgress,
    Failed(VerificationError),
    Successful,
}

#[derive(Debug, PartialEq)]
pub struct VerifyTask {
    header_name: Option<Box<str>>,
    header_value: Option<Box<str>>,

    pub status: VerifyStatus,
    pub index: usize,
    pub signature: Option<DkimSignature>,
    pub key_record: Option<Arc<DkimKeyRecord>>,
}

impl VerifyTask {
    fn failed(index: usize, error: VerificationError) -> Self {
        Self {
            header_name: None,
            header_value: None,
            status: VerifyStatus::Failed(error),
            index,
            signature: None,
            key_record: None,
        }
    }

    fn started(index: usize, sig: DkimSignature, name: Box<str>, value: Box<str>) -> Self {
        Self {
            header_name: Some(name),
            header_value: Some(value),
            status: VerifyStatus::InProgress,
            index,
            signature: Some(sig),
            key_record: None,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct HeaderVerifier<'a, 'b> {
    headers: &'a HeaderFields,
    config: &'b Config,
    tasks: Vec<VerifyTask>,
}

impl<'a, 'b> HeaderVerifier<'a, 'b> {
    pub fn find_signatures(headers: &'a HeaderFields, config: &'b Config) -> Option<Self> {
        let mut tasks = vec![];

        let dkim_headers = headers
            .as_ref()
            .iter()
            .enumerate()
            .filter(|(_, (name, _))| *name == DKIM_SIGNATURE_NAME)
            .take(config.max_signatures);

        for (index, (name, value)) in dkim_headers {
            let value = match str::from_utf8(value.as_ref()) {
                Ok(s) => s,
                Err(_) => {
                    trace!(index, "invalid UTF-8 in DKIM-Signature header");
                    let error = VerificationError::DkimSignatureFormat(DkimSignatureError::new(
                        DkimSignatureErrorKind::Utf8Encoding,
                    ));
                    tasks.push(VerifyTask::failed(index, error));
                    continue;
                }
            };

            let sig = match DkimSignature::from_str(value) {
                Ok(sig) => sig,
                Err(e) => {
                    trace!(index, "failed to parse DKIM-Signature header");
                    let error = VerificationError::DkimSignatureFormat(e);
                    tasks.push(VerifyTask::failed(index, error));
                    continue;
                }
            };

            if let Err(e) = validate_signature(&sig, index, headers, config) {
                let mut task = VerifyTask::failed(index, e);
                // Also record `DkimSignature`, which we were able to parse:
                task.signature = Some(sig);
                tasks.push(task);
                continue;
            }

            trace!(index, "found DKIM-Signature header");
            let task = VerifyTask::started(index, sig, name.as_ref().into(), value.into());

            tasks.push(task);
        }

        if tasks.is_empty() {
            None
        } else {
            Some(Self { headers, config, tasks })
        }
    }

    pub async fn verify_all<T>(mut self, resolver: &T) -> Vec<VerifyTask>
    where
        T: LookupTxt + Clone + 'static,
    {
        // First, spawn off the DNS queries for the still in-progress tasks.
        let mut queries = Queries::spawn(&self.tasks, resolver, self.config).await;
        
        // Then, step through the query results *as they come in*, and perform
        // verification for each signature that has the corresponding
        // (domain, selector) pair.

        for  raw_result in queries.set.into_iter() {
            
            let (indexes, result) = raw_result;


            

            let mut records = map_lookup_result_to_key_records(result);

            // This repeated linear search is acceptable as there is always a
            // limited number of signatures/tasks to process.
            let selected_tasks = self.tasks.iter_mut().filter(|t| indexes.contains(&t.index));

            for task in selected_tasks {
                verify_task(task, self.headers, self.config, &mut records);
            }
        }

        self.tasks
    }
}

fn validate_signature(
    sig: &DkimSignature,
    index: usize,
    headers: &HeaderFields,
    config: &Config,
) -> Result<(), VerificationError> {
    validate_signed_headers(
        index,
        headers.as_ref(),
        &config.headers_required_in_signature,
        &config.headers_forbidden_to_be_unsigned,
        &sig.signed_headers,
    )?;

    if let Some(len) = sig.body_length {
        if usize::try_from(len).is_err() {
            trace!(index, "body length declared in DKIM-Signature too large");
            return Err(VerificationError::Overflow);
        }
    }

    let current_t = config.current_timestamp();

    if !config.allow_expired {
        if let Some(t) = sig.expiration {
            let delta = config.time_tolerance.as_secs();
            if current_t >= t.saturating_add(delta) {
                trace!(index, "DKIM-Signature has expired");
                return Err(VerificationError::Policy(PolicyError::SignatureExpired));
            }
        }
    }

    if !config.allow_timestamp_in_future {
        if let Some(t) = sig.timestamp {
            let delta = config.time_tolerance.as_secs();
            if t.saturating_sub(delta) > current_t {
                trace!(index, "DKIM-Signature has timestamp in future");
                return Err(VerificationError::Policy(PolicyError::TimestampInFuture));
            }
        }
    }

    #[cfg(feature = "pre-rfc8301")]
    if !config.allow_sha1 {
        if let HashAlgorithm::Sha1 = sig.algorithm.hash_algorithm() {
            trace!(index, "DKIM-Signature uses unacceptable SHA-1 hash algorithm");
            return Err(VerificationError::Policy(PolicyError::Sha1HashAlgorithm));
        }
    }

    Ok(())
}

fn validate_signed_headers(
    index: usize,
    headers: &[HeaderField],
    headers_required_in_signature: &[FieldName],
    headers_forbidden_to_be_unsigned: &[FieldName],
    signed_headers: &[FieldName],
) -> Result<(), VerificationError> {
    for h in headers_required_in_signature {
        if !signed_headers.contains(h) {
            trace!(index, "required header not included in DKIM-Signature");
            return Err(VerificationError::Policy(PolicyError::RequiredHeaderNotSigned));
        }
    }

    for req in headers_forbidden_to_be_unsigned {
        let actual_n = headers.iter().filter(|(name, _)| name == req).count();
        let signed_n = signed_headers
            .iter()
            .filter(|&name| name == req)
            .take(actual_n)
            .count();

        if signed_n < actual_n {
            trace!(index, "unsigned occurrence of required header in DKIM-Signature");
            return Err(VerificationError::Policy(PolicyError::UnsignedHeaderOccurrence));
        }
    }

    Ok(())
}

// This enum ensures that we parse a `DkimKeyRecord` from an
// `io::Result<String>` at most once, even if used by multiple signatures.
enum CachedDkimKeyRecord {
    Unparsed(io::Result<String>),
    Parsed(Result<Arc<DkimKeyRecord>, DkimKeyRecordError>),
}

impl CachedDkimKeyRecord {
    fn parse_and_cache(&mut self) -> &Result<Arc<DkimKeyRecord>, DkimKeyRecordError> {
        if let Self::Unparsed(s) = self {
            let r = match s {
                Ok(s) => DkimKeyRecord::from_str(s),
                Err(e) => {
                    // The per-record I/O error is mapped to an opaque
                    // `DkimKeyRecordError` variant, details are only exposed in
                    // the trace log.
                    trace!("cannot use DNS TXT record: {e}");
                    Err(DkimKeyRecordError::RecordFormat)
                }
            };
            *self = Self::Parsed(r.map(Arc::new));
        }

        match self {
            Self::Unparsed(_) => unreachable!(),
            Self::Parsed(r) => &*r,
        }
    }
}

fn map_lookup_result_to_key_records(
    lookup_result: QueryResult,
) -> Result<Vec<CachedDkimKeyRecord>, VerificationError> {
    match lookup_result {
        Ok(txts) if txts.is_empty() => {
            trace!("query found no key records");
            Err(VerificationError::NoKeyFound)
        }
        Ok(txts) => {
            let records = txts
                .into_iter()
                .map(CachedDkimKeyRecord::Unparsed)
                .collect();
            Ok(records)
        }
        Err(e) => match e.kind() {
            ErrorKind::NotFound => {
                trace!("query found no key records");
                Err(VerificationError::NoKeyFound)
            }
            ErrorKind::InvalidInput => {
                trace!("invalid key record domain name");
                Err(VerificationError::InvalidKeyDomain)
            }
            ErrorKind::TimedOut => {
                trace!("key record lookup timed out");
                Err(VerificationError::Timeout)
            }
            _ => {
                // Other I/O errors are mapped to `VerifierError::KeyLookup`,
                // further details are only exposed in the trace log.
                trace!("could not look up key record: {e}");
                Err(VerificationError::KeyLookup)
            }
        },
    }
}

fn verify_task(
    task: &mut VerifyTask,
    headers: &HeaderFields,
    config: &Config,
    lookup_result: &mut Result<Vec<CachedDkimKeyRecord>, VerificationError>,
) {
    let sig = task.signature.as_ref().unwrap();

    let domain = &sig.domain;
    let selector = &sig.selector;

    trace!(%domain, %selector, "processing DKIM-Signature");

    let cached_records = match lookup_result {
        Ok(r) => r,
        Err(e) => {
            trace!("cannot evaluate signature without lookup result");
            task.status = VerifyStatus::Failed(e.clone());
            return;
        }
    };

    let (key_type, hash_alg) = sig.algorithm.into();

    assert!(!cached_records.is_empty());

    let key_records = cached_records.iter_mut().map(|r| r.parse_and_cache());

    // Step through all (usually only one, but more possible) key records. If we
    // can successfully complete verification with one record, then that will be
    // the result; else the last failing record will be reported.

    for (i, key_record) in key_records.enumerate() {
        trace!("trying verification using DKIM key record {}", i + 1);

        let key_record = match key_record {
            Ok(key_record) => key_record,
            Err(e) => {
                trace!("unusable DKIM public key record: {e}");
                task.status = VerifyStatus::Failed(VerificationError::KeyRecordFormat(*e));
                task.key_record = None;
                continue;
            }
        };

        if let Err(e) = validate_key_record(
            key_type,
            hash_alg,
            key_record,
            domain,
            sig.identity.as_ref(),
        ) {
            task.status = VerifyStatus::Failed(e);
            task.key_record = Some(key_record.clone());
            continue;
        }

        let key_data = &key_record.key_data;

        let key = match read_verifying_key(key_type, key_data) {
            Ok(k) => k,
            Err(e) => {
                task.status = VerifyStatus::Failed(VerificationError::VerificationFailure(e));
                task.key_record = Some(key_record.clone());
                continue;
            }
        };

        if let Err(e) = validate_verifying_key(&key, config) {
            task.status = VerifyStatus::Failed(e);
            task.key_record = Some(key_record.clone());
            continue;
        }

        task.key_record = Some(key_record.clone());

        let name = task.header_name.as_ref().unwrap();
        let value = task.header_value.as_ref().unwrap();

        match verify::perform_verification(headers, &key, sig, name, value) {
            Ok(()) => {
                task.status = VerifyStatus::Successful;
                break;
            }
            Err(e) => {
                task.status = VerifyStatus::Failed(e);
            }
        }
    }
}

fn validate_key_record(
    key_type: KeyType,
    hash_alg: HashAlgorithm,
    record: &DkimKeyRecord,
    domain: &DomainName,
    identity: Option<&Identity>,
) -> Result<(), VerificationError> {
    if record.key_type != key_type {
        trace!("wrong key type in public key record");
        return Err(VerificationError::WrongKeyType);
    }

    if record.key_data.is_empty() {
        trace!("key in public key record is revoked");
        return Err(VerificationError::KeyRevoked);
    }

    if !record.hash_algorithms.contains(&hash_alg) {
        trace!("hash algorithm not allowed by public key record");
        return Err(VerificationError::DisallowedHashAlgorithm);
    }

    if record.flags.contains(&SelectorFlag::NoSubdomains) {
        if let Some(identity) = identity {
            // Parsing of the DKIM signature already ensures that *i=* domain is
            // subdomain of *d=*, can now compare normalised (lowercase) A-label
            // form directly.
            if domain.to_ascii() != identity.domain.to_ascii() {
                trace!("i= and d= domains not allowed to differ by public key record");
                return Err(VerificationError::DomainMismatch);
            }
        }
    }

    Ok(())
}

fn read_verifying_key(
    key_type: KeyType,
    key_data: &[u8],
) -> Result<VerifyingKey, crypto::VerificationError> {
    let key = match VerifyingKey::from_key_data(key_type, key_data) {
        Ok(k) => k,
        Err(e) => {
            trace!("unusable key data in public key record: {e}");
            return Err(crypto::VerificationError::InvalidKey);
        }
    };

    if let Err(e) = key.validate_min_key_size() {
        trace!("public key too small for DKIM verification");
        return Err(e);
    }

    Ok(key)
}

fn validate_verifying_key(
    verifying_key: &VerifyingKey,
    config: &Config,
) -> Result<(), VerificationError> {
    if let Some(n) = verifying_key.key_size() {
        if n < config.min_key_bits {
            trace!("public key size not acceptable due to local policy");
            return Err(VerificationError::Policy(PolicyError::KeyTooSmall));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::FieldBody;

    #[test]
    fn header_verifier_find_signatures_empty() {
        let headers = "From: me\nTo: you\n".parse().unwrap();
        let config = Default::default();

        let verifier = HeaderVerifier::find_signatures(&headers, &config);

        assert_eq!(verifier, None);
    }

    #[test]
    fn header_verifier_find_signatures_ok() {
        let headers = "\
a: aaa
dkim-signature: broken~~
b: bb
dkim-signature: v=1; d=example.com; s=sel; a=rsa-sha256;
  h=From:To; bh=YWJjCg==; b=ZGVmCg==;
dkim-signature: v=1; d=example.com; s=sel; a=rsa-sha256;
  h=From:To; i=@example.org; bh=YWJjCg==; b=ZGVmCg==;
c: ccc cc
dkim-signature: v=2; d=example.com; s=sel; x=y
"
        .parse()
        .unwrap();

        let config = Config {
            max_signatures: 3,
            ..Default::default()
        };

        let tasks = HeaderVerifier::find_signatures(&headers, &config)
            .unwrap()
            .tasks;

        assert_eq!(tasks.len(), 3);

        let mut iter = tasks.into_iter();

        assert!(matches!(iter.next().unwrap().status, VerifyStatus::Failed(_)));
        assert!(matches!(iter.next().unwrap().status, VerifyStatus::InProgress));
        assert!(matches!(iter.next().unwrap().status, VerifyStatus::Failed(_)));
    }

    #[test]
    fn validate_signed_headers_ok() {
        let header = header_fields(["a", "b", "a", "c"]);

        let required = field_names([]);
        let exhaustive = field_names(["a", "d"]);

        let signed = field_names(["a", "b", "a", "a"]);
        assert_eq!(validate_signed_headers(0, &header, &required, &exhaustive, &signed), Ok(()));

        let signed = field_names(["a", "b", "a"]);
        assert_eq!(validate_signed_headers(0, &header, &required, &exhaustive, &signed), Ok(()));

        let signed = field_names(["a", "b"]);
        assert_eq!(
            validate_signed_headers(0, &header, &required, &exhaustive, &signed),
            Err(VerificationError::Policy(
                PolicyError::UnsignedHeaderOccurrence
            ))
        );
    }

    fn header_fields(names: impl IntoIterator<Item = &'static str>) -> Vec<HeaderField> {
        names.into_iter()
            .map(|name| (FieldName::new(name).unwrap(), FieldBody::new(*b"").unwrap()))
            .collect()
    }

    fn field_names(names: impl IntoIterator<Item = &'static str>) -> Vec<FieldName> {
        names.into_iter()
            .map(|name| FieldName::new(name).unwrap())
            .collect()
    }
}
