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
    crypto::{HashAlgorithm, KeyType, VerifyingKey},
    header::HeaderFields,
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
    pub status: VerifyStatus,
    pub index: usize,
    pub signature: Option<DkimSignature>,
    pub header_name: Option<Box<str>>,
    pub header_value: Option<Box<str>>,
    pub key_record: Option<Arc<DkimKeyRecord>>,
}

impl VerifyTask {
    fn failed(index: usize, error: VerificationError) -> Self {
        Self {
            status: VerifyStatus::Failed(error),
            index,
            signature: None,
            header_name: None,
            header_value: None,
            key_record: None,
        }
    }

    fn started(index: usize, sig: DkimSignature, name: Box<str>, value: Box<str>) -> Self {
        Self {
            status: VerifyStatus::InProgress,
            index,
            signature: Some(sig),
            header_name: Some(name),
            header_value: Some(value),
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
                    let error = VerificationError::DkimSignatureFormat(e);
                    tasks.push(VerifyTask::failed(index, error));
                    continue;
                }
            };

            if let Err(e) = validate_signature(&sig, config) {
                let mut task = VerifyTask::failed(index, e);
                // Also record `DkimSignature`, which we were able to parse:
                task.signature = Some(sig);
                tasks.push(task);
                continue;
            }

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
        let mut queries = Queries::spawn(&self.tasks, resolver, self.config);

        // Then, step through the query results *as they come in*, and perform
        // verification for each signature that has the corresponding
        // (domain, selector) pair.
        while let Some(result) = queries.set.join_next().await {
            let (indexes, result) = result.expect("could not await query task");

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

fn validate_signature(sig: &DkimSignature, config: &Config) -> Result<(), VerificationError> {
    for h in &config.required_signed_headers {
        if !sig.signed_headers.contains(h) {
            return Err(VerificationError::Policy(PolicyError::RequiredHeadersNotSigned));
        }
    }

    if let Some(len) = sig.body_length {
        if usize::try_from(len).is_err() {
            // signed body length too large to undergo DKIM processing on this platform
            return Err(VerificationError::Overflow);
        }
    }

    let current_t = config.current_timestamp();

    if !config.allow_expired {
        if let Some(t) = sig.expiration {
            let delta = config.time_tolerance.as_secs();
            if current_t >= t.saturating_add(delta) {
                return Err(VerificationError::Policy(PolicyError::SignatureExpired));
            }
        }
    }

    if !config.allow_timestamp_in_future {
        if let Some(t) = sig.timestamp {
            let delta = config.time_tolerance.as_secs();
            if t.saturating_sub(delta) > current_t {
                return Err(VerificationError::Policy(PolicyError::TimestampInFuture));
            }
        }
    }

    #[cfg(feature = "pre-rfc8301")]
    if !config.allow_sha1 {
        if let HashAlgorithm::Sha1 = sig.algorithm.hash_algorithm() {
            return Err(VerificationError::Policy(PolicyError::Sha1HashAlgorithm));
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
                    trace!("cannot use DNS record: {e}");
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
            trace!("no key record");
            Err(VerificationError::NoKeyFound)
        }
        Ok(txts) => Ok(txts
            .into_iter()
            .map(CachedDkimKeyRecord::Unparsed)
            .collect()),
        Err(e) => match e.kind() {
            ErrorKind::NotFound => {
                trace!("no key record");
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
    trace!("processing DKIM-Signature");

    let sig = task.signature.as_ref().unwrap();

    let cached_records = match lookup_result {
        Ok(r) => r,
        Err(e) => {
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
            &sig.domain,
            sig.identity.as_ref(),
        ) {
            task.status = VerifyStatus::Failed(e);
            task.key_record = Some(key_record.clone());
            continue;
        }

        let key_data = &key_record.key_data;

        let key = match VerifyingKey::from_key_data(key_type, key_data) {
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
        trace!("wrong public key type");
        return Err(VerificationError::WrongKeyType);
    }

    if record.key_data.is_empty() {
        trace!("key revoked");
        return Err(VerificationError::KeyRevoked);
    }

    if !record.hash_algorithms.contains(&hash_alg) {
        trace!("disallowed hash algorithm");
        return Err(VerificationError::DisallowedHashAlgorithm);
    }

    if record.flags.contains(&SelectorFlag::NoSubdomains) {
        // assumes that parsing already validated that i= domain is subdomain of d=
        // need to compare A-label form (case-normalised) strings
        if let Some(identity) = identity {
            if domain.to_ascii() != identity.domain_part.to_ascii() {
                trace!("domain mismatch");
                return Err(VerificationError::DomainMismatch);
            }
        }
    }

    Ok(())
}

fn validate_verifying_key(
    verifying_key: &VerifyingKey,
    config: &Config,
) -> Result<(), VerificationError> {
    if let Some(n) = verifying_key.key_size() {
        // Note the hard minimum key size already enforced when constructing an
        // `RsaPublicKey`.
        if n < config.min_key_bits {
            return Err(VerificationError::Policy(PolicyError::KeyTooSmall));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
