use crate::{
    crypto::{HashAlgorithm, KeyType, VerifyingKey},
    header::HeaderFields,
    record::{DkimKeyRecord, DkimKeyRecordParseError, Flags, ServiceType},
    signature::{
        DkimSignature, DkimSignatureError, DkimSignatureErrorKind, DomainName, Identity,
        DKIM_SIGNATURE_NAME,
    },
    verifier::{query::Queries, verify, Config, PolicyError, VerificationStatus, VerifierError},
};
use std::{
    io::{self, ErrorKind},
    str::{self, FromStr},
};
use tracing::trace;

/*
// TODO what is a good design for this module...?
struct VerifyingTask2 {
    index: usize,
    task_type: VerifyingTaskType,
}
enum VerifyingTaskType {
    Error(ErrorTask),
    Active(ActiveTask)
}
struct ErrorTask {
    error: VerifierError,
}
struct ActiveTask {
    sig: Box<DkimSignature>,
    name: Box<str>,
    value: Box<str>,
    // later: (could be output of `verify`?)
    status: Option<VerificationStatus>,
    testing: bool,
    key_size: Option<usize>,
}
*/

pub struct VerifyingTask {
    pub index: usize,

    pub sig: Option<DkimSignature>,
    pub name: Option<Box<str>>,
    pub value: Option<Box<str>>,

    pub status: Option<VerificationStatus>,
    pub testing: bool,
    pub key_size: Option<usize>,
}

impl VerifyingTask {
    fn new_not_started(index: usize, error: VerifierError) -> Self {
        let status = VerificationStatus::Failure(error);
        Self {
            index,
            sig: None,
            name: None,
            value: None,
            status: Some(status),
            testing: false,
            key_size: None,
        }
    }

    fn new(index: usize, sig: DkimSignature, name: Box<str>, value: Box<str>) -> Self {
        Self {
            index,
            sig: Some(sig),
            name: Some(name),
            value: Some(value),
            status: None,
            testing: false,
            key_size: None,
        }
    }
}

// TODO revisit
pub struct HeaderVerifier<'a> {
    pub headers: &'a HeaderFields,
    pub tasks: Vec<VerifyingTask>,
}

impl<'a> HeaderVerifier<'a> {
    pub fn find_dkim_signatures(headers: &'a HeaderFields, config: &Config) -> Option<Self> {
        let mut tasks = vec![];

        let dkim_headers = headers
            .as_ref()
            .iter()
            .enumerate()
            .filter(|(_, (name, _))| *name == DKIM_SIGNATURE_NAME)
            .take(config.max_signatures);

        'outer:
        for (idx, (name, value)) in dkim_headers {
            // at this point, the DKIM sig "counts", and a result must be recorded

            // well-formed DKIM-Signature contain only UTF-8
            let value = match str::from_utf8(value.as_ref()) {
                Ok(r) => r,
                Err(_) => {
                    tasks.push(VerifyingTask::new_not_started(
                        idx,
                        VerifierError::DkimSignatureHeaderFormat(DkimSignatureError {
                            domain: None,
                            signature_data_base64: None,
                            kind: DkimSignatureErrorKind::Utf8Encoding,
                        }),
                    ));
                    continue;
                }
            };

            let task = match DkimSignature::from_str(value) {
                Ok(sig) => {
                    // TODO revisit, clean up
                    // TODO here, a DkimSignature is actually available: store in task. same below
                    for h in &config.required_signed_headers {
                        if !sig.signed_headers.contains(h) {
                            tasks.push(VerifyingTask::new_not_started(
                                idx,
                                VerifierError::Policy(PolicyError::RequiredHeadersNotSigned),
                            ));
                            continue 'outer;
                        }
                    }

                    if let Some(len) = sig.body_length {
                        if usize::try_from(len).is_err() {
                            // signed body length too large to undergo DKIM processing on this platform
                            tasks.push(VerifyingTask::new_not_started(
                                idx,
                                VerifierError::Overflow,
                            ));
                            continue 'outer;
                        }
                    }

                    let current_t = config.current_timestamp();

                    if config.fail_if_expired {
                        if let Some(t) = sig.expiration {
                            let delta = config.time_tolerance.as_secs();
                            if current_t >= t.saturating_add(delta) {
                                tasks.push(VerifyingTask::new_not_started(
                                        idx, VerifierError::Policy(PolicyError::SignatureExpired),
                                ));
                                continue 'outer;
                            }
                        }
                    }
                    if config.fail_if_in_future {
                        if let Some(t) = sig.timestamp {
                            let delta = config.time_tolerance.as_secs();
                            if t.saturating_sub(delta) > current_t {
                                tasks.push(VerifyingTask::new_not_started(
                                        idx, VerifierError::Policy(PolicyError::TimestampInFuture),
                                ));
                                continue 'outer;
                            }
                        }
                    }

                    VerifyingTask::new(idx, sig, name.as_ref().into(), value.into())
                }
                Err(e) => VerifyingTask::new_not_started(idx, VerifierError::DkimSignatureHeaderFormat(e)),
            };

            tasks.push(task);
        }

        if tasks.is_empty() {
            None
        } else {
            Some(Self { headers, tasks })
        }
    }

    pub async fn verify_all(mut self, mut queries: Queries) -> Vec<VerifyingTask> {
        let headers = self.headers;

        let mut vec = vec![];

        // step through queries *as they come in*; queries are keyed by (domain, selector)
        while let Some(res) = queries.set.join_next().await {
            let (indexes, res) = res.unwrap();

            let mut res = extract_record_strs(res);

            // for each incoming query result:
            // select tasks that have that (domain, selector) pair
            // perform verification
            let mut i = 0;
            while i < self.tasks.len() {
                if indexes.contains(&self.tasks[i].index) {
                    let mut task = self.tasks.remove(i);

                    verify_task(&mut task, headers, &mut res).await;

                    vec.push(task);
                } else {
                    i += 1;
                }
            }
        }

        // some tasks do not have corresponding query, no query was spawned
        // merge together again, and sort by index
        self.tasks.append(&mut vec);
        self.tasks.sort_unstable_by_key(|t| t.index);

        self.tasks
    }
}

enum MaybeRecord {
    Unparsed(io::Result<String>),
    Parsed(Result<DkimKeyRecord, DkimKeyRecordParseError>),
}

fn extract_record_strs(
    lookup_result: io::Result<Vec<io::Result<String>>>,
) -> Result<Vec<MaybeRecord>, VerifierError> {
    match lookup_result {
        Ok(txts) if txts.is_empty() => {
            trace!("no key record");
            Err(VerifierError::NoKeyFound)
        }
        Ok(txts) => Ok(txts.into_iter().map(MaybeRecord::Unparsed).collect()),
        Err(e) => {
            match e.kind() {
                ErrorKind::NotFound => {
                    trace!("no key record");
                    Err(VerifierError::NoKeyFound)
                }
                ErrorKind::InvalidInput => {
                    trace!("invalid key record domain name");
                    Err(VerifierError::InvalidKeyDomain)
                }
                ErrorKind::TimedOut => {
                    trace!("key record lookup timed out");
                    Err(VerifierError::KeyLookupTimeout)
                }
                _ => {
                    trace!("could not look up key record: {e}");
                    Err(VerifierError::KeyLookup)
                }
            }
        }
    }
}

async fn verify_task(
    task: &mut VerifyingTask,
    headers: &HeaderFields,
    lookup_result: &mut Result<Vec<MaybeRecord>, VerifierError>,
) {
    trace!("processing DKIM-Signature");

    let sig = task.sig.as_ref().unwrap();

    let hash_alg = sig.algorithm.hash_algorithm();
    let key_type = sig.algorithm.key_type();
    let signature_data = &sig.signature_data;

    let txts = match lookup_result {
        Ok(txts) => txts,
        Err(e) => {
            task.status = Some(VerificationStatus::Failure(e.clone()));
            return;
        }
    };

    assert!(!txts.is_empty());

    let txts = iter_records(txts);

    // step through all (usually only 1, but many allowed) key records
    for (i, key_record) in txts.enumerate() {
        trace!("trying verification using DKIM key record {}", i + 1);

        let key_record = match key_record {
            Ok(key_record) => key_record,
            Err(e) => {
                // conflate syntax errors, but propagate error about revoked key
                let error = match e {
                    DkimKeyRecordParseError::RevokedKey => VerifierError::KeyRevoked,
                    _ => VerifierError::KeyRecordSyntax,
                };
                // record last error seen
                task.status = Some(VerificationStatus::Failure(error));
                task.testing = false;  // unknown
                task.key_size = None;
                continue;
            }
        };

        if let Err(e) = validate_key_record(
            key_type,
            hash_alg,
            key_record,
            &sig.domain,
            sig.user_id.as_ref(),
        ) {
            // record last error seen
            task.status = Some(VerificationStatus::Failure(e));
            task.testing = false;  // unknown
            task.key_size = None;
            continue;
        }

        let testing = key_record.flags.contains(&Flags::Testing);
        let key_data = &key_record.key_data;

        let public_key = match VerifyingKey::from_key_data(key_type, key_data) {
            Ok(k) => k,
            Err(e) => {
                // record last error seen
                task.status = Some(VerificationStatus::Failure(
                    VerifierError::VerificationFailure(e),
                ));
                task.testing = false;  // unknown
                task.key_size = None;
                continue;
            }
        };

        task.testing = testing;
        task.key_size = public_key.key_size();

        let name = task.name.as_ref().unwrap();
        let value = task.value.as_ref().unwrap();

        match verify::perform_verification(headers, &public_key, sig, name, value, signature_data) {
            Ok(()) => {
                task.status = Some(VerificationStatus::Success);
                break;
            }
            Err(e) => {
                // record last error seen
                task.status = Some(VerificationStatus::Failure(e));
            }
        }
    }
}

fn iter_records(
    cached_records: &mut [MaybeRecord],
) -> impl Iterator<Item = &Result<DkimKeyRecord, DkimKeyRecordParseError>> {
    cached_records.iter_mut().map(|rec| {
        if let MaybeRecord::Unparsed(s) = rec {
            let r = match s {
                Ok(s) => DkimKeyRecord::from_str(s),
                Err(e) => {
                    trace!("syntax error in DNS record: {e}");
                    Err(DkimKeyRecordParseError::RecordSyntax)
                }
            };
            *rec = MaybeRecord::Parsed(r);
        }
        match rec {
            MaybeRecord::Parsed(r) => &*r,
            _ => unreachable!(),
        }
    })
}

fn validate_key_record(
    key_type: KeyType,
    hash_alg: HashAlgorithm,
    rec: &DkimKeyRecord,
    domain: &DomainName,
    user_id: Option<&Identity>,
) -> Result<(), VerifierError> {
    if rec.key_type != key_type {
        trace!("wrong public key type");
        return Err(VerifierError::WrongKeyType);
    }
    if !rec.hash_algorithms.contains(&hash_alg) {
        trace!("disallowed hash algorithm");
        return Err(VerifierError::DisallowedHashAlgorithm);
    }
    if !(rec.service_types.contains(&ServiceType::Any)
        || rec.service_types.contains(&ServiceType::Email))
    {
        trace!("disallowed service type");
        return Err(VerifierError::DisallowedServiceType);
    }
    if rec.flags.contains(&Flags::NoSubdomains) {
        // assumes that parsing already validated that i= domain is subdomain of d=
        // need to compare A-label form (case-normalised) strings
        if let Some(user_id) = user_id {
            if domain.to_ascii() != user_id.domain_part.to_ascii() {
                trace!("domain mismatch");
                return Err(VerifierError::DomainMismatch);
            }
        }
    }

    Ok(())
}
