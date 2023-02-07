//! Verifier and supporting types.

mod lookup;
mod query;

pub use lookup::LookupTxt;

use crate::{
    body_hash::{canonicalizing_hasher_key, CanonicalizingHasher, CanonicalizingHasherBuilder},
    canon::{self, BodyCanonStatus},
    crypto::{self, HashAlgorithm, InsufficientInput, KeyType, VerificationError, VerifyingKey},
    header::HeaderFields,
    parse::strip_fws,
    record::{DkimKeyRecord, DkimKeyRecordParseError, Flags, ServiceType},
    signature::{
        self, CanonicalizationAlgorithm, DkimSignature, DkimSignatureError, DkimSignatureErrorKind,
        DomainName, Ident, Selector,
    },
    verifier::query::Queries,
};
use base64ct::{Base64, Encoding};
use std::{
    fmt::{self, Display, Formatter},
    io,
    str::{self, FromStr},
    time::Duration,
};
use tracing::trace;

// verifier config
pub struct Config {
    pub lookup_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            lookup_timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct VerificationResult {
    pub index: usize,  // index in HeaderFields
    pub signature: Option<DkimSignature>,
    pub status: VerificationStatus,
    pub testing: bool,  // t=y in record
    pub key_size: Option<usize>,
}

// TODO RFC 6376 vs RFC 8601:
// Success Permfail Tempfail
#[derive(Debug, PartialEq)]
pub enum VerificationStatus {
    Success,
    Failure(VerifierError),
}

#[derive(Clone, Debug, PartialEq)]
pub enum VerifierError {
    DkimSignatureHeaderFormat(DkimSignatureError),
    WrongKeyType,
    KeyRecordSyntax,
    DisallowedHashAlgorithm,
    DisallowedServiceType,
    DomainMismatch,
    VerificationFailure(VerificationError),
    BodyHashMismatch,
    InsufficientBodyLength,
    NoKeyFound,
    KeyLookup,
}

impl Display for VerifierError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::DkimSignatureHeaderFormat(error) => error.kind.fmt(f),
            Self::WrongKeyType => write!(f, "wrong key type"),
            Self::KeyRecordSyntax => write!(f, "invalid syntax in key record"),
            Self::DisallowedHashAlgorithm => write!(f, "hash algorithm not allowed"),
            Self::DisallowedServiceType => write!(f, "service type not allowed"),
            Self::DomainMismatch => write!(f, "domain mismatch"),
            Self::VerificationFailure(error) => error.fmt(f),
            Self::BodyHashMismatch => write!(f, "body hash mismatch"),
            Self::InsufficientBodyLength => write!(f, "truncated body"),
            Self::NoKeyFound => write!(f, "no key record found"),
            Self::KeyLookup => write!(f, "key record lookup failed"),
        }
    }
}

struct SigTask {
    index: usize,
    sig: Option<DkimSignature>,
    status: VerificationStatus,
    testing: bool,
    key_size: Option<usize>,
}

// TODO
pub(crate) struct HeaderVerifier {
    pub tasks: Vec<VerifyingTask>,
}

impl HeaderVerifier {
    fn find_dkim_signatures(headers: &HeaderFields) -> Self {
        let mut tasks = vec![];

        let dkim_headers = headers
            .as_ref()
            .iter()
            .enumerate()
            .filter(|(_, (name, _))| *name == "DKIM-Signature")
            .take(20);  // hard limit

        for (idx, (name, value)) in dkim_headers {
            // at this point, the DKIM sig "counts", and a result must be recorded

            // well-formed DKIM-Signature contain only UTF-8
            let value = match str::from_utf8(value.as_ref()) {
                Ok(r) => r,
                Err(_) => {
                    tasks.push(VerifyingTask::new_not_started(
                        idx,
                        DkimSignatureError {
                            domain: None,
                            signature_data_base64: None,
                            kind: DkimSignatureErrorKind::InvalidTagList,
                        },
                    ));
                    continue;
                }
            };

            let t = match DkimSignature::from_str(value) {
                Ok(sig) => VerifyingTask::new(idx, sig, name.as_ref().into(), value.into()),
                Err(e) => VerifyingTask::new_not_started(idx, e),
            };

            tasks.push(t);
        }

        Self { tasks }
    }

    async fn verify_all(mut self, mut queries: Queries, headers: &HeaderFields) -> Vec<VerifyingTask> {
        let mut vec = vec![];

        // step through queries *as they come in* (mpsc); queries are keyed by (domain, selector)
        while let Some(res) = queries.rx.recv().await {
            let ((domain, selector), res) = res;

            let mut res = extract_record_strs(res);

            // for each incoming query result:
            // select tasks that have that (domain, selector) pair
            // perform verification
            let mut i = 0;
            while i < self.tasks.len() {
                if is_matching_task(&self.tasks[i], &domain, &selector) {
                    let mut task = self.tasks.remove(i);

                    verify_sig(&mut task, headers, &mut res).await;
                    //

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

fn is_matching_task(task: &VerifyingTask, domain: &DomainName, selector: &Selector) -> bool {
    if let Some(sig) = &task.sig {
        &sig.domain == domain && &sig.selector == selector
    } else {
        false
    }
}

enum MaybeRecord {
    Unparsed(Box<str>),
    Parsed(Result<DkimKeyRecord, DkimKeyRecordParseError>),
}

fn extract_record_strs(lookup_result: io::Result<Vec<Box<str>>>) -> Result<Vec<MaybeRecord>, VerifierError> {
    match lookup_result {
        Ok(txts) => {
            if txts.is_empty() {
                trace!("no key record");
                return Err(VerifierError::NoKeyFound);
            }
            Ok(txts.into_iter().map(MaybeRecord::Unparsed).collect())
        }
        Err(e) => {
            // TODO is this branch also entered on NXDOMAIN? => should return NoKeyFound instead
            trace!("could not look up key record: {e}");
            return Err(VerifierError::KeyLookup);
        }
    }
}

pub(crate) struct VerifyingTask {
    index: usize,

    sig: Option<DkimSignature>,
    name: Option<Box<str>>,
    value: Option<Box<str>>,

    status: Option<VerificationStatus>,
    testing: bool,
    key_size: Option<usize>,
}

impl VerifyingTask {
    fn new_not_started(index: usize, error: DkimSignatureError) -> Self {
        let status = VerificationStatus::Failure(VerifierError::DkimSignatureHeaderFormat(error));
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

async fn verify_sig(
    task: &mut VerifyingTask,
    headers: &HeaderFields,
    lookup_result: &mut Result<Vec<MaybeRecord>, VerifierError>,
) {
    trace!("processing DKIM-Signature");

    let sig = task.sig.as_ref().unwrap();

    let hash_alg = sig.algorithm.to_hash_algorithm();
    let key_type = sig.algorithm.to_key_type();
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
            Err(_e) => {
                // TODO look at _e: doesn't have to be a syntax error, eg revoked key
                // record last error seen
                task.status = Some(VerificationStatus::Failure(VerifierError::KeyRecordSyntax));
                task.testing = false; // unknown
                task.key_size = None;
                continue;
            }
        };

        match validate_key_record(
            key_type,
            hash_alg,
            key_record,
            &sig.domain,
            &sig.user_id,
        ) {
            Ok(()) => {}
            Err(e) => {
                // record last error seen
                task.status = Some(VerificationStatus::Failure(e));
                task.testing = false; // unknown
                task.key_size = None;
                continue;
            }
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
                task.testing = false; // unknown
                task.key_size = None;
                continue;
            }
        };

        task.testing = testing;
        task.key_size = public_key.key_size();

        let data_hash = compute_data_hash(
            sig,
            task.name.as_ref().unwrap(),
            task.value.as_ref().unwrap(),
            headers,
        );

        match verify_signature(&public_key, hash_alg, &data_hash, signature_data) {
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
    cached_records: &mut Vec<MaybeRecord>,
) -> impl Iterator<Item = &Result<DkimKeyRecord, DkimKeyRecordParseError>> {
    cached_records.iter_mut().map(|rec| {
        if let MaybeRecord::Unparsed(s) = rec {
            let r = DkimKeyRecord::from_str(s);
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
    user_id: &Ident,
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
        if domain != &user_id.domain_part {
            trace!("domain mismatch");
            return Err(VerifierError::DomainMismatch);
        }
    }

    Ok(())
}

fn compute_data_hash(
    sig: &DkimSignature,
    name: &str,
    value: &str,
    headers: &HeaderFields,
) -> Box<[u8]> {
    let headers = canon::canon_headers(
        sig.canonicalization.header,
        headers,
        &sig.signed_headers,
    );

    //trace!("canonicalized headers: {:?}", BStr::new(&headers));

    let original_canon_header = make_original_canon_header(
        name,
        value,
        sig.canonicalization.header,
    );

    crypto::data_hash_digest(
        sig.algorithm.to_hash_algorithm(),
        &headers,
        &original_canon_header,
    )
}

fn verify_signature(
    public_key: &VerifyingKey,
    hash_alg: HashAlgorithm,
    data_hash: &[u8],
    signature_data: &[u8],
) -> Result<(), VerifierError> {
    match public_key {
        VerifyingKey::Rsa(pk) => {
            match crypto::verify_rsa(hash_alg, pk, data_hash, signature_data) {
                Ok(()) => {
                    trace!("RSA public key verification successful");
                    Ok(())
                }
                Err(e) => {
                    trace!("RSA public key verification failed: {e}");
                    Err(VerifierError::VerificationFailure(e))
                }
            }
        }
        VerifyingKey::Ed25519(pk) => {
            match crypto::verify_ed25519(pk, data_hash, signature_data) {
                Ok(()) => {
                    trace!("Ed25519 public key verification successful");
                    Ok(())
                }
                Err(e) => {
                    trace!("Ed25519 public key verification failed: {e}");
                    Err(VerifierError::VerificationFailure(e))
                }
            }
        }
    }
}

/// A verifier validating all DKIM signatures in a message.
///
/// The verifier proceeds in three stages...
pub struct Verifier {
    tasks: Vec<SigTask>,
    canonicalizing_hasher: CanonicalizingHasher,
}

impl Verifier {
    pub async fn process_headers<T>(resolver: &T, headers: &HeaderFields, config: &Config) -> Self
    where
        T: LookupTxt + Clone + 'static,
    {
        let tasks = HeaderVerifier::find_dkim_signatures(headers);

        let queries = Queries::spawn(&tasks.tasks, resolver, config);

        let tasks = tasks.verify_all(queries, headers).await;

        let mut final_tasks = vec![];
        let mut canonicalizing_hasher = CanonicalizingHasherBuilder::new();
        for task in tasks {
            let status = task.status.unwrap();
            if let Some(sig) = &task.sig {
                if status == VerificationStatus::Success {
                    let (body_len, hash_alg, canon_kind) = canonicalizing_hasher_key(sig);
                    canonicalizing_hasher.register_canon(body_len, hash_alg, canon_kind);
                }
            }
            final_tasks.push(SigTask {
                index: task.index,
                sig: task.sig,
                status,
                testing: task.testing,
                key_size: task.key_size,
            });
        }

        Self {
            tasks: final_tasks,
            canonicalizing_hasher: canonicalizing_hasher.build(),
        }
    }

    pub fn body_chunk(&mut self, chunk: &[u8]) -> BodyCanonStatus {
        self.canonicalizing_hasher.hash_chunk(chunk)
    }

    pub fn finish(self) -> Vec<VerificationResult> {
        let mut result = vec![];

        let hasher_results = self.canonicalizing_hasher.finish();

        for task in self.tasks {
            match task.status {
                VerificationStatus::Failure(e) => {
                    result.push(VerificationResult {
                        index: task.index,
                        signature: task.sig,
                        status: VerificationStatus::Failure(e),
                        testing: task.testing,
                        key_size: task.key_size,
                    });
                }
                VerificationStatus::Success => {
                    trace!("now checking body hash for signature");

                    let sig = task.sig.unwrap();

                    let key = canonicalizing_hasher_key(&sig);

                    let status = match hasher_results.get(&key).unwrap() {
                        Ok((h, _)) => {
                            if h != &sig.body_hash {
                                // downgrade status Success -> Failure!
                                trace!("body hash mismatch: {}", &Base64::encode_string(h));
                                VerificationStatus::Failure(VerifierError::BodyHashMismatch)
                            } else {
                                trace!("body hash matched");
                                VerificationStatus::Success
                            }
                        }
                        Err(InsufficientInput) => {
                            // downgrade status Success -> Failure!
                            VerificationStatus::Failure(VerifierError::InsufficientBodyLength)
                        }
                    };

                    result.push(VerificationResult {
                        index: task.index,
                        signature: Some(sig),
                        status,
                        testing: task.testing,
                        key_size: task.key_size,
                    });
                }
            }
        }

        result
    }
}

fn make_original_canon_header(name: &str, value: &str, canon: CanonicalizationAlgorithm) -> String {
    let mut value = value.to_owned();
    let mut last_i = 0;
    let mut ms = value.match_indices(';');

    // TODO clean up this abomination
    loop {
        match ms.next() {
            Some((i, _)) => {
                let tag = &value[last_i..i];
                let without_fws = strip_fws(tag).unwrap_or(tag);
                if without_fws.starts_with("b=") {
                    value.drain((last_i + (tag.len() - without_fws.len() + 2 ))..i);
                    break;
                } else {
                    last_i = i + 1;
                }
            }
            None => {
                let i = value.len();
                if last_i != i {
                    // last slice
                    let tag = &value[last_i..i];
                    let without_fws = strip_fws(tag).unwrap_or(tag);
                    if without_fws.starts_with("b=") {
                        value.drain((last_i + (tag.len() - without_fws.len() + 2 ))..i);
                    }
                }
                break;
            }
        }
    }

    signature::canon_dkim_header(canon, name, &value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_original_canon_header_ok() {
        let example = "v=1; a=rsa-sha256; d=example.net; s=brisbane;
  c=simple; q=dns/txt; i=@eng.example.net;
  h=from:to:subject:date;
  bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;
  b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR";
        let example = example.replace('\n', "\r\n");

        let s = make_original_canon_header("Dkim-Signature", &example, CanonicalizationAlgorithm::Relaxed);

        assert_eq!(s,
            "dkim-signature:v=1; a=rsa-sha256; d=example.net; \
            s=brisbane; c=simple; q=dns/txt; i=@eng.example.net; h=from:to:subject:date; \
            bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=; b=");
    }

    //#[ignore]
    //#[tokio::test]
    //async fn live_dkim_key_record() {
    //    let resolver = TokioAsyncResolver::tokio(Default::default(), Default::default()).unwrap();

    //    let r = look_up_records(&resolver, "gluet.ch", "2020")
    //        .await
    //        .unwrap();

    //    let taglist = TagList::from_str(&r[0]).unwrap();

    //    let rec = DkimKeyRecord::from_tag_list(&taglist).unwrap();

    //    assert_eq!(
    //        &base64::encode(rec.key_data),
    //        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzQQGy3HpwbcWhBXXDTBv\
    //        bWGJy38WK8kLascRJyvYAkFCLx1QqCi7Q7baABkee5lkGRGLQidUyNfDoW9MNCiT\
    //        5SLhnl2iPaT9kcKhAYSezMNWyQxueXhLIZ5wT9LKCfFNVvz2R5SNcVE7a/CxU4XA\
    //        iEhNsKg4o/LyEhE1665BT0GizPz5ukNwwePQrLgGSpygHd/TQBa/xzKlQdLvTHiQ\
    //        OqgnoG/G3ThVOnQV/Ntc8UjKDZO5n1pynTsVmtmCASwykN6ZDZTaeaRCnIrS02nO\
    //        YB1ba2TJl+xugdNja1agDvUL6t0n2kfGp85A/Z6v5Fq0nlzvmwHth2eg3lVVgI2c\
    //        KwIDAQAB"
    //    );
    //}
}
