//! Verifier and supporting types.

mod lookup;

pub use lookup::LookupTxt;

use crate::{
    canon::{self, BodyCanonStatus, BodyCanonicalizer},
    crypto::{
        self, CountingHasher, HashAlgorithm, HashStatus, InsufficientInput, KeyType,
        VerificationError, VerifyingKey,
    },
    header::HeaderFields,
    parse::strip_fws,
    record::{DkimKeyRecord, Flags, ServiceType},
    signature::{
        self, CanonicalizationAlgorithm, DkimSignature, DkimSignatureError, DkimSignatureErrorKind,
        DomainName, Ident,
    },
};
use base64ct::{Base64, Encoding};
use std::{
    io,
    str::{self, FromStr},
    time::Duration,
};
use tokio::{task::JoinHandle, time};
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

#[derive(Debug, PartialEq)]
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

struct SigTask {
    index: usize,
    sig: Option<DkimSignature>,
    body_hasher: Option<CountingHasher>,
    status: VerificationStatus,
    testing: bool,
    key_size: Option<usize>,
}

struct VerifyingTask {
    index: usize,

    sig: Option<DkimSignature>,
    name: Option<Box<str>>,
    value: Option<Box<str>>,

    lookup_task: Option<JoinHandle<io::Result<Vec<Box<str>>>>>,

    data_hash: Option<Box<[u8]>>,

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
            lookup_task: None,
            data_hash: None,
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
            lookup_task: None,
            data_hash: None,
            status: None,
            testing: false,
            key_size: None,
        }
    }
}

// TODO make inherent methods

fn spawn_lookup_task<T>(
    task: &mut VerifyingTask,
    resolver: &T,
    config: &Config,
)
where
    T: LookupTxt + Clone + 'static,
{
    if let Some(sig) = &mut task.sig {
        // this is why resolver is Clone: need to pass it to tokio::spawn
        let resolver = resolver.clone();
        let domain = sig.domain.clone();
        let selector = sig.selector.clone();

        let lookup_timeout = config.lookup_timeout;

        let lookup_task = tokio::spawn(async move {
            time::timeout(
                lookup_timeout,
                look_up_records(&resolver, domain.as_ref(), selector.as_ref()),
            )
            .await?
        });

        task.lookup_task = Some(lookup_task);
    }
}

async fn look_up_records<T: LookupTxt + ?Sized>(
    resolver: &T,
    domain: &str,
    selector: &str,
) -> io::Result<Vec<Box<str>>> {
    let dname = format!("{selector}._domainkey.{domain}.");

    let mut result = vec![];

    // §6.1.2: ‘If the query for the public key returns multiple key records,
    // the Verifier can choose one of the key records or may cycle through the
    // key records […]. The order of the key records is unspecified.’ We return
    // at most three keys.
    for v in resolver.lookup_txt(&dname).await?.into_iter().take(3) {
        // TODO check if error is io::ErrorKind::NotFound here => should map to VerifierError::NoKeyFound!
        // TODO also error should not be propagated with ? here?
        let s = v?;
        let s = String::from_utf8_lossy(&s);
        result.push(s.into());
    }

    Ok(result)
}

fn compute_data_hash(task: &mut VerifyingTask, headers: &HeaderFields) {
    if let Some(sig) = &mut task.sig {
        let headers = canon::canon_headers(
            sig.canonicalization.header,
            headers,
            &sig.signed_headers,
        );

        //trace!("canonicalized headers: {:?}", BStr::new(&headers));

        let original_canon_header = make_original_canon_header(
            task.name.as_ref().unwrap(),
            task.value.as_ref().unwrap(),
            sig.canonicalization.header,
        );

        let data_hash = crypto::data_hash_digest(
            sig.algorithm.to_hash_algorithm(),
            &headers,
            &original_canon_header,
        );

        task.data_hash = Some(data_hash);
    }
}

async fn verify_sig(task: &mut VerifyingTask) {
    if let Some(sig) = &mut task.sig {
        trace!("processing DKIM-Signature");

        let hash_alg = sig.algorithm.to_hash_algorithm();
        let key_type = sig.algorithm.to_key_type();
        let signature_data = &sig.signature_data;

        let data_hash = task.data_hash.as_ref().unwrap();

        let txts = match task.lookup_task.take().unwrap().await.unwrap() {
            Ok(txts) => {
                if txts.is_empty() {
                    trace!("no key record");
                    task.status = Some(VerificationStatus::Failure(VerifierError::NoKeyFound));
                    return;
                }
                txts
            }
            Err(e) => {
                // TODO is this branch also entered on NXDOMAIN? => should return NoKeyFound instead
                trace!("could not look up key record: {e}");
                task.status = Some(VerificationStatus::Failure(VerifierError::KeyLookup));
                return;
            }
        };

        assert!(!txts.is_empty());

        // step through all (usually only 1, but many allowed) key records
        for (i, key_record) in txts.into_iter().enumerate() {
            trace!("trying verification using DKIM key record {}", i + 1);

            let key_record = match get_validated_key_record(
                key_type, hash_alg, &key_record, &sig.domain, &sig.user_id,
            ) {
                Ok(r) => r,
                Err(e) => {
                    // record last error seen
                    task.status = Some(VerificationStatus::Failure(e));
                    task.testing = false;  // unknown
                    task.key_size = None;
                    continue;
                }
            };

            let testing = key_record.flags.contains(&Flags::Testing);
            let key_data = key_record.key_data;

            let public_key = match VerifyingKey::from_key_data(key_type, &key_data) {
                Ok(k) => k,
                Err(e) => {
                    // record last error seen
                    task.status = Some(VerificationStatus::Failure(VerifierError::VerificationFailure(e)));
                    task.testing = false;  // unknown
                    task.key_size = None;
                    continue;
                }
            };

            task.testing = testing;
            task.key_size = public_key.key_size();

            match verify_signature(
                &public_key,
                hash_alg,
                data_hash,
                signature_data,
            ) {
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
}

fn get_validated_key_record(
    key_type: KeyType,
    hash_alg: HashAlgorithm,
    key_record: &str,
    domain: &DomainName,
    user_id: &Ident,
) -> Result<DkimKeyRecord, VerifierError> {
    let rec = match DkimKeyRecord::from_str(key_record) {
        Ok(r) => r,
        Err(_e) => {
            // TODO doesn't have to be a syntax error, eg revoked key
            trace!("invalid key record syntax");
            return Err(VerifierError::KeyRecordSyntax);
        }
    };

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

    Ok(rec)
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
    body_canonicalizer_simple: BodyCanonicalizer,
    body_canonicalizer_relaxed: BodyCanonicalizer,
}

impl Verifier {
    pub async fn process_headers<T>(resolver: &T, headers: &HeaderFields, config: &Config) -> Self
    where
        T: LookupTxt + Clone + 'static,
    {
        let mut tasks = find_dkim_signatures(headers);

        // do lookups in background
        for task in &mut tasks {
            spawn_lookup_task(task, resolver, config);
        }

        // compute data hashes for all sigs
        for task in &mut tasks {
            compute_data_hash(task, headers);
        }

        // verify signatures using lookups and data hashes
        // TODO order verification by first verifying sigs with d= equal or subdomain of From: header?
        for task in &mut tasks {
            verify_sig(task).await;
        }

        let mut final_tasks = vec![];
        for task in tasks {
            let body_hasher = match &task.sig {
                Some(sig) => {
                    let body_len = sig.body_length.map(|len| len.try_into().unwrap_or(usize::MAX));
                    let hash_alg = sig.algorithm.to_hash_algorithm();
                    Some(CountingHasher::new(hash_alg, body_len))

                }
                None => None,
            };
            final_tasks.push(SigTask {
                index: task.index,
                sig: task.sig,
                body_hasher,
                status: task.status.unwrap(),
                testing: task.testing,
                key_size: task.key_size,
            });
        }

        Self {
            tasks: final_tasks,
            body_canonicalizer_simple: BodyCanonicalizer::simple(),
            body_canonicalizer_relaxed: BodyCanonicalizer::relaxed(),
        }
    }

    pub fn body_chunk(&mut self, chunk: &[u8]) -> BodyCanonStatus {
        let mut cached_canonicalized_chunk_simple = None;
        let mut cached_canonicalized_chunk_relaxed = None;

        let mut all_done = true;

        for task in &mut self.tasks {
            if task.status != VerificationStatus::Success {
                continue;
            }

            if !task.body_hasher.as_ref().unwrap().is_done() {
                let canon_kind = task.sig.as_ref().unwrap().canonicalization.body;

                let canonicalized_chunk = match canon_kind {
                    CanonicalizationAlgorithm::Simple => cached_canonicalized_chunk_simple
                        .get_or_insert_with(|| self.body_canonicalizer_simple.canon_chunk(chunk)),
                    CanonicalizationAlgorithm::Relaxed => cached_canonicalized_chunk_relaxed
                        .get_or_insert_with(|| self.body_canonicalizer_relaxed.canon_chunk(chunk)),
                };

                if let HashStatus::NotDone = task.body_hasher.as_mut().unwrap().update(canonicalized_chunk) {
                    all_done = false;
                }
            }
        }

        if all_done {
            BodyCanonStatus::Done
        } else {
            BodyCanonStatus::NotDone
        }
    }

    pub fn finish(self) -> Vec<VerificationResult> {
        let mut result = vec![];

        let cached_canonicalized_chunk_simple = self.body_canonicalizer_simple.finish_canon();
        let cached_canonicalized_chunk_relaxed = self.body_canonicalizer_relaxed.finish_canon();

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

                    let canon_kind = task.sig.as_ref().unwrap().canonicalization.body;
                    let canonicalized_chunk = match canon_kind {
                        CanonicalizationAlgorithm::Simple => &cached_canonicalized_chunk_simple[..],
                        CanonicalizationAlgorithm::Relaxed => &cached_canonicalized_chunk_relaxed[..],
                    };

                    let mut hasher = task.body_hasher.unwrap();

                    hasher.update(canonicalized_chunk);

                    let status = match hasher.finish() {
                        Ok((h, _)) => {
                            if h != task.sig.as_ref().unwrap().body_hash.as_ref() {
                                // downgrade status Success -> Failure!
                                trace!("body hash mismatch: {}", &Base64::encode_string(&h));
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
                        signature: Some(task.sig.unwrap()),
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


fn find_dkim_signatures(headers: &HeaderFields) -> Vec<VerifyingTask> {
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

    tasks
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
