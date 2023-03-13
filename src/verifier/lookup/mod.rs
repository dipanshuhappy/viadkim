#[cfg(feature = "trust-dns-resolver")]
mod trust_dns_resolver;

use std::{future::Future, io};

/// A trait for looking up DNS TXT records containing DKIM public key records.
///
/// The error type used here is `std::io::Error`. The following error kinds on
/// the query result are recognised and receive special treatment.
///
/// * `ErrorKind::InvalidInput` on the query: the domain argument could not be used
/// * `ErrorKind::NotFound` on the query: NXDOMAIN, no key record found
/// * `ErrorKind::TimedOut` on the query: timeout
///
/// The inner, per-record `std::io::Error` can be used to signal errors
/// (parsing, encoding) with individual TXT records.
pub trait LookupTxt: Send + Sync {
    /// The answer consisting of TXT records found.
    type Answer: IntoIterator<Item = io::Result<Vec<u8>>>;
    /// The future resolving to the query’s answer.
    type Query<'a>: Future<Output = io::Result<Self::Answer>> + Send + 'a
    where
        Self: 'a;

    /// Looks up the domain’s TXT records in DNS.
    ///
    /// The domain will be passed to this trait as a string in human-readable
    /// A-label (ASCII) format (eg `selector._domainkey.example.com`).
    ///
    /// Note that according to RFC 6376, the final answer is expected to contain
    /// only a single TXT record (but DNS allows > 1).
    fn lookup_txt(&self, domain: &str) -> Self::Query<'_>;
}
