#[cfg(feature = "trust-dns-resolver")]
mod trust_dns_resolver;

use std::{future::Future, io};

/// A trait for looking up DNS TXT records containing DKIM public key records.
///
/// The error type used here is `std::io::Error`. The following error kinds are
/// recognised and receive special treatment.
///
/// * `ErrorKind::InvalidInput` on the query: the domain argument could not be used
/// * `ErrorKind::NotFound` on the query: NXDOMAIN, no key record found
/// * `ErrorKind::TimedOut` on the query: timeout
pub trait LookupTxt: Send + Sync {
    /// The answer consisting of TXT records found.
    type Answer: IntoIterator<Item = io::Result<Vec<u8>>>;
    /// The future resolving to the query’s answer.
    type Query<'a>: Future<Output = io::Result<Self::Answer>> + Send + 'a
    where
        Self: 'a;

    /// Looks up the domain’s TXT records in DNS.
    fn lookup_txt(&self, domain: &str) -> Self::Query<'_>;
}
