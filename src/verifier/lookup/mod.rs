#[cfg(feature = "trust-dns-resolver")]
mod trust_dns_resolver;

use std::{future::Future, io};

pub trait LookupTxt: Send + Sync {
    type Answer: IntoIterator<Item = Result<Vec<u8>, io::Error>>;
    type Query<'a>: Future<Output = Result<Self::Answer, io::Error>> + Send + 'a
    where
        Self: 'a;

    fn lookup_txt(&self, domain: &str) -> Self::Query<'_>;
}
