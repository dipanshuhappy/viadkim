use super::LookupTxt;
use std::{
    future::Future,
    io::{self, ErrorKind},
    pin::Pin,
};
use trust_dns_resolver::{error::ResolveErrorKind, Name, TokioAsyncResolver};

impl LookupTxt for TokioAsyncResolver {
    type Answer = Box<dyn Iterator<Item = io::Result<Vec<u8>>>>;
    type Query<'a> = Pin<Box<dyn Future<Output = io::Result<Self::Answer>> + Send + 'a>>;

    fn lookup_txt(&self, domain: &str) -> Self::Query<'_> {
        let name = Name::from_ascii(domain);

        Box::pin(async move {
            let name = name.map_err(|_| ErrorKind::InvalidInput)?;

            let lookup = self.txt_lookup(name).await.map_err(|e| match e.kind() {
                ResolveErrorKind::NoRecordsFound { .. } => io::Error::from(ErrorKind::NotFound),
                _ => e.into(),
            })?;

            let txts = lookup
                .into_iter()
                .map(|txt| Ok(txt.txt_data().join(&[][..])));

            let txts: Box<dyn Iterator<Item = _>> = Box::new(txts);

            Ok(txts)
        })
    }
}
