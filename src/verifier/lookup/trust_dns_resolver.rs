use super::LookupTxt;
use std::{future::Future, io, pin::Pin};
use trust_dns_resolver::{Name as TrustDnsName, TokioAsyncResolver};

// TODO actually make use of IntoIterator trait (avoid collection into Vec)
impl LookupTxt for TokioAsyncResolver {
    type Answer = Vec<Result<Vec<u8>, io::Error>>;
    type Query<'a> = Pin<Box<dyn Future<Output = Result<Self::Answer, io::Error>> + Send + 'a>>;

    fn lookup_txt(&self, domain: &str) -> Self::Query<'_> {
        let name = TrustDnsName::from_ascii(domain);

        Box::pin(async move {
            let name = name?;
            let it = self
                .txt_lookup(name)
                .await?
                .into_iter()
                .map(|txt| {
                    let v: Vec<u8> = txt
                        .iter()
                        .flat_map(|bo| bo.as_ref())
                        .copied()
                        // .map(|data| String::from_utf8_lossy(data))
                        .collect();
                    Ok(v)
                })
                .collect();
            Ok(it)
        })
    }
}
