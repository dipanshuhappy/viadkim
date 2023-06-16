use std::{future::Future, io, pin::Pin, sync::Arc};
use tokio::fs;
use viadkim::{crypto::SigningKey, verifier::LookupTxt};

pub type LookupOutput = Vec<io::Result<Vec<u8>>>;
pub type LookupFuture<'a> = Pin<Box<dyn Future<Output = io::Result<LookupOutput>> + Send + 'a>>;

#[derive(Clone)]
pub struct MockLookup(Arc<dyn Fn(&str) -> LookupFuture<'_> + Send + Sync>);

impl MockLookup {
    pub fn new(f: impl Fn(&str) -> LookupFuture<'_> + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }
}

impl LookupTxt for MockLookup {
    type Answer = LookupOutput;
    type Query<'a> = Pin<Box<dyn Future<Output = io::Result<Self::Answer>> + Send + 'a>>;

    fn lookup_txt(&self, domain: &str) -> Self::Query<'_> {
        let domain = domain.to_owned();

        Box::pin(async move { self.0(&domain).await })
    }
}

// TODO
pub async fn read_public_key_file_base64(file_name: &str) -> io::Result<String> {
    let s = fs::read_to_string(file_name).await?;
    let mut key_base64: Vec<_> = s.lines().skip(1).collect();
    key_base64.pop();
    Ok(key_base64.join(""))
}

pub async fn read_signing_key_from_file(file_name: &str) -> io::Result<SigningKey> {
    let s = fs::read_to_string(file_name).await?;
    Ok(SigningKey::from_pkcs8_pem(&s).unwrap())
}
