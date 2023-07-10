use std::{future::Future, io, iter, pin::Pin, sync::Arc};
use tokio::fs;
use viadkim::{
    crypto::SigningKey,
    header::{HeaderField, HeaderFields},
    signer::{SignRequest, SigningResult, Signer, SigningError},
    verifier::{Config, LookupTxt, VerificationResult, Verifier},
};

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

// TODO test helpers
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

pub async fn sign<I>(
    headers: HeaderFields,
    body: &[u8],
    requests: I,
) -> Vec<Result<SigningResult, SigningError>>
where
    I: IntoIterator<Item = SignRequest<SigningKey>>,
{
    let mut signer = Signer::prepare_signing(headers, requests).unwrap();

    let _ = signer.process_body_chunk(body);

    signer.sign().await
}

pub async fn verify<T>(
    resolver: &T,
    headers: &HeaderFields,
    body: &[u8],
    config: &Config,
) -> Vec<VerificationResult>
where
    T: LookupTxt + Clone + 'static,
{
    let mut verifier = Verifier::verify_header(resolver, headers, config)
        .await
        .unwrap();

    let _ = verifier.process_body_chunk(body);

    verifier.finish()
}

pub fn prepend_header_field<I>(first: HeaderField, rest: I) -> HeaderFields
where
    I: IntoIterator<Item = HeaderField>,
{
    let headers: Vec<_> = iter::once(first).chain(rest).collect();
    HeaderFields::new(headers).unwrap()
}
