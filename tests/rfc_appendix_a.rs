use std::{
    future::Future,
    io::{self, ErrorKind},
    pin::Pin,
    sync::Arc,
};
use tokio::fs;
use viadkim::{
    crypto::{KeyType, SigningKey},
    signature::{DomainName, Selector},
    signer::{KeyId, KeyStore, SigningRequest, SigningStatus},
    verifier::{LookupTxt, VerificationStatus},
    FieldName, HeaderFields, Signer, Verifier,
};

#[derive(Clone, Copy)]
enum KeyFormat {
    RsaPublicKey,
    SubjectPublicKeyInfo,
}

#[derive(Clone)]
struct MockLookup(KeyFormat);

impl LookupTxt for MockLookup {
    type Answer = Vec<Result<Vec<u8>, io::Error>>;
    type Query<'a> = Pin<Box<dyn Future<Output = Result<Self::Answer, io::Error>> + Send + 'a>>;

    fn lookup_txt(&self, domain: &str) -> Self::Query<'_> {
        let name = domain.to_owned();

        Box::pin(async move {
            match name.as_str() {
                "brisbane._domainkey.example.com." => {
                    let s = match self.0 {
                        KeyFormat::RsaPublicKey => {
                            fs::read_to_string("tests/brisbane_rsa.pem").await?
                        }
                        KeyFormat::SubjectPublicKeyInfo => {
                            fs::read_to_string("tests/brisbane_spki.pem").await?
                        }
                    };

                    let mut key_base64: Vec<_> = s.lines().skip(1).collect();
                    key_base64.pop();

                    let record = format!("v=DKIM1; k=rsa; p={}", key_base64.join(""));

                    Ok(vec![Ok(record.into())])
                }
                _ => Err(ErrorKind::NotFound.into()),
            }
        })
    }
}

struct MockKeyStore;

impl KeyStore for MockKeyStore {
    type Query<'a> = Pin<Box<dyn Future<Output = io::Result<Option<Arc<SigningKey>>>> + Send + 'a>>;

    fn get(&self, key_id: KeyId) -> Self::Query<'_> {
        Box::pin(async move {
            if key_id == KeyId::new(1) {
                let s = fs::read_to_string("tests/brisbane_private.pem").await?;
                let key = SigningKey::from_pkcs8_pem(&s)?;
                return Ok(Some(Arc::new(key)));
            }
            Ok(None)
        })
    }
}

/// Example from RFC 6376, appendix A.2, with public key in RSAPublicKey format.
#[tokio::test]
async fn rfc_appendix_a_rsa() {
    let _ = tracing_subscriber::fmt::try_init();

    let resolver = MockLookup(KeyFormat::RsaPublicKey);
    let headers = make_header_fields();
    let config = Default::default();

    let mut verifier = Verifier::process_headers(&resolver, &headers, &config).await;

    let body = make_body();

    verifier.body_chunk(&body);

    let sigs = verifier.finish();

    let result = sigs.into_iter().next().unwrap();

    assert_eq!(result.status, VerificationStatus::Success);
}

/// Example from RFC 6376, appendix A.2, with public key in SPKI format.
#[tokio::test]
async fn rfc_appendix_a_spki() {
    let _ = tracing_subscriber::fmt::try_init();

    let resolver = MockLookup(KeyFormat::SubjectPublicKeyInfo);
    let headers = make_header_fields();
    let config = Default::default();

    let mut verifier = Verifier::process_headers(&resolver, &headers, &config).await;

    let body = make_body();

    verifier.body_chunk(&body);

    let sigs = verifier.finish();

    let result = sigs.into_iter().next().unwrap();

    assert_eq!(result.status, VerificationStatus::Success);
}

/// Sign as in example from RFC 6376, appendix A.2, with private key shown
/// there, then verify result.
#[tokio::test]
async fn sign_roundtrip() {
    let _ = tracing_subscriber::fmt::try_init();

    let body = make_body();

    let mut req = SigningRequest::new(
        DomainName::new("example.com").unwrap(),
        Selector::new("brisbane").unwrap(),
        KeyType::Rsa,
        KeyId::new(1),
    );
    req.signed_headers = vec![
        FieldName::new("Received").unwrap(),
        FieldName::new("From").unwrap(),
        FieldName::new("To").unwrap(),
        FieldName::new("Subject").unwrap(),
        FieldName::new("Date").unwrap(),
        FieldName::new("Message-ID").unwrap(),
    ];

    let headers = make_header_fields();

    let mut signer = Signer::prepare_signing(vec![req], headers).unwrap();

    signer.body_chunk(&body);

    let key_store = MockKeyStore;

    let sigs = signer.finish(&key_store).await;

    let result = sigs.into_iter().next().unwrap();

    match result.status {
        SigningStatus::Success { header_name, header_value, .. } => {
            tracing::trace!("{}:{}", header_name, header_value);
        }
        _ => panic!(),
    }

    let resolver = MockLookup(KeyFormat::SubjectPublicKeyInfo);
    let headers = make_header_fields();
    let config = Default::default();

    let mut verifier = Verifier::process_headers(&resolver, &headers, &config).await;

    verifier.body_chunk(&body);

    let sigs = verifier.finish();

    let result = sigs.into_iter().next().unwrap();

    assert_eq!(result.status, VerificationStatus::Success);
}

fn make_header_fields() -> HeaderFields {
    let headers: Vec<(String, Vec<u8>)> = vec![
        (
            "DKIM-Signature".into(),
            b" v=1; a=rsa-sha256; s=brisbane; d=example.com;\r
      c=simple/simple; q=dns/txt; i=joe@football.example.com;\r
      h=Received : From : To : Subject : Date : Message-ID;\r
      bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r
      b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB\r
        4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut\r
        KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV\r
        4bmp/YzhwvcubU4=;"
                .to_vec(),
        ),
        (
            "Received".into(),
            b" from client1.football.example.com  [192.0.2.1]\r
      by submitserver.example.com with SUBMISSION;\r
      Fri, 11 Jul 2003 21:01:54 -0700 (PDT)"
                .to_vec(),
        ),
        (
            "From".into(),
            b" Joe SixPack <joe@football.example.com>".to_vec(),
        ),
        (
            "To".into(),
            b" Suzie Q <suzie@shopping.example.net>".to_vec(),
        ),
        ("Subject".into(), b" Is dinner ready?".to_vec()),
        (
            "Date".into(),
            b" Fri, 11 Jul 2003 21:00:37 -0700 (PDT)".to_vec(),
        ),
        (
            "Message-ID".into(),
            b" <20030712040037.46341.5F8J@football.example.com>".to_vec(),
        ),
    ];

    HeaderFields::from_vec(headers).unwrap()
}

fn make_body() -> Vec<u8> {
    b"Hi.\r
\r
We lost the game. Are you hungry yet?\r
\r
Joe.\r
"
    .to_vec()
}
