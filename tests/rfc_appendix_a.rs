pub mod common;

use common::MockLookup;
use std::{collections::HashSet, io::ErrorKind};
use viadkim::{
    header::{FieldName, HeaderFields},
    signature::{DomainName, Selector, SigningAlgorithm},
    signer::{self, HeaderSelection, SignRequest},
    verifier::VerificationStatus,
};

/// Example from RFC 6376, appendix A.2, with public key in RSAPublicKey format.
#[tokio::test]
async fn rfc_appendix_a_rsa() {
    let _ = tracing_subscriber::fmt::try_init();

    let resolver = make_resolver_rsa();
    let headers = make_header_fields();
    let config = Default::default();

    let body = make_body();

    let sigs = common::verify(&resolver, &headers, &body, &config).await;

    let result = sigs.into_iter().next().unwrap();

    assert_eq!(result.status, VerificationStatus::Success);
}

/// Example from RFC 6376, appendix A.2, with public key in SPKI format.
#[tokio::test]
async fn rfc_appendix_a_spki() {
    let _ = tracing_subscriber::fmt::try_init();

    let resolver = make_resolver_spki();
    let headers = make_header_fields();
    let config = Default::default();

    let body = make_body();

    let sigs = common::verify(&resolver, &headers, &body, &config).await;

    let result = sigs.into_iter().next().unwrap();

    assert_eq!(result.status, VerificationStatus::Success);
}

/// Sign as in example from RFC 6376, appendix A.2, with private key shown
/// there, then verify result.
#[tokio::test]
async fn sign_roundtrip() {
    let _ = tracing_subscriber::fmt::try_init();

    let headers = make_header_fields();
    let body = make_body();

    let signing_key = common::read_signing_key("tests/keys/brisbane_private.pem").await.unwrap();
    let mut req = SignRequest::new(
        DomainName::new("example.com").unwrap(),
        Selector::new("brisbane").unwrap(),
        SigningAlgorithm::RsaSha256,
        signing_key,
    );

    let def = HashSet::from([
        FieldName::new("Received").unwrap(),
        FieldName::new("From").unwrap(),
        FieldName::new("To").unwrap(),
        FieldName::new("Subject").unwrap(),
        FieldName::new("Date").unwrap(),
        FieldName::new("Message-ID").unwrap(),
    ]);
    let signed_headers = signer::select_headers(&headers, move |name| def.contains(name));

    req.header_selection = HeaderSelection::Manual(signed_headers.cloned().collect());

    let sigs = common::sign(headers, &body, [req]).await;

    let sign_result = sigs.into_iter().next().unwrap().unwrap();

    let resolver = make_resolver_spki();
    let config = Default::default();

    let headers = common::prepend_header_field(sign_result.to_header_field(), make_header_fields());

    let sigs = common::verify(&resolver, &headers, &body, &config).await;

    let result = sigs.into_iter().next().unwrap();

    assert_eq!(result.status, VerificationStatus::Success);
}

fn make_resolver_rsa() -> MockLookup {
    MockLookup::new(|name| {
        Box::pin(async move {
            match name {
                "brisbane._domainkey.example.com." => {
                    let base64 =
                        common::read_public_key_file_base64("tests/keys/brisbane_rsa.pem").await?;
                    Ok(vec![Ok(format!("v=DKIM1; k=rsa; p={base64}").into())])
                }
                _ => Err(ErrorKind::NotFound.into()),
            }
        })
    })
}

fn make_resolver_spki() -> MockLookup {
    MockLookup::new(|name| {
        Box::pin(async move {
            match name {
                "brisbane._domainkey.example.com." => {
                    let base64 =
                        common::read_public_key_file_base64("tests/keys/brisbane_spki.pem").await?;
                    Ok(vec![Ok(format!("v=DKIM1; k=rsa; p={base64}").into())])
                }
                _ => Err(ErrorKind::NotFound.into()),
            }
        })
    })
}

// Note RFC 6376, erratum 4926!
fn make_header_fields() -> HeaderFields {
    "\
DKIM-Signature: v=1; a=rsa-sha256; s=brisbane; d=example.com;
      c=simple/simple; q=dns/txt; i=joe@football.example.com;
      h=Received : From : To : Subject : Date : Message-ID;
      bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
      b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB
        4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut
        KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV
        4bmp/YzhwvcubU4=;
Received: from client1.football.example.com  [192.0.2.1]
      by submitserver.example.com with SUBMISSION;
      Fri, 11 Jul 2003 21:01:54 -0700 (PDT)
From: Joe SixPack <joe@football.example.com>
To: Suzie Q <suzie@shopping.example.net>
Subject: Is dinner ready?
Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
Message-ID: <20030712040037.46341.5F8J@football.example.com>
"
    .parse()
    .unwrap()
}

// Note RFC 6376, erratum 3192!
fn make_body() -> Vec<u8> {
    "Hi.

We lost the game. Are you hungry yet?

Joe.
"
    .replace('\n', "\r\n")
    .bytes()
    .collect()
}
