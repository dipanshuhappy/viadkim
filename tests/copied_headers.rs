pub mod common;

use common::MockLookup;
use std::io::ErrorKind;
use viadkim::{
    header::{FieldBody, FieldName, HeaderFields},
    signature::{DomainName, Selector, SignatureAlgorithm},
    signer::{HeaderSelection, SignRequest},
    verifier::VerificationStatus,
};

// This test shows how z= can record the original, unmodified header.

#[tokio::test]
async fn copied_headers_ok() {
    let _ = tracing_subscriber::fmt::try_init();

    let resolver = MockLookup::new(|name| {
        Box::pin(async move {
            match name {
                "sel._domainkey.example.com." => {
                    let base64 =
                        common::read_public_key_file_base64("tests/keys/rsa2048pub.pem").await?;
                    Ok(vec![Ok(format!("v=DKIM1; k=rsa; p={base64}").into())])
                }
                _ => Err(ErrorKind::NotFound.into()),
            }
        })
    });

    let headers = make_header_fields();
    let body = make_body();

    // First, sign the message properly

    let signing_key = common::read_signing_key_from_file("tests/keys/rsa2048.pem").await.unwrap();
    let mut req = SignRequest::new(
        DomainName::new("example.com").unwrap(),
        Selector::new("sel").unwrap(),
        SignatureAlgorithm::RsaSha256,
        signing_key,
    );

    req.header_selection = HeaderSelection::Manual(vec![
        FieldName::new("Subject").unwrap(),
        FieldName::new("To").unwrap(),
        FieldName::new("From").unwrap(),
    ]);
    req.copy_headers = true;

    let sigs = common::sign(headers, &body, [req]).await;

    let sig = sigs.into_iter().next().unwrap().unwrap();

    // Verify with modified headers

    let mut headers = vec![sig.to_header_field()];
    let x = make_header_fields().into_iter().map(|(name, value)| {
        if name.as_ref() == "Subject" {
            (name, FieldBody::new(*b" REPLACED").unwrap())
        } else {
            (name, value)
        }
    });
    headers.extend(x);
    let headers = HeaderFields::new(headers).unwrap();

    let config = Default::default();

    let sigs = common::verify(&resolver, &headers, &body, &config).await;

    let result = sigs.into_iter().next().unwrap();

    assert!(matches!(result.status, VerificationStatus::Failure(_)));

    // Verify again, but now providing original headers from z=

    let mut headers = vec![sig.to_header_field()];
    let x = sig
        .signature
        .copied_headers
        .iter()
        .map(|(name, value)| (name.clone(), FieldBody::new(&value[..]).unwrap()));
    headers.extend(x);
    let headers = HeaderFields::new(headers).unwrap();

    let sigs = common::verify(&resolver, &headers, &body, &config).await;

    let result = sigs.into_iter().next().unwrap();

    assert_eq!(result.status, VerificationStatus::Success);
}

fn make_header_fields() -> HeaderFields {
    "From: me
To: you
Subject: how are you"
        .parse()
        .unwrap()
}

fn make_body() -> Vec<u8> {
    "Hello dearie,
how goes it?

Gruesse
"
    .replace('\n', "\r\n")
    .bytes()
    .collect()
}
