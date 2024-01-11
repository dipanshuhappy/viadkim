pub mod common;

use common::MockLookup;
use std::{io::ErrorKind, str::FromStr};
use viadkim::{
    header::{FieldBody, FieldName, HeaderFields},
    signature::{DomainName, Selector, SigningAlgorithm},
    signer::{BodyLength, SignRequest},
    verifier::VerificationStatus,
};

#[tokio::test]
async fn basic_verify() {
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

    let signing_key = common::read_signing_key("tests/keys/rsa2048.pem").await.unwrap();
    let req = SignRequest::new(
        DomainName::new("example.com").unwrap(),
        Selector::new("sel").unwrap(),
        SigningAlgorithm::RsaSha256,
        signing_key,
    );

    let sigs = common::sign(headers, &body, [req]).await;

    let sig = sigs.into_iter().next().unwrap().unwrap();

    let headers = common::prepend_header_field(sig.to_header_field(), make_header_fields());

    let config = Default::default();

    let sigs = common::verify(&resolver, &headers, &body, &config).await;

    let result = sigs.into_iter().next().unwrap();

    assert_eq!(result.status, VerificationStatus::Success);
}

#[tokio::test]
async fn limited_body_length() {
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
    let mut body = make_body();

    let signing_key = common::read_signing_key("tests/keys/rsa2048.pem").await.unwrap();
    let mut req = SignRequest::new(
        DomainName::new("example.com").unwrap(),
        Selector::new("sel").unwrap(),
        SigningAlgorithm::RsaSha256,
        signing_key,
    );

    req.body_length = BodyLength::MessageContent;

    let sigs = common::sign(headers, &body, [req]).await;

    let sig = sigs.into_iter().next().unwrap().unwrap();

    let headers = common::prepend_header_field(sig.to_header_field(), make_header_fields());

    let config = Default::default();

    body.extend(b"\r\n-- trailing content, ignored --\r\n");

    let sigs = common::verify(&resolver, &headers, &body, &config).await;

    let result = sigs.into_iter().next().unwrap();

    assert_eq!(result.status, VerificationStatus::Success);
}

fn make_header_fields() -> HeaderFields {
    let mut header_fields: Vec<_> = HeaderFields::from_str(
        "Message-ID: <1511928109048645963@gluet.ch>
Date: Fri, 9 Jun 2023 16:13:12 +0200
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Content-Disposition: inline
Content-Transfer-Encoding: 8bit
References: <4344283917108237944@example.com>
 <3993077819152979884@gluet.ch>
 <3209900529850518454@example.com>
In-Reply-To: <3209900529850518454@example.com>
From: me <me@gluet.ch>
To: you@example.com",
    ) 
    .unwrap()
    .into();

    // include invalid UTF-8 in Subject for fun
    header_fields.push((
        FieldName::new("Subject").unwrap(),
        FieldBody::new(*b" wie gohts dr R\xfcdis\xfcli?").unwrap(),
    ));

    HeaderFields::new(header_fields).unwrap()
}

fn make_body() -> Vec<u8> {
    "Hallo!

Here is some trailing whitespace:  
  <- and some leading whitespace
𝔍nclude some Unicode emojis 🕊 💜
all just to exercise the c14n algorithm a bit.

Das wars!

Tschüss,
"
    .replace('\n', "\r\n")
    .bytes()
    .collect()
}
