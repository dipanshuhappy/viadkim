pub mod common;

use common::MockLookup;
use std::{io::ErrorKind, str::FromStr};
use viadkim::{
    header::{FieldBody, FieldName, HeaderFields},
    signature::{DomainName, Selector, SigningAlgorithm},
    signer::SignRequest,
    verifier::{VerificationError, VerificationStatus},
};

// These tests check behaviour with and without feature pre-rfc8301.

#[cfg(feature = "pre-rfc8301")]
#[tokio::test]
async fn key_512_basic() {
    use viadkim::verifier::{Config, PolicyError};

    let _ = tracing_subscriber::fmt::try_init();

    let headers = make_header_fields();
    let body = make_body();

    let signing_key = common::read_signing_key_from_file("tests/keys/rsa512.pem")
        .await
        .unwrap();
    let request = SignRequest::new(
        DomainName::new("example.com").unwrap(),
        Selector::new("sel").unwrap(),
        SigningAlgorithm::RsaSha256,
        signing_key,
    );

    let sigs = common::sign(headers, &body, [request]).await;

    let sig = sigs.into_iter().next().unwrap().unwrap();

    let headers = common::prepend_header_field(sig.to_header_field(), make_header_fields());

    let resolver = MockLookup::new(|name| {
        Box::pin(async move {
            match name {
                "sel._domainkey.example.com." => {
                    let base64 =
                        common::read_public_key_file_base64("tests/keys/rsa512pub.pem").await?;
                    Ok(vec![Ok(format!("v=DKIM1; k=rsa; p={base64}").into())])
                }
                _ => Err(ErrorKind::NotFound.into()),
            }
        })
    });

    let config = Default::default();

    let sigs = common::verify(&resolver, &headers, &body, &config).await;

    let result = sigs.into_iter().next().unwrap();

    assert_eq!(
        result.status,
        VerificationStatus::Failure(VerificationError::Policy(PolicyError::KeyTooSmall))
    );

    let config = Config {
        min_key_bits: 512,
        ..Default::default()
    };

    let sigs = common::verify(&resolver, &headers, &body, &config).await;

    let result = sigs.into_iter().next().unwrap();

    assert_eq!(result.status, VerificationStatus::Success);
}

#[cfg(not(feature = "pre-rfc8301"))]
#[tokio::test]
async fn key_512_basic() {
    use viadkim::crypto;

    let _ = tracing_subscriber::fmt::try_init();

    let headers = make_header_fields();
    let body = make_body();

    let signing_key = common::read_signing_key_from_file("tests/keys/rsa512.pem")
        .await
        .unwrap();
    let request = SignRequest::new(
        DomainName::new("example.com").unwrap(),
        Selector::new("sel").unwrap(),
        SigningAlgorithm::RsaSha256,
        signing_key,
    );

    let sigs = common::sign(headers, &body, [request]).await;

    let sig = sigs.into_iter().next().unwrap().unwrap();

    let headers = common::prepend_header_field(sig.to_header_field(), make_header_fields());

    let resolver = MockLookup::new(|name| {
        Box::pin(async move {
            match name {
                "sel._domainkey.example.com." => {
                    let base64 =
                        common::read_public_key_file_base64("tests/keys/rsa512pub.pem").await?;
                    Ok(vec![Ok(format!("v=DKIM1; k=rsa; p={base64}").into())])
                }
                _ => Err(ErrorKind::NotFound.into()),
            }
        })
    });

    let config = Default::default();

    let sigs = common::verify(&resolver, &headers, &body, &config).await;

    let result = sigs.into_iter().next().unwrap();

    assert_eq!(
        result.status,
        VerificationStatus::Failure(VerificationError::VerificationFailure(
            crypto::VerificationError::InsufficientKeySize
        ))
    );
}

#[cfg(feature = "pre-rfc8301")]
#[tokio::test]
async fn sha1_basic() {
    use viadkim::verifier::{Config, PolicyError};

    let _ = tracing_subscriber::fmt::try_init();

    let headers = make_header_fields();
    let body = make_body();

    let signing_key = common::read_signing_key_from_file("tests/keys/rsa1024.pem")
        .await
        .unwrap();
    let request = SignRequest::new(
        DomainName::new("example.com").unwrap(),
        Selector::new("sel").unwrap(),
        SigningAlgorithm::RsaSha1,
        signing_key,
    );

    let sigs = common::sign(headers, &body, [request]).await;

    let sig = sigs.into_iter().next().unwrap().unwrap();

    let headers = common::prepend_header_field(sig.to_header_field(), make_header_fields());

    let resolver = MockLookup::new(|name| {
        Box::pin(async move {
            match name {
                "sel._domainkey.example.com." => {
                    let base64 =
                        common::read_public_key_file_base64("tests/keys/rsa1024pub.pem").await?;
                    Ok(vec![Ok(format!("v=DKIM1; k=rsa; p={base64}").into())])
                }
                _ => Err(ErrorKind::NotFound.into()),
            }
        })
    });

    let config = Default::default();

    let sigs = common::verify(&resolver, &headers, &body, &config).await;

    let result = sigs.into_iter().next().unwrap();

    assert_eq!(
        result.status,
        VerificationStatus::Failure(VerificationError::Policy(PolicyError::Sha1HashAlgorithm))
    );

    let config = Config {
        allow_sha1: true,
        ..Default::default()
    };

    let sigs = common::verify(&resolver, &headers, &body, &config).await;

    let result = sigs.into_iter().next().unwrap();

    assert_eq!(result.status, VerificationStatus::Success);
}

#[cfg(not(feature = "pre-rfc8301"))]
#[tokio::test]
async fn sha1_basic() {
    use viadkim::signature::DkimSignatureErrorKind;

    let _ = tracing_subscriber::fmt::try_init();

    let body = make_body();

    let name = FieldName::new("DKIM-Signature").unwrap();
    let value = FieldBody::new(
        *b" v=1; d=example.com; s=sel; a=rsa-sha1; t=1687794684;\r
\th=Subject:To:From:In-Reply-To:References:Date; bh=MXqKrb5jreQOzPjHMEfbuldBxU8\r
\t=; b=JxWc1tmeyfhtffOkn0p/9tZeAZ91vl/KuxuixeiAA33N9hxv5OVQPfBV88L3/r5WbZiKOcMc\r
\tLfl9jL9J91ijWcHdVo2l8e7s8Fh3IluGPIgGaVb1Meaa2LQ8894i0xGvRA8V5CPaq8DF3KG3Rkjqy\r
\tczZsfxAdaIgp63QvBsxm/Q=",
    )
    .unwrap();

    let headers = common::prepend_header_field((name, value), make_header_fields());

    let resolver = MockLookup::new(|name| {
        Box::pin(async move {
            match name {
                "sel._domainkey.example.com." => {
                    let base64 =
                        common::read_public_key_file_base64("tests/keys/rsa1024pub.pem").await?;
                    Ok(vec![Ok(format!("v=DKIM1; k=rsa; p={base64}").into())])
                }
                _ => Err(ErrorKind::NotFound.into()),
            }
        })
    });

    let config = Default::default();

    let sigs = common::verify(&resolver, &headers, &body, &config).await;

    let result = sigs.into_iter().next().unwrap();

    match result.status {
        VerificationStatus::Failure(VerificationError::DkimSignatureFormat(e)) => {
            assert_eq!(e.kind, DkimSignatureErrorKind::HistoricAlgorithm);
        }
        _ => panic!(),
    }
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
