pub mod common;

use common::MockLookup;
use std::{
    io::ErrorKind,
    str::{self, FromStr},
};
use viadkim::{
    canonicalize::{self, BodyCanonicalizer},
    crypto::{self, HashAlgorithm, KeyType, SigningKey},
    header::{FieldBody, FieldName, HeaderFields},
    quoted_printable,
    record::DkimKeyRecord,
    signature::{
        CanonicalizationAlgorithm, DkimSignature, DomainName, Selector, SigningAlgorithm,
        DKIM_SIGNATURE_NAME,
    },
    signer::{HeaderSelection, SignRequest},
    verifier::{LookupTxt, VerificationStatus},
};

// These tests exercise the low-level APIs, signing and verifying without going
// through `Signer` or `Verifier`.

#[tokio::test]
async fn low_level_sign() {
    let _ = tracing_subscriber::fmt::try_init();

    let headers = make_header_fields();
    let body = make_body();

    let hash_alg = HashAlgorithm::Sha256;
    let canon_alg = CanonicalizationAlgorithm::Relaxed;

    // canonicalize body and hash it
    let mut bc = BodyCanonicalizer::new(canon_alg);
    let mut cbody = bc.canonicalize_chunk(&body[..]);
    cbody.extend(bc.finish());
    let body_hash1 = crypto::digest(hash_alg, &cbody);

    let body_hash = viadkim::encode_base64(body_hash1);

    let ident = quoted_printable::encode(b"\"me;you\"@sub.example.com", None);

    let sig_name = "DKIM-Signature";
    let mut sig_value = format!(
        " v = 1 ;\r\n \
        i={ident}; d=Example.Com; s=Sel1;\r\n \
        h=From : To;\r\n \
        a\r\n =\r\n Rsa-Sha256\r\n ; c=Relaxed/Relaxed; bh={body_hash}; b="
    );

    let selected_headers = [
        FieldName::new("From").unwrap(),
        FieldName::new("To").unwrap(),
    ];

    // compute data hash

    let mut cheaders = canonicalize::canonicalize_headers(canon_alg, &headers, &selected_headers);

    canonicalize::canonicalize_header(&mut cheaders, canon_alg, sig_name, &sig_value);

    let data_hash = crypto::digest(hash_alg, &cheaders);

    // sign data hash

    let signing_key = common::read_signing_key("tests/keys/rsa2048.pem")
        .await
        .unwrap();
    let signature = match &signing_key {
        SigningKey::Rsa(k) => crypto::sign_rsa(hash_alg, k, &data_hash).unwrap(),
        _ => panic!(),
    };

    // append to sig_value

    let s = viadkim::encode_base64(signature);

    sig_value.push_str(&s);

    let headers = common::prepend_header_field(
        (
            FieldName::new(sig_name).unwrap(),
            FieldBody::new(sig_value.as_bytes()).unwrap(),
        ),
        headers,
    );

    // afterwards verify with high-level Verifier to see if it works

    let resolver = MockLookup::new(|name| {
        Box::pin(async move {
            match name {
                "sel1._domainkey.example.com." => {
                    let base64 =
                        common::read_public_key_file_base64("tests/keys/rsa2048pub.pem").await?;
                    Ok(vec![Ok(format!("v=DKIM1; k=rsa; p={base64}").into())])
                }
                _ => Err(ErrorKind::NotFound.into()),
            }
        })
    });

    let config = Default::default();

    let sigs = common::verify(&resolver, &headers, &body, &config).await;

    let result = sigs.into_iter().next().unwrap();

    assert_eq!(result.status, VerificationStatus::Success);
}

#[tokio::test]
async fn low_level_verify() {
    let _ = tracing_subscriber::fmt::try_init();

    let headers = make_header_fields();
    let body = make_body();

    // first sign message with high-level Signer

    let signing_key = common::read_signing_key("tests/keys/rsa2048.pem")
        .await
        .unwrap();
    let mut req = SignRequest::new(
        DomainName::new("example.com").unwrap(),
        Selector::new("sel1").unwrap(),
        SigningAlgorithm::RsaSha256,
        signing_key,
    );

    req.header_selection = HeaderSelection::Manual(vec![
        FieldName::new("From").unwrap(),
        FieldName::new("To").unwrap(),
    ]);

    let sigs = common::sign(headers, &body, [req]).await;

    let sig = sigs.into_iter().next().unwrap().unwrap();

    let headers = common::prepend_header_field(sig.to_header_field(), make_header_fields());

    // now verify using low-level APIs

    // extract and parse signature

    let sig = headers
        .as_ref()
        .iter()
        .find(|(name, _)| *name == DKIM_SIGNATURE_NAME)
        .unwrap();

    let sig_name = &sig.0;
    let sig_value = str::from_utf8(sig.1.as_ref()).unwrap();

    let sig = DkimSignature::from_str(sig_value).unwrap();

    let alg = sig.algorithm;
    let hash_alg = alg.hash_algorithm();
    let canon = sig.canonicalization;

    // calculate body hash

    let mut bc = BodyCanonicalizer::new(canon.body);
    let mut cbody = bc.canonicalize_chunk(&body[..]);
    cbody.extend(bc.finish());
    let body_hash = crypto::digest(hash_alg, &cbody);

    assert_eq!(body_hash, sig.body_hash);

    // get public key

    let resolver = MockLookup::new(|name| {
        Box::pin(async move {
            match name {
                "sel1._domainkey.example.com." => {
                    let base64 =
                        common::read_public_key_file_base64("tests/keys/rsa2048pub.pem").await?;
                    Ok(vec![Ok(format!("v=DKIM1; k=rsa; p={base64}").into())])
                }
                _ => Err(ErrorKind::NotFound.into()),
            }
        })
    });

    let selector = sig.selector.to_ascii();
    let domain = sig.domain.to_ascii();
    let domain = format!("{selector}._domainkey.{domain}.");
    let result = resolver.lookup_txt(&domain).await.unwrap();

    let record = result.into_iter().next().unwrap().unwrap();
    let record = str::from_utf8(&record).unwrap();

    let record = DkimKeyRecord::from_str(record).unwrap();

    assert_eq!(record.key_type, KeyType::Rsa);

    let pubkey = crypto::read_rsa_public_key(&record.key_data).unwrap();

    // calculate data hash

    let canon_alg = canon.header;

    let mut cheaders = canonicalize::canonicalize_headers(canon_alg, &headers, &sig.signed_headers);

    // strip b= value from sig_value:
    let i = sig_value.rfind("b=").unwrap();
    canonicalize::canonicalize_header(&mut cheaders, canon_alg, sig_name, &sig_value[..i + 2]);

    let data_hash = crypto::digest(hash_alg, &cheaders);

    // verify hash

    assert!(crypto::verify_rsa(&pubkey, hash_alg, &data_hash, &sig.signature_data).is_ok());
}

fn make_header_fields() -> HeaderFields {
    "Message-ID: <1511928109048645963@gluet.ch>
Date: Fri, 9 Jun 2023 16:13:12 +0200
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Content-Disposition: inline
Content-Transfer-Encoding: 8bit
From: me <me@gluet.ch>
To: you@example.com"
        .parse()
        .unwrap()
}

fn make_body() -> Vec<u8> {
    "Hello!

How are you?

Ciao,
Your friend

"
    .replace('\n', "\r\n")
    .bytes()
    .collect()
}
