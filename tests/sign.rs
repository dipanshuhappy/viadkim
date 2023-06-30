pub mod common;

use std::str::FromStr;
use viadkim::{
    header::{FieldBody, FieldName, HeaderFields},
    signature::{CanonicalizationAlgorithm, DomainName, Selector, SignatureAlgorithm},
    signer::{SignRequest, Timestamp},
};

// TODO idea: sign msg with opendkim, compare or verify with viadkim?

#[tokio::test]
async fn basic_sign() {
    use CanonicalizationAlgorithm::*;

    let _ = tracing_subscriber::fmt::try_init();

    let headers = make_header_fields();
    let body = make_body();

    let signing_key = common::read_signing_key_from_file("tests/keys/rsa2048.pem").await.unwrap();
    let mut request = SignRequest::new(
        DomainName::new("example.com").unwrap(),
        Selector::new("sel").unwrap(),
        SignatureAlgorithm::RsaSha256,
        signing_key,
    );

    request.canonicalization = (Relaxed, Relaxed).into();
    request.timestamp = Some(Timestamp::Exact(1686737001));
    request.valid_duration = None;
    request.format.header_name = "DKiM-Signature".into();
    request.format.line_width = 64.try_into().unwrap();
    request.format.indentation = "  ".into();
    request.format.tag_order = Some(Box::new(Ord::cmp));

    let sigs = common::sign(headers, &body, [request]).await;

    assert_eq!(sigs.len(), 1);

    let sig = sigs.into_iter().next().unwrap().unwrap();

    assert_eq!(
        sig.format_header().to_string(),
        "\
DKiM-Signature: a=rsa-sha256; b=litEQ1zgN91wbbXy4cA4KoYXMICLLq68\r
  0Nx344mTgELlzZ7nbO3CnFmjKOl2RxW+bhH4sroTS5LfPjc7zMgBAkoydza+Q6\r
  bSSfed2/iU16JTvKdCtmuw5UoyEVhgja+VrORA/dEp6yJ7T8N+FAz7rVFLsass\r
  hBYNu+hixg7DbMYBklOocU8OezNPB8kIg0T1lNP4dD3futrYuQiCYE+gxV20wK\r
  jacmjK7axG5tdx2UjeWq8nQezcvuPaoiQivJavxOPXluJNTGISUafTFKZt7tIW\r
  ADu69AYdrlM9wY7udiT/wsh0ErI1EM3cetFozOuj7cPweq1gU1XH63lSji/mAQ\r
  ==; bh=i9bmAkqhhUlk6na4gb+reyESFnAbREglMDib/b+U2Qk=;\r
  c=relaxed/relaxed; d=example.com; h=Subject:To:From:\r
  In-Reply-To:References:Date; s=sel; t=1686737001; v=1"
    );
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
