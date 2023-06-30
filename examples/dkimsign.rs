use std::{env, process};
use tokio::{
    fs,
    io::{self, AsyncReadExt},
};
use viadkim::{
    crypto::{HashAlgorithm, SigningKey},
    signature::{DomainName, Selector, SignatureAlgorithm},
    signer::{SignRequest, SignResult, Signer},
};

#[tokio::main]
async fn main() {
    let _ = tracing_subscriber::fmt::try_init();

    let mut args = env::args();

    let (key_file, domain, selector) = match (
        args.next().as_deref(),
        args.next(),
        args.next(),
        args.next(),
        args.next(),
    ) {
        (_, Some(key_file), Some(domain), Some(selector), None) => (key_file, domain, selector),
        (program, ..) => {
            eprintln!("usage: {} <key_file> <domain> <selector>", program.unwrap_or("dkimsign"));
            process::exit(1);
        }
    };

    let key_file = fs::read_to_string(key_file).await.unwrap();
    let domain = DomainName::new(domain).unwrap();
    let selector = Selector::new(selector).unwrap();

    let signing_key = SigningKey::from_pkcs8_pem(&key_file).unwrap();
    let algorithm = SignatureAlgorithm::from_parts(signing_key.key_type(), HashAlgorithm::Sha256).unwrap();

    let mut request = SignRequest::new(domain, selector, algorithm, signing_key);
    request.valid_duration = None;
    request.copy_headers = false;
    // request.body_length = viadkim::signer::BodyLength::OnlyMessageLength;
    // request.identity = Some(viadkim::signature::Identity::new("\"abc|;de\"@中文.gluet.ch").unwrap());
    // request.algorithm = SignatureAlgorithm::RsaSha1;
    // request.format.tag_order = Some(Box::new(|a, b| a.cmp(b)));
    // request.format.line_width = 64.try_into().unwrap();
    // request.format.indentation = "  ".into();
    // request.ext_tags = vec![("r".into(), "y".into())];

    let mut msg = String::new();
    let n = io::stdin().read_to_string(&mut msg).await.unwrap();
    assert!(n > 0, "empty message on stdin");

    let msg = msg.replace('\n', "\r\n");

    let (header, body) = msg.split_once("\r\n\r\n").unwrap();

    let headers = header.parse().unwrap();
    // dbg!(&headers);

    let mut signer = Signer::prepare_signing(headers, [request]).unwrap();

    let _ = signer.process_body_chunk(body.as_bytes());

    let sigs = signer.sign().await;

    for (_i, result) in sigs.into_iter().enumerate() {
        match result {
            Ok(result) => {
                let SignResult { header_name, header_value, .. } = result;
                let header_value = header_value.replace("\r\n", "\n");
                println!("{header_name}:{header_value}");
            }
            Err(e) => {
                println!("ERROR: {e:?}");
            }
        }
    }
}
