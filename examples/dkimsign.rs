use std::{env, process};
use tokio::fs;
use viadkim::{
    crypto::{HashAlgorithm, SigningKey},
    header::HeaderFields,
    signature::{DomainName, Selector, SignatureAlgorithm},
    signer::{Signer, SigningRequest, SigningStatus},
};

#[tokio::main]
async fn main() {
    let _ = tracing_subscriber::fmt::try_init();

    let mut args = env::args();

    let (domain, selector, keyfile, path) = match (
        args.next().as_deref(),
        args.next(),
        args.next(),
        args.next(),
        args.next(),
    ) {
        (_, Some(domain), Some(selector), Some(keyfile), Some(path)) => {
            (domain, selector, keyfile, path)
        }
        (program, ..) => {
            eprintln!(
                "usage: {} <domain> <selector> <keyfile> <path>",
                program.unwrap_or("dkimsign")
            );
            process::exit(1);
        }
    };

    let domain = DomainName::new(&domain).unwrap();
    let selector = Selector::new(&selector).unwrap();
    let keyfile = fs::read_to_string(keyfile).await.unwrap();
    let signing_key = SigningKey::from_pkcs8_pem(&keyfile).unwrap();
    let signature_alg = SignatureAlgorithm::from_parts(signing_key.to_key_type(), HashAlgorithm::Sha256).unwrap();

    let request = SigningRequest::new(domain, selector, signature_alg, signing_key);

    let s = fs::read_to_string(path).await.unwrap();

    let s = s.replace('\n', "\r\n");

    let (header, body) = s.split_once("\r\n\r\n").unwrap();

    // TODO XXX

    let mut headers = vec![];
    let mut current_line = "".to_owned();
    for (i, header_line) in header.lines().enumerate() {
        if header_line.starts_with(' ') || header_line.starts_with('\t') {
            current_line.push_str("\r\n");
            current_line.push_str(header_line);
        } else {
            if i != 0 {
                let s = std::mem::take(&mut current_line);
                let (name, value) = s.split_once(':').unwrap();
                headers.push((name.to_owned(), value.as_bytes().to_vec()));
            }
            current_line.push_str(header_line);
        }
    }
    let s = std::mem::take(&mut current_line);
    let (name, value) = s.split_once(':').unwrap();
    headers.push((name.to_owned(), value.as_bytes().to_vec()));

    let headers = HeaderFields::from_vec(headers).unwrap();

    // dbg!(&headers);

    let mut signer = Signer::prepare_signing([request], headers).unwrap();

    let _ = signer.body_chunk(body.as_bytes());

    let sigs = signer.finish().await;

    for (_i, sig) in sigs.into_iter().enumerate() {
        println!();
        match sig.status {
            SigningStatus::Success {
                signature: _sig,
                header_name,
                header_value,
            } => {
                println!("{header_name}:{header_value}");
            }
            SigningStatus::Error { error } => {
                println!("ERROR: {error:?}");
            }
        }
    }
}
