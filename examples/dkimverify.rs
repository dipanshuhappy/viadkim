use std::{env, process};
use tokio::fs;
use trust_dns_resolver::TokioAsyncResolver;
use viadkim::{HeaderFields, Verifier};

#[tokio::main]
async fn main() {
    // let _ = tracing_subscriber::fmt::try_init();
    let mut args = env::args();

    let path = match (args.next().as_deref(), args.next()) {
        (_, Some(path)) => path,
        (program, ..) => {
            eprintln!("usage: {} <path>", program.unwrap_or("dkimverify"));
            process::exit(1);
        }
    };

    let s = fs::read_to_string(path).await.unwrap();

    let s = s.replace("\n", "\r\n");

    let (header, body) = s.split_once("\r\n\r\n").unwrap();

    // TODO
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

    let resolver = TokioAsyncResolver::tokio(Default::default(), Default::default()).unwrap();

    let config = Default::default();

    let mut verifier = Verifier::process_headers(&resolver, &headers, &config).await;

    let _ = verifier.body_chunk(body.as_bytes());

    let sigs = verifier.finish();

    for (i, sig) in sigs.into_iter().enumerate() {
        let h = sig.signature;
        let s = sig.status;
        println!();
        println!("SIGNATURE {}", i + 1);
        println!("{h:#?}");
        println!("{s:?}");
    }
}
