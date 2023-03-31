use std::{env, process};
use tokio::io::{self, AsyncReadExt};
use trust_dns_resolver::TokioAsyncResolver;
use viadkim::{header, verifier::Config, Verifier};

#[tokio::main]
async fn main() {
    let _ = tracing_subscriber::fmt::try_init();

    let mut args = env::args();

    match (args.next().as_deref(), args.next()) {
        (_, None) => {}
        (program, ..) => {
            eprintln!("usage: {}", program.unwrap_or("dkimverify"));
            process::exit(1);
        }
    }

    let mut msg = String::new();
    let n = io::stdin().read_to_string(&mut msg).await.unwrap();
    assert!(n > 0, "empty message on stdin");

    let msg = msg.replace('\n', "\r\n");

    let (header, body) = msg.split_once("\r\n\r\n").unwrap();

    let headers = header::parse_header(header).unwrap();
    // dbg!(&headers);

    let resolver = TokioAsyncResolver::tokio(Default::default(), Default::default()).unwrap();

    let config = Config {
        fail_if_expired: false,
        ..Default::default()
    };

    let mut verifier = Verifier::process_header(&resolver, &headers, &config)
        .await
        .unwrap();

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
