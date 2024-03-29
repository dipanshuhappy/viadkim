use hickory_resolver::TokioAsyncResolver;
use std::{env, process};
use tokio::io::{self, AsyncReadExt};
use viadkim::{Config, Verifier};

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

    let headers = header.parse().unwrap();

    let resolver = TokioAsyncResolver::tokio(Default::default(), Default::default());

    let config = Config {
        allow_expired: true,
        allow_timestamp_in_future: true,
        //
        // Experiment with the various configuration options here.
        //
        // max_signatures: 5,
        // allow_sha1: true,
        // min_key_bits: 512,
        ..Default::default()
    };

    let mut verifier = Verifier::verify_header(&resolver, &headers, &config)
        .await
        .unwrap();

    let _ = verifier.process_body_chunk(body.as_bytes());

    let sigs = verifier.finish();

    for (i, sig) in sigs.into_iter().enumerate() {
        println!();
        println!("SIGNATURE {}", i + 1);
        println!("{sig:#?}");
    }
}
