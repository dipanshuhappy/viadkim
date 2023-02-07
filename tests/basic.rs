use trust_dns_resolver::TokioAsyncResolver;
use viadkim::{HeaderFields, Verifier};

// TODO
#[tokio::test]
#[ignore = "TODO"]
async fn basic_verify() {
    let _ = tracing_subscriber::fmt::try_init();

    let resolver = TokioAsyncResolver::tokio(Default::default(), Default::default()).unwrap();

    let headers: Vec<(String, Vec<u8>)> = vec![
        ("From".into(), b" me <here@now.com>".to_vec()),
        ("To".into(), b" you <there@then.com>".to_vec()),
    ];
    let headers = HeaderFields::from_vec(headers).unwrap();

    let config = Default::default();

    let mut verifier = Verifier::process_headers(&resolver, &headers, &config).await;

    verifier.body_chunk(b"how is it going\r\n");

    let sigs = verifier.finish();

    assert!(sigs.is_empty());
}
