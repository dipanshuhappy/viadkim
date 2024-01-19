// viadkim – implementation of the DKIM specification
// Copyright © 2022–2023 David Bürgin <dbuergin@gluet.ch>
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.

use crate::{
    signature::{DomainName, Selector},
    verifier::{
        header::{VerifyStatus, VerifyTask},
        Config, LookupTxt,
    },
};
use std::{
    collections::{HashMap, HashSet, BTreeSet},
    io::{self, ErrorKind},
};
use tokio::{task::JoinSet, time};
use tracing::trace;

struct QueriesBuilder {
    // A-label form domain/selector, mapped to collection of signature header indexes
    lookup_pairs: HashMap<(String, String), HashSet<usize>>,
}

impl QueriesBuilder {
    fn new() -> Self {
        Self {
            lookup_pairs: HashMap::new(),
        }
    }

    fn add_lookup(&mut self, domain: &DomainName, selector: &Selector, index: usize) {
        let domain = domain.to_ascii();
        let selector = selector.to_ascii();

        self.lookup_pairs
            .entry((domain, selector))
            .or_default()
            .insert(index);
    }

    async fn spawn_all<T>(self, resolver: &T, config: &Config) -> Queries
    where
        T: LookupTxt + Clone + 'static,
    {
        let mut set = Vec::new();

        for ((domain, selector), indexes) in self.lookup_pairs {
            trace!(%domain, %selector, "spawning DNS query");

            let resolver = resolver.clone();

            let lookup_timeout = config.lookup_timeout;

            // set.spawn(async move {
            //     let f = look_up_records(&resolver, domain.as_ref(), selector.as_ref());
                // let result = match time::timeout(lookup_timeout, f).await {
                //     Ok(r) => r,
                //     Err(e) => Err(e.into()),
                // };

            //     (indexes, result)
            // });

            let f = look_up_records(&resolver,domain.as_ref(),selector.as_ref()).await;
            // let f = look_up_records(&resolver, domain.as_ref(), selector.as_ref());
            // let result = match time::timeout(lookup_timeout, f).await {
            //             Ok(r) => r,
            //             Err(e) => Err(e.into()),
            // };
            
            set.push(
                (indexes, f)
            );
        }


        Queries { set }
    }
}

pub type QueryResult = io::Result<Vec<io::Result<String>>>;

async fn look_up_records<T: LookupTxt + ?Sized>(
    resolver: &T,
    domain: &str,
    selector: &str,
) -> QueryResult {
    fn parse_utf8(txt: io::Result<Vec<u8>>) -> io::Result<String> {
        txt.and_then(|s| String::from_utf8(s).map_err(|_| ErrorKind::InvalidData.into()))
    }

    // Note the trailing dot: only absolute queries.
    let dname = format!("{selector}._domainkey.{domain}.");

    let txts = resolver.lookup_txt(&dname).await?;

    // §3.6.2.2: ‘TXT RRs MUST be unique for a particular selector name; […] if
    // there are multiple records in an RRset, the results are undefined.’
    // However, note §6.1.2: ‘If the query for the public key returns multiple
    // key records, the Verifier can choose one of the key records or may cycle
    // through the key records […]. The order of the key records is
    // unspecified.’ So, as a courtesy we do try at most three selected keys.
    // This is an implementation detail.

    let mut result = vec![];

    let mut last = None;
    for (i, txt) in txts.into_iter().enumerate() {
        if i < 2 {
            result.push(parse_utf8(txt));
        } else {
            last = Some(txt);
        }
    }
    if let Some(txt) = last {
        result.push(parse_utf8(txt));
    }

    Ok(result)
}


pub struct Queries {
    pub set: Vec<(HashSet<usize>, QueryResult)>,
}

impl Queries {
    pub async fn spawn<T>(tasks: &[VerifyTask], resolver: &T, config: &Config) -> Self
    where
        T: LookupTxt + Clone + 'static,
    {
        let mut builder = QueriesBuilder::new();

        // Register a lookup for each verification task that is still in
        // progress.
        for task in tasks {
            if let VerifyStatus::InProgress = &task.status {
                let sig: &crate::signature::DkimSignature = task.signature.as_ref()
                    .expect("signature of in-progress verification task not available");

                builder.add_lookup(&sig.domain, &sig.selector, task.index);
            }
        }

        builder.spawn_all(resolver, config).await
    }
}

// // #[cfg(test)]
// mod tests {
//     use super::*;
//     use std::{
//         future::Future,
//         io::{self, ErrorKind},
//         pin::Pin,
//     };
//     use tokio::time::Duration;

//     #[derive(Clone)]
//     struct MockLookupTxt;

//     impl LookupTxt for MockLookupTxt {
//         type Answer = Vec<io::Result<Vec<u8>>>;
//         type Query<'a> = Pin<Box<dyn Future<Output = io::Result<Self::Answer>> + Send + 'a>>;

//         fn lookup_txt(&self, domain: &str) -> Self::Query<'_> {
//             let domain = domain.to_owned();

//             Box::pin(async move {
//                 match domain.as_str() {
//                     "sel._domainkey.example.com." => {
//                         time::sleep(Duration::from_millis(300)).await;
//                         Ok(vec![
//                             Ok(b"one".to_vec()),
//                             Ok(b"two\xff\x00".to_vec()),
//                             Ok(b"three".to_vec()),
//                             Err(ErrorKind::Unsupported.into()),
//                         ])
//                     }
//                     "xn--9j8hqg._domainkey.example.xn--fiqs8s." => {
//                         time::sleep(Duration::from_millis(200)).await;
//                         Ok(vec![])
//                     }
//                     "err._domainkey.example.org." => {
//                         time::sleep(Duration::from_millis(100)).await;
//                         Err(ErrorKind::TimedOut.into())
//                     }
//                     _ => unimplemented!(),
//                 }
//             })
//         }
//     }

//     #[tokio::test]
//     async fn queries_spawn_ok() {
//         let domain_and_selector = |domain, selector| {
//             (
//                 DomainName::new(domain).unwrap(),
//                 Selector::new(selector).unwrap(),
//             )
//         };

//         let (d1, s1) = domain_and_selector("example.com", "sel");
//         let (d2, s2) = domain_and_selector("Example.中国", "xn--9j8hqg");
//         let (d3, s3) = domain_and_selector("eXample.xn--fiqs8s", "🎆🏮");
//         let (d4, s4) = domain_and_selector("example.org", "err");

//         let resolver = MockLookupTxt;
//         let config = Default::default();

//         let mut builder = QueriesBuilder::new();
//         builder.add_lookup(&d1, &s1, 1);
//         builder.add_lookup(&d2, &s2, 2);
//         builder.add_lookup(&d3, &s3, 3);
//         builder.add_lookup(&d4, &s4, 4);

//         time::pause();

//         let mut queries = builder.spawn_all(&resolver, &config);

//         let (indexes, result) = queries.set.join_next().await.unwrap().unwrap();
//         assert_eq!(indexes, HashSet::from([4]));
//         assert_eq!(result.unwrap_err().kind(), ErrorKind::TimedOut);

//         let (indexes, result) = queries.set.join_next().await.unwrap().unwrap();
//         assert_eq!(indexes, HashSet::from([2, 3]));
//         assert!(result.unwrap().is_empty());

//         let (indexes, result) = queries.set.join_next().await.unwrap().unwrap();
//         assert_eq!(indexes, HashSet::from([1]));

//         let txts = result.unwrap();

//         assert_eq!(txts.len(), 3);

//         let mut iter = txts.into_iter();
//         assert_eq!(iter.next().unwrap().unwrap(), "one");
//         assert_eq!(iter.next().unwrap().unwrap_err().kind(), ErrorKind::InvalidData);
//         assert_eq!(iter.next().unwrap().unwrap_err().kind(), ErrorKind::Unsupported);

//         time::resume();
//     }

//     #[cfg(feature = "hickory-resolver")]
//     #[tokio::test]
//     #[ignore = "depends on live DNS records"]
//     async fn look_up_live_dkim_key_record() {
//         use crate::record::DkimKeyRecord;
//         use hickory_resolver::TokioAsyncResolver;
//         use std::str::FromStr;

//         let resolver = TokioAsyncResolver::tokio(Default::default(), Default::default());

//         let r = look_up_records(&resolver, "gluet.ch", "ed25519.2022")
//             .await
//             .unwrap();

//         let first_txt = r[0].as_ref().unwrap();

//         let r = DkimKeyRecord::from_str(first_txt);

//         assert!(r.is_ok());
//     }
// }
