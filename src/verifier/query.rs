use crate::{
    signature::{DomainName, Selector},
    verifier::{header::VerifyingTask, Config, LookupTxt},
};
use std::{collections::HashMap, io::{self, ErrorKind}};
use tokio::{task::JoinSet, time};

struct QueriesBuilder {
    // A-label form domain/selector, mapped to collection of signature header indexes
    lookup_pairs: HashMap<(String, String), Vec<usize>>,
}

impl QueriesBuilder {
    fn new() -> Self {
        Self {
            lookup_pairs: HashMap::new(),
        }
    }

    fn add_lookup(&mut self, domain: &DomainName, selector: &Selector, index: usize) {
        let domain = domain.as_ref();
        let selector = selector.as_ref();

        // Note: domain and selector here guaranteed to be convertible to ASCII.
        let domain = idna::domain_to_ascii(domain).unwrap();
        let selector = idna::domain_to_ascii(selector).unwrap();

        self.lookup_pairs.entry((domain, selector)).or_insert(vec![]).push(index);
    }

    fn spawn_all<T>(self, resolver: &T, config: &Config) -> Queries
    where
        T: LookupTxt + Clone + 'static,
    {
        let mut set = JoinSet::new();

        for ((domain, selector), indexes) in self.lookup_pairs {
            let resolver = resolver.clone();

            let lookup_timeout = config.lookup_timeout;

            set.spawn(async move {
                let result = match time::timeout(
                    lookup_timeout,
                    look_up_records(&resolver, domain.as_ref(), selector.as_ref()),
                )
                .await
                {
                    Ok(r) => r,
                    Err(e) => Err(e.into()),
                };

                (indexes, result)
            });
        }

        Queries { set }
    }
}

async fn look_up_records<T: LookupTxt + ?Sized>(
    resolver: &T,
    domain: &str,
    selector: &str,
) -> io::Result<Vec<io::Result<String>>> {
    let dname = format!("{selector}._domainkey.{domain}.");

    let txts = resolver.lookup_txt(&dname).await?;

    // §6.1.2: ‘If the query for the public key returns multiple key records,
    // the Verifier can choose one of the key records or may cycle through the
    // key records […]. The order of the key records is unspecified.’ We return
    // at most three keys.
    let result = txts
        .into_iter()
        .take(3)
        .map(|txt| {
            txt.and_then(|s| String::from_utf8(s).map_err(|_| ErrorKind::InvalidData.into()))
        })
        .collect();

    Ok(result)
}

pub struct Queries {
    pub set: JoinSet<(Vec<usize>, io::Result<Vec<io::Result<String>>>)>,
}

impl Queries {
    pub fn spawn<T>(sigs: &[VerifyingTask], resolver: &T, config: &Config) -> Self
    where
        T: LookupTxt + Clone + 'static,
    {
        let mut builder = QueriesBuilder::new();

        for task in sigs {
            if let Some(sig) = &task.sig {
                builder.add_lookup(&sig.domain, &sig.selector, task.index);
            }
        }

        builder.spawn_all(resolver, config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::DkimKeyRecord;
    use std::str::FromStr;
    use trust_dns_resolver::TokioAsyncResolver;

    #[tokio::test]
    #[ignore = "depends on live DNS records"]
    async fn look_up_live_dkim_key_record() {
        let resolver = TokioAsyncResolver::tokio(Default::default(), Default::default()).unwrap();

        let r = look_up_records(&resolver, "gluet.ch", "ed25519.2022")
            .await
            .unwrap();

        let first_txt = r[0].as_ref().unwrap();

        let r = DkimKeyRecord::from_str(&first_txt);

        assert!(r.is_ok());
    }
}
