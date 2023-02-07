use crate::{
    signature::{DomainName, Selector},
    verifier::{Config, LookupTxt, VerifyingTask},
};
use std::{collections::HashSet, io};
use tokio::{
    sync::mpsc::{self, UnboundedReceiver},
    time,
};
use tracing::debug;

struct QueriesBuilder {
    lookup_pairs: HashSet<(DomainName, Selector)>,
}

impl QueriesBuilder {
    fn new() -> Self {
        Self {
            lookup_pairs: HashSet::new(),
        }
    }

    fn add_lookup(&mut self, domain: &DomainName, selector: &Selector) {
        self.lookup_pairs.insert((domain.clone(), selector.clone()));
    }

    fn spawn_all<T>(self, resolver: &T, config: &Config) -> Queries
    where
        T: LookupTxt + Clone + 'static,
    {
        let (tx, rx) = mpsc::unbounded_channel();

        for (domain, selector) in self.lookup_pairs {
            let domain_ = domain.clone();
            let selector_ = selector.clone();
            let resolver = resolver.clone();

            let tx_ = tx.clone();

            let lookup_timeout = config.lookup_timeout;

            tokio::spawn(async move {
                let result = match time::timeout(
                    lookup_timeout,
                    look_up_records(&resolver, domain_.as_ref(), selector_.as_ref()),
                )
                .await
                {
                    Ok(r) => r,
                    Err(e) => Err(e.into()),
                };

                tx_.send(((domain_, selector_), result)).unwrap();
            });
        }

        Queries { rx }
    }
}

async fn look_up_records<T: LookupTxt + ?Sized>(
    resolver: &T,
    domain: &str,
    selector: &str,
) -> io::Result<Vec<Box<str>>> {
    // TODO this doesn't belong here, should be canonicalized (and deduped) earlier; same for selector
    let d;
    let domain = match idna::domain_to_ascii(domain) {
        Ok(s) => {
            d = s;
            &d
        }
        Err(_) => {
            debug!("failed to convert IDNA domain to ASCII, continuing with original format");
            domain
        }
    };

    let dname = format!("{selector}._domainkey.{domain}.");

    let mut result = vec![];

    // §6.1.2: ‘If the query for the public key returns multiple key records,
    // the Verifier can choose one of the key records or may cycle through the
    // key records […]. The order of the key records is unspecified.’ We return
    // at most three keys.
    for v in resolver.lookup_txt(&dname).await?.into_iter().take(3) {
        // TODO check if error is io::ErrorKind::NotFound here => should map to VerifierError::NoKeyFound!
        // TODO also error should not be propagated with ? here?
        let s = v?;
        let s = String::from_utf8_lossy(&s);
        result.push(s.into());
    }

    Ok(result)
}

pub struct Queries {
    pub rx: UnboundedReceiver<((DomainName, Selector), io::Result<Vec<Box<str>>>)>,
}

impl Queries {
    pub(crate) fn spawn<T>(sigs: &[VerifyingTask], resolver: &T, config: &Config) -> Self
    where
        T: LookupTxt + Clone + 'static,
    {
        let mut builder = QueriesBuilder::new();

        for task in sigs {
            if let Some(sig) = &task.sig {
                builder.add_lookup(&sig.domain, &sig.selector);
            }
        }

        builder.spawn_all(resolver, config)
    }
}
