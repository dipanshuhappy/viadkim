use crate::{
    crypto::{HashAlgorithm, KeyType},
    tag_list::{
        parse_base64_tag_value, parse_colon_separated_tag_value, parse_qp_section_tag_value,
        TagList, TagSpec,
    },
    verifier::LookupTxt,
};
use std::io;

#[derive(Debug, PartialEq, Eq)]
pub enum ServiceType {
    Any,
    Email,
    Other(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Flags {
    Testing,
    NoSubdomains,
    Other(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum DkimKeyRecordParseError {
    UnsupportedVersion,
    MisplacedVersionTag,
    UnsupportedKeyType,
    NoSupportedHashAlgorithms,
    ValueSyntax,
    RevokedKey,
    MissingKeyTag,
    ServiceTypesEmpty,
}

#[derive(Debug, PartialEq, Eq)]
pub struct DkimKeyRecord {
    pub hash_algorithms: Vec<HashAlgorithm>,  // non-empty
    pub key_type: KeyType,
    pub notes: Option<String>,
    pub key_data: Vec<u8>,
    pub service_types: Vec<ServiceType>,  // non-empty
    pub flags: Vec<Flags>,
}

impl DkimKeyRecord {
    pub fn from_tag_list(tag_list: &TagList<'_>) -> Result<Self, DkimKeyRecordParseError> {
        let mut hash_algorithms = HashAlgorithm::all();
        let mut key_type = KeyType::Rsa;
        let mut notes = None;
        let mut key_data = None;
        let mut service_types = vec![ServiceType::Any];
        let mut flags = vec![];

        for (i, &TagSpec { name, value }) in tag_list.as_ref().iter().enumerate() {
            match name {
                "v" => {
                    if i != 0 {
                        return Err(DkimKeyRecordParseError::MisplacedVersionTag);
                    }
                    if value != "DKIM1" {
                        return Err(DkimKeyRecordParseError::UnsupportedVersion);
                    }
                }
                "h" => {
                    hash_algorithms.clear();
                    for v in parse_colon_separated_tag_value(value) {
                        if v.eq_ignore_ascii_case("sha256") {
                            hash_algorithms.push(HashAlgorithm::Sha256);
                        }
                    }
                    if hash_algorithms.is_empty() {
                        return Err(DkimKeyRecordParseError::NoSupportedHashAlgorithms);
                    }
                }
                "k" => {
                    if value.eq_ignore_ascii_case("ed25519") {
                        key_type = KeyType::Ed25519;
                    } else if !value.eq_ignore_ascii_case("rsa") {
                        return Err(DkimKeyRecordParseError::UnsupportedKeyType);
                    }
                }
                "n" => {
                    let v = parse_qp_section_tag_value(value)
                        .map_err(|_| DkimKeyRecordParseError::ValueSyntax)?;
                    // only UTF-8 supported:
                    let val = String::from_utf8_lossy(&v).into_owned();
                    notes = Some(val);
                }
                "p" => {
                    if value.is_empty() {
                        return Err(DkimKeyRecordParseError::RevokedKey);
                    }
                    let v = parse_base64_tag_value(value)
                        .map_err(|_| DkimKeyRecordParseError::ValueSyntax)?;
                    key_data = Some(v);
                }
                "s" => {
                    let mut st = vec![];
                    for v in parse_colon_separated_tag_value(value) {
                        if v == "*" {
                            st.push(ServiceType::Any);
                        } else if v.eq_ignore_ascii_case("email") {
                            st.push(ServiceType::Email);
                        } else {
                            st.push(ServiceType::Other(v.into()));
                        }
                    }
                    if st.is_empty() {
                        return Err(DkimKeyRecordParseError::ServiceTypesEmpty);
                    }
                    service_types = st;
                }
                "t" => {
                    let mut fs = vec![];
                    for v in parse_colon_separated_tag_value(value) {
                        if v.eq_ignore_ascii_case("y") {
                            fs.push(Flags::Testing);
                        } else if v.eq_ignore_ascii_case("s") {
                            fs.push(Flags::NoSubdomains);
                        } else {
                            fs.push(Flags::Other(v.into()));
                        }
                    }
                    flags = fs;
                }
                _ => {}
            }
        }

        let key_data = key_data.ok_or(DkimKeyRecordParseError::MissingKeyTag)?;

        Ok(Self {
            hash_algorithms,
            key_type,
            notes,
            key_data,
            service_types,
            flags,
        })
    }
}

pub async fn look_up_records<T: LookupTxt + ?Sized>(
    resolver: &T,
    domain: &str,
    selector: &str,
) -> io::Result<Vec<String>> {
    let dname = format!("{selector}._domainkey.{domain}.");

    let mut result = vec![];

    // §6.1.2: ‘If the query for the public key returns multiple key records,
    // the Verifier can choose one of the key records or may cycle through the
    // key records […]. The order of the key records is unspecified.’ We return
    // at most three keys.
    for v in resolver.lookup_txt(&dname).await?.into_iter().take(3) {
        let s = v?;
        let s = String::from_utf8_lossy(&s);
        result.push(s.into_owned());
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tag_list::TagList;
    use trust_dns_resolver::TokioAsyncResolver;

    #[test]
    fn dkim_key_record_from_tag_list_ok() {
        let tags = TagList::from_str("v=DKIM1; p=YWJj; s = email; n = highly=20interesting;").unwrap();

        let dkim_key_record = DkimKeyRecord::from_tag_list(&tags).unwrap();

        assert_eq!(
            dkim_key_record,
            DkimKeyRecord {
                hash_algorithms: vec![HashAlgorithm::Sha256],
                key_type: KeyType::Rsa,
                notes: Some("highly interesting".into()),
                key_data: b"abc".to_vec(),
                service_types: vec![ServiceType::Email],
                flags: vec![],
            }
        );
    }

    #[ignore]
    #[tokio::test]
    async fn live_dkim_key_record() {
        let resolver = TokioAsyncResolver::tokio(Default::default(), Default::default()).unwrap();

        let r = look_up_records(&resolver, "gluet.ch", "2020")
            .await
            .unwrap();

        let taglist = TagList::from_str(&r[0]).unwrap();

        let rec = DkimKeyRecord::from_tag_list(&taglist).unwrap();

        assert_eq!(
            &base64::encode(rec.key_data),
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzQQGy3HpwbcWhBXXDTBv\
            bWGJy38WK8kLascRJyvYAkFCLx1QqCi7Q7baABkee5lkGRGLQidUyNfDoW9MNCiT\
            5SLhnl2iPaT9kcKhAYSezMNWyQxueXhLIZ5wT9LKCfFNVvz2R5SNcVE7a/CxU4XA\
            iEhNsKg4o/LyEhE1665BT0GizPz5ukNwwePQrLgGSpygHd/TQBa/xzKlQdLvTHiQ\
            OqgnoG/G3ThVOnQV/Ntc8UjKDZO5n1pynTsVmtmCASwykN6ZDZTaeaRCnIrS02nO\
            YB1ba2TJl+xugdNja1agDvUL6t0n2kfGp85A/Z6v5Fq0nlzvmwHth2eg3lVVgI2c\
            KwIDAQAB"
        );
    }
}
