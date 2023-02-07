//! DKIM public key record.

use crate::{
    crypto::{HashAlgorithm, KeyType},
    tag_list::{
        parse_base64_tag_value, parse_colon_separated_tag_value, parse_qp_section_tag_value,
        TagList, TagSpec,
    },
};
use std::str::FromStr;

#[derive(Debug, PartialEq, Eq)]
pub enum ServiceType {
    Any,
    Email,
    Other(Box<str>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Flags {
    Testing,
    NoSubdomains,
    Other(Box<str>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum DkimKeyRecordParseError {
    TagListSyntax,

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
    pub hash_algorithms: Box<[HashAlgorithm]>,  // non-empty
    pub key_type: KeyType,
    pub notes: Option<Box<str>>,
    pub key_data: Box<[u8]>,
    pub service_types: Box<[ServiceType]>,  // non-empty
    pub flags: Box<[Flags]>,
}

impl FromStr for DkimKeyRecord {
    type Err = DkimKeyRecordParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let tag_list = match TagList::from_str(s) {
            Ok(r) => r,
            Err(_e) => {
                return Err(DkimKeyRecordParseError::TagListSyntax);
            }
        };

        Self::from_tag_list(&tag_list)
    }
}

impl DkimKeyRecord {
    fn from_tag_list(tag_list: &TagList<'_>) -> Result<Self, DkimKeyRecordParseError> {
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
                    let val = String::from_utf8_lossy(&v);
                    notes = Some(val.into());
                }
                "p" => {
                    if value.is_empty() {
                        return Err(DkimKeyRecordParseError::RevokedKey);
                    }
                    let v = parse_base64_tag_value(value)
                        .map_err(|_| DkimKeyRecordParseError::ValueSyntax)?;
                    key_data = Some(v.into());
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
            hash_algorithms: hash_algorithms.into(),
            key_type,
            notes,
            key_data,
            service_types: service_types.into(),
            flags: flags.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tag_list::TagList;

    #[test]
    fn dkim_key_record_from_tag_list_ok() {
        let tags = TagList::from_str("v=DKIM1; p=YWJj; s = email; n = highly=20interesting;").unwrap();

        let dkim_key_record = DkimKeyRecord::from_tag_list(&tags).unwrap();

        assert_eq!(
            dkim_key_record,
            DkimKeyRecord {
                hash_algorithms: [HashAlgorithm::Sha256].into(),
                key_type: KeyType::Rsa,
                notes: Some("highly interesting".into()),
                key_data: b"abc".to_vec().into(),
                service_types: [ServiceType::Email].into(),
                flags: [].into(),
            }
        );
    }
}
