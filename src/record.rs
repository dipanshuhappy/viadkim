//! DKIM public key record.

use crate::{
    crypto::{HashAlgorithm, KeyType},
    tag_list::{
        parse_base64_tag_value, parse_colon_separated_tag_value, parse_qp_section_tag_value,
        TagList, TagSpec,
    },
};
use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

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
    RecordSyntax,  // fundamental syntax errors such as DNS record format or invalid UTF-8 data
    InvalidQuotedPrintable,
    InvalidBase64,
    TagListSyntax,
    UnsupportedVersion,
    MisplacedVersionTag,
    UnsupportedKeyType,
    NoSupportedHashAlgorithms,
    RevokedKey,
    MissingKeyTag,
    ServiceTypesEmpty,
}

impl Display for DkimKeyRecordParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::RecordSyntax => write!(f, "ill-formed key record"),
            Self::InvalidQuotedPrintable => write!(f, "invalid Quoted-Printable string"),
            Self::InvalidBase64 => write!(f, "invalid Base64 string"),
            Self::TagListSyntax => write!(f, "invalid tag-list"),
            Self::UnsupportedVersion => write!(f, "unsupported version"),
            Self::MisplacedVersionTag => write!(f, "v= tag not initial"),
            Self::UnsupportedKeyType => write!(f, "unsupported key type"),
            Self::NoSupportedHashAlgorithms => write!(f, "no supported hash algorithms"),
            Self::RevokedKey => write!(f, "key revoked"),
            Self::MissingKeyTag => write!(f, "p= tag missing"),
            Self::ServiceTypesEmpty => write!(f, "service types empty"),
        }
    }
}

/// A DKIM public key record.
#[derive(Debug, PartialEq, Eq)]
pub struct DkimKeyRecord {
    pub hash_algorithms: Box<[HashAlgorithm]>,  // non-empty
    pub key_type: KeyType,
    pub notes: Option<Box<str>>,
    pub key_data: Box<[u8]>,
    pub service_types: Box<[ServiceType]>,  // non-empty
    pub flags: Box<[Flags]>,

    // TODO make available "unknown" tags?
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

                    for s in parse_colon_separated_tag_value(value) {
                        if s.eq_ignore_ascii_case("sha256") {
                            hash_algorithms.push(HashAlgorithm::Sha256);
                        } else {
                            #[cfg(feature = "sha1")]
                            if s.eq_ignore_ascii_case("sha1") {
                                hash_algorithms.push(HashAlgorithm::Sha1);
                            }
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
                    let s = parse_qp_section_tag_value(value)
                        .map_err(|_| DkimKeyRecordParseError::InvalidQuotedPrintable)?;

                    // §3.6.1: ‘Notes that might be of interest to a human’. It
                    // seems therefore justified to support only UTF-8 strings.
                    let value = String::from_utf8_lossy(&s);

                    notes = Some(value.into());
                }
                "p" => {
                    if value.is_empty() {
                        return Err(DkimKeyRecordParseError::RevokedKey);
                    }

                    let s = parse_base64_tag_value(value)
                        .map_err(|_| DkimKeyRecordParseError::InvalidBase64)?;

                    key_data = Some(s.into());
                }
                "s" => {
                    let mut st = vec![];

                    for s in parse_colon_separated_tag_value(value) {
                        if s == "*" {
                            st.push(ServiceType::Any);
                        } else if s.eq_ignore_ascii_case("email") {
                            st.push(ServiceType::Email);
                        } else {
                            // TODO disallow empty flags ("... ; s= ; ...")
                            st.push(ServiceType::Other(s.into()));
                        }
                    }

                    if st.is_empty() {
                        return Err(DkimKeyRecordParseError::ServiceTypesEmpty);
                    }

                    service_types = st;
                }
                "t" => {
                    let mut fs = vec![];

                    for s in parse_colon_separated_tag_value(value) {
                        if s.eq_ignore_ascii_case("y") {
                            fs.push(Flags::Testing);
                        } else if s.eq_ignore_ascii_case("s") {
                            fs.push(Flags::NoSubdomains);
                        } else {
                            // TODO disallow empty flags ("... ; t= ; ...")
                            fs.push(Flags::Other(s.into()));
                        }
                    }

                    flags = fs;
                }
                // §3.6.1: ‘Other tags MAY be present and MUST be ignored by any
                // implementation that does not understand them.’
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tag_list::TagList;

    #[test]
    fn dkim_key_record_from_tag_list_ok() {
        let tags = TagList::from_str("v=DKIM1; p=YWJj; s = email; n = highly=20interesting;").unwrap();

        let dkim_key_record = DkimKeyRecord::from_tag_list(&tags).unwrap();

        let hash_algorithms = vec![
            HashAlgorithm::Sha256,
            #[cfg(feature = "sha1")]
            HashAlgorithm::Sha1,
        ];

        assert_eq!(
            dkim_key_record,
            DkimKeyRecord {
                hash_algorithms: hash_algorithms.into(),
                key_type: KeyType::Rsa,
                notes: Some("highly interesting".into()),
                key_data: b"abc".to_vec().into(),
                service_types: [ServiceType::Email].into(),
                flags: [].into(),
            }
        );
    }

    #[test]
    fn dkim_key_record_from_str_broken() {
        // This is an actual record from mail._domainkey.circleshop.ch. Note
        // OpenDKIM accepts this record even though it is ill-formed (uses LF
        // instead of CRLF in FWS).
        let s = "v=DKIM1; h=sha256; k=rsa; \n\t  p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxjVprCb0VDFsrDawxGnwI6OoMUXIc7MKm6354dN9sDDxKi4w3jLQZhiMGHrc/j1JqxWX0CA6lGKfJxlmoLahSD3o92hBkG0b4b2B3erza26gzbKEkKr223WAhxNTfPllECF2HBXPp5tuvMVCQXGJ9uEi9WkgmD4Ns8Va9SLMOg9UKD/vbzE CGuf6jNCVhngzXTVli2vIL/OTE7\n\t  ZWOuXnRENt01sv/aiAQC4PFOMKs1ZVkpcgOQMIZO/5PrMKU/bjUx/9uaaIDLkLJ0RBFgkSJ2uXWtrm6kP7lI8H/7zGunbiDoLiEoAUU7PT98VR4TXvU0DDItzHVoiF/CZsLKwSvQIDAQAB";

        assert!(DkimKeyRecord::from_str(s).is_err());
    }
}
