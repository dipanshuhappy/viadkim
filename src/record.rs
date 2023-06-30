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

//! DKIM public key record.

use crate::{
    crypto::{HashAlgorithm, KeyType},
    tag_list::{self, TagList, TagSpec},
    util::Base64Debug,
};
use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

// TODO Debug impls!

/// Service types to which a DKIM public key record applies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceType {
    /// Service type <em>*</em>.
    Any,
    /// Service type *email*.
    Email,
}

/// Flags set on a DKIM public key record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectorFlag {
    /// The *y* flag.
    Testing,
    /// The *s* flag.
    NoSubdomains,
}

// TODO Rename DkimKeyRecordError[Kind], b/c not just 'parse'? (cf. DkimSignatureError)
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DkimKeyRecordParseError {
    RecordSyntax,  // fundamental syntax errors such as DNS record format or invalid UTF-8 data
    InvalidQuotedPrintable,
    InvalidBase64,
    TagListSyntax,
    UnsupportedVersion,
    MisplacedVersionTag,
    UnsupportedKeyType,
    InvalidHashAlgorithm,
    NoSupportedHashAlgorithms,
    RevokedKey,
    MissingKeyTag,
    InvalidServiceType,
    NoSupportedServiceTypes,
    InvalidFlag,
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
            Self::InvalidHashAlgorithm => write!(f, "invalid hash algorithm type"),
            Self::NoSupportedHashAlgorithms => write!(f, "no supported hash algorithms"),
            Self::RevokedKey => write!(f, "key revoked"),
            Self::MissingKeyTag => write!(f, "p= tag missing"),
            Self::InvalidServiceType => write!(f, "invalid service type"),
            Self::NoSupportedServiceTypes => write!(f, "no supported service types"),
            Self::InvalidFlag => write!(f, "invalid flag"),
        }
    }
}

/// A DKIM public key record.
///
/// The *v=* tag (always 1) is not included.
#[derive(Clone, Eq, PartialEq)]
pub struct DkimKeyRecord {
    /// The *h=* tag.
    pub hash_algorithms: Box<[HashAlgorithm]>,  // non-empty
    /// The *k=* tag.
    pub key_type: KeyType,
    /// The *n=* tag.
    pub notes: Option<Box<str>>,
    /// The *p=* tag.
    pub key_data: Box<[u8]>,
    /// The *s=* tag.
    pub service_types: Box<[ServiceType]>,  // non-empty
    /// The *t=* tag.
    pub flags: Box<[SelectorFlag]>,
    /// Additional, unrecognised tag name and value pairs.
    pub ext_tags: Box<[(Box<str>, Box<str>)]>,
}

impl DkimKeyRecord {
    // Implementation note: For struct members that have an enumerated type
    // (like `HashAlgorithm` or `ServiceType`), unrecognised items are ignored
    // and not part of the final parsed result.

    fn from_tag_list(tag_list: &TagList<'_>) -> Result<Self, DkimKeyRecordParseError> {
        let mut hash_algorithms = None;
        let mut key_type = None;
        let mut notes = None;
        let mut key_data = None;
        let mut service_types = None;
        let mut flags = None;
        let mut ext_tags = vec![];

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
                    let mut algs = vec![];

                    for s in tag_list::parse_colon_separated_value(value) {
                        if s.is_empty() {
                            return Err(DkimKeyRecordParseError::InvalidHashAlgorithm);
                        }

                        if s.eq_ignore_ascii_case("sha256") {
                            algs.push(HashAlgorithm::Sha256);
                        } else {
                            #[cfg(feature = "pre-rfc8301")]
                            if s.eq_ignore_ascii_case("sha1") {
                                algs.push(HashAlgorithm::Sha1);
                            }
                        }
                    }

                    if algs.is_empty() {
                        return Err(DkimKeyRecordParseError::NoSupportedHashAlgorithms);
                    }

                    hash_algorithms = Some(algs.into());
                }
                "k" => {
                    if value.eq_ignore_ascii_case("rsa") {
                        key_type = Some(KeyType::Rsa);
                    } else if value.eq_ignore_ascii_case("ed25519") {
                        key_type = Some(KeyType::Ed25519);
                    } else {
                        return Err(DkimKeyRecordParseError::UnsupportedKeyType);
                    }
                }
                "n" => {
                    let s = tag_list::parse_qp_section_value(value)
                        .map_err(|_| DkimKeyRecordParseError::InvalidQuotedPrintable)?;

                    // §3.6.1: ‘Notes that might be of interest to a human’. It
                    // seems therefore justified to support only well-formed
                    // UTF-8 strings.
                    let value = String::from_utf8_lossy(&s);

                    notes = Some(value.into());
                }
                "p" => {
                    if value.is_empty() {
                        return Err(DkimKeyRecordParseError::RevokedKey);
                    }

                    let s = tag_list::parse_base64_value(value)
                        .map_err(|_| DkimKeyRecordParseError::InvalidBase64)?;

                    key_data = Some(s.into());
                }
                "s" => {
                    let mut st = vec![];

                    for s in tag_list::parse_colon_separated_value(value) {
                        if s.is_empty() {
                            return Err(DkimKeyRecordParseError::InvalidServiceType);
                        }

                        if s == "*" {
                            st.push(ServiceType::Any);
                        } else if s.eq_ignore_ascii_case("email") {
                            st.push(ServiceType::Email);
                        }
                    }

                    if st.is_empty() {
                        return Err(DkimKeyRecordParseError::NoSupportedServiceTypes);
                    }

                    service_types = Some(st.into());
                }
                "t" => {
                    let mut fs = vec![];

                    for s in tag_list::parse_colon_separated_value(value) {
                        if s.is_empty() {
                            return Err(DkimKeyRecordParseError::InvalidFlag);
                        }

                        if s.eq_ignore_ascii_case("y") {
                            fs.push(SelectorFlag::Testing);
                        } else if s.eq_ignore_ascii_case("s") {
                            fs.push(SelectorFlag::NoSubdomains);
                        }
                    }

                    flags = Some(fs.into());
                }
                _ => {
                    ext_tags.push((name.into(), value.into()));
                }
            }
        }

        let key_data = key_data.ok_or(DkimKeyRecordParseError::MissingKeyTag)?;

        let hash_algorithms = hash_algorithms.unwrap_or_else(|| HashAlgorithm::all().into());
        let key_type = key_type.unwrap_or(KeyType::Rsa);
        let service_types = service_types.unwrap_or_else(|| [ServiceType::Any].into());
        let flags = flags.unwrap_or_default();
        let ext_tags = ext_tags.into();

        Ok(Self {
            hash_algorithms,
            key_type,
            notes,
            key_data,
            service_types,
            flags,
            ext_tags,
        })
    }

    /// Returns true if this key record is flagged *t=y*, false otherwise.
    pub fn is_testing_mode(&self) -> bool {
        self.flags.contains(&SelectorFlag::Testing)
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

impl fmt::Debug for DkimKeyRecord {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("DkimKeyRecord")
            .field("hash_algorithms", &self.hash_algorithms)
            .field("key_type", &self.key_type)
            .field("notes", &self.notes)
            .field("key_data", &Base64Debug(&self.key_data))
            .field("service_types", &self.service_types)
            .field("flags", &self.flags)
            .field("ext_tags", &self.ext_tags)
            .finish()
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
            #[cfg(feature = "pre-rfc8301")]
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
                ext_tags: [].into(),
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
