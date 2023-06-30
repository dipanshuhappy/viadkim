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

//! Tag=value lists. See RFC 6376, section 3.2.

use crate::{
    header::FieldName,
    parse::{rstrip_fws, strip_fws, strip_suffix},
    quoted_printable,
};
use base64ct::{Base64, Encoding};
use std::{collections::HashSet, str};

#[derive(Debug, PartialEq, Eq)]
pub enum TagListParseError {
    DuplicateTag,
    Syntax,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TagSpec<'a> {
    pub name: &'a str,
    pub value: &'a str,
}

/// A list of well-formed tag=value pairs with unique tag names.
#[derive(Debug, PartialEq, Eq)]
pub struct TagList<'a>(Vec<TagSpec<'a>>);

impl<'a> AsRef<[TagSpec<'a>]> for TagList<'a> {
    fn as_ref(&self) -> &[TagSpec<'a>] {
        &self.0
    }
}

impl<'a> TagList<'a> {
    pub fn from_str(s: &'a str) -> Result<Self, TagListParseError> {
        match strip_tag_list(s) {
            Some((rest, tag_list)) if rest.is_empty() => {
                let mut names_seen = HashSet::new();
                if tag_list.iter().any(|tag| !names_seen.insert(tag.name)) {
                    return Err(TagListParseError::DuplicateTag);
                }
                Ok(Self(tag_list))
            }
            _ => Err(TagListParseError::Syntax),
        }
    }
}

fn strip_tag_list(val: &str) -> Option<(&str, Vec<TagSpec<'_>>)> {
    let (mut s, t) = strip_tag_spec(val)?;

    let mut tags = vec![t];

    while let Some((snext, t)) = s.strip_prefix(';').and_then(strip_tag_spec) {
        s = snext;
        tags.push(t);
    }

    let s = s.strip_prefix(';').unwrap_or(s);

    Some((s, tags))
}

fn strip_tag_spec(val: &str) -> Option<(&str, TagSpec<'_>)> {
    let (s, name) = strip_tag_name_and_equals(val)?;

    let s = strip_fws(s).unwrap_or(s);

    let (s, value) = match strip_tag_value(s) {
        Some((s, value)) => {
            let s = strip_fws(s).unwrap_or(s);
            (s, value)
        }
        None => (s, Default::default()),
    };

    Some((s, TagSpec { name, value }))
}

/// Strips a tag name including the equals sign, ie everything before a value.
pub fn strip_tag_name_and_equals(val: &str) -> Option<(&str, &str)> {
    let s = strip_fws(val).unwrap_or(val);

    let (s, name) = strip_tag_name(s)?;

    let s = strip_fws(s).unwrap_or(s);

    let s = s.strip_prefix('=')?;

    Some((s, name))
}

fn strip_tag_name(value: &str) -> Option<(&str, &str)> {
    let s = value
        .strip_prefix(is_alpha)?
        .trim_start_matches(is_alphanum);
    Some((s, strip_suffix(value, s)))
}

// Note erratum 5070 in ABNF
fn strip_tag_value(value: &str) -> Option<(&str, &str)> {
    fn strip_tval(s: &str) -> Option<&str> {
        s.strip_prefix(is_tval_char)
            .map(|s| s.trim_start_matches(is_tval_char))
    }

    let mut s = strip_tval(value)?;

    while let Some(snext) = strip_fws(s).and_then(strip_tval) {
        s = snext;
    }

    Some((s, strip_suffix(value, s)))
}

fn is_alpha(c: char) -> bool {
    c.is_ascii_alphabetic()
}

fn is_alphanum(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

pub fn is_tval_char(c: char) -> bool {
    // printable ASCII without ; plus any non-ASCII UTF-8
    matches!(c, '!'..=':' | '<'..='~') || !c.is_ascii()
}

pub fn parse_colon_separated_value(value: &str) -> Vec<&str> {
    debug_assert!(is_tag_value(value));

    value.split(':').map(trim_surrounding_fws).collect()
}

pub fn parse_base64_value(value: &str) -> Result<Vec<u8>, TagListParseError> {
    debug_assert!(is_tag_value(value));

    let value = strip_fws_from_tag_value(value);

    Base64::decode_vec(&value).map_err(|_| TagListParseError::Syntax)
}

pub fn parse_qp_section_value(value: &str) -> Result<Vec<u8>, TagListParseError> {
    debug_assert!(is_tag_value(value));

    quoted_printable::decode_qp_section(value).map_err(|_| TagListParseError::Syntax)
}

pub fn parse_quoted_printable_value(value: &str) -> Result<Vec<u8>, TagListParseError> {
    debug_assert!(is_tag_value(value));

    quoted_printable::decode(value).map_err(|_| TagListParseError::Syntax)
}

pub fn parse_quoted_printable_header_field(
    value: &str,
) -> Result<(FieldName, Box<[u8]>), TagListParseError> {
    // Unlike other functions here, value may be surrounded with FWS.
    debug_assert!(is_tag_value(trim_surrounding_fws(value)));

    // This enforces well-formedness requirement for header field names, but not
    // for the qp-encoded value, which can be anything (it should of course
    // conform to `FieldBody`, but since it is foreign data we cannot assume).

    let val = quoted_printable::decode(value).map_err(|_| TagListParseError::Syntax)?;

    let mut iter = val.splitn(2, |&c| c == b':');

    match (iter.next(), iter.next()) {
        (Some(name), Some(value)) => {
            let name = str::from_utf8(name).map_err(|_| TagListParseError::Syntax)?;
            let name = FieldName::new(name).map_err(|_| TagListParseError::Syntax)?;
            let value = value.into();
            Ok((name, value))
        }
        _ => Err(TagListParseError::Syntax),
    }
}

pub fn is_tag_name(s: &str) -> bool {
    matches!(strip_tag_name(s), Some((rest, _)) if rest.is_empty())
}

pub fn is_tag_value(s: &str) -> bool {
    s.is_empty() || matches!(strip_tag_value(s), Some((rest, _)) if rest.is_empty())
}

/// Strips folding whitespace from a well-formed tag value.
pub fn strip_fws_from_tag_value(value: &str) -> String {
    debug_assert!(is_tag_value(value));

    // A tag value contains only well-formed FWS, so may strip indiscriminately:
    value
        .chars()
        .filter(|c| !matches!(c, ' ' | '\t' | '\r' | '\n'))
        .collect()
}

fn trim_surrounding_fws(s: &str) -> &str {
    let s = strip_fws(s).unwrap_or(s);
    rstrip_fws(s).unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_list_from_str_ok() {
        let example = " v = 1 ; a=rsa-sha256;d=example.net; s=brisbane;
  c=simple; q=dns/txt; i=中文@eng.example.net;
  t=1117574938; x=1118006938;
  h=from:to:subject:date;
  z=From:foo@eng.example.net|To:joe@example.com|
   Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700
   ;
  bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;
  b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR";
        let example = example.replace('\n', "\r\n");

        let tag_list = TagList::from_str(&example).unwrap();

        assert!(!tag_list.as_ref().is_empty());
    }

    #[test]
    fn parse_colon_separated_value_ok() {
        assert_eq!(
            parse_colon_separated_value("ab:\r\n\tc\r\n\td\r\n\t:e"),
            ["ab", "c\r\n\td", "e"]
        );
        assert_eq!(parse_colon_separated_value(""), [""]);
    }

    #[test]
    fn parse_base64_value_ok() {
        assert_eq!(parse_base64_value("").unwrap(), []);
        assert_eq!(parse_base64_value("TQ==").unwrap(), b"M");
    }

    #[test]
    fn parse_quoted_printable_header_field_ok() {
        let example = " Date:=20July=205,=0D=0A=092005=20\r\n\t3:44:08=20PM=20-0700 ";

        let result = parse_quoted_printable_header_field(example);

        assert_eq!(
            result,
            Ok((
                FieldName::new("Date").unwrap(),
                Box::from(*b" July 5,\r\n\t2005 3:44:08 PM -0700"),
            ))
        );
    }
}
