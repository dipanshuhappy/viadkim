use crate::{
    header::FieldName,
    parse::{strip_fws, strip_suffix},
    quoted_printable,
};
use base64ct::{Base64, Encoding};
use std::{collections::HashSet, str};

// TODO revisit module, names, errors

pub fn parse_colon_separated_tag_value(value: &str) -> Vec<&str> {
    // assume input is a valid tag-list value
    debug_assert!(is_tag_value(value));

    value
        .split(':')
        .map(|s| s.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n')))
        .collect()
}

pub fn parse_qp_section_tag_value(value: &str) -> Result<Vec<u8>, TagListParseError> {
    debug_assert!(is_tag_value(value));
    // TODO also: no FWS allowed in qp-section

    match quoted_printable::parse_qp_section(value) {
        Some(v) => Ok(v),
        None => Err(TagListParseError::Syntax),
    }
}

pub fn parse_base64_tag_value(value: &str) -> Result<Vec<u8>, TagListParseError> {
    debug_assert!(is_tag_value(value));

    let value = strip_fws_from_tag_value(value);
    Base64::decode_vec(&value).map_err(|_| TagListParseError::Syntax)
}

pub fn parse_dqp_tag_value(value: &str) -> Result<String, TagListParseError> {
    debug_assert!(is_tag_value(value));

    let value = strip_fws_from_tag_value(value);

    let val = quoted_printable::dqp_decode(&value).map_err(|_| TagListParseError::Syntax)?;

    String::from_utf8(val).map_err(|_| TagListParseError::Syntax)
}

pub fn parse_dqp_header_field(value: &str) -> Result<(FieldName, Box<[u8]>), TagListParseError> {
    // note: unlike other functions here, value may be surrounded with FWS
    debug_assert!({
        let v = strip_fws(value).unwrap_or(value);
        v.is_empty()
            || matches!(parse_tag_value(v), Some((rest, _)) if strip_fws(rest).unwrap_or(rest).is_empty())
    });

    // This enforces well-formedness requirement for header field names, but not
    // for the dqp-encoded value, which can be anything.

    let value = strip_fws_from_tag_value(value);

    let val = quoted_printable::dqp_decode(&value).map_err(|_| TagListParseError::Syntax)?;

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

fn is_tag_value(s: &str) -> bool {
    s.is_empty() || matches!(parse_tag_value(s), Some((rest, _)) if rest.is_empty())
}

// TODO this is not good public API, revisit
pub fn strip_fws_from_tag_value(value: &str) -> String {
    // assume only well-formed FWS
    value
        .chars()
        .filter(|c| !matches!(c, ' ' | '\t' | '\r' | '\n'))
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
pub struct TagSpec<'a> {
    pub name: &'a str,
    pub value: &'a str,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TagListParseError {
    DuplicateTag,
    Syntax,
}

#[derive(Debug, PartialEq, Eq)]
pub struct TagList<'a>(Vec<TagSpec<'a>>);

impl<'a> AsRef<[TagSpec<'a>]> for TagList<'a> {
    fn as_ref(&self) -> &[TagSpec<'a>] {
        &self.0
    }
}

impl<'a> TagList<'a> {
    pub fn from_str(val: &'a str) -> Result<Self, TagListParseError> {
        match parse_tag_list_internal(val) {
            Some((rest, tag_list)) if rest.is_empty() => {
                // ensure no duplicate names
                let mut names_seen = HashSet::new();
                if tag_list.iter().any(|tag| !names_seen.insert(tag.name)) {
                    return Err(TagListParseError::DuplicateTag);
                }
                Ok(TagList(tag_list))
            }
            _ => Err(TagListParseError::Syntax),
        }
    }
}

pub fn parse_tag_list_internal(val: &str) -> Option<(&str, Vec<TagSpec<'_>>)> {
    let (mut s, t) = parse_tag_spec(val)?;

    let mut tags = vec![t];

    while let Some((snext, t)) = s.strip_prefix(';').and_then(parse_tag_spec) {
        s = snext;
        tags.push(t);
    }

    let s = s.strip_prefix(';').unwrap_or(s);

    Some((s, tags))
}

fn parse_tag_spec(val: &str) -> Option<(&str, TagSpec<'_>)> {
    let s = strip_fws(val).unwrap_or(val);

    let (s, name) = parse_tag_name(s)?;

    let s = strip_fws(s).unwrap_or(s);

    let s = s.strip_prefix('=')?;

    let s = strip_fws(s).unwrap_or(s);

    let (s, value) = match parse_tag_value(s) {
        Some((s, value)) => {
            let s = strip_fws(s).unwrap_or(s);
            (s, value)
        }
        None => (s, Default::default()),
    };

    Some((s, TagSpec { name, value }))
}

fn parse_tag_name(value: &str) -> Option<(&str, &str)> {
    let s = value
        .strip_prefix(is_alpha)?
        .trim_start_matches(is_alphanum);
    Some((s, strip_suffix(value, s)))
}

// Note erratum 5070 in ABNF
fn parse_tag_value(value: &str) -> Option<(&str, &str)> {
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
    // printable ASCII w/o ; or non-ASCII UTF-8
    matches!(c, '!'..=':' | '<'..='~') || !c.is_ascii()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_colon_separated_tag_value_ok() {
        assert_eq!(
            parse_colon_separated_tag_value("ab:\r\n\tc\r\n\td:e"),
            ["ab", "c\r\n\td", "e"]
        );
        assert_eq!(parse_colon_separated_tag_value(""), [""]);
    }

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

        let q = TagList::from_str(&example).unwrap();
        assert!(!q.as_ref().is_empty());
    }

    #[test]
    fn parse_dqp_header_field_ok() {
        let example = " Date:=20July=205,=0D=0A=092005=20\r\n\t3:44:08=20PM=20-0700 ";

        let result = parse_dqp_header_field(example);

        assert_eq!(
            result,
            Ok((
                FieldName::new("Date").unwrap(),
                Box::from(*b" July 5,\r\n\t2005 3:44:08 PM -0700"),
            ))
        );
    }
}
