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
    header::FieldName,
    quoted_printable,
    signature::{
        Canonicalization, CanonicalizationAlgorithm, DkimSignature, DomainName, Identity, Selector,
        SigningAlgorithm,
    },
    signer::OutputFormat,
    util::{self, CanonicalStr},
};
use std::{cmp::Ordering, fmt::Write, iter};

// Note: Careful with offsets: formatting works with *characters*, not bytes!

/// DKIM signature data that does not yet have a cryptographic signature.
pub struct UnsignedDkimSignature {
    pub algorithm: SigningAlgorithm,
    pub body_hash: Box<[u8]>,
    pub canonicalization: Canonicalization,
    pub domain: DomainName,
    pub signed_headers: Box<[FieldName]>,
    pub identity: Option<Identity>,
    pub body_length: Option<u64>,
    pub selector: Selector,
    pub timestamp: Option<u64>,
    pub expiration: Option<u64>,
    pub copied_headers: Box<[(FieldName, Box<[u8]>)]>,
    pub ext_tags: Box<[(Box<str>, Box<str>)]>,
}

impl UnsignedDkimSignature {
    /// Returns the formatted signature without the *b=* tag value, and the
    /// index where the *b=* tag value is to be inserted.
    pub fn format_without_signature(
        &self,
        format: &OutputFormat,
        b_tag_len: usize,
    ) -> (String, usize) {
        format_without_signature(self, format, b_tag_len)
    }

    pub fn into_signature(self, signature_data: Box<[u8]>) -> DkimSignature {
        DkimSignature {
            algorithm: self.algorithm,
            signature_data,
            body_hash: self.body_hash,
            canonicalization: self.canonicalization,
            domain: self.domain,
            signed_headers: self.signed_headers,
            identity: self.identity,
            body_length: self.body_length,
            selector: self.selector,
            timestamp: self.timestamp,
            expiration: self.expiration,
            copied_headers: self.copied_headers,
            ext_tags: self.ext_tags,
        }
    }
}

pub const LINE_WIDTH: usize = 78;

pub fn is_output_tag(name: &str) -> bool {
    matches!(
        name,
        "v" | "a" | "b" | "bh" | "c" | "d" | "h" | "i" | "l" | "s" | "t" | "x" | "z"
    )
}

/// Selects and sorts the tags to include in the signature.
fn compute_tag_names<'a>(
    sig: &'a UnsignedDkimSignature,
    tag_order: Option<&(dyn Fn(&str, &str) -> Ordering + Send + Sync)>,
) -> Vec<&'a str> {
    use CanonicalizationAlgorithm::*;

    let mut names = Vec::with_capacity(16);

    names.push("v");
    names.push("d");
    sig.identity.is_some().then(|| names.push("i"));
    names.push("s");
    names.push("a");

    // Note: tag q=dns/txt is omitted.

    let c = sig.canonicalization;
    if !matches!((c.header, c.body), (Simple, Simple)) {
        names.push("c");
    }

    sig.body_length.is_some().then(|| names.push("l"));
    sig.timestamp.is_some().then(|| names.push("t"));
    sig.expiration.is_some().then(|| names.push("x"));
    names.push("h");
    names.push("bh");
    names.push("b");

    if !sig.copied_headers.is_empty() {
        names.push("z");
    }

    for (t, _) in sig.ext_tags.iter() {
        names.push(t);
    }

    if let Some(tag_order) = tag_order {
        names.sort_by(|a, b| tag_order(a, b));
    }

    names
}

// Ephemeral context holding current formatting options.
#[derive(Clone, Copy)]
struct Fmt<'a> {
    width: usize,
    indent: &'a str,
    last: bool,
    ascii: bool,
}

fn format_without_signature(
    sig: &UnsignedDkimSignature,
    format: &OutputFormat,
    b_tag_len: usize,
) -> (String, usize) {
    let width = format.line_width.into();
    let indent = &format.indentation;
    let ascii = format.ascii_only;

    // First, find out which tags will be included in which order in the
    // generated header.
    let tag_names = compute_tag_names(sig, format.tag_order.as_deref());
    let last_index = tag_names.len().checked_sub(1).unwrap();

    // The starting point of cursor `i` is just past header name + ':'.
    // The insertion index will be used when inserting the signature value.
    let mut output = String::new();
    let mut i = format.header_name.len() + 1;
    let mut insertion_i: Option<usize> = None;

    let out = &mut output;
    let i = &mut i;

    // Now, format the tags into the output. Given the invariants enforced by
    // the first step, `unwrap` is used deliberately.
    for (index, tag_name) in tag_names.into_iter().enumerate() {
        let last = index == last_index;

        let fmt = Fmt { width, indent, last, ascii };

        match tag_name {
            "a" => format_tag_a(out, i, fmt, sig.algorithm),
            "b" => format_tag_name_b(out, i, fmt, b_tag_len, &mut insertion_i),
            "bh" => format_tag_bh(out, i, fmt, &sig.body_hash),
            "c" => format_tag_c(out, i, fmt, sig.canonicalization),
            "d" => format_tag_d(out, i, fmt, &sig.domain),
            "h" => format_tag_h(out, i, fmt, &sig.signed_headers),
            "i" => format_tag_i(out, i, fmt, sig.identity.as_ref().unwrap()),
            "l" => format_tag_l(out, i, fmt, sig.body_length.unwrap()),
            "s" => format_tag_s(out, i, fmt, &sig.selector),
            "t" => format_tag_t(out, i, fmt, sig.timestamp.unwrap()),
            "v" => format_tag_v(out, i, fmt),
            "x" => format_tag_x(out, i, fmt, sig.expiration.unwrap()),
            "z" => format_tag_z(out, i, fmt, &sig.copied_headers),
            tag_name => {
                let (t, v) = sig
                    .ext_tags
                    .iter()
                    .find(|(t, _)| t.as_ref() == tag_name)
                    .unwrap();

                // A tag value is allowed to contain FWS. In those cases, make
                // no effort to introduce any line breaks. The result will not
                // be pretty, but still well-formed.
                format_tag(out, i, fmt, t, v);
            }
        }
    }

    (output, insertion_i.unwrap())
}

// Note: Our well-formed *DKIM-Signature* output is UTF-8 only. It *may* contain
// non-ASCII Unicode characters (in the *d=*, *s=*, *i=* [and *z=*] tags); see
// RFC 8616.

// Note: Throughout, `out` is the final formatted output. `i` is the ‘cursor’ in
// the current line, based on *characters*, not bytes!

fn format_tag_v(out: &mut String, i: &mut usize, fmt: Fmt<'_>) {
    format_tag(out, i, fmt, "v", "1");
}

fn format_tag_d(out: &mut String, i: &mut usize, fmt: Fmt<'_>, domain: &DomainName) {
    let xdomain = if fmt.ascii {
        domain.to_ascii()
    } else {
        domain.to_unicode()
    };

    let domain = select_str_form(domain, &xdomain);

    format_tag(out, i, fmt, "d", domain);
}

fn format_tag_s(out: &mut String, i: &mut usize, fmt: Fmt<'_>, selector: &Selector) {
    let xselector = if fmt.ascii {
        selector.to_ascii()
    } else {
        selector.to_unicode()
    };

    let selector = select_str_form(selector, &xselector);

    format_tag(out, i, fmt, "s", selector);
}

fn format_tag_i(out: &mut String, i: &mut usize, fmt: Fmt<'_>, identity: &Identity) {
    let Identity { local_part, domain } = identity;

    let xdomain = if fmt.ascii {
        domain.to_ascii()
    } else {
        domain.to_unicode()
    };

    let d = select_str_form(domain, &xdomain);

    let identity = match local_part {
        Some(l) => {
            let encode = if fmt.ascii {
                quoted_printable::encode_ascii_only
            } else {
                quoted_printable::encode
            };

            format!("{}@{d}", encode(l.as_bytes(), None))
        }
        None => format!("@{d}"),
    };

    format_tag(out, i, fmt, "i", &identity);
}

// Pick transformed (A-form or U-form) string only if it was changed further
// than trivial ASCII-case differences.
fn select_str_form<'a>(orig: &'a impl AsRef<str>, xformed: &'a str) -> &'a str {
    if orig.as_ref().eq_ignore_ascii_case(xformed) {
        orig.as_ref()
    } else {
        xformed
    }
}

fn format_tag_a(out: &mut String, i: &mut usize, fmt: Fmt<'_>, algorithm: SigningAlgorithm) {
    format_tag(out, i, fmt, "a", algorithm.canonical_str());
}

fn format_tag_c(out: &mut String, i: &mut usize, fmt: Fmt<'_>, canonicalization: Canonicalization) {
    use CanonicalizationAlgorithm::*;

    let canon = match (canonicalization.header, canonicalization.body) {
        (Simple, Simple) => return,
        (Simple, Relaxed) => "simple/relaxed",
        (Relaxed, Simple) => "relaxed",
        (Relaxed, Relaxed) => "relaxed/relaxed",
    };

    format_tag(out, i, fmt, "c", canon);
}

fn format_tag_l(out: &mut String, i: &mut usize, fmt: Fmt<'_>, body_length: u64) {
    format_tag(out, i, fmt, "l", &body_length.to_string());
}

fn format_tag_t(out: &mut String, i: &mut usize, fmt: Fmt<'_>, timestamp: u64) {
    format_tag(out, i, fmt, "t", &timestamp.to_string());
}

fn format_tag_x(out: &mut String, i: &mut usize, fmt: Fmt<'_>, expiration: u64) {
    format_tag(out, i, fmt, "x", &expiration.to_string());
}

fn format_tag(out: &mut String, i: &mut usize, fmt: Fmt<'_>, name: &str, value: &str) {
    debug_assert!(name.is_ascii());

    let Fmt { last, .. } = fmt;

    // name + '=' + val [+ ';']
    let taglen = name.len() + value.chars().count() + if last { 1 } else { 2 };

    advance_i_initial(out, i, taglen, fmt);
    write!(out, "{name}={value}").unwrap();

    if !last {
        out.push(';');
    }
}

fn format_tag_h(out: &mut String, i: &mut usize, fmt: Fmt<'_>, value: &[FieldName]) {
    debug_assert!(!value.is_empty());

    let Fmt { last, .. } = fmt;

    let mut names = value.iter().map(|f| f.as_ref()).peekable();

    let first_name = names.next().unwrap();

    // "h=" + name [+ ';'/':']
    let taglen = first_name.chars().count() + if names.peek().is_none() && last { 2 } else { 3 };

    advance_i_initial(out, i, taglen, fmt);
    write!(out, "h={first_name}").unwrap();
    // now still need to write ;/: to match current i, this is done right away in the next stmt below

    while let Some(name) = names.next() {
        out.push(':');

        // name [+ ';'/':']
        let len = name.chars().count() + if names.peek().is_none() && last { 0 } else { 1 };

        advance_i(out, i, len, fmt);
        write!(out, "{name}").unwrap();
        // again, still need to write ;/:, it is done right away
    }

    if !last {
        out.push(';');
    }
}

fn format_tag_bh(out: &mut String, i: &mut usize, fmt: Fmt<'_>, value: &[u8]) {
    let Fmt { last, .. } = fmt;

    let value = util::encode_base64(value);

    // "bh=" + 1 char (we prefer at least one additional char behind =)
    let taglen = 4;

    advance_i_initial(out, i, taglen, fmt);
    *i -= 1;  // backwards again before the ghost character
    out.push_str("bh=");

    format_chunks_into_string(out, i, fmt, &value);

    // if final chunk makes line *width* chars long, the final ; will be
    // appended nevertheless (giving a width of *width + 1*; this is fine)
    if !last {
        out.push(';');
        *i += 1;
    }
}

fn format_tag_name_b(
    out: &mut String,
    i: &mut usize,
    fmt: Fmt<'_>,
    b_tag_len: usize,
    insertion_i: &mut Option<usize>,
) {
    let Fmt { width, indent, last, .. } = fmt;

    // "b=" + 1 char (we prefer at least one additional char behind =)
    let taglen = 3;
    advance_i_initial(out, i, taglen, fmt);
    *i -= 1;  // backwards again before the ghost character
    out.push_str("b=");

    *insertion_i = Some(out.len());

    // Where in the line are we now given the estimated b= tag value length?
    let chunk_len = width.saturating_sub(indent.len()).max(1);
    let remaining_len = width.saturating_sub(*i);
    if b_tag_len <= remaining_len {
        *i += b_tag_len;
    } else {
        let mut final_chunk_len = (b_tag_len - remaining_len) % chunk_len;
        if final_chunk_len == 0 {
            final_chunk_len = chunk_len;
        }
        *i = final_chunk_len + indent.len();
    }

    if !last {
        out.push(';');
        *i += 1;
    }
}

fn format_tag_z(out: &mut String, i: &mut usize, fmt: Fmt<'_>, value: &[(FieldName, Box<[u8]>)]) {
    debug_assert!(!value.is_empty());

    let Fmt { width, indent, last, ascii } = fmt;

    let format_field_value = |value| {
        let encode = if ascii {
            quoted_printable::encode_ascii_only
        } else {
            quoted_printable::encode
        };
        encode(value, Some('|'))
    };

    let mut iter = value.iter().map(|(f, v)| (f.as_ref(), v));

    // ensure that z= plus the first header name (including ':') fit on the first line

    let (first_name, val) = iter.next().unwrap();

    // "z=" + name + ':'
    let taglen = first_name.chars().count() + 3;

    advance_i_initial(out, i, taglen, fmt);
    write!(out, "z={first_name}:").unwrap();

    let val = format_field_value(val);
    format_chunks_into_string(out, i, fmt, &val);

    for (name, val) in iter {
        if *i >= width {
            write!(out, "\r\n{indent}").unwrap();
            *i = indent.len();
        }
        out.push('|');
        *i += 1;

        let namelen = name.chars().count() + 1;
        if *i + namelen <= width {
            write!(out, "{name}:").unwrap();
            *i += namelen;
        } else {
            write!(out, "\r\n{indent}{name}:").unwrap();
            *i = indent.len() + namelen;
        }

        let val = format_field_value(val);
        format_chunks_into_string(out, i, fmt, &val);
    }

    if !last {
        out.push(';');
        *i += 1;
    }
}

/// Advances the cursor `i`, making space for an item of length `len`, inserting
/// line break and indentation if necessary.
fn advance_i(out: &mut String, i: &mut usize, len: usize, fmt: Fmt<'_>) {
    let Fmt { width, indent, .. } = fmt;

    if *i + len <= width {
        *i += len;
    } else {
        write!(out, "\r\n{indent}").unwrap();
        *i = indent.len() + len;
    }
}

fn advance_i_initial(out: &mut String, i: &mut usize, len: usize, fmt: Fmt<'_>) {
    let Fmt { width, indent, .. } = fmt;

    // + 1 for initial SP
    if *i + len + 1 <= width {
        out.push(' ');
        *i += len + 1;
    } else {
        write!(out, "\r\n{indent}").unwrap();
        *i = indent.len() + len;
    }
}

fn format_chunks_into_string(out: &mut String, i: &mut usize, fmt: Fmt<'_>, mut s: &str) {
    let Fmt { width, indent, .. } = fmt;

    let first_chunk_len = width.saturating_sub(*i);
    let first_chunk_len = first_chunk_len.min(s.chars().count());

    if first_chunk_len > 0 {
        let c = match s.char_indices().nth(first_chunk_len) {
            Some((c, _)) => c,
            None => s.len(),
        };
        let first_chunk;
        (first_chunk, s) = s.split_at(c);
        out.push_str(first_chunk);
        *i += first_chunk.chars().count();
    }

    let chunk_width = width.saturating_sub(indent.len()).max(1);  // no empty chunks
    let chunks = iter::from_fn(|| {
        if s.is_empty() {
            None
        } else {
            let chunk;
            match s.char_indices().nth(chunk_width) {
                Some((c, _)) => {
                    (chunk, s) = s.split_at(c);
                    Some(chunk)
                }
                None => {
                    (chunk, s) = s.split_at(s.len());
                    Some(chunk)
                }
            }
        }
    });

    for chunk in chunks {
        write!(out, "\r\n{indent}{chunk}").unwrap();
        *i = chunk.chars().count() + indent.len();
    }
}

pub fn insert_signature_data(
    formatted_header: &mut String,
    insertion_index: usize,
    header_name: &str,
    signature_data: &[u8],
    line_width: usize,
    indent: &str,
) {
    debug_assert!(insertion_index <= formatted_header.len());

    let fmt = Fmt { width: line_width, indent, last: false /*notused*/, ascii: false /*notused*/};

    let s = util::encode_base64(signature_data);
    // s contains only ASCII now

    let formatted_header_pre = &formatted_header[..insertion_index];

    let mut it = formatted_header_pre.rsplit("\r\n");
    let last_line = it.next().unwrap();
    let mut len = if it.next().is_some() {
        last_line.chars().count()
    } else {
        header_name.len() + last_line.chars().count() + 1
    };

    let mut result = String::with_capacity(s.len());
    format_chunks_into_string(&mut result, &mut len, fmt, &s);

    formatted_header.insert_str(insertion_index, &result);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_tag_h_ok() {
        let mut out = String::new();
        let mut i = 0;
        let fmt = Fmt { width: 10, indent: "  ", last: false, ascii: false };
        let value = [FieldName::new("Ribbit").unwrap()];

        format_tag_h(&mut out, &mut i, fmt, &value);

        assert_eq!(out, " h=Ribbit;");
        assert_eq!(i, 10);
    }

    #[test]
    fn format_tag_z_ok() {
        let value = [
            (FieldName::new("From").unwrap(), Box::from(*b" Me <x@gluet.ch>")),
            (FieldName::new("To").unwrap(), Box::from(*b" \xe2\x99\xa5")),
        ];

        let mut out = String::new();
        let mut i = 0;
        let fmt = Fmt { width: 10, indent: " ", last: false, ascii: false };

        format_tag_z(&mut out, &mut i, fmt, &value);

        assert_eq!(out, " z=From:=2\r\n 0Me=20<x@\r\n gluet.ch>\r\n |To:=20♥;");
        assert_eq!(i, 10);
    }
}
