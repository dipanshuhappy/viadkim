use crate::{
    header::FieldName,
    quoted_printable,
    signature::{
        Canonicalization, CanonicalizationAlgorithm, DkimSignature, DomainName, Identity, Selector,
        SignatureAlgorithm, DKIM_SIGNATURE_NAME,
    },
    util::{self, CanonicalStr},
};
use std::{fmt::Write, iter};

// careful with offsets: formatting works on characters not bytes!

#[derive(Clone, Eq, PartialEq)]
pub struct UnsignedDkimSignature {
    pub algorithm: SignatureAlgorithm,
    pub body_hash: Box<[u8]>,
    pub canonicalization: Canonicalization,
    pub domain: DomainName,
    pub signed_headers: Box<[FieldName]>,
    pub user_id: Option<Identity>,
    pub body_length: Option<u64>,
    pub selector: Selector,
    pub timestamp: Option<u64>,
    pub expiration: Option<u64>,
    pub copied_headers: Option<Box<[(FieldName, Box<[u8]>)]>>,
}

impl UnsignedDkimSignature {
    // Returns the formatted signature without the b= value, and the index where
    // the b= value is to be inserted.
    // width: *char-based* line width
    // b_tag_len: *char-based* b= tag value length
    pub fn format_without_signature(
        &self,
        header_name: &str,
        width: usize,
        b_tag_len: usize,
    ) -> (String, usize) {
        format_without_signature(self, header_name, width, b_tag_len)
    }

    pub fn into_signature(self, signature_data: Box<[u8]>) -> DkimSignature {
        DkimSignature {
            algorithm: self.algorithm,
            signature_data,
            body_hash: self.body_hash,
            canonicalization: self.canonicalization,
            domain: self.domain,
            signed_headers: self.signed_headers,
            user_id: self.user_id,
            body_length: self.body_length,
            selector: self.selector,
            timestamp: self.timestamp,
            expiration: self.expiration,
            copied_headers: self.copied_headers,
            extra_tags: None,
        }
    }
}

pub const LINE_WIDTH: usize = 78;

fn format_without_signature(
    sig: &UnsignedDkimSignature,
    header_name: &str,
    width: usize,
    b_tag_len: usize,
) -> (String, usize) {
    debug_assert!(header_name.eq_ignore_ascii_case(DKIM_SIGNATURE_NAME));

    let start_i = header_name.len() + 1;  // plus ":"

    let mut result = String::new();
    let mut i = start_i;

    format_tag_into_string(&mut result, width, &mut i, "v", "1");

    // For the U-label form conversion, see RFC 8616.
    let domain = sig.domain.to_unicode();
    format_tag_into_string(&mut result, width, &mut i, "d", &domain);

    let selector = sig.selector.to_unicode();
    format_tag_into_string(&mut result, width, &mut i, "s", &selector);

    if let Some(Identity { local_part, domain_part }) = &sig.user_id {
        let d = domain_part.to_unicode();

        // in i= value substitute =3B for ; and =20 for space
        // (both of which are allowed to appear in the identity's local-part!)
        // TODO revisit, inefficient
        let l = match local_part {
            Some(x) => Some(x.replace(';', "=3B").replace(' ', "=20")),
            None => None,
        };
        let l = l.as_deref().unwrap_or("");

        let identity = format!("{l}@{d}");
        format_tag_into_string(&mut result, width, &mut i, "i", &identity);
    }

    format_tag_into_string(&mut result, width, &mut i, "a", sig.algorithm.canonical_str());

    let canon = match (sig.canonicalization.header, sig.canonicalization.body) {
        (CanonicalizationAlgorithm::Simple, CanonicalizationAlgorithm::Simple) => None,
        (CanonicalizationAlgorithm::Simple, CanonicalizationAlgorithm::Relaxed) => {
            Some("simple/relaxed")
        }
        (CanonicalizationAlgorithm::Relaxed, CanonicalizationAlgorithm::Simple) => {
            Some("relaxed")
        }
        (CanonicalizationAlgorithm::Relaxed, CanonicalizationAlgorithm::Relaxed) => {
            Some("relaxed/relaxed")
        }
    };
    if let Some(canon) = canon {
        format_tag_into_string(&mut result, width, &mut i, "c", canon);
    }

    if let Some(body_length) = &sig.body_length {
        format_tag_into_string(&mut result, width, &mut i, "l", &body_length.to_string());
    }

    if let Some(timestamp) = &sig.timestamp {
        format_tag_into_string(&mut result, width, &mut i, "t", &timestamp.to_string());
    }
    if let Some(expiration) = &sig.expiration {
        format_tag_into_string(&mut result, width, &mut i, "x", &expiration.to_string());
    }

    format_signed_headers_into_string(&mut result, width, &mut i, &sig.signed_headers);

    let bh = util::encode_binary(&sig.body_hash);
    format_body_hash_into_string(&mut result, width, &mut i, &bh);

    if i + 4 <= width {  // at least one additional char behind =
        result.push_str(" b=");
        i += 3;
    } else {
        result.push_str("\r\n\tb=");
        i = 3;
    }

    let insertion_i = result.len();

    if let Some(z) = &sig.copied_headers {
        // where in the line we are now given the estimated b= tag value length?
        let chunk_len = width.saturating_sub(1).max(1);
        let remaining_len = width.saturating_sub(i);
        if b_tag_len <= remaining_len {
            i += b_tag_len + 1;  // ;
        } else {
            i = (b_tag_len - remaining_len) % chunk_len + 2;  // WSP + ;
        }

        // push terminating ; for b= value
        result.push(';');

        // format
        format_copied_headers_into_string(&mut result, width, &mut i, z);
    }

    (result, insertion_i)
}

fn format_tag_into_string(
    result: &mut String,
    width: usize,
    i: &mut usize,
    tag: &'static str,
    value: &str,
) {
    debug_assert!(tag.is_ascii());

    // WSP + tag + '=' + val + ';'
    let taglen = tag.len() + value.chars().count() + 3;

    if *i + taglen <= width {
        result.push(' ');
        *i += taglen;
    } else {
        result.push_str("\r\n\t");
        *i = taglen;
    }

    write!(result, "{tag}={value};").unwrap();
}

fn format_signed_headers_into_string(
    result: &mut String,
    width: usize,
    i: &mut usize,
    value: &[FieldName],
) {
    debug_assert!(!value.is_empty());

    let mut names = value.iter();

    let first_name = names.next().unwrap();
    let first_name = first_name.as_ref();

    // WSP + 'h=' + name + ';'/':'
    let taglen = first_name.chars().count() + 4;
    if *i + taglen <= width {
        result.push(' ');
        *i += taglen;
    } else {
        result.push_str("\r\n\t");
        *i = taglen;
    }
    write!(result, "h={first_name}").unwrap();  // don't write ;/: yet

    for name in names {
        let name = name.as_ref();

        result.push(':');

        let len = name.chars().count() + 1;  // name + ';'/':'
        if *i + len <= width {
            *i += len;
        } else {
            result.push_str("\r\n\t");
            *i = len + 1;
        }
        write!(result, "{name}").unwrap();  // don't write ;/: yet
    }

    result.push(';');
}

fn format_body_hash_into_string(result: &mut String, width: usize, i: &mut usize, value: &str) {
    // WSP + 'bh=' + 1char (at least one additional char behind =)
    let taglen = 5;

    if *i + taglen <= width {
        result.push(' ');
        *i += taglen - 1;
    } else {
        result.push_str("\r\n\t");
        *i = taglen - 1;
    }
    result.push_str("bh=");

    format_chunks_into_string(result, width, i, value);

    // if final chunk makes line 78 chars long, the final ; will be appended nevertheless (=> width == 79)
    result.push(';');
    *i += 1;
}

fn format_copied_headers_into_string(
    result: &mut String,
    width: usize,
    i: &mut usize,
    value: &[(FieldName, Box<[u8]>)],
) {
    debug_assert!(!value.is_empty());

    let mut iter = value.iter();

    // ensure that z= plus the first header name (including :) fit on the first line

    let (first_name, val) = iter.next().unwrap();
    let first_name = first_name.as_ref();

    // WSP + "z=" + name + ':'
    let taglen = first_name.chars().count() + 4;

    if *i + taglen <= width {
        result.push(' ');
        *i += taglen;
    } else {
        result.push_str("\r\n\t");
        *i = taglen;
    }
    write!(result, "z={first_name}:").unwrap();

    let val = quoted_printable::dqp_encode(val, true);

    format_chunks_into_string(result, width, i, &val);

    for (name, val) in iter {
        let name = name.as_ref();
        if *i >= width {
            result.push_str("\r\n\t");
            *i = 1;
        }
        result.push('|');
        *i += 1;

        let namelen = name.chars().count() + 1;
        if *i + namelen <= width {
            result.push_str(name);
            result.push(':');
            *i += namelen;
        } else {
            result.push_str("\r\n\t");
            result.push_str(name);
            result.push(':');
            *i = namelen + 1;
        }

        let val = quoted_printable::dqp_encode(val, true);

        format_chunks_into_string(result, width, i, &val);
    }

    // no ; necessary
}

// note always:
// i: *char-based* line offset
// width: *char-based* line width
pub fn format_chunks_into_string(output: &mut String, width: usize, i: &mut usize, mut s: &str) {
    let first_chunk_len = width.saturating_sub(*i);
    let first_chunk_len = first_chunk_len.min(s.chars().count());

    if first_chunk_len > 0 {
        let c = match s.char_indices().nth(first_chunk_len) {
            Some((c, _)) => c,
            None => s.len(),
        };
        let first_chunk;
        (first_chunk, s) = s.split_at(c);
        output.push_str(first_chunk);
        *i += first_chunk.chars().count();
    }

    let chunk_width = width.saturating_sub(1).max(1);  // no empty chunks
    let chunk_iter = iter::from_fn(|| {
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

    for chunk in chunk_iter {
        output.push_str("\r\n\t");
        output.push_str(chunk);
        *i = chunk.chars().count() + 1;
    }
}

pub fn insert_signature_data(
    formatted_header: &mut String,
    insertion_index: usize,
    signature_data: &[u8],
    line_width: usize,
) {
    debug_assert!(insertion_index <= formatted_header.len());

    let s = util::encode_binary(signature_data);
    // note s contains only ASCII now

    let formatted_header_pre = &formatted_header[..insertion_index];

    let mut len = match formatted_header_pre.rsplit("\r\n").next() {
        Some(last_line) => last_line.chars().count(),
        None => DKIM_SIGNATURE_NAME.len() + formatted_header_pre.chars().count() + 1,
    };

    let mut result = String::with_capacity(s.len());
    format_chunks_into_string(&mut result, line_width, &mut len, &s);

    formatted_header.insert_str(insertion_index, &result);
}
