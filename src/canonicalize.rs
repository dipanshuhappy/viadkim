//! Canonicalization utilities.

use crate::{
    header::{FieldName, HeaderFields, FieldBody},
    signature::CanonicalizationAlgorithm,
};
use bstr::ByteSlice;
use std::collections::HashSet;

const SP: u8 = b' ';
const CR: u8 = b'\r';
const LF: u8 = b'\n';
const CRLF: [u8; 2] = [CR, LF];

// which state are we in = what did we see last?
#[derive(Copy, Clone)]
enum CanonState {
    Init,
    CrLf,
    Cr,
    Wsp,
    WspCr,
    Byte,
}

/// A canonicalizer using the body canonicalization algorithm.
pub struct BodyCanonicalizer {
    kind: CanonicalizationAlgorithm,
    state: CanonState,
    blank_line: bool,  // whether currently on an empty or blank line
    empty_lines: usize,  // number of empty lines seen
}

impl BodyCanonicalizer {
    pub fn simple() -> Self {
        Self::new(CanonicalizationAlgorithm::Simple)
    }

    pub fn relaxed() -> Self {
        Self::new(CanonicalizationAlgorithm::Relaxed)
    }

    fn new(kind: CanonicalizationAlgorithm) -> Self {
        Self {
            kind,
            state: CanonState::Init,
            blank_line: true,
            empty_lines: 0,
        }
    }

    // canonicalisation recognises only CRLF as line separator/terminator, stray
    // CR and LF are treated like other bytes
    pub fn canon_chunk(&mut self, bytes: &[u8]) -> Vec<u8> {
        match self.kind {
            CanonicalizationAlgorithm::Simple => self.canon_chunk_simple(bytes),
            CanonicalizationAlgorithm::Relaxed => self.canon_chunk_relaxed(bytes),
        }
    }

    fn canon_chunk_simple(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut result = vec![];

        for &b in bytes {
            match self.state {
                CanonState::Init | CanonState::CrLf => {
                    if b == CR {
                        self.state = CanonState::Cr;
                    } else {
                        self.flush_empty_lines(&mut result);
                        result.push(b);
                        self.state = CanonState::Byte;
                    }
                }
                CanonState::Cr => {
                    if b == LF {
                        if self.blank_line {
                            self.empty_lines += 1;
                        } else {
                            result.extend(CRLF);
                            self.blank_line = true;
                        }
                        self.state = CanonState::CrLf;
                        continue;
                    }

                    self.flush_empty_lines(&mut result);
                    result.push(CR);

                    if b != CR {
                        result.push(b);
                        self.state = CanonState::Byte;
                    }
                }
                CanonState::Byte => {
                    if b == CR {
                        self.state = CanonState::Cr;
                    } else {
                        result.push(b);
                    }
                }
                CanonState::Wsp | CanonState::WspCr => unreachable!(),
            }
        }

        result
    }

    fn canon_chunk_relaxed(&mut self, bytes: &[u8]) -> Vec<u8> {
        fn is_wsp(b: u8) -> bool {
            matches!(b, b'\t' | b' ')
        }

        let mut result = vec![];

        for &b in bytes {
            match self.state {
                CanonState::Init | CanonState::CrLf => {
                    if is_wsp(b) {
                        self.state = CanonState::Wsp;
                    } else if b == CR {
                        self.state = CanonState::Cr;
                    } else {
                        self.flush_empty_lines(&mut result);
                        result.push(b);
                        self.state = CanonState::Byte;
                    }
                }
                CanonState::Wsp => {
                    if b == CR {
                        self.state = CanonState::WspCr;
                    } else if !is_wsp(b) {
                        self.flush_empty_lines(&mut result);
                        result.push(SP);
                        result.push(b);
                        self.state = CanonState::Byte;
                    }
                }
                CanonState::Cr => {
                    if b == LF {
                        if self.blank_line {
                            self.empty_lines += 1;
                        } else {
                            result.extend(CRLF);
                            self.blank_line = true;
                        }
                        self.state = CanonState::CrLf;
                        continue;
                    }

                    self.flush_empty_lines(&mut result);
                    result.push(CR);

                    if is_wsp(b) {
                        self.state = CanonState::Wsp;
                    } else if b != CR {
                        result.push(b);
                        self.state = CanonState::Byte;
                    }
                }
                CanonState::WspCr => {
                    if b == LF {
                        if self.blank_line {
                            self.empty_lines += 1;
                        } else {
                            result.extend(CRLF);
                            self.blank_line = true;
                        }
                        self.state = CanonState::CrLf;
                        continue;
                    }

                    self.flush_empty_lines(&mut result);
                    result.push(SP);
                    result.push(CR);

                    if b == CR {
                        self.state = CanonState::Cr;
                    } else if is_wsp(b) {
                        self.state = CanonState::Wsp;
                    } else {
                        result.push(b);
                        self.state = CanonState::Byte;
                    }
                }
                CanonState::Byte => {
                    if is_wsp(b) {
                        self.state = CanonState::Wsp;
                    } else if b == CR {
                        self.state = CanonState::Cr;
                    } else {
                        result.push(b);
                    }
                }
            }
        }

        result
    }

    pub fn finish_canon(mut self) -> Vec<u8> {
        match self.kind {
            CanonicalizationAlgorithm::Simple => {
                match self.state {
                    CanonState::Init => CRLF.to_vec(),  // empty body is CRLF
                    CanonState::CrLf => vec![],
                    CanonState::Cr => {
                        let mut result = vec![];  // final chunk to hash
                        self.flush_empty_lines(&mut result);
                        result.push(CR);
                        result.extend(CRLF);  // body needs final CRLF
                        result
                    }
                    CanonState::Byte => CRLF.to_vec(),  // body needs final CRLF
                    CanonState::Wsp | CanonState::WspCr => unreachable!(),
                }
            }
            CanonicalizationAlgorithm::Relaxed => {
                match self.state {
                    CanonState::Init | CanonState::CrLf => vec![],
                    CanonState::Cr => {
                        let mut result = vec![];
                        self.flush_empty_lines(&mut result);
                        result.push(CR);
                        result.extend(CRLF);  // non-empty body needs final CRLF
                        result
                    }
                    CanonState::Wsp => {
                        // unspecified how to treat final WSP: drop, no flush
                        CRLF.to_vec()  // non-empty body needs final CRLF
                    }
                    CanonState::WspCr => {
                        let mut result = vec![];
                        self.flush_empty_lines(&mut result);
                        result.push(SP);
                        result.push(CR);
                        result.extend(CRLF);  // non-empty body needs final CRLF
                        result
                    }
                    CanonState::Byte => CRLF.to_vec(),  // non-empty body needs final CRLF
                }
            }
        }
    }

    // write out remembered empty lines after encountering/before processing
    // byte that ends a section of empty lines
    fn flush_empty_lines(&mut self, result: &mut Vec<u8>) {
        for _ in 0..self.empty_lines {
            result.extend(CRLF);
        }
        self.empty_lines = 0;
        self.blank_line = false;
    }
}

/// Produces the header canonicalization result for some header fields.
pub fn canonicalize_headers(
    canon_alg: CanonicalizationAlgorithm,
    headers: &HeaderFields,
    selected_headers: &[FieldName],
) -> Vec<u8> {
    let mut result = vec![];
    let mut processed_indexes = HashSet::with_capacity(selected_headers.len());

    for selected_header in selected_headers {
        for (i, (name, val)) in headers
            .as_ref()
            .iter()
            .rev()
            .enumerate()
            .filter(|(i, _)| !processed_indexes.contains(i))
        {
            if name == selected_header {
                canonicalize_header(&mut result, canon_alg, name, val);

                result.extend(CRLF);

                processed_indexes.insert(i);

                break;
            }
        }
    }

    result
}

/// Canonicalizes a header field into some result vector.
pub fn canonicalize_header(
    result: &mut Vec<u8>,
    algorithm: CanonicalizationAlgorithm,
    name: impl AsRef<str>,
    value: impl AsRef<[u8]>,
) {
    let name = name.as_ref();
    let value = value.as_ref();

    match algorithm {
        CanonicalizationAlgorithm::Simple => {
            result.extend(name.bytes());
            result.push(b':');
            result.extend(value);
        }
        CanonicalizationAlgorithm::Relaxed => {
            result.extend(name.to_ascii_lowercase().bytes());
            result.push(b':');
            canonicalize_header_relaxed(result, value);
        }
    }
}

fn canonicalize_header_relaxed(canon_headers: &mut Vec<u8>, value: &[u8]) {
    fn is_space(c: char) -> bool {
        matches!(c, ' ' | '\t' | '\r' | '\n')
    }

    debug_assert!(FieldBody::new(value).is_ok());

    let value = value.trim_with(is_space);

    let mut compressing = false;
    for &b in value {
        if is_space(b.into()) {
            if !compressing {
                canon_headers.push(SP);
                compressing = true;
            }
        } else {
            canon_headers.push(b);
            if compressing {
                compressing = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bstr::BStr;

    #[test]
    fn canonicalize_headers_relaxed_ok() {
        let headers = HeaderFields::from_vec(vec![
            ("from".to_owned(), b" Good \t ".to_vec()),
            ("to".to_owned(), b" see   me".to_vec()),
            ("Date".to_owned(), b" Fri 24\r\n\tfoo".to_vec()),
            ("To".to_owned(), b" another one".to_vec()),
        ])
        .unwrap();

        let selected_headers = vec![
            FieldName::new("to").unwrap(),
            FieldName::new("from").unwrap(),
            FieldName::new("to").unwrap(),
        ];

        assert_eq!(
            BStr::new(&canonicalize_headers(
                CanonicalizationAlgorithm::Relaxed,
                &headers,
                &selected_headers,
            )),
            BStr::new(&b"to:another one\r\nfrom:Good\r\nto:see me\r\n"[..]),
        );
    }

    #[test]
    fn body_canon_simple_ok() {
        let bc = BodyCanonicalizer::simple();

        let body = canonicalize_chunks(
            bc,
            &[b"well  hello \r\n", b"\r\n what agi \r\n\r\n", b"\r\n"],
        );

        assert_eq!(body, b"well  hello \r\n\r\n what agi \r\n");
    }

    #[test]
    fn body_canon_relaxed_basic() {
        let bc = BodyCanonicalizer::relaxed();

        let body = canonicalize_chunks(
            bc,
            &[b"well  hello \r\n", b"\r\n what agi \r\n\r\n", b"\r\n"],
        );

        assert_eq!(body, b"well hello\r\n\r\n what agi\r\n");
    }

    #[test]
    fn body_canon_relaxed_small_chunks() {
        let bc = BodyCanonicalizer::relaxed();

        let body = canonicalize_chunks(
            bc,
            &[
                b"well ",
                b" hello ",
                b"\r",
                b"\n\r",
                b"\n what agi \r\n\r\n",
                b"\r\n",
            ],
        );

        assert_eq!(body, b"well hello\r\n\r\n what agi\r\n");
    }

    #[test]
    fn body_canon_relaxed_initial_empty_lines() {
        let bc = BodyCanonicalizer::relaxed();

        let body = canonicalize_chunks(bc, &[b"\r\n\r\n", b"\ra \r", b"\nb  ", b"c"]);

        assert_eq!(body, b"\r\n\r\n\ra\r\nb c\r\n");
    }

    fn canonicalize_chunks(mut bc: BodyCanonicalizer, chunks: &[&[u8]]) -> Vec<u8> {
        let mut result = vec![];
        for c in chunks {
            result.extend(bc.canon_chunk(c));
        }
        result.extend(bc.finish_canon());
        result
    }
}
