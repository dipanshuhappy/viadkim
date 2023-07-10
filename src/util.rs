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

use base64ct::{Base64, Encoding};
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

/// A trait for entities that have a canonical string representation in the DKIM
/// specification.
pub trait CanonicalStr {
    /// Returns the canonical representation as a static string slice.
    fn canonical_str(&self) -> &'static str;
}

/// Encodes binary data as a Base64 string.
pub fn encode_base64<T: AsRef<[u8]>>(input: T) -> String {
    Base64::encode_string(input.as_ref())
}

/// An error that occurs when decoding Base64-encoded data.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Base64Error;

impl Display for Base64Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "failed to decode Base64 data")
    }
}

impl Error for Base64Error {}

/// Decodes binary data from a Base64-encoded string.
pub fn decode_base64(input: &str) -> Result<Vec<u8>, Base64Error> {
    Base64::decode_vec(input).map_err(|_| Base64Error)
}

/// Helper for `fmt::Debug` implementations of binary byte slices.
pub struct Base64Debug<'a>(pub &'a [u8]);

impl fmt::Debug for Base64Debug<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // This displays the byte slice as Base64, without the surrounding
        // double quotes usually used for strings.
        //
        // The awkward implementation is due to the possibility of empty byte
        // slices. In these cases, `write!(f, "{}", …)` prints nothing at all,
        // which looks unpleasant. This implementation introduces a wrapping
        // `Base64(…)` pseudo-tuple, and `Empty` for empty slices.

        struct Base64DebugHelper<'a>(&'a str);

        impl fmt::Debug for Base64DebugHelper<'_> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        let s = encode_base64(self.0);

        if s.is_empty() {
            write!(f, "Empty")
        } else {
            f.debug_tuple("Base64")
                .field(&Base64DebugHelper(&s))
                .finish()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_debug_ok() {
        assert_eq!(format!("{:?}", Base64Debug(&[])), "Empty");
        assert_eq!(format!("{:?}", Base64Debug(&[1, 2, 3])), "Base64(AQID)");
    }
}
