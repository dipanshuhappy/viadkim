use base64ct::{Base64, Encoding};

/// A trait for entities that can be represented as a canonical string.
pub trait CanonicalStr {
    /// Returns the canonical representation as a static string slice.
    fn canonical_str(&self) -> &'static str;
}

// TODO rename _base64
// TODO also provide decode_base64 (could be used for trying to parse *Error::signature_data_base64)
/// Encodes binary data as a Base64 string.
pub fn encode_binary<T: AsRef<[u8]>>(input: T) -> String {
    Base64::encode_string(input.as_ref())
}
