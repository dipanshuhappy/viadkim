/// A trait for entities that can be represented as a canonical string.
pub trait CanonicalStr {
    /// Returns the canonical representation as a static string slice.
    fn canonical_str(&self) -> &'static str;
}
