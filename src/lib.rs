//! DKIM library.
//!
//! *experimental, in development*

// - secure
// - RFCs compliance
// - focus on compatibility and interoperability
//   - balance compatibility with security
//   - be lenient on inputs so far as sensible in terms of security
//   - where acceptable, don't require valid UTF-8
//   - support widespread non-standard key formats
//
// Credits:
// While this is an independent implementation that was created from scratch it
// is worth crediting the excellent OpenDKIM library. The 'staged' design, that
// does not require the whole message in memory at once, is inspired from
// OpenDKIM.

// #![allow(unused_imports, unused_variables)]
// #![allow(dead_code, unused_imports, unused_variables)]

pub mod canon;  // c14n ?
pub mod crypto;
mod dqp;
pub mod header;
mod parse;
pub mod record;
pub mod signature;
pub mod signer;
mod tag_list;
pub mod verifier;

pub use crate::{
    crypto::SigningKey,
    header::{FieldBody, FieldName, HeaderFields},
    signature::{Canonicalization, CanonicalizationAlgorithm, SignatureAlgorithm},
    signer::{Signer, SignerError, SigningRequest},
    verifier::{VerificationResult, VerificationStatus, Verifier, VerifierError},
};
