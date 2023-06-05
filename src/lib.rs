//! DKIM library.
//!
//! 🚧
//!
//! ***experimental, in development***
//!
//! 🏗
//!
//! A library implementing the *DomainKeys Identified Mail* (DKIM) specification
//! described in RFC 6376.
//!
//! This library provides APIs to sign email messages using DKIM signatures, and
//! to verify such signatures.
//!
//! # Usage
//!
//! The types [`Signer`] and [`Verifier`] provide the entry points to signing
//! and verifying with viadkim.
//!
//! # Cargo features
//!
//! The feature **`trust-dns-resolver`** makes an implementation of `LookupTxt`
//! available for the Trust-DNS resolver.
//!
//! The feature **`sha1`** enables the insecure, historic SHA-1 hash algorithm.
//! In the API and implementation, wherever there is support for the SHA-256
//! hash algorithm, with this feature additional support for SHA-1 becomes
//! available. This is a legacy compatibility feature, its use is strongly
//! discouraged.

pub mod canonicalize;
pub mod crypto;
pub mod header;
pub mod message_hash;
mod parse;
mod quoted_printable;
pub mod record;
pub mod signature;
pub mod signer;
mod tag_list;
mod util;
pub mod verifier;

pub use crate::{
    crypto::SigningKey,
    header::{FieldBody, FieldName, HeaderField, HeaderFields},
    signer::{Signer, SignerError},
    util::{encode_binary, CanonicalStr},
    verifier::{VerificationResult, VerificationStatus, Verifier, VerifierError},
};
