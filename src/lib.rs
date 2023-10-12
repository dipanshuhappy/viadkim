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

//! A library implementing the *DomainKeys Identified Mail* (DKIM) specification
//! described in [RFC 6376].
//!
//! This library provides both high-level APIs for signing and verifying, as
//! well as low-level APIs that cover the various DKIM protocol areas.
//!
//! The high-level API can be used to sign email messages using DKIM signatures
//! (module `signer`), and to verify such signatures (module `verifier`). Most
//! users will want to deal with DKIM via these APIs. For convenience, all the
//! relevant items are re-exported at the top level.
//!
//! The high-level API exposes various configuration options for both the
//! signing and verification process. It is, however, closed, and not
//! extensible. Instead, the low-level building blocks are provided in various
//! additional modules. They contain basic helpers for cryptography,
//! canonicalisation, encoding, etc. Users familiar with DKIM could use these
//! building blocks to build their own signing and verification facilities.
//!
//! # Usage
//!
//! The types [`Signer`] and [`Verifier`] provide the entry points to signing
//! and verifying with viadkim.
//!
//! See the examples for `Signer` and `Verifier` for basic usage.
//!
//! # Cargo features
//!
//! The feature **`trust-dns-resolver`** makes an implementation of trait
//! [`LookupTxt`][crate::verifier::LookupTxt] available for the [Trust-DNS
//! resolver]. `LookupTxt` is the abstraction used for DNS resolution during
//! verification.
//!
//! The feature **`pre-rfc8301`** reverts cryptographic algorithm and key usage
//! back to before [RFC 8301]: it lowers the minimum RSA key size to 512 bits,
//! and enables the insecure, historic SHA-1 hash algorithm. In the API and
//! implementation, wherever there is support for the SHA-256 hash algorithm,
//! with this feature additional support for SHA-1 becomes available. This is a
//! legacy compatibility feature, its use is strongly discouraged.
//!
//! # Trace logging
//!
//! This library uses the [tracing] crate for internal trace logging. For
//! insight into library operation, install a [tracing
//! subscriber][tracing-subscriber] and enable logging at `trace` level.
//!
//! [RFC 6376]: https://www.rfc-editor.org/rfc/rfc6376
//! [RFC 8301]: https://www.rfc-editor.org/rfc/rfc8301
//! [Trust-DNS resolver]: https://crates.io/crates/trust-dns-resolver
//! [tracing]: https://crates.io/crates/tracing
//! [tracing-subscriber]: https://crates.io/crates/tracing-subscriber

// Trace logging: logging about internal operation via `tracing::trace!` is done
// only in the high-level API in modules `signer` and `verifier`.

// Throughout, where RFC 6376 is quoted in comments, section numbers are
// referred to with the symbol ‘§’ (also where RFC 6376 is not mentioned).

pub mod canonicalize;
pub mod crypto;
pub mod header;
pub mod message_hash;
mod parse;
pub mod quoted_printable;
pub mod record;
pub mod signature;
pub mod signer;
mod tag_list;
mod util;
pub mod verifier;

pub use crate::{
    crypto::SigningKey,
    header::{FieldBody, FieldName, HeaderField, HeaderFields},
    signature::{DomainName, Selector, SigningAlgorithm},
    signer::{RequestError, SignRequest, Signer, SigningError, SigningResult},
    util::{decode_base64, encode_base64, Base64Error, CanonicalStr},
    verifier::{
        Config, DkimResult, VerificationError, VerificationResult, VerificationStatus, Verifier,
    },
};
