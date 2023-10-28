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

#[cfg(feature = "hickory-resolver")]
mod hickory_resolver;

use std::{future::Future, io};

/// A trait for looking up DNS TXT records containing DKIM public key records.
///
/// The error type used here is `std::io::Error`. The following error kinds on
/// the query result are recognised and receive special treatment.
///
/// * `ErrorKind::InvalidInput` on the query: the domain argument could not be used
/// * `ErrorKind::NotFound` on the query: NXDOMAIN, no key record found
/// * `ErrorKind::TimedOut` on the query: timeout
///
/// The inner, per-record `std::io::Error` can be used to signal errors
/// (parsing, encoding) with individual TXT records.
///
/// If **Cargo feature `hickory-resolver`** is enabled, an implementation of
/// this trait for the Hickory DNS `TokioAsyncResolver` is provided.
pub trait LookupTxt: Send + Sync {
    /// The answer consisting of TXT records found.
    type Answer: IntoIterator<Item = io::Result<Vec<u8>>>;
    /// The future resolving to the query’s answer.
    type Query<'a>: Future<Output = io::Result<Self::Answer>> + Send + 'a
    where
        Self: 'a;

    /// Looks up the domain’s TXT records in DNS.
    ///
    /// The domain will be passed to this method as a string in absolute,
    /// A-label (ASCII) format (eg `selector._domainkey.example.com.`). In the
    /// answer, if a TXT record consists of multiple character strings these
    /// should be concatenated into a single byte vector.
    ///
    /// Note that according to RFC 6376, the final answer is expected to contain
    /// only a single TXT record (but DNS allows > 1).
    fn lookup_txt(&self, domain: &str) -> Self::Query<'_>;
}
