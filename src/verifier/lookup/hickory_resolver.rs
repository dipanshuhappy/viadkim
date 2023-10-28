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

use super::LookupTxt;
use hickory_resolver::{error::ResolveErrorKind, Name, TokioAsyncResolver};
use std::{
    future::Future,
    io::{self, ErrorKind},
    pin::Pin,
};

impl LookupTxt for TokioAsyncResolver {
    type Answer = Box<dyn Iterator<Item = io::Result<Vec<u8>>>>;
    type Query<'a> = Pin<Box<dyn Future<Output = io::Result<Self::Answer>> + Send + 'a>>;

    fn lookup_txt(&self, domain: &str) -> Self::Query<'_> {
        let name = Name::from_ascii(domain);

        Box::pin(async move {
            let name = name.map_err(|_| ErrorKind::InvalidInput)?;

            let lookup = self.txt_lookup(name).await.map_err(|e| match e.kind() {
                ResolveErrorKind::NoRecordsFound { .. } => io::Error::from(ErrorKind::NotFound),
                _ => e.into(),
            })?;

            let txts = lookup.into_iter().map(|txt| Ok(txt.txt_data().concat()));

            let txts: Box<dyn Iterator<Item = _>> = Box::new(txts);

            Ok(txts)
        })
    }
}
