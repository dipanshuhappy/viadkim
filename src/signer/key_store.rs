use crate::crypto::SigningKey;
use std::{future::Future, io, sync::Arc};

// TODO the whole KeyId/KeyStore design doesn't really convince me

// TODO pub type KeyId = ...
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyId(usize);

impl KeyId {
    pub fn new(id: usize) -> Self {
        Self(id)
    }
}

pub trait KeyStore: Send + Sync {
    type Query<'a>: Future<Output = io::Result<Option<Arc<SigningKey>>>> + Send + 'a
    where
        Self: 'a;

    fn get(&self, key_id: KeyId) -> Self::Query<'_>;
}
