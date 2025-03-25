// Copyright (c) Zefchain Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::CryptoRng;
use crate::{
    crypto::{AccountPublicKey, AccountSecretKey, AccountSignature, BcsSignable},
    identifiers::AccountOwner,
};

/// Wrapper around bytes that can be signed.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignableBytes(Vec<u8>);
impl SignableBytes {
    /// Creates a new `SignableBytes` from the given bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        SignableBytes(bytes)
    }

    /// Returns the inner bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl BcsSignable<'_> for SignableBytes {}

/// A trait for signing keys.
#[cfg_attr(not(web), trait_variant::make(Send + Sync))]
pub trait Signer {
    /// Generates a new signing key for the Self type.
    /// New secret key is inserted into Signer's memory and the `AccountPublicKey` is returned.
    #[cfg(with_getrandom)]
    fn generate_new(&mut self) -> AccountPublicKey;

    /// Creates a signature for the given `value` using the provided `owner`.
    fn sign(&self, owner: &AccountOwner, value: &SignableBytes) -> Option<AccountSignature>;

    /// Returns the public key corresponding to the given `owner`.
    fn get_public(&self, owner: &AccountOwner) -> Option<AccountPublicKey>;

    /// Returnes whether the given `owner` is a known signer.
    fn contains_key(&self, owner: &AccountOwner) -> bool;

    /// Removes the key for the given `owner`.
    fn remove(&mut self, owner: &AccountOwner) -> bool;

    /// Returns a clone of the `Signer` as a boxed trait object.
    fn clone_box(&self) -> Box<dyn Signer>;

    /// Returns an iterator over the keys in the signer.
    fn keys(&self) -> Vec<(AccountOwner, Vec<u8>)>;
}

impl Serialize for InMemSigner {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct Inner<'a> {
            prng_seed: Option<u64>,
            keys_generated: u64,
            keys: &'a Vec<(AccountOwner, Vec<u8>)>,
        }
        let inner = Inner {
            prng_seed: self.prng_seed,
            keys_generated: self.keys_generated,
            keys: &self.keys(),
        };
        Inner::serialize(&inner, serializer)
    }
}

impl<'de> Deserialize<'de> for InMemSigner {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Inner {
            prng_seed: Option<u64>,
            keys_generated: u64,
            keys: Vec<(AccountOwner, Vec<u8>)>,
        }
        let inner = Inner::deserialize(deserializer)?;

        Ok(InMemSigner {
            prng_seed: inner.prng_seed,
            keys_generated: inner.keys_generated,
            prng: inner.prng_seed.into(),
            keys: inner
                .keys
                .into_iter()
                .map(|(owner, secret)| {
                    let secret =
                        serde_json::from_slice(&secret).map_err(serde::de::Error::custom)?;
                    Ok((owner, secret))
                })
                .collect::<Result<BTreeMap<_, _>, _>>()?,
        })
    }
}

impl Clone for Box<dyn Signer> {
    fn clone(&self) -> Box<dyn Signer> {
        self.clone_box()
    }
}

impl Signer for Box<dyn Signer> {
    fn generate_new(&mut self) -> AccountPublicKey {
        (**self).generate_new()
    }

    fn sign(&self, owner: &AccountOwner, value: &SignableBytes) -> Option<AccountSignature> {
        (**self).sign(owner, value)
    }

    fn get_public(&self, owner: &AccountOwner) -> Option<AccountPublicKey> {
        (**self).get_public(owner)
    }

    fn contains_key(&self, owner: &AccountOwner) -> bool {
        (**self).contains_key(owner)
    }

    fn remove(&mut self, owner: &AccountOwner) -> bool {
        (**self).remove(owner)
    }

    fn clone_box(&self) -> Box<dyn Signer> {
        (**self).clone_box()
    }

    fn keys(&self) -> Vec<(AccountOwner, Vec<u8>)> {
        (**self).keys()
    }
}

/// In-memory signer.
pub struct InMemSigner {
    prng_seed: Option<u64>,
    keys_generated: u64,
    prng: Box<dyn CryptoRng>,
    keys: BTreeMap<AccountOwner, AccountSecretKey>,
}

impl InMemSigner {
    /// Creates a new `InMemSigner`.
    pub fn new(prng_seed: Option<u64>) -> Self {
        let prng: Box<dyn CryptoRng> = prng_seed.into();
        InMemSigner {
            prng_seed,
            keys_generated: 0,
            prng,
            keys: BTreeMap::new(),
        }
    }
}

impl<T: IntoIterator<Item = (AccountOwner, AccountSecretKey)>> From<T> for InMemSigner {
    fn from(input: T) -> Self {
        InMemSigner {
            prng_seed: None,
            keys_generated: 0,
            prng: None.into(),
            keys: BTreeMap::from_iter(input),
        }
    }
}

impl Default for InMemSigner {
    fn default() -> Self {
        InMemSigner::new(None)
    }
}

impl Clone for InMemSigner {
    fn clone(&self) -> Self {
        let mut keys = BTreeMap::new();
        for (owner, secret) in self.keys.iter() {
            keys.insert(*owner, secret.copy());
        }
        let prng = self.prng_seed.into();
        InMemSigner {
            prng_seed: self.prng_seed,
            keys_generated: self.keys_generated,
            prng,
            keys,
        }
    }
}

impl Signer for InMemSigner {
    /// Generates a new key pair from Signer's RNG. Use with care.
    #[cfg(with_getrandom)]
    fn generate_new(&mut self) -> AccountPublicKey {
        let secret = AccountSecretKey::generate_from(&mut self.prng);
        self.keys_generated
            .checked_add(1)
            .expect("too many keys generated");
        let public = secret.public();
        let owner = AccountOwner::from(public);
        self.keys.insert(owner, secret);
        public
    }

    /// Creates a signature for the given `value` using the provided `owner`.
    fn sign(&self, owner: &AccountOwner, value: &SignableBytes) -> Option<AccountSignature> {
        let secret = self.keys.get(owner)?;
        let signature = secret.sign(value);
        Some(signature)
    }

    /// Returns the public key corresponding to the given `owner`.
    fn get_public(&self, owner: &AccountOwner) -> Option<AccountPublicKey> {
        let secret = self.keys.get(owner)?;
        Some(secret.public())
    }

    /// Returnes whether the given `owner` is a known signer.
    fn contains_key(&self, owner: &AccountOwner) -> bool {
        self.keys.contains_key(owner)
    }

    /// Removes the key for the given `owner`.
    fn remove(&mut self, owner: &AccountOwner) -> bool {
        self.keys.remove(owner).is_some()
    }

    fn clone_box(&self) -> Box<dyn Signer> {
        Box::new(self.clone())
    }

    fn keys(&self) -> Vec<(AccountOwner, Vec<u8>)> {
        self.keys
            .iter()
            .map(|(owner, secret)| {
                (
                    *owner,
                    serde_json::to_vec(secret).expect("serialization should not fail"),
                )
            })
            .collect()
    }
}

impl Default for Box<dyn Signer> {
    fn default() -> Self {
        Box::new(InMemSigner::new(None))
    }
}
