// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! Key rotator implementation, which provides key synchronization with Memcached server.

use lazy_static::lazy_static;

#[cfg(not(test))]
use memcache::MemcacheError;

use prometheus::{opts, register_counter, register_int_counter, IntCounter};

use ring::hmac;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::thread;
#[cfg(not(test))]
use std::time::SystemTime;
use std::time::{Duration, UNIX_EPOCH};

use crate::cookie::CookieKey;

lazy_static! {
    static ref ROTATION_COUNTER: IntCounter =
        register_int_counter!("ntp_key_rotations_total", "Number of key rotations").unwrap();
    static ref FAILURE_COUNTER: IntCounter = register_int_counter!(
        "ntp_key_rotations_failed_total",
        "Number of failures in key rotation"
    )
    .unwrap();
}

/// Key id for `KeyRotator`.
// This struct should be `Clone` and `Copy` because the internal representation is just a `u32`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KeyId(u32);

impl KeyId {
    /// Create `KeyId` from raw `u32`.
    pub fn new(key_id: u32) -> KeyId {
        KeyId(key_id)
    }

    /// Create `KeyId` from a `u64` epoch. The 32 most significant bits of the parameter will be
    /// discarded.
    pub fn from_epoch(epoch: u64) -> KeyId {
        // This will discard the 32 most significant bits.
        let epoch_residue = epoch as u32;
        KeyId(epoch_residue)
    }

    /// Create `KeyId` from its representation as a byte array in big endian.
    pub fn from_be_bytes(bytes: [u8; 4]) -> KeyId {
        KeyId(u32::from_be_bytes(bytes))
    }

    /// Return the memory representation of this `KeyId` as a byte array in big endian.
    pub fn to_be_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

/// Error struct returned from `KeyRotator::rotate` method.
#[derive(Debug)]
pub enum RotateError {
    /// Error from Memcached server.
    MemcacheError(MemcacheError),
    /// Error when the Memcached server doesn't have a specified `KeyId`.
    KeyIdNotFound(KeyId),
}

impl From<MemcacheError> for RotateError {
    /// Wrap MemcacheError.
    fn from(error: MemcacheError) -> RotateError {
        RotateError::MemcacheError(error)
    }
}

/// Key rotator.
pub struct KeyRotator {
    /// URL of the Memcached server.
    memcached_url: String,

    /// Prefix for the Memcached key.
    prefix: String,

    // This property type needs to fit an Epoch time in seconds.
    /// Length of each period in seconds.
    duration: u64,

    // The number of forward and backward periods are `u64` because the timestamp is `u64` and the
    // duration can be as small as 1.
    /// The number of future periods that the rotator must cache their values from the
    /// Memcached server.
    number_of_forward_periods: u64,

    /// The number of previous periods that the rotator must cache their values from the
    /// Memcached server.
    number_of_backward_periods: u64,

    /// Cookie key that will be used as a MAC key of the rotator.
    master_key: CookieKey,

    /// Key id of the current period.
    latest_key_id: KeyId,

    /// Cache store.
    cache: HashMap<KeyId, hmac::Tag>,

    /// Logger.
    // TODO: since we don't use the logger now, I will put an `allow(dead_code)` here first. I will
    // remove it when it's used.
    #[allow(dead_code)]
    logger: slog::Logger,
}

impl KeyRotator {
    /// Connect to the Memcached server and sync some inital keys.
    pub fn connect(
        prefix: String,
        memcached_url: String,
        master_key: CookieKey,
        logger: slog::Logger,
    ) -> Result<KeyRotator, RotateError> {
        let mut rotator = KeyRotator {
            // Zero shouldn't be a valid KeyId. This is just a temporary value.
            latest_key_id: KeyId::new(0),
            // The cache should never be empty. This is just a temporary value.
            cache: HashMap::new(),

            // It seems that currently we don't have to customize the following three properties,
            // so I will just put default values.
            duration: 3600,
            number_of_forward_periods: 2,
            number_of_backward_periods: 24,

            // From parameters.
            prefix,
            memcached_url,
            master_key,
            logger,
        };

        // Maximum number of times that we want to try rotating the keys.
        let maximum_try = 5;

        // Try to rotate the keys up to 5 times to make sure that the rotator has some keys in it.
        // If it doesn't, we will not have any key to use.
        for try_number in 1.. {
            match rotator.rotate() {
                Err(error) => {
                    // Side-effect. Logging.
                    // Disable the log for now because the Error trait is not implemented for
                    // RotateError yet.
                    // error!(rotator.logger, "failure to initialize key rotation: {}", error);

                    // If it already tried a lot of times already, it may be a time to give up.
                    if try_number == maximum_try {
                        return Err(error);
                    }

                    // Wait for 5 seconds before retrying key rotation.
                    std::thread::sleep(std::time::Duration::from_secs(5));
                }
                // If it's a success, stop retrying.
                Ok(()) => break,
            }
        }

        Ok(rotator)
    }

    /// Rotate keys.
    ///
    /// # Panics
    ///
    /// If the system time is before the UNIX Epoch time.
    ///
    /// # Errors
    ///
    /// There is an error, if there is a connection problem with Memcached server or the Memcached
    /// server doesn't contain a key id it supposed to contain.
    ///
    pub fn rotate(&mut self) -> Result<(), RotateError> {
        // Side-effect. It's not related to the operation.
        ROTATION_COUNTER.inc();

        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("The system time must be after the UNIX Epoch time.");

        // The number of seconds since the Epoch time.
        let timestamp = duration.as_secs();

        // The current period number of the timestamp.
        let current_period = timestamp / self.duration;
        // The timestamp at the beginning of the current period.
        let current_epoch = current_period * self.duration;

        // The first period number that we want to iterate through.
        let first_period = current_period.saturating_sub(self.number_of_backward_periods);

        // The last period number that we want to iterate through.
        let last_period = current_period.saturating_add(self.number_of_forward_periods);

        let removed_period = first_period.saturating_sub(1);
        let removed_epoch = removed_period * self.duration;
        self.cache_remove(KeyId::from_epoch(removed_epoch));

        // Connecting to memcached. I have to add [..] because it seems that Rust is not smart
        // enough to do auto-dereference.
        let mut client = memcache::Client::connect(&self.memcached_url[..])?;

        for period_number in first_period..=last_period {
            // The timestamp at the beginning of the period.
            let epoch = period_number * self.duration;

            let memcached_key = format!("{}/{}", self.prefix, epoch);
            let memcached_value: Option<Vec<u8>> = client.get(&memcached_key)?;

            let key_id = KeyId::from_epoch(epoch);
            match memcached_value {
                Some(value) => self.cache_insert(key_id, value.as_slice()),
                None => {
                    FAILURE_COUNTER.inc();
                    return Err(RotateError::KeyIdNotFound(key_id));
                }
            }
        }

        // Not all of our friends may have gotten the same forwards keys as we did.
        self.latest_key_id = KeyId::from_epoch(current_epoch);

        Ok(())
    }

    /// Add an entry to the cache.
    // It should be private. Don't make it public.
    fn cache_insert(&mut self, key_id: KeyId, value: &[u8]) {
        // Create a MAC key.
        let mac_key = hmac::Key::new(hmac::HMAC_SHA256, self.master_key.as_bytes());
        // Generating a MAC tag with a MAC key.
        let tag = hmac::sign(&mac_key, value);

        self.cache.insert(key_id, tag);
    }

    /// Remove an entry from the cache.
    // It should be private. Don't make it public.
    fn cache_remove(&mut self, key_id: KeyId) {
        self.cache.remove(&key_id);
    }

    /// Return the latest key id and hmac tag of the rotator.
    pub fn latest_key_value(&self) -> (KeyId, &hmac::Tag) {
        // This unwrap cannot panic because the HashMap will always contain the latest key id.
        (self.latest_key_id, self.get(self.latest_key_id).unwrap())
    }

    /// Return an entry in the cache using a key id.
    pub fn get(&self, key_id: KeyId) -> Option<&hmac::Tag> {
        self.cache.get(&key_id)
    }
}

pub fn periodic_rotate(rotor: Arc<RwLock<KeyRotator>>) {
    let mut rotor = rotor;
    thread::spawn(move || loop {
        inner(&mut rotor);
        let restlen = read_sleep(&rotor);
        thread::sleep(Duration::from_secs(restlen));
    });
}

fn inner(rotor: &mut Arc<RwLock<KeyRotator>>) {
    let _ = rotor.write().unwrap().rotate();
}

fn read_sleep(rotor: &Arc<RwLock<KeyRotator>>) -> u64 {
    rotor.read().unwrap().duration
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
use ::memcache::MemcacheError;
#[cfg(test)]
use test::memcache;
#[cfg(test)]
use test::SystemTime;

#[cfg(test)]
mod test {
    use super::*;

    use ::memcache::MemcacheError;
    use lazy_static::lazy_static;
    use sloggers::null::NullLoggerBuilder;
    use sloggers::Build;
    use std::sync::Mutex;
    use std::time::Duration;

    // Mocking memcache.
    pub mod memcache {
        use super::*;
        use std::collections::HashMap;

        lazy_static! {
            pub static ref HASH_MAP: Mutex<HashMap<String, Vec<u8>>> = Mutex::new(HashMap::new());
        }
        pub struct Client;
        impl Client {
            pub fn connect(_url: &str) -> Result<Client, MemcacheError> {
                Ok(Client)
            }
            pub fn get(&mut self, key: &str) -> Result<Option<Vec<u8>>, MemcacheError> {
                Ok(HASH_MAP.lock().unwrap().get(&String::from(key)).cloned())
            }
        }
    }

    // Mocking SystemTime.
    lazy_static! {
        pub static ref NOW: Mutex<u64> = Mutex::new(0);
    }
    pub struct SystemTime;
    impl SystemTime {
        pub fn now() -> std::time::SystemTime {
            let now = NOW.lock().unwrap();
            let duration = Duration::new(*now, 0);
            UNIX_EPOCH.checked_add(duration).unwrap()
        }
    }

    #[test]
    fn test_rotation() {
        use self::memcache::HASH_MAP;

        let mut hash_map = HASH_MAP.lock().unwrap();
        hash_map.insert("test/1".to_string(), vec![1; 32]);
        hash_map.insert("test/2".to_string(), vec![2; 32]);
        hash_map.insert("test/3".to_string(), vec![3; 32]);
        hash_map.insert("test/4".to_string(), vec![4; 32]);
        drop(hash_map);

        let mut rotator = KeyRotator {
            memcached_url: String::from("unused"),
            prefix: String::from("test"),
            duration: 1,
            number_of_forward_periods: 1,
            number_of_backward_periods: 1,
            master_key: CookieKey::from(&[0, 32][..]),
            latest_key_id: KeyId::from_be_bytes([1, 2, 3, 4]),
            cache: HashMap::new(),
            logger: NullLoggerBuilder.build().unwrap(),
        };

        *NOW.lock().unwrap() = 2;
        // No error because the hash map has "test/1", "test/2", and "test/3".
        rotator.rotate().unwrap();
        let old_latest = rotator.latest_key_id;

        *NOW.lock().unwrap() = 3;
        // No error because the hash map has "test/2", "test/3", and "test/4".
        rotator.rotate().unwrap();
        let new_latest = rotator.latest_key_id;

        // The key id should change.
        assert_ne!(old_latest, new_latest);

        *NOW.lock().unwrap() = 1;
        // Return error because the hash map doesn't have "test/0".
        rotator.rotate().unwrap_err();

        *NOW.lock().unwrap() = 4;
        // Return error because the hash map doesn't have "test/5".
        rotator.rotate().unwrap_err();
    }
}
