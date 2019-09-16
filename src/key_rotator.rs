// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! Key rotator.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use memcache;
use memcache::MemcacheError;

use lazy_static::lazy_static;
use prometheus::{opts, register_counter, register_int_counter, IntCounter};
use slog::{error};

use ring::digest;
use ring::hmac;

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
    pub fn new() -> KeyId {
        KeyId(0)
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
    pub fn to_be_bytes(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

pub struct KeyRotator {
    pub memcached_url: String,
    pub prefix: String,

    // This property type needs to fit an Epoch time in seconds.
    pub duration: u64,

    // The number of forward and backward periods are `u64` because the timestamp is `u64` and the
    // duration can be as small as 1.
    pub number_of_forward_periods: u64,
    pub number_of_backward_periods: u64,

    pub master_key: CookieKey,
    pub latest: KeyId,
    pub keys: HashMap<KeyId, Vec<u8>>,
    pub logger: slog::Logger,
}

trait VecMap {
    fn get(&mut self, key: &str) -> Result<Option<Vec<u8>>, MemcacheError>;
}

struct MemcacheVecMap {
    client: memcache::Client,
}

impl VecMap for MemcacheVecMap {
    fn get(&mut self, key: &str) -> Result<Option<Vec<u8>>, MemcacheError> {
        self.client.get::<Vec<u8>>(key)
    }
}

impl KeyRotator {
    /// Create a `KeyRotator` instance with the given parameters.
    pub fn new(
        prefix: String,
        memcached_url: String,
        master_key: CookieKey,
        logger: slog::Logger,
    ) -> KeyRotator {
        KeyRotator {
            latest: KeyId::new(),
            keys: HashMap::new(),

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
        }
    }

    /// Rotate keys.
    pub fn rotate(&mut self) -> Result<(), Box<std::error::Error>> {
        // Side-effect. It's not related to the operation.
        ROTATION_COUNTER.inc();

        // Connecting to memcached. I have to add [..] because it seems that Rust is not smart
        // enough to do auto-dereference.
        let client = memcache::Client::connect(&self.memcached_url[..])?;

        let duration = SystemTime::now().duration_since(UNIX_EPOCH)?;
        // The number of seconds since the Epoch time.
        let timestamp = duration.as_secs();

        let mut vecmap = MemcacheVecMap { client: client };
        self.internal_rotate(&mut vecmap, timestamp)
    }

    fn internal_rotate(&mut self, client: &mut dyn VecMap, timestamp: u64)
        -> Result<(), Box<std::error::Error>>
    {
        // The current period number of the timestamp.
        let current_period = timestamp / self.duration;
        // The timestamp at the beginning of the current period.
        let current_epoch = current_period * self.duration;

        // The first period number that we want to iterate through.
        let first_period = current_period - self.number_of_backward_periods;

        // The last period number that we want to iterate through.
        let last_period = current_period + self.number_of_forward_periods;

        let mut failed = false;

        for period_number in first_period..=last_period {
            // The timestamp at the beginning of the period.
            let epoch = period_number * self.duration;

            let memcached_key = format!("{}/{}", self.prefix, period_number);
            let memcached_value = client.get(&memcached_key)?;

            let key_id = KeyId::from_epoch(epoch);
            match memcached_value {
                Some(s) => {
                    self.keys.insert(key_id, self.compute_wrap(s));
                }
                None => {
                    FAILURE_COUNTER.inc();
                    error!(self.logger, "cannot read from memcache";
                           "key" => memcached_key,
                           "memcached_url" => self.memcached_url.clone());
                    failed = true;
                }
            }
        }
        // removed_period shouldn't be negative because first_period shouldn't be zero.
        let removed_period = first_period - 1;
        let removed_epoch = removed_period * self.duration;
        self.keys.remove(&KeyId::from_epoch(removed_epoch));

        // Not all of our friends may have gotten the same forwards keys as we did
        self.latest = KeyId::from_epoch(current_epoch);
        if failed {
            return Err(
                io::Error::new(io::ErrorKind::Other, "A request to memcached failed").into(),
            );
        } else {
            return Ok(());
        }
    }

    fn compute_wrap(&self, val: Vec<u8>) -> Vec<u8> {
        let key = hmac::SigningKey::new(&digest::SHA256, self.master_key.as_bytes());
        hmac::sign(&key, &val).as_ref().to_vec()
    }

    pub fn latest(&self) -> (KeyId, Vec<u8>) {
        (self.latest, self.keys[&self.latest].clone())
    }
}

pub fn periodic_rotate(rotor: Arc<RwLock<KeyRotator>>) {
    let mut rotor = rotor.clone();
    thread::spawn(move || loop {
        inner(&mut rotor);
        let restlen = read_sleep(&rotor);
        thread::sleep(Duration::from_secs(restlen as u64));
    });
}

fn inner(rotor: &mut Arc<RwLock<KeyRotator>>) {
    let _ = rotor.write().unwrap().rotate();
}

fn read_sleep(rotor: &Arc<RwLock<KeyRotator>>) -> u64 {
    rotor.read().unwrap().duration
}

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::HashMap;

    struct HashMapVecMap {
        table: HashMap<String, Option<Vec<u8>>>,
    }

    impl VecMap for HashMapVecMap {
        fn get(&mut self, key: &str) -> Result<Option<Vec<u8>>, MemcacheError> {
            Ok(self.table[&key.to_owned()].clone())
        }
    }

    #[test]
    fn test_rotation() {
        use sloggers::null::NullLoggerBuilder;
        use sloggers::Build;
        let mut testmap = HashMapVecMap {
            table: HashMap::new(),
        };
        testmap
            .table
            .insert("test/1".to_string(), Some(vec![1; 32]));
        testmap
            .table
            .insert("test/2".to_string(), Some(vec![2; 32]));
        testmap
            .table
            .insert("test/3".to_string(), Some(vec![3; 32]));
        testmap
            .table
            .insert("test/4".to_string(), Some(vec![4; 32]));
        testmap.table.insert("test/5".to_string(), None);
        testmap.table.insert("test/0".to_string(), None);

        let mut test_rotor = KeyRotator {
            memcached_url: "unused".to_owned(),
            prefix: "test".to_owned(),
            duration: 1,
            number_of_forward_periods: 1,
            number_of_backward_periods: 1,
            master_key: vec![0, 32],
            latest: [1, 2, 3, 4],
            keys: HashMap::new(),
            logger: NullLoggerBuilder.build().unwrap(),
        };
        test_rotor.internal_rotate(&mut testmap, 2).unwrap();
        let old_latest = test_rotor.latest;
        test_rotor.internal_rotate(&mut testmap, 3).unwrap();
        let new_latest = test_rotor.latest;
        assert_ne!(old_latest, new_latest);
        let res = test_rotor.internal_rotate(&mut testmap, 1);
        if let Ok(_) = res {
            panic!("Success should not have happened!")
        }
        let res = test_rotor.internal_rotate(&mut testmap, 4);
        if let Ok(_) = res {
            panic!("Success should not have happened!")
        }
    }
}
