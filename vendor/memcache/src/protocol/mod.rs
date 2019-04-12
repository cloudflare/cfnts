mod ascii;
mod binary;
mod binary_packet;

use client::Stats;
use error::MemcacheError;
pub(crate) use protocol::ascii::AsciiProtocol;
pub(crate) use protocol::binary::BinaryProtocol;
use std::collections::HashMap;
use stream::Stream;
use value::{FromMemcacheValue, ToMemcacheValue};

pub enum Protocol {
    Ascii(AsciiProtocol<Stream>),
    Binary(BinaryProtocol),
}

impl Protocol {
    pub(super) fn version(&mut self) -> Result<String, MemcacheError> {
        match self {
            Protocol::Ascii(ref mut protocol) => protocol.version(),
            Protocol::Binary(ref mut protocol) => protocol.version(),
        }
    }

    pub(super) fn flush(&mut self) -> Result<(), MemcacheError> {
        match self {
            Protocol::Ascii(ref mut protocol) => protocol.flush(),
            Protocol::Binary(ref mut protocol) => protocol.flush(),
        }
    }

    pub(super) fn flush_with_delay(&mut self, delay: u32) -> Result<(), MemcacheError> {
        match self {
            Protocol::Ascii(ref mut protocol) => protocol.flush_with_delay(delay),
            Protocol::Binary(ref mut protocol) => protocol.flush_with_delay(delay),
        }
    }

    pub(super) fn get<V: FromMemcacheValue>(&mut self, key: &str) -> Result<Option<V>, MemcacheError> {
        match self {
            Protocol::Ascii(ref mut protocol) => protocol.get(key),
            Protocol::Binary(ref mut protocol) => protocol.get(key),
        }
    }

    pub(super) fn gets<V: FromMemcacheValue>(&mut self, keys: Vec<&str>) -> Result<HashMap<String, V>, MemcacheError> {
        match self {
            Protocol::Ascii(ref mut protocol) => protocol.gets(keys),
            Protocol::Binary(ref mut protocol) => protocol.gets(keys),
        }
    }

    pub(super) fn set<V: ToMemcacheValue<Stream>>(
        &mut self,
        key: &str,
        value: V,
        expiration: u32,
    ) -> Result<(), MemcacheError> {
        match self {
            Protocol::Ascii(ref mut protocol) => protocol.set(key, value, expiration),
            Protocol::Binary(ref mut protocol) => protocol.set(key, value, expiration),
        }
    }

    pub(super) fn add<V: ToMemcacheValue<Stream>>(
        &mut self,
        key: &str,
        value: V,
        expiration: u32,
    ) -> Result<(), MemcacheError> {
        match self {
            Protocol::Ascii(ref mut protocol) => protocol.add(key, value, expiration),
            Protocol::Binary(ref mut protocol) => protocol.add(key, value, expiration),
        }
    }

    pub(super) fn replace<V: ToMemcacheValue<Stream>>(
        &mut self,
        key: &str,
        value: V,
        expiration: u32,
    ) -> Result<(), MemcacheError> {
        match self {
            Protocol::Ascii(ref mut protocol) => protocol.replace(key, value, expiration),
            Protocol::Binary(ref mut protocol) => protocol.replace(key, value, expiration),
        }
    }

    pub(super) fn append<V: ToMemcacheValue<Stream>>(&mut self, key: &str, value: V) -> Result<(), MemcacheError> {
        match self {
            Protocol::Ascii(ref mut protocol) => protocol.append(key, value),
            Protocol::Binary(ref mut protocol) => protocol.append(key, value),
        }
    }

    pub(super) fn prepend<V: ToMemcacheValue<Stream>>(&mut self, key: &str, value: V) -> Result<(), MemcacheError> {
        match self {
            Protocol::Ascii(ref mut protocol) => protocol.prepend(key, value),
            Protocol::Binary(ref mut protocol) => protocol.prepend(key, value),
        }
    }

    pub(super) fn delete(&mut self, key: &str) -> Result<bool, MemcacheError> {
        match self {
            Protocol::Ascii(ref mut protocol) => protocol.delete(key),
            Protocol::Binary(ref mut protocol) => protocol.delete(key),
        }
    }

    pub(super) fn increment(&mut self, key: &str, amount: u64) -> Result<u64, MemcacheError> {
        match self {
            Protocol::Ascii(ref mut protocol) => protocol.increment(key, amount),
            Protocol::Binary(ref mut protocol) => protocol.increment(key, amount),
        }
    }

    pub(super) fn decrement(&mut self, key: &str, amount: u64) -> Result<u64, MemcacheError> {
        match self {
            Protocol::Ascii(ref mut protocol) => protocol.decrement(key, amount),
            Protocol::Binary(ref mut protocol) => protocol.decrement(key, amount),
        }
    }

    pub(super) fn touch(&mut self, key: &str, expiration: u32) -> Result<bool, MemcacheError> {
        match self {
            Protocol::Ascii(ref mut protocol) => protocol.touch(key, expiration),
            Protocol::Binary(ref mut protocol) => protocol.touch(key, expiration),
        }
    }

    pub(super) fn stats(&mut self) -> Result<Stats, MemcacheError> {
        match self {
            Protocol::Ascii(ref mut protocol) => protocol.stats(),
            Protocol::Binary(ref mut protocol) => protocol.stats(),
        }
    }
}
