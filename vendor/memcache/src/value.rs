use error::MemcacheError;
use std::io;
use std::io::Write;
use std::str;
use std::str::FromStr;

pub enum Flags {
    Bytes = 0,
}

/// determine how the value is serialize to memcache
pub trait ToMemcacheValue<W: Write> {
    fn get_flags(&self) -> u32;
    fn get_length(&self) -> usize;
    fn write_to(&self, stream: &mut W) -> io::Result<()>;
}

impl<'a, W: Write> ToMemcacheValue<W> for &'a [u8] {
    fn get_flags(&self) -> u32 {
        return Flags::Bytes as u32;
    }

    fn get_length(&self) -> usize {
        return self.len();
    }

    fn write_to(&self, stream: &mut W) -> io::Result<()> {
        match stream.write(self) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

impl<W: Write> ToMemcacheValue<W> for String {
    fn get_flags(&self) -> u32 {
        return Flags::Bytes as u32;
    }

    fn get_length(&self) -> usize {
        return self.as_bytes().len();
    }

    fn write_to(&self, stream: &mut W) -> io::Result<()> {
        match stream.write(self.as_bytes()) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

impl<'a, W: Write> ToMemcacheValue<W> for &'a str {
    fn get_flags(&self) -> u32 {
        return Flags::Bytes as u32;
    }

    fn get_length(&self) -> usize {
        return self.as_bytes().len();
    }

    fn write_to(&self, stream: &mut W) -> io::Result<()> {
        match stream.write(self.as_bytes()) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

macro_rules! impl_to_memcache_value_for_number {
    ($ty:ident) => {
        impl<W: Write> ToMemcacheValue<W> for $ty {
            fn get_flags(&self) -> u32 {
                return Flags::Bytes as u32;
            }

            fn get_length(&self) -> usize {
                return self.to_string().as_bytes().len();
            }

            fn write_to(&self, stream: &mut W) -> io::Result<()> {
                match stream.write(self.to_string().as_bytes()) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(e),
                }
            }
        }
    };
}

impl_to_memcache_value_for_number!(bool);
impl_to_memcache_value_for_number!(u8);
impl_to_memcache_value_for_number!(u16);
impl_to_memcache_value_for_number!(u32);
impl_to_memcache_value_for_number!(u64);
impl_to_memcache_value_for_number!(i8);
impl_to_memcache_value_for_number!(i16);
impl_to_memcache_value_for_number!(i32);
impl_to_memcache_value_for_number!(i64);
impl_to_memcache_value_for_number!(f32);
impl_to_memcache_value_for_number!(f64);

type MemcacheValue<T> = Result<T, MemcacheError>;

/// determine how the value is unserialize to memcache
pub trait FromMemcacheValue: Sized {
    fn from_memcache_value(Vec<u8>, u32) -> MemcacheValue<Self>;
}

impl FromMemcacheValue for (Vec<u8>, u32) {
    fn from_memcache_value(value: Vec<u8>, flags: u32) -> MemcacheValue<Self> {
        return Ok((value, flags));
    }
}

impl FromMemcacheValue for Vec<u8> {
    fn from_memcache_value(value: Vec<u8>, _: u32) -> MemcacheValue<Self> {
        return Ok(value);
    }
}

impl FromMemcacheValue for String {
    fn from_memcache_value(value: Vec<u8>, _: u32) -> MemcacheValue<Self> {
        return Ok(String::from_utf8(value)?);
    }
}

macro_rules! impl_from_memcache_value_for_number {
    ($ty:ident) => {
        impl FromMemcacheValue for $ty {
            fn from_memcache_value(value: Vec<u8>, _: u32) -> MemcacheValue<Self> {
                let s: String = String::from_memcache_value(value, 0)?;
                match Self::from_str(s.as_str()) {
                    Ok(v) => return Ok(v),
                    Err(e) => Err(MemcacheError::from(e)),
                }
            }
        }
    };
}

impl_from_memcache_value_for_number!(bool);
impl_from_memcache_value_for_number!(u8);
impl_from_memcache_value_for_number!(u16);
impl_from_memcache_value_for_number!(u32);
impl_from_memcache_value_for_number!(u64);
impl_from_memcache_value_for_number!(i8);
impl_from_memcache_value_for_number!(i16);
impl_from_memcache_value_for_number!(i32);
impl_from_memcache_value_for_number!(i64);
impl_from_memcache_value_for_number!(f32);
impl_from_memcache_value_for_number!(f64);
