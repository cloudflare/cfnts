use std::collections::HashMap;
use std::fmt;
use std::io::{BufRead, BufReader, Read, Write};

use client::Stats;
use error::MemcacheError;
use stream::Stream;
use value::{FromMemcacheValue, ToMemcacheValue};

#[derive(Default)]
pub struct Options {
    pub noreply: bool,
    pub exptime: u32,
    pub flags: u32,
}

enum StoreCommand {
    Set,
    Add,
    Replace,
    Append,
    Prepend,
}

impl fmt::Display for StoreCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            StoreCommand::Set => write!(f, "set"),
            StoreCommand::Add => write!(f, "add"),
            StoreCommand::Replace => write!(f, "replace"),
            StoreCommand::Append => write!(f, "append"),
            StoreCommand::Prepend => write!(f, "prepend"),
        }
    }
}
pub struct AsciiProtocol<C: Read + Write + Sized> {
    pub reader: BufReader<C>,
}

impl AsciiProtocol<Stream> {
    fn store<V: ToMemcacheValue<Stream>>(
        &mut self,
        command: StoreCommand,
        key: &str,
        value: V,
        options: &Options,
    ) -> Result<(), MemcacheError> {
        if key.len() > 250 {
            return Err(MemcacheError::ClientError(String::from("key is too long")));
        }

        let mut header = format!(
            "{} {} {} {} {}",
            command,
            key,
            value.get_flags(),
            options.exptime,
            value.get_length()
        );
        if options.noreply {
            header += " noreply";
        }
        header += "\r\n";
        self.reader.get_mut().write(header.as_bytes())?;
        value.write_to(self.reader.get_mut())?;
        self.reader.get_mut().write(b"\r\n")?;
        self.reader.get_mut().flush()?;

        if options.noreply {
            return Ok(());
        }

        let mut s = String::new();
        let _ = self.reader.read_line(&mut s);
        if is_memcache_error(s.as_str()) {
            return Err(MemcacheError::from(s));
        } else if s == "STORED\r\n" {
            return Ok(());
        } else if s == "NOT_STORED\r\n" {
            return Ok(());
        } else {
            return Err(MemcacheError::ClientError("invalid server response".into()));
        }
    }

    pub(super) fn version(&mut self) -> Result<String, MemcacheError> {
        self.reader.get_mut().write(b"version\r\n")?;
        self.reader.get_mut().flush()?;
        let mut s = String::new();
        let _ = self.reader.read_line(&mut s);
        if is_memcache_error(s.as_str()) {
            return Err(MemcacheError::from(s));
        } else if !s.starts_with("VERSION") {
            return Err(MemcacheError::ServerError(0));
        }
        let s = s.trim_start_matches("VERSION ");
        let s = s.trim_end_matches("\r\n");

        return Ok(s.to_string());
    }

    pub(super) fn flush(&mut self) -> Result<(), MemcacheError> {
        match self.reader.get_mut().write(b"flush_all\r\n") {
            Ok(_) => {}
            Err(err) => return Err(MemcacheError::from(err)),
        }
        self.reader.get_mut().flush()?;
        let mut s = String::new();
        let _ = self.reader.read_line(&mut s);
        if is_memcache_error(s.as_str()) {
            return Err(MemcacheError::from(s));
        } else if s != "OK\r\n" {
            return Err(MemcacheError::ClientError("invalid server response".into()));
        }
        return Ok(());
    }

    pub(super) fn flush_with_delay(&mut self, delay: u32) -> Result<(), MemcacheError> {
        write!(self.reader.get_mut(), "flush_all {}\r\n", delay)?;
        self.reader.get_mut().flush()?;
        let mut s = String::new();
        let _ = self.reader.read_line(&mut s);
        if is_memcache_error(s.as_str()) {
            return Err(MemcacheError::from(s));
        } else if s != "OK\r\n" {
            return Err(MemcacheError::ClientError("invalid server response".into()));
        }
        return Ok(());
    }

    pub(super) fn get<V: FromMemcacheValue>(&mut self, key: &str) -> Result<Option<V>, MemcacheError> {
        write!(self.reader.get_mut(), "get {}\r\n", key)?;

        let mut s = String::new();
        let _ = self.reader.read_line(&mut s)?;

        if is_memcache_error(s.as_str()) {
            return Err(MemcacheError::from(s));
        } else if s.starts_with("END") {
            return Ok(None);
        } else if !s.starts_with("VALUE") {
            return Err(MemcacheError::ClientError("invalid server response".into()));
        }

        let header: Vec<_> = s.trim_end_matches("\r\n").split(" ").collect();
        if header.len() != 4 {
            return Err(MemcacheError::ClientError("invalid server response".into()));
        }

        if key != header[1] {
            return Err(MemcacheError::ClientError("invalid server response".into()));
        }
        let flags = header[2].parse()?;
        let length = header[3].parse()?;

        let mut buffer = vec![0; length];
        self.reader.read_exact(buffer.as_mut_slice())?;

        // read the rest \r\n and END\r\n
        let mut s = String::new();
        let _ = self.reader.read_line(&mut s)?;
        if s != "\r\n" {
            return Err(MemcacheError::ClientError("invalid server response".into()));
        }
        s = String::new();
        let _ = self.reader.read_line(&mut s)?;
        if s != "END\r\n" {
            return Err(MemcacheError::ClientError("invalid server response".into()));
        }

        return Ok(Some(FromMemcacheValue::from_memcache_value(buffer, flags)?));
    }

    pub(super) fn gets<V: FromMemcacheValue>(&mut self, keys: Vec<&str>) -> Result<HashMap<String, V>, MemcacheError> {
        write!(self.reader.get_mut(), "gets {}\r\n", keys.join(" "))?;

        let mut result: HashMap<String, V> = HashMap::new();
        loop {
            let mut s = String::new();
            let _ = self.reader.read_line(&mut s)?;

            if is_memcache_error(s.as_str()) {
                return Err(MemcacheError::from(s));
            } else if s.starts_with("END") {
                break;
            } else if !s.starts_with("VALUE") {
                return Err(MemcacheError::ClientError("invalid server response".into()));
            }

            let header: Vec<_> = s.trim_end_matches("\r\n").split(" ").collect();
            if header.len() != 5 {
                return Err(MemcacheError::ClientError("invalid server response".into()));
            }

            let key = header[1];
            let flags = header[2].parse()?;
            let length = header[3].parse()?;

            let mut buffer = vec![0; length];
            self.reader.read_exact(buffer.as_mut_slice())?;

            result.insert(key.to_string(), FromMemcacheValue::from_memcache_value(buffer, flags)?);

            // read the rest \r\n
            let mut s = String::new();
            let _ = self.reader.read_line(&mut s)?;
            if s != "\r\n" {
                return Err(MemcacheError::ClientError("invalid server response".into()));
            }
        }

        return Ok(result);
    }

    pub(super) fn set<V: ToMemcacheValue<Stream>>(
        &mut self,
        key: &str,
        value: V,
        expiration: u32,
    ) -> Result<(), MemcacheError> {
        let options = Options {
            exptime: expiration,
            ..Default::default()
        };
        return self.store(StoreCommand::Set, key, value, &options);
    }

    pub(super) fn add<V: ToMemcacheValue<Stream>>(
        &mut self,
        key: &str,
        value: V,
        expiration: u32,
    ) -> Result<(), MemcacheError> {
        let options = Options {
            exptime: expiration,
            ..Default::default()
        };
        return self.store(StoreCommand::Add, key, value, &options);
    }

    pub(super) fn replace<V: ToMemcacheValue<Stream>>(
        &mut self,
        key: &str,
        value: V,
        expiration: u32,
    ) -> Result<(), MemcacheError> {
        let options = Options {
            exptime: expiration,
            ..Default::default()
        };
        return self.store(StoreCommand::Replace, key, value, &options);
    }

    pub(super) fn append<V: ToMemcacheValue<Stream>>(&mut self, key: &str, value: V) -> Result<(), MemcacheError> {
        if key.len() > 250 {
            return Err(MemcacheError::ClientError(String::from("key is too long")));
        }
        return self.store(StoreCommand::Append, key, value, &Default::default());
    }

    pub(super) fn prepend<V: ToMemcacheValue<Stream>>(&mut self, key: &str, value: V) -> Result<(), MemcacheError> {
        if key.len() > 250 {
            return Err(MemcacheError::ClientError(String::from("key is too long")));
        }
        return self.store(StoreCommand::Prepend, key, value, &Default::default());
    }

    pub(super) fn delete(&mut self, key: &str) -> Result<bool, MemcacheError> {
        if key.len() > 250 {
            return Err(MemcacheError::ClientError(String::from("key is too long")));
        }
        write!(self.reader.get_mut(), "delete {}\r\n", key)?;
        self.reader.get_mut().flush()?;
        let mut s = String::new();
        let _ = self.reader.read_line(&mut s);
        if is_memcache_error(s.as_str()) {
            return Err(MemcacheError::from(s));
        } else if s == "DELETED\r\n" {
            return Ok(true);
        } else if s == "NOT_FOUND\r\n" {
            return Ok(false);
        } else {
            return Err(MemcacheError::ClientError(String::from("invalid server response")));
        }
    }

    pub(super) fn increment(&mut self, key: &str, amount: u64) -> Result<u64, MemcacheError> {
        if key.len() > 250 {
            return Err(MemcacheError::ClientError(String::from("key is too long")));
        }
        write!(self.reader.get_mut(), "incr {} {}\r\n", key, amount)?;
        let mut s = String::new();
        let _ = self.reader.read_line(&mut s);
        if is_memcache_error(s.as_str()) {
            return Err(MemcacheError::from(s));
        } else if s == "NOT_FOUND\r\n" {
            return Err(MemcacheError::from(1));
        } else {
            match s.trim_end_matches("\r\n").parse::<u64>() {
                Ok(n) => return Ok(n),
                Err(_) => return Err(MemcacheError::ClientError("invalid server response".into())),
            }
        }
    }

    pub(super) fn decrement(&mut self, key: &str, amount: u64) -> Result<u64, MemcacheError> {
        if key.len() > 250 {
            return Err(MemcacheError::ClientError(String::from("key is too long")));
        }
        write!(self.reader.get_mut(), "decr {} {}\r\n", key, amount)?;
        let mut s = String::new();
        let _ = self.reader.read_line(&mut s);
        if is_memcache_error(s.as_str()) {
            return Err(MemcacheError::from(s));
        } else if s == "NOT_FOUND\r\n" {
            return Err(MemcacheError::from(1));
        } else {
            match s.trim_end_matches("\r\n").parse::<u64>() {
                Ok(n) => return Ok(n),
                Err(_) => return Err(MemcacheError::ClientError("invalid server response".into())),
            }
        }
    }

    pub(super) fn touch(&mut self, key: &str, expiration: u32) -> Result<bool, MemcacheError> {
        if key.len() > 250 {
            return Err(MemcacheError::ClientError(String::from("key is too long")));
        }
        write!(self.reader.get_mut(), "touch {} {}\r\n", key, expiration)?;
        self.reader.get_mut().flush()?;
        let mut s = String::new();
        let _ = self.reader.read_line(&mut s);
        if is_memcache_error(s.as_str()) {
            return Err(MemcacheError::from(s));
        } else if s == "TOUCHED\r\n" {
            return Ok(true);
        } else if s == "NOT_FOUND\r\n" {
            return Ok(false);
        } else {
            return Err(MemcacheError::ClientError(String::from("invalid server response")));
        }
    }

    pub(super) fn stats(&mut self) -> Result<Stats, MemcacheError> {
        self.reader.get_mut().write(b"stats\r\n")?;
        self.reader.get_mut().flush()?;

        let mut result: Stats = HashMap::new();
        loop {
            let mut s = String::new();
            let _ = self.reader.read_line(&mut s)?;

            if is_memcache_error(s.as_str()) {
                return Err(MemcacheError::from(s));
            } else if s.starts_with("END") {
                break;
            } else if !s.starts_with("STAT") {
                return Err(MemcacheError::ClientError("invalid server response".into()));
            }

            let stat: Vec<_> = s.trim_end_matches("\r\n").split(" ").collect();
            if stat.len() < 3 {
                return Err(MemcacheError::ClientError("invalid server response".into()));
            }
            let key = stat[1];
            let value = s.trim_start_matches(format!("STAT {}", key).as_str());
            result.insert(key.into(), value.into());
        }

        return Ok(result);
    }
}

fn is_memcache_error(s: &str) -> bool {
    return s == "ERROR\r\n" || s.starts_with("CIENT_ERROR") || s.starts_with("SERVER_ERROR");
}
