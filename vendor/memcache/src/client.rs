use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use url::Url;

use connection::Connection;
use error::MemcacheError;
use protocol::Protocol;
use stream::Stream;
use value::{FromMemcacheValue, ToMemcacheValue};

pub type Stats = HashMap<String, String>;

pub trait Connectable {
    fn get_urls(self) -> Vec<String>;
}

impl Connectable for String {
    fn get_urls(self) -> Vec<String> {
        return vec![self];
    }
}

impl Connectable for Vec<String> {
    fn get_urls(self) -> Vec<String> {
        return self;
    }
}

impl Connectable for &str {
    fn get_urls(self) -> Vec<String> {
        return vec![self.to_string()];
    }
}

impl Connectable for Vec<&str> {
    fn get_urls(self) -> Vec<String> {
        let mut urls = vec![];
        for url in self {
            urls.push(url.to_string());
        }
        return urls;
    }
}

pub struct Client {
    connections: Vec<Connection>,
    pub hash_function: fn(&str) -> u64,
}

fn default_hash_function(key: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    return hasher.finish();
}

impl Client {
    #[deprecated(since = "0.10.0", note = "please use `connect` instead")]
    pub fn new<C: Connectable>(target: C) -> Result<Self, MemcacheError> {
        return Self::connect(target);
    }

    pub fn connect<C: Connectable>(target: C) -> Result<Self, MemcacheError> {
        let urls = target.get_urls();
        let mut connections = vec![];
        for url in urls {
            let parsed = match Url::parse(url.as_str()) {
                Ok(v) => v,
                Err(_) => return Err(MemcacheError::ClientError("Invalid memcache URL".into())),
            };

            let mut connection = Connection::connect(&parsed)?;

            // if parsed.has_authority() && parsed.username() != "" && parsed.password().is_some() {
            //     let key = "PLAIN";
            //     let value = format!("\x00{}\x00{}", parsed.username(), parsed.password().unwrap());
            //     let request_header = PacketHeader {
            //         magic: Magic::Request as u8,
            //         opcode: Opcode::StartAuth as u8,
            //         key_length: key.len() as u16,
            //         total_body_length: (key.len() + value.len()) as u32,
            //         ..Default::default()
            //     };
            //     request_header.write(&mut connection)?;
            //     connection.write_all(key.as_bytes())?;
            //     value.write_to(&mut connection)?;
            //     connection.flush()?;
            //     packet::parse_start_auth_response(&mut connection)?;
            // }

            connections.push(connection);
        }
        return Ok(Client {
            connections: connections,
            hash_function: default_hash_function,
        });
    }

    fn get_connection(&mut self, key: &str) -> &mut Connection {
        let connections_count = self.connections.len();
        return &mut self.connections[(self.hash_function)(key) as usize % connections_count];
    }

    /// Set the socket read timeout for tcp conections.
    ///
    /// Example:
    ///
    /// ```rust
    /// let mut client = memcache::Client::connect("memcache://localhost:12345").unwrap();
    /// client.set_read_timeout(Some(::std::time::Duration::from_secs(3))).unwrap();
    /// ```
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<(), MemcacheError> {
        for conn in self.connections.iter_mut() {
            match conn.protocol {
                Protocol::Ascii(ref mut protocol) => protocol.reader.get_mut().set_read_timeout(timeout)?,
                Protocol::Binary(ref mut protocol) => protocol.stream.set_read_timeout(timeout)?,
            }
        }
        Ok(())
    }

    /// Set the socket write timeout for tcp conections.
    ///
    /// Example:
    ///
    /// ```rust
    /// let mut client = memcache::Client::connect("memcache://localhost:12345?protocol=ascii").unwrap();
    /// client.set_write_timeout(Some(::std::time::Duration::from_secs(3))).unwrap();
    /// ```
    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) -> Result<(), MemcacheError> {
        for conn in self.connections.iter_mut() {
            match conn.protocol {
                Protocol::Ascii(ref mut protocol) => protocol.reader.get_mut().set_read_timeout(timeout)?,
                Protocol::Binary(ref mut protocol) => protocol.stream.set_write_timeout(timeout)?,
            }
        }
        Ok(())
    }

    /// Get the memcached server version.
    ///
    /// Example:
    ///
    /// ```rust
    /// let mut client = memcache::Client::connect("memcache://localhost:12345").unwrap();
    /// client.version().unwrap();
    /// ```
    pub fn version(&mut self) -> Result<Vec<(String, String)>, MemcacheError> {
        let mut result: Vec<(String, String)> = vec![];
        for connection in &mut self.connections {
            result.push(("".into(), connection.protocol.version()?));
        }
        return Ok(result);
    }

    /// Flush all cache on memcached server immediately.
    ///
    /// Example:
    ///
    /// ```rust
    /// let mut client = memcache::Client::connect("memcache://localhost:12345").unwrap();
    /// client.flush().unwrap();
    /// ```
    pub fn flush(&mut self) -> Result<(), MemcacheError> {
        for connection in &mut self.connections {
            connection.protocol.flush()?;
        }
        return Ok(());
    }

    /// Flush all cache on memcached server with a delay seconds.
    ///
    /// Example:
    ///
    /// ```rust
    /// let mut client = memcache::Client::connect("memcache://localhost:12345").unwrap();
    /// client.flush_with_delay(10).unwrap();
    /// ```
    pub fn flush_with_delay(&mut self, delay: u32) -> Result<(), MemcacheError> {
        for connection in &mut self.connections {
            connection.protocol.flush_with_delay(delay)?;
        }
        return Ok(());
    }

    /// Get a key from memcached server.
    ///
    /// Example:
    ///
    /// ```rust
    /// let mut client = memcache::Client::connect("memcache://localhost:12345").unwrap();
    /// let _: Option<String> = client.get("foo").unwrap();
    /// ```
    pub fn get<V: FromMemcacheValue>(&mut self, key: &str) -> Result<Option<V>, MemcacheError> {
        return self.get_connection(key).protocol.get(key);
    }

    /// Get multiple keys from memcached server. Using this function instead of calling `get` multiple times can reduce netwark workloads.
    ///
    /// Example:
    ///
    /// ```rust
    /// let mut client = memcache::Client::connect("memcache://localhost:12345").unwrap();
    /// client.set("foo", "42", 0).unwrap();
    /// let result: std::collections::HashMap<String, String> = client.gets(vec!["foo", "bar", "baz"]).unwrap();
    /// assert_eq!(result.len(), 1);
    /// assert_eq!(result["foo"], "42");
    /// ```
    pub fn gets<V: FromMemcacheValue>(&mut self, keys: Vec<&str>) -> Result<HashMap<String, V>, MemcacheError> {
        let mut con_keys: HashMap<usize, Vec<&str>> = HashMap::new();
        let mut result: HashMap<String, V> = HashMap::new();
        let connections_count = self.connections.len();

        for key in keys {
            let connection_index = (self.hash_function)(key) as usize % connections_count;
            let array = con_keys.entry(connection_index).or_insert_with(Vec::new);
            array.push(key);
        }
        for (&connection_index, keys) in con_keys.iter() {
            let connection = &mut self.connections[connection_index];
            result.extend(connection.protocol.gets(keys.to_vec())?);
        }
        return Ok(result);
    }

    /// Set a key with associate value into memcached server with expiration seconds.
    ///
    /// Example:
    ///
    /// ```rust
    /// let mut client = memcache::Client::connect("memcache://localhost:12345").unwrap();
    /// client.set("foo", "bar", 10).unwrap();
    /// ```
    pub fn set<V: ToMemcacheValue<Stream>>(
        &mut self,
        key: &str,
        value: V,
        expiration: u32,
    ) -> Result<(), MemcacheError> {
        return self.get_connection(key).protocol.set(key, value, expiration);
    }

    /// Add a key with associate value into memcached server with expiration seconds.
    ///
    /// Example:
    ///
    /// ```rust
    /// let mut client = memcache::Client::connect("memcache://localhost:12345").unwrap();
    /// let key = "add_test";
    /// client.delete(key).unwrap();
    /// client.add(key, "bar", 100000000).unwrap();
    /// ```
    pub fn add<V: ToMemcacheValue<Stream>>(
        &mut self,
        key: &str,
        value: V,
        expiration: u32,
    ) -> Result<(), MemcacheError> {
        return self.get_connection(key).protocol.add(key, value, expiration);
    }

    /// Replace a key with associate value into memcached server with expiration seconds.
    ///
    /// Example:
    ///
    /// ```rust
    /// let mut client = memcache::Client::connect("memcache://localhost:12345").unwrap();
    /// let key = "replace_test";
    /// client.set(key, "bar", 0).unwrap();
    /// client.replace(key, "baz", 100000000).unwrap();
    /// ```
    pub fn replace<V: ToMemcacheValue<Stream>>(
        &mut self,
        key: &str,
        value: V,
        expiration: u32,
    ) -> Result<(), MemcacheError> {
        return self.get_connection(key).protocol.replace(key, value, expiration);
    }

    /// Append value to the key.
    ///
    /// Example:
    ///
    /// ```rust
    /// let mut client = memcache::Client::connect("memcache://localhost:12345").unwrap();
    /// let key = "key_to_append";
    /// client.set(key, "hello", 0).unwrap();
    /// client.append(key, ", world!").unwrap();
    /// let result: String = client.get(key).unwrap().unwrap();
    /// assert_eq!(result, "hello, world!");
    /// ```
    pub fn append<V: ToMemcacheValue<Stream>>(&mut self, key: &str, value: V) -> Result<(), MemcacheError> {
        return self.get_connection(key).protocol.append(key, value);
    }

    /// Prepend value to the key.
    ///
    /// Example:
    ///
    /// ```rust
    /// let mut client = memcache::Client::connect("memcache://localhost:12345").unwrap();
    /// let key = "key_to_append";
    /// client.set(key, "world!", 0).unwrap();
    /// client.prepend(key, "hello, ").unwrap();
    /// let result: String = client.get(key).unwrap().unwrap();
    /// assert_eq!(result, "hello, world!");
    /// ```
    pub fn prepend<V: ToMemcacheValue<Stream>>(&mut self, key: &str, value: V) -> Result<(), MemcacheError> {
        return self.get_connection(key).protocol.prepend(key, value);
    }

    /// Delete a key from memcached server.
    ///
    /// Example:
    ///
    /// ```rust
    /// let mut client = memcache::Client::connect("memcache://localhost:12345").unwrap();
    /// client.delete("foo").unwrap();
    /// ```
    pub fn delete(&mut self, key: &str) -> Result<bool, MemcacheError> {
        return self.get_connection(key).protocol.delete(key);
    }

    /// Increment the value with amount.
    ///
    /// Example:
    ///
    /// ```rust
    /// let mut client = memcache::Client::connect("memcache://localhost:12345").unwrap();
    /// client.increment("counter", 42).unwrap();
    /// ```
    pub fn increment(&mut self, key: &str, amount: u64) -> Result<u64, MemcacheError> {
        return self.get_connection(key).protocol.increment(key, amount);
    }

    /// Decrement the value with amount.
    ///
    /// Example:
    ///
    /// ```rust
    /// let mut client = memcache::Client::connect("memcache://localhost:12345").unwrap();
    /// client.decrement("counter", 42).unwrap();
    /// ```
    pub fn decrement(&mut self, key: &str, amount: u64) -> Result<u64, MemcacheError> {
        return self.get_connection(key).protocol.decrement(key, amount);
    }

    /// Set a new expiration time for a exist key.
    ///
    /// Example:
    ///
    /// ```rust
    /// let mut client = memcache::Client::connect("memcache://localhost:12345").unwrap();
    /// assert_eq!(client.touch("not_exists_key", 12345).unwrap(), false);
    /// client.set("foo", "bar", 123).unwrap();
    /// assert_eq!(client.touch("foo", 12345).unwrap(), true);
    /// ```
    pub fn touch(&mut self, key: &str, expiration: u32) -> Result<bool, MemcacheError> {
        return self.get_connection(key).protocol.touch(key, expiration);
    }

    /// Get all servers' statistics.
    ///
    /// Example:
    /// ```rust
    /// let mut client = memcache::Client::connect("memcache://localhost:12345").unwrap();
    /// let stats = client.stats().unwrap();
    /// ```
    pub fn stats(&mut self) -> Result<Vec<(String, Stats)>, MemcacheError> {
        let mut result: Vec<(String, HashMap<String, String>)> = vec![];
        for connection in &mut self.connections {
            let stats_info = connection.protocol.stats()?;
            let url = connection.url.clone();
            result.push((url, stats_info));
        }
        return Ok(result);
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn unix() {
        let mut client = super::Client::connect("memcache:///tmp/memcached.sock").unwrap();
        assert!(client.version().unwrap()[0].1 != "");
    }

    #[test]
    fn delete() {
        let mut client = super::Client::connect("memcache://localhost:12345").unwrap();
        client.set("an_exists_key", "value", 0).unwrap();
        assert_eq!(client.delete("an_exists_key").unwrap(), true);
        assert_eq!(client.delete("a_not_exists_key").unwrap(), false);
    }

    #[test]
    fn increment() {
        let mut client = super::Client::connect("memcache://localhost:12345").unwrap();
        client.delete("counter").unwrap();
        client.set("counter", 321, 0).unwrap();
        assert_eq!(client.increment("counter", 123).unwrap(), 444);
    }
}
