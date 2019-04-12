use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use error::MemcacheError;
use std::collections::HashMap;
use std::io;
use value::FromMemcacheValue;

#[allow(dead_code)]
pub enum Opcode {
    Get = 0x00,
    Set = 0x01,
    Add = 0x02,
    Replace = 0x03,
    Delete = 0x04,
    Increment = 0x05,
    Decrement = 0x06,
    Flush = 0x08,
    Stat = 0x10,
    Noop = 0x0a,
    Version = 0x0b,
    GetKQ = 0x0d,
    Append = 0x0e,
    Prepend = 0x0f,
    Touch = 0x1c,
    StartAuth = 0x21,
}

pub enum Magic {
    Request = 0x80,
    Response = 0x81,
}

#[allow(dead_code)]
pub enum ResponseStatus {
    NoError = 0x00,
    KeyNotFound = 0x01,
    KeyExits = 0x02,
    ValueTooLarge = 0x03,
    InvalidArguments = 0x04,
    AuthenticationRequired = 0x20,
}

#[derive(Debug, Default)]
pub struct PacketHeader {
    pub magic: u8,
    pub opcode: u8,
    pub key_length: u16,
    pub extras_length: u8,
    pub data_type: u8,
    pub vbucket_id_or_status: u16,
    pub total_body_length: u32,
    pub opaque: u32,
    pub cas: u64,
}

#[derive(Debug)]
pub struct StoreExtras {
    pub flags: u32,
    pub expiration: u32,
}

#[derive(Debug)]
pub struct CounterExtras {
    pub amount: u64,
    pub initial_value: u64,
    pub expiration: u32,
}

impl PacketHeader {
    pub fn write<W: io::Write>(self, writer: &mut W) -> Result<(), io::Error> {
        writer.write_u8(self.magic)?;
        writer.write_u8(self.opcode)?;
        writer.write_u16::<BigEndian>(self.key_length)?;
        writer.write_u8(self.extras_length)?;
        writer.write_u8(self.data_type)?;
        writer.write_u16::<BigEndian>(self.vbucket_id_or_status)?;
        writer.write_u32::<BigEndian>(self.total_body_length)?;
        writer.write_u32::<BigEndian>(self.opaque)?;
        writer.write_u64::<BigEndian>(self.cas)?;
        return Ok(());
    }

    pub fn read<R: io::Read>(reader: &mut R) -> Result<PacketHeader, MemcacheError> {
        let magic = reader.read_u8()?;
        if magic != Magic::Response as u8 {
            return Err(MemcacheError::ClientError(format!(
                "Bad magic number in response header: {}",
                magic
            )));
        }
        let header = PacketHeader {
            magic,
            opcode: reader.read_u8()?,
            key_length: reader.read_u16::<BigEndian>()?,
            extras_length: reader.read_u8()?,
            data_type: reader.read_u8()?,
            vbucket_id_or_status: reader.read_u16::<BigEndian>()?,
            total_body_length: reader.read_u32::<BigEndian>()?,
            opaque: reader.read_u32::<BigEndian>()?,
            cas: reader.read_u64::<BigEndian>()?,
        };
        return Ok(header);
    }
}

pub fn parse_header_only_response<R: io::Read>(reader: &mut R) -> Result<(), MemcacheError> {
    let header = PacketHeader::read(reader)?;
    if header.vbucket_id_or_status != ResponseStatus::NoError as u16 {
        return Err(MemcacheError::from(header.vbucket_id_or_status));
    }
    return Ok(());
}

pub fn parse_version_response<R: io::Read>(reader: &mut R) -> Result<String, MemcacheError> {
    let header = PacketHeader::read(reader)?;
    if header.vbucket_id_or_status != ResponseStatus::NoError as u16 {
        return Err(MemcacheError::from(header.vbucket_id_or_status));
    }
    let mut buffer = vec![0; header.total_body_length as usize];
    reader.read_exact(buffer.as_mut_slice())?;
    return Ok(String::from_utf8(buffer)?);
}

pub fn parse_get_response<R: io::Read, V: FromMemcacheValue>(reader: &mut R) -> Result<Option<V>, MemcacheError> {
    let header = PacketHeader::read(reader)?;
    if header.vbucket_id_or_status == ResponseStatus::KeyNotFound as u16 {
        let mut buffer = vec![0; header.total_body_length as usize];
        reader.read_exact(buffer.as_mut_slice())?;
        return Ok(None);
    } else if header.vbucket_id_or_status != ResponseStatus::NoError as u16 {
        return Err(MemcacheError::from(header.vbucket_id_or_status));
    }
    let flags = reader.read_u32::<BigEndian>()?;
    let value_length = header.total_body_length - u32::from(header.extras_length);
    let mut buffer = vec![0; value_length as usize];
    reader.read_exact(buffer.as_mut_slice())?;
    return Ok(Some(FromMemcacheValue::from_memcache_value(buffer, flags)?));
}

pub fn parse_gets_response<R: io::Read, V: FromMemcacheValue>(
    reader: &mut R,
) -> Result<HashMap<String, V>, MemcacheError> {
    let mut result = HashMap::new();
    loop {
        let header = PacketHeader::read(reader)?;
        if header.vbucket_id_or_status != ResponseStatus::NoError as u16 {
            return Err(MemcacheError::from(header.vbucket_id_or_status));
        }
        if header.opcode == Opcode::Noop as u8 {
            break;
        }
        let flags = reader.read_u32::<BigEndian>()?;
        let key_length = header.key_length;
        let value_length = header.total_body_length - u32::from(key_length) - u32::from(header.extras_length);
        let mut key_buffer = vec![0; key_length as usize];
        reader.read_exact(key_buffer.as_mut_slice())?;
        let key = String::from_utf8(key_buffer)?;
        let mut value_buffer = vec![0; value_length as usize];
        reader.read_exact(value_buffer.as_mut_slice())?;
        result.insert(key, FromMemcacheValue::from_memcache_value(value_buffer, flags)?);
    }
    return Ok(result);
}

pub fn parse_delete_response<R: io::Read>(reader: &mut R) -> Result<bool, MemcacheError> {
    let header = PacketHeader::read(reader)?;
    if header.total_body_length != 0 {
        reader.read_exact(vec![0; header.total_body_length as usize].as_mut_slice())?;
    }
    if header.vbucket_id_or_status == ResponseStatus::KeyNotFound as u16 {
        return Ok(false);
    } else if header.vbucket_id_or_status != ResponseStatus::NoError as u16 {
        return Err(MemcacheError::from(header.vbucket_id_or_status));
    }
    return Ok(true);
}

pub fn parse_counter_response<R: io::Read>(reader: &mut R) -> Result<u64, MemcacheError> {
    let header = PacketHeader::read(reader)?;
    if header.vbucket_id_or_status != ResponseStatus::NoError as u16 {
        return Err(MemcacheError::from(header.vbucket_id_or_status));
    }
    return Ok(reader.read_u64::<BigEndian>()?);
}

pub fn parse_touch_response<R: io::Read>(reader: &mut R) -> Result<bool, MemcacheError> {
    let header = PacketHeader::read(reader)?;
    if header.total_body_length != 0 {
        reader.read_exact(vec![0; header.total_body_length as usize].as_mut_slice())?;
    }
    if header.vbucket_id_or_status == ResponseStatus::KeyNotFound as u16 {
        return Ok(false);
    } else if header.vbucket_id_or_status != ResponseStatus::NoError as u16 {
        return Err(MemcacheError::from(header.vbucket_id_or_status));
    }
    return Ok(true);
}

pub fn parse_stats_response<R: io::Read>(reader: &mut R) -> Result<HashMap<String, String>, MemcacheError> {
    let mut result = HashMap::new();
    loop {
        let header = PacketHeader::read(reader)?;
        if header.vbucket_id_or_status != ResponseStatus::NoError as u16 {
            return Err(MemcacheError::from(header.vbucket_id_or_status));
        }
        let key_length = header.key_length;
        let value_length = header.total_body_length - u32::from(key_length) - u32::from(header.extras_length);
        let mut key_buffer = vec![0; key_length as usize];
        reader.read_exact(key_buffer.as_mut_slice())?;
        let key = String::from_utf8(key_buffer)?;
        let mut value_buffer = vec![0; value_length as usize];
        reader.read_exact(value_buffer.as_mut_slice())?;
        let value = String::from_utf8(value_buffer)?;
        if key == "" && value == "" {
            break;
        }
        result.insert(key, value);
    }
    return Ok(result);
}

pub fn parse_start_auth_response<R: io::Read>(reader: &mut R) -> Result<bool, MemcacheError> {
    let header = PacketHeader::read(reader)?;
    if header.total_body_length != 0 {
        reader.read_exact(vec![0; header.total_body_length as usize].as_mut_slice())?;
    }
    if header.vbucket_id_or_status != ResponseStatus::NoError as u16 {
        return Err(MemcacheError::from(header.vbucket_id_or_status));
    }
    return Ok(true);
}
