use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use error::MemcacheError;
use rand;
use std::collections::HashMap;
use std::io;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::UdpSocket;
use std::u16;
use url::Url;

pub struct UdpStream {
    socket: UdpSocket,
    read_buf: Vec<u8>,
    write_buf: Vec<u8>,
    request_id: u16,
}

impl UdpStream {
    pub fn new(addr: Url) -> Result<Self, MemcacheError> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(addr)?;
        return Ok(UdpStream {
            socket,
            read_buf: Vec::new(),
            write_buf: Vec::new(),
            request_id: rand::random::<u16>(),
        });
    }
}

impl Read for UdpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut buf_len = buf.len();
        if buf_len > self.read_buf.len() {
            buf_len = self.read_buf.len();
        }
        buf[0..buf_len].copy_from_slice(&(self.read_buf[0..buf_len]));
        self.read_buf.drain(0..buf_len);
        Ok(buf_len)
    }
}

impl Write for UdpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // udp header is 8 bytes in the begining of each datagram
        let mut udp_header: Vec<u8> = Vec::new();

        udp_header.write_u16::<BigEndian>(self.request_id)?; // request id to uniquely identify response for this request
        udp_header.write_u16::<BigEndian>(0)?; // 0 indicates this is the first datagram for this request
        udp_header.write_u16::<BigEndian>(1)?; // total datagrams in this request (requests can only be 1 datagram long)
        udp_header.write_u16::<BigEndian>(0)?; // reserved bytes
        self.write_buf.splice(0..0, udp_header.iter().cloned());
        self.socket.send(self.write_buf.as_slice())?;
        self.write_buf.clear(); // clear the buffer for the next command

        let mut response_datagrams: HashMap<u16, Vec<u8>> = HashMap::new();
        let mut total_datagrams;
        let mut remaining_datagrams = 0;
        self.read_buf.clear();
        loop {
            // for large values, response can span multiple datagrams, so gather them all
            let mut buf: [u8; 1400] = [0; 1400]; // memcache udp response payload can not be longer than 1400 bytes
            let bytes_read = self.socket.recv(&mut buf)?;
            if bytes_read < 8 {
                // make an error here to avoid panic below
                return Err(Error::new(ErrorKind::Other, "Invalid UDP header received"));
            }

            let request_id = BigEndian::read_u16(&buf[0..]);
            if self.request_id != request_id {
                // ideally this shouldn't happen as we wait to read out response before sending another request
                continue;
            }
            let sequence_no = BigEndian::read_u16(&buf[2..]);
            total_datagrams = BigEndian::read_u16(&buf[4..]);
            if remaining_datagrams == 0 {
                remaining_datagrams = total_datagrams;
            }

            let mut v: Vec<u8> = Vec::new();
            v.extend_from_slice(&buf[8..bytes_read]);
            response_datagrams.insert(sequence_no, v);
            remaining_datagrams -= 1;
            if remaining_datagrams == 0 {
                break;
            }
        }
        for i in 0..total_datagrams {
            self.read_buf.append(&mut (response_datagrams[&i].clone()));
        }

        self.request_id = (self.request_id % (u16::MAX)) + 1;
        Ok(())
    }
}
