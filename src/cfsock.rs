use libc::*;
use net2::{TcpBuilder, UdpBuilder};
use std::io::{Error, ErrorKind};
use std::net::{SocketAddr, SocketAddr::*};
use std::os::unix::io::{AsRawFd};

fn set_freebind(fd: c_int) -> Result<(), std::io::Error> {
    const IP_FREEBIND: libc::c_int = 0xf;
    match unsafe {
        setsockopt(
            fd,
            SOL_IP,
            IP_FREEBIND,
            &1u32 as *const u32 as *const c_void,
            std::mem::size_of::<u32>() as u32,
        )
    } {
        -1 => Err(std::io::Error::new(
            ErrorKind::Other,
            Error::last_os_error(),
        )),
        _ => Ok(()),
    }
}

pub fn tcp_listener(addr: &SocketAddr) -> Result<std::net::TcpListener, std::io::Error> {
    let builder = match addr {
        V4(_) => TcpBuilder::new_v4()?,
        V6(_) => TcpBuilder::new_v6()?,
    };
    builder.reuse_address(true)?;
    set_freebind(builder.as_raw_fd())?;
    builder.bind(addr)?;
    builder.listen(128)
}

pub fn udp_listen(addr: &SocketAddr) -> Result<std::net::UdpSocket, std::io::Error> {
    let builder = match addr {
        V4(_) => UdpBuilder::new_v4()?,
        V6(_) => UdpBuilder::new_v6()?,
    };
    builder.reuse_address(true)?;
    set_freebind(builder.as_raw_fd())?;
    builder.bind(addr)
}
