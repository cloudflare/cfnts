use libc::*;
use socket2::{Domain, Socket, Type};
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;

#[cfg(target_os = "linux")]
fn set_freebind(fd: c_int) -> Result<(), std::io::Error> {
    use std::io::{Error, ErrorKind};
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

#[cfg(not(target_os = "linux"))]
fn set_freebind(_fd: c_int) -> Result<(), std::io::Error> {
    Ok(()) // no op for mac build
}

pub fn tcp_listener(addr: &SocketAddr) -> Result<std::net::TcpListener, std::io::Error> {
    let domain = match addr {
        SocketAddr::V4(..) => Domain::IPV4,
        SocketAddr::V6(..) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, None)?;
    socket.set_reuse_address(true)?;
    set_freebind(socket.as_raw_fd())?;
    socket.bind(&(*addr).into())?;
    socket.listen(128)?;
    Ok(socket.into())
}

pub fn udp_listen(addr: &SocketAddr) -> Result<std::net::UdpSocket, std::io::Error> {
    let domain = match addr {
        SocketAddr::V4(..) => Domain::IPV4,
        SocketAddr::V6(..) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, None)?;
    socket.set_reuse_address(true)?;
    set_freebind(socket.as_raw_fd())?;
    socket.bind(&(*addr).into())?;
    Ok(socket.into())
}
