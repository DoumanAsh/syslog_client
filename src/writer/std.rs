extern crate std;

use core::{ops, time};
use std::sync::mpsc;
use std::{io, net};

use super::{MakeTransport, Transport, TransportError};
use crate::syslog::Severity;

const LF: &[u8] = &[b'\n'];

///Local host address
///
///For use when you want to connect to locally running service
pub const LOCAL_HOST: net::IpAddr = net::IpAddr::V4(net::Ipv4Addr::new(127, 0, 0, 1));

#[repr(transparent)]
///Syslog transport that uses channel to send syslog messages.
///
///This is mostly useful for testing purposes.
pub struct InMemory<T>(mpsc::Sender<T>);

impl<T: for<'a> From<&'a str>> InMemory<T> {
    #[inline(always)]
    ///Creates new in memory writer using provided sender
    pub fn new(chan: mpsc::Sender<T>) -> Self {
        Self(chan)
    }

    #[inline(always)]
    ///Returns reference to underlying channel
    pub fn channel(&self) -> &mpsc::Sender<T> {
        &self.0
    }
}

impl<T: for<'a> From<&'a str>> MakeTransport for InMemory<T> {
    type Error = mpsc::SendError<T>;
    type Transport = Self;

    #[inline(always)]
    fn create(&self) -> Result<Self::Transport, Self::Error> {
        Ok((*self).clone())
    }
}

impl<T> TransportError for mpsc::SendError<T> {
    #[inline(always)]
    fn is_terminal(&self) -> bool {
        true
    }
}

impl<T: for<'a> From<&'a str>> Transport<mpsc::SendError<T>> for InMemory<T> {
    #[inline(always)]
    fn write(&mut self, _severity: Severity, msg: &str) -> Result<(), mpsc::SendError<T>> {
        self.0.send(msg.into())
    }
}

impl<T> Clone for InMemory<T> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }

    #[inline(always)]
    fn clone_from(&mut self, source: &Self) {
        self.0.clone_from(&source.0);
    }
}

impl TransportError for io::Error {
    #[inline(always)]
    fn is_terminal(&self) -> bool {
        use io::ErrorKind;

        match self.kind() {
            ErrorKind::AddrInUse | ErrorKind::AddrNotAvailable | ErrorKind::InvalidInput | ErrorKind::Unsupported | ErrorKind::ConnectionRefused => true,
            _ => false,
        }
    }
}

#[derive(Copy, Clone, Debug)]
///UDP transport
pub struct Udp {
    ///Local port to use
    pub local_port: u16,
    ///Remote address of the syslog server to connect to
    pub remote_addr: net::SocketAddr,
}

impl MakeTransport for Udp {
    type Error = io::Error;
    type Transport = net::UdpSocket;

    #[inline(always)]
    fn create(&self) -> Result<Self::Transport, Self::Error> {
        let socket = net::UdpSocket::bind((LOCAL_HOST, self.local_port))?;
        socket.connect(self.remote_addr)?;
        Ok(socket)
    }
}

impl Transport<io::Error> for net::UdpSocket {
    #[inline(always)]
    fn write(&mut self, _severity: Severity, msg: &str) -> Result<(), io::Error> {
        self.send(msg.as_bytes()).map(|_| ())
    }
}

#[derive(Copy, Clone, Debug)]
///Tcp transport
pub struct Tcp {
    ///Remote address of the syslog server to connect to
    pub remote_addr: net::SocketAddr,
    ///Timeout of all operations
    pub timeout: Option<time::Duration>,
}

impl MakeTransport for Tcp {
    type Error = io::Error;
    type Transport = TcpSocket;

    #[inline(always)]
    fn create(&self) -> Result<Self::Transport, Self::Error> {
        let socket = match self.timeout {
            Some(timeout) => net::TcpStream::connect_timeout(&self.remote_addr, timeout)?,
            None => net::TcpStream::connect(self.remote_addr)?,
        };
        socket.set_write_timeout(self.timeout)?;
        Ok(TcpSocket(socket))
    }
}

#[repr(transparent)]
///TCP Socket wrapper which shutdowns socket on Drop
pub struct TcpSocket(net::TcpStream);

impl Transport<io::Error> for TcpSocket {
    #[inline(always)]
    fn write(&mut self, _severity: Severity, msg: &str) -> Result<(), io::Error> {
        io::Write::write_all(&mut self.0, msg.as_bytes())?;
        io::Write::write_all(&mut self.0, LF)?;
        io::Write::flush(&mut self.0)
    }
}

impl ops::Deref for TcpSocket {
    type Target = net::TcpStream;
    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<net::TcpStream> for TcpSocket {
    #[inline(always)]
    fn from(socket: net::TcpStream) -> Self {
        Self(socket)
    }
}

impl Drop for TcpSocket {
    #[inline(always)]
    fn drop(&mut self) {
        let _ = self.0.shutdown(net::Shutdown::Both);
    }
}

#[derive(Copy, Clone)]
///Unix socket writer
pub struct Unix<'a> {
    #[cfg_attr(not(unix), allow(dead_code))]
    path: &'a str,
    timeout: Option<time::Duration>,
}

impl Unix<'static> {
    ///Attempts to find viable system syslog path
    ///
    ///Looks into following paths:
    ///- /dev/log
    ///- /var/run/syslog
    ///- /var/run/log
    pub fn new_system() -> Option<Self> {
        use std::path::Path;

        static SYSTEM_PATHS: &[&str] = &["/dev/log", "/var/run/syslog", "/var/run/log"];

        for path in SYSTEM_PATHS.into_iter() {
            let meta = Path::new(path).metadata();
            if let Ok(meta) = meta {
                if !meta.is_dir() {
                    return Some(Self::new(path))
                }
            }
        }

        None
    }
}

impl<'a> Unix<'a> {
    ///Creates new unix socket writer with specified path.
    ///
    ///Performs no check whether file actually exists
    pub const fn new(path: &'a str) -> Self {
        Self {
            path,
            timeout: None,
        }
    }

    ///Sets timeout on all socket operations.
    ///
    ///Defaults to no setting (i.e. system default)
    pub const fn with_timeout(mut self, timeout: time::Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

impl<'a> MakeTransport for Unix<'a> {
    type Error = io::Error;
    type Transport = UnixSocket;

    #[inline(always)]
    fn create(&self) -> Result<Self::Transport, Self::Error> {
        #[cfg(unix)]
        {
            let socket = std::os::unix::net::UnixDatagram::unbound()?;
            socket.connect(self.path)?;
            if let Some(timeout) = self.timeout {
                socket.set_write_timeout(Some(timeout))?;
            }
            Ok(UnixSocket {
                socket
            })
        }

        #[cfg(not(unix))]
        {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "Unix socket is only supported on unix systems"));
        }
    }
}
///Wrapper over Unix socket
pub struct UnixSocket {
    #[cfg(unix)]
    socket: std::os::unix::net::UnixDatagram,
}

impl Transport<io::Error> for UnixSocket {
    #[inline(always)]
    fn write(&mut self, _severity: Severity, _msg: &str) -> Result<(), io::Error> {
        #[cfg(unix)]
        {
            return self.socket.send(_msg.as_bytes()).map(|_| ());
        }
        #[cfg(not(unix))]
        {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "Unix socket is only supported on unix systems"));
        }
    }
}

impl Drop for UnixSocket {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            let _ = self.socket.shutdown(std::net::Shutdown::Both);
        }
    }
}
