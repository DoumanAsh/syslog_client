extern crate std;

use core::{ops, time};
use std::sync::mpsc;
use std::{io, net};

use super::{MakeWriter, Writer, WriterError};
use crate::syslog::Severity;

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

impl<T: for<'a> From<&'a str>> MakeWriter for InMemory<T> {
    type Error = mpsc::SendError<T>;
    type Writer = Self;

    #[inline(always)]
    fn create(&self) -> Result<Self::Writer, Self::Error> {
        Ok((*self).clone())
    }
}

impl<T> WriterError for mpsc::SendError<T> {
    #[inline(always)]
    fn is_terminal(&self) -> bool {
        true
    }
}

impl<T: for<'a> From<&'a str>> Writer<mpsc::SendError<T>> for InMemory<T> {
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

impl WriterError for io::Error {
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

impl MakeWriter for Udp {
    type Error = io::Error;
    type Writer = net::UdpSocket;

    #[inline(always)]
    fn create(&self) -> Result<Self::Writer, Self::Error> {
        let socket = net::UdpSocket::bind((LOCAL_HOST, self.local_port))?;
        socket.connect(self.remote_addr)?;
        Ok(socket)
    }
}

impl Writer<io::Error> for net::UdpSocket {
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

impl MakeWriter for Tcp {
    type Error = io::Error;
    type Writer = TcpSocket;

    #[inline(always)]
    fn create(&self) -> Result<Self::Writer, Self::Error> {
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

impl Writer<io::Error> for TcpSocket {
    #[inline(always)]
    fn write(&mut self, _severity: Severity, msg: &str) -> Result<(), io::Error> {
        io::Write::write_all(&mut self.0, msg.as_bytes())?;
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

impl Drop for TcpSocket {
    fn drop(&mut self) {
        let _ = self.0.shutdown(net::Shutdown::Both);
    }
}
