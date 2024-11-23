//! Syslog writer

#![no_std]
#![warn(missing_docs)]
#![allow(clippy::style)]

#[doc(hidden)]
#[cfg(not(debug_assertions))]
macro_rules! unreach {
    () => {{
        unsafe {
            core::hint::unreachable_unchecked();
        }
    }};
}

#[doc(hidden)]
#[cfg(debug_assertions)]
macro_rules! unreach {
    () => {{
        unreachable!();
    }};
}

pub mod syslog;
pub use syslog::{Facility, Severity};
pub mod writer;
#[cfg(feature = "log04")]
pub mod log04;

///Syslogger
pub struct Syslog {
    facility: syslog::Facility,
    hostname: syslog::header::Hostname,
    tag: syslog::header::Tag,
    retry_count: u8,
}

impl Syslog {
    #[inline(always)]
    ///Creates new syslog instance
    pub const fn new(facility: syslog::Facility, hostname: syslog::header::Hostname, tag: syslog::header::Tag) -> Self {
        Self {
            facility,
            tag,
            hostname,
            retry_count: 2,
        }
    }

    #[inline(always)]
    ///Changes retry count of attempts to re-try write.
    ///
    ///Retry count is used when logger fails to create writer or write.
    ///
    ///Once number of attempts exceeds retry count, logger will give up and return error.
    ///
    ///Defaults to 2
    pub const fn with_retry_count(mut self, retry_count: u8) -> Self {
        self.retry_count = retry_count;
        self
    }

    #[inline(always)]
    ///Creates RFC-3164 format logger using specified `writer`
    pub const fn rfc3164<W: writer::MakeWriter>(self, writer: W) -> Rfc3164Logger<W> {
        Rfc3164Logger::new(self, writer)
    }

    #[cfg(feature = "log04")]
    fn rfc3164_write_fmt<W: writer::MakeWriter>(&self, writer: &mut Writer<W>, buffer: &mut Rfc3164Buffer, severity: Severity, text: &core::fmt::Arguments<'_>) -> Result<(), W::Error> {
        let timestamp = syslog::header::Timestamp::now_utc();
        let header = syslog::header::Rfc3164 {
            pri: severity.priority(self.facility),
            hostname: &self.hostname,
            tag: &self.tag,
            pid: os_id::process::get_raw_id() as _,
            timestamp,
        };

        header.write_buffer(buffer);
        buffer.push_str(" ");
        let _ = core::fmt::Write::write_fmt(buffer, *text);
        writer.write_buffer(buffer.as_str(), severity, self.retry_count)?;

        buffer.clear();
        Ok(())
    }

    fn rfc3164_write_str<W: writer::MakeWriter>(&self, writer: &mut Writer<W>, buffer: &mut Rfc3164Buffer, severity: Severity, mut text: &str) -> Result<(), W::Error> {
        let timestamp = syslog::header::Timestamp::now_utc();
        let header = syslog::header::Rfc3164 {
            pri: severity.priority(self.facility),
            hostname: &self.hostname,
            tag: &self.tag,
            pid: os_id::process::get_raw_id() as _,
            timestamp,
        };

        header.write_buffer(buffer);
        buffer.push_str(" ");
        let header_size = buffer.len();

        loop {
            let consumed = buffer.push_str(text);
            text = &text[consumed..];

            writer.write_buffer(buffer.as_str(), severity, self.retry_count)?;
            //This is safe because we know exact header size written
            unsafe {
                buffer.set_len(header_size);
            }

            if text.is_empty() {
                break;
            }
        }

        buffer.clear();
        Ok(())
    }
}

struct Writer<W: writer::MakeWriter> {
    writer: W,
    cached_writer: Option<W::Writer>,
}

impl<W: writer::MakeWriter> Writer<W> {
    #[inline(always)]
    const fn new(writer: W) -> Self {
        Self {
            writer,
            cached_writer: None,
        }
    }

    fn write_buffer(&mut self, buffer: &str, severity: Severity, retry_count: u8) -> Result<(), W::Error> {
        use writer::{Writer, WriterError};

        //We will try once + retry_count
        let mut retry_attempts = retry_count.saturating_add(1);

        loop {
            retry_attempts = retry_attempts.saturating_sub(1);

            let mut writer = match self.cached_writer.take() {
                Some(writer) => writer,
                None => match self.writer.create() {
                    Ok(writer) => writer,
                    //If interface error indicates you cannot proceed then give up immediately
                    Err(error) if error.is_terminal() => return Err(error),
                    Err(_) if retry_attempts > 0 => continue,
                    Err(error) => break Err(error),
                },
            };

            match writer.write(severity, buffer) {
                Ok(()) => {
                    //Only cache writer, if it is able to write
                    self.cached_writer = Some(writer);
                    break Ok(());
                }
                //If interface error indicates you cannot proceed then give up immediately
                //Also there is high risk in caching interface that errors out, so avoid that
                Err(error) if error.is_terminal() => return Err(error),
                Err(_) if retry_attempts > 0 => continue,
                Err(error) => break Err(error),
            }
        }
    }
}

///Buffer type to hold max possible message as per RFC 3164 (1024 bytes)
pub type Rfc3164Buffer = str_buf::StrBuf<{ str_buf::capacity(1024) }>;

///RFC 3164 logger
pub struct Rfc3164Logger<W: writer::MakeWriter> {
    syslog: Syslog,
    writer: Writer<W>,
}

impl<W: writer::MakeWriter> Rfc3164Logger<W> {
    #[inline(always)]
    ///Creates new RFC 3164 format logger
    pub const fn new(syslog: Syslog, writer: W) -> Self {
        Self {
            syslog,
            writer: Writer::new(writer),
        }
    }

    ///Adds internal buffer to the logger
    pub const fn with_buffer(self) -> Rfc3164BufferedLogger<W> {
        Rfc3164BufferedLogger::new(self)
    }

    #[inline(always)]
    ///Writes specified string onto syslog
    ///
    ///If text doesn't fit limit of 1024 bytes, then it is split into chunks
    pub fn write_str(&mut self, buffer: &mut Rfc3164Buffer, severity: Severity, text: &str) -> Result<(), W::Error> {
        self.syslog.rfc3164_write_str(&mut self.writer, buffer, severity, text)
    }
}

///RFC 3164 logger
pub struct Rfc3164BufferedLogger<W: writer::MakeWriter> {
    inner: Rfc3164Logger<W>,
    buffer: Rfc3164Buffer,
}

impl<W: writer::MakeWriter> Rfc3164BufferedLogger<W> {
    #[inline(always)]
    ///Creates new instance of logger with internal buffer
    pub const fn new(inner: Rfc3164Logger<W>) -> Self {
        Self {
            inner,
            buffer: Rfc3164Buffer::new(),
        }
    }

    #[inline(always)]
    ///Writes specified string onto syslog
    ///
    ///If text doesn't fit limit of 1024 bytes, then it is split into chunks
    pub fn write_str(&mut self, severity: Severity, text: &str) -> Result<(), W::Error> {
        self.inner.write_str(&mut self.buffer, severity, text)
    }
}
