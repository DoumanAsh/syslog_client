//! Syslog writer

#![no_std]
#![warn(missing_docs)]
#![allow(clippy::style)]

use str_buf::StrBuf;

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
        unreachable!()
    }};
}

pub mod syslog;
pub use syslog::{Facility, Severity};
pub mod writer;

#[repr(transparent)]
///Hostname, limited to 64 characters
pub struct Hostname(StrBuf<{ str_buf::capacity(64) }>);

impl Hostname {
    #[inline]
    ///Initializes with no hostname, indicating it as `-` when sending to the server.
    pub const fn none(&self) -> Self {
        Self(StrBuf::from_str("-"))
    }

    #[inline]
    ///Gets tag
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }

    #[inline]
    ///Creates new hostname
    ///
    ///It verifies that name is non-empty alphanumeric string, returning None otherwise.
    pub const fn new(name: &str) -> Option<Self> {
        if name.is_empty() {
            None
        } else {
            match StrBuf::from_str_checked(name) {
                Ok(buffer) => {
                    let mut idx = 0;
                    loop {
                        let byt = buffer.as_slice()[idx];
                        if byt.is_ascii_alphanumeric() || byt == b'-' || byt == b'.' {
                            idx += 1;
                            if idx >= name.len() {
                                break Some(Self(buffer));
                            }
                        } else {
                            break None;
                        }
                    }
                }
                Err(_) => None,
            }
        }
    }
}

///Syslogger
pub struct Syslog {
    facility: syslog::Facility,
    hostname: Hostname,
    tag: syslog::header::Tag,
    retry_count: u8,
}

impl Syslog {
    #[inline(always)]
    ///Creates new syslog instance
    pub const fn new(facility: syslog::Facility, hostname: Hostname, tag: syslog::header::Tag) -> Self {
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
    buffer: Rfc3164Buffer,
}

impl<W: writer::MakeWriter> Rfc3164Logger<W> {
    #[inline(always)]
    ///Creates new RFC 3164 format logger
    pub const fn new(syslog: Syslog, writer: W) -> Self {
        Self {
            syslog,
            writer: Writer::new(writer),
            buffer: Rfc3164Buffer::new(),
        }
    }

    ///Writes specified string onto syslog
    ///
    ///If text doesn't fit limit of 1024 bytes, then it is split into chunks
    pub fn write_str(&mut self, severity: Severity, mut text: &str) -> Result<(), W::Error> {
        let timestamp = match time_c::Time::now_utc() {
            Some(time_c::Time { sec, min, hour, month_day, month, year, .. }) => syslog::header::Timestamp {
                year,
                month: month.saturating_sub(1),
                day: month_day,
                hour,
                sec,
                min,
            },
            None => syslog::header::Timestamp::utc(),
        };
        let header = syslog::header::Rfc3164 {
            pri: severity.priority(self.syslog.facility),
            hostname: &self.syslog.hostname,
            tag: &self.syslog.tag,
            pid: os_id::process::get_raw_id() as _,
            timestamp,
        };

        header.write_buffer(&mut self.buffer);
        self.buffer.push_str(" ");
        let header_size = self.buffer.len();

        loop {
            let consumed = self.buffer.push_str(text);
            text = &text[consumed..];

            self.writer.write_buffer(self.buffer.as_str(), severity, self.syslog.retry_count)?;
            //This is safe because we know exact header size written
            unsafe {
                self.buffer.set_len(header_size);
            }

            if text.is_empty() {
                break;
            }
        }

        self.buffer.clear();
        Ok(())
    }
}
