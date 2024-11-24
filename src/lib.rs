//! Syslog client
//!
//!## Features
//!
//!- `std` - Enables std types for purpose of implementing transport methods
//!- `log04` - Enables integration with `log` 0.4

#![no_std]
#![warn(missing_docs)]
#![allow(clippy::style)]

use core::fmt;

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
use writer::Writer;
#[cfg(feature = "log04")]
pub mod log04;

///Buffer type to hold max possible message as per RFC 3164 (1024 bytes)
pub type Rfc3164Buffer = str_buf::StrBuf<{ str_buf::capacity(1024) }>;

///RFC 3164 record writer.
///
///It can be used to efficiently create logging record via `fmt::Write` interface
///
///When necessary record will be split into chunks of 1024 bytes
///
///On Drop internal buffer is cleared
pub struct Rfc3164RecordWriter<'a, W: writer::MakeTransport> {
    writer: &'a mut Writer<W>,
    buffer: &'a mut Rfc3164Buffer,
    severity: Severity,
    header_size: usize,
    retry_count: u8,
}

impl<'a, W: writer::MakeTransport> Rfc3164RecordWriter<'a, W> {
    #[inline]
    ///Creates new record writer
    fn new(syslog: &'a Syslog, writer: &'a mut Writer<W>, buffer: &'a mut Rfc3164Buffer, severity: Severity) -> Self {
        let timestamp = syslog::header::Timestamp::now_utc();
        let header = syslog::header::Rfc3164 {
            pri: severity.priority(syslog.facility),
            hostname: &syslog.hostname,
            tag: &syslog.tag,
            pid: os_id::process::get_raw_id() as _,
            timestamp,
        };

        header.write_buffer(buffer);
        buffer.push_str(" ");
        let header_size = buffer.len();

        Rfc3164RecordWriter {
            writer,
            buffer,
            severity,
            header_size,
            retry_count: syslog.retry_count,
        }
    }

    ///Attempts to write specified string to fit syslog record
    ///
    ///If buffer is to overflow, then record will be flushed and buffer will be filled with rest of message
    ///
    ///On success, text will be fully written
    pub fn write_str(&mut self, mut text: &str) -> Result<(), W::Error> {
        loop {
            if text.is_empty() {
                break Ok(())
            }

            let consumed = self.buffer.push_str(text);

            if consumed < text.len() {
                self.flush()?;
                text = &text[consumed..];
                continue;
            } else {
                //Everything consumed, so carry on.
                //User has to manually flush once he is ready
                break Ok(());
            }
        }
    }

    #[inline(always)]
    ///Clears current content of the record, preparing it for next write
    pub fn clear(&mut self) {
        //This is safe because we know exact header size written
        unsafe {
            self.buffer.set_len(self.header_size);
        }
    }

    #[inline(always)]
    fn flush_without_clear(&mut self) -> Result<(), W::Error> {
        if self.buffer.len() > self.header_size {
            self.writer.write_buffer(self.buffer.as_str(), self.severity, self.retry_count)?;
        }
        Ok(())
    }

    #[inline(always)]
    ///Flushes record by sending current buffer to the server
    ///
    ///On success clear buffer.
    pub fn flush(&mut self) -> Result<(), W::Error> {
        if self.buffer.len() > self.header_size {
            self.writer.write_buffer(self.buffer.as_str(), self.severity, self.retry_count)?;
            self.clear();
        }

        Ok(())
    }
}

impl<'a, W: writer::MakeTransport> Drop for Rfc3164RecordWriter<'a, W> {
    #[inline(always)]
    fn drop(&mut self) {
        self.buffer.clear()
    }
}

impl<'a, W: writer::MakeTransport> fmt::Write for Rfc3164RecordWriter<'a, W> {
    #[inline]
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if self.write_str(text).is_err() {
            return Err(fmt::Error);
        } else {
            Ok(())
        }
    }
}

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
    pub const fn rfc3164<W: writer::MakeTransport>(self, writer: W) -> Rfc3164Logger<W> {
        Rfc3164Logger::new(self, writer)
    }

    #[inline(always)]
    pub(crate) fn rfc3164_record<'a, W: writer::MakeTransport>(&'a self, writer: &'a mut Writer<W>, buffer: &'a mut Rfc3164Buffer, severity: Severity) -> Rfc3164RecordWriter<'a, W> {
        Rfc3164RecordWriter::new(self, writer, buffer, severity)
    }
}

///RFC 3164 logger
pub struct Rfc3164Logger<W: writer::MakeTransport> {
    syslog: Syslog,
    writer: Writer<W>,
}

impl<W: writer::MakeTransport> Rfc3164Logger<W> {
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
        let mut record = self.syslog.rfc3164_record(&mut self.writer, buffer, severity);

        record.write_str(text)?;
        record.flush_without_clear()
    }
}

///RFC 3164 logger
pub struct Rfc3164BufferedLogger<W: writer::MakeTransport> {
    inner: Rfc3164Logger<W>,
    buffer: Rfc3164Buffer,
}

impl<W: writer::MakeTransport> Rfc3164BufferedLogger<W> {
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

    #[inline(always)]
    ///Creates syslog record writer
    pub fn write_record(&mut self, severity: Severity) -> Rfc3164RecordWriter<'_, W> {
        Rfc3164RecordWriter::new(&self.inner.syslog, &mut self.inner.writer, &mut self.buffer, severity)
    }
}
