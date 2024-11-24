//!Implementation for `log` crate interface

use log04::{kv, Log, Metadata, Record, Level, max_level, STATIC_MAX_LEVEL};

use crate::{writer, Writer, Syslog, Severity, Rfc3164Buffer, Rfc3164RecordWriter};

use core::fmt;

///Syslog with log interface
///
///In case of non-static record, truncates to fit 1024 bytes limit
pub struct Rfc3164Logger<W> {
    syslog: Syslog,
    writer: W,
}

impl<W: Clone> Rfc3164Logger<W> {
    ///Creates new instance which requires writer to be Clone-able
    pub const fn new(syslog: Syslog, writer: W) -> Self {
        Self {
            syslog,
            writer,
        }
    }
}

impl From<Level> for Severity {
    #[inline(always)]
    fn from(level: Level) -> Self {
        match level {
            Level::Error => Self::LOG_ERR,
            Level::Warn => Self::LOG_WARNING,
            Level::Info => Self::LOG_NOTICE,
            Level::Debug => Self::LOG_INFO,
            Level::Trace => Self::LOG_DEBUG,
        }
    }
}

impl<W: Sync + Send + writer::MakeTransport + Clone> Log for Rfc3164Logger<W> where W::Transport: Sync + Send {
    #[inline(always)]
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= max_level() && metadata.level() <= STATIC_MAX_LEVEL
    }

    #[inline]
    fn log(&self, record: &Record) {
        let level = record.level().into();
        let args = record.args();

        let mut writer = Writer::new(self.writer.clone());
        let mut buffer = Rfc3164Buffer::new();
        let mut syslog = self.syslog.rfc3164_record(&mut writer, &mut buffer, level);
        if let Some(log) = args.as_str() {
            if syslog.write_str(log).is_err() {
                return;
            }
        } else {
            if fmt::Write::write_fmt(&mut syslog, *args).is_err() {
                return;
            }
        }

        //Visitor will do final flush
        let mut key_values_writer = StructuredVisitor {
            record: syslog,
            //no key values written unless visit() is called
            is_written: false,
        };

        if record.key_values().visit(&mut key_values_writer).is_err() {
            return;
        }
    }

    #[inline(always)]
    fn flush(&self) {
    }
}

#[cold]
#[inline(never)]
fn unlikely_write_error() -> kv::Error {
    kv::Error::msg("Logger unable to flush")
}

struct StructuredVisitor<'a, W: writer::MakeTransport> {
    record: Rfc3164RecordWriter<'a, W>,
    is_written: bool,
}

impl<'a, W: Sync + Send + writer::MakeTransport> kv::VisitSource<'_> for StructuredVisitor<'a, W> {
    #[inline(always)]
    fn visit_pair(&mut self, key: kv::Key<'_>, value: kv::Value<'_>) -> Result<(), kv::Error> {
        if !self.is_written {
            if self.record.write_str(" [KV").is_err() {
                return Err(unlikely_write_error());
            }

            self.is_written = true;
        }

        if fmt::Write::write_fmt(&mut self.record, format_args!(" {key}={value}")).is_err() {
            return Err(unlikely_write_error());
        }

        Ok(())
    }
}

impl<'a, W: writer::MakeTransport> Drop for StructuredVisitor<'a, W> {
    #[inline(always)]
    fn drop(&mut self) {
        if self.is_written {
            let _ = self.record.write_str("]");
        }
        let _ = self.record.flush_without_clear();
    }
}
