//!Implementation for `log` crate interface

use log04::{Log, Metadata, Record, Level, max_level, STATIC_MAX_LEVEL};

use crate::{writer, Writer, Syslog, Severity, Rfc3164Buffer};

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

impl<W: Sync + Send + writer::MakeWriter + Clone> Log for Rfc3164Logger<W> where W::Writer: Sync + Send {
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
        let _ = if let Some(log) = args.as_str() {
            self.syslog.rfc3164_write_str(&mut writer, &mut buffer, level, log)
        } else {
            self.syslog.rfc3164_write_fmt(&mut writer, &mut buffer, level, args)
        };
    }

    #[inline(always)]
    fn flush(&self) {
    }
}
