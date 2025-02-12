//!Tracing support

use core::fmt;

use crate::{writer, Syslog, Severity, Writer, Rfc3164Buffer, Rfc3164RecordWriter};

use tracing::Level;
use tracing::Event;
use tracing::span::{Id, Attributes, Record};
use tracing::subscriber::Subscriber as Collect;
use tracing::field::{Field, Visit};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::layer::Context;

//Event message which is recorded as it is rather than as field
const MESSAGE_FIELD: &str = "message";

#[cfg(feature = "tracing-full")]
macro_rules! get_span {
    ($ctx:ident[$id:ident]) => {
        match $ctx.span($id) {
            Some(span) => span,
            None => return,
        }
    }
}

impl From<Level> for Severity {
    #[inline(always)]
    fn from(level: Level) -> Self {
        match level {
            Level::ERROR => Self::LOG_ERR,
            Level::WARN => Self::LOG_WARNING,
            Level::INFO => Self::LOG_NOTICE,
            Level::DEBUG => Self::LOG_INFO,
            Level::TRACE => Self::LOG_DEBUG,
        }
    }
}

///Tracing layer for syslog
pub struct Rfc3164Layer<W> {
    syslog: Syslog,
    writer: W,
}

impl<W> Rfc3164Layer<W> {
    ///Creates new instance which requires writer to be Clone-able
    pub const fn new(syslog: Syslog, writer: W) -> Self {
        Self {
            syslog,
            writer,
        }
    }
}

struct Rfc3164EventVisitor<'a, W: writer::MakeTransport> {
    record: Rfc3164RecordWriter<'a, W>,
}

impl<W: writer::MakeTransport> Drop for Rfc3164EventVisitor<'_, W> {
    #[inline(always)]
    fn drop(&mut self) {
        let _ = self.record.flush_without_clear();
    }
}

impl<W: writer::MakeTransport> Visit for Rfc3164EventVisitor<'_, W> {
    #[inline(always)]
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let name = field.name();
        let _ = if name == MESSAGE_FIELD {
            fmt::Write::write_fmt(&mut self.record, format_args!("{:?}", value))
        } else {
            fmt::Write::write_fmt(&mut self.record, format_args!(" {name}={:?}", value))
        };
    }

    #[inline(always)]
    fn record_f64(&mut self, field: &Field, value: f64) {
        let name = field.name();
        let _ = if name == MESSAGE_FIELD {
            fmt::Write::write_fmt(&mut self.record, format_args!("{value}"))
        } else {
            fmt::Write::write_fmt(&mut self.record, format_args!(" {name}={value}"))
        };
    }

    #[inline(always)]
    fn record_i64(&mut self, field: &Field, value: i64) {
        let name = field.name();
        let _ = if name == MESSAGE_FIELD {
            fmt::Write::write_fmt(&mut self.record, format_args!("{value}"))
        } else {
            fmt::Write::write_fmt(&mut self.record, format_args!(" {name}={value}"))
        };
    }

    #[inline(always)]
    fn record_u64(&mut self, field: &Field, value: u64) {
        let name = field.name();
        let _ = if name == MESSAGE_FIELD {
            fmt::Write::write_fmt(&mut self.record, format_args!("{value}"))
        } else {
            fmt::Write::write_fmt(&mut self.record, format_args!(" {name}={value}"))
        };
    }

    #[inline(always)]
    fn record_i128(&mut self, field: &Field, value: i128) {
        let name = field.name();
        let _ = if name == MESSAGE_FIELD {
            fmt::Write::write_fmt(&mut self.record, format_args!("{value}"))
        } else {
            fmt::Write::write_fmt(&mut self.record, format_args!(" {name}={value}"))
        };
    }

    #[inline(always)]
    fn record_u128(&mut self, field: &Field, value: u128) {
        let name = field.name();
        let _ = if name == MESSAGE_FIELD {
            fmt::Write::write_fmt(&mut self.record, format_args!("{value}"))
        } else {
            fmt::Write::write_fmt(&mut self.record, format_args!(" {name}={value}"))
        };
    }

    #[inline(always)]
    fn record_bool(&mut self, field: &Field, value: bool) {
        let name = field.name();
        let _ = if name == MESSAGE_FIELD {
            fmt::Write::write_fmt(&mut self.record, format_args!("{value}"))
        } else {
            fmt::Write::write_fmt(&mut self.record, format_args!(" {name}={value}"))
        };
    }

    #[inline(always)]
    fn record_str(&mut self, field: &Field, value: &str) {
        let name = field.name();
        let _ = if name == MESSAGE_FIELD {
            fmt::Write::write_fmt(&mut self.record, format_args!("{value}"))
        } else {
            fmt::Write::write_fmt(&mut self.record, format_args!(" {name}={value}"))
        };
    }

    #[cfg(feature = "std")]
    #[inline(always)]
    fn record_error(&mut self, field: &Field, value: &(dyn core::error::Error + 'static)) {
        let name = field.name();
        let _ = if name == MESSAGE_FIELD {
            fmt::Write::write_fmt(&mut self.record, format_args!("{value}"))
        } else {
            fmt::Write::write_fmt(&mut self.record, format_args!(" {name}={value}"))
        };
    }
}

const MAX_SPAN_SIZE: usize = 250;

///Accumulator of span's attributes
pub struct Rfc3164SpanAttrsAccum {
    ///Span identifier
    name: &'static str,
    ///Extensions are kept on heap but we want to limit every span to some reasonable buffer size
    ///to avoid overall message to be too big
    ///If field value is too big to fit single buffer, then we really need to truncate it
    ///We should only keep values that are short as otherwise it is unsuitable for structured data
    buffer: str_buf::StrBuf<{str_buf::capacity(MAX_SPAN_SIZE)}>,
}

impl Rfc3164SpanAttrsAccum {
    const PLACEHOLDER: &str = "<TRNCT>";
    const FIELD_SIZE_LIMIT: usize = 50;

    #[inline(always)]
    ///Creates new span accumulator
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            buffer: str_buf::StrBuf::new(),
        }
    }

    #[inline(always)]
    ///Returns accumulated list of span fields
    pub fn span_values(&self) -> &str {
        self.buffer.as_str()
    }

    #[inline(always)]
    fn prepare_next_field(&mut self, name: &str) {
        if !self.buffer.is_empty() {
            self.buffer.push_str(" ");
        }

        self.buffer.push_str(name);
        self.buffer.push_str("=");
    }

    fn truncate_value_if_necessary(&mut self, prev_size: usize) {
        let value_size = self.buffer.len().saturating_sub(prev_size);
        if value_size > Self::FIELD_SIZE_LIMIT {
            unsafe {
                self.buffer.set_len(prev_size);
            }

            self.buffer.push_str(Self::PLACEHOLDER);
        }
    }

    #[inline(always)]
    ///Records error using fmt::Debug, truncating if necessary
    pub fn record_debug_value(&mut self, value: &dyn fmt::Debug) {
        let prev_size = self.buffer.len();
        let _ = fmt::Write::write_fmt(&mut self.buffer, format_args!("{:?}", value));

        self.truncate_value_if_necessary(prev_size);
    }

    #[inline(always)]
    ///Records error using fmt::Display, truncating if necessary
    pub fn record_error_value(&mut self, value: &(dyn core::error::Error + 'static)) {
        let prev_size = self.buffer.len();
        let _ = fmt::Write::write_fmt(&mut self.buffer, format_args!("{}", value));

        self.truncate_value_if_necessary(prev_size);
    }

    #[inline(always)]
    ///Records str as it is, truncating if necessary
    pub fn record_str_value(&mut self, value: &str) {
        if value.len() <= Self::FIELD_SIZE_LIMIT {
            self.buffer.push_str(value);
        } else {
            self.buffer.push_str(Self::PLACEHOLDER);
        }
    }
}

impl fmt::Display for Rfc3164SpanAttrsAccum {
    #[inline(always)]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_str("[")?;
        fmt.write_str(self.name)?;
        fmt.write_str(" ")?;
        fmt.write_str(self.span_values())?;
        fmt.write_str("]")
    }
}

impl Visit for Rfc3164SpanAttrsAccum {
    #[inline(always)]
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.prepare_next_field(field.name());

        self.record_debug_value(value);
    }

    #[inline(always)]
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.prepare_next_field(field.name());
        let _ = fmt::Write::write_fmt(&mut self.buffer, format_args!("{value}"));
    }

    #[inline(always)]
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.prepare_next_field(field.name());
        let _ = fmt::Write::write_fmt(&mut self.buffer, format_args!("{value}"));
    }

    #[inline(always)]
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.prepare_next_field(field.name());
        let _ = fmt::Write::write_fmt(&mut self.buffer, format_args!("{value}"));
    }

    #[inline(always)]
    fn record_i128(&mut self, field: &Field, value: i128) {
        self.prepare_next_field(field.name());
        let _ = fmt::Write::write_fmt(&mut self.buffer, format_args!("{value}"));
    }

    #[inline(always)]
    fn record_u128(&mut self, field: &Field, value: u128) {
        self.prepare_next_field(field.name());
        let _ = fmt::Write::write_fmt(&mut self.buffer, format_args!("{value}"));
    }

    #[inline(always)]
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.prepare_next_field(field.name());
        if value {
            self.buffer.push_str("true");
        } else {
            self.buffer.push_str("false");
        }
    }

    #[inline(always)]
    fn record_str(&mut self, field: &Field, value: &str) {
        self.prepare_next_field(field.name());
        self.record_str_value(value);
    }

    #[cfg(feature = "std")]
    #[inline(always)]
    fn record_error(&mut self, field: &Field, value: &(dyn core::error::Error + 'static)) {
        self.prepare_next_field(field.name());
        self.record_error_value(value);
    }
}

impl<C: Collect + for<'a> LookupSpan<'a>, W: writer::MakeTransport + 'static> tracing_subscriber::layer::Layer<C> for Rfc3164Layer<W> {
    #[inline(always)]
    fn on_new_span(&self, _attrs: &Attributes<'_>, _id: &Id, _ctx: Context<'_, C>) {
        //Generally you cannot have the same span wit the same set of extensions
        #[cfg(feature = "tracing-full")]
        {
            let span = get_span!(_ctx[_id]);
            let mut extensions = span.extensions_mut();
            if extensions.get_mut::<Rfc3164SpanAttrsAccum>().is_none() {
                extensions.insert(Rfc3164SpanAttrsAccum::new(span.name()));
                let accum = match extensions.get_mut::<Rfc3164SpanAttrsAccum>() {
                    Some(accum) => accum,
                    None => unreach!(),
                };

                _attrs.record(accum);
            }
        }
    }

    #[inline(always)]
    fn on_record(&self, _id: &Id, _values: &Record<'_>, _ctx: Context<'_, C>) {
        #[cfg(feature = "tracing-full")]
        {
            let span = get_span!(_ctx[_id]);
            let mut extensions = span.extensions_mut();
            if let Some(accum) = extensions.get_mut::<Rfc3164SpanAttrsAccum>() {
                _values.record(accum);
            }
        }
    }

    #[inline]
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, C>) {
        let level = (*event.metadata().level()).into();

        let mut writer = Writer::new(&self.writer);
        let mut buffer = Rfc3164Buffer::new();
        let record = self.syslog.rfc3164_record(&mut writer, &mut buffer, level);
        let mut visitor = Rfc3164EventVisitor {
            record,
        };
        event.record(&mut visitor);

        //Optionally record all spans after main event data
        //
        //We prefer to do it as span data can be potentially very big so we want to start splitting
        //after event itself is written (as it is more likely to be concise
        #[cfg(feature = "tracing-full")]
        if let Some(current_span) = _ctx.event_span(event) {
            for span in current_span.scope() {
                if let Some(span) = span.extensions().get::<Rfc3164SpanAttrsAccum>() {
                    let _ = fmt::Write::write_fmt(&mut visitor.record, format_args!(" {span}"));
                }
            }
        }
    }
}
