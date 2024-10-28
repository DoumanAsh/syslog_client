//! Syslog header components

use core::{fmt, mem};

use str_buf::StrBuf;

pub use super::{Facility, Severity};
use crate::Hostname;

#[repr(transparent)]
///Process name
pub struct Tag(StrBuf<{ str_buf::capacity(32) }>);

impl Tag {
    #[inline]
    ///Gets tag
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }

    ///Creates new tag with name of the process.
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
                        if buffer.as_slice()[idx].is_ascii_alphanumeric() {
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

///Timestamp components
pub struct Timestamp {
    ///Year
    pub year: u16,
    ///Months since January. Range 0-11
    pub month: u8,
    ///Day of the month. Range 1-31
    pub day: u8,
    ///Seconds after the minute. Range 0-60
    pub sec: u8,
    ///Minutes after the hour. Range 0-59
    pub min: u8,
    ///Hours since midnight. Range 0-23
    pub hour: u8,
}

impl Timestamp {
    ///Creates new UTC timestamp as default value when time is not available
    pub const fn utc() -> Self {
        Self {
            year: 1970,
            month: 0,
            day: 1,
            hour: 0,
            min: 0,
            sec: 0,
        }
    }

    const fn rfc3164_month(&self) -> &'static str {
        match self.month {
            0 => "Jan",
            1 => "Feb",
            2 => "Mar",
            3 => "Apr",
            4 => "May",
            5 => "Jun",
            6 => "Jul",
            7 => "Aug",
            8 => "Sep",
            9 => "Oct",
            10 => "Nov",
            11 => "Dec",
            _ => unreach!(),
        }
    }
}

///RFC 3164 header to the message
pub struct Rfc3164<'a> {
    ///Encoded priority
    pub pri: u8,
    ///Timestamp
    pub timestamp: Timestamp,
    ///Hostname
    pub hostname: &'a Hostname,
    ///Process name (tag)
    pub tag: &'a Tag,
    ///Process pid
    ///
    ///While it is optional, it should be always available so there is no need not to include it
    pub pid: u32,
}

///Header size
const RFC_3164_SIZE: usize = 3 + 2 //Prio(u8 integer) wrapped in <>
    + 3 + 1 + 2 + 1 // Month in 3 letter format + 2 characters for day (empty space in case if <10)
    + 8 + 1 //Time is separated by `:` and always 2 digits (padded with 0) hence 8 bytes
    + mem::size_of::<Hostname>() - 1 + 1 //TLS certificate limit is used arbitrary, but generally it should not be longer than 23 characters. -1 for Hostname length byte
    + mem::size_of::<Tag>() - 1 //Process name(tag) type uses extra byte for length so -1
    + 2 + 10 //Optional PID component(u32 integer) wrapped into []
    + 1; //Common part ends with `:`, afterwards we put actual message

impl<'a> Rfc3164<'a> {
    ///Header size
    pub const SIZE: usize = RFC_3164_SIZE;

    ///Writes static buffer with this header value
    ///
    ///It assumes `out` will be successful because I only use it like that
    ///
    ///On success writes `Rfc3164::SIZE` bytes long string
    pub fn write_buffer(&self, out: &mut impl fmt::Write) {
        let Self { pri, timestamp, hostname, tag, pid } = self;
        let tag = tag.as_str();
        let hostname = hostname.as_str();
        let month = timestamp.rfc3164_month();
        let Timestamp { day, hour, sec, min, .. } = timestamp;
        let _ = fmt::Write::write_fmt(out, format_args!("<{pri}>{month} {day:>2} {hour:>02}:{min:>02}:{sec:>02} {hostname} {tag}[{pid}]:"));
    }

    ///Creates static sized string that holds content of header
    pub fn create_buffer(&self) -> StrBuf<{ str_buf::capacity(RFC_3164_SIZE) }> {
        let mut out = StrBuf::new();
        self.write_buffer(&mut out);
        out
    }
}
