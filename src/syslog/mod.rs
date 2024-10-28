//! Syslog protocol
//!
//! Reference: syslog.h

pub mod header;

///Log importance
#[repr(u8)]
#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
pub enum Severity {
    ///system is unusable
    LOG_EMERG = 0,
    ///action must be taken immediately
    LOG_ALERT = 1,
    ///critical conditions
    LOG_CRIT = 2,
    ///error conditions
    LOG_ERR = 3,
    ///warning conditions
    LOG_WARNING = 4,
    ///normal but significant condition
    LOG_NOTICE = 5,
    ///informational
    LOG_INFO = 6,
    ///debug-level messages
    LOG_DEBUG = 7,
}

impl Severity {
    ///Encodes severity into priority with corresponding facility
    pub const fn priority(self, fac: Facility) -> u8 {
        fac as u8 | self as u8
    }
}

///Facility code, indicating source of log
#[repr(u8)]
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug)]
pub enum Facility {
    ///Kernel
    LOG_KERN = 0 << 3,
    ///User space application (Default leveL)
    LOG_USER = 1 << 3,
    ///Mail system
    LOG_MAIL = 2 << 3,
    ///System daemon
    LOG_DAEMON = 3 << 3,
    ///Security
    LOG_AUTH = 4 << 3,
    ///Internal syslogd
    LOG_SYSLOG = 5 << 3,
    ///Line printer
    LOG_LPR = 6 << 3,
    ///News
    LOG_NEWS = 7 << 3,
    ///Unix-to-Unix Copy
    LOG_UUCP = 8 << 3,
    ///Cron daemon
    LOG_CRON = 9 << 3,
    ///Security (private)
    LOG_AUTHPRIV = 10 << 3,
    ///FTP daemon
    LOG_FTP = 11 << 3,
    ///Reserved for local use
    LOG_LOCAL0 = 16 << 3,
    ///Reserved for local use
    LOG_LOCAL1 = 17 << 3,
    ///Reserved for local use
    LOG_LOCAL2 = 18 << 3,
    ///Reserved for local use
    LOG_LOCAL3 = 19 << 3,
    ///Reserved for local use
    LOG_LOCAL4 = 20 << 3,
    ///Reserved for local use
    LOG_LOCAL5 = 21 << 3,
    ///Reserved for local use
    LOG_LOCAL6 = 22 << 3,
    ///Reserved for local use
    LOG_LOCAL7 = 23 << 3,
}

impl Default for Facility {
    #[inline(always)]
    fn default() -> Self {
        Self::LOG_USER
    }
}
