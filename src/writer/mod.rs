//!Logger writer
use core::fmt;

use crate::syslog::Severity;

#[cfg(feature = "std")]
mod std;
#[cfg(feature = "std")]
pub use std::*;

///Writer builder trait
pub trait MakeWriter {
    ///Internal Error Type
    type Error: WriterError;
    ///Writer type
    type Writer: Writer<Self::Error>;

    ///Creates instance
    ///
    ///This function is called when required or previous instance is no longer able to write
    fn create(&self) -> Result<Self::Writer, Self::Error>;
}

///Utility trait to determine write error handling
pub trait WriterError: fmt::Debug {
    ///Returns whether write error indicates Writer cannot be used
    ///
    ///If `true`, then Writer shall be created anew using `MakeWriter`
    fn is_terminal(&self) -> bool;
}

///Log writer
pub trait Writer<ERR: WriterError> {
    ///Performs write of the full encoded message.
    ///
    ///Severity is encoded already and is only for informational purpose
    fn write(&mut self, severity: Severity, msg: &str) -> Result<(), ERR>;
}
