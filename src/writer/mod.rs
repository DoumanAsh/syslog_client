//!Logger writer
use core::fmt;

use crate::syslog::Severity;

#[cfg(feature = "std")]
mod std;
#[cfg(feature = "std")]
pub use std::*;

///Transport builder trait
pub trait MakeTransport {
    ///Internal Error Type
    type Error: TransportError;
    ///Transport type
    type Transport: Transport<Self::Error>;

    ///Creates instance
    ///
    ///This function is called when required or previous instance is no longer able to write
    fn create(&self) -> Result<Self::Transport, Self::Error>;
}

///Utility trait to determine write error handling
pub trait TransportError: fmt::Debug {
    ///Returns whether write error indicates Transport cannot be used
    ///
    ///If `true`, then Transport shall be created anew using `MakeTransport`
    fn is_terminal(&self) -> bool;
}

///Log writer
pub trait Transport<ERR: TransportError> {
    ///Performs write of the full encoded message.
    ///
    ///Severity is encoded already and is only for informational purpose
    fn write(&mut self, severity: Severity, msg: &str) -> Result<(), ERR>;
}

pub(crate) struct Writer<IO: MakeTransport> {
    transport: IO,
    cached_writer: Option<IO::Transport>,
}

impl<IO: MakeTransport> Writer<IO> {
    #[inline(always)]
    pub(crate) const fn new(transport: IO) -> Self {
        Self {
            transport,
            cached_writer: None,
        }
    }

    pub(crate) fn write_buffer(&mut self, buffer: &str, severity: Severity, retry_count: u8) -> Result<(), IO::Error> {
        //We will try once + retry_count
        let mut retry_attempts = retry_count.saturating_add(1);

        loop {
            retry_attempts = retry_attempts.saturating_sub(1);

            let mut writer = match self.cached_writer.take() {
                Some(writer) => writer,
                None => match self.transport.create() {
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
