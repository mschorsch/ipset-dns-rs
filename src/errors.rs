#![allow(dead_code)]

use std::error::Error as StdError;
use std::fmt;
use std::io::Error as IoError;
use std::result::Result as StdResult;

use dns_parser::Error as DnsPacketError;

pub type Result<T> = StdResult<T, Error>;

pub(crate) fn new_error(kind: ErrorKind) -> Error {
    Error::new(kind)
}

#[derive(Debug)]
pub struct Error(Box<ErrorKind>);

impl Error {
    pub fn new(kind: ErrorKind) -> Self {
        Error(Box::new(kind))
    }

    pub fn kind(&self) -> &ErrorKind {
        &self.0
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Error::new(kind)
    }
}

impl Into<ErrorKind> for Error {
    fn into(self) -> ErrorKind {
        *self.0
    }
}

#[derive(Debug)]
pub enum ErrorKind {
    Io(IoError),
    DnsPacket(DnsPacketError),
    Msg(String),
}

impl From<IoError> for Error {
    fn from(err: IoError) -> Self {
        From::from(ErrorKind::Io(err))
    }
}

impl From<String> for Error {
    fn from(msg: String) -> Self {
        From::from(ErrorKind::Msg(msg))
    }
}

impl<'a> From<&'a str> for Error {
    fn from(msg: &'a str) -> Self {
        From::from(ErrorKind::Msg(msg.to_owned()))
    }
}

impl From<DnsPacketError> for Error {
    fn from(err: DnsPacketError) -> Self {
        From::from(ErrorKind::DnsPacket(err))
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        use self::ErrorKind::*;

        match *self.0 {
            Io(ref err) => Some(err),
            DnsPacket(ref err) => Some(err),
            Msg(_) => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ErrorKind::*;

        match *self.0 {
            Io(ref err) => write!(f, "IO error: {}", err),
            DnsPacket(ref err) => write!(f, "DNS-Paket error: {}", err),
            Msg(ref msg) => write!(f, "{}", msg),
        }
    }
}