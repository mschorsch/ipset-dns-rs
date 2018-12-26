use std::io::Error as IoError;

use dns_parser::Error as DnsPacketError;
use failure::Fail;

#[derive(Fail, Debug)]
pub enum AppError {
    #[fail(display = "IO error: {}", _0)]
    IoError(IoError),

    #[fail(display = "DNS-Packet error: {}", _0)]
    DnsPacketError(DnsPacketError),

    #[fail(display = "{}", _0)]
    MsgError(String),
}

impl From<IoError> for AppError {
    fn from(err: IoError) -> Self {
        AppError::IoError(err)
    }
}

impl From<String> for AppError {
    fn from(msg: String) -> Self {
        AppError::MsgError(msg)
    }
}

impl<'a> From<&'a str> for AppError {
    fn from(msg: &'a str) -> Self {
        AppError::MsgError(msg.to_owned())
    }
}

impl From<DnsPacketError> for AppError {
    fn from(err: DnsPacketError) -> Self {
        AppError::DnsPacketError(err)
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
