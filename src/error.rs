use crate::{if_no_std, if_std};
use core::fmt::{Display, Formatter};

if_no_std! {
    use alloc::string::String;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum ErrorType {
    ReadError,
    WriteError,
    OtherError,
    #[cfg(feature = "log")]
    LogError,
    #[cfg(feature = "bgp")]
    BGPError(crate::bgp::error::BGPError),
}

impl ErrorType {
    pub fn err(&self, message: impl Into<String>) -> Error {
        Error {
            message: message.into(),
            ty: *self,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct Error {
    message: String,
    ty: ErrorType,
}

impl Display for Error {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{} ({:?})", self.message, self.ty)
    }
}

if_std! {
    impl std::error::Error for Error {}
}
