#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct BGPError {
    error_code: ErrorCode,
    sub_code: u8,
}

impl BGPError {
    pub fn new<T: Into<u8>>(error_code: ErrorCode, sub_code: T) -> BGPError {
        Self {
            error_code,
            sub_code: sub_code.into(),
        }
    }

    pub fn header_error(sub_code: HeaderError) -> BGPError {
        Self::new(ErrorCode::MessageHeader, sub_code)
    }

    pub fn open(sub_code: OpenMessageError) -> BGPError {
        Self::new(ErrorCode::OpenMessage, sub_code)
    }
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum ErrorCode {
    MessageHeader = 1,
    OpenMessage = 2,
    UpdateMessage = 3,
    HoldTimerExpired = 4,
    FiniteStateMachine = 5,
    Cease = 6,
    Unknown(u8),
}

impl From<u8> for ErrorCode {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::MessageHeader,
            2 => Self::OpenMessage,
            3 => Self::UpdateMessage,
            4 => Self::HoldTimerExpired,
            5 => Self::FiniteStateMachine,
            6 => Self::Cease,
            value => Self::Unknown(value),
        }
    }
}

impl From<ErrorCode> for u8 {
    fn from(value: ErrorCode) -> Self {
        match value {
            ErrorCode::MessageHeader => 1,
            ErrorCode::OpenMessage => 2,
            ErrorCode::UpdateMessage => 3,
            ErrorCode::HoldTimerExpired => 4,
            ErrorCode::FiniteStateMachine => 5,
            ErrorCode::Cease => 6,
            ErrorCode::Unknown(value) => value,
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum HeaderError {
    ConnectionNotSynchronized = 1,
    BadMessageLength = 2,
    BadMessageType = 3,
}

impl From<HeaderError> for u8 {
    fn from(value: HeaderError) -> Self {
        value as u8
    }
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum OpenMessageError {
    UnsupportedVersionNumber = 1,
    BadPeerAS = 2,
    BadBGPIdentifier = 3,
    UnsupportedOptionalParameter = 4,
    UnacceptableHoldTime = 6,
}

impl From<OpenMessageError> for u8 {
    fn from(value: OpenMessageError) -> Self {
        value as u8
    }
}
