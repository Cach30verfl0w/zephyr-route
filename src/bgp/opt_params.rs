use crate::bgp::error::{BGPError, OpenMessageError};
use crate::error::ErrorType;
use crate::if_no_std;
use crate::io::{Buffer, ByteOrder, WriteRead};

if_no_std! {
    use alloc::{
        format,
        vec::Vec
    };
}

/// Optional Parameters are sent in the Open packet. These are used to transfer the information of
/// the router capabilities and more.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub enum OptionalParameter {
    /// This optional parameter transfers all capabilities like the support for BGPsec or other
    /// extensions of the BGP protocol.
    Capabilities(Vec<Capability>),
}

impl WriteRead for OptionalParameter {
    fn write(&self, buffer: &mut Buffer) -> crate::Result<()> {
        self.id().write(buffer)?;
        let temp_buffer = &mut Buffer::empty(ByteOrder::BigEndian);

        match self {
            Self::Capabilities(capabilities) => {
                for capability in capabilities {
                    capability.write(temp_buffer)?;
                }
            }
        }

        (temp_buffer.len() as u8).write(buffer)?;
        temp_buffer.write_buffer(buffer)
    }

    fn read(buffer: &mut Buffer) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let id = u8::read(buffer)?;
        let length = u8::read(buffer)?;
        let buffer = &mut Buffer::read_buffer(buffer, length as usize)?;

        match id {
            2 => {
                let mut capabilities = Vec::new();
                while buffer.remaining() > 0 {
                    capabilities.push(Capability::read(buffer)?)
                }
                Ok(Self::Capabilities(capabilities))
            }
            _ => Err(ErrorType::ReadError.err(format!(
                "Unexpected identifier {id} for optional parameter received!"
            ))),
        }
    }
}

impl OptionalParameter {
    pub fn id(&self) -> u8 {
        match self {
            Self::Capabilities(_) => 2,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub enum Capability {
    #[cfg(feature = "bgp_route_refresh")]
    RouteRefresh,
    FourOctetASNumberSupport(u64),
    #[cfg(feature = "bgp_route_refresh")]
    EnhancedRouteRefresh,
    LongLivedGracefulRestart,
    #[cfg(feature = "bgp_multiprotocol")]
    MultiProtocolExtensions(AFI, SAFI),
    Unknown(u8, Vec<u8>),
}

impl WriteRead for Capability {
    fn write(&self, buffer: &mut Buffer) -> crate::Result<()> {
        match self.id() {
            Some(value) => value.write(buffer)?,
            None => {
                if let Self::Unknown(id, _) = self {
                    return Err(ErrorType::BGPError(BGPError::open(
                        OpenMessageError::UnsupportedOptionalParameter,
                    ))
                    .err(format!("Unexpected capability with id {id} found!")));
                }
            }
        }
        let temp_buffer = &mut Buffer::empty(ByteOrder::BigEndian);
        match self {
            #[cfg(feature = "bgp_route_refresh")]
            Self::RouteRefresh => {}
            Self::FourOctetASNumberSupport(autonomous_system) => {
                autonomous_system.write(temp_buffer)?
            }
            #[cfg(feature = "bgp_route_refresh")]
            Self::EnhancedRouteRefresh => {}
            Self::LongLivedGracefulRestart => {}
            #[cfg(feature = "bgp_multiprotocol")]
            Self::MultiProtocolExtensions(afi, safi) => {
                match (*afi).into() {
                    Ok(value) => value.write(temp_buffer)?,
                    Err(value) => {
                        return Err(
                            ErrorType::ReadError.err(format!("Unexpected AFI value {value}!"))
                        )
                    }
                }
                (0_u8).write(temp_buffer)?;
                match (*safi).into() {
                    Ok(value) => value.write(temp_buffer)?,
                    Err(value) => {
                        return Err(
                            ErrorType::ReadError.err(format!("Unexpected SAFI value {value}!"))
                        )
                    }
                }
            }
            Self::Unknown(_, _) => {}
        }

        (temp_buffer.len() as u8).write(buffer)?;
        temp_buffer.write_buffer(buffer)
    }

    fn read(buffer: &mut Buffer) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let id = u8::read(buffer)?;
        let length = u8::read(buffer)?;
        let buffer = &mut Buffer::read_buffer(buffer, length as usize)?;

        match id {
            #[cfg(feature = "bgp_multiprotocol")]
            1 => {
                let afi = u16::read(buffer)?;
                u8::read(buffer)?;
                let safi = u8::read(buffer)?;
                Ok(Self::MultiProtocolExtensions(
                    AFI::from(afi),
                    SAFI::from(safi),
                ))
            }
            #[cfg(feature = "bgp_route_refresh")]
            2 => Ok(Self::RouteRefresh),
            65 => Ok(Self::FourOctetASNumberSupport(u64::read(buffer)?)),
            #[cfg(feature = "bgp_route_refresh")]
            70 => Ok(Self::EnhancedRouteRefresh),
            71 => Ok(Self::LongLivedGracefulRestart),
            _ => Ok(Self::Unknown(id, buffer.bytes.clone())),
        }
    }
}

impl Capability {
    pub fn id(&self) -> Option<u8> {
        match self {
            #[cfg(feature = "bgp_multiprotocol")]
            Self::MultiProtocolExtensions(_, _) => Some(1),
            #[cfg(feature = "bgp_route_refresh")]
            Self::RouteRefresh => Some(2),
            Self::FourOctetASNumberSupport(_) => Some(65),
            #[cfg(feature = "bgp_route_refresh")]
            Self::EnhancedRouteRefresh => Some(70),
            Self::LongLivedGracefulRestart => Some(71),
            Self::Unknown(_, _) => None,
        }
    }
}

/// This is the representation of the AFI (Address Family Indicator). This representation is used in
/// the Multi-protocol extensions of the BGP protocol. This value is sent in the Multi-protocol
/// extensions support capability to tell. the remote peer what specified address family the local
/// BGP router will transport routes for.
///
/// This allows BGP to not only carry IPv4 prefixes but IPv6 and VPN routing information.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum AFI {
    /// This is the value for IPv4 (Internet Protocol 4) addresses. This information tells your
    /// peer, that the local router is able to transport IPv4 routes.
    IPv4,

    /// This is the value for IPv6 (Internet Protocol 6) addresses. This information tells your
    /// peer, that the local router is able to transport IPv6 routes.
    IPv6,

    /// This is only the representation for a unexpected value
    Unexpected(u16),
}

impl From<u16> for AFI {
    fn from(value: u16) -> Self {
        match value {
            1 => Self::IPv4,
            2 => Self::IPv6,
            value => Self::Unexpected(value),
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<Result<u16, u16>> for AFI {
    fn into(self) -> Result<u16, u16> {
        match self {
            Self::IPv4 => Ok(1),
            Self::IPv6 => Ok(2),
            Self::Unexpected(value) => Err(value),
        }
    }
}

/// This is the representation of the SAFI (Subsequent Address Family Indicator). This representation
/// is used in the Multi-protocol extensions of the BGP protocol. This values are sent in the Multi-
/// protocol extensions support capability to tell the remote peer what specified sub address family
/// the local BGP router will transport routes for.
///
/// This allows BGP to carry Multicast and Unicast routing information.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum SAFI {
    Unicast,
    Multicast,
    LabeledUnicast,
    NG_MVPN,
    MDT,
    VPN,
    VPNMulticast,
    RouteTargetConstrain,
    FlowSpec,
    Unexpected(u8),
}

impl From<u8> for SAFI {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Unicast,
            2 => Self::Multicast,
            4 => Self::LabeledUnicast,
            5 => Self::NG_MVPN,
            66 => Self::MDT,
            128 => Self::VPN,
            129 => Self::VPNMulticast,
            132 => Self::RouteTargetConstrain,
            133 => Self::FlowSpec,
            value => Self::Unexpected(value),
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<Result<u8, u8>> for SAFI {
    fn into(self) -> Result<u8, u8> {
        match self {
            Self::Unicast => Ok(1),
            Self::Multicast => Ok(2),
            Self::LabeledUnicast => Ok(4),
            Self::NG_MVPN => Ok(5),
            Self::MDT => Ok(66),
            Self::VPN => Ok(128),
            Self::VPNMulticast => Ok(129),
            Self::RouteTargetConstrain => Ok(132),
            Self::FlowSpec => Ok(133),
            Self::Unexpected(value) => Err(value),
        }
    }
}
