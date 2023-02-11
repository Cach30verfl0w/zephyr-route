use bitflags::bitflags;
use crate::error::ErrorType;
use crate::{if_no_std, if_std};
use crate::io::{Buffer, ByteOrder, WriteRead};
use crate::Result;

#[cfg(feature = "bgp_multiprotocol")]
use crate::bgp::opt_params::{AFI, SAFI};

if_no_std! {
    use {
        core::mem,
        alloc::{
            format,
            vec::Vec
        }
    };
}

if_std! {
    use std::mem;
}

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct Attribute {
    ty: AttributeType,
    flags: AttributeFlags,
    value: AttributeValue
}

impl WriteRead for Attribute {
    fn write(&self, buffer: &mut Buffer) -> Result<()> {
        self.flags.bits().write(buffer)?;
        (self.ty as u8).write(buffer)?;

        let temp_buffer = &mut Buffer::empty(ByteOrder::BigEndian);
        match &self.value {
            AttributeValue::Origin(origin) => (*origin as u8).write(temp_buffer)?,
            AttributeValue::ASPath(path) => path.write(temp_buffer)?,
            AttributeValue::NextHop(next_hop) => temp_buffer.write_bytes_vector(next_hop),
            AttributeValue::Communities(communities) => {
                for community in communities {
                    community.write(temp_buffer)?;
                }
            },
            AttributeValue::LargeCommunities(communities) => {
                for community in communities {
                    community.write(temp_buffer)?;
                }
            },
            #[cfg(feature = "bgp_multiprotocol")]
            AttributeValue::MPReachableNLRI(afi, safi, next_hop, nlri) => {
                match (*afi).into() {
                    Ok(value) => value.write(temp_buffer)?,
                    Err(value) => return Err(
                        ErrorType::ReadError.err(format!("Unexpected AFI value {value}!"))
                    )
                }

                match (*safi).into() {
                    Ok(value) => value.write(temp_buffer)?,
                    Err(value) => return Err(
                        ErrorType::ReadError.err(format!("Unexpected SAFI value {value}!"))
                    )
                }

                (next_hop.len() as u8).write(temp_buffer)?;
                temp_buffer.write_bytes_vector(next_hop);
                (0_u8).write(temp_buffer)?;
                temp_buffer.write_bytes_vector(nlri);
            },
            #[cfg(feature = "bgp_multiprotocol")]
            AttributeValue::MPUnreachableNLRI(afi, safi, withdrawn_routes) => {
                match (*afi).into() {
                    Ok(value) => value.write(temp_buffer)?,
                    Err(value) => return Err(
                        ErrorType::ReadError.err(format!("Unexpected AFI value {value}!"))
                    )
                }

                match (*safi).into() {
                    Ok(value) => value.write(temp_buffer)?,
                    Err(value) => return Err(
                        ErrorType::ReadError.err(format!("Unexpected SAFI value {value}!"))
                    )
                }

                temp_buffer.write_bytes_vector(withdrawn_routes);
            }
        }

        (temp_buffer.len() as u8).write(buffer)?;
        temp_buffer.write_buffer(buffer)
    }

    fn read(buffer: &mut Buffer) -> Result<Self> where Self: Sized {
        let flags = AttributeFlags::from_bits(u8::read(buffer)?).unwrap();
        let ty = AttributeType::from(u8::read(buffer)?)?;

        let length = u8::read(buffer)?;
        let temp_buffer = &mut Buffer::read_buffer(buffer, length as usize)?;
        let value = match ty {
            AttributeType::Origin => AttributeValue::Origin(Origin::from(u8::read(temp_buffer)?)?),
            AttributeType::ASPath => AttributeValue::ASPath(ASPathSegment::read(temp_buffer)?),
            AttributeType::NextHop => AttributeValue::NextHop(temp_buffer.read_bytes_vector(temp_buffer.len())?),
            AttributeType::Community => {
                let mut communities = Vec::new();
                while temp_buffer.remaining() > 0 {
                    communities.push(Community::read(temp_buffer)?);
                }
                AttributeValue::Communities(communities)
            },
            AttributeType::LargeCommunity => {
                let mut communities = Vec::new();
                while temp_buffer.remaining() > 0 {
                    communities.push(LargeCommunity::read(temp_buffer)?);
                }
                AttributeValue::LargeCommunities(communities)
            },
            #[cfg(feature = "bgp_multiprotocol")]
            AttributeType::MPReachableNLRI => {

                let afi = AFI::from(u16::read(buffer)?);
                let safi = SAFI::from(u8::read(buffer)?);
                let next_hop_length = u8::read(buffer)?;
                let next_hop = Buffer::read_buffer(buffer, next_hop_length as usize)?.bytes;
                u8::read(buffer)?;
                let nlri = temp_buffer.bytes.clone();

                AttributeValue::MPReachableNLRI(
                    afi,
                    safi,
                    next_hop,
                    nlri
                )
            },
            #[cfg(feature = "bgp_multiprotocol")]
            AttributeType::MPUnreachableNLRI => {
                AttributeValue::MPUnreachableNLRI(
                    AFI::from(u16::read(buffer)?),
                    SAFI::from(u8::read(buffer)?),
                    temp_buffer.bytes.clone()
                )
            }
            _ => return Err(ErrorType::ReadError.err("Unexpected type! Expected implemented type but got /value/"))
        };

        Ok(Self {
            flags,
            ty,
            value
        })
    }
}

impl Attribute {

    pub fn new(ty: AttributeType, flags: AttributeFlags, value: AttributeValue) -> Self {
        Self {
            ty,
            flags,
            value
        }
    }

}

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub enum AttributeValue {
    Origin(Origin),
    ASPath(ASPathSegment),
    NextHop(Vec<u8>),
    Communities(Vec<Community>),
    LargeCommunities(Vec<LargeCommunity>),
    #[cfg(feature = "bgp_multiprotocol")]
    MPReachableNLRI(AFI, SAFI, Vec<u8>, Vec<u8>),
    #[cfg(feature = "bgp_multiprotocol")]
    MPUnreachableNLRI(AFI, SAFI, Vec<u8>)
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Origin {
    IGP = 0,
    EGP = 1,
    Incomplete = 2
}

impl Origin {

    pub fn from(value: u8) -> Result<Self> {
        if !(0..=2).contains(&value) {
            return Err(ErrorType::OtherError.err("Unable to parse "))
        }

        Ok(unsafe { mem::transmute(value) })
    }

}

bitflags! {
    #[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
    pub struct AttributeFlags: u8 {
        const OPTIONAL        = 0b10000000;
        const TRANSITIVE      = 0b01000000;
        const PARTIAL         = 0b00100000;
        const EXTENDED_LENGTH = 0b00010000;
        const NONE            = 0b00000000;
    }
}

// TODO: Add Unknown(u8) union and reconstruct the enum
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum AttributeType {
    Reserved                              = 0,
    Origin                                = 1,
    ASPath                                = 2,
    NextHop                               = 3,
    MultiExitDisc                         = 4,
    LocalPref                             = 5,
    AtomicAggregate                       = 6,
    Aggregator                            = 7,
    Community                             = 8,
    OriginatorId                          = 9,
    ClusterList                           = 10,
    #[cfg(feature = "bgp_multiprotocol")]
    MPReachableNLRI                       = 14,
    #[cfg(feature = "bgp_multiprotocol")]
    MPUnreachableNLRI                     = 15,
    ExtendedCommunities                   = 16,
    AS4Path                               = 17,
    AS4Aggregator                         = 18,
    PMSITunnel                            = 22,
    TunnelEncapsulation                   = 23,
    TrafficEngineering                    = 24,
    Ipv6AddressSpecifiedExtendedCommunity = 25,
    AIGP                                  = 26,
    PEDistinguisherLabels                 = 27,
    BGPLSAttribute                        = 29,
    LargeCommunity                        = 32,
    BGPSecPath                            = 33,
    OnlyToCustomer                        = 35,
    BGPDomainPath                         = 36,
    SFPAttribute                          = 37,
    BFDDiscriminator                      = 38,
    BGPRouterCapabilities                 = 39,
    BGPPrefixSID                          = 40,
    AttributeSet                          = 128,
    ReservedForDevelopment                = 255
}

impl AttributeType {

    pub fn from(value: u8) -> Result<Self> {
        // TODO: + Add validation / This isn't production ready

        Ok(unsafe { mem::transmute(value) })
    }

}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct Community {
    community_as: u32,
    community_value: u16
}

impl WriteRead for Community {
    fn write(&self, buffer: &mut Buffer) -> Result<()> {
        self.community_as.write(buffer)?;
        self.community_value.write(buffer)
    }

    fn read(buffer: &mut Buffer) -> Result<Self> where Self: Sized {
        Ok(Self {
            community_as: u32::read(buffer)?,
            community_value: u16::read(buffer)?
        })
    }
}

impl Community {

    pub fn new(community_as: u32, value: u16) -> Self {
        Self {
            community_as,
            community_value: value
        }
    }

}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct LargeCommunity {
    global_administrator: u64,
    local_data_part_1: u64,
    local_data_part_2: u64
}

impl WriteRead for LargeCommunity {
    fn write(&self, buffer: &mut Buffer) -> Result<()> {
        self.global_administrator.write(buffer)?;
        self.local_data_part_1.write(buffer)?;
        self.local_data_part_2.write(buffer)
    }

    fn read(buffer: &mut Buffer) -> Result<Self> where Self: Sized {
        Ok(Self {
            global_administrator: u64::read(buffer)?,
            local_data_part_1: u64::read(buffer)?,
            local_data_part_2: u64::read(buffer)?
        })
    }
}

impl LargeCommunity {

    pub fn new(global_administrator: u64, local_data_part_1: u64, local_data_part_2: u64) -> Self {
        Self {
            global_administrator,
            local_data_part_1,
            local_data_part_2
        }
    }

}

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub enum ASPathSegment {
    ASSequence(Vec<u32>),
    Unknown(u8)
}

impl WriteRead for ASPathSegment {
    fn write(&self, buffer: &mut Buffer) -> Result<()> {
        u8::from(self).write(buffer)?;
        match self {
            Self::ASSequence(values) => {
                (values.len() as u8).write(buffer)?;
                for value in values {
                    value.write(buffer)?;
                }
                Ok(())
            },
            Self::Unknown(ty) => Err(ErrorType::WriteError.err(format!("Unexpected AS Path segment type detected! Got {ty}!")))
        }
    }

    fn read(buffer: &mut Buffer) -> Result<Self> where Self: Sized {
        let id = u8::read(buffer)?;
        Ok(match id {
            2 => {
                let length = u8::read(buffer)?;
                let mut values = Vec::new();
                for _ in 0..length {
                    values.push(u32::read(buffer)?);
                }
                Self::ASSequence(values)
            },
            value => Self::Unknown(value)
        })
    }
}

impl From<&ASPathSegment> for u8 {
    fn from(value: &ASPathSegment) -> Self {
        match value {
            ASPathSegment::ASSequence(_) => 2,
            ASPathSegment::Unknown(value) => *value
        }
    }
}