use crate::bgp::error::{BGPError, ErrorCode, HeaderError, OpenMessageError};
use crate::bgp::opt_params::OptionalParameter;
use crate::error::ErrorType;
use crate::io::{Buffer, ByteOrder, WriteRead};
use crate::Result;
use crate::{if_no_std, if_std};
use crate::bgp::path_attr::Attribute;

pub mod error;
pub mod opt_params;
pub mod path_attr;

if_no_std! {
    use {
        alloc::{
            vec::Vec,
            format
        },
        core::mem
    };
}

if_std! {
    use std::{mem, io::{Write, Read}};
}

if_std! {
    use crate::if_log;
}

/// This is the representation of the fixed-size (length of 19 bytes) header, which are appended
/// before each packet sent by the BGP protocol. The layout of these fields is shown below:
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                           Marker                              +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Length               |      Type     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// ## Short explanation of fields
/// Here can you see a short list with the explanations of every field in the header. All headers a
/// explained simple. For more information, you can look at
/// [RFC4271, Section 4.1](https://www.rfc-editor.org/rfc/rfc4271#section-4.1).
///
/// - Marker: This 16-bytes field is included for compatibility. It is set to 0xF bytes by default.
/// - Length: This 2-bytes unsigned-integer field indicates the length of the BGP packet with this
/// header inclusive. The value on this field MUST always be at least 19 and no greater than 4096.
/// - Type: This 1-byte unsigned-integer field indicates the type of the packet.
/// [RFC4271](https://www.rfc-editor.org/rfc/rfc4271) defines 4 types of packets, that can be sent
/// over BGP.
///
/// ## Header Validation Checks
/// [RFC4271, Section 6.1](https://www.rfc-editor.org/rfc/rfc4271#section-6.1) defines multiple
/// cases for invalid packets that can be sent by your peer. Here you can find a short description
/// of all invalidation cases:
///
/// The validations fails
/// - if the Length field of the packet header is less than 19 bytes or greater than 4096 bytes, or
/// - if the Length field of an OPEN packet is less than the minimum of the OPEN packet, or
/// - if the Length field of an UPDATE packet is less than the minimum of the UPDATE packet, or
/// - if the Length field of a KEEPALIVE packet is not equal to 19, or
/// - if the Length field of a NOTIFICATION packet is less than the minimum length of the
/// NOTIFICATION packet, or
/// - if the Type field of the packet is not recognized.
///
/// If the length validation fails, you should send a notification packet with "Bad Message Length",
/// or the type validation fails, you should send a notification packet with "Bad Message Type".
///
/// ## Usage of the header
/// This header can only created with the information from the packet. The header can built easily,
/// by the packet, if you write the following code:
/// ```rust
/// use zephyr_route::bgp::{BGPHeader, Packet};
/// let packet = Packet::KeepAlive;
/// let header = BGPHeader::from(packet);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct BGPHeader {
    /// This is the 16-byte marker in the header. The header is only filled up with 0xF bytes. This
    /// field is only used for compatibility. If you don't want to fill up this field, you can use
    /// the `BGPHeader#by_type` as following for a keep-alive packet:
    /// ```rust
    /// use zephyr_route::bgp::{BGPHeader, PacketType};
    /// let header = BGPHeader::by_type(PacketType::KeepAlive, 19);
    /// ```
    pub marker: [u8; 16],

    /// This 2-byte unsigned-integer field indicates the length of the BGP packet with the header
    /// inclusive. This packet MUST always be at least 19 bytes and not greater than 4096 bytes.
    /// This field is automatically filled if you send the packet over the packet API.
    ///
    /// If you want to get the length of the packet, you should use the function `Packet#len` as
    /// following:
    /// ```rust
    /// use zephyr_route::bgp::Packet;
    /// let packet = Packet::KeepAlive;
    /// let length_of_packet = packet.len();
    /// ```
    pub length: u16,

    /// This 1-byte field indicates the type of the packet. All type of the packets are defined in
    /// `PacketType`. This field is automatically filled with the information, if you use the
    /// methods as following:
    /// ```rust
    /// use zephyr_route::bgp::{BGPHeader, Packet, PacketType};
    /// let packet = Packet::KeepAlive;
    /// let header = BGPHeader::by_type(PacketType::from(&packet), packet.len().unwrap() as u16);
    /// ```
    pub ty: PacketType,
}

impl WriteRead for BGPHeader {
    fn write(&self, buffer: &mut Buffer) -> Result<()> {
        buffer.write_bytes_array(self.marker);
        self.length.write(buffer)?;
        (self.ty as u8).write(buffer)
    }

    fn read(buffer: &mut Buffer) -> Result<Self>
    where
        Self: Sized,
    {
        let marker = buffer.read_bytes_array()?;
        let length = u16::read(buffer)?;
        let ty = u8::read(buffer)?;

        let header = Self {
            marker,
            length,
            ty: PacketType::from(ty),
        };

        // RFC4271, Section 6.1 specified validation
        if header.length < 19 || header.length > 4096 {
            return Err(ErrorType::BGPError(BGPError::header_error(HeaderError::BadMessageLength))
                .err(format!("Unexpected length of packet! Packet is {} bytes long but expected greater than 19 and lower than 4096", header.length)));
        }

        if header.ty == PacketType::KeepAlive && header.length != 19 {
            return Err(ErrorType::BGPError(BGPError::header_error(HeaderError::BadMessageLength))
                .err(format!("Unexpected length of packet! Packet is {} bytes long but a Keep Alive packet has a size of exactly 19 bytes!", header.length)));
        }

        if header.ty == PacketType::Open && header.length < 29 {
            return Err(ErrorType::BGPError(BGPError::header_error(HeaderError::BadMessageLength))
                .err(format!("Unexpected length of packet! Packet is {} bytes long but a Open packet is not lower than 29 bytes!", header.length)));
        }

        if header.ty == PacketType::Update && header.length < 23 {
            return Err(ErrorType::BGPError(BGPError::header_error(HeaderError::BadMessageLength))
                .err(format!("Unexpected length of packet! Packet is {} bytes long but a Update packet is not lower than 23 bytes!", header.length)));
        }

        if header.ty == PacketType::Notification && header.length < 21 {
            return Err(ErrorType::BGPError(BGPError::header_error(HeaderError::BadMessageLength))
                .err(format!("Unexpected length of packet! Packet is {} bytes long but a Notification packet is not lower than 21 bytes!", header.length)));
        }

        if header.length as usize > buffer.len() {
            return Err(ErrorType::BGPError(BGPError::header_error(HeaderError::BadMessageLength))
                .err(format!("Unexpected length of packet! Header specified a length of {} bytes, but the buffer contains {} bytes!", header.length, buffer.len())));
        }

        if header.ty == PacketType::Unexpected {
            return Err(ErrorType::BGPError(BGPError::header_error(HeaderError::BadMessageType))
                .err(format!("Unexpected type of packet! The packet type is {}, but only 1 to 5 are supported!", header.length)));
        }

        if header.marker != [0xFF; 16] {
            // TODO: Check with other routers
            return Err(ErrorType::BGPError(BGPError::header_error(HeaderError::ConnectionNotSynchronized))
                .err("Unexpected marker in header of packet! Are you possibly using the protocol on a connection that does not use BGP?"));
        }

        Ok(header)
    }
}

impl Default for BGPHeader {
    fn default() -> Self {
        Self {
            ty: PacketType::KeepAlive,
            length: 19,
            marker: [0xFF; 16],
        }
    }
}

impl From<Packet> for BGPHeader {
    fn from(value: Packet) -> Self {
        let len = value.len().unwrap();
        BGPHeader::by_type(PacketType::from(&value), len as u16)
    }
}

impl BGPHeader {
    /// This method creates a new header with the marker only with 0xF bytes. You have to specify
    /// the length of the packet and the type of the packet. Here is an example if you try to create
    /// the header for a KeepAlive packet with 19 bytes:
    /// ```rust
    /// use zephyr_route::bgp::{BGPHeader, PacketType};
    /// let header = BGPHeader::by_type(PacketType::KeepAlive, 19);
    /// ```
    ///
    /// **Time Complexity O(1)**
    pub fn by_type(ty: PacketType, length: u16) -> Self {
        Self {
            marker: [0xFF; 16],
            length,
            ty,
        }
    }

    /// This method creates a raw header with all data specified by the caller. As example a header
    /// filled with 0xA bytes, a packet length of 19 bytes and the KeepAlive type for the packet.
    /// Here is an example if you try to create the header for a KeepAlive packet:
    /// ```rust
    /// use zephyr_route::bgp::{BGPHeader, PacketType};
    /// let header = BGPHeader::new(PacketType::KeepAlive, 19, [0xA; 16]);
    /// ```
    ///
    /// **Time Complexity O(1)**
    pub fn new(ty: PacketType, length: u16, marker: [u8; 16]) -> Self {
        Self { ty, length, marker }
    }
}

/// This is a enum representation of all types that are implemented in Zephyr Route for the BGP
/// protocol. All defined packet types we implemented, were defined in
/// [RFC4271](https://www.rfc-editor.org/rfc/rfc4271)
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum PacketType {
    Open = 1,
    Update = 2,
    Notification = 3,
    KeepAlive = 4,
    #[cfg(feature = "bgp_route_refresh")]
    RouteRefresh = 5,
    Unexpected = 255,
}

impl From<&Packet> for PacketType {
    fn from(value: &Packet) -> Self {
        match value {
            Packet::Open(_, _, _, _, _) => PacketType::Open,
            Packet::Update(_, _, _) => PacketType::Update,
            Packet::Notification(_, _, _) => PacketType::Notification,
            Packet::KeepAlive => PacketType::KeepAlive,
            #[cfg(feature = "bgp_route_refresh")]
            Packet::RouteRefresh => PacketType::RouteRefresh,
        }
    }
}

impl From<u8> for PacketType {
    fn from(value: u8) -> Self {
        if !(1..=5).contains(&value) {
            return Self::Unexpected;
        }

        unsafe { mem::transmute(value) }
    }
}

/// This is the representation of a packet that is defined for the BGP protocol. This is the central
/// object to write and read BGP packets. You should use this library direct to parse all packets or
/// send the packets over a TcpStream.
///
/// Our library implements all packets from the following list of RFCs:
/// - [RFC4271](https://www.rfc-editor.org/rfc/rfc4271) - Basic definition of the BGP 4 protocol
/// - [RFC2918](https://www.rfc-editor.org/rfc/rfc2918) - Definition of the Route Refresh Capability
///
/// ## Send and parse packets
/// The packet representation provides multiple methods to parse and send packets, if you activated
/// the `std`-feature. You can use the send method if you want to send a message to the peer. Here
/// can you view an example of this, with a KeepAlive packet:
/// ```rust
/// use std::net::TcpStream;
/// use zephyr_route::bgp::Packet;
/// let mut stream = unsafe { std::ptr::null() as TcpStream };  // The null pointer is only here, because I don't have a stream in this example.
/// let packet = Packet::KeepAlive;
/// packet.send("socket", &mut stream).unwrap();
/// ```
///
/// Or if you want to receive a packet from the peer. You need a `stream` and your packet. In the
/// following example, you can see, how to receive a packet:
/// ```rust
/// use std::net::TcpStream;
/// use zephyr_route::bgp::Packet;
/// let mut stream = unsafe { std::ptr::null() as TcpStream }; // The null pointer is only here, because I don't have a stream in this example.
/// let packet = Packet::receive("socket", &mut stream).unwrap();
/// ```
///
/// ## Type of packets
/// Here is a short listing with all packets with it's definitions inclusive.
/// - Open: The open packet is the initial packet after the establishment of a TCP connection to
/// your peer. Both sides sends one Open packets and responds after a successful validation with a
/// keep alive packet to establish the BGP session.
/// - Update: The update packet is the packet to transfer the routing information between the peers
/// but in other RFCs, this packet has the ability to do more. **Add other abilities to explanation**
/// - Notification: If on one side a error occurs, the side sends you a notification packet with the
/// error information and closes the connection.
/// - Keep Alive: BGP doesn't use the TCP-implemented mechanism of Keep Alive, but BGP needs to get
/// sure the connection to your peer is still open. Both sides sends in the range of the hold time,
/// that was sent with the open packet, a keep alive packet or the other side closes the connection.
/// - Route Refresh: With [RFC2918](https://www.rfc-editor.org/rfc/rfc2918), BGP got the ability to
/// send the newest information to a specified route. If your peer is able to use the Route Refresh
/// packet you should see in the Open packet, that the Route Refresh capability is set.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub enum Packet {
    /// This is the representation of the [RFC4271](https://www.rfc-editor.org/rfc/rfc4271)-defined
    /// BGP Open packet with a minimal size of 29 bytes and a id of 1. The layout of the packet
    /// after the header looks like below:
    /// ```text
    /// 0                   1                   2                   3
    /// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+
    /// |    Version    |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |     My Autonomous System      |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |           Hold Time           |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                         BGP Identifier                        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// | Opt Parm Len  |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                                                               |
    /// |             Optional Parameters (variable)                    |
    /// |                                                               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    ///
    /// ## Short explanation of fields
    /// - Version: This 8-byte unsigned integer field indicates the version of BGP.
    /// - My Autonomous System: This 16-byte unsigned integer field indicates the autonomous system
    /// number (ASN) of the sender-router.
    /// - Hold Time: This 16-byte unsigned integer field indicates the time in seconds, that the
    /// sender proposes of the hold timer. The value of this field must be 0 or at least 3.
    /// - BGP Identifier: This 64-byte unsigned integer field indicates the identifier of the sender-
    /// router. This value should be the same on every local interface.
    /// - Opt. Param length: This 8-byte unsigned integer field indicates the length of the optional
    /// parameters field.
    /// - Optional Parameters: This variable-byte field contains all optional parameters of the Open
    /// packet like the capabilities of the router.
    ///
    /// ## Establishment of a BGP connection
    /// Both peers send a BGP open packet to the other peer. If the other peer accepts this open
    /// packet, the peer sends a BGP keep-alive packet to your router and the same routine for your
    /// own router.
    Open(u8, u16, u16, u32, Vec<OptionalParameter>),

    /// This is the representation of the [RFC4271](https://www.rfc-editor.org/rfc/rfc4271)-defined
    /// BGP Update packet with a minimal size of 23 bytes and a id of 2. The layout of the packet
    /// after the header looks like below:
    /// ```test
    /// 0                   1                   2                   3
    /// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |    Withdrawn Routes Length    |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                   Withdrawn Routes (variable)                 |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |     Path Attribute Length     |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                      Attributes (variable)                    |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |        Network Layer Reachability Information (variable)      |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    ///
    /// ## Short explanation of fields
    /// - Withdrawn Routes Length: This 2-byte unsigned integer field defines the length of the
    /// withdrawn-routes field.
    /// - Withdrawn Routes: This variable-byte field contains a list of prefixes, that are withdrawn
    /// by the router.
    /// - Path Attribute Length: This 2-byte unsigned integer field defines the length of the
    /// attributes field.
    /// - Attributes: This variable-byte field contains a list of attributes for the Open packet,
    /// which defines a bunch of information for the router.
    /// - Network Layer Reachability Information (NLRI): This variable-byte field contains a list
    /// of prefixes, which are now known by the router.
    ///
    /// ## Meaning of the packet
    /// This packet is there for the actual task of BGP, for transferring routes between two peers.
    /// This packet is therefore usually the most sent packet in a BGP connection.
    Update(Vec<RoutePrefix>, Vec<RoutePrefix>, Vec<Attribute>),

    /// This is the representation of the [RFC4271](https://www.rfc-editor.org/rfc/rfc4271)-defined
    /// BGP Notification packet with a minimal size of 23 bytes and a id of 3. The layout of the
    /// packet after the header looks like below:
    /// ```test
    /// 0                   1                   2                   3
    /// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// | Error code    | Error subcode |   Data (variable)             |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    ///
    /// ## Short explanation of fields
    /// - Error Code: This 1-byte unsigned integer field indicates the error code. (Category of error)
    /// - Error Sub-code: This 1-byte unsigned integer field indicates the error subcode.
    /// - Data: This variable-byte field indicates specific data for the error for the transfer of
    /// more information about the error.
    ///
    /// ## Actions when sending of the packet
    /// After the sending of this packet, the sender closes normally the connection between the two
    /// peers.
    Notification(ErrorCode, u8, Vec<u8>),

    /// This is the representation of the [RFC4271](https://www.rfc-editor.org/rfc/rfc4271)-defined
    /// BGP Notification packet with a size of 19 bytes and a id of 4. I can't show the
    /// layout of the packet after the header, because this packet contains no data.
    ///
    /// This packet is a replacement of the TCP Keep-Alive system. If a peer doesn't receive a TCP
    /// packet in the specified Hold Timer, the peer closes the continuation, because the peer
    /// thinks that the connection is closed.
    KeepAlive,
    #[cfg(feature = "bgp_route_refresh")]
    RouteRefresh,
}

impl WriteRead for Packet {
    fn write(&self, buffer: &mut Buffer) -> Result<()> {
        let temp_buffer = &mut Buffer::empty(ByteOrder::BigEndian);

        match self {
            Self::Open(version, autonomous_system, hold_time, bgp_ident, opt_params) => {
                version.write(temp_buffer)?;
                autonomous_system.write(temp_buffer)?;
                hold_time.write(temp_buffer)?;
                bgp_ident.write(temp_buffer)?;

                let temp_buffer_params = &mut Buffer::empty(ByteOrder::BigEndian);
                for opt_param in opt_params {
                    opt_param.write(temp_buffer_params)?;
                }
                (temp_buffer_params.len() as u8).write(temp_buffer)?;
                temp_buffer_params.write_buffer(temp_buffer)?;
            }
            Self::Update(withdrawn_routes, nlri, attributes) => {
                let withdrawn_routes_buffer = &mut Buffer::empty(ByteOrder::BigEndian);
                for route in withdrawn_routes {
                    route.write(withdrawn_routes_buffer)?;
                }
                (withdrawn_routes_buffer.len() as u16).write(temp_buffer)?;
                withdrawn_routes_buffer.write_buffer(temp_buffer)?;

                let attributes_buffer = &mut Buffer::empty(ByteOrder::BigEndian);
                for attribute in attributes {
                    attribute.write(attributes_buffer)?;
                }
                (attributes_buffer.len() as u16).write(temp_buffer)?;
                attributes_buffer.write_buffer(temp_buffer)?;

                let nlri_buffer = &mut Buffer::empty(ByteOrder::BigEndian);
                for route in nlri {
                    route.write(nlri_buffer)?;
                }
                (nlri_buffer.len() as u16).write(temp_buffer)?;
                nlri_buffer.write_buffer(temp_buffer)?;
            }
            Self::KeepAlive => {}
            Self::Notification(error_code, sub_code, data) => {
                u8::from(*error_code).write(temp_buffer)?;
                sub_code.write(temp_buffer)?;
                temp_buffer.write_bytes_vector(data);
            }
            #[cfg(feature = "bgp_route_refresh")]
            Self::RouteRefresh => {}
        }

        let header = BGPHeader::by_type(PacketType::from(self), (temp_buffer.len() as u16) + 19);
        header.write(buffer)?;
        temp_buffer.write_buffer(buffer)?;
        Ok(())
    }

    fn read(buffer: &mut Buffer) -> Result<Self>
    where
        Self: Sized,
    {
        let header = BGPHeader::read(buffer)?;
        let buffer = &mut Buffer::read_buffer(buffer, (header.length as usize) - 19)?;

        match header.ty {
            PacketType::Open => {
                let version = u8::read(buffer)?;
                let autonomous_system = u16::read(buffer)?;
                let hold_time = u16::read(buffer)?;
                let bgp_ident = u32::read(buffer)?;
                u8::read(buffer)?;

                let mut opt_params = Vec::new();
                while buffer.remaining() > 0 {
                    opt_params.push(OptionalParameter::read(buffer)?);
                }

                if hold_time != 0 && hold_time < 3 {
                    return Err(ErrorType::BGPError(BGPError::open(OpenMessageError::UnacceptableHoldTime))
                        .err(format!("Unacceptable hold time! Expected 0 or greater than 3, but got {hold_time}")))
                }

                Ok(Packet::Open(
                    version,
                    autonomous_system,
                    hold_time,
                    bgp_ident,
                    opt_params,
                ))
            }
            PacketType::Update => {
                let length = u16::read(buffer)?;
                let withdrawn_routes_buffer = &mut Buffer::read_buffer(buffer, length as usize)?;
                let mut withdrawn_routes = Vec::new();
                while withdrawn_routes_buffer.remaining() > 0 {
                    withdrawn_routes.push(RoutePrefix::read(withdrawn_routes_buffer)?);
                }

                let length = u16::read(buffer)?;
                let attributes_buffer = &mut Buffer::read_buffer(buffer, length as usize)?;
                let mut attributes = Vec::new();
                while attributes_buffer.remaining() > 0 {
                    attributes.push(Attribute::read(attributes_buffer)?);
                }

                let length = u16::read(buffer)?;
                let nlri_buffer = &mut Buffer::read_buffer(buffer, length as usize)?;
                let mut nlri = Vec::new();
                while nlri_buffer.remaining() > 0 {
                    nlri.push(RoutePrefix::read(nlri_buffer)?);
                }

                Ok(Packet::Update(withdrawn_routes, nlri, attributes))
            },
            PacketType::Notification => {
                let error_code = u8::read(buffer)?;
                let sub_code = u8::read(buffer)?;
                let buffer = Buffer::read_buffer(buffer, (header.length - 21) as usize)?;
                Ok(Packet::Notification(
                    ErrorCode::from(error_code),
                    sub_code,
                    buffer.bytes,
                ))
            }
            PacketType::KeepAlive => Ok(Packet::KeepAlive),
            #[cfg(feature = "bgp_route_refresh")]
            PacketType::RouteRefresh => Ok(Packet::RouteRefresh),
            PacketType::Unexpected => {
                Err(ErrorType::ReadError.err("Unable to parse unexpected packet!"))
            }
        }
    }
}

impl Packet {
    /// TODO: Do description
    #[cfg(feature = "std")]
    pub fn receive(edge: impl Into<String>, stream: &mut impl Read) -> Result<Option<Vec<Packet>>> {
        // Read from peer
        let mut received = [0; 4096];
        let length = stream
            .read(&mut received)
            .map_err(|err| ErrorType::ReadError.err(err.to_string()))?;
        if length == 0 {
            return Ok(None);
        }

        if_log! {
            log::debug!("Read {} bytes from {}", length, edge.into())
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&received[..length]);
        let buffer = &mut Buffer::from_vec(bytes, ByteOrder::BigEndian);
        let mut packets = Vec::new();
        while buffer.remaining() >= 19 { // 19 is the minimal length of an BGP packet
            packets.push(Self::read(buffer)?);
        }

        if buffer.remaining() > 0 {
            return Err(ErrorType::ReadError.err(format!("{} bytes remaining after read!", buffer.remaining())));
        }

        Ok(Some(packets))
    }

    /// TODO: Do description
    #[cfg(feature = "std")]
    pub fn send(edge: impl Into<String>, stream: &mut impl Write, packets: Vec<Self>) -> Result<()> {
        let buffer = &mut Buffer::empty(ByteOrder::BigEndian);

        for packet in packets {
            packet.write(buffer).map_err(|err| ErrorType::WriteError.err(err.to_string()))?;
        }

        stream
            .write_all(buffer.bytes.as_slice())
            .map_err(|err| ErrorType::WriteError.err(err.to_string()))?;
        stream
            .flush()
            .map_err(|err| ErrorType::WriteError.err(err.to_string()))?;

        if_log! {
            log::debug!("Written bytes to {}", edge.into())
        }
        Ok(())
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> Result<usize> {
        let buffer = &mut Buffer::empty(ByteOrder::BigEndian);
        self.write(buffer)?;
        Ok(buffer.len())
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub enum RoutePrefix {
    IPv4(u8, Vec<u8>),
}

impl WriteRead for RoutePrefix {
    fn write(&self, buffer: &mut Buffer) -> Result<()> {
        match self {
            Self::IPv4(prefix_length, prefix) => {
                prefix_length.write(buffer)?;
                buffer.write_bytes_vector(prefix);
            }
        }
        Ok(())
    }

    fn read(buffer: &mut Buffer) -> Result<Self>
    where
        Self: Sized,
    {
        let prefix_length = u8::read(buffer)?;
        Ok(Self::IPv4(
            prefix_length,
            buffer.read_bytes_vector((prefix_length as usize + 7) / 8)?,
        ))
    }
}
