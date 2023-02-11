use crate::bgp::error::ErrorCode;
use crate::bgp::opt_params::{Capability, OptionalParameter};
use crate::bgp::{BGPHeader, Packet, RoutePrefix};
use crate::io::{Buffer, ByteOrder, WriteRead};
use crate::{buffer_test, if_no_std};
use crate::bgp::path_attr::{Attribute, AttributeFlags, AttributeType, AttributeValue, Community, Origin};

pub mod prefix;

if_no_std! {
    use alloc::{vec, vec::Vec};
}

buffer_test!(BGPHeader);

#[test]
fn test_open_packet() {
    let buffer = &mut Buffer::empty(ByteOrder::BigEndian);
    let packet = Packet::Open(
        4,
        64600,
        240,
        127127127,
        vec![OptionalParameter::Capabilities(vec![
            Capability::FourOctetASNumberSupport(11111111),
            Capability::LongLivedGracefulRestart,
            #[cfg(feature = "bgp_route_refresh")]
            Capability::EnhancedRouteRefresh,
        ])],
    );
    packet.write(buffer).unwrap();
    buffer.reset_position();
    let packet_read = Packet::read(buffer).unwrap();
    assert_eq!(packet, packet_read);
}

#[test]
fn test_notification_packet() {
    let buffer = &mut Buffer::empty(ByteOrder::BigEndian);
    let packet = Packet::Notification(ErrorCode::MessageHeader, 1, Vec::new());
    packet.write(buffer).unwrap();
    buffer.reset_position();
    let packet_read = Packet::read(buffer).unwrap();
    assert_eq!(packet, packet_read);
}

#[test]
fn test_update_packet() {
    let buffer = &mut Buffer::empty(ByteOrder::BigEndian);
    let packet = Packet::Update(vec![
        RoutePrefix::IPv4(16, vec![255, 255])
    ], vec![
        RoutePrefix::IPv4(8, vec![255])
    ], vec![
        Attribute::new(AttributeType::Origin, AttributeFlags::NONE, AttributeValue::Origin(Origin::IGP)),
        Attribute::new(AttributeType::NextHop, AttributeFlags::OPTIONAL, AttributeValue::NextHop(vec![127, 168, 0, 1])),
        Attribute::new(AttributeType::Community, AttributeFlags::OPTIONAL, AttributeValue::Communities(vec![
            Community::new(127127127, 1),
            Community::new(127127128, 2)
        ]))
    ]);
    packet.write(buffer).unwrap();
    buffer.reset_position();
    let packet_read = Packet::read(buffer).unwrap();
    assert_eq!(packet, packet_read);
}

#[test]
fn test_keep_alive_packet() {
    let buffer = &mut Buffer::empty(ByteOrder::BigEndian);
    let packet = Packet::KeepAlive;
    packet.write(buffer).unwrap();
    buffer.reset_position();
    let packet_read = Packet::read(buffer).unwrap();
    assert_eq!(packet, packet_read);
}

#[cfg(feature = "std")]
#[test]
fn test_multiple_packets() {
    let packets = vec![
        Packet::Update(vec![RoutePrefix::IPv4(15, vec![255, 255])], Vec::new(), Vec::new()),
        Packet::Update(vec![RoutePrefix::IPv4(8, vec![255])], Vec::new(), Vec::new()),
    ];
    let buffer = &mut Buffer::system_order();
    Packet::send("buffer", buffer, packets.clone()).unwrap();
    buffer.reset_position();
    let packets_recv = Packet::receive("buffer", buffer).unwrap().unwrap();
    assert_eq!(packets, packets_recv);
}