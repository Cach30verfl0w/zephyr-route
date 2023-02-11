use crate::bgp::{BGPHeader, PacketType};
use crate::io::{Buffer, ByteOrder, WriteRead};

#[cfg(feature = "bgp")]
pub mod bgp;

#[macro_export]
macro_rules! buffer_test {
    ($tt: ty) => {
        paste::paste! {
            #[test]
            #[allow(non_snake_case)]
            pub fn [<test_ $tt>]() {
                let buffer = &mut Buffer::system_order();
                $tt::default().write(buffer).unwrap();
                buffer.reset_position();
                assert_eq!($tt::default(), $tt::read(buffer).unwrap());
            }
        }
    };
}

buffer_test!(u8);
buffer_test!(i8);
buffer_test!(u16);
buffer_test!(i16);
buffer_test!(u32);
buffer_test!(i32);
buffer_test!(u64);
buffer_test!(i64);

#[test]
pub fn test_peek() {
    let buffer = &mut Buffer::empty(ByteOrder::BigEndian);
    let header = BGPHeader::by_type(PacketType::KeepAlive, 19);
    header.write(buffer).unwrap();
    buffer.reset_position();
    let header_peek = BGPHeader::peek(buffer).unwrap();
    let header_read = BGPHeader::read(buffer).unwrap();
    assert_eq!(header, header_peek);
    assert_eq!(header, header_read);
}