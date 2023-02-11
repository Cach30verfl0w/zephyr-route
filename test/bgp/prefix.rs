use crate::{bgp::RoutePrefix, if_no_std, io::{Buffer, ByteOrder, WriteRead}};

if_no_std! {
    use alloc::vec;
}

macro_rules! ipv4_prefix_test {
    ($length: expr, $prefix: expr) => {
        paste::paste! {
            #[test]
            fn [<test_ipv4_ $length>]() {
                let prefix1 = RoutePrefix::IPv4($length, $prefix);
                let buffer = &mut Buffer::empty(ByteOrder::BigEndian);
                prefix1.write(buffer).unwrap();
                buffer.reset_position();
                let prefix2 = RoutePrefix::read(buffer).unwrap();
                assert_eq!(prefix1, prefix2);
            }
        }
    };
}

// IPv4

ipv4_prefix_test!(0, vec![]);
ipv4_prefix_test!(1, vec![128]);
ipv4_prefix_test!(2, vec![192]);
ipv4_prefix_test!(3, vec![224]);
ipv4_prefix_test!(4, vec![240]);
ipv4_prefix_test!(5, vec![248]);
ipv4_prefix_test!(6, vec![252]);
ipv4_prefix_test!(7, vec![254]);

// Class A
ipv4_prefix_test!(8, vec![255]);
ipv4_prefix_test!(9, vec![255, 128]);
ipv4_prefix_test!(10, vec![255, 192]);
ipv4_prefix_test!(11, vec![255, 224]);
ipv4_prefix_test!(12, vec![255, 240]);
ipv4_prefix_test!(13, vec![255, 248]);
ipv4_prefix_test!(14, vec![255, 252]);
ipv4_prefix_test!(15, vec![255, 254]);

// Class B
ipv4_prefix_test!(16, vec![255, 255]);
ipv4_prefix_test!(17, vec![255, 255, 128]);
ipv4_prefix_test!(18, vec![255, 255, 192]);
ipv4_prefix_test!(19, vec![255, 255, 224]);
ipv4_prefix_test!(20, vec![255, 255, 240]);
ipv4_prefix_test!(21, vec![255, 255, 248]);
ipv4_prefix_test!(22, vec![255, 255, 252]);
ipv4_prefix_test!(23, vec![255, 255, 254]);

// Class C
ipv4_prefix_test!(24, vec![255, 255, 255]);
ipv4_prefix_test!(25, vec![255, 255, 255, 128]);
ipv4_prefix_test!(26, vec![255, 255, 255, 192]);
ipv4_prefix_test!(27, vec![255, 255, 255, 224]);
ipv4_prefix_test!(28, vec![255, 255, 255, 240]);
ipv4_prefix_test!(29, vec![255, 255, 255, 248]);
ipv4_prefix_test!(30, vec![255, 255, 255, 252]);
ipv4_prefix_test!(31, vec![255, 255, 255, 254]);
ipv4_prefix_test!(32, vec![255, 255, 255, 255]);
