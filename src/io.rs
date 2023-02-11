use crate::error::ErrorType;
use crate::error::ErrorType::ReadError;
use crate::{if_no_std, if_std};
use crate::Result;

if_no_std! {
    use {
        alloc::{
            format,
            vec::Vec,
            vec
        }
    };
}

if_std! {
    use std::io::{Write, Read};
}

/// This is a simple representation of the byte order. The byte order defines the memory organisation
/// of simple numeric values. The following two byte orders exist:
/// - Big Endian: The most significant byte is stored first at the smallest memory address.
/// - Little Endian: The smallest byte is stored at the beginning of the memory address.
///
/// We use this simply for the Buffer for the order of the stored data. As example the BGP protocol
/// reads the bytes in Big Order.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum ByteOrder {
    /// This is the Big Endian byte order. This order stores the most significant byte in the first
    /// part of the memory address.
    BigEndian,

    /// This is the Little Endian byte order. This order stores the most smallest byte in the first
    /// part of the memory address.
    LittleEndian,
}

impl ByteOrder {
    /// This function returns the byte order used for the compiled system. This is used for several
    /// tests but I don't really know, why I implemented this function.
    ///
    /// **Time Complexity: O(1)**
    #[inline]
    pub fn system_order() -> ByteOrder {
        if cfg!(target_endian = "big") {
            Self::BigEndian
        } else {
            Self::LittleEndian
        }
    }
}

pub trait WriteRead {
    fn write(&self, buffer: &mut Buffer) -> Result<()>;
    fn read(buffer: &mut Buffer) -> Result<Self>
    where
        Self: Sized;

    fn peek(buffer: &mut Buffer) -> Result<Self> where Self: Sized {
        let position = buffer.position;
        let read = Self::read(buffer);
        buffer.position = buffer.position - (buffer.position - position);
        read
    }
}

/// This buffer is used to store bytes in one array and provides the functionality to store different
/// variables in the specified order. This buffer also provides the functionality to read the
/// information. This is simply used to write und read BGP packets from a byte array.
///
/// ## Short explanation of fields
/// This struct
/// provides 3 fields but only 1 field is accessible:
/// - Bytes (accessible): This field stores all data in a u8 vector and is the central storing unit
/// for all information of the buffer.
/// - Position (inaccessible): This field stores the current position of the buffer while the reading
/// and writing.
/// - Order (inaccessible): This field stores the specified order for reading and writing from the
/// buffer.
///
/// ## Usage of Buffer
/// The following code creates a buffer with the system order and stores 2 u16 in the array, then read
/// them and validate the data:
/// ```rust
/// use zephyr_route::io::{Buffer, ByteOrder, WriteRead};
/// let buffer = &mut Buffer::empty(ByteOrder::system_order());
/// 1_u16.write(buffer).unwrap();
/// 2_u16.write(buffer).unwrap();
///
/// let (first, second) = (u16::read(buffer), u16::read(buffer));
/// assert_eq!(first, 1);
/// assert_eq!(second, 2);
/// ```
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct Buffer {
    pub bytes: Vec<u8>,
    position: usize,
    order: ByteOrder,
}

#[cfg(feature = "std")]
impl Write for Buffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write_bytes_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "std")]
impl Read for Buffer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        for i in 0..buf.len() {
            if self.is_empty() {
                return Ok(i)
            }

            buf[i] = u8::read(self).unwrap();
        }
        Ok(buf.len())
    }
}

impl Buffer {
    /// This function creates a buffer based on the specified vector of the bytes and the specified
    /// byte order. This buffer is positioned on zero and the buffer follows the specified order.
    ///
    /// **Time Complexity O(1)**
    pub fn from_vec(bytes: Vec<u8>, order: ByteOrder) -> Self {
        Self {
            bytes,
            position: 0,
            order,
        }
    }

    /// This function creates a buffer filled with nulls, based on the initial capacity of the buffer,
    /// but the buffer is positioned on zero and the buffer follows the specified order.
    ///
    /// **Time Complexity O(n)**
    pub fn capacity(capacity: usize, order: ByteOrder) -> Self {
        Self::from_vec(vec![0; capacity], order)
    }

    /// This function creates a empty buffer, based on the specified order. This buffer is positioned
    /// on zero and the buffer follows the specified order.
    ///
    /// **Time Complexity O(1)**
    pub fn empty(order: ByteOrder) -> Self {
        Self {
            bytes: Vec::new(),
            position: 0,
            order,
        }
    }

    /// This function creates a empty buffer, based on the system order. This function is a
    /// simplification of:
    /// ```rust
    /// use zephyr_route::io::{Buffer, ByteOrder};
    /// let buffer = Buffer::empty(ByteOrder::system_order());
    /// ```
    ///
    /// **Time Complexity: O(1)**
    #[inline]
    pub fn system_order() -> Self {
        Self::empty(ByteOrder::system_order())
    }

    pub fn write_buffer(&self, buffer: &mut Buffer) -> Result<()> {
        buffer.write_bytes_vector(&self.bytes);
        Ok(())
    }

    pub fn read_buffer(buffer: &mut Buffer, length: usize) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Buffer::from_vec(
            buffer.read_bytes_vector(length)?,
            buffer.order,
        ))
    }

    pub fn write_bytes_array<const L: usize>(&mut self, data: [u8; L]) {
        for byte in data {
            byte.write(self).unwrap();
        }
    }

    pub fn write_bytes_slice(&mut self, data: &[u8]) {
        for byte in data {
            byte.write(self).unwrap();
        }
    }

    pub fn read_bytes_array<const L: usize>(&mut self) -> Result<[u8; L]> {
        if self.remaining() < L {
            return Err(ReadError.err(
                format!("Unable to read array of {} bytes from the {} buffer (Position: {})! After the end of the buffer {} bytes remaining.",
                        L,
                        self.bytes.len(),
                        self.position,
                        L - self.remaining()
                )
            ));
        }

        let mut array = [0; L];
        array
            .iter_mut()
            .enumerate()
            .for_each(|(_, item)| *item = u8::read(self).unwrap());
        Ok(array)
    }

    pub fn write_bytes_vector(&mut self, vector: &Vec<u8>) {
        for element in vector {
            element.write(self).unwrap();
        }
    }

    pub fn read_bytes_vector(&mut self, length: usize) -> Result<Vec<u8>> {
        if self.remaining() < length {
            return Err(ReadError.err(
                format!("Unable to read array of {} bytes from the {} buffer (Position: {})! After the end of the buffer {} bytes remaining.",
                        length,
                        self.bytes.len(),
                        self.position,
                        length - self.remaining()
                )
            ));
        }

        Ok(vec![0; length]
            .iter_mut()
            .enumerate()
            .map(|(_, _)| u8::read(self).unwrap())
            .collect())
    }

    pub fn skip(&mut self, bytes: usize) -> Result<()> {
        if self.remaining() < bytes {
            return Err(ErrorType::OtherError.err(format!("Unexpected end of buffer! Planned to skip {bytes} bytes, but only {} bytes are remaining.", self.remaining())));
        }

        self.position += bytes;
        Ok(())
    }

    pub fn reset_position(&mut self) {
        self.position = 0;
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }
}

impl WriteRead for u8 {
    fn write(&self, buffer: &mut Buffer) -> Result<()> {
        buffer.bytes.insert(buffer.position, *self);
        buffer.position += 1;
        Ok(())
    }

    fn read(buffer: &mut Buffer) -> Result<Self> {
        if buffer.is_empty() {
            return Err(ReadError
                .err("Unable to read one byte from the array! No available byte found in array!"));
        }

        buffer.position += 1;
        Ok(buffer.bytes[buffer.position - 1])
    }
}

macro_rules! write_read_number {
    ($tt: tt) => {
        impl WriteRead for $tt {
            fn write(&self, buffer: &mut Buffer) -> Result<()> {
                buffer.write_bytes_array(if buffer.order == ByteOrder::BigEndian {
                    self.to_be_bytes()
                } else {
                    self.to_le_bytes()
                });
                Ok(())
            }

            fn read(buffer: &mut Buffer) -> Result<Self> {
                Ok(if buffer.order == ByteOrder::BigEndian {
                    $tt::from_be_bytes(buffer.read_bytes_array()?)
                } else {
                    $tt::from_le_bytes(buffer.read_bytes_array()?)
                })
            }
        }
    };
}

write_read_number!(i8);
write_read_number!(u16);
write_read_number!(i16);
write_read_number!(u32);
write_read_number!(i32);
write_read_number!(u64);
write_read_number!(i64);
