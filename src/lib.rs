#![cfg_attr(not(feature = "std"), no_std)]

/// A simple, binary streaming format supporting dynamically sized payloads.
///
///
// TODO: Parameterize to achieve the following:
// - Magic: [const M = 1; u8].
// - CRC algorithm: Any function with the following signature `Fn(&[u8]) -> CRC type`
// - CRC type: (u8, ...)
// - Length type (n): (u16, ...)
// - Payload (n bytes above)
pub struct BitflareWriter<'a> {
    buf: &'a mut [u8],
    valid_length: Option<usize>,
}

const MAGIC: u8 = 0xFC;
// 1 byte magic + 1 byte CRC + 2 bytes payload len
const PAYLOAD_OFFSET: usize = 1 + 1 + 2;

impl<'a> BitflareWriter<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            valid_length: None,
        }
    }

    /// Invokes `f` which writes the payload into the passed array and returns the number of bytes written.
    pub fn write_payload(&mut self, f: impl FnOnce(&mut [u8]) -> usize) -> Result<(), ()> {
        let payload_length = f(&mut self.buf[PAYLOAD_OFFSET..]);

        if payload_length > self.buf.len() - PAYLOAD_OFFSET {
            return Err(());
        }
        self.valid_length = Some(PAYLOAD_OFFSET + payload_length);

        // Write payload len
        let len_bytes = u16::to_le_bytes(payload_length.try_into().map_err(|_| ())?);
        (&mut self.buf[2..4]).copy_from_slice(&len_bytes);

        // Compute CRC over length field + payload and store
        let crc_algorithm = crc::Crc::<u8>::new(&crc::CRC_8_GSM_A);

        let crc = crc_algorithm.checksum(&self.buf[2..PAYLOAD_OFFSET + payload_length]);
        (&mut self.buf[1..2]).copy_from_slice(&[crc]);

        // Write magic
        (&mut self.buf[0..1]).copy_from_slice(&[MAGIC]);

        Ok(())
    }

    pub fn finish(&self) -> &[u8] {
        match self.valid_length {
            Some(n) => &self.buf[..n],
            None => &[],
        }
    }

    pub fn finish_mut(&mut self) -> &mut [u8] {
        match self.valid_length {
            Some(n) => &mut self.buf[..n],
            None => &mut [],
        }
    }
}

//// `N` the maximum size of a message
pub struct BitflareReader<const N: usize> {
    buf: heapless::Vec<u8, N>,
}

impl<const N: usize> BitflareReader<N> {
    pub fn new() -> Self {
        Self {
            buf: Default::default(),
        }
    }

    pub fn decode(&mut self, input: &[u8], mut on_payload: impl FnMut(&[u8])) {
        let mut input = input;
        while !input.is_empty() {
            if self.buf.is_empty() {
                // Nothing buffered, just decode

                let Some(magic_offset) = memchr::memchr(MAGIC, input) else {
                    break;
                };
                let (_, maybe_payload) = input.split_at(magic_offset);
                match Self::try_decode_payload(maybe_payload) {
                    Ok((payload, rest)) => {
                        on_payload(payload);
                        input = rest
                    }
                    Err(e) => match e {
                        TryDecodeError::InvalidMagic => {
                            // Nothing buffered to work with. Throw away and try again from next byte
                            input = &input[1..];
                        }
                        TryDecodeError::CrcMismatch { packet_size } => {
                            let (_old, rest) = input.split_at(packet_size);
                            input = rest;
                        }
                        TryDecodeError::PayloadTooBig => {
                            // Payload too big (header field) skip to next packet
                            break;
                        }
                        TryDecodeError::TruncatedPayload | TryDecodeError::TruncatedHeader => {
                            // Start of packet was okay
                            // Buffer packet for later when we receive the rest of it
                            if self.buf.extend_from_slice(input).is_err() {
                                self.buf.clear();
                            }
                            break;
                        }
                    },
                }
            } else {
                // Buffered bytes from before
                todo!();
            }
        }
    }

    /// Performs validity checks on the given packet.
    /// Returns Some(payload, rest) on success.
    fn try_decode_payload(buf: &[u8]) -> Result<(&[u8], &[u8]), TryDecodeError> {
        if buf.len() <= 4 {
            return Err(TryDecodeError::TruncatedHeader);
        }
        if buf[0] != MAGIC {
            return Err(TryDecodeError::InvalidMagic);
        }
        let encoded_crc = buf[1];

        let mut len_bytes = [0u8; 2];
        len_bytes.copy_from_slice(&buf[2..4]);
        let len = u16::from_le_bytes(len_bytes) as usize;
        if len > N {
            return Err(TryDecodeError::PayloadTooBig);
        }

        if len + PAYLOAD_OFFSET > buf.len() {
            return Err(TryDecodeError::TruncatedPayload);
        }

        let crc_algorithm = crc::Crc::<u8>::new(&crc::CRC_8_GSM_A);
        let actual_crc = crc_algorithm.checksum(&buf[2..(PAYLOAD_OFFSET + len)]);

        if encoded_crc != actual_crc {
            return Err(TryDecodeError::CrcMismatch {
                packet_size: PAYLOAD_OFFSET + len,
            });
        }

        Ok((&buf[PAYLOAD_OFFSET..]).split_at(len))
    }
}

#[derive(Clone, Debug)]
enum TryDecodeError {
    TruncatedHeader,
    InvalidMagic,
    CrcMismatch {
        /// The full length of the invalid packet.
        /// For knowing where the next packet is likely to start.
        packet_size: usize,
    },
    TruncatedPayload,
    PayloadTooBig,
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use rand::Rng;

    use crate::{BitflareReader, BitflareWriter};

    #[test]
    fn abc() {
        let mut buf = [0u8; 8];
        let mut writer = BitflareWriter::new(&mut buf);
        writer
            .write_payload(|buf| {
                buf.copy_from_slice(&u32::to_le_bytes(0x69690420));
                4
            })
            .unwrap();

        let bytes = writer.finish();
        //                  magic crc   len
        assert_eq!(bytes, &[0xFC, 0xa1, 4, 0, 0x20, 0x04, 0x69, 0x69]);

        let mut reader = BitflareReader::<4>::new();
        reader.decode(bytes, |payload| {
            assert_eq!(payload, &[0x20, 0x04, 0x69, 0x69]);
        });

        let mut buf = [0u8; 12];
        let mut writer = BitflareWriter::new(&mut buf);
        writer
            .write_payload(|buf| {
                buf.copy_from_slice(&u64::to_le_bytes(0x0102030469690420));
                8
            })
            .unwrap();

        let bytes = writer.finish();
        assert_eq!(
            bytes,
            &[
                0xFC, 0xcd, 8, 0, 0x20, 0x04, 0x69, 0x69, 0x04, 0x03, 0x02, 0x01
            ]
        );

        let mut reader = BitflareReader::<8>::new();
        reader.decode(bytes, |payload| {
            assert_eq!(payload, &[0x20, 0x04, 0x69, 0x69, 0x04, 0x03, 0x02, 0x01]);
        });
    }

    #[test]
    fn fuzz() {
        let mut rng = rand::rng();
        let mut buf = vec![0u8; 1024 + 20];

        for _ in 0..1_000_000 {
            let len = rng.random_range(0..=buf.len());
            rand::Fill::fill(&mut buf[..len], &mut rng);

            let mut reader = BitflareReader::<1024>::new();

            // Make sure it doesnt crash or get stuck
            reader.decode(&buf[..len], |_| {});
        }
    }

    #[test]
    fn byte_stream() {
        let mut rng = rand::rng();
        const MAX_PACKET_SIZE: usize = 32;
        let mut payloads: VecDeque<Vec<u8>> = (0..(100_000_000))
            .map(|_| {
                let len = rng.random_range(0..=MAX_PACKET_SIZE);
                let mut buf = vec![0u8; len];
                rand::Fill::fill(&mut buf[..len], &mut rng);
                buf
            })
            .collect();

        let src_all_bytes: Vec<u8> = payloads
            .iter()
            .map(|p| p.iter().copied())
            .flatten()
            .collect();

        let mut i = 0;
        while i < src_all_bytes.len() {
            let mut reader = BitflareReader::<MAX_PACKET_SIZE>::new();

            let len = rng.random_range(0..=99).min(src_all_bytes.len() - i);
            let buf = &src_all_bytes[i..(i + len)];
            i += len;

            reader.decode(buf, |payload| {
                loop {
                    // Remove any old expected payloads we may have dropped from consuming too many
                    // bytes at once. Exit if we found the same one
                    let Some(expected) = payloads.pop_front() else {
                        panic!(
                            "Ran out of expected payloads. {i}/{} bytes",
                            src_all_bytes.len()
                        );
                    };
                    if expected == payload {
                        break;
                    }
                }
            });
        }

        assert!(payloads.is_empty());
    }
}

// Assumptions: The user can control how much to return
// input -> slice from returned slice
