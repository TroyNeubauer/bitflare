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

    pub fn valid_length(&self) -> Option<usize> {
        self.valid_length
    }

    pub fn into_inner(self) -> &'a mut [u8] {
        self.buf
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
                        TryDecodeError::TruncatedPayload { .. }
                        | TryDecodeError::TruncatedHeader => {
                            // Start of packet was okay
                            // Buffer packet for later when we receive the rest of it
                            if self.buf.extend_from_slice(input).is_err() {
                                if cfg!(debug_assertions) || true {
                                    println!(
                                        "WARN: TMP payload too big: {:02X?}, for input: {input:02X?}",
                                        self.buf
                                    );
                                }
                            }

                            break;
                        }
                    },
                }
            } else {
                // Keep adding to buf until we run out of input or are able to handle a full packet

                while !input.is_empty() {
                    let byte = input[0];
                    input = &input[1..];

                    if self.buf.push(byte).is_err() {
                        self.buf.clear();
                    }

                    match Self::try_decode_payload(&self.buf) {
                        Ok((payload, _)) => {
                            on_payload(payload);

                            // Try to handle rest of input with zero copy
                            self.buf.clear();
                            break;
                        }
                        Err(e) => match e {
                            TryDecodeError::InvalidMagic => {
                                if cfg!(debug_assertions) || true {
                                    unreachable!("Buffered packet should always have valid magic");
                                }

                                self.buf.clear();
                                break;
                            }
                            TryDecodeError::CrcMismatch { .. } => {
                                println!("WARN: CRC match while handling buffered packet");
                                self.buf.clear();
                                break;
                            }
                            TryDecodeError::PayloadTooBig => {
                                println!("WARN: Received invalid packet (payload too big)");
                                self.buf.clear();
                                break;
                            }
                            TryDecodeError::TruncatedPayload { .. }
                            | TryDecodeError::TruncatedHeader => {
                                // Waiting for mode data...
                            }
                        },
                    }
                }
            }
        }
    }

    /// Performs validity checks on the given packet.
    /// Returns Some(payload, rest) on success.
    fn try_decode_payload(buf: &[u8]) -> Result<(&[u8], &[u8]), TryDecodeError> {
        if buf.len() < 4 {
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

    use rand::{Rng, SeedableRng};

    use crate::{BitflareReader, BitflareWriter};

    #[test]
    fn feels_good() {
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
        let mut buf = vec![0u8; 32 * 1024];

        for _ in 0..1_000 {
            rand::Fill::fill(buf.as_mut_slice(), &mut rng);

            let mut reader = BitflareReader::<1024>::new();

            // Make sure it doesnt crash or get stuck
            reader.decode(&buf, |_| {});
        }
    }

    #[test]
    fn byte_stream_perfect() {
        // Ensure that we dont drop any messages assuming perfect transmission,
        // even if framing is completely random
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(0x5372420);

        let num_packets = 100_000;

        const MAX_PAYLOAD: usize = 32;
        let mut payloads: VecDeque<heapless::Vec<u8, MAX_PAYLOAD>> = (0..num_packets)
            .map(|_| {
                let len = rng.random_range(0..=MAX_PAYLOAD);
                let mut buf = heapless::Vec::new();
                buf.resize(len, 0).unwrap();
                rand::Fill::fill(&mut buf[..len], &mut rng);
                buf
            })
            .collect();

        let src_all_bytes: Vec<u8> = payloads
            .iter()
            .map(|p| {
                let mut tmp = heapless::Vec::<u8, { MAX_PAYLOAD + 4 }>::new();
                tmp.resize(MAX_PAYLOAD + 4, 0).unwrap();
                let mut writer = BitflareWriter::new(&mut tmp);
                writer
                    .write_payload(|dst| {
                        (&mut dst[..p.len()]).copy_from_slice(p);
                        p.len()
                    })
                    .unwrap();
                let len = writer.valid_length().unwrap();
                tmp.resize(len, 0).unwrap();
                tmp
            })
            .flatten()
            .collect();

        // hxdmp::hexdump(&src_all_bytes, &mut std::io::stdout()).unwrap();

        let mut reader = BitflareReader::<{ MAX_PAYLOAD + 4 }>::new();

        let mut i = 0;
        while i < src_all_bytes.len() {
            // Read a random amount of bytes to test framing,
            // Test everything between parts of a packet, to mutiple packets at a time
            let len = rng
                .random_range(0..(2 * MAX_PAYLOAD + 8))
                .min(src_all_bytes.len() - i);

            let buf = &src_all_bytes[i..(i + len)];
            i += len;

            reader.decode(buf, |payload| {
                let expected = payloads.pop_front().unwrap();
                assert_eq!(payload, expected);
            });
        }

        assert!(payloads.is_empty());
        println!(
            "Parsed {:.1}MB bytes successfully",
            src_all_bytes.len() as f64 / 1_000_000.0
        );
    }
}

// Assumptions: The user can control how much to return
// input -> slice from returned slice
