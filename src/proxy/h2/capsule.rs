// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io;

const DATAGRAM_CAPSULE_TYPE: u64 = 0;
const DEFAULT_CONTEXT_ID: u64 = 0;
// IPv6 permits a 65,527-byte UDP payload (65,535-byte payload length minus the UDP header).
// IPv4 is limited to 65,507 bytes, but the socket family enforces that smaller wire limit.
const MAX_DATAGRAM_SIZE: usize = 65_527;

#[cfg(test)]
pub fn encode_datagram(payload: &[u8]) -> io::Result<Bytes> {
    let mut out = BytesMut::with_capacity(payload.len() + 10);
    encode_datagram_into(payload, &mut out)?;
    Ok(out.freeze())
}

pub fn encode_datagram_into(payload: &[u8], out: &mut BytesMut) -> io::Result<()> {
    if payload.len() > MAX_DATAGRAM_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "UDP datagram exceeds the maximum payload size",
        ));
    }
    encode_varint(DATAGRAM_CAPSULE_TYPE, out)?;
    encode_varint((payload.len() + 1) as u64, out)?;
    encode_varint(DEFAULT_CONTEXT_ID, out)?;
    out.extend_from_slice(payload);
    Ok(())
}

#[derive(Default)]
pub struct Decoder {
    buffer: BytesMut,
    skip_remaining: u64,
    dropped_oversized: u64,
}

impl Decoder {
    pub fn take_dropped_oversized(&mut self) -> u64 {
        std::mem::take(&mut self.dropped_oversized)
    }

    pub fn push(&mut self, chunk: &[u8]) -> io::Result<Vec<Bytes>> {
        let skipped = self.skip_remaining.min(chunk.len() as u64) as usize;
        self.skip_remaining -= skipped as u64;
        if self.skip_remaining > 0 {
            return Ok(Vec::new());
        }
        self.buffer.extend_from_slice(&chunk[skipped..]);
        let mut datagrams = Vec::new();
        loop {
            let Some((capsule_type, type_len)) = decode_varint(&self.buffer)? else {
                break;
            };
            let Some((capsule_len, length_len)) = decode_varint(&self.buffer[type_len..])? else {
                break;
            };
            let header_len = type_len + length_len;
            if capsule_type != DATAGRAM_CAPSULE_TYPE {
                self.buffer.advance(header_len);
                let available = self.buffer.len().min(capsule_len as usize);
                self.buffer.advance(available);
                self.skip_remaining = capsule_len - available as u64;
                if self.skip_remaining > 0 {
                    break;
                }
                continue;
            }

            let capsule_len = usize::try_from(capsule_len).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "capsule length does not fit usize",
                )
            })?;
            if capsule_len > MAX_DATAGRAM_SIZE + 8 {
                self.dropped_oversized += 1;
                self.buffer.advance(header_len);
                let available = self.buffer.len().min(capsule_len);
                self.buffer.advance(available);
                self.skip_remaining = (capsule_len - available) as u64;
                if self.skip_remaining > 0 {
                    break;
                }
                continue;
            }
            let frame_len = header_len.checked_add(capsule_len).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "capsule length overflow")
            })?;
            if self.buffer.len() < frame_len {
                break;
            }
            let frame = self.buffer.split_to(frame_len).freeze();
            let value = &frame[header_len..];
            let Some((context_id, context_len)) = decode_varint(value)? else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DATAGRAM capsule is missing a context ID",
                ));
            };
            if context_id == DEFAULT_CONTEXT_ID {
                let payload_offset = header_len + context_len;
                if frame.len() - payload_offset > MAX_DATAGRAM_SIZE {
                    self.dropped_oversized += 1;
                } else {
                    datagrams.push(frame.slice(payload_offset..));
                }
            }
        }
        Ok(datagrams)
    }
}

fn encode_varint(value: u64, out: &mut BytesMut) -> io::Result<()> {
    match value {
        0..=63 => out.put_u8(value as u8),
        64..=16_383 => out.put_u16((value as u16) | 0x4000),
        16_384..=1_073_741_823 => out.put_u32((value as u32) | 0x8000_0000),
        1_073_741_824..=4_611_686_018_427_387_903 => out.put_u64(value | 0xc000_0000_0000_0000),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "value exceeds QUIC variable-length integer range",
            ));
        }
    }
    Ok(())
}

fn decode_varint(input: &[u8]) -> io::Result<Option<(u64, usize)>> {
    let Some(first) = input.first() else {
        return Ok(None);
    };
    let len = 1usize << (first >> 6);
    if input.len() < len {
        return Ok(None);
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &input[1..len] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok(Some((value, len)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_envoy_datagram_capsule() {
        let payload = [0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7];
        let got = encode_datagram(&payload).unwrap();
        assert_eq!(
            got.as_ref(),
            &[0x00, 0x08, 0x00, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7]
        );
    }

    #[test]
    fn decodes_fragmented_and_coalesced_capsules() {
        let first = encode_datagram(b"one").unwrap();
        let second = encode_datagram(b"two").unwrap();
        let wire = [first.as_ref(), second.as_ref()].concat();
        let mut decoder = Decoder::default();

        assert!(decoder.push(&wire[..2]).unwrap().is_empty());
        assert_eq!(
            decoder.push(&wire[2..6]).unwrap(),
            vec![Bytes::from_static(b"one")]
        );
        assert_eq!(
            decoder.push(&wire[6..]).unwrap(),
            vec![Bytes::from_static(b"two")]
        );
    }

    #[test]
    fn decodes_capsule_split_inside_multibyte_length() {
        let payload = vec![0x5a; 64];
        let wire = encode_datagram(&payload).unwrap();
        let mut decoder = Decoder::default();

        // A 65-byte capsule value needs a two-byte QUIC varint. Leave only its
        // first byte in the initial fragment.
        assert!(decoder.push(&wire[..2]).unwrap().is_empty());
        assert_eq!(
            decoder.push(&wire[2..]).unwrap(),
            vec![Bytes::from(payload)]
        );
    }

    #[test]
    fn accepts_maximum_ipv6_udp_payload() {
        let payload = vec![0x5a; 65_527];
        let wire = encode_datagram(&payload).unwrap();
        let mut decoder = Decoder::default();

        assert_eq!(decoder.push(&wire).unwrap(), vec![Bytes::from(payload)]);
    }

    #[test]
    fn skips_oversized_datagram_and_decodes_following_capsule() {
        let oversized_payload = vec![0x5a; 65_528];
        let mut wire = BytesMut::new();
        encode_varint(DATAGRAM_CAPSULE_TYPE, &mut wire).unwrap();
        encode_varint((oversized_payload.len() + 1) as u64, &mut wire).unwrap();
        encode_varint(DEFAULT_CONTEXT_ID, &mut wire).unwrap();
        wire.extend_from_slice(&oversized_payload);
        wire.extend_from_slice(&encode_datagram(b"after-oversized").unwrap());
        let mut decoder = Decoder::default();

        assert_eq!(
            decoder.push(&wire).unwrap(),
            vec![Bytes::from_static(b"after-oversized")]
        );
        assert_eq!(decoder.take_dropped_oversized(), 1);
        assert_eq!(decoder.take_dropped_oversized(), 0);
    }

    #[test]
    fn ignores_unknown_capsules_and_contexts() {
        let mut decoder = Decoder::default();
        let wire = [
            0x17, 0x02, 0x00, 0xff, // unknown capsule type
            0x00, 0x02, 0x01, 0xff, // datagram context other than zero
            0x00, 0x02, 0x00, 0x42, // accepted datagram
        ];
        assert_eq!(
            decoder.push(&wire).unwrap(),
            vec![Bytes::from_static(&[0x42])]
        );
    }

    #[test]
    fn streams_past_oversized_unknown_capsule() {
        let mut header = BytesMut::new();
        encode_varint(0x17, &mut header).unwrap();
        encode_varint(70_000, &mut header).unwrap();
        header.extend_from_slice(&[0u8; 10]);

        let mut decoder = Decoder::default();
        assert!(decoder.push(&header).unwrap().is_empty());

        let accepted = encode_datagram(b"after-unknown").unwrap();
        let mut tail = vec![0u8; 69_990];
        tail.extend_from_slice(&accepted);
        assert_eq!(
            decoder.push(&tail).unwrap(),
            vec![Bytes::from_static(b"after-unknown")]
        );
    }
}
