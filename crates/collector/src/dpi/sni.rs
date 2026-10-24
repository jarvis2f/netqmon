//! Bounded TLS SNI extraction from sampled TCP packets.
//!
//! nDPI normally supplies `host_server_name`, but incomplete or direction-
//! split samples can leave it empty. This parser only reads the ClientHello
//! already present in the bounded sample; it never decrypts traffic and never
//! stores payload bytes.

use netqmon_protocol::v1::SamplePacket;

const TLS_HANDSHAKE: u8 = 22;
const TLS_CLIENT_HELLO: u8 = 1;
const SNI_EXTENSION: u16 = 0;
const MAX_HOSTNAME_LEN: usize = 253;

/// Extract a validated SNI hostname from sampled TCP ClientHello packets.
pub(crate) fn extract_tls_sni(packets: &[SamplePacket]) -> Option<String> {
    let mut payload = Vec::new();
    for packet in packets {
        if let Some(bytes) = tcp_payload(&packet.payload) {
            payload.extend_from_slice(bytes);
        }
    }
    find_client_hello(&payload)
}

fn tcp_payload(packet: &[u8]) -> Option<&[u8]> {
    if packet.is_empty() {
        return None;
    }
    match packet[0] >> 4 {
        4 => {
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            if header_len < 20 || packet.len() < header_len || packet[9] != 6 {
                return None;
            }
            let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            let end = total_len.min(packet.len());
            if end <= header_len {
                return None;
            }
            let tcp = &packet[header_len..end];
            if tcp.len() < 20 {
                return None;
            }
            let data_offset = usize::from(tcp[12] >> 4) * 4;
            (data_offset >= 20 && data_offset <= tcp.len()).then(|| &tcp[data_offset..])
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let next_header = packet[6];
            let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            let end = (40 + payload_len).min(packet.len());
            if next_header != 6 || end <= 40 {
                return None;
            }
            let tcp = &packet[40..end];
            if tcp.len() < 20 {
                return None;
            }
            let data_offset = usize::from(tcp[12] >> 4) * 4;
            (data_offset >= 20 && data_offset <= tcp.len()).then(|| &tcp[data_offset..])
        }
        _ => None,
    }
}

fn find_client_hello(data: &[u8]) -> Option<String> {
    let mut offset = 0;
    while offset + 5 <= data.len() {
        if data[offset] != TLS_HANDSHAKE {
            offset += 1;
            continue;
        }
        let length = usize::from(u16::from_be_bytes([data[offset + 3], data[offset + 4]]));
        let body_end = offset.checked_add(5 + length)?;
        if body_end > data.len() {
            return None;
        }
        let record = data.get(offset + 5..body_end)?;
        if record.first() == Some(&TLS_CLIENT_HELLO) {
            // The handshake header is four bytes, even for a short TLS record.
            let header = record.get(..4)?;
            let handshake_len = (usize::from(header[1]) << 16)
                | (usize::from(header[2]) << 8)
                | usize::from(header[3]);
            return parse_client_hello(record.get(4..4 + handshake_len)?);
        }
        offset = body_end;
    }
    None
}

fn parse_client_hello(handshake: &[u8]) -> Option<String> {
    if handshake.len() < 38 || handshake[0] != 3 {
        return None;
    }
    let mut offset = 34; // legacy_version + random
    let session_len = usize::from(*handshake.get(offset)?);
    offset = offset.checked_add(1 + session_len)?;
    let cipher_len = usize::from(u16::from_be_bytes([
        *handshake.get(offset)?,
        *handshake.get(offset + 1)?,
    ]));
    offset = offset.checked_add(2 + cipher_len)?;
    let compression_len = usize::from(*handshake.get(offset)?);
    offset = offset.checked_add(1 + compression_len)?;
    let extensions_len = usize::from(u16::from_be_bytes([
        *handshake.get(offset)?,
        *handshake.get(offset + 1)?,
    ]));
    offset = offset.checked_add(2)?;
    let extensions_end = offset.checked_add(extensions_len)?.min(handshake.len());
    while offset + 4 <= extensions_end {
        let extension_type = u16::from_be_bytes([handshake[offset], handshake[offset + 1]]);
        let extension_len = usize::from(u16::from_be_bytes([
            handshake[offset + 2],
            handshake[offset + 3],
        ]));
        let data_start = offset + 4;
        let data_end = data_start.checked_add(extension_len)?;
        if data_end > extensions_end {
            return None;
        }
        if extension_type == SNI_EXTENSION {
            return parse_sni_extension(&handshake[data_start..data_end]);
        }
        offset = data_end;
    }
    None
}

fn parse_sni_extension(extension: &[u8]) -> Option<String> {
    if extension.len() < 5 {
        return None;
    }
    let list_len = usize::from(u16::from_be_bytes([extension[0], extension[1]]));
    let list_end = (2 + list_len).min(extension.len());
    let mut offset = 2;
    while offset + 3 <= list_end {
        let name_type = extension[offset];
        let name_len = usize::from(u16::from_be_bytes([
            extension[offset + 1],
            extension[offset + 2],
        ]));
        let start = offset + 3;
        let end = start.checked_add(name_len)?;
        if end > list_end {
            return None;
        }
        if name_type == 0 {
            let host = std::str::from_utf8(&extension[start..end]).ok()?;
            return valid_hostname(host);
        }
        offset = end;
    }
    None
}

fn valid_hostname(host: &str) -> Option<String> {
    let host = host.trim_end_matches('.');
    if host.is_empty()
        || host.len() > MAX_HOSTNAME_LEN
        || host.parse::<std::net::IpAddr>().is_ok()
        || !host.contains('.')
        || !host
            .split('.')
            .all(|label| !label.is_empty() && label.len() <= 63)
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use netqmon_protocol::v1::SamplePacket;

    fn packet(payload: &[u8], tcp: bool) -> SamplePacket {
        let header = if tcp { 40 } else { 28 };
        let mut bytes = vec![0; header + payload.len()];
        bytes[0] = 0x45;
        let length = u16::try_from(bytes.len()).unwrap();
        bytes[2..4].copy_from_slice(&length.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = if tcp { 6 } else { 17 };
        bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
        bytes[16..20].copy_from_slice(&[198, 51, 100, 1]);
        bytes[20..22].copy_from_slice(&50_000u16.to_be_bytes());
        bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
        if tcp {
            bytes[32] = 0x50;
            bytes[33] = 0x18;
            bytes[24..28].copy_from_slice(&1u32.to_be_bytes());
        } else {
            bytes[24..26].copy_from_slice(&u16::try_from(payload.len() + 8).unwrap().to_be_bytes());
        }
        bytes[header..].copy_from_slice(payload);
        SamplePacket {
            direction: 1,
            timestamp_unix_ms: 1,
            original_length: u32::from(length),
            captured_length: u32::from(length),
            payload: bytes,
        }
    }

    fn client_hello(host: &str) -> Vec<u8> {
        let mut sni = vec![0, 0, 0, 0, 0];
        sni[0..2].copy_from_slice(&u16::try_from(host.len() + 3).unwrap().to_be_bytes());
        sni[3..5].copy_from_slice(&u16::try_from(host.len()).unwrap().to_be_bytes());
        sni.extend_from_slice(host.as_bytes());
        let mut extensions = vec![0, 0];
        extensions.extend_from_slice(&u16::try_from(sni.len()).unwrap().to_be_bytes());
        extensions.extend_from_slice(&sni);
        let mut hello = vec![3, 3];
        hello.extend_from_slice(&[7; 32]);
        hello.extend_from_slice(&[0, 0, 2, 0xc0, 0x2f, 1, 0]);
        hello.extend_from_slice(&u16::try_from(extensions.len()).unwrap().to_be_bytes());
        hello.extend_from_slice(&extensions);
        let mut handshake = vec![1, 0];
        handshake.extend_from_slice(&u16::try_from(hello.len()).unwrap().to_be_bytes());
        handshake.extend_from_slice(&hello);
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&u16::try_from(handshake.len()).unwrap().to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn extracts_sni_from_tcp_client_hello() {
        let record = client_hello("v11-hcd.douyinvod.com");
        let sample = packet(&record, true);
        assert_eq!(
            extract_tls_sni(&[sample]),
            Some("v11-hcd.douyinvod.com".to_owned())
        );
    }

    #[test]
    fn rejects_udp_and_invalid_hostnames() {
        let record = client_hello("v11-hcd.douyinvod.com");
        assert_eq!(extract_tls_sni(&[packet(&record, false)]), None);
        let invalid = client_hello("not a host");
        assert_eq!(extract_tls_sni(&[packet(&invalid, true)]), None);
    }

    #[test]
    fn rejects_short_handshake_records_without_panicking() {
        for length in 0..4 {
            let mut record = vec![22, 3, 3, 0, length];
            record.extend(std::iter::repeat_n(1, usize::from(length)));
            assert_eq!(extract_tls_sni(&[packet(&record, true)]), None);
        }
        let mut record = client_hello("example.com");
        record[6..9].copy_from_slice(&[0xff, 0xff, 0xff]);
        assert_eq!(extract_tls_sni(&[packet(&record, true)]), None);
    }

    #[test]
    fn rejects_every_truncated_client_hello_without_panicking() {
        let record = client_hello("example.com");
        for end in 0..record.len() {
            assert_eq!(extract_tls_sni(&[packet(&record[..end], true)]), None);
        }
    }
}
