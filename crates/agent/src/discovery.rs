use std::collections::{BTreeMap, HashMap, VecDeque};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::time::{Duration, Instant};

use hickory_proto::op::Message;
use hickory_proto::rr::RData;
use netqmon_protocol::v1::DeviceDiscoveryObservation;

use crate::discovery_event::DiscoveryEvent;

const DEDUP_TTL: Duration = Duration::from_secs(1);
const DEDUP_CAPACITY: usize = 16_384;
const HTTP_PORT: u16 = 80;
/// HTTP requests repeat many times per page load; one User-Agent observation
/// per minute per (device, value) is enough for device fingerprints.
const HTTP_USER_AGENT_DEDUP_TTL: Duration = Duration::from_secs(60);
const HTTP_USER_AGENT_DEDUP_CAPACITY: usize = 4_096;

#[derive(Debug, Default)]
pub(super) struct DiscoveryCounters {
    pub discovery_packets: u64,
    pub discovery_truncated: u64,
    pub discovery_duplicate: u64,
    pub discovery_parse_failed: u64,
    pub discovery_decode_failed: u64,
    pub mdns_parse_success: u64,
    pub mdns_parse_failed: u64,
    pub ssdp_parse_success: u64,
    pub dhcp6_parse_success: u64,
    pub http_parse_success: u64,
    pub http_duplicate: u64,
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct DiscoveryKey {
    source_mac: crate::identity::MacAddress,
    source_ip: std::net::IpAddr,
    source_port: u16,
    destination_port: u16,
    payload_hash: u64,
}

#[derive(Default)]
pub(super) struct DiscoveryProcessor {
    pub counters: DiscoveryCounters,
    pub failures_since_report: u64,
    recent: HashMap<DiscoveryKey, Instant>,
    expiry: VecDeque<(Instant, DiscoveryKey)>,
    user_agent_recent: HashMap<(crate::identity::MacAddress, u64), Instant>,
    user_agent_expiry: VecDeque<(Instant, (crate::identity::MacAddress, u64))>,
}

impl DiscoveryProcessor {
    pub fn dedup_entries(&self) -> (usize, usize) {
        (self.recent.len(), self.user_agent_recent.len())
    }

    pub fn process(
        &mut self,
        bytes: &[u8],
        observed_at: u64,
        now: Instant,
    ) -> Result<Vec<DeviceDiscoveryObservation>, String> {
        self.counters.discovery_packets += 1;
        match DiscoveryEvent::try_from(bytes) {
            Ok(event) => self.process_event(&event, observed_at, now),
            Err(error) => {
                self.counters.discovery_decode_failed += 1;
                self.failures_since_report += 1;
                Err(error.to_string())
            }
        }
    }

    fn process_event(
        &mut self,
        event: &DiscoveryEvent,
        observed_at: u64,
        now: Instant,
    ) -> Result<Vec<DeviceDiscoveryObservation>, String> {
        // Count captures, including repeated truncated captures. Never parse partial data.
        if event.truncated {
            self.counters.discovery_truncated += 1;
            return Ok(Vec::new());
        }
        while self
            .expiry
            .front()
            .is_some_and(|(seen, _)| now.duration_since(*seen) >= DEDUP_TTL)
        {
            let (_, key) = self.expiry.pop_front().unwrap();
            self.recent.remove(&key);
        }
        let mut hasher = DefaultHasher::new();
        event.payload.hash(&mut hasher);
        let key = DiscoveryKey {
            source_mac: event.source_mac,
            source_ip: event.source_ip,
            source_port: event.source_port,
            destination_port: event.destination_port,
            payload_hash: hasher.finish(),
        };
        if self.recent.contains_key(&key) {
            self.counters.discovery_duplicate += 1;
            return Ok(Vec::new());
        }
        // Bound memory even if a source floods us with unique discovery packets.
        if self.recent.len() >= DEDUP_CAPACITY {
            let (_, oldest) = self.expiry.pop_front().unwrap();
            self.recent.remove(&oldest);
        }
        self.recent.insert(key.clone(), now);
        self.expiry.push_back((now, key));
        let mut result = parse(event, observed_at);
        let mdns = event.source_port == 5353 || event.destination_port == 5353;
        if result.is_ok() {
            match (event.source_port, event.destination_port) {
                (5353, _) | (_, 5353) => self.counters.mdns_parse_success += 1,
                (1900, _) | (_, 1900) => self.counters.ssdp_parse_success += 1,
                (546, 547) => self.counters.dhcp6_parse_success += 1,
                (HTTP_PORT, _) | (_, HTTP_PORT) => {
                    self.counters.http_parse_success += 1;
                    self.dedup_user_agent(event, &mut result, now);
                }
                _ => {}
            }
        } else {
            self.counters.discovery_parse_failed += 1;
            self.failures_since_report += 1;
            if mdns {
                self.counters.mdns_parse_failed += 1;
            }
        }
        result
    }

    fn dedup_user_agent(
        &mut self,
        event: &DiscoveryEvent,
        result: &mut Result<Vec<DeviceDiscoveryObservation>, String>,
        now: Instant,
    ) {
        let Ok(observations) = result.as_mut() else {
            return;
        };
        let Some(user_agent) = observations
            .iter()
            .find(|observation| observation.protocol == "http")
            .and_then(|observation| observation.attributes.get("user-agent"))
            .filter(|user_agent| !user_agent.is_empty())
        else {
            return;
        };
        let mut hasher = DefaultHasher::new();
        user_agent.hash(&mut hasher);
        let key = (event.source_mac, hasher.finish());
        while self
            .user_agent_expiry
            .front()
            .is_some_and(|(seen, _)| now.duration_since(*seen) >= HTTP_USER_AGENT_DEDUP_TTL)
        {
            let (_, stale) = self.user_agent_expiry.pop_front().unwrap();
            self.user_agent_recent.remove(&stale);
        }
        if self.user_agent_recent.contains_key(&key) {
            self.counters.http_duplicate += 1;
            observations.retain(|observation| observation.protocol != "http");
            return;
        }
        if self.user_agent_recent.len() >= HTTP_USER_AGENT_DEDUP_CAPACITY {
            let (_, stale) = self.user_agent_expiry.pop_front().unwrap();
            self.user_agent_recent.remove(&stale);
        }
        self.user_agent_recent.insert(key, now);
        self.user_agent_expiry.push_back((now, key));
    }
}

pub(super) fn parse(
    event: &DiscoveryEvent,
    observed_at_unix_ms: u64,
) -> Result<Vec<DeviceDiscoveryObservation>, String> {
    if event.truncated {
        return Err(format!(
            "truncated discovery datagram: captured_payload_length={} original_payload_length={} truncated=true",
            event.captured_payload_length, event.original_payload_length
        ));
    }
    match (event.source_port, event.destination_port) {
        (5353, _) | (_, 5353) => parse_mdns(event, observed_at_unix_ms),
        (1900, _) | (_, 1900) => parse_ssdp(event, observed_at_unix_ms),
        (546, 547) => parse_dhcp6(event, observed_at_unix_ms),
        (HTTP_PORT, _) | (_, HTTP_PORT) => parse_http(event, observed_at_unix_ms),
        _ => Ok(Vec::new()),
    }
}

fn base(event: &DiscoveryEvent, observed_at_unix_ms: u64) -> DeviceDiscoveryObservation {
    DeviceDiscoveryObservation {
        mac: event.source_mac.octets().to_vec(),
        ip: match event.source_ip {
            std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
            std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
        },
        observed_at_unix_ms,
        attributes: HashMap::from([
            (
                "captured_payload_length".into(),
                event.captured_payload_length.to_string(),
            ),
            (
                "original_payload_length".into(),
                event.original_payload_length.to_string(),
            ),
            ("truncated".into(), event.truncated.to_string()),
        ]),
        ..DeviceDiscoveryObservation::default()
    }
}

fn parse_mdns(
    event: &DiscoveryEvent,
    observed_at: u64,
) -> Result<Vec<DeviceDiscoveryObservation>, String> {
    let message = Message::from_vec(&event.payload).map_err(|error| error.to_string())?;
    if message.truncated() {
        return Err("DNS TC flag set: incomplete mDNS message".into());
    }
    let mut by_instance = BTreeMap::<String, DeviceDiscoveryObservation>::new();
    for record in message
        .answers()
        .iter()
        .chain(message.name_servers())
        .chain(message.additionals())
    {
        let owner = dns_name(record.name());
        match record.data() {
            RData::PTR(ptr) => {
                let instance = dns_name(&ptr.0);
                let item = by_instance
                    .entry(instance.clone())
                    .or_insert_with(|| base(event, observed_at));
                item.service = owner;
                item.instance = instance;
            }
            RData::SRV(srv) => {
                let item = by_instance
                    .entry(owner.clone())
                    .or_insert_with(|| base(event, observed_at));
                item.instance.clone_from(&owner);
                if item.service.is_empty() {
                    item.service = service_from_instance(&owner);
                }
                item.hostname = dns_name(srv.target());
                item.port = u32::from(srv.port());
            }
            RData::TXT(txt) => {
                let item = by_instance
                    .entry(owner.clone())
                    .or_insert_with(|| base(event, observed_at));
                item.instance.clone_from(&owner);
                if item.service.is_empty() {
                    item.service = service_from_instance(&owner);
                }
                for value in txt.txt_data() {
                    if let Ok(value) = std::str::from_utf8(value) {
                        let (key, value) = value.split_once('=').unwrap_or((value, ""));
                        if !key.is_empty() {
                            item.attributes
                                .insert(key.to_ascii_lowercase(), value.to_owned());
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(by_instance
        .into_values()
        .filter(|item| !item.service.is_empty())
        .map(|mut item| {
            item.protocol = if item.service.starts_with("_matter") {
                "matter".to_owned()
            } else {
                "mdns".to_owned()
            };
            item
        })
        .collect())
}

fn parse_ssdp(
    event: &DiscoveryEvent,
    observed_at: u64,
) -> Result<Vec<DeviceDiscoveryObservation>, String> {
    let payload = std::str::from_utf8(&event.payload).map_err(|error| error.to_string())?;
    let mut headers = HashMap::new();
    let mut lines = payload.split("\r\n");
    let first_line = lines.next().unwrap_or_default().trim();
    if !(first_line.starts_with("NOTIFY ")
        || first_line.starts_with("M-SEARCH ")
        || first_line.starts_with("HTTP/1.1 200"))
    {
        return Err("invalid SSDP start line".to_owned());
    }
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        if ["server", "user-agent", "st", "nt", "usn", "location"].contains(&name.as_str()) {
            headers.insert(name, value.trim().to_owned());
        }
    }
    let mut observation = base(event, observed_at);
    "ssdp".clone_into(&mut observation.protocol);
    headers.insert(
        "message_kind".to_owned(),
        first_line
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_owned(),
    );
    observation.service = headers
        .get("st")
        .or_else(|| headers.get("nt"))
        .cloned()
        .unwrap_or_default();
    observation.attributes.extend(headers);
    Ok(vec![observation])
}

fn parse_http(
    event: &DiscoveryEvent,
    observed_at: u64,
) -> Result<Vec<DeviceDiscoveryObservation>, String> {
    let payload = &event.payload[..usize::from(event.captured_payload_length)];
    let request_line_end = payload
        .iter()
        .position(|&byte| byte == b'\n')
        .ok_or("http request line missing newline")?;
    let line = &payload[..request_line_end];
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let request_line = std::str::from_utf8(line).map_err(|error| error.to_string())?;
    let mut request_line_parts = request_line.split(' ');
    let valid_request_line = request_line_parts.next().is_some_and(|method| {
        [
            "GET", "POST", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT",
        ]
        .contains(&method)
    }) && request_line_parts.next().is_some()
        && request_line_parts
            .next()
            .is_some_and(|version| version.starts_with("HTTP/1."));
    if !valid_request_line {
        return Err("invalid HTTP request line".to_owned());
    }
    let mut offset = request_line_end + 1;
    while offset < payload.len() {
        let line_end = match payload[offset..].iter().position(|&byte| byte == b'\n') {
            Some(position) => offset + position,
            None => break,
        };
        let line = &payload[offset..line_end];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        let Some(colon) = line.iter().position(|&byte| byte == b':') else {
            offset = line_end + 1;
            continue;
        };
        let (name, value) = (&line[..colon], &line[colon + 1..]);
        if name.eq_ignore_ascii_case(b"User-Agent") {
            let user_agent = std::str::from_utf8(value)
                .map_err(|error| error.to_string())?
                .trim();
            if user_agent.is_empty() {
                return Err("empty User-Agent header".to_owned());
            }
            let mut observation = base(event, observed_at);
            "http".clone_into(&mut observation.protocol);
            observation
                .attributes
                .insert("user-agent".to_owned(), user_agent.to_owned());
            return Ok(vec![observation]);
        }
        offset = line_end + 1;
    }
    Err("User-Agent header not found".to_owned())
}

fn parse_dhcp6(
    event: &DiscoveryEvent,
    observed_at: u64,
) -> Result<Vec<DeviceDiscoveryObservation>, String> {
    if event.payload.len() < 4 {
        return Err("DHCPv6 payload is shorter than its header".to_owned());
    }
    let mut attributes = HashMap::new();
    attributes.insert("message_type".to_owned(), event.payload[0].to_string());
    let mut index = 4;
    while index + 4 <= event.payload.len() {
        let code = u16::from_be_bytes([event.payload[index], event.payload[index + 1]]);
        let length = usize::from(u16::from_be_bytes([
            event.payload[index + 2],
            event.payload[index + 3],
        ]));
        index += 4;
        if index + length > event.payload.len() {
            return Err("truncated DHCPv6 option".to_owned());
        }
        let value = &event.payload[index..index + length];
        match code {
            1 => {
                attributes.insert("duid".to_owned(), hex(value));
            }
            6 => {
                let oro = value
                    .chunks_exact(2)
                    .map(|part| u16::from_be_bytes([part[0], part[1]]).to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                attributes.insert("oro".to_owned(), oro);
            }
            16 => {
                if value.len() < 4 {
                    return Err("short DHCPv6 vendor class enterprise number".into());
                }
                attributes.insert(
                    "vendor_enterprise".into(),
                    u32::from_be_bytes(value[..4].try_into().unwrap()).to_string(),
                );
                let mut cursor = 4;
                let mut classes = Vec::new();
                while cursor < value.len() {
                    let length_bytes = value
                        .get(cursor..cursor + 2)
                        .ok_or("truncated DHCPv6 vendor class length")?;
                    let length = usize::from(u16::from_be_bytes(length_bytes.try_into().unwrap()));
                    cursor += 2;
                    let data = value
                        .get(cursor..cursor + length)
                        .ok_or("truncated DHCPv6 vendor class data")?;
                    if let Ok(text) = std::str::from_utf8(data) {
                        if text.chars().all(|ch| !ch.is_control()) {
                            classes.push(text);
                        }
                    }
                    cursor += length;
                }
                attributes.insert("vendor_class".to_owned(), classes.join(";"));
            }
            17 => {
                attributes.insert("vendor_specific".to_owned(), hex(value));
            }
            39 if value.len() > 1 => {
                attributes.insert("client_fqdn".to_owned(), dns_wire_name(&value[1..]));
            }
            _ => {}
        }
        index += length;
    }
    if index != event.payload.len() {
        return Err("truncated DHCPv6 option header".into());
    }
    let mut observation = base(event, observed_at);
    "dhcp6".clone_into(&mut observation.protocol);
    observation.hostname = attributes.get("client_fqdn").cloned().unwrap_or_default();
    observation.attributes.extend(attributes);
    Ok(vec![observation])
}

fn dns_name(name: &hickory_proto::rr::Name) -> String {
    name.to_utf8().trim_end_matches('.').to_ascii_lowercase()
}

fn service_from_instance(instance: &str) -> String {
    instance
        .split('.')
        .position(|label| label.starts_with('_'))
        .map_or_else(String::new, |index| {
            instance
                .split('.')
                .skip(index)
                .collect::<Vec<_>>()
                .join(".")
        })
}

fn dns_wire_name(value: &[u8]) -> String {
    let mut labels = Vec::new();
    let mut index = 0;
    while index < value.len() {
        let length = usize::from(value[index]);
        index += 1;
        if length == 0 {
            break;
        }
        if index + length > value.len() {
            return String::new();
        }
        if let Ok(label) = std::str::from_utf8(&value[index..index + length]) {
            labels.push(label);
        }
        index += length;
    }
    labels.join(".").to_ascii_lowercase()
}

fn hex(value: &[u8]) -> String {
    use std::fmt::Write as _;
    value.iter().fold(String::new(), |mut output, byte| {
        let _ = write!(output, "{byte:02x}");
        output
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(source_port: u16, destination_port: u16, payload: Vec<u8>) -> DiscoveryEvent {
        DiscoveryEvent {
            source_ip: "192.0.2.2".parse().unwrap(),
            source_mac: "00:01:02:03:04:05".parse().unwrap(),
            source_port,
            destination_port,
            captured_payload_length: u16::try_from(payload.len()).unwrap(),
            original_payload_length: u16::try_from(payload.len()).unwrap(),
            truncated: false,
            payload,
        }
    }

    fn mdns_payload(length: usize) -> Vec<u8> {
        let mut payload = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        let owner = "Printer._ipp._tcp.local";
        let data_length = length - payload.len() - wire_name(owner).len() - 10;
        let mut txt = Vec::new();
        while txt.len() < data_length {
            let size = (data_length - txt.len() - 1).min(255);
            txt.push(u8::try_from(size).unwrap());
            txt.extend(std::iter::repeat_n(b'a', size));
        }
        dns_record(&mut payload, owner, 16, &txt);
        assert_eq!(payload.len(), length);
        payload
    }

    fn captured_bytes(source: u16, destination: u16, payload: &[u8]) -> Vec<u8> {
        use crate::discovery_event::{DISCOVERY_EVENT_SIZE, DISCOVERY_MAX_PAYLOAD_LENGTH};
        let captured = payload.len().min(DISCOVERY_MAX_PAYLOAD_LENGTH);
        let mut bytes = vec![0; DISCOVERY_EVENT_SIZE];
        bytes[16..18].copy_from_slice(&u16::try_from(captured).unwrap().to_ne_bytes());
        bytes[18] = 4;
        bytes[19] = u8::from(captured < payload.len());
        bytes[20..24].copy_from_slice(&[192, 0, 2, 2]);
        bytes[36..42].copy_from_slice(&[0, 1, 2, 3, 4, 5]);
        bytes[42..44].copy_from_slice(&source.to_be_bytes());
        bytes[44..46].copy_from_slice(&destination.to_be_bytes());
        bytes[46..48].copy_from_slice(&u16::try_from(payload.len()).unwrap().to_ne_bytes());
        bytes[48..48 + captured].copy_from_slice(&payload[..captured]);
        bytes
    }

    #[test]
    fn mdns_capture_boundaries_and_crossing_resource_record() {
        let now = Instant::now();
        let mut processor = DiscoveryProcessor::default();
        for length in [577, 1025, 2048, 2049, 3000] {
            let payload = mdns_payload(length);
            // The complete wire message is valid, even when the capture cuts its TXT RR.
            assert_eq!(
                parse(&event(5353, 5353, payload.clone()), 1).unwrap().len(),
                1
            );
            let bytes = captured_bytes(5353, 5353, &payload);
            let decoded = DiscoveryEvent::try_from(bytes.as_slice()).unwrap();
            assert_eq!(usize::from(decoded.original_payload_length), length);
            assert_eq!(
                usize::from(decoded.captured_payload_length),
                length.min(2048)
            );
            assert_eq!(decoded.truncated, length > 2048);
            let observations = processor.process(&bytes, 1, now).unwrap();
            assert_eq!(observations.len(), usize::from(length <= 2048));
        }
        assert_eq!(processor.counters.discovery_packets, 5);
        assert_eq!(processor.counters.discovery_truncated, 2);
        assert_eq!(processor.counters.mdns_parse_success, 3);
        assert_eq!(processor.counters.mdns_parse_failed, 0);
        assert_eq!(processor.failures_since_report, 0);
    }

    #[test]
    fn duplicate_ingress_egress_produces_one_observation_and_expires_at_one_second() {
        let mut processor = DiscoveryProcessor::default();
        let now = Instant::now();
        let ingress = captured_bytes(5353, 5353, &mdns_payload(1025));
        let mut egress = ingress.clone();
        // Timestamp, interface and packet length must not affect the identity.
        egress[..16].fill(42);
        assert_eq!(processor.process(&ingress, 1, now).unwrap().len(), 1);
        assert!(
            processor
                .process(&egress, 2, now + Duration::from_millis(999))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            processor
                .process(&egress, 3, now + DEDUP_TTL)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(processor.counters.discovery_duplicate, 1);
        assert_eq!(processor.counters.mdns_parse_success, 2);
    }

    #[test]
    fn dedup_key_includes_every_source_field_and_payload() {
        let now = Instant::now();
        let bytes = captured_bytes(5353, 5353, &mdns_payload(577));
        let mut processor = DiscoveryProcessor::default();
        assert_eq!(processor.process(&bytes, 1, now).unwrap().len(), 1);
        for offset in [20, 36, 42, 44, 60] {
            let mut changed = bytes.clone();
            changed[offset] ^= 1;
            // Payload change may fail parsing, but must still bypass deduplication.
            let _ = processor.process(&changed, 1, now);
        }
        assert_eq!(processor.counters.discovery_duplicate, 0);
    }

    #[test]
    fn truncation_is_skipped_for_every_protocol_and_failures_are_counted() {
        let now = Instant::now();
        let mut processor = DiscoveryProcessor::default();
        for (source, destination) in [(5353, 5353), (1900, 1900), (546, 547)] {
            assert!(
                processor
                    .process(&captured_bytes(source, destination, &vec![0; 2049]), 1, now)
                    .unwrap()
                    .is_empty()
            );
        }
        assert_eq!(processor.counters.discovery_truncated, 3);
        assert_eq!(processor.counters.discovery_parse_failed, 0);
        assert!(
            processor
                .process(&captured_bytes(5353, 5353, &[0]), 1, now)
                .is_err()
        );
        assert!(processor.process(&[0], 1, now).is_err());
        assert_eq!(processor.counters.mdns_parse_failed, 1);
        assert_eq!(processor.counters.discovery_parse_failed, 1);
        assert_eq!(processor.counters.discovery_decode_failed, 1);
        assert_eq!(processor.failures_since_report, 2);
        assert_eq!(
            processor
                .process(
                    &captured_bytes(1900, 1900, b"NOTIFY * HTTP/1.1\r\n\r\n"),
                    1,
                    now
                )
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            processor
                .process(&captured_bytes(546, 547, &[1, 0, 0, 1]), 1, now)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(processor.counters.ssdp_parse_success, 1);
        assert_eq!(processor.counters.dhcp6_parse_success, 1);
    }

    #[test]
    fn parses_ssdp_headers_without_retaining_payload() {
        let observations = parse(
            &event(
                1900,
                1900,
                b"NOTIFY * HTTP/1.1\r\nNT: urn:schemas-upnp-org:device:MediaRenderer:1\r\nSERVER: Linux/5 UPnP/1.1\r\nUSN: uuid:test\r\n\r\n".to_vec(),
            ),
            10,
        )
        .unwrap();
        assert_eq!(observations[0].protocol, "ssdp");
        assert!(observations[0].service.contains("MediaRenderer"));
        assert_eq!(observations[0].attributes["server"], "Linux/5 UPnP/1.1");
    }

    #[test]
    fn parses_http_user_agent_from_request() {
        let payload = b"GET / HTTP/1.1\r\nHost: example.test\r\nUser-Agent: Mozilla/5.0 (iPad2,1; CPU OS 7_1 like Mac OS X) AppleWebKit/534.46\r\nAccept: */*\r\n\r\n".to_vec();
        let observations = parse(&event(51000, HTTP_PORT, payload), 10).unwrap();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].protocol, "http");
        assert_eq!(
            observations[0].attributes["user-agent"],
            "Mozilla/5.0 (iPad2,1; CPU OS 7_1 like Mac OS X) AppleWebKit/534.46"
        );
    }

    #[test]
    fn parses_http_user_agent_with_binary_body_tail() {
        let mut payload = b"POST /api HTTP/1.1\r\nuser-AGENT: curl/8.5.0\r\n\r\n".to_vec();
        payload.extend_from_slice(&[0x00, 0xff, 0xfe, 0x80, 0x81]);
        let observations = parse(&event(40000, HTTP_PORT, payload), 10).unwrap();
        assert_eq!(observations[0].protocol, "http");
        assert_eq!(observations[0].attributes["user-agent"], "curl/8.5.0");
    }

    #[test]
    fn rejects_non_http_payload_on_port_80() {
        assert!(
            parse(
                &event(40000, HTTP_PORT, b"\x16\x03\x01\x00\xa8".to_vec()),
                10
            )
            .is_err()
        );
        assert!(parse(&event(40000, HTTP_PORT, b"GET / 2.0\r\n".to_vec()), 10).is_err());
    }

    #[test]
    fn rejects_http_request_without_user_agent() {
        let payload = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec();
        assert!(parse(&event(40000, HTTP_PORT, payload), 10).is_err());
    }

    #[test]
    fn dedups_repeated_user_agent_within_ttl() {
        use std::time::Duration;

        let payload = b"GET / HTTP/1.1\r\nUser-Agent: AFTMM\r\n\r\n".to_vec();
        let bytes = captured_bytes(40000, HTTP_PORT, &payload);
        let mut processor = DiscoveryProcessor::default();
        let now = Instant::now();
        let first = processor.process(&bytes, 10, now).unwrap();
        assert_eq!(first.len(), 1);
        let second = processor
            .process(&bytes, 10, now + Duration::from_secs(5))
            .unwrap();
        assert!(second.is_empty());
        assert_eq!(processor.counters.http_duplicate, 1);
        let third = processor
            .process(&bytes, 10, now + Duration::from_secs(120))
            .unwrap();
        assert_eq!(third.len(), 1);
    }

    #[test]
    fn search_targets_are_marked_as_queries() {
        let observations = parse(
            &event(
                1900,
                1900,
                b"M-SEARCH * HTTP/1.1\r\nST: urn:device:Camera:1\r\n\r\n".to_vec(),
            ),
            1,
        )
        .unwrap();
        assert_eq!(observations[0].attributes["message_kind"], "M-SEARCH");
    }

    #[test]
    fn dhcp6_preserves_vendor_spaces_and_rejects_partial_class_data() {
        let mut payload = vec![1, 0, 0, 1, 0, 16, 0, 17, 0, 0, 0, 1, 0, 11];
        payload.extend_from_slice(b"HP LaserJet");
        let observations = parse(&event(546, 547, payload.clone()), 1).unwrap();
        assert_eq!(observations[0].attributes["vendor_class"], "HP LaserJet");
        payload[13] = 12;
        assert!(parse(&event(546, 547, payload), 1).is_err());
    }

    #[test]
    fn parses_dhcp6_oro_vendor_and_fqdn() {
        let payload = vec![
            1, 0, 0, 1, 0, 6, 0, 4, 0, 23, 0, 24, 0, 16, 0, 11, 0, 0, 1, 55, 0, 5, b'a', b'n',
            b'd', b'r', b'o', 0, 39, 0, 8, 0, 5, b'p', b'h', b'o', b'n', b'e', 0,
        ];
        let observations = parse(&event(546, 547, payload), 10).unwrap();
        assert_eq!(observations[0].attributes["oro"], "23,24");
        assert!(observations[0].attributes["vendor_class"].contains("andro"));
        assert_eq!(observations[0].hostname, "phone");
    }

    #[test]
    fn parses_mdns_ptr_srv_and_txt_records() {
        let service = "_ipp._tcp.local";
        let instance = "Office Printer._ipp._tcp.local";
        let mut payload = vec![0, 0, 0x84, 0, 0, 0, 0, 3, 0, 0, 0, 0];
        dns_record(&mut payload, service, 12, &wire_name(instance));
        let mut srv = vec![0, 0, 0, 0, 0x02, 0x77];
        srv.extend(wire_name("printer.local"));
        dns_record(&mut payload, instance, 33, &srv);
        let txt = b"md=LaserJet";
        let mut txt_data = vec![u8::try_from(txt.len()).unwrap()];
        txt_data.extend(txt);
        dns_record(&mut payload, instance, 16, &txt_data);

        let observations = parse(&event(5353, 5353, payload), 10).unwrap();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].service, service);
        assert_eq!(observations[0].hostname, "printer.local");
        assert_eq!(observations[0].port, 631);
        assert_eq!(observations[0].attributes["md"], "LaserJet");
    }

    fn dns_record(message: &mut Vec<u8>, name: &str, record_type: u16, data: &[u8]) {
        message.extend(wire_name(name));
        message.extend(record_type.to_be_bytes());
        message.extend(1_u16.to_be_bytes());
        message.extend(120_u32.to_be_bytes());
        message.extend(u16::try_from(data.len()).unwrap().to_be_bytes());
        message.extend(data);
    }

    fn wire_name(name: &str) -> Vec<u8> {
        let mut result = Vec::new();
        for label in name.split('.') {
            result.push(u8::try_from(label.len()).unwrap());
            result.extend(label.as_bytes());
        }
        result.push(0);
        result
    }
}
