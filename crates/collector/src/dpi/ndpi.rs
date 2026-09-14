//! The only unsafe boundary: opaque, independently owned nDPI module/flow pairs.
#![allow(unsafe_code)]
use super::engine::{DpiEngine, DpiFlow};
use netqmon_protocol::v1::FlowSampleKey;
pub struct NdpiEngine;
impl DpiEngine for NdpiEngine {
    fn name(&self) -> &'static str {
        "ndpi"
    }
    fn start(&self, _flow: &FlowSampleKey) -> Result<Box<dyn DpiFlow>, String> {
        #[cfg(ndpi_available)]
        {
            native::NativeFlow::new().map(|flow| Box::new(flow) as Box<dyn DpiFlow>)
        }
        #[cfg(not(ndpi_available))]
        {
            Err("nDPI 4.14 was not available at build time".into())
        }
    }
}
pub fn available() -> bool {
    cfg!(ndpi_available)
}

#[cfg(ndpi_available)]
mod native {
    use super::super::engine::{DpiFlow, DpiResult};
    use netqmon_protocol::v1::SamplePacket;
    use std::{
        ffi::{CStr, c_char, c_void},
        sync::{Arc, Mutex},
    };
    static MODULE: Mutex<Option<Arc<Mutex<Module>>>> = Mutex::new(None);
    struct Module(*mut c_void);
    // Access to module state is serialized by its Mutex.
    unsafe impl Send for Module {}
    impl Drop for Module {
        fn drop(&mut self) {
            unsafe {
                nqm_ndpi_destroy(self.0);
            }
        }
    }
    unsafe extern "C" {
        fn nqm_ndpi_create() -> *mut c_void;
        fn nqm_ndpi_destroy(module: *mut c_void);
        fn nqm_ndpi_flow_new() -> *mut c_void;
        fn nqm_ndpi_flow_destroy(flow: *mut c_void);
        fn nqm_ndpi_packet(
            module: *mut c_void,
            flow: *mut c_void,
            packet: *const u8,
            length: u16,
            timestamp: u64,
            master: *mut c_char,
            application: *mut c_char,
            hostname: *mut c_char,
            protocol_length: u32,
            confidence: *mut f64,
        ) -> i32;
        fn nqm_ndpi_finish(
            module: *mut c_void,
            flow: *mut c_void,
            master: *mut c_char,
            application: *mut c_char,
            hostname: *mut c_char,
            capacity: u32,
            confidence: *mut f64,
        ) -> i32;
    }
    // Buffers use the same bounded ABI for incremental and final results.
    pub struct NativeFlow {
        module: Arc<Mutex<Module>>,
        flow: *mut c_void,
    }
    // Exclusive ownership; calls require &mut self. Initialization is serialized.
    unsafe impl Send for NativeFlow {}
    impl NativeFlow {
        pub fn new() -> Result<Self, String> {
            let mut shared = MODULE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // SAFETY: allocation APIs return owned opaque pointers, checked below.
            unsafe {
                if shared.is_none() {
                    let pointer = nqm_ndpi_create();
                    if pointer.is_null() {
                        return Err("nDPI module allocation failed".into());
                    }
                    *shared = Some(Arc::new(Mutex::new(Module(pointer))));
                }
                let module = Arc::clone(shared.as_ref().expect("initialized"));
                let flow = nqm_ndpi_flow_new();
                if flow.is_null() {
                    return Err("nDPI flow allocation failed".into());
                }
                Ok(Self { module, flow })
            }
        }
    }
    impl DpiFlow for NativeFlow {
        fn classify(&mut self, packets: &[SamplePacket]) -> Option<DpiResult> {
            let module = self
                .module
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut latest = None;
            for packet in packets {
                let Ok(length) = u16::try_from(packet.payload.len()) else {
                    continue;
                };
                let mut name = [0 as c_char; 256];
                let mut application = [0 as c_char; 256];
                let mut hostname = [0 as c_char; 256];
                let mut confidence = 0.0;
                // SAFETY: live exclusive state and bounded buffers for the entire call.
                let found = unsafe {
                    nqm_ndpi_packet(
                        module.0,
                        self.flow,
                        packet.payload.as_ptr(),
                        length,
                        packet.timestamp_unix_ms,
                        name.as_mut_ptr(),
                        application.as_mut_ptr(),
                        hostname.as_mut_ptr(),
                        256,
                        &raw mut confidence,
                    )
                };
                if found != 0 {
                    latest = Some(decode_result(&name, &application, &hostname, confidence));
                }
            }
            latest
        }
        fn finish(&mut self) -> Option<DpiResult> {
            let module = self
                .module
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut master = [0 as c_char; 256];
            let mut application = [0 as c_char; 256];
            let mut hostname = [0 as c_char; 256];
            let mut confidence = 0.0;
            // SAFETY: owned live state, serialized module, bounded writable buffers.
            let found = unsafe {
                nqm_ndpi_finish(
                    module.0,
                    self.flow,
                    master.as_mut_ptr(),
                    application.as_mut_ptr(),
                    hostname.as_mut_ptr(),
                    256,
                    &raw mut confidence,
                )
            };
            (found != 0).then(|| decode_result(&master, &application, &hostname, confidence))
        }
    }
    fn decode_result(
        master: &[c_char; 256],
        application: &[c_char; 256],
        hostname: &[c_char; 256],
        confidence: f64,
    ) -> DpiResult {
        let text = |buffer: &[c_char; 256]| {
            // SAFETY: the shim always NUL-terminates its output.
            unsafe { CStr::from_ptr(buffer.as_ptr()) }
                .to_string_lossy()
                .into_owned()
        };
        let master = text(master);
        let application = text(application);
        let protocol = if master.is_empty() {
            &application
        } else {
            &master
        };
        DpiResult {
            protocol: protocol.to_ascii_lowercase().replace(['/', ' ', '.'], "_"),
            confidence,
            source: "ndpi".into(),
            metadata: std::collections::BTreeMap::from([
                ("master_protocol".into(), master),
                ("application_protocol".into(), application),
                ("hostname".into(), text(hostname)),
                ("engine_version".into(), "4.14".into()),
            ]),
        }
    }

    impl Drop for NativeFlow {
        fn drop(&mut self) {
            // SAFETY: each allocation is freed once; flow must die before its module.
            unsafe {
                nqm_ndpi_flow_destroy(self.flow);
            }
        }
    }
}

#[cfg(all(test, ndpi_available))]
mod tests {
    use super::*;
    use netqmon_protocol::v1::SamplePacket;
    fn packet(payload: &[u8], udp: bool, reverse: bool, timestamp: u64) -> SamplePacket {
        let header = if udp { 28 } else { 40 };
        let mut bytes = vec![0; header + payload.len()];
        bytes[0] = 0x45;
        let len = u16::try_from(bytes.len()).unwrap();
        bytes[2..4].copy_from_slice(&len.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = if udp { 17 } else { 6 };
        let (src, dst, sp, dp) = if reverse {
            ([198, 51, 100, 2], [192, 0, 2, 1], 443u16, 50000u16)
        } else {
            ([192, 0, 2, 1], [198, 51, 100, 2], 50000u16, 443u16)
        };
        bytes[12..16].copy_from_slice(&src);
        bytes[16..20].copy_from_slice(&dst);
        bytes[20..22].copy_from_slice(&sp.to_be_bytes());
        bytes[22..24].copy_from_slice(&dp.to_be_bytes());
        if udp {
            bytes[24..26].copy_from_slice(&u16::try_from(payload.len() + 8).unwrap().to_be_bytes());
        } else {
            bytes[32] = 0x50;
            bytes[33] = 0x18;
            bytes[24..28].copy_from_slice(&1u32.to_be_bytes());
        }
        bytes[header..].copy_from_slice(payload);
        SamplePacket {
            direction: if reverse { 2 } else { 1 },
            timestamp_unix_ms: timestamp,
            original_length: u32::from(len),
            captured_length: u32::from(len),
            payload: bytes,
        }
    }
    #[test]
    fn native_tls_preserves_youtube_and_sni_and_http_host() {
        let host = b"www.youtube.com";
        let mut sni = vec![0, 0, 0, 0, 0];
        sni[0..2].copy_from_slice(&u16::try_from(host.len() + 3).unwrap().to_be_bytes());
        sni[3..5].copy_from_slice(&u16::try_from(host.len()).unwrap().to_be_bytes());
        sni.extend_from_slice(host);
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
        let mut flow = NdpiEngine.start(&FlowSampleKey::default()).unwrap();
        let result = flow
            .classify(&[packet(&record, false, false, 1000)])
            .unwrap();
        assert_eq!(result.protocol, "tls");
        assert_eq!(result.metadata["master_protocol"], "TLS");
        assert_eq!(result.metadata["application_protocol"], "YouTube");
        assert_eq!(result.metadata["hostname"], "www.youtube.com");
        assert_eq!(
            flow.finish().unwrap().metadata["application_protocol"],
            "YouTube"
        );
        let mut flow = NdpiEngine.start(&FlowSampleKey::default()).unwrap();
        let result = flow
            .classify(&[packet(
                b"GET / HTTP/1.1\r\nHost: www.youtube.com\r\nUser-Agent: netqmon-test\r\n\r\n",
                false,
                false,
                1000,
            )])
            .unwrap();
        assert_eq!(result.protocol, "http");
        assert_eq!(result.metadata["hostname"], "www.youtube.com");
    }

    #[test]
    fn real_ndpi_identifies_bittorrent_wireguard_and_openvpn() {
        let engine = NdpiEngine;
        let key = FlowSampleKey::default();
        let mut bt = vec![19];
        bt.extend_from_slice(b"BitTorrent protocol");
        bt.resize(68, 0);
        let result = engine
            .start(&key)
            .unwrap()
            .classify(&[packet(&bt, false, false, 1000)])
            .unwrap();
        assert_eq!(result.protocol, "bittorrent");
        let mut wg = engine.start(&key).unwrap();
        let mut init = vec![0; 148];
        init[0] = 1;
        init[4] = 42;
        assert!(wg.classify(&[packet(&init, true, false, 1000)]).is_none());
        let mut reply = vec![0; 92];
        reply[0] = 2;
        reply[4] = 43;
        reply[8] = 42;
        assert_eq!(
            wg.classify(&[packet(&reply, true, true, 1001)])
                .unwrap()
                .protocol,
            "wireguard"
        );
        let mut ovpn = engine.start(&key).unwrap();
        let mut packets = Vec::new();
        for i in 0..4 {
            let mut payload = vec![0; 32];
            payload[0] = if i == 0 { 0x38 } else { 0x20 };
            payload[1..9].fill(7);
            packets.push(packet(&payload, true, false, 1000 + i));
        }
        assert_eq!(ovpn.classify(&packets).unwrap().protocol, "openvpn");
    }
    #[test]
    fn random_and_truncated_input_does_not_claim_protocol() {
        let engine = NdpiEngine;
        let key = FlowSampleKey::default();
        assert!(
            engine
                .start(&key)
                .unwrap()
                .classify(&[packet(&[0xff; 64], true, false, 1000)])
                .is_none()
        );
        let mut truncated = packet(&[0xff; 64], true, false, 1000);
        truncated.payload.truncate(10);
        assert!(engine.start(&key).unwrap().classify(&[truncated]).is_none());
    }
}
