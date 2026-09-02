use std::io;
use std::time::Duration;
use serde::{Deserialize, Serialize};

pub const OBEX_VERSION_10: u8 = 0x10;

// OBEX opcodes
const OBEX_CONNECT: u8 = 0x80;
const OBEX_SETPATH: u8 = 0x85;
const OBEX_GET_FINAL: u8 = 0x83;

// OBEX headers
const HDR_NAME: u8 = 0x01; // Unicode (Null terminated UTF-16BE)
const HDR_TYPE: u8 = 0x42; // Byte sequence (ASCII MIME)
const HDR_LENGTH: u8 = 0xC3; // 4-byte length (not used for GET)
const HDR_TARGET: u8 = 0x46; // Byte sequence (UUID for MAP)
const HDR_APP_PARAMS: u8 = 0x4C; // Byte sequence (TLV application params)
const HDR_BODY: u8 = 0x48; // Byte sequence
const HDR_END_OF_BODY: u8 = 0x49; // Byte sequence

pub trait Transport {
    fn send(&mut self, req: &[u8]) -> io::Result<Vec<u8>>;
}

pub struct ObexClient<T: Transport> {
    transport: T,
    pub max_packet_len: u16,
}

impl<T: Transport> ObexClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport, max_packet_len: 0x0ff0 }
    }

    pub fn connect_with_target(&mut self, target_uuid: &[u8; 16]) -> io::Result<ObexResponse> {
        let mut pkt = Vec::with_capacity(7 + 3 + 19);
        pkt.push(OBEX_CONNECT);
        pkt.extend_from_slice(&0u16.to_be_bytes()); // placeholder for len
        pkt.push(OBEX_VERSION_10);
        pkt.push(0x00); // flags
        pkt.extend_from_slice(&self.max_packet_len.to_be_bytes());
        // Target header
        put_hdr_bytes(&mut pkt, HDR_TARGET, target_uuid);
        // fill length
        let len = pkt.len() as u16;
        pkt[1..3].copy_from_slice(&len.to_be_bytes());

        let resp = self.transport.send(&pkt)?;
        Ok(parse_response(&resp)?)
    }

    pub fn setpath_segment(&mut self, segment: &str) -> io::Result<ObexResponse> {
        let mut pkt = Vec::with_capacity(5 + 2 + (segment.len() * 2 + 2));
        pkt.push(OBEX_SETPATH);
        pkt.extend_from_slice(&0u16.to_be_bytes()); // placeholder for len
        pkt.push(0x00); // flags: no backup, no create
        pkt.push(0x00); // constants (reserved)
        put_hdr_unicode_name(&mut pkt, segment);
        let len = pkt.len() as u16;
        pkt[1..3].copy_from_slice(&len.to_be_bytes());
        let resp = self.transport.send(&pkt)?;
        Ok(parse_response(&resp)?)
    }

    pub fn get_msg_listing(
        &mut self,
        max_list_count: u16,
        start_offset: u16,
    ) -> io::Result<ObexResponse> {
        let mut pkt = Vec::with_capacity(3 + 5 + 5 + 16);
        pkt.push(OBEX_GET_FINAL);
        pkt.extend_from_slice(&0u16.to_be_bytes());
        put_hdr_ascii_type(&mut pkt, b"x-bt/MAP-msg-listing");
        let mut app = Vec::with_capacity(8);
        // TLV: MaxListCount (tag 0x01, 2 bytes)
        app.push(0x01);
        app.push(0x02);
        app.extend_from_slice(&max_list_count.to_be_bytes());
        // TLV: StartOffset (tag 0x02, 2 bytes)
        app.push(0x02);
        app.push(0x02);
        app.extend_from_slice(&start_offset.to_be_bytes());
        put_hdr_bytes(&mut pkt, HDR_APP_PARAMS, &app);
        let len = pkt.len() as u16;
        pkt[1..3].copy_from_slice(&len.to_be_bytes());
        let resp = self.transport.send(&pkt)?;
        Ok(parse_response(&resp)?)
    }
}

pub struct ObexResponse {
    pub code: u8,
    pub len: u16,
    pub connect_info: Option<ConnectInfo>,
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ConnectInfo {
    pub version: u8,
    pub flags: u8,
    pub max_packet_len: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Header {
    Name(String),
    Type(Vec<u8>),
    Target(Vec<u8>),
    AppParams(Vec<u8>),
    Body(Vec<u8>),
    EndOfBody(Vec<u8>),
    Length(u32),
    Unknown(u8, Vec<u8>),
}

fn put_hdr_bytes(buf: &mut Vec<u8>, id: u8, data: &[u8]) {
    buf.push(id);
    let len = (data.len() + 3) as u16; // header id + 2 len + data
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
}

fn put_hdr_ascii_type(buf: &mut Vec<u8>, data: &[u8]) {
    put_hdr_bytes(buf, HDR_TYPE, data);
}

fn put_hdr_unicode_name(buf: &mut Vec<u8>, s: &str) {
    let mut data = Vec::with_capacity((s.len() + 1) * 2);
    for ch in s.encode_utf16() {
        data.extend_from_slice(&ch.to_be_bytes());
    }
    // null terminator
    data.extend_from_slice(&0u16.to_be_bytes());
    put_hdr_bytes(buf, HDR_NAME, &data);
}

fn parse_response(resp: &[u8]) -> io::Result<ObexResponse> {
    if resp.len() < 3 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "OBEX response too short"));
    }
    let code = resp[0];
    let len = u16::from_be_bytes([resp[1], resp[2]]);
    if len as usize != resp.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "OBEX response length mismatch"));
    }
    let mut i = 3usize;
    let mut connect_info = None;
    // CONNECT response includes a 4-byte info block at start
    if code & 0xF0 == 0xA0 && resp.len() >= 7 && (resp[3] == OBEX_VERSION_10) {
        // Heuristic: if it looks like connect info
        let version = resp[3];
        let flags = resp[4];
        let max_packet_len = u16::from_be_bytes([resp[5], resp[6]]);
        connect_info = Some(ConnectInfo { version, flags, max_packet_len });
        i = 7;
    }

    let mut headers = Vec::new();
    let mut body = Vec::new();
    let mut content_type: Option<String> = None;
    while i < resp.len() {
        let id = resp[i]; i += 1;
        let hdr_type = id >> 6;
        match hdr_type {
            0 | 1 => {
                if i + 2 > resp.len() { break; }
                let hlen = u16::from_be_bytes([resp[i], resp[i+1]]) as usize; i += 2;
                if hlen < 3 || i + (hlen - 3) > resp.len() { break; }
                let data = &resp[i..i + (hlen - 3)];
                i += hlen - 3;
                match id {
                    HDR_NAME => {
                        // UTF-16BE null terminated
                        let mut u16s = Vec::with_capacity(data.len()/2);
                        for chunk in data.chunks_exact(2) { u16s.push(u16::from_be_bytes([chunk[0], chunk[1]])); }
                        // trim trailing null
                        if let Some(&0) = u16s.last() { u16s.pop(); }
                        let s = String::from_utf16(&u16s).unwrap_or_default();
                        headers.push(Header::Name(s));
                    }
                    HDR_TYPE => {
                        content_type = Some(String::from_utf8_lossy(data).to_string());
                        headers.push(Header::Type(data.to_vec()));
                    }
                    HDR_TARGET => headers.push(Header::Target(data.to_vec())),
                    HDR_APP_PARAMS => headers.push(Header::AppParams(data.to_vec())),
                    HDR_BODY => { body.extend_from_slice(data); headers.push(Header::Body(data.to_vec())); }
                    HDR_END_OF_BODY => { body.extend_from_slice(data); headers.push(Header::EndOfBody(data.to_vec())); }
                    _ => headers.push(Header::Unknown(id, data.to_vec())),
                }
            }
            2 => {
                // 1-byte quantity (not used here)
                if i >= resp.len() { break; }
                headers.push(Header::Unknown(id, vec![resp[i]]));
                i += 1;
            }
            3 => {
                // 4-byte quantity
                if i + 4 > resp.len() { break; }
                let val = u32::from_be_bytes([resp[i], resp[i+1], resp[i+2], resp[i+3]]);
                i += 4;
                if id == HDR_LENGTH { headers.push(Header::Length(val)); } else { headers.push(Header::Unknown(id, val.to_be_bytes().to_vec())); }
            }
            _ => {}
        }
    }

    Ok(ObexResponse { code, len, connect_info, headers, body, content_type })
}

pub struct MockTransport {
    responses: Vec<Vec<u8>>,
    pub sent: Vec<Vec<u8>>,
}

impl MockTransport {
    pub fn new() -> Self { Self { responses: Vec::new(), sent: Vec::new() } }
    pub fn with_responses(resps: Vec<Vec<u8>>) -> Self { Self { responses: resps, sent: Vec::new() } }
    pub fn push_response(&mut self, r: Vec<u8>) { self.responses.push(r); }
}

impl Transport for MockTransport {
    fn send(&mut self, req: &[u8]) -> io::Result<Vec<u8>> {
        self.sent.push(req.to_vec());
        if self.responses.is_empty() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no mock response queued"));
        }
        Ok(self.responses.remove(0))
    }
}

pub fn map_target_uuid_bytes() -> [u8; 16] {
    // bb582b40420c11dbb0de0800200c9a66
    [
        0xbb, 0x58, 0x2b, 0x40, 0x42, 0x0c, 0x11, 0xdb,
        0xb0, 0xde, 0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66,
    ]
}

pub fn pbap_target_uuid_bytes() -> [u8; 16] {
    // 796135f0f0c511d809660800200c9a66 (PBAP OBEX Target UUID)
    [
        0x79, 0x61, 0x35, 0xF0, 0xF0, 0xC5, 0x11, 0xD8,
        0x09, 0x66, 0x08, 0x00, 0x20, 0x0C, 0x9A, 0x66,
    ]
}

pub fn bmessage_minimal(vcard_name: &str, text: &str) -> Vec<u8> {
    // A very small, standards-shaped bMessage for testing serialization needs.
    let s = format!(
        "BEGIN:BMSG\r\nVERSION:1.0\r\nSTATUS:READ\r\nTYPE:SMS_GSM\r\nFOLDER:telecom/msg/inbox\r\nBEGIN:VCARD\r\nVERSION:2.1\r\nN:{}\r\nEND:VCARD\r\nBEGIN:BENV\r\nBEGIN:BBODY\r\nCHARSET:UTF-8\r\nLENGTH:{}\r\n{}\r\nEND:BBODY\r\nEND:BENV\r\nEND:BMSG\r\n",
        vcard_name,
        text.len(),
        text
    );
    s.into_bytes()
}

pub struct IoTransport<RW: io::Read + io::Write> {
    inner: RW,
}

impl<RW: io::Read + io::Write> IoTransport<RW> {
    pub fn new(inner: RW) -> Self { Self { inner } }

    fn read_obex_response(&mut self) -> io::Result<Vec<u8>> {
        let mut hdr = [0u8; 3];
        // Read exactly 3 bytes (code + len)
        io::Read::read_exact(&mut self.inner, &mut hdr)?;
        let total_len = u16::from_be_bytes([hdr[1], hdr[2]]) as usize;
        if total_len < 3 { return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid OBEX length")); }
        let mut buf = vec![0u8; total_len];
        buf[..3].copy_from_slice(&hdr);
        let remain = total_len - 3;
        if remain > 0 {
            io::Read::read_exact(&mut self.inner, &mut buf[3..])?;
        }
        Ok(buf)
    }
}

impl<RW: io::Read + io::Write> Transport for IoTransport<RW> {
    fn send(&mut self, req: &[u8]) -> io::Result<Vec<u8>> {
        io::Write::write_all(&mut self.inner, req)?;
        io::Write::flush(&mut self.inner)?;
        self.read_obex_response()
    }
}

#[cfg(target_os = "linux")]
pub struct BluezSocketTransport {
    inner: IoTransport<std::fs::File>,
}

#[cfg(target_os = "linux")]
impl BluezSocketTransport {
    pub fn connect(mac: &str, channel: u8, timeout: Duration) -> io::Result<Self> {
        use std::mem::{size_of, size_of_val};
        use std::os::fd::FromRawFd;

        // Linux Bluetooth constants
        const AF_BLUETOOTH: libc::c_int = 31;
        const BTPROTO_RFCOMM: libc::c_int = 3;

        // Parse MAC and convert to bdaddr order (LSB first)
        let mac6 = parse_mac_addr(mac)?; // [AA,BB,CC,DD,EE,FF]
        let bdaddr = [mac6[5], mac6[4], mac6[3], mac6[2], mac6[1], mac6[0]];

        // SAFETY: libc socket calls
        let fd = unsafe { libc::socket(AF_BLUETOOTH, libc::SOCK_STREAM, BTPROTO_RFCOMM) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Set timeouts
        let tv = libc::timeval {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_usec: (timeout.subsec_micros()) as libc::suseconds_t,
        };
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                size_of_val(&tv) as libc::socklen_t,
            )
        };
        if ret < 0 { let _ = unsafe { libc::close(fd) }; return Err(io::Error::last_os_error()); }
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDTIMEO,
                &tv as *const _ as *const libc::c_void,
                size_of_val(&tv) as libc::socklen_t,
            )
        };
        if ret < 0 { let _ = unsafe { libc::close(fd) }; return Err(io::Error::last_os_error()); }

        // sockaddr_rc definition
        #[repr(C)]
        struct SockAddrRc {
            rc_family: libc::sa_family_t,
            rc_bdaddr: [u8; 6],
            rc_channel: u8,
        }

        let addr = SockAddrRc {
            rc_family: AF_BLUETOOTH as libc::sa_family_t,
            rc_bdaddr: bdaddr,
            rc_channel: channel,
        };
        let ret = unsafe {
            libc::connect(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                size_of::<SockAddrRc>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            let e = io::Error::last_os_error();
            let _ = unsafe { libc::close(fd) };
            return Err(e);
        }

        // Wrap into File
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        Ok(Self { inner: IoTransport::new(file) })
    }
}

#[cfg(target_os = "linux")]
impl Transport for BluezSocketTransport {
    fn send(&mut self, req: &[u8]) -> io::Result<Vec<u8>> {
        self.inner.send(req)
    }
}

fn parse_mac_addr(s: &str) -> io::Result<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 { return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid MAC")); }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        let b = u8::from_str_radix(p, 16).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid hex"))?;
        out[i] = b;
    }
    Ok(out)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceResponseTelemetry {
    pub service: String,
    pub code: Option<u8>,
    pub send_ns: u128,
    pub recv_ns: Option<u128>,
    pub rtt_ms: Option<i128>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiServiceTelemetry {
    pub map: ServiceResponseTelemetry,
    pub pbap: ServiceResponseTelemetry,
    pub denied_delta_ms: Option<i128>,
}

#[cfg(target_os = "linux")]
pub fn run_multi_service_sync(mac: &str, map_channel: u8, pbap_channel: u8, timeout: Duration) -> MultiServiceTelemetry {
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Instant;

    let barrier = Arc::new(Barrier::new(3));
    let mac_map = mac.to_string();
    let mac_pbap = mac.to_string();
    let anchor = Instant::now();

    let bm = barrier.clone();
    let th_map = thread::spawn(move || {
        let mut tele = ServiceResponseTelemetry { service: "MAP".to_string(), code: None, send_ns: 0, recv_ns: None, rtt_ms: None, error: None };
        let mut client_opt = match BluezSocketTransport::connect(&mac_map, map_channel, timeout) {
            Ok(transport) => Some(ObexClient::new(transport)),
            Err(e) => { tele.error = Some(e.to_string()); None }
        };
        // Align send with barrier regardless of connect outcome to avoid hanging the coordinator
        bm.wait();
        let t_send = anchor.elapsed();
        tele.send_ns = t_send.as_nanos();
        if let Some(ref mut client) = client_opt {
            let uuid = map_target_uuid_bytes();
            match client.connect_with_target(&uuid) {
                Ok(resp) => {
                    tele.code = Some(resp.code);
                    let t_recv = anchor.elapsed();
                    tele.recv_ns = Some(t_recv.as_nanos());
                    tele.rtt_ms = Some(((t_recv.as_nanos() as i128) - (t_send.as_nanos() as i128)) / 1_000_000);
                }
                Err(e) => {
                    tele.error = Some(e.to_string());
                    let t_recv = anchor.elapsed();
                    tele.recv_ns = Some(t_recv.as_nanos());
                    tele.rtt_ms = Some(((t_recv.as_nanos() as i128) - (t_send.as_nanos() as i128)) / 1_000_000);
                }
            }
        }
        tele
    });

    let bp = barrier.clone();
    let th_pbap = thread::spawn(move || {
        let mut tele = ServiceResponseTelemetry { service: "PBAP".to_string(), code: None, send_ns: 0, recv_ns: None, rtt_ms: None, error: None };
        let mut client_opt = match BluezSocketTransport::connect(&mac_pbap, pbap_channel, timeout) {
            Ok(transport) => Some(ObexClient::new(transport)),
            Err(e) => { tele.error = Some(e.to_string()); None }
        };
        // Align send with barrier regardless of connect outcome
        bp.wait();
        let t_send = anchor.elapsed();
        tele.send_ns = t_send.as_nanos();
        if let Some(ref mut client) = client_opt {
            let uuid = pbap_target_uuid_bytes();
            match client.connect_with_target(&uuid) {
                Ok(resp) => {
                    tele.code = Some(resp.code);
                    let t_recv = anchor.elapsed();
                    tele.recv_ns = Some(t_recv.as_nanos());
                    tele.rtt_ms = Some(((t_recv.as_nanos() as i128) - (t_send.as_nanos() as i128)) / 1_000_000);
                }
                Err(e) => {
                    tele.error = Some(e.to_string());
                    let t_recv = anchor.elapsed();
                    tele.recv_ns = Some(t_recv.as_nanos());
                    tele.rtt_ms = Some(((t_recv.as_nanos() as i128) - (t_send.as_nanos() as i128)) / 1_000_000);
                }
            }
        }
        tele
    });

    // Release both workers at (roughly) the same time
    barrier.wait();

    let map_tele = th_map.join().unwrap_or(ServiceResponseTelemetry { service: "MAP".to_string(), code: None, send_ns: 0, recv_ns: None, rtt_ms: None, error: Some("thread panicked".into()) });
    let pbap_tele = th_pbap.join().unwrap_or(ServiceResponseTelemetry { service: "PBAP".to_string(), code: None, send_ns: 0, recv_ns: None, rtt_ms: None, error: Some("thread panicked".into()) });

    // Compute delta if both are 0xD1 or 0xC3
    let denied = |c: Option<u8>| matches!(c, Some(0xD1) | Some(0xC3));
    let delta = if denied(map_tele.code) && denied(pbap_tele.code) {
        match (map_tele.recv_ns, pbap_tele.recv_ns) {
            (Some(m), Some(p)) => Some(((m as i128) - (p as i128)) / 1_000_000),
            _ => None,
        }
    } else { None };

    MultiServiceTelemetry { map: map_tele, pbap: pbap_tele, denied_delta_ms: delta }
}

#[derive(Debug, Clone, Default)]
pub struct DiscoveredChannels { pub map: Option<u8>, pub pbap: Option<u8> }

#[cfg(target_os = "linux")]
pub fn sdp_discover_channels(mac: &str, _timeout: Duration) -> io::Result<DiscoveredChannels> {
    use std::process::Command;
    let out = Command::new("sdptool").arg("browse").arg(mac).output()?;
    if !out.status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, format!("sdptool failed: {}", out.status)));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut cur_service = String::new();
    let mut map_chan: Option<u8> = None;
    let mut pbap_chan: Option<u8> = None;
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() { continue; }
        if l.contains("Message Access Server") { cur_service = "MAP".into(); }
        else if l.contains("Phonebook Access") || l.contains("PBAP") { cur_service = "PBAP".into(); }
        if let Some(pos) = l.find("Channel:") {
            let num = l[pos+8..].trim();
            if let Ok(n) = num.parse::<u8>() {
                if cur_service == "MAP" && map_chan.is_none() { map_chan = Some(n); }
                if cur_service == "PBAP" && pbap_chan.is_none() { pbap_chan = Some(n); }
            }
        }
    }
    Ok(DiscoveredChannels { map: map_chan, pbap: pbap_chan })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_connect_success_resp(max_len: u16) -> Vec<u8> {
        let mut r = vec![0xA0, 0, 0, OBEX_VERSION_10, 0x00];
        r.extend_from_slice(&max_len.to_be_bytes());
        // No headers required here, but include a Type echo for completeness
        let mut rest = Vec::new();
        put_hdr_ascii_type(&mut rest, b"x-obex/folder-listing");
        let total_len = (r.len() + rest.len()) as u16;
        r[1..3].copy_from_slice(&total_len.to_be_bytes());
        r.extend_from_slice(&rest);
        r
    }

    fn build_simple_ok_resp_with_type_and_body(mime: &str, body: &[u8]) -> Vec<u8> {
        let mut r = vec![0xA0, 0, 0];
        let mut rest = Vec::new();
        put_hdr_ascii_type(&mut rest, mime.as_bytes());
        put_hdr_bytes(&mut rest, HDR_END_OF_BODY, body);
        let total_len = (3 + rest.len()) as u16;
        r[1..3].copy_from_slice(&total_len.to_be_bytes());
        r.extend_from_slice(&rest);
        r
    }

    #[test]
    fn test_map_msg_listing_get_mock_happy_path() -> anyhow::Result<()> {
        // Build mock transport with expected responses for: CONNECT, SETPATH x3, GET
        let connect_resp = build_connect_success_resp(0x0ff0);
        let setpath_ok = build_simple_ok_resp_with_type_and_body("x-obex/folder-listing", b"");
        let listing_xml = br#"<?xml version=\"1.0\"?>\n<!DOCTYPE MAP-msg-listing SYSTEM \"obex-map-message-listing.dtd\">\n<MAP-msg-listing version=\"1.0\"></MAP-msg-listing>"#;
        let get_resp = build_simple_ok_resp_with_type_and_body("x-bt/MAP-msg-listing", listing_xml);

        let mock = MockTransport::with_responses(vec![
            connect_resp,
            setpath_ok.clone(),
            setpath_ok.clone(),
            setpath_ok.clone(),
            get_resp,
        ]);

        let mut client = ObexClient::new(mock);

        // CONNECT with Target MAP UUID
        let uuid = map_target_uuid_bytes();
        let r = client.connect_with_target(&uuid)?;
        assert_eq!(r.code, 0xA0);
        assert!(r.connect_info.is_some());

        // Navigate to telecom/msg/inbox via SETPATH segments
        for seg in ["telecom", "msg", "inbox"] { 
            let r = client.setpath_segment(seg)?; 
            assert_eq!(r.code, 0xA0);
        }

        // Issue GET for message listing and validate response
        let r = client.get_msg_listing(10, 0)?;
        assert_eq!(r.code, 0xA0);
        assert_eq!(r.content_type.as_deref(), Some("x-bt/MAP-msg-listing"));
        assert!(std::str::from_utf8(&r.body)?.contains("MAP-msg-listing"));

        Ok(())
    }
}
use std::env;
use std::fs::File;
use std::io::Write;
use std::time::Instant;


#[cfg(target_os = "linux")]
#[derive(serde::Serialize)]
struct MapGetTelemetry {
    connect_code: Option<u8>,
    get_code: Option<u8>,
    content_type: Option<String>,
    body_len: usize,
    body_preview: Option<String>,
    connect_rtt_ms: Option<i128>,
    get_rtt_ms: Option<i128>,
    error: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return Ok(());
    }
    let default_mac = "AA:BB:CC:DD:EE:FF".to_string();
    let mac = args.get(1).cloned().unwrap_or(default_mac);
    let mut channel: Option<u8> = args.get(2).and_then(|s| s.parse().ok());
    let max_list_count: u16 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(10);
    let start_offset: u16 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);
    let timeout_s_flag: Option<u64> = args.iter().skip(1).find_map(|a| if a.starts_with("--timeout-s=") { a[12..].parse().ok() } else { None });
    let timeout_s: u64 = timeout_s_flag.unwrap_or(5);
    let json_out: bool = args.iter().any(|a| a == "--json");
    let csv_path: Option<String> = args.iter().skip(1).find_map(|a| if a.starts_with("--csv=") { Some(a[6..].to_string()) } else { None });
    let out_dir: Option<String> = args.iter().skip(1).find_map(|a| if a.starts_with("--out-dir=") { Some(a[10..].to_string()) } else { None });
    let append: bool = args.iter().any(|a| a == "--append");
    let redact: bool = args.iter().any(|a| a == "--redact");
    let out_prefix: String = args.iter().skip(1).find_map(|a| if a.starts_with("--out-prefix=") { Some(a[13..].to_string()) } else { None }).unwrap_or_else(|| "mapget".to_string());
    let no_stdout_json: bool = args.iter().any(|a| a == "--no-stdout-json");
    let repeat: usize = args.iter().skip(1).find_map(|a| if a.starts_with("--repeat=") { a[9..].parse().ok() } else { None }).unwrap_or(1);
    let sleep_ms: u64 = args.iter().skip(1).find_map(|a| if a.starts_with("--sleep-ms=") { a[11..].parse().ok() } else { None }).unwrap_or(0);
    let warmup: bool = args.iter().any(|a| a == "--warmup");
    let preview_body: usize = args.iter().skip(1).find_map(|a| if a.starts_with("--preview-body=") { a[15..].parse().ok() } else { None }).unwrap_or(0);

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("This tool requires Linux BlueZ (RFCOMM socket)." );
        std::process::exit(1);
    }

    #[cfg(target_os = "linux")]
    {
        if channel.is_none() {
            if let Ok(d) = sdp_discover_channels(&mac, Duration::from_secs(5)) { channel = d.map; }
        }
        let ch = channel.unwrap_or(4);

        let effective_preview = if redact { 0 } else { preview_body };
        if warmup {
            let _ = run_once(&mac, ch, Duration::from_secs(timeout_s), max_list_count, start_offset, effective_preview);
            if !json_out { println!("Warm-up run completed (discarded)"); }
            if sleep_ms > 0 && repeat > 0 { std::thread::sleep(Duration::from_millis(sleep_ms)); }
        }

        let mut runs: Vec<MapGetTelemetry> = Vec::with_capacity(repeat);
        for i in 0..repeat {
            let tele = run_once(&mac, ch, Duration::from_secs(timeout_s), max_list_count, start_offset, effective_preview);
            if !json_out {
                println!("Run {}:", i + 1);
                if redact {
                    println!("  CONNECT -> code=REDACTED rtt_ms={:?}", tele.connect_rtt_ms);
                    println!("  GET     -> code=REDACTED rtt_ms={:?} content={:?} body_len={}", tele.get_rtt_ms, tele.content_type, tele.body_len);
                } else {
                    println!("  CONNECT -> code={:?} rtt_ms={:?}", tele.connect_code.map(|c| format!("0x{:02X}", c)), tele.connect_rtt_ms);
                    println!("  GET     -> code={:?} rtt_ms={:?} content={:?} body_len={}", tele.get_code.map(|c| format!("0x{:02X}", c)), tele.get_rtt_ms, tele.content_type, tele.body_len);
                }
                if !redact { if let Some(p) = &tele.body_preview { println!("  body_preview: {}", p); } }
                if let Some(err) = &tele.error { println!("  error: {}", err); }
            }
            runs.push(tele);
            if sleep_ms > 0 && i + 1 < repeat { std::thread::sleep(Duration::from_millis(sleep_ms)); }
        }

        // Determine default output paths if requested
        let mut effective_csv = csv_path.clone();
        let mut json_path: Option<String> = None;
        if let Some(dir) = out_dir.clone() {
            let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            if effective_csv.is_none() { effective_csv = Some(format!("{}/{}_{}.csv", dir, out_prefix, ts)); }
            if json_out { json_path = Some(format!("{}/{}_{}.json", dir, out_prefix, ts)); }
        }

        if let Some(path) = effective_csv {
            use std::fs::OpenOptions;
            let mut f = OpenOptions::new().create(true).append(append).write(true).open(&path)?;
            let meta_len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            if !append || meta_len == 0 {
                writeln!(f, "run,connect_code_hex,connect_rtt_ms,get_code_hex,get_rtt_ms,content_type,body_len,body_preview,error")?;
            }
            for (i, t) in runs.iter().enumerate() {
                let cc = t.connect_code.map(|c| format!("0x{:02X}", c)).unwrap_or_default();
                let gc = t.get_code.map(|c| format!("0x{:02X}", c)).unwrap_or_default();
                writeln!(f, "{},{},{},{},{},{},{},{},{}",
                    i + 1,
                    cc,
                    t.connect_rtt_ms.map(|v| v.to_string()).unwrap_or_default(),
                    gc,
                    t.get_rtt_ms.map(|v| v.to_string()).unwrap_or_default(),
                    t.content_type.clone().unwrap_or_default(),
                    t.body_len,
                    t.body_preview.clone().unwrap_or_default(),
                    t.error.clone().unwrap_or_default()
                )?;
            }
        }

        if json_out {
            use std::collections::BTreeMap;
            let mut connect_counts: BTreeMap<String, usize> = BTreeMap::new();
            let mut get_counts: BTreeMap<String, usize> = BTreeMap::new();
            let mut conn_rtts: Vec<i128> = Vec::new();
            let mut get_rtts: Vec<i128> = Vec::new();
            let mut body_lens: Vec<i128> = Vec::new();
            for t in &runs {
                if let Some(c) = t.connect_code { *connect_counts.entry(format!("0x{:02X}", c)).or_insert(0) += 1; }
                if let Some(c) = t.get_code { *get_counts.entry(format!("0x{:02X}", c)).or_insert(0) += 1; }
                if let Some(v) = t.connect_rtt_ms { conn_rtts.push(v); }
                if let Some(v) = t.get_rtt_ms { get_rtts.push(v); }
                body_lens.push(t.body_len as i128);
            }
            fn stats(vals: &[i128]) -> serde_json::Value {
                if vals.is_empty() { return serde_json::json!({"count":0}); }
                let mut min = vals[0]; let mut max = vals[0]; let mut sum = 0i128;
                for &v in vals { if v < min { min = v; } if v > max { max = v; } sum += v; }
                let avg = sum as f64 / vals.len() as f64;
                serde_json::json!({"count": vals.len(), "min": min, "max": max, "avg": avg})
            }
            let summary = serde_json::json!({
                "connect_code_counts": connect_counts,
                "get_code_counts": get_counts,
                "connect_rtt_ms": stats(&conn_rtts),
                "get_rtt_ms": stats(&get_rtts),
                "body_len": stats(&body_lens),
            });
            let obj = serde_json::json!({ "runs": runs, "summary": summary });
            if !no_stdout_json { println!("{}", serde_json::to_string_pretty(&obj)?); }
            if let Some(jp) = json_path {
                let mut jf = File::create(jp)?;
                writeln!(jf, "{}", serde_json::to_string_pretty(&obj)?)?;
            }
        }
    }

    Ok(())
}

fn print_help() {
    println!("obex-map-get: MAP message-listing GET probe");
    println!("Usage: obex-map-get <MAC> [MAP_CH] [MAX_LIST] [START_OFFSET] [flags]\n");
    println!("Positional:");
    println!("  <MAC>           Target device MAC (default AA:BB:CC:DD:EE:FF)");
    println!("  [MAP_CH]        MAP RFCOMM channel (auto-SDP if omitted)");
    println!("  [MAX_LIST]      MaxListCount (default 10)");
    println!("  [START_OFFSET]  StartOffset (default 0)");
    println!("\nFlags:");
    println!("  --timeout-s=N   Set socket timeout seconds (default 5)");
    println!("  --repeat=N      Number of runs (default 1)");
    println!("  --sleep-ms=M    Sleep M ms between runs");
    println!("  --warmup        Do one discarded warm-up run");
    println!("  --preview-body=N  Include first N bytes of body in telemetry");
    println!("  --json          Emit JSON with runs + summary");
    println!("  --no-stdout-json Suppress JSON on stdout (still writes file if --out-dir)");
    println!("  --csv=FILE      Write CSV to FILE (append requires --append)");
    println!("  --out-dir=DIR   Auto-save CSV/JSON to DIR with timestamped names");
    println!("  --out-prefix=P  Prefix for auto-saved files (default 'mapget')");
    println!("  --append        Append to CSV instead of overwriting");
    println!("  --redact        Mask codes/errors and force body preview to 0 in stdout");
}

#[cfg(target_os = "linux")]
fn run_once(mac: &str, channel: u8, timeout: Duration, max_list_count: u16, start_offset: u16, preview_len: usize) -> MapGetTelemetry {
    let mut tele = MapGetTelemetry { connect_code: None, get_code: None, content_type: None, body_len: 0, body_preview: None, connect_rtt_ms: None, get_rtt_ms: None, error: None };
    let transport = match BluezSocketTransport::connect(mac, channel, timeout) {
        Ok(t) => t,
        Err(e) => { tele.error = Some(e.to_string()); return tele; }
    };
    let mut client = ObexClient::new(transport);
    let uuid = map_target_uuid_bytes();
    let t0 = Instant::now();
    match client.connect_with_target(&uuid) {
        Ok(r) => { tele.connect_code = Some(r.code); tele.connect_rtt_ms = Some((t0.elapsed().as_millis()) as i128); if r.code != 0xA0 { tele.error = Some(format!("CONNECT failed: 0x{:02X}", r.code)); return tele; } },
        Err(e) => { tele.error = Some(e.to_string()); return tele; }
    }
    for seg in ["telecom", "msg", "inbox"] {
        match client.setpath_segment(seg) {
            Ok(r) => { if r.code != 0xA0 { tele.error = Some(format!("SETPATH '{}' failed: 0x{:02X}", seg, r.code)); return tele; } },
            Err(e) => { tele.error = Some(e.to_string()); return tele; }
        }
    }
    let t1 = Instant::now();
    let mut total_body: Vec<u8> = Vec::new();
    loop {
        match client.get_msg_listing(max_list_count, start_offset) {
            Ok(r) => {
                if tele.content_type.is_none() { tele.content_type = r.content_type.clone(); }
                total_body.extend_from_slice(&r.body);
                if r.code == 0xA0 { tele.get_code = Some(r.code); break; }
                if r.code != 0x90 { tele.get_code = Some(r.code); tele.error = Some(format!("GET failed: 0x{:02X}", r.code)); break; }
            }
            Err(e) => { tele.error = Some(e.to_string()); break; }
        }
    }
    tele.get_rtt_ms = Some((t1.elapsed().as_millis()) as i128);
    if preview_len > 0 {
        let take = std::cmp::min(preview_len, total_body.len());
        let s = String::from_utf8_lossy(&total_body[..take]).to_string();
        tele.body_preview = Some(s);
    }
    tele.body_len = total_body.len();
    tele
}
