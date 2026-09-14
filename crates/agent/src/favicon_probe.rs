use std::io::Read as _;
use std::net::IpAddr;
use std::time::Duration;

use netqmon_protocol::v1::{FaviconProbe, FaviconProbeResult};
use reqwest::Url;
use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use sha2::{Digest as _, Sha256};

const MAX_BODY_BYTES: u64 = 2 * 1024 * 1024;
const MAX_DISCOVERED_ICONS: usize = 4;

pub(super) fn execute(request: &FaviconProbe) -> (FaviconProbeResult, String) {
    let Some(ip) = decode_ip(&request.target_ip) else {
        return result(request, Vec::new(), "invalid_target");
    };
    let Ok(port) = u16::try_from(request.port) else {
        return result(request, Vec::new(), "invalid_target");
    };
    if port == 0 || !private_target(ip) {
        return result(request, Vec::new(), "invalid_target");
    }
    let Ok(client) = Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(5))
        .redirect(Policy::none())
        .danger_accept_invalid_certs(true)
        .user_agent(concat!("netqmon-agent/", env!("CARGO_PKG_VERSION")))
        .build()
    else {
        return result(request, Vec::new(), "client_error");
    };

    let schemes = if port == 443 {
        ["https", "http"]
    } else {
        ["http", "https"]
    };
    for scheme in schemes {
        let Ok(base) = Url::parse(&format!("{scheme}://{}/", authority(ip, port))) else {
            continue;
        };
        let mut paths = vec!["/favicon.ico".to_owned()];
        if let Some(page) = fetch(&client, &base) {
            for href in icon_hrefs(&page) {
                if let Ok(url) = base.join(&href) {
                    if url.host_str() == base.host_str()
                        && url.port_or_known_default() == base.port_or_known_default()
                    {
                        let mut path = url.path().to_owned();
                        if let Some(query) = url.query() {
                            path.push('?');
                            path.push_str(query);
                        }
                        if !paths.contains(&path) {
                            paths.insert(0, path);
                        }
                    }
                }
            }
        }
        let mut hashes = Vec::new();
        for path in paths.into_iter().take(MAX_DISCOVERED_ICONS) {
            let Ok(url) = base.join(&path) else { continue };
            let Some(bytes) = fetch(&client, &url) else {
                continue;
            };
            let digest = Sha256::digest(bytes).to_vec();
            if !hashes.contains(&digest) {
                hashes.push(digest);
            }
        }
        if !hashes.is_empty() {
            return result(request, hashes, "ok");
        }
    }
    result(request, Vec::new(), "not_found")
}

fn fetch(client: &Client, url: &Url) -> Option<Vec<u8>> {
    let response = client.get(url.clone()).send().ok()?;
    if !response.status().is_success() {
        return None;
    }
    let mut body = Vec::new();
    response
        .take(MAX_BODY_BYTES + 1)
        .read_to_end(&mut body)
        .ok()?;
    (body.len() as u64 <= MAX_BODY_BYTES && !body.is_empty()).then_some(body)
}

fn icon_hrefs(page: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(page);
    let lower = text.to_ascii_lowercase();
    let mut output = Vec::new();
    let mut offset = 0;
    while let Some(start) = lower[offset..].find("<link") {
        let start = offset + start;
        let Some(end) = lower[start..].find('>') else {
            break;
        };
        let end = start + end + 1;
        let tag_lower = &lower[start..end];
        if attribute(tag_lower, "rel")
            .is_some_and(|value| value.split_whitespace().any(|part| part.contains("icon")))
        {
            if let Some(href) = attribute(&text[start..end], "href") {
                if !href.trim().is_empty() && !href.trim_start().starts_with("data:") {
                    output.push(href);
                }
            }
        }
        offset = end;
    }
    output
}

fn attribute(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let mut cursor = 0;
    while let Some(found) = lower[cursor..].find(name) {
        let start = cursor + found;
        let before_ok = start == 0 || !lower.as_bytes()[start - 1].is_ascii_alphanumeric();
        let mut equals = start + name.len();
        while lower
            .as_bytes()
            .get(equals)
            .is_some_and(u8::is_ascii_whitespace)
        {
            equals += 1;
        }
        if !before_ok || lower.as_bytes().get(equals) != Some(&b'=') {
            cursor = equals;
            continue;
        }
        equals += 1;
        while lower
            .as_bytes()
            .get(equals)
            .is_some_and(u8::is_ascii_whitespace)
        {
            equals += 1;
        }
        let quote = *tag.as_bytes().get(equals)?;
        if matches!(quote, b'\'' | b'"') {
            let value_start = equals + 1;
            let value_end = tag.as_bytes()[value_start..]
                .iter()
                .position(|byte| *byte == quote)?
                + value_start;
            return Some(tag[value_start..value_end].to_owned());
        }
        let value_end = tag.as_bytes()[equals..]
            .iter()
            .position(|byte| byte.is_ascii_whitespace() || *byte == b'>')
            .unwrap_or(tag.len() - equals)
            + equals;
        return Some(tag[equals..value_end].to_owned());
    }
    None
}

fn result(
    request: &FaviconProbe,
    sha256: Vec<Vec<u8>>,
    status: &str,
) -> (FaviconProbeResult, String) {
    (
        FaviconProbeResult {
            target_ip: request.target_ip.clone(),
            port: request.port,
            sha256,
        },
        status.to_owned(),
    )
}

fn authority(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(ip) => format!("{ip}:{port}"),
        IpAddr::V6(ip) => format!("[{ip}]:{port}"),
    }
}

fn decode_ip(bytes: &[u8]) -> Option<IpAddr> {
    match bytes {
        [a, b, c, d] => Some(std::net::Ipv4Addr::new(*a, *b, *c, *d).into()),
        bytes if bytes.len() == 16 => {
            Some(std::net::Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?).into())
        }
        _ => None,
    }
}

fn private_target(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local() || ip.is_loopback(),
        IpAddr::V6(ip) => {
            ip.is_loopback() || ip.is_unicast_link_local() || (ip.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_link_icons_without_accepting_inline_data() {
        let html = br#"<link href='/a.png' rel='shortcut icon'><link rel=icon href=data:image/png,abc><link REL=ICON HREF=/b.ico>"#;
        assert_eq!(icon_hrefs(html), vec!["/a.png", "/b.ico"]);
    }
}
