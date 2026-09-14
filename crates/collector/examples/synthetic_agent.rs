use std::error::Error;
use std::time::Duration;

use netqmon_protocol::v1::{EnrollRequest, EnrollResponse, FlowDelta, TelemetryBatch};
use netqmon_protocol::{PROTOCOL_VERSION, encode_telemetry_batch};
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args().skip(1);
    let address = arguments.next().ok_or("missing Collector address")?;
    let enrollment_token = arguments.next().ok_or("missing enrollment token")?;
    let batches: u64 = arguments.next().unwrap_or_else(|| "3".to_owned()).parse()?;

    let enrollment = EnrollRequest {
        enrollment_token,
        agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        protocol_version: PROTOCOL_VERSION,
        boot_id: "synthetic-boot".to_owned(),
        gateway_name: "synthetic-agent".to_owned(),
    };
    let (status, body) = post(
        &address,
        "/v1/ingest/enroll",
        &[("Content-Type", "application/x-protobuf".to_owned())],
        &enrollment.encode_to_vec(),
    )
    .await?;
    if status != 200 {
        return Err(format!("enrollment returned HTTP {status}").into());
    }
    let enrollment = EnrollResponse::decode(body.as_slice())?;

    for sequence in 1..=batches {
        let batch = TelemetryBatch {
            gateway_id: enrollment.gateway_id.clone(),
            boot_id: "synthetic-boot".to_owned(),
            sequence,
            sent_at: 1_700_000_000_000 + sequence * 1_000,
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
            protocol_version: PROTOCOL_VERSION,
            flows: vec![FlowDelta {
                upload_bytes: 100,
                download_bytes: 50,
                packets: 1,
                ..FlowDelta::default()
            }],
            ..TelemetryBatch::default()
        };
        let encoded = encode_telemetry_batch(&batch, 1)?;
        let mut headers = vec![
            ("Content-Type", "application/x-protobuf".to_owned()),
            (
                "Authorization",
                format!("Bearer {}", enrollment.agent_token),
            ),
        ];
        if let Some(encoding) = encoded.encoding.http_value() {
            headers.push(("Content-Encoding", encoding.to_owned()));
        }
        let (status, _) = post(&address, "/v1/ingest/telemetry", &headers, &encoded.body).await?;
        if status != 204 {
            return Err(format!("batch {sequence} returned HTTP {status}").into());
        }
        if sequence < batches {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    println!("sent {batches} one-second telemetry batches");
    Ok(())
}

async fn post(
    address: &str,
    path: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> Result<(u16, Vec<u8>), Box<dyn Error>> {
    let mut stream = TcpStream::connect(address).await?;
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {address}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(body).await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    parse_response(&response)
}

fn parse_response(response: &[u8]) -> Result<(u16, Vec<u8>), Box<dyn Error>> {
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| {
            format!(
                "HTTP response has no header terminator ({} bytes: {:?})",
                response.len(),
                response
            )
        })?;
    let headers = std::str::from_utf8(&response[..separator])?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or("HTTP response has no status")?
        .parse()?;
    Ok((status, response[separator + 4..].to_vec()))
}
