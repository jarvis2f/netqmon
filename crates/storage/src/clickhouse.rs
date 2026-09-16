//! Lightweight `ClickHouse` client shared by analytics storage.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{StorageError, StorageResult};

/// `ClickHouse` client configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClickHouseConfig {
    pub url: String,
    pub database: String,
    pub user: Option<String>,
    pub password: Option<String>,
    pub timeout_ms: u64,
}

impl Default for ClickHouseConfig {
    fn default() -> Self {
        Self {
            url: "http://127.0.0.1:8123".to_owned(),
            database: "default".to_owned(),
            user: None,
            password: None,
            timeout_ms: 5_000,
        }
    }
}

/// Lightweight `ClickHouse` HTTP/1.1 client over a standard TCP stream.
#[derive(Clone, Debug)]
pub struct ClickHouseClient {
    config: ClickHouseConfig,
}

impl ClickHouseClient {
    #[must_use]
    pub fn new(config: ClickHouseConfig) -> Self {
        Self { config }
    }

    /// Checks connectivity to the `ClickHouse` server.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` on network or HTTP error.
    pub fn ping(&self) -> StorageResult<()> {
        let _ = self.execute("SELECT 1")?;
        Ok(())
    }

    /// Executes arbitrary SQL without expecting a structured result.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` on execution failure.
    pub fn execute(&self, sql: &str) -> StorageResult<String> {
        let path = format!("/?database={}", url_encode(&self.config.database));
        self.post(&path, sql.as_bytes(), "text/plain; charset=utf-8")
    }

    /// Executes a SQL query and parses the response as JSON.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` on query failure or JSON parse error.
    pub fn query_json(&self, sql: &str) -> StorageResult<Value> {
        let formatted = if sql.to_uppercase().contains("FORMAT ") {
            sql.to_owned()
        } else {
            format!("{sql} FORMAT JSON")
        };
        let response = self.execute(&formatted)?;
        if response.trim().is_empty() {
            return Ok(json!({}));
        }
        serde_json::from_str(&response).map_err(|err| {
            StorageError::Serialization(format!("failed to parse ClickHouse JSON response: {err}"))
        })
    }

    /// Inserts JSON rows with `FORMAT JSONEachRow`.
    ///
    /// # Errors
    ///
    /// Returns `StorageError` on serialization or insertion failure.
    pub fn insert_json_each_row(&self, table: &str, rows: &[Value]) -> StorageResult<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut body = Vec::new();
        for row in rows {
            serde_json::to_writer(&mut body, row).map_err(|err| {
                StorageError::Serialization(format!("failed to serialize row to JSON: {err}"))
            })?;
            body.push(b'\n');
        }
        let query = format!("INSERT INTO {table} FORMAT JSONEachRow");
        let path = format!(
            "/?database={}&query={}",
            url_encode(&self.config.database),
            url_encode(&query)
        );
        self.post(&path, &body, "application/x-ndjson")?;
        Ok(())
    }

    fn post(&self, path_and_query: &str, body: &[u8], content_type: &str) -> StorageResult<String> {
        let (host, port) = parse_host_port(&self.config.url)?;
        let address = format!("{host}:{port}");
        let socket_address = address
            .to_socket_addrs()
            .map_err(|err| StorageError::Connection(format!("cannot resolve {address}: {err}")))?
            .next()
            .ok_or_else(|| {
                StorageError::Connection(format!("no address resolved for {address}"))
            })?;
        let timeout = Duration::from_millis(self.config.timeout_ms.max(1_000));
        let mut stream = TcpStream::connect_timeout(&socket_address, timeout).map_err(|err| {
            StorageError::Connection(format!("failed to connect to {address}: {err}"))
        })?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|err| StorageError::Connection(format!("set read timeout failed: {err}")))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|err| StorageError::Connection(format!("set write timeout failed: {err}")))?;

        let mut request = format!(
            "POST {path_and_query} HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: netqmon-storage\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        if let Some(user) = &self.config.user {
            request.push_str("X-ClickHouse-User: ");
            request.push_str(user);
            request.push_str("\r\n");
        }
        if let Some(password) = &self.config.password {
            request.push_str("X-ClickHouse-Key: ");
            request.push_str(password);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        stream
            .write_all(request.as_bytes())
            .map_err(|err| StorageError::Connection(format!("write request failed: {err}")))?;
        stream
            .write_all(body)
            .map_err(|err| StorageError::Connection(format!("write body failed: {err}")))?;
        stream
            .flush()
            .map_err(|err| StorageError::Connection(format!("flush failed: {err}")))?;

        read_response(BufReader::new(stream))
    }
}

fn read_response(mut reader: impl BufRead) -> StorageResult<String> {
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .map_err(|err| StorageError::Connection(format!("read status line failed: {err}")))?;
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(StorageError::Connection(format!(
            "invalid HTTP status line: {status_line}"
        )));
    }
    let status_code: u16 = parts[1]
        .parse()
        .map_err(|_| StorageError::Connection(format!("invalid HTTP status code: {}", parts[1])))?;
    let mut content_length = None;
    let mut is_chunked = false;
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|err| StorageError::Connection(format!("read header failed: {err}")))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        let lower = trimmed.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("content-length:") {
            if let Ok(length) = rest.trim().parse::<usize>() {
                content_length = Some(length);
            }
        } else if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            is_chunked = true;
        }
    }
    let mut response_body = Vec::new();
    if is_chunked {
        loop {
            let mut size = String::new();
            reader.read_line(&mut size).map_err(|err| {
                StorageError::Connection(format!("read chunk size failed: {err}"))
            })?;
            let size = size.trim();
            let chunk_size = usize::from_str_radix(size, 16)
                .map_err(|_| StorageError::Connection(format!("invalid chunk size: {size}")))?;
            if chunk_size == 0 {
                let mut trailer = String::new();
                let _ = reader.read_line(&mut trailer);
                break;
            }
            let mut chunk = vec![0; chunk_size];
            reader
                .read_exact(&mut chunk)
                .map_err(|err| StorageError::Connection(format!("read chunk failed: {err}")))?;
            response_body.extend_from_slice(&chunk);
            let mut crlf = [0; 2];
            let _ = reader.read_exact(&mut crlf);
        }
    } else if let Some(length) = content_length {
        response_body.resize(length, 0);
        reader
            .read_exact(&mut response_body)
            .map_err(|err| StorageError::Connection(format!("read body failed: {err}")))?;
    } else {
        let _ = reader.read_to_end(&mut response_body);
    }
    let response = String::from_utf8_lossy(&response_body).to_string();
    if status_code != 200 {
        return Err(StorageError::ClickHouse(format!(
            "HTTP {status_code}: {}",
            response.trim()
        )));
    }
    Ok(response)
}

fn parse_host_port(url: &str) -> StorageResult<(String, u16)> {
    let stripped = url.strip_prefix("http://").unwrap_or(url);
    let host_port = stripped.split('/').next().unwrap_or(stripped);
    if let Some((host, port)) = host_port.split_once(':') {
        let port = port.parse().map_err(|_| {
            StorageError::Connection(format!("invalid port in ClickHouse URL: {port}"))
        })?;
        Ok((host.to_owned(), port))
    } else {
        Ok((host_port.to_owned(), 8123))
    }
}

fn url_encode(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                output.push(byte as char);
            }
            _ => {
                output.push('%');
                output.push(char::from(HEX[usize::from(byte >> 4)]));
                output.push(char::from(HEX[usize::from(byte & 0x0f)]));
            }
        }
    }
    output
}

#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}

/// Decodes a hexadecimal string into bytes.
///
/// # Errors
///
/// Returns `StorageError` when the value is not valid hexadecimal.
pub fn from_hex(value: &str) -> StorageResult<Vec<u8>> {
    if value.len() % 2 != 0 {
        return Err(StorageError::Serialization(
            "hex string has odd length".to_owned(),
        ));
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|error| StorageError::Serialization(error.to_string()))
        })
        .collect()
}
