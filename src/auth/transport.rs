use std::io::{Cursor, Read, Write};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthMethod {
    Get,
    Post,
}

impl AuthMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthRequest {
    pub method: AuthMethod,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthHttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum AuthTransportError {
    #[error("I/O failure: {0}")]
    Io(String),
    #[error("TLS certificate failure: {0}")]
    Certificate(String),
    #[error("transport failure: {0}")]
    Transport(String),
    #[error("HTTP response body exceeds {limit} bytes")]
    ResponseTooLarge { limit: usize },
    #[error("download length mismatch: expected {expected}, received {actual}")]
    DownloadLengthMismatch { expected: u64, actual: u64 },
}

pub trait AuthTransport: Send + Sync {
    #[allow(non_snake_case)]
    fn Send(&self, request: AuthRequest) -> Result<AuthHttpResponse, AuthTransportError>;

    /// Send a request while bounding the response body retained in memory.
    ///
    /// Implementations that can stream the response should override this
    /// method. The default keeps source compatibility for small test/custom
    /// transports and enforces the same result limit after their existing
    /// `Send` implementation returns.
    #[allow(non_snake_case)]
    fn SendBounded(
        &self,
        request: AuthRequest,
        max_body_bytes: usize,
    ) -> Result<AuthHttpResponse, AuthTransportError> {
        let response = self.Send(request)?;
        if response.body.len() > max_body_bytes {
            return Err(AuthTransportError::ResponseTooLarge {
                limit: max_body_bytes,
            });
        }
        Ok(response)
    }

    #[allow(non_snake_case)]
    fn Download(
        &self,
        request: AuthRequest,
        sink: &mut dyn Write,
    ) -> Result<u64, AuthTransportError>;

    /// 下载完整文件并限制写入字节数；已有测试/自定义传输可沿用 Download 实现。
    #[allow(non_snake_case)]
    fn DownloadExact(
        &self,
        request: AuthRequest,
        sink: &mut dyn Write,
        expected: u64,
    ) -> Result<u64, AuthTransportError> {
        let mut bounded = ExactDownloadWriter::new(sink, expected);
        let reported = self.Download(request, &mut bounded)?;
        bounded.finish(reported)
    }
}

#[derive(Clone, Debug)]
pub struct RustlsTransportConfig {
    pub base_url: String,
    pub ca_pem: Option<Vec<u8>>,
    pub client_cert_pem: Option<Vec<u8>>,
    pub client_key_pem: Option<Vec<u8>>,
}

pub struct RustlsTransport {
    base_url: String,
    agent: ureq::Agent,
    download_agent: ureq::Agent,
}

/// Keep authenticated and material-catalog requests from pinning an owner
/// thread forever when a peer accepts a connection but stops responding.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(15);
// main 的文件流式传输使用独立超时；不能用大文件下载策略放宽普通 JSON 请求。
const DOWNLOAD_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const DOWNLOAD_READ_TIMEOUT: Duration = Duration::from_secs(20);
const DOWNLOAD_WRITE_TIMEOUT: Duration = Duration::from_secs(20);

struct ExactDownloadWriter<'a> {
    sink: &'a mut dyn Write,
    expected: u64,
    written: u64,
}

impl<'a> ExactDownloadWriter<'a> {
    fn new(sink: &'a mut dyn Write, expected: u64) -> Self {
        Self {
            sink,
            expected,
            written: 0,
        }
    }

    fn finish(self, reported: u64) -> Result<u64, AuthTransportError> {
        if self.written != self.expected {
            return Err(AuthTransportError::DownloadLengthMismatch {
                expected: self.expected,
                actual: self.written,
            });
        }
        if reported != self.written {
            return Err(AuthTransportError::DownloadLengthMismatch {
                expected: self.written,
                actual: reported,
            });
        }
        Ok(self.written)
    }
}

impl Write for ExactDownloadWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() as u64 > self.expected - self.written {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "download body exceeds expected size",
            ));
        }
        let written = self.sink.write(bytes)?;
        self.written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.sink.flush()
    }
}

fn require_download_length(
    content_length: Option<&str>,
    expected: u64,
) -> Result<(), AuthTransportError> {
    if let Some(content_length) = content_length {
        let actual = content_length.trim().parse::<u64>().map_err(|_| {
            AuthTransportError::Transport("invalid download Content-Length".to_owned())
        })?;
        if actual != expected {
            return Err(AuthTransportError::DownloadLengthMismatch { expected, actual });
        }
    }
    Ok(())
}

fn require_http_200(status: u16) -> Result<(), AuthTransportError> {
    if status == 200 {
        Ok(())
    } else {
        Err(AuthTransportError::Transport(format!("HTTP {status}")))
    }
}

fn read_bounded_body(
    reader: &mut dyn Read,
    max_body_bytes: usize,
) -> Result<Vec<u8>, AuthTransportError> {
    let read_limit = max_body_bytes
        .checked_add(1)
        .ok_or(AuthTransportError::ResponseTooLarge {
            limit: max_body_bytes,
        })?;
    let mut body = Vec::with_capacity(read_limit.min(64 * 1024));
    reader
        .take(read_limit as u64)
        .read_to_end(&mut body)
        .map_err(|error| AuthTransportError::Io(error.to_string()))?;
    if body.len() > max_body_bytes {
        Err(AuthTransportError::ResponseTooLarge {
            limit: max_body_bytes,
        })
    } else {
        Ok(body)
    }
}

impl RustlsTransport {
    pub fn new(config: RustlsTransportConfig) -> Result<Self, AuthTransportError> {
        Self::new_with_timeouts(config, DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT)
    }

    fn new_with_timeouts(
        config: RustlsTransportConfig,
        connect_timeout: Duration,
        read_timeout: Duration,
    ) -> Result<Self, AuthTransportError> {
        let mut roots = rustls::RootCertStore::empty();
        if let Some(ca_pem) = config.ca_pem {
            let certs = rustls_pemfile::certs(&mut Cursor::new(ca_pem))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| AuthTransportError::Certificate(e.to_string()))?;
            if certs.is_empty() {
                return Err(AuthTransportError::Certificate(
                    "CA PEM contains no certificates".to_owned(),
                ));
            }
            for cert in certs {
                roots
                    .add(cert)
                    .map_err(|e| AuthTransportError::Certificate(e.to_string()))?;
            }
        } else {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
        let tls = match (config.client_cert_pem, config.client_key_pem) {
            (Some(cert), Some(key)) => {
                let certs = rustls_pemfile::certs(&mut Cursor::new(cert))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| AuthTransportError::Certificate(e.to_string()))?;
                let private_key = rustls_pemfile::private_key(&mut Cursor::new(key))
                    .map_err(|e| AuthTransportError::Certificate(e.to_string()))?
                    .ok_or_else(|| {
                        AuthTransportError::Certificate(
                            "client key PEM contains no private key".to_owned(),
                        )
                    })?;
                builder
                    .with_client_auth_cert(certs, private_key)
                    .map_err(|e| AuthTransportError::Certificate(e.to_string()))?
            }
            (None, None) => builder.with_no_client_auth(),
            _ => {
                return Err(AuthTransportError::Certificate(
                    "client certificate and key must be supplied together".to_owned(),
                ))
            }
        };
        let tls = Arc::new(tls);
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .timeout_connect(connect_timeout)
            .timeout_read(read_timeout)
            .tls_config(Arc::clone(&tls))
            .build();
        let download_agent = ureq::AgentBuilder::new()
            .redirects(0)
            .timeout_connect(DOWNLOAD_CONNECT_TIMEOUT)
            .timeout_read(DOWNLOAD_READ_TIMEOUT)
            .timeout_write(DOWNLOAD_WRITE_TIMEOUT)
            .tls_config(tls)
            .build();
        Ok(Self {
            base_url: config.base_url.trim_end_matches('/').to_owned(),
            agent,
            download_agent,
        })
    }

    fn execute(&self, request: &AuthRequest) -> Result<ureq::Response, AuthTransportError> {
        self.execute_with_agent(&self.agent, request)
    }

    fn execute_with_agent(
        &self,
        agent: &ureq::Agent,
        request: &AuthRequest,
    ) -> Result<ureq::Response, AuthTransportError> {
        let url = format!("{}{}", self.base_url, request.path);
        let mut call = agent.request(request.method.as_str(), &url);
        for (name, value) in &request.headers {
            call = call.set(name, value);
        }
        let result = if request.body.is_empty() {
            call.call()
        } else {
            call.send_bytes(&request.body)
        };
        match result {
            Ok(response) | Err(ureq::Error::Status(_, response)) => Ok(response),
            Err(error) => {
                if let ureq::Error::Transport(ref transport) = error {
                    // Do not log the URL, headers, credentials or response body.
                    crate::espframe_log!(
                        "auth.transport.error",
                        "kind={:?} source={}",
                        transport.kind(),
                        std::error::Error::source(transport)
                            .map(|source| source.to_string())
                            .unwrap_or_default()
                    );
                }
                Err(AuthTransportError::Transport(error.to_string()))
            }
        }
    }
}

impl AuthTransport for RustlsTransport {
    fn Send(&self, request: AuthRequest) -> Result<AuthHttpResponse, AuthTransportError> {
        let response = self.execute(&request)?;
        let status = response.status();
        let headers = response
            .headers_names()
            .into_iter()
            .map(|name| {
                let value = response.header(&name).unwrap_or("").to_owned();
                (name, value)
            })
            .collect();
        let mut body = Vec::new();
        response
            .into_reader()
            .read_to_end(&mut body)
            .map_err(|error| AuthTransportError::Io(error.to_string()))?;
        Ok(AuthHttpResponse {
            status,
            headers,
            body,
        })
    }

    fn SendBounded(
        &self,
        request: AuthRequest,
        max_body_bytes: usize,
    ) -> Result<AuthHttpResponse, AuthTransportError> {
        let response = self.execute(&request)?;
        let status = response.status();
        let headers = response
            .headers_names()
            .into_iter()
            .map(|name| {
                let value = response.header(&name).unwrap_or("").to_owned();
                (name, value)
            })
            .collect();
        let mut reader = response.into_reader();
        let body = read_bounded_body(&mut reader, max_body_bytes)?;
        Ok(AuthHttpResponse {
            status,
            headers,
            body,
        })
    }

    fn Download(
        &self,
        request: AuthRequest,
        sink: &mut dyn Write,
    ) -> Result<u64, AuthTransportError> {
        let response = self.execute_with_agent(&self.download_agent, &request)?;
        require_http_200(response.status())?;
        let mut reader = response.into_reader();
        std::io::copy(&mut reader, sink).map_err(|error| AuthTransportError::Io(error.to_string()))
    }

    fn DownloadExact(
        &self,
        request: AuthRequest,
        sink: &mut dyn Write,
        expected: u64,
    ) -> Result<u64, AuthTransportError> {
        let response = self.execute_with_agent(&self.download_agent, &request)?;
        require_http_200(response.status())?;
        // 与 main 一样，在响应头长度不符时拒绝，不向目标文件写入响应正文。
        require_download_length(response.header("Content-Length"), expected)?;
        let mut reader = response.into_reader();
        let mut bounded = ExactDownloadWriter::new(sink, expected);
        let copied = std::io::copy(&mut reader, &mut bounded)
            .map_err(|error| AuthTransportError::Io(error.to_string()))?;
        bounded.finish(copied)
    }
}

#[cfg(test)]
mod tests {
    use super::{read_bounded_body, require_http_200, AuthTransport, AuthTransportError};
    use std::io::{self, Read};
    use std::net::TcpListener;
    use std::thread;
    use std::time::{Duration, Instant};

    fn download_request() -> super::AuthRequest {
        super::AuthRequest {
            method: super::AuthMethod::Get,
            path: "/model".to_owned(),
            headers: vec![("Accept-Encoding".to_owned(), "identity".to_owned())],
            body: Vec::new(),
        }
    }

    fn serve_download(
        response: &'static [u8],
        json_read_timeout: Duration,
        body_delay: Duration,
    ) -> (super::RustlsTransport, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            use std::io::Write;
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            assert!(request.starts_with(b"GET /model HTTP/1.1\r\n"));
            let split = response
                .windows(4)
                .position(|bytes| bytes == b"\r\n\r\n")
                .unwrap()
                + 4;
            stream.write_all(&response[..split]).unwrap();
            if !body_delay.is_zero() {
                thread::sleep(body_delay);
            }
            // 长度头被拒绝时客户端可能已关闭连接。
            let _ = stream.write_all(&response[split..]);
        });
        let transport = super::RustlsTransport::new_with_timeouts(
            super::RustlsTransportConfig {
                base_url: format!("http://{address}"),
                ca_pem: None,
                client_cert_pem: None,
                client_key_pem: None,
            },
            Duration::from_millis(100),
            json_read_timeout,
        )
        .unwrap();
        (transport, server)
    }

    #[test]
    fn exact_download_default_checks_written_count_and_preserves_sink_limit() {
        struct MockDownload {
            body: &'static [u8],
            reported: u64,
        }
        impl AuthTransport for MockDownload {
            fn Send(
                &self,
                _: super::AuthRequest,
            ) -> Result<super::AuthHttpResponse, AuthTransportError> {
                unreachable!()
            }
            fn Download(
                &self,
                _: super::AuthRequest,
                sink: &mut dyn std::io::Write,
            ) -> Result<u64, AuthTransportError> {
                sink.write_all(self.body)
                    .map_err(|error| AuthTransportError::Io(error.to_string()))?;
                Ok(self.reported)
            }
        }
        for (body, reported, success) in [
            (&b"data"[..], 4, true),
            (&b"dat"[..], 3, false),
            (&b"excess"[..], 6, false),
            (&b"dat"[..], 4, false),
            (&b"data"[..], 3, false),
        ] {
            let mut sink = Vec::new();
            let result =
                MockDownload { body, reported }.DownloadExact(download_request(), &mut sink, 4);
            assert_eq!(result.is_ok(), success);
            assert!(sink.len() <= 4);
        }
    }

    #[test]
    fn exact_download_rejects_header_mismatch_before_writing_body() {
        for response in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\ndat"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nexcess"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: invalid\r\nConnection: close\r\n\r\ndata"[..],
            &b"HTTP/1.1 206 Partial Content\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata"
                [..],
        ] {
            let (transport, server) =
                serve_download(response, Duration::from_secs(1), Duration::ZERO);
            let mut sink = Vec::new();
            assert!(transport
                .DownloadExact(download_request(), &mut sink, 4)
                .is_err());
            assert!(sink.is_empty());
            server.join().unwrap();
        }
    }

    #[test]
    fn exact_download_checks_chunked_and_close_delimited_lengths() {
        for (response, success) in [
            (&b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata"[..], true),
            (&b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nda\r\n2\r\nta\r\n0\r\n\r\n"[..], true),
            (&b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\ndat\r\n0\r\n\r\n"[..], false),
            (&b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\nexcess\r\n0\r\n\r\n"[..], false),
            (&b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\ndata"[..], true),
            (&b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\ndat"[..], false),
            (&b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndat"[..], false),
        ] {
            let (transport, server) =
                serve_download(response, Duration::from_secs(1), Duration::ZERO);
            let mut sink = Vec::new();
            let result = transport.DownloadExact(download_request(), &mut sink, 4);
            assert_eq!(result.is_ok(), success, "{result:?}");
            assert!(sink.len() <= 4);
            if success {
                assert_eq!(sink, b"data");
            }
            server.join().unwrap();
        }
    }

    #[test]
    fn download_has_its_own_read_timeout_instead_of_json_timeout() {
        let (transport, server) = serve_download(
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata",
            Duration::from_millis(10),
            Duration::from_millis(100),
        );
        let mut sink = Vec::new();
        assert_eq!(
            transport
                .DownloadExact(download_request(), &mut sink, 4)
                .unwrap(),
            4
        );
        assert_eq!(sink, b"data");
        server.join().unwrap();
    }

    struct CountingReader {
        bytes: Vec<u8>,
        offset: usize,
        requested: Vec<usize>,
    }

    impl CountingReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                bytes,
                offset: 0,
                requested: Vec::new(),
            }
        }
    }

    impl Read for CountingReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.requested.push(output.len());
            if self.offset == self.bytes.len() {
                return Ok(0);
            }
            let count = output.len().min(self.bytes.len() - self.offset);
            output[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
            self.offset += count;
            Ok(count)
        }
    }

    #[test]
    fn download_accepts_only_exact_http_200() {
        assert!(require_http_200(200).is_ok());
        for status in [199, 201, 204, 299, 300] {
            assert!(require_http_200(status).is_err(), "accepted HTTP {status}");
        }
    }

    #[test]
    fn bounded_body_stops_at_limit_plus_one_without_reading_complete_response() {
        let mut reader = CountingReader::new(b"abcdef".to_vec());
        let result = read_bounded_body(&mut reader, 4);

        assert!(matches!(
            result,
            Err(AuthTransportError::ResponseTooLarge { limit: 4 })
        ));
        assert_eq!(reader.offset, 5, "reader must stop after limit + 1 bytes");
        assert_eq!(reader.requested.len(), 1);
    }

    #[test]
    fn rustls_transport_bounds_connect_and_read_waits() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            use std::io::{Read, Write};
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: keep-alive\r\n\r\n",
                )
                .unwrap();
            let mut byte = [0_u8; 1];
            let _ = stream.read(&mut byte);
        });

        let transport = super::RustlsTransport::new_with_timeouts(
            super::RustlsTransportConfig {
                base_url: format!("http://{address}"),
                ca_pem: None,
                client_cert_pem: None,
                client_key_pem: None,
            },
            Duration::from_millis(100),
            Duration::from_millis(100),
        )
        .unwrap();
        let started = Instant::now();
        let result = transport.SendBounded(
            super::AuthRequest {
                method: super::AuthMethod::Get,
                path: "/hang".to_owned(),
                headers: Vec::new(),
                body: Vec::new(),
            },
            1024,
        );
        assert!(result.is_err(), "read timeout must be reported");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "transport waited past configured read timeout"
        );
        server.join().unwrap();
    }
}
