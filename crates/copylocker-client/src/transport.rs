use core::fmt;
use core::future::Future;
use core::pin::Pin;
use std::time::Duration;

#[cfg(feature = "transport-reqwest")]
use futures_util::StreamExt;

/// HTTP methods used by the client protocol.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HttpMethod {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
}

/// One bounded HTTP request.
pub struct TransportRequest {
    /// Method.
    pub method: HttpMethod,
    /// Absolute endpoint URL.
    pub url: String,
    /// Request headers.
    pub headers: Vec<(String, String)>,
    /// Opaque CBOR body.
    pub body: Vec<u8>,
    /// Complete request timeout.
    pub timeout: Duration,
    /// Maximum response bytes after transfer decoding.
    pub max_response_bytes: usize,
}

impl fmt::Debug for TransportRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("header_count", &self.headers.len())
            .field("body_len", &self.body.len())
            .field("body", &"<redacted>")
            .field("timeout", &self.timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

/// One fully bounded HTTP response.
pub struct TransportResponse {
    /// HTTP status.
    pub status: u16,
    /// Raw `Content-Type` header.
    pub content_type: Option<String>,
    /// Raw `X-CL-Proto` header.
    pub protocol_version: Option<String>,
    /// Parsed `Retry-After` delta seconds, when present.
    pub retry_after: Option<u32>,
    /// Opaque response body.
    pub body: Vec<u8>,
}

impl fmt::Debug for TransportResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportResponse")
            .field("status", &self.status)
            .field("content_type", &self.content_type)
            .field("protocol_version", &self.protocol_version)
            .field("retry_after", &self.retry_after)
            .field("body_len", &self.body.len())
            .field("body", &"<redacted>")
            .finish()
    }
}

/// Failure below the signed protocol layer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum TransportError {
    /// Name resolution or connection failed.
    Offline,
    /// The request deadline elapsed.
    Timeout,
    /// TLS, socket, or response streaming failed.
    Failure,
    /// The response exceeded the caller's explicit bound.
    ResponseTooLarge,
    /// The request itself was malformed.
    InvalidRequest,
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Offline => "network unavailable",
            Self::Timeout => "request timed out",
            Self::Failure => "transport failed",
            Self::ResponseTooLarge => "response exceeded its size limit",
            Self::InvalidRequest => "invalid transport request",
        })
    }
}

impl std::error::Error for TransportError {}

/// Boxed future returned by [`Transport`].
pub type TransportFuture<'a> =
    Pin<Box<dyn Future<Output = Result<TransportResponse, TransportError>> + Send + 'a>>;

/// Injectable asynchronous transport.
pub trait Transport: Send + Sync {
    /// Send one request without blocking the calling thread.
    fn send(&self, request: TransportRequest) -> TransportFuture<'_>;
}

/// Default Rustls-backed transport. Redirects are never followed.
#[cfg(feature = "transport-reqwest")]
#[derive(Clone, Debug)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

#[cfg(feature = "transport-reqwest")]
impl ReqwestTransport {
    /// Build the default desktop transport.
    pub fn new() -> Result<Self, crate::LocalError> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("copylocker-client/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| crate::LocalError::TransportInitialization)?;
        Ok(Self { client })
    }

    async fn execute(
        &self,
        request: TransportRequest,
    ) -> Result<TransportResponse, TransportError> {
        if request.timeout.is_zero() || request.max_response_bytes == 0 {
            return Err(TransportError::InvalidRequest);
        }
        let method = match request.method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
        };
        let mut builder = self
            .client
            .request(method, &request.url)
            .timeout(request.timeout)
            .header(reqwest::header::ACCEPT_ENCODING, "identity");
        for (name, value) in request.headers {
            builder = builder.header(name, value);
        }
        if !request.body.is_empty() {
            builder = builder.body(request.body);
        }
        let response = builder.send().await.map_err(classify_reqwest_error)?;
        if response
            .content_length()
            .is_some_and(|length| length > request.max_response_bytes as u64)
        {
            return Err(TransportError::ResponseTooLarge);
        }

        let status = response.status().as_u16();
        let content_type = header_string(response.headers(), reqwest::header::CONTENT_TYPE);
        let protocol_version = header_string(
            response.headers(),
            reqwest::header::HeaderName::from_static("x-cl-proto"),
        );
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u32>().ok());
        let mut stream = response.bytes_stream();
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| TransportError::Failure)?;
            let next_len = body
                .len()
                .checked_add(chunk.len())
                .ok_or(TransportError::ResponseTooLarge)?;
            if next_len > request.max_response_bytes {
                return Err(TransportError::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(TransportResponse {
            status,
            content_type,
            protocol_version,
            retry_after,
            body,
        })
    }
}

#[cfg(feature = "transport-reqwest")]
impl Default for ReqwestTransport {
    fn default() -> Self {
        match Self::new() {
            Ok(transport) => transport,
            Err(_) => Self {
                client: reqwest::Client::new(),
            },
        }
    }
}

#[cfg(feature = "transport-reqwest")]
impl Transport for ReqwestTransport {
    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        Box::pin(self.execute(request))
    }
}

#[cfg(feature = "transport-reqwest")]
fn classify_reqwest_error(error: reqwest::Error) -> TransportError {
    if error.is_timeout() {
        TransportError::Timeout
    } else if error.is_connect() {
        TransportError::Offline
    } else if error.is_builder() {
        TransportError::InvalidRequest
    } else {
        TransportError::Failure
    }
}

#[cfg(feature = "transport-reqwest")]
fn header_string(
    headers: &reqwest::header::HeaderMap,
    name: reqwest::header::HeaderName,
) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    #[test]
    fn request_and_response_debug_hide_cbor_bytes() {
        let request = TransportRequest {
            method: HttpMethod::Post,
            url: String::from("https://license.example/v1/activate"),
            headers: Vec::new(),
            body: b"license-secret".to_vec(),
            timeout: Duration::from_secs(1),
            max_response_bytes: 1024,
        };
        let response = TransportResponse {
            status: 200,
            content_type: Some(String::from("application/cbor")),
            protocol_version: Some(String::from("1")),
            retry_after: None,
            body: b"credential-secret".to_vec(),
        };
        let request_debug = format!("{request:?}");
        let response_debug = format!("{response:?}");
        assert!(request_debug.contains("redacted"));
        assert!(!request_debug.contains("license-secret"));
        assert!(response_debug.contains("redacted"));
        assert!(!response_debug.contains("credential-secret"));
    }

    #[tokio::test]
    async fn redirects_are_disabled_in_the_default_client() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 2_048];
            let bytes_read = stream.read(&mut request).unwrap();
            assert!(String::from_utf8_lossy(&request[..bytes_read]).starts_with("GET /start "));
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{address}/final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).unwrap();
        });

        let transport = ReqwestTransport::new().unwrap();
        let response = transport
            .send(TransportRequest {
                method: HttpMethod::Get,
                url: format!("http://{address}/start"),
                headers: Vec::new(),
                body: Vec::new(),
                timeout: Duration::from_secs(2),
                max_response_bytes: 1_024,
            })
            .await
            .unwrap();
        server.join().unwrap();

        assert_eq!(response.status, 302);
        assert!(response.body.is_empty());
    }
}
