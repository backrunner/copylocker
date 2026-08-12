use serde::Serialize;
use worker::{ByteStream, Headers, Response, Result};

use copylocker_suite::cbor::{CborValue, MapBuilder};

#[derive(Debug, Serialize)]
struct ErrorEnvelope<'a> {
    ok: bool,
    error: ErrorBody<'a>,
}

#[derive(Debug, Serialize)]
struct ErrorBody<'a> {
    code: &'a str,
    message: &'a str,
}

pub(crate) fn json<T: Serialize>(status: u16, value: &T) -> Result<Response> {
    Ok(Response::from_json(value)?.with_status(status))
}

pub(crate) fn json_no_store<T: Serialize>(status: u16, value: &T) -> Result<Response> {
    let mut response = Response::from_json(value)?.with_status(status);
    response.headers_mut().set("Cache-Control", "no-store")?;
    response
        .headers_mut()
        .set("X-Content-Type-Options", "nosniff")?;
    Ok(response)
}

pub(crate) fn api_error(status: u16, code: &str, message: &str) -> Result<Response> {
    json(
        status,
        &ErrorEnvelope {
            ok: false,
            error: ErrorBody { code, message },
        },
    )
}

pub(crate) fn api_error_no_store(status: u16, code: &str, message: &str) -> Result<Response> {
    json_no_store(
        status,
        &ErrorEnvelope {
            ok: false,
            error: ErrorBody { code, message },
        },
    )
}

pub(crate) fn cbor_stream(
    status: u16,
    stream: ByteStream,
    cache_control: &str,
) -> Result<Response> {
    let headers = cbor_headers(cache_control)?;
    Ok(Response::from_stream(stream)?
        .with_status(status)
        .with_headers(headers))
}

pub(crate) fn cbor(status: u16, body: Vec<u8>, cache_control: &str) -> Result<Response> {
    Ok(Response::from_bytes(body)?
        .with_status(status)
        .with_headers(cbor_headers(cache_control)?))
}

pub(crate) fn protocol_error(
    status: u16,
    code: u64,
    message: Option<&str>,
    retry_after: Option<u64>,
) -> Result<Response> {
    let mut body = MapBuilder::new();
    body.put(0, CborValue::Uint(code));
    body.put_opt(1, message.map(|value| CborValue::Text(value.to_owned())));
    body.put_opt(2, retry_after.map(CborValue::Uint));

    let mut response = Response::from_bytes(body.finish())?
        .with_status(status)
        .with_headers(cbor_headers("no-store")?);
    if let Some(seconds) = retry_after {
        response
            .headers_mut()
            .set("Retry-After", &seconds.to_string())?;
    }
    Ok(response)
}

fn cbor_headers(cache_control: &str) -> Result<Headers> {
    let headers = Headers::new();
    headers.set("Content-Type", "application/cbor")?;
    headers.set("Cache-Control", cache_control)?;
    headers.set("X-CL-Proto", "1")?;
    headers.set("X-Content-Type-Options", "nosniff")?;
    // The unauthenticated client protocol endpoints must be reachable from
    // browser apps on any origin (the web SDK talks to a license server on
    // its own origin). No credentials or cookies are involved, so `*` is
    // safe here; `/v1/admin/*` responses deliberately carry no CORS headers.
    headers.set("Access-Control-Allow-Origin", "*")?;
    Ok(headers)
}

/// CORS preflight answer for the client protocol endpoints. Browser POSTs
/// with `Content-Type: application/cbor` are not "simple requests" and always
/// preflight; without this handler every browser activation fails.
pub(crate) fn cors_preflight() -> Result<Response> {
    let headers = Headers::new();
    headers.set("Access-Control-Allow-Origin", "*")?;
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")?;
    headers.set(
        "Access-Control-Allow-Headers",
        "Accept, Content-Type, X-CL-Proto, Idempotency-Key",
    )?;
    headers.set("Access-Control-Max-Age", "86400")?;
    headers.set("Cache-Control", "no-store")?;
    Ok(Response::empty()?.with_status(204).with_headers(headers))
}
