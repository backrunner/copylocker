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
    Ok(headers)
}
