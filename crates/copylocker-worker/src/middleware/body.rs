use std::fmt;
use std::io::Read;

use futures_util::StreamExt;
use worker::{Error, Request};

const MAX_CLIENT_BODY: usize = copylocker_types::MAX_BODY_BYTES;
const MAX_COMPRESSED_BODY: usize = 64 * 1024;

#[derive(Debug)]
pub(crate) enum BodyError {
    InvalidContentLength,
    MissingBody,
    Read(Error),
    TooLarge,
    UnsupportedEncoding,
    UnsupportedMediaType,
    InvalidCompressedBody,
}

impl fmt::Display for BodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidContentLength => "invalid Content-Length header",
            Self::MissingBody => "request body is missing",
            Self::Read(_) => "request body could not be read",
            Self::TooLarge => "request body exceeds the size limit",
            Self::UnsupportedEncoding => "unsupported Content-Encoding",
            Self::UnsupportedMediaType => "Content-Type must be application/cbor",
            Self::InvalidCompressedBody => "request body compression is invalid",
        })
    }
}

impl std::error::Error for BodyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read(error) => Some(error),
            _ => None,
        }
    }
}

pub(crate) async fn read_cbor(request: &mut Request) -> Result<Vec<u8>, BodyError> {
    validate_content_type(request)?;
    let encoding = content_encoding(request)?;
    let wire_limit = match encoding {
        Encoding::Identity => MAX_CLIENT_BODY,
        Encoding::Gzip | Encoding::Brotli => MAX_COMPRESSED_BODY,
    };
    validate_content_length(request, wire_limit)?;
    let wire = read_stream(request, wire_limit).await?;

    match encoding {
        Encoding::Identity => Ok(wire),
        Encoding::Gzip => read_decompressed(flate2::read::MultiGzDecoder::new(wire.as_slice())),
        Encoding::Brotli => read_decompressed(brotli::Decompressor::new(wire.as_slice(), 4096)),
    }
}

pub(crate) async fn read_raw(request: &mut Request, limit: usize) -> Result<Vec<u8>, BodyError> {
    validate_content_length(request, limit)?;
    read_stream(request, limit).await
}

async fn read_stream(request: &mut Request, limit: usize) -> Result<Vec<u8>, BodyError> {
    let mut stream = request.stream().map_err(|error| match error {
        Error::RustError(message) if message == "no body for request" => BodyError::MissingBody,
        other => BodyError::Read(other),
    })?;
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(BodyError::Read)?;
        let length = bytes
            .len()
            .checked_add(chunk.len())
            .ok_or(BodyError::TooLarge)?;
        if length > limit {
            return Err(BodyError::TooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Encoding {
    Identity,
    Gzip,
    Brotli,
}

fn validate_content_type(request: &Request) -> Result<(), BodyError> {
    let value = request
        .headers()
        .get("Content-Type")
        .map_err(BodyError::Read)?
        .ok_or(BodyError::UnsupportedMediaType)?;
    let media_type = value
        .split_once(';')
        .map_or(value.as_str(), |(media_type, _)| media_type)
        .trim();
    if media_type.eq_ignore_ascii_case("application/cbor") {
        Ok(())
    } else {
        Err(BodyError::UnsupportedMediaType)
    }
}

fn content_encoding(request: &Request) -> Result<Encoding, BodyError> {
    let value = request
        .headers()
        .get("Content-Encoding")
        .map_err(BodyError::Read)?;
    match value.as_deref().map(str::trim) {
        None | Some("") => Ok(Encoding::Identity),
        Some(value) if value.eq_ignore_ascii_case("identity") => Ok(Encoding::Identity),
        Some(value) if value.eq_ignore_ascii_case("gzip") => Ok(Encoding::Gzip),
        Some(value) if value.eq_ignore_ascii_case("br") => Ok(Encoding::Brotli),
        Some(_) => Err(BodyError::UnsupportedEncoding),
    }
}

fn validate_content_length(request: &Request, limit: usize) -> Result<(), BodyError> {
    let Some(value) = request
        .headers()
        .get("Content-Length")
        .map_err(BodyError::Read)?
    else {
        return Ok(());
    };
    let length = value
        .parse::<usize>()
        .map_err(|_| BodyError::InvalidContentLength)?;
    if length > limit {
        Err(BodyError::TooLarge)
    } else {
        Ok(())
    }
}

fn read_decompressed(reader: impl Read) -> Result<Vec<u8>, BodyError> {
    let limit = u64::try_from(MAX_CLIENT_BODY)
        .map_err(|_| BodyError::TooLarge)?
        .saturating_add(1);
    let mut output = Vec::new();
    reader
        .take(limit)
        .read_to_end(&mut output)
        .map_err(|_| BodyError::InvalidCompressedBody)?;
    if output.len() > MAX_CLIENT_BODY {
        Err(BodyError::TooLarge)
    } else {
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::{read_decompressed, BodyError, MAX_CLIENT_BODY};

    #[test]
    fn gzip_decompression_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&vec![0; MAX_CLIENT_BODY + 1])?;
        let compressed = encoder.finish()?;

        let result = read_decompressed(flate2::read::MultiGzDecoder::new(compressed.as_slice()));
        assert!(matches!(result, Err(BodyError::TooLarge)));
        Ok(())
    }

    #[test]
    fn brotli_decompression_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let mut compressed = Vec::new();
        {
            let mut encoder = brotli::CompressorWriter::new(&mut compressed, 4096, 3, 20);
            encoder.write_all(&vec![0; MAX_CLIENT_BODY + 1])?;
        }

        let result = read_decompressed(brotli::Decompressor::new(compressed.as_slice(), 4096));
        assert!(matches!(result, Err(BodyError::TooLarge)));
        Ok(())
    }
}
