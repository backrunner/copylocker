//! GitHub Actions OIDC authentication for the remote manifest signer (M4-B).
//!
//! CI builds present the OIDC JWT that `actions/checkout` workflows mint with
//! `permissions: id-token: write` as the bearer token of `POST /v1/admin/integrity/sign`.
//! Validation is fail-closed: issuer, audience, expiry, repository and ref allowlists, and an
//! RS256 signature checked with WebCrypto against the GitHub JWKS. All configuration lives in
//! plain Worker vars (nothing here is secret):
//!
//! - `INTEGRITY_OIDC_AUDIENCE` — required; OIDC is disabled without it.
//! - `INTEGRITY_OIDC_ISSUER` — defaults to `https://token.actions.githubusercontent.com`.
//! - `INTEGRITY_OIDC_REPOSITORIES` — comma-separated `owner/repo` allowlist.
//! - `INTEGRITY_OIDC_REFS` — comma-separated ref allowlist (for example
//!   `refs/heads/main`); absent means any ref of an allowed repository.
//! - `INTEGRITY_OIDC_JWKS` — inline JWKS JSON (test seam; avoids the network fetch).
//! - `INTEGRITY_OIDC_JWKS_URL` — defaults to `{issuer}/.well-known/jwks`.

use serde::Deserialize;
use worker::wasm_bindgen::{JsCast as _, JsValue};
use worker::wasm_bindgen_futures::JsFuture;
use worker::{js_sys, web_sys, Env, Error, Fetch, Headers, Request, RequestInit, Result};

const AUDIENCE_VAR: &str = "INTEGRITY_OIDC_AUDIENCE";
const ISSUER_VAR: &str = "INTEGRITY_OIDC_ISSUER";
const REPOSITORIES_VAR: &str = "INTEGRITY_OIDC_REPOSITORIES";
const REFS_VAR: &str = "INTEGRITY_OIDC_REFS";
const JWKS_VAR: &str = "INTEGRITY_OIDC_JWKS";
const JWKS_URL_VAR: &str = "INTEGRITY_OIDC_JWKS_URL";
const DEFAULT_ISSUER: &str = "https://token.actions.githubusercontent.com";
const MAX_JWT_LENGTH: usize = 8 * 1024;
const MAX_JWKS_BYTES: u64 = 64 * 1024;
const MAX_CLAIM_LENGTH: usize = 256;
/// Tolerance for `nbf`/`iat` clock skew. `exp` is strict.
const CLOCK_SKEW_SECONDS: i64 = 300;

/// A successfully authenticated CI identity.
pub(crate) struct OidcIdentity {
    repository: String,
    reference: String,
}

impl OidcIdentity {
    /// Stable audit actor, for example `oidc:octo/app`. Bounded by the claim validation below
    /// so it always fits the Admin journal's actor limit.
    pub(crate) fn actor(&self) -> String {
        format!("oidc:{}", self.repository)
    }

    pub(crate) fn repository(&self) -> &str {
        &self.repository
    }

    pub(crate) fn reference(&self) -> &str {
        &self.reference
    }
}

/// Validate a bearer token as a GitHub Actions OIDC JWT.
///
/// Returns `Ok(None)` when OIDC is not configured or the token fails any check; callers map that
/// to a uniform 401. Infrastructure failures (JWKS fetch, WebCrypto) surface as `Err`.
pub(crate) async fn authenticate(env: &Env, token: &str, now: i64) -> Result<Option<OidcIdentity>> {
    let Some(config) = Config::load(env) else {
        return Ok(None);
    };
    if token.len() > MAX_JWT_LENGTH {
        return Ok(None);
    }
    let mut segments = token.split('.');
    let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Ok(None);
    };
    let (Some(header), Some(payload), Some(signature)) = (
        base64url_decode(header_b64),
        base64url_decode(payload_b64),
        base64url_decode(signature_b64),
    ) else {
        return Ok(None);
    };
    let header = serde_json::from_slice::<Header>(&header)
        .ok()
        .filter(|header| header.alg == "RS256");
    let claims = serde_json::from_slice::<Claims>(&payload).ok();
    let (Some(header), Some(claims)) = (header, claims) else {
        return Ok(None);
    };
    let Some(kid) = header.kid.filter(|kid| valid_claim(kid)) else {
        return Ok(None);
    };

    if claims.iss != config.issuer || !claims.audience_matches(&config.audience) {
        return Ok(None);
    }
    if claims.exp <= now
        || claims.nbf.is_some_and(|nbf| nbf > now + CLOCK_SKEW_SECONDS)
        || claims.iat.is_some_and(|iat| iat > now + CLOCK_SKEW_SECONDS)
    {
        return Ok(None);
    }
    if !valid_repository(&claims.repository)
        || !valid_claim(&claims.reference)
        || !config
            .repositories
            .iter()
            .any(|allowed| allowed == &claims.repository)
        || (!config.refs.is_empty()
            && !config
                .refs
                .iter()
                .any(|allowed| allowed == &claims.reference))
    {
        return Ok(None);
    }

    let jwks = config.load_jwks().await?;
    let Some(jwk) = jwks.keys.iter().find(|key| {
        key.kid.as_deref() == Some(kid.as_str())
            && key.kty == "RSA"
            && key.use_.as_deref().is_none_or(|usage| usage == "sig")
            && key.alg.as_deref().is_none_or(|alg| alg == "RS256")
            && key.n.as_deref().is_some_and(|n| !n.is_empty())
            && key.e.as_deref().is_some_and(|e| !e.is_empty())
    }) else {
        return Ok(None);
    };
    let Some(jwk_json) = serde_json::to_string(&serde_json::json!({
        "kty": "RSA",
        "kid": kid,
        "n": jwk.n,
        "e": jwk.e,
        "alg": "RS256",
        "ext": true,
    }))
    .ok() else {
        return Ok(None);
    };
    let signed = format!("{header_b64}.{payload_b64}");
    if !verify_rs256(&jwk_json, &signature, signed.as_bytes()).await? {
        return Ok(None);
    }
    Ok(Some(OidcIdentity {
        repository: claims.repository,
        reference: claims.reference,
    }))
}

async fn verify_rs256(jwk_json: &str, signature: &[u8], data: &[u8]) -> Result<bool> {
    let global = js_sys::global();
    let crypto: web_sys::Crypto = js_sys::Reflect::get(&global, &JsValue::from_str("crypto"))
        .map_err(|_| oidc_error("Workers crypto global is unavailable"))?
        .dyn_into()
        .map_err(|_| oidc_error("Workers crypto global has an invalid type"))?;
    let subtle = crypto.subtle();
    let key_data = js_sys::JSON::parse(jwk_json)
        .map_err(|_| oidc_error("OIDC JWK could not be encoded"))?
        .unchecked_into::<js_sys::Object>();
    let algorithm =
        js_sys::JSON::parse(r#"{"name":"RSASSA-PKCS1-v1_5","hash":{"name":"SHA-256"}}"#)
            .map_err(|_| oidc_error("OIDC algorithm descriptor could not be encoded"))?
            .unchecked_into::<js_sys::Object>();
    let usages = js_sys::Array::of1(&JsValue::from_str("verify"));
    let key: web_sys::CryptoKey = JsFuture::from(
        subtle
            .import_key_with_object("jwk", &key_data, &algorithm, false, &usages)
            .map_err(|_| oidc_error("OIDC JWK import failed"))?,
    )
    .await
    .map_err(|_| oidc_error("OIDC JWK import was rejected"))?
    .dyn_into()
    .map_err(|_| oidc_error("OIDC JWK import returned an invalid key"))?;
    let verified = JsFuture::from(
        subtle
            .verify_with_object_and_u8_array_and_u8_array(&algorithm, &key, signature, data)
            .map_err(|_| oidc_error("OIDC signature verification failed"))?,
    )
    .await
    .map_err(|_| oidc_error("OIDC signature verification was rejected"))?;
    Ok(verified.is_truthy())
}

fn base64url_decode(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || value.len() % 4 == 1 {
        return None;
    }
    let mut output = Vec::with_capacity(value.len() / 4 * 3 + 3);
    let mut buffer = 0_u32;
    let mut bits = 0_u32;
    for byte in value.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => u32::from(byte - b'A'),
            b'a'..=b'z' => u32::from(byte - b'a') + 26,
            b'0'..=b'9' => u32::from(byte - b'0') + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | digit;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push(u8::try_from((buffer >> bits) & 0xff).ok()?);
        }
    }
    if bits >= 6 || (buffer & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(output)
}

fn valid_claim(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CLAIM_LENGTH
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

/// `owner/repo`, bounded by GitHub's own name limits so the audit actor stays within the
/// Admin journal's 128-character budget.
fn valid_repository(value: &str) -> bool {
    let mut parts = value.split('/');
    let (Some(owner), Some(repo), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let valid_part = |part: &str| {
        !part.is_empty()
            && part.len() <= 100
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    };
    valid_part(owner) && valid_part(repo)
}

struct Config {
    audience: String,
    issuer: String,
    repositories: Vec<String>,
    refs: Vec<String>,
    jwks_inline: Option<String>,
    jwks_url: String,
}

impl Config {
    fn load(env: &Env) -> Option<Self> {
        let audience = env.var(AUDIENCE_VAR).ok()?.to_string();
        if audience.is_empty() || audience.len() > MAX_CLAIM_LENGTH {
            return None;
        }
        let issuer = env
            .var(ISSUER_VAR)
            .map(|value| value.to_string())
            .unwrap_or_else(|_| DEFAULT_ISSUER.to_owned());
        if !issuer.starts_with("https://") {
            return None;
        }
        let list = |name: &str| -> Vec<String> {
            env.var(name)
                .map(|value| {
                    value
                        .to_string()
                        .split(',')
                        .map(str::trim)
                        .filter(|entry| valid_claim(entry))
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default()
        };
        let repositories = list(REPOSITORIES_VAR);
        if repositories.is_empty() {
            return None;
        }
        let jwks_url = env
            .var(JWKS_URL_VAR)
            .map(|value| value.to_string())
            .unwrap_or_else(|_| format!("{issuer}/.well-known/jwks"));
        let jwks_inline = env.var(JWKS_VAR).ok().map(|value| value.to_string());
        if !jwks_url.starts_with("https://") {
            return None;
        }
        Some(Self {
            audience,
            issuer,
            repositories,
            refs: list(REFS_VAR),
            jwks_inline,
            jwks_url,
        })
    }

    async fn load_jwks(&self) -> Result<Jwks> {
        let json = match &self.jwks_inline {
            Some(inline) => inline.clone(),
            None => {
                let headers = Headers::new();
                headers.set("Accept", "application/json")?;
                let mut init = RequestInit::new();
                init.with_method(worker::Method::Get).with_headers(headers);
                let request = Request::new_with_init(&self.jwks_url, &init)?;
                let mut response = Fetch::Request(request)
                    .send()
                    .await
                    .map_err(|_| oidc_error("OIDC JWKS fetch failed"))?;
                if !(200..300).contains(&response.status_code()) {
                    return Err(oidc_error("OIDC JWKS endpoint returned an error"));
                }
                let bytes = response
                    .bytes()
                    .await
                    .map_err(|_| oidc_error("OIDC JWKS body could not be read"))?;
                if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_JWKS_BYTES {
                    return Err(oidc_error("OIDC JWKS body exceeds the size limit"));
                }
                String::from_utf8(bytes)
                    .map_err(|_| oidc_error("OIDC JWKS body is not valid UTF-8"))?
            }
        };
        serde_json::from_str(&json).map_err(|_| oidc_error("OIDC JWKS payload is invalid"))
    }
}

#[derive(Debug, Deserialize)]
struct Header {
    alg: String,
    kid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Claims {
    iss: String,
    #[serde(default)]
    aud: serde_json::Value,
    exp: i64,
    nbf: Option<i64>,
    iat: Option<i64>,
    #[serde(default)]
    repository: String,
    #[serde(default, rename = "ref")]
    reference: String,
}

impl Claims {
    fn audience_matches(&self, expected: &str) -> bool {
        match &self.aud {
            serde_json::Value::String(value) => value == expected,
            serde_json::Value::Array(values) => {
                values.iter().any(|value| value.as_str() == Some(expected))
            }
            _ => false,
        }
    }
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kty: String,
    kid: Option<String>,
    #[serde(rename = "use")]
    use_: Option<String>,
    alg: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

fn oidc_error(message: &str) -> Error {
    Error::RustError(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::base64url_decode;

    #[test]
    fn base64url_decode_is_strict() {
        assert_eq!(base64url_decode("aGk"), Some(vec![b'h', b'i']));
        assert_eq!(base64url_decode("aGk="), None);
        assert_eq!(base64url_decode("a"), None);
        assert_eq!(base64url_decode(""), None);
        assert_eq!(base64url_decode("aGk+"), None);
        assert_eq!(base64url_decode("____"), Some(vec![0xff, 0xff, 0xff]));
    }
}
