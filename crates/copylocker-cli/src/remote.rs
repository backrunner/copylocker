use std::io::Read as _;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Subcommand};
use reqwest::blocking::Client;
use reqwest::{Method, Url};
use serde_json::{json, Value};
use zeroize::Zeroize as _;

use crate::{project, CliError, Output};

const DEFAULT_TOKEN_ENV: &str = "COPYLOCKER_ADMIN_TOKEN";
const API_URL_ENV: &str = "COPYLOCKER_API_URL";
const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, Args)]
pub(crate) struct ConnectionArgs {
    /// Directory in or below an initialized CopyLocker project.
    #[arg(long, global = true, default_value = ".")]
    pub(crate) project: PathBuf,
    /// Override the API origin from copylocker.json or COPYLOCKER_API_URL.
    #[arg(long, global = true)]
    pub(crate) api_url: Option<String>,
    /// Environment variable containing the Admin bearer token.
    #[arg(long, global = true)]
    pub(crate) admin_token_env: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct RequestArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    #[command(subcommand)]
    command: RequestCommand,
}

#[derive(Debug, Subcommand)]
enum RequestCommand {
    /// Send an authenticated read-only request to /v1/admin/*.
    Get {
        /// Absolute Admin API path, including an optional query string.
        path: String,
    },
}

#[derive(Debug)]
pub(crate) struct AdminClient {
    client: Client,
    base_url: Url,
    token: String,
    token_env: String,
    product_id: Option<String>,
}

#[derive(Debug)]
pub(crate) struct ApiResponse {
    pub(crate) status: u16,
    pub(crate) value: Value,
}

impl Drop for AdminClient {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl AdminClient {
    pub(crate) fn connect(args: &ConnectionArgs) -> Result<Self, CliError> {
        let config_path = project::find_project_config(&args.project);
        let config = config_path
            .as_deref()
            .map(project::load_project_config)
            .transpose()?;
        let api_url = args
            .api_url
            .clone()
            .or_else(|| std::env::var(API_URL_ENV).ok())
            .or_else(|| config.as_ref().and_then(|value| value.api_url.clone()))
            .ok_or_else(|| {
                CliError::new(
                    "api_url_missing",
                    format!(
                        "set --api-url, {API_URL_ENV}, or api_url in an initialized copylocker.json"
                    ),
                )
            })?;
        let base_url = parse_api_url(&api_url)?;
        let token_env = args
            .admin_token_env
            .clone()
            .or_else(|| config.as_ref().map(|value| value.admin_token_env.clone()))
            .unwrap_or_else(|| DEFAULT_TOKEN_ENV.to_owned());
        if !valid_env_name(&token_env) {
            return Err(CliError::new(
                "invalid_token_env",
                "Admin token environment variable names must use ASCII letters, digits, and underscores",
            ));
        }
        let token = std::env::var(&token_env).map_err(|_| {
            CliError::new(
                "admin_token_missing",
                format!("set {token_env} to the Admin bearer token"),
            )
        })?;
        if !valid_token_format(&token) {
            return Err(CliError::new(
                "invalid_admin_token",
                format!("{token_env} does not contain a valid clat_ Admin token"),
            ));
        }
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("copylocker-cli/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| {
                CliError::new(
                    "http_client_failed",
                    format!("failed to initialize the Admin HTTP client: {error}"),
                )
            })?;
        Ok(Self {
            client,
            base_url,
            token,
            token_env,
            product_id: config.map(|value| value.product_id),
        })
    }

    pub(crate) fn product_id(&self, explicit: Option<&str>) -> Result<String, CliError> {
        let value = explicit
            .map(str::to_owned)
            .or_else(|| self.product_id.clone())
            .ok_or_else(|| {
                CliError::new(
                    "product_id_missing",
                    "pass --product or run the command in an initialized CopyLocker project",
                )
            })?;
        validate_identifier("product id", &value, 128)?;
        Ok(value)
    }

    pub(crate) fn token_env(&self) -> &str {
        &self.token_env
    }

    pub(crate) fn get(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<ApiResponse, CliError> {
        self.send(Method::GET, path, query, None, None)
    }

    pub(crate) fn post(
        &self,
        path: &str,
        query: &[(&str, String)],
        body: &Value,
        idempotency_key: Option<&str>,
    ) -> Result<ApiResponse, CliError> {
        self.send(Method::POST, path, query, Some(body), idempotency_key)
    }

    pub(crate) fn patch(
        &self,
        path: &str,
        body: &Value,
        idempotency_key: &str,
    ) -> Result<ApiResponse, CliError> {
        self.send(Method::PATCH, path, &[], Some(body), Some(idempotency_key))
    }

    pub(crate) fn delete(
        &self,
        path: &str,
        query: &[(&str, String)],
        idempotency_key: Option<&str>,
    ) -> Result<ApiResponse, CliError> {
        self.send(Method::DELETE, path, query, None, idempotency_key)
    }

    fn send(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
        idempotency_key: Option<&str>,
    ) -> Result<ApiResponse, CliError> {
        let mut url = self.endpoint(path)?;
        if !query.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (name, value) in query {
                pairs.append_pair(name, value);
            }
        }
        if let Some(key) = idempotency_key {
            validate_idempotency_key(key)?;
        }
        let mut request = self
            .client
            .request(method, url)
            .bearer_auth(&self.token)
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::ACCEPT_ENCODING, "identity");
        if let Some(key) = idempotency_key {
            request = request.header("Idempotency-Key", key);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().map_err(|error| {
            CliError::new(
                "network_error",
                format!("Admin API request failed: {error}"),
            )
        })?;
        let status = response.status();
        let content_length = response.content_length();
        if content_length.is_some_and(|length| length > MAX_RESPONSE_BYTES) {
            return Err(CliError::new(
                "response_too_large",
                "Admin API response exceeds the 4 MiB CLI limit",
            ));
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                CliError::new(
                    "response_read_failed",
                    format!("failed to read the Admin API response: {error}"),
                )
            })?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_RESPONSE_BYTES {
            return Err(CliError::new(
                "response_too_large",
                "Admin API response exceeds the 4 MiB CLI limit",
            ));
        }
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| {
            CliError::new(
                "invalid_api_response",
                format!(
                    "Admin API returned HTTP {} with invalid JSON",
                    status.as_u16()
                ),
            )
        })?;
        if !status.is_success() {
            return Err(api_error(status.as_u16(), &value));
        }
        Ok(ApiResponse {
            status: status.as_u16(),
            value,
        })
    }

    fn endpoint(&self, path: &str) -> Result<Url, CliError> {
        if !path.starts_with("/v1/admin/")
            || path.contains("\\")
            || path.contains('#')
            || path.bytes().any(|byte| byte.is_ascii_control())
            || path.split('/').any(|segment| segment == "..")
        {
            return Err(CliError::new(
                "invalid_admin_path",
                "raw requests must use an absolute /v1/admin/* path without traversal",
            ));
        }
        let url = self
            .base_url
            .join(path.trim_start_matches('/'))
            .map_err(|_| {
                CliError::new(
                    "invalid_admin_path",
                    "Admin API path could not be joined to the configured origin",
                )
            })?;
        if !url.path().starts_with("/v1/admin/") || url.fragment().is_some() {
            return Err(CliError::new(
                "invalid_admin_path",
                "raw requests must remain below /v1/admin/ after URL normalization",
            ));
        }
        Ok(url)
    }
}

pub(crate) fn run_request(args: &RequestArgs) -> Result<Output, CliError> {
    let client = AdminClient::connect(&args.connection)?;
    match &args.command {
        RequestCommand::Get { path } => {
            let response = client.get(path, &[])?;
            Ok(output("request.get", response))
        }
    }
}

pub(crate) fn output_result(
    command: &str,
    response: Result<ApiResponse, CliError>,
) -> Result<Output, CliError> {
    response.map(|response| output(command, response))
}

pub(crate) fn output(command: &str, mut response: ApiResponse) -> Output {
    if let Some(object) = response.value.as_object_mut() {
        object.insert("command".to_owned(), Value::String(command.to_owned()));
        object.insert(
            "http_status".to_owned(),
            Value::from(u64::from(response.status)),
        );
    } else {
        response.value = json!({
            "ok": true,
            "command": command,
            "http_status": response.status,
            "result": response.value
        });
    }
    let human = serde_json::to_string_pretty(&response.value)
        .unwrap_or_else(|_| format!("{command} completed with HTTP {}", response.status));
    Output {
        human,
        json: response.value,
    }
}

pub(crate) fn validate_identifier(
    kind: &str,
    value: &str,
    max_length: usize,
) -> Result<(), CliError> {
    if !value.is_empty()
        && value.len() <= max_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Ok(())
    } else {
        Err(CliError::new(
            "invalid_identifier",
            format!(
                "{kind} must be 1-{max_length} ASCII letters, digits, hyphens, underscores, or dots"
            ),
        ))
    }
}

pub(crate) fn validate_hex_id(kind: &str, value: &str, bytes: usize) -> Result<(), CliError> {
    if value.len() == bytes.saturating_mul(2) && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
    {
        Ok(())
    } else {
        Err(CliError::new(
            "invalid_identifier",
            format!(
                "{kind} must contain exactly {} hexadecimal characters",
                bytes * 2
            ),
        ))
    }
}

pub(crate) fn validate_idempotency_key(value: &str) -> Result<(), CliError> {
    if !value.is_empty() && value.len() <= 128 && value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        Ok(())
    } else {
        Err(CliError::new(
            "invalid_idempotency_key",
            "idempotency keys must be 1-128 printable non-whitespace ASCII characters",
        ))
    }
}

fn parse_api_url(value: &str) -> Result<Url, CliError> {
    let mut url = Url::parse(value).map_err(|_| {
        CliError::new(
            "invalid_api_url",
            "API URL must be an absolute HTTP(S) origin",
        )
    })?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(CliError::new(
            "invalid_api_url",
            "API URL must be an HTTP(S) origin without credentials, path, query, or fragment",
        ));
    }
    url.set_path("/");
    Ok(url)
}

fn valid_env_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

pub(crate) fn valid_token_format(value: &str) -> bool {
    let Some(payload) = value
        .as_bytes()
        .get(5..)
        .filter(|_| value.len() == 48 && value.starts_with("clat_"))
    else {
        return false;
    };
    payload.iter().all(|byte| base64url_value(*byte).is_some())
        && payload
            .last()
            .and_then(|byte| base64url_value(*byte))
            .is_some_and(|value| value & 0b11 == 0)
}

fn base64url_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

fn api_error(status: u16, value: &Value) -> CliError {
    let code = value
        .pointer("/error/code")
        .and_then(Value::as_str)
        .unwrap_or("admin_api_error");
    let message = value
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or("Admin API request failed");
    CliError::new(code, format!("Admin API returned HTTP {status}: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_origins_reject_credentials_and_paths() {
        assert!(parse_api_url("https://licenses.example.test").is_ok());
        assert!(parse_api_url("http://127.0.0.1:8787/").is_ok());
        assert!(parse_api_url("https://user@example.test").is_err());
        assert!(parse_api_url("https://example.test/prefix").is_err());
    }

    #[test]
    fn idempotency_keys_match_the_worker_contract() {
        assert!(validate_idempotency_key("release-2026.07:feature:1").is_ok());
        assert!(validate_idempotency_key("contains space").is_err());
        assert!(validate_idempotency_key(&"x".repeat(129)).is_err());
    }

    #[test]
    fn token_format_matches_worker_canonical_base64url() {
        assert!(valid_token_format(&format!("clat_{}", "A".repeat(43))));
        assert!(!valid_token_format(&format!("clat_{}B", "A".repeat(42))));
        assert!(!valid_token_format(&format!("clat_{}=", "A".repeat(42))));
    }
}
