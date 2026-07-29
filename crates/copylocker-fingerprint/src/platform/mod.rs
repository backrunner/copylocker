use std::process::Command;

#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::path::Path;

use copylocker_suite::DeviceAttrs;

use crate::FingerprintError;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

const MAX_SOURCE_BYTES: u64 = 64 * 1024;

#[cfg(target_os = "linux")]
pub(super) fn collect() -> Result<DeviceAttrs, FingerprintError> {
    Ok(linux::collect())
}

#[cfg(target_os = "macos")]
pub(super) fn collect() -> Result<DeviceAttrs, FingerprintError> {
    Ok(macos::collect())
}

#[cfg(target_os = "windows")]
pub(super) fn collect() -> Result<DeviceAttrs, FingerprintError> {
    Ok(windows::collect())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(super) fn collect() -> Result<DeviceAttrs, FingerprintError> {
    Err(FingerprintError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
fn read_text(path: impl AsRef<Path>) -> Option<String> {
    let path = path.as_ref();
    if path.metadata().ok()?.len() > MAX_SOURCE_BYTES {
        return None;
    }
    let mut output = String::new();
    File::open(path)
        .ok()?
        .take(MAX_SOURCE_BYTES)
        .read_to_string(&mut output)
        .ok()?;
    nonempty(output)
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .output()
        .ok()?;
    if !output.status.success() || output.stdout.len() > MAX_SOURCE_BYTES as usize {
        return None;
    }
    nonempty(String::from_utf8(output.stdout).ok()?)
}

fn nonempty(value: String) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

#[cfg(any(target_os = "macos", test))]
fn key_value(output: &str, key: &str, separator: char) -> Option<String> {
    output.lines().find_map(|line| {
        let (name, value) = line.split_once(separator)?;
        (name.trim().eq_ignore_ascii_case(key))
            .then(|| value.trim().trim_matches('"').to_owned())
            .filter(|value| !value.is_empty())
    })
}

fn combined(values: &[Option<String>]) -> Option<String> {
    let present = values
        .iter()
        .filter_map(Option::as_deref)
        .filter(|value| !value.trim().is_empty())
        .collect::<Vec<_>>();
    (!present.is_empty()).then(|| present.join("|"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_value_is_case_insensitive_and_trims_quotes() {
        let input = "Other: no\n Volume UUID: \"ABC-123\"\n";
        assert_eq!(key_value(input, "volume uuid", ':'), Some("ABC-123".into()));
    }

    #[test]
    fn combined_skips_missing_values_without_reordering() {
        assert_eq!(
            combined(&[Some("model".into()), None, Some("serial".into())]),
            Some("model|serial".into())
        );
        assert_eq!(combined(&[None, None]), None);
    }
}
