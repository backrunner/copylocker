use copylocker_suite::{AttrValue, DeviceAttrs, EnvClass};

use super::{combined, command_output, key_value};

const PHYSICAL_INTERFACE_PREFIXES: &[&str] = &["en"];

pub(super) fn collect() -> DeviceAttrs {
    let ioreg = command_output("/usr/sbin/ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"]);
    let model = command_output("/usr/sbin/sysctl", &["-n", "hw.model"]);
    let serial = ioreg
        .as_deref()
        .and_then(|output| ioreg_value(output, "IOPlatformSerialNumber"));
    let platform_uuid = ioreg
        .as_deref()
        .and_then(|output| ioreg_value(output, "IOPlatformUUID"));
    let volume = command_output("/usr/sbin/diskutil", &["info", "/"]);
    let boot_volume_uuid = volume
        .as_deref()
        .and_then(|output| key_value(output, "Volume UUID", ':'));
    let network = command_output("/sbin/ifconfig", &["-a"]);
    let mac_addresses = network
        .as_deref()
        .map(physical_mac_addresses)
        .unwrap_or_default();
    let hostname = command_output("/usr/sbin/scutil", &["--get", "ComputerName"])
        .or_else(|| command_output("/bin/hostname", &[]));
    let env_class = classify_environment(model.as_deref());

    let mut attrs = DeviceAttrs::new();
    attrs.insert("platform_uuid", optional_text(platform_uuid));
    attrs.insert("hw_model_serial", optional_text(combined(&[model, serial])));
    attrs.insert("boot_volume_uuid", optional_text(boot_volume_uuid));
    attrs.insert("mac_addrs", AttrValue::set(mac_addresses));
    attrs.insert("hostname", optional_text(hostname));
    attrs.set_env_class(env_class);
    attrs
}

fn optional_text(value: Option<String>) -> AttrValue {
    value.map_or(AttrValue::Absent, |value| AttrValue::text(&value))
}

fn ioreg_value(output: &str, key: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (name, value) = line.split_once('=')?;
        let name = name.trim().trim_matches('"');
        (name == key)
            .then(|| value.trim().trim_matches('"').to_owned())
            .filter(|value| !value.is_empty())
    })
}

fn physical_mac_addresses(output: &str) -> Vec<String> {
    let mut interface = None;
    let mut addresses = Vec::new();
    for line in output.lines() {
        if !line.starts_with(char::is_whitespace) {
            interface = line.split_once(':').map(|(name, _)| name);
            continue;
        }
        let Some(name) = interface else {
            continue;
        };
        if !PHYSICAL_INTERFACE_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
        {
            continue;
        }
        let mut parts = line.split_whitespace();
        if parts.next() == Some("ether") {
            if let Some(address) = parts.next() {
                addresses.push(address.to_owned());
            }
        }
    }
    addresses
}

fn classify_environment(model: Option<&str>) -> EnvClass {
    let hypervisor = command_output("/usr/sbin/sysctl", &["-n", "kern.hv_vmm_present"])
        .is_some_and(|value| value.trim() == "1");
    let virtual_model = model.is_some_and(|value| {
        let value = value.to_ascii_lowercase();
        ["virtual", "vmware", "parallels", "qemu"]
            .iter()
            .any(|marker| value.contains(marker))
    });
    if hypervisor || virtual_model {
        EnvClass::VirtualMachine
    } else {
        EnvClass::Bare
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioreg_parser_extracts_quoted_values() {
        let output = "    \"IOPlatformUUID\" = \"ABC-123\"\n\
                      \"IOPlatformSerialNumber\" = \"SERIAL\"";
        assert_eq!(
            ioreg_value(output, "IOPlatformUUID"),
            Some("ABC-123".into())
        );
        assert_eq!(
            ioreg_value(output, "IOPlatformSerialNumber"),
            Some("SERIAL".into())
        );
    }

    #[test]
    fn only_physical_en_interfaces_contribute_mac_addresses() {
        let output =
            "en0: flags=1\n\tether AA:BB:CC:DD:EE:FF\nawdl0: flags=1\n\tether 11:22:33:44:55:66\n";
        assert_eq!(
            physical_mac_addresses(output),
            vec!["AA:BB:CC:DD:EE:FF".to_owned()]
        );
    }
}
