use std::fs;
use std::path::Path;

use copylocker_suite::{AttrValue, DeviceAttrs, EnvClass};

use super::{combined, command_output, read_text};

pub(super) fn collect() -> DeviceAttrs {
    let machine_id = read_text("/etc/machine-id").or_else(|| read_text("/var/lib/dbus/machine-id"));
    let product_uuid = read_text("/sys/class/dmi/id/product_uuid");
    let board_serial = read_text("/sys/class/dmi/id/board_serial");
    let dmi_identity = combined(&[product_uuid, board_serial]);
    let rootfs_uuid = command_output(
        "/usr/bin/findmnt",
        &["--noheadings", "--output", "UUID", "/"],
    )
    .or_else(|| command_output("/bin/findmnt", &["--noheadings", "--output", "UUID", "/"]));
    let hostname = read_text("/etc/hostname");
    let mac_addresses = physical_mac_addresses();
    let env_class = classify_environment();

    let mut attrs = DeviceAttrs::new();
    attrs.insert("machine_id", optional_text(machine_id));
    attrs.insert("dmi_product_uuid", optional_text(dmi_identity));
    attrs.insert("rootfs_uuid", optional_text(rootfs_uuid));
    attrs.insert("mac_addrs", AttrValue::set(mac_addresses));
    attrs.insert("hostname", optional_text(hostname));
    attrs.set_env_class(env_class);
    attrs
}

fn optional_text(value: Option<String>) -> AttrValue {
    value.map_or(AttrValue::Absent, |value| AttrValue::text(&value))
}

fn physical_mac_addresses() -> Vec<String> {
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_str()?;
            if name == "lo" || is_virtual_interface(&entry.path()) {
                return None;
            }
            read_text(entry.path().join("address"))
        })
        .collect()
}

fn is_virtual_interface(path: &Path) -> bool {
    path.canonicalize()
        .ok()
        .is_some_and(|path| path.to_string_lossy().contains("/virtual/"))
}

fn classify_environment() -> EnvClass {
    if Path::new("/.dockerenv").exists()
        || Path::new("/run/.containerenv").exists()
        || read_text("/proc/1/cgroup").is_some_and(|value| {
            ["docker", "containerd", "kubepods", "lxc", "podman"]
                .iter()
                .any(|marker| value.contains(marker))
        })
    {
        return EnvClass::Container;
    }

    let dmi = combined(&[
        read_text("/sys/class/dmi/id/sys_vendor"),
        read_text("/sys/class/dmi/id/product_name"),
    ])
    .unwrap_or_default()
    .to_ascii_lowercase();
    let cpu_hypervisor = read_text("/proc/cpuinfo")
        .is_some_and(|value| value.lines().any(|line| line.contains(" hypervisor")));
    let virtual_dmi = [
        "qemu",
        "kvm",
        "vmware",
        "virtualbox",
        "parallels",
        "hyper-v",
        "microsoft corporation|virtual machine",
    ]
    .iter()
    .any(|marker| dmi.contains(marker));
    if cpu_hypervisor || virtual_dmi {
        EnvClass::VirtualMachine
    } else {
        EnvClass::Bare
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_text_preserves_missing_values_explicitly() {
        assert_eq!(optional_text(None), AttrValue::Absent);
        assert_eq!(
            optional_text(Some(" HOST ".into())),
            AttrValue::text("host")
        );
    }
}
