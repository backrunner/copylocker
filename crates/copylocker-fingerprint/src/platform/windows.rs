use std::env;

use copylocker_suite::{AttrValue, DeviceAttrs, EnvClass};

use super::{combined, command_output};

pub(super) fn collect() -> DeviceAttrs {
    let machine_guid = command_output(
        "reg.exe",
        &[
            "query",
            r"HKLM\SOFTWARE\Microsoft\Cryptography",
            "/v",
            "MachineGuid",
        ],
    )
    .and_then(|output| output.split_whitespace().last().map(str::to_owned));
    let cpu_id = powershell(
        "(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty ProcessorId)",
    );
    let board_serial = powershell(
        "(Get-CimInstance Win32_BaseBoard | Select-Object -First 1 -ExpandProperty SerialNumber)",
    );
    let disk_serial = powershell("(Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\" | Select-Object -First 1 -ExpandProperty VolumeSerialNumber)");
    let install_date = powershell("(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty InstallDate).ToString('O')");
    let mac_addresses: Vec<String> = powershell("Get-CimInstance Win32_NetworkAdapter -Filter \"PhysicalAdapter=True AND MACAddress IS NOT NULL\" | ForEach-Object { $_.MACAddress }")
        .map(|output| output.lines().map(str::to_owned).collect())
        .unwrap_or_default();
    let hostname = env::var("COMPUTERNAME").ok();
    let system_identity =
        powershell("$c = Get-CimInstance Win32_ComputerSystem; \"$($c.Manufacturer)|$($c.Model)\"");

    let mut attrs = DeviceAttrs::new();
    attrs.insert("machine_guid", optional_text(machine_guid));
    attrs.insert("cpu_id", optional_text(cpu_id));
    attrs.insert("board_serial", optional_text(board_serial));
    attrs.insert("disk_serial", optional_text(disk_serial));
    attrs.insert("os_install_id", optional_text(install_date));
    attrs.insert("mac_addrs", AttrValue::set(mac_addresses));
    attrs.insert("hostname", optional_text(hostname));
    attrs.set_env_class(classify_environment(system_identity.as_deref()));
    attrs
}

fn powershell(script: &str) -> Option<String> {
    command_output(
        "powershell.exe",
        &[
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ],
    )
}

fn optional_text(value: Option<String>) -> AttrValue {
    value.map_or(AttrValue::Absent, |value| AttrValue::text(&value))
}

fn classify_environment(identity: Option<&str>) -> EnvClass {
    let identity = combined(&[identity.map(str::to_owned)])
        .unwrap_or_default()
        .to_ascii_lowercase();
    if ["virtual", "vmware", "qemu", "parallels", "innotek", "xen"]
        .iter()
        .any(|marker| identity.contains(marker))
    {
        EnvClass::VirtualMachine
    } else {
        EnvClass::Bare
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_machine_markers_are_case_insensitive() {
        assert_eq!(
            classify_environment(Some("VMware, Inc.|VMware Virtual Platform")),
            EnvClass::VirtualMachine
        );
        assert_eq!(classify_environment(Some("Dell|Precision")), EnvClass::Bare);
    }
}
