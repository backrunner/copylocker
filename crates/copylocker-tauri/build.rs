const COMMANDS: &[&str] = &[
    "cl_activate",
    "cl_deactivate",
    "cl_state",
    "cl_unseal",
    "cl_challenge",
    "cl_offline_request",
    "cl_offline_import",
    "cl_import_olk",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS).build();
}
