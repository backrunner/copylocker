use tauri::State;

use crate::state::{CommandError, ManagedClient, StateDto};

#[tauri::command]
pub(crate) async fn cl_activate(
    key: String,
    state: State<'_, ManagedClient>,
) -> Result<(), CommandError> {
    state.get().activate(key).await
}

#[tauri::command]
pub(crate) async fn cl_deactivate(state: State<'_, ManagedClient>) -> Result<(), CommandError> {
    state.get().deactivate().await
}

/// Advisory only. Productive access goes through `cl_unseal` or `cl_challenge`.
#[tauri::command]
pub(crate) fn cl_state(state: State<'_, ManagedClient>) -> StateDto {
    state.get().state()
}

#[tauri::command]
pub(crate) fn cl_unseal(
    feature: String,
    data: Vec<u8>,
    state: State<'_, ManagedClient>,
) -> Result<Vec<u8>, CommandError> {
    state.get().unseal(&feature, &data)
}

#[tauri::command]
pub(crate) fn cl_challenge(
    input: Vec<u8>,
    state: State<'_, ManagedClient>,
) -> Result<Vec<u8>, CommandError> {
    state.get().challenge(&input)
}

#[tauri::command]
pub(crate) fn cl_offline_request(
    key: String,
    state: State<'_, ManagedClient>,
) -> Result<Vec<u8>, CommandError> {
    state.get().offline_request(&key)
}

#[tauri::command]
pub(crate) fn cl_offline_import(
    data: Vec<u8>,
    state: State<'_, ManagedClient>,
) -> Result<(), CommandError> {
    state.get().offline_import(&data)
}

#[tauri::command]
pub(crate) fn cl_import_olk(
    data: String,
    state: State<'_, ManagedClient>,
) -> Result<(), CommandError> {
    state.get().import_olk(&data)
}
