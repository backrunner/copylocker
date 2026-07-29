use worker::{
    durable_object, wasm_bindgen, DurableObject, Env, Request, Response, Result, SqlStorage, State,
};

use super::{ready, unavailable};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS _sql_schema_migrations (
  id INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash BLOB PRIMARY KEY,
  machine_id BLOB,
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS login_attempts (
  at INTEGER NOT NULL,
  ok INTEGER NOT NULL,
  ip_hash BLOB
);
INSERT OR IGNORE INTO _sql_schema_migrations(id) VALUES (1);
"#;

#[durable_object]
#[derive(Debug)]
pub struct AccountDO {
    initialization_error: Option<String>,
}

impl DurableObject for AccountDO {
    fn new(state: State, _env: Env) -> Self {
        let initialization_error = initialize(&state.storage().sql())
            .err()
            .map(|error| error.to_string());
        Self {
            initialization_error,
        }
    }

    async fn fetch(&self, _request: Request) -> Result<Response> {
        match self.initialization_error.as_deref() {
            Some(error) => unavailable("AccountDO", error),
            None => ready("AccountDO", 1),
        }
    }

    async fn alarm(&self) -> Result<Response> {
        Response::empty()
    }
}

fn initialize(sql: &SqlStorage) -> Result<()> {
    sql.exec(SCHEMA, None)?;
    Ok(())
}
