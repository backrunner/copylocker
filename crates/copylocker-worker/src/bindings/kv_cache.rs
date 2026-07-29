use worker::{ByteStream, Env, Result};

const CACHE_BINDING: &str = "CACHE";

pub(crate) async fn stream(env: &Env, key: &str) -> Result<Option<ByteStream>> {
    let value = env.kv(CACHE_BINDING)?.get(key).stream().await?;
    Ok(value.map(ByteStream::from))
}
