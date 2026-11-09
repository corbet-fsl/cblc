//! Scalar queries and fault injection used by the ledger SQL scenarios only.
use super::inspection::Connection;
use serde::de::DeserializeOwned;
use serde_json::Value;

pub struct Row(Vec<Value>);
impl Row {
    pub fn get<I: TryInto<usize>, T: DeserializeOwned>(&self, index: I) -> Result<T, String> {
        let index = index.try_into().map_err(|_| "column index")?;
        serde_json::from_value(self.0.get(index).ok_or("missing column")?.clone())
            .map_err(|e| e.to_string())
    }
}
impl Connection {
    pub fn query_row<T>(
        &self,
        sql: &str,
        params: impl AsRef<[Vec<u8>]>,
        read: impl FnOnce(&Row) -> Result<T, String>,
    ) -> Result<T, String> {
        let row = self
            .run(sql, params.as_ref(), false)?
            .into_iter()
            .next()
            .ok_or("no row")?;
        read(&Row(row))
    }
}
