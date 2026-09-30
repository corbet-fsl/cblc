//! Independent SQLite-file inspection, without linking two conflicting C engines.
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
pub struct Connection(PathBuf);
pub struct Row(Vec<Value>);
impl Row {
    pub fn get<I: TryInto<usize>, T: DeserializeOwned>(&self, index: I) -> Result<T, String> {
        let index = index.try_into().map_err(|_| "column index")?;
        serde_json::from_value(self.0.get(index).ok_or("missing column")?.clone())
            .map_err(|e| e.to_string())
    }
}
impl Connection {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        if !path.as_ref().is_file() {
            return Err("database must exist".into());
        }
        Ok(Self(path.as_ref().into()))
    }
    fn run(&self, sql: &str, params: &[Vec<u8>], execute: bool) -> Result<Vec<Vec<Value>>, String> {
        let mut child = Command::new("python3")
            .args(["-c", include_str!("inspect_sqlite.py")])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(
                &serde_json::to_vec(
                    &json!({"path":self.0,"sql":sql,"params":params,"execute":execute}),
                )
                .unwrap(),
            )
            .map_err(|e| e.to_string())?;
        let output = child.wait_with_output().map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into_owned());
        }
        serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())
    }
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
    pub fn execute_batch(&self, sql: &str) -> Result<(), String> {
        self.run(sql, &[], true).map(|_| ())
    }
    pub fn snapshot(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.run("SELECT key,value FROM cssr_records WHERE community_id='community.example' ORDER BY key",&[],false).unwrap().into_iter()
            .map(|row|serde_json::from_value(Value::Array(row)).unwrap()).collect()
    }
}
