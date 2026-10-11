//! Fault-injection writes used only by ledger and extension adversary scenarios.
use crate::inspection::Connection;

impl Connection {
    pub fn execute_batch(&self, sql: &str) -> Result<(), String> {
        self.run(sql, &[], true).map(|_| ())
    }
}
