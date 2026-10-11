//! Original public economic policy and explicit host execution bounds.
use crate::{Error, accounting::AccountPolicy, admission::MAX_INTEGER};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountLedgerPolicy {
    pub account: AccountPolicy,
    pub max_authorization_seconds: u64,
    pub max_proof_bytes: usize,
    /// Common checkpoint slots have exactly this duration. Only one root can be
    /// admitted for a slot; publication is a trusted operator operation.
    pub checkpoint_period_seconds: u64,
}

impl AccountLedgerPolicy {
    /// Validate the existing host bounds and canonical economic policy.
    pub fn validate(&self) -> Result<(), Error> {
        if self.max_authorization_seconds == 0
            || self.max_authorization_seconds > MAX_INTEGER
            || self.max_proof_bytes == 0
            || self.max_proof_bytes > i32::MAX as usize
            || self.checkpoint_period_seconds == 0
            || self.checkpoint_period_seconds > MAX_INTEGER
        {
            return Err(Error::InvalidInput);
        }
        self.account.validate()
    }
}
