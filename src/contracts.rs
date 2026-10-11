//! Canonical account wire values and original signature transcripts.
//! These data types do not establish admission, proof validity, or currentness.

use crate::{
    Error,
    accounting::{AccountAcceptance, AccountRequest, AccountStatusRequest, AccountStatusResponse},
    admission::{AdmissionGrant, DeviceAuthorization},
};
use czkp::{MAX_INTEGER, decode};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "action", rename_all = "camelCase", deny_unknown_fields)]
pub enum AccountServiceRequest {
    RegisterRecordRecipient {
        grant: AdmissionGrant,
        authorization: DeviceAuthorization,
        request: RecipientRequest,
    },
    Apply {
        grant: AdmissionGrant,
        authorization: DeviceAuthorization,
        request: Box<AccountRequest>,
    },
    ApplyExtended {
        grant: AdmissionGrant,
        authorization: DeviceAuthorization,
        request: Box<AccountRequest>,
        update: crate::extensions::ExtendedUpdate,
    },
    Obligations {
        grant: AdmissionGrant,
        authorization: DeviceAuthorization,
        request: AccountStatusRequest,
    },
    Status {
        grant: AdmissionGrant,
        authorization: DeviceAuthorization,
        request: AccountStatusRequest,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    tag = "action",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum AccountServiceResponse {
    /// Completion of the actual durable registration; never record authority.
    RecordRecipient {
        recipient_key: [u8; 32],
    },
    Apply(AccountAcceptance),
    Status(AccountStatusResponse),
    ApplyExtended {
        acceptance: AccountAcceptance,
        certificate: crate::extensions::StateCertificate,
        /// Original ancestry issued only in this acceptance's verified CAS.
        ancestry: Option<Box<crate::extensions::EpochAncestryCertificate>>,
    },
    Obligations(crate::obligations::ObligationsResponse),
}

/// The existing admitted account's device signs its common-root-derived recipient
/// key. This is an account enrollment operation, never a listing/contact request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecipientRequest {
    pub community: [u8; 32],
    pub owner: [u8; 32],
    pub recipient_key: [u8; 32],
    pub chat_public_key: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

/// Original device signature transcript, binding every recipient request field.
pub fn recipient_bytes(request: &RecipientRequest) -> Result<Vec<u8>, Error> {
    if request.recipient_key == [0; 32]
        || request.issued_at == 0
        || request.issued_at >= request.expires_at
        || request.expires_at > MAX_INTEGER
    {
        return Err(Error::InvalidInput);
    }
    decode::<32>(&request.chat_public_key)?;
    serde_json::to_vec(&serde_json::json!([
        "cblc.record-recipient.v1",
        request.community,
        request.owner,
        request.recipient_key,
        request.chat_public_key,
        request.issued_at,
        request.expires_at
    ]))
    .map_err(|_| Error::InvalidInput)
}
