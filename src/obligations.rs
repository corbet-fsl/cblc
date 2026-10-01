//! Authenticated observation used only to prepare complete obligation ingestion.
use crate::{
    Error,
    accounting::{AccountStatusRequest, account_status_bytes},
    extensions::{Inbox, PendingObligation},
};
use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Device signature transcript. A status-query signature cannot authorize this read.
pub fn request_bytes(request: &AccountStatusRequest) -> Result<Vec<u8>, Error> {
    if request.request_id.is_some() {
        return Err(Error::InvalidInput);
    }
    let mut bytes = b"cblc.obligations.request.v1\0".to_vec();
    bytes.extend_from_slice(&account_status_bytes(request)?);
    Ok(bytes)
}

pub fn request_digest(request: &AccountStatusRequest) -> Result<[u8; 32], Error> {
    let mut bytes = request_bytes(request)?;
    bytes.extend_from_slice(&czkp::decode::<64>(&request.signature)?);
    Ok(Sha256::digest(bytes).into())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObligationsResponse {
    pub request_digest: [u8; 32],
    pub observed_at: u64,
    pub inbox: Inbox,
    pub entries: Vec<PendingObligation>,
    pub signature: String,
}

pub(crate) fn response_bytes(response: &ObligationsResponse) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(&(
        "cblc.obligations.response.v1",
        response.request_digest,
        response.observed_at,
        &response.inbox,
        &response.entries,
    ))
    .map_err(|_| Error::InvalidInput)
}

/// Check a response to the exact signed request. This is an observation, never a
/// spend/record permission or a guarantee that no later obligation has arrived.
pub fn verify_response(
    request: &AccountStatusRequest,
    response: &ObligationsResponse,
    operator_key: &[u8; 32],
    now: u64,
) -> Result<(), Error> {
    if response.request_digest != request_digest(request)? || response.entries.len() > 64 {
        return Err(Error::Replay);
    }
    if response.observed_at < request.issued_at
        || response.observed_at > now
        || now >= request.expires_at
    {
        return Err(Error::Expired);
    }
    czkp::signature(
        &BASE64URL_NOPAD.encode(operator_key),
        &response_bytes(response)?,
        &response.signature,
    )
}
