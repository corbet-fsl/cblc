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
    /// Member route: a blinded settlement pass, issued under the member's session.
    IssueSettlementPass {
        grant: AdmissionGrant,
        authorization: DeviceAuthorization,
        request: crate::settlement::SettlementPassRequest,
    },
    /// Anonymous route, no member session: stage one deposit with its settlement token.
    StageSettlement {
        submission: crate::settlement::SettlementSubmission,
    },
    /// Anonymous route: post the obligation tag of a verified `Post` presentation.
    /// `expected_binding` is computed by the host from its own request, never taken from
    /// the client.
    PostObligation {
        presentation: crate::extensions::VoucherPresentation,
        #[serde(with = "hex_bytes")]
        #[cfg_attr(feature = "schema", schemars(with = "String"))]
        proof: Vec<u8>,
        expected_binding: [u8; 32],
    },
    /// Anonymous route: verify an `Issue` presentation against the current voucher epoch
    /// and spend its allowance units. Same binding rule as `PostObligation`.
    CheckVoucherEpoch {
        presentation: crate::extensions::VoucherPresentation,
        #[serde(with = "hex_bytes")]
        #[cfg_attr(feature = "schema", schemars(with = "String"))]
        proof: Vec<u8>,
        expected_binding: [u8; 32],
    },
}

impl AccountServiceRequest {
    /// Routes that carry no member grant and must be reachable without a session.
    pub fn is_anonymous(&self) -> bool {
        matches!(
            self,
            Self::StageSettlement { .. }
                | Self::PostObligation { .. }
                | Self::CheckVoucherEpoch { .. }
        )
    }
}

/// Lower-case hex for proof and pass bytes: far smaller than a JSON number array.
pub(crate) mod hex_bytes {
    use data_encoding::HEXLOWER;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&HEXLOWER.encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        HEXLOWER
            .decode(text.as_bytes())
            .map_err(serde::de::Error::custom)
    }
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
    /// The blinded settlement pass, ready for the member to unblind.
    SettlementPass {
        #[serde(with = "hex_bytes")]
        #[cfg_attr(feature = "schema", schemars(with = "String"))]
        pass: Vec<u8>,
    },
    /// Durable staging result of an anonymous deposit; a replay is an error, not a status.
    Settlement(crate::settlement::SettlementStatus),
    /// The obligation tag is now waiting in the bond mailbox.
    Posted,
    /// The issue presentation verified and its slices are spent.
    VoucherEpoch,
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
    /// Lineage epoch of this recipient key. A replacement of the stored key must carry a strictly
    /// greater epoch than the stored one (an unreplaced legacy entry counts as epoch 0).
    pub lineage_epoch: u64,
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
        "cblc.record-recipient.v2",
        request.community,
        request.owner,
        request.recipient_key,
        request.chat_public_key,
        request.lineage_epoch,
        request.issued_at,
        request.expires_at
    ]))
    .map_err(|_| Error::InvalidInput)
}
