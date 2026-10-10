//! Original account-owned recipient registration for the common record epoch.
//! Registration grants no record proof, frozen frontier or listing authority.
use super::*;

const RECIPIENT_PREFIX: &[u8] = b"record-recipient:v1:";

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

fn recipient_key(owner: &[u8; 32]) -> Vec<u8> {
    [RECIPIENT_PREFIX, owner.as_slice()].concat()
}

impl<V: AccountProofVerifier> AccountLedger<V> {
    /// Register once, or idempotently repeat the SAME member-wide recipient.
    /// A different key needs an explicit future custody migration; device loss
    /// must not silently rotate it. All equal passkeys derive the same key.
    pub fn register_record_recipient(
        &mut self,
        grant: &AdmissionGrant,
        authorization: &DeviceAuthorization,
        request: &RecipientRequest,
        clock: impl Fn() -> u64,
    ) -> Result<(), Error> {
        let clock = observed_clock(self.observed_time.clone(), clock);
        let bytes = recipient_bytes(request)?;
        if request.community != self.community
            || decode::<32>(&grant.member_id)? != request.owner
            || request.chat_public_key != grant.chat_public_key
        {
            return Err(Error::Admission);
        }
        if request.expires_at - request.issued_at > self.policy.max_authorization_seconds {
            return Err(Error::Expired);
        }
        let before = clock();
        check_time(before, 0)?;
        verify_admission(grant, &self.trust, before)?;
        verify_device_authorization(authorization, grant, before)?;
        signature(&request.chat_public_key, &bytes, &request.signature)?;
        let mut tx = self.connection.transaction()?;
        let now = clock();
        check_time(now, before.max(clock_floor(&mut tx)?))?;
        check_config(&mut tx, &self.config)?;
        verify_admission(grant, &self.trust, now)?;
        verify_device_authorization(authorization, grant, now)?;
        if now < request.issued_at || now >= request.expires_at {
            return Err(Error::Expired);
        }
        check_root(
            &mut tx,
            &request.owner,
            &decode::<32>(&authorization.root_public_key)?,
        )?;
        // An accepted account MUST already exist. check_root alone permits a
        // fresh genesis, which cannot authorize a recipient registry entry.
        tx.get::<Frontier>(&key(1, &[&request.owner]))?
            .ok_or(Error::Admission)?;
        let key = recipient_key(&request.owner);
        if let Some(old) = tx.get::<[u8; 32]>(&key)? {
            if old != request.recipient_key {
                return Err(Error::Replay);
            }
        } else {
            tx.put(&key, &request.recipient_key)?;
        }
        tx.commit_before(&CommitDeadline::new(
            &clock,
            now,
            request
                .expires_at
                .min(grant.expires_at)
                .min(authorization.expires_at),
        ))
    }
}
