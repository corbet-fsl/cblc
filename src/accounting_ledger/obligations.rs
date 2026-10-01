//! Signed complete-inbox reads under the existing admission and device authority.
use super::*;
use crate::obligations::ObligationsResponse;
impl<V: AccountProofVerifier> AccountLedger<V> {
    fn authenticated_read<T>(
        &mut self,
        grant: &AdmissionGrant,
        authorization: &DeviceAuthorization,
        request: &AccountStatusRequest,
        clock: impl Fn() -> u64,
        read: impl FnOnce(&mut Transaction<'_>, &SigningKey, u64) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let bytes = crate::obligations::request_bytes(request)?;
        if request.community != self.community
            || decode::<32>(&grant.member_id)? != request.owner
            || request.chat_public_key != grant.chat_public_key
        {
            return Err(Error::Admission);
        }
        if request.expires_at - request.issued_at > self.policy.max_authorization_seconds
            || request.expires_at > grant.expires_at
            || request.expires_at > authorization.expires_at
            || request.expires_at > self.policy.account.policy_valid_until
        {
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
        let result = read(&mut tx, &self.operator, now)?;
        tx.rollback()?;
        Ok(result)
    }

    /// Observe the exact complete obligation chain without persisting a member trace.
    /// This response prepares ingestion; only a later real proof and atomic
    /// accepted-state comparison can authorize a holder transition.
    pub fn authenticated_obligations(
        &mut self,
        grant: &AdmissionGrant,
        authorization: &DeviceAuthorization,
        request: &AccountStatusRequest,
        clock: impl Fn() -> u64,
    ) -> Result<ObligationsResponse, Error> {
        let config = self
            .extensions
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?
            .config
            .clone();
        self.authenticated_read(grant, authorization, request, clock, |tx, operator, now| {
            let stored: Option<Vec<u8>> = tx.get(b"extensions")?;
            if stored.as_ref() != Some(&config) {
                return Err(Error::UnsupportedCapability);
            }
            let (inbox, entries) = super::extensions::read_obligations(tx, request.owner)?;
            let mut response = ObligationsResponse {
                request_digest: crate::obligations::request_digest(request)?,
                observed_at: now,
                inbox,
                entries,
                signature: String::new(),
            };
            response.signature = BASE64URL_NOPAD.encode(
                &operator
                    .sign(&crate::obligations::response_bytes(&response)?)
                    .to_bytes(),
            );
            Ok(response)
        })
    }
}
