//! The certificate issuer key ring, recorded in the ledger's own store. Artifacts pin no
//! issuer key: the host configures one, it becomes the ring's open period (retiring the
//! previous key at that time) and the signed verifier status publishes the whole ring.
use super::*;
use czkp::issuer_keys::{self, CertificateKeyPeriod};

const RING: &[u8] = b"certificate-keys";
const IDENTITY: &[u8] = b"certificate-identity";

/// The recorded ring and the community identity every accepted-state certificate binds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CertificateIssuance {
    pub ring: Vec<CertificateKeyPeriod>,
    pub identity: [u8; 32],
}

impl<V: AccountProofVerifier> AccountLedger<V> {
    /// Record `public_key` as the current issuer at `now` (a no-op when it already is) in
    /// one transaction: read the stored ring, advance it, write it back. The identity is
    /// fixed at the first call; another identity is refused.
    pub fn record_certificate_issuer(
        &mut self,
        identity: [u8; 32],
        public_key: [u8; 64],
        now: u64,
    ) -> Result<(), Error> {
        if identity == [0; 32] {
            return Err(Error::InvalidInput);
        }
        let mut tx = self.connection.transaction()?;
        check_config(&mut tx, &self.config)?;
        let stored: Option<[u8; 32]> = tx.get(IDENTITY)?;
        if stored.is_some_and(|stored| stored != identity) {
            return Err(Error::PolicyMismatch);
        }
        let ring: Vec<CertificateKeyPeriod> = tx.get(RING)?.unwrap_or_default();
        let ring = match issuer_keys::advance(&ring, &public_key, now)? {
            Some(next) => {
                tx.put(RING, &next)?;
                next
            }
            None => ring,
        };
        if stored.is_none() {
            tx.put(IDENTITY, &identity)?;
        }
        tx.commit()?;
        self.certificates = Some(CertificateIssuance { ring, identity });
        Ok(())
    }

    /// The recorded issuance, provided `issuer` is the ring's open key.
    pub(crate) fn current_issuer(
        &self,
        issuer: &cssr::certificate::CertificateIssuer,
    ) -> Result<&CertificateIssuance, Error> {
        let certificates = self.certificates.as_ref().ok_or(Error::PolicyMismatch)?;
        match certificates.ring.last() {
            Some(open) if open.valid_until.is_none() && open.public_key == issuer.public_key() => {
                Ok(certificates)
            }
            _ => Err(Error::PolicyMismatch),
        }
    }
}
