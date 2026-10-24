//! Witness that the requesting device is in the member's CURRENT device lineage.
//!
//! cblc verifies grants, device authorizations and signatures, but it owns no device registry: a
//! removed device that still holds an unexpired grant and authorization would pass every one of
//! those checks. The embedding door owns the registry. Every account-update entry point therefore
//! takes a [`CurrentDevice`], and the only way to obtain one is [`CurrentDevice::attest`], which
//! asks a [`CurrentLineage`] (the registry) about the requesting device. There is no constructor
//! that skips that question, and the witness cannot be cloned, so one lookup covers one update.
//!
//! ```compile_fail
//! // The field is private: a witness cannot be written down without asking the registry.
//! let _ = cblc::current_device::CurrentDevice { device: [7; 32] };
//! ```
//!
//! ```compile_fail
//! // The witness is not Clone: it cannot be minted once and replayed for later updates.
//! fn replay(witness: cblc::current_device::CurrentDevice) {
//!     let _again = witness.clone();
//! }
//! ```
use crate::{
    Error,
    admission::{DeviceAuthorization, decode},
};

/// The door's view of the member's current device lineage (its device registry).
pub trait CurrentLineage {
    /// True only while `device` is an Active device of the member in the current lineage.
    fn is_current(&self, device: &[u8; 32]) -> bool;
}

/// Proof that the registry listed the requesting device as current. Not `Clone`, not `Copy`.
#[derive(Debug)]
pub struct CurrentDevice {
    device: [u8; 32],
}

impl CurrentDevice {
    /// Ask the registry about the device that `authorization` names. A removed or unknown
    /// device is refused here, before any cblc state is read.
    pub fn attest(
        lineage: &dyn CurrentLineage,
        authorization: &DeviceAuthorization,
    ) -> Result<Self, Error> {
        let device = decode::<32>(&authorization.device_public_key)?;
        if !lineage.is_current(&device) {
            return Err(Error::Admission);
        }
        Ok(Self { device })
    }

    /// The witnessed device must be exactly the device the root authorized for this request.
    pub(crate) fn require(&self, authorization: &DeviceAuthorization) -> Result<(), Error> {
        if decode::<32>(&authorization.device_public_key)? != self.device {
            return Err(Error::Admission);
        }
        Ok(())
    }
}
