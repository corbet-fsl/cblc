//! Durable original CSGN continuity, separate from economic policy or artifacts.
use super::*;

const BOOTSTRAP: &[u8] = b"admission-key-bootstrap:v1";
const HISTORY: &[u8] = b"admission-key-history:v1";
// Match the original publication continuity resource boundary. Never truncate.
const MAX_TRANSITIONS: usize = 256;
const MAX_HISTORY_BYTES: usize = 1 << 20;

/// Actual installed admission signer authority. This is host data, not a grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionKeyState {
    /// Permanent original CSGN public-ring transition revision.
    pub revision: u64,
    /// Independently configured bootstrap, or a signature-verified successor.
    pub policy_keys: csgn::KeyRing,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Bootstrap {
    format: String,
    revision: u64,
    policy_keys: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AcceptedTransition {
    revision: u64,
    verified_at: u64,
    proof: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct History {
    format: String,
    revision: u64,
    transitions: Vec<AcceptedTransition>,
}

fn bounded(history: &History) -> Result<(), Error> {
    if history.transitions.len() > MAX_TRANSITIONS
        || serde_json::to_vec(history)
            .map_err(|_| Error::Storage)?
            .len()
            > MAX_HISTORY_BYTES
    {
        return Err(Error::Capacity);
    }
    Ok(())
}

fn chain(
    bootstrap: &Bootstrap,
    history: &History,
    floor: u64,
) -> Result<Vec<AdmissionKeyState>, Error> {
    bounded(history)?;
    if bootstrap.format != "cblc.admission-key-bootstrap.v1"
        || history.format != "cblc.admission-key-history.v1"
        || bootstrap.revision > MAX_INTEGER
    {
        return Err(Error::Storage);
    }
    let mut installed = AdmissionKeyState {
        revision: bootstrap.revision,
        policy_keys: csgn::KeyRing::from_cbor(&bootstrap.policy_keys)
            .map_err(|_| Error::Storage)?,
    };
    let mut states = vec![installed.clone()];
    let mut observed = 0;
    for item in &history.transitions {
        check_time(item.verified_at, observed)?;
        if item.verified_at > floor
            || Some(item.revision) != installed.revision.checked_add(1)
            || item.revision > MAX_INTEGER
        {
            return Err(Error::Storage);
        }
        // This recorded observation authenticates history only. It never
        // refreshes an expired transition or supplies live member authority.
        let verified =
            csgn::verify_transition(&installed.policy_keys, &item.proof, item.verified_at)
                .map_err(|_| Error::Storage)?;
        if verified.revision() != item.revision
            || verified.previous() != &installed.policy_keys
            || verified.next() == verified.previous()
        {
            return Err(Error::Storage);
        }
        installed = AdmissionKeyState {
            revision: item.revision,
            policy_keys: verified.next().clone(),
        };
        observed = item.verified_at;
        states.push(installed.clone());
    }
    if history.revision != installed.revision {
        return Err(Error::Storage);
    }
    Ok(states)
}

fn read(tx: &mut Transaction<'_>) -> Result<(Bootstrap, History, Vec<AdmissionKeyState>), Error> {
    let bootstrap: Bootstrap = tx.get(BOOTSTRAP)?.ok_or(Error::UnsupportedCapability)?;
    let history: History = tx.get(HISTORY)?.ok_or(Error::Storage)?;
    let states = chain(&bootstrap, &history, clock_floor(tx)?)?;
    Ok((bootstrap, history, states))
}

pub(super) fn open(
    tx: &mut Transaction<'_>,
    keys: &csgn::KeyRing,
    new: bool,
    expected: Option<&AdmissionKeyState>,
) -> Result<Option<AdmissionKeyState>, Error> {
    let bootstrap: Option<Bootstrap> = tx.get(BOOTSTRAP)?;
    let history: Option<History> = tx.get(HISTORY)?;
    match (bootstrap, history) {
        (None, None) if new => {
            if let Some(expected) = expected {
                if expected.revision > MAX_INTEGER || &expected.policy_keys != keys {
                    return Err(Error::PolicyMismatch);
                }
                tx.put(
                    BOOTSTRAP,
                    &Bootstrap {
                        format: "cblc.admission-key-bootstrap.v1".into(),
                        revision: expected.revision,
                        policy_keys: keys.to_cbor(),
                    },
                )?;
                tx.put(
                    HISTORY,
                    &History {
                        format: "cblc.admission-key-history.v1".into(),
                        revision: expected.revision,
                        transitions: Vec::new(),
                    },
                )?;
                return Ok(Some(expected.clone()));
            }
        }
        (None, None) if expected.is_none() => {}
        (Some(bootstrap), Some(history)) => {
            let states = chain(&bootstrap, &history, clock_floor(tx)?)?;
            let current = states.last().ok_or(Error::Storage)?;
            if &current.policy_keys != keys || expected.is_some_and(|value| value != current) {
                return Err(Error::PolicyMismatch);
            }
            return Ok(states.first().cloned());
        }
        (None, None) => return Err(Error::UnsupportedCapability),
        _ => return Err(Error::Storage),
    }
    Ok(None)
}

pub(super) fn check_successor(
    tx: &mut Transaction<'_>,
    previous: &csgn::KeyRing,
    current: &csgn::KeyRing,
) -> Result<(), Error> {
    let (_, _, states) = read(tx)?;
    if states
        .last()
        .is_none_or(|value| &value.policy_keys != current)
        || !states.iter().any(|value| &value.policy_keys == previous)
    {
        return Err(Error::PolicyMismatch);
    }
    Ok(())
}

impl<V: AccountProofVerifier> AccountLedger<V> {
    /// Read the original permanent floor; missing bootstrap metadata refuses.
    pub fn admission_key_state(&mut self) -> Result<AdmissionKeyState, Error> {
        let mut tx = self.connection.transaction()?;
        check_config(&mut tx, &self.config)?;
        let (_, _, states) = read(&mut tx)?;
        if states.first() != self.admission_bootstrap.as_ref() {
            return Err(Error::PolicyMismatch);
        }
        let state = states.last().ok_or(Error::Storage)?.clone();
        if state.policy_keys != self.trust.policy_keys {
            return Err(Error::PolicyMismatch);
        }
        tx.rollback()?;
        Ok(state)
    }

    /// Adopt only an original live CSGN proof from the exact installed predecessor.
    /// The host serializes this with Policy rotation and subsequent publication.
    /// Uncertain or late commit returns no success; reload the same owner to
    /// reconcile. Exact already-applied proof retry reports installed state only.
    pub fn advance_admission_keys(
        &mut self,
        expected_revision: u64,
        proof: &[u8],
        clock: impl Fn() -> u64,
    ) -> Result<AdmissionKeyState, Error> {
        if proof.is_empty() || proof.len() > MAX_HISTORY_BYTES {
            return Err(Error::Capacity);
        }
        let clock = observed_clock(self.observed_time.clone(), clock);
        let before = clock();
        check_time(before, 0)?;
        let mut tx = self.connection.transaction()?;
        check_config(&mut tx, &self.config)?;
        let (_, mut history, states) = read(&mut tx)?;
        if states.first() != self.admission_bootstrap.as_ref() {
            return Err(Error::PolicyMismatch);
        }
        let current = states.last().ok_or(Error::Storage)?;
        if current.policy_keys != self.trust.policy_keys {
            return Err(Error::PolicyMismatch);
        }
        let now = clock();
        check_time(now, before.max(clock_floor(&mut tx)?))?;
        if expected_revision != current.revision {
            if history.transitions.last().is_some_and(|last| {
                Some(last.revision) == expected_revision.checked_add(1) && last.proof == proof
            }) {
                let state = current.clone();
                tx.rollback()?;
                check_time(clock(), now)?;
                return Ok(state);
            }
            return Err(Error::PolicyMismatch);
        }
        if history.transitions.len() == MAX_TRANSITIONS {
            return Err(Error::Capacity);
        }
        let verified = csgn::verify_transition(&current.policy_keys, proof, now)
            .map_err(|_| Error::Admission)?;
        if verified.previous() != &current.policy_keys
            || Some(verified.revision()) != current.revision.checked_add(1)
            || verified.revision() > MAX_INTEGER
            || verified.next() == verified.previous()
        {
            return Err(Error::PolicyMismatch);
        }
        // Obtain the authenticated exclusive deadline through that same
        // maintained COSE owner; never parse unsigned envelope metadata.
        let deadline = current
            .policy_keys
            .verify(proof, csgn::Kind::KeyRingTransition, now)
            .map_err(|_| Error::Admission)?
            .valid_until();
        let next = AdmissionKeyState {
            revision: verified.revision(),
            policy_keys: verified.next().clone(),
        };
        history.revision = next.revision;
        history.transitions.push(AcceptedTransition {
            revision: next.revision,
            verified_at: now,
            proof: proof.to_vec(),
        });
        bounded(&history)?;
        let mut trust = self.trust.clone();
        trust.policy_keys = next.policy_keys.clone();
        let config = config_bytes(
            &trust,
            &self.policy,
            &self.proof_scope,
            self.operator.verifying_key().to_bytes(),
            self.tuning_revision,
        )?;
        tx.put(HISTORY, &history)?;
        tx.put(b"config", &config)?;
        tx.commit_before(&CommitDeadline::new(&clock, now, deadline))?;
        let returned = clock();
        check_time(returned, now).map_err(|_| Error::Storage)?;
        if returned >= deadline {
            return Err(Error::Storage);
        }
        self.trust = trust;
        self.config = config;
        Ok(next)
    }
}

#[cfg(test)]
#[path = "../../tests/internal/admission_keys.rs"]
mod tests;
