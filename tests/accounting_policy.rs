//! Exercise the production policy helpers at their public bounds.

use cblc::{Error, accounting::AccountPolicy};
use czkp::MAX_INTEGER;

fn policy() -> AccountPolicy {
    AccountPolicy {
        initial_credit: 3,
        maximum_available: 6,
        outgoing_reservation: 1,
        incoming_reservation: 2,
        policy_revision: 1,
        policy_valid_from: 1,
        policy_valid_until: 10_000_000,
        newcomer_period: 100,
        rate_window: 10,
        newcomer_admissions: 3,
        maximum_admissions: 6,
        refill_period: 5,
        refill_units: 1,
        abandon_after: 20,
    }
}

#[test]
fn every_invalid_policy_is_refused_before_time_or_binding_operations() {
    for (field, value) in [
        ("maximumAvailable", 0),
        ("initialCredit", 7),
        ("outgoingReservation", 0),
        ("incomingReservation", 0),
        ("outgoingReservation", 7),
        ("incomingReservation", 7),
        ("initialCredit", 0),
        ("initialCredit", 1),
        ("newcomerAdmissions", 0),
        ("newcomerAdmissions", 7),
        ("refillUnits", 0),
        ("refillUnits", 4),
        ("abandonAfter", 9),
        ("newcomerPeriod", 0),
        ("newcomerPeriod", MAX_INTEGER + 1),
        ("rateWindow", 0),
        ("refillPeriod", 0),
        ("policyRevision", 0),
        ("policyRevision", MAX_INTEGER + 1),
        ("policyValidFrom", 0),
        ("policyValidUntil", 1),
        ("policyValidUntil", MAX_INTEGER + 1),
    ] {
        let mut encoded = serde_json::to_value(policy()).unwrap();
        encoded[field] = value.into();
        let invalid: AccountPolicy = serde_json::from_value(encoded).unwrap();
        assert_eq!(invalid.validate(), Err(Error::InvalidInput), "{field}");
        assert_eq!(invalid.proof_valid_until(100), Err(Error::InvalidInput));
        assert_eq!(invalid.reservation_deadline(100), Err(Error::InvalidInput));
        assert_eq!(invalid.capacity_at(100, 100), Err(Error::InvalidInput));
        assert_eq!(
            invalid.admission_limit_at(100, 100),
            Err(Error::InvalidInput)
        );
        assert_eq!(invalid.digest(&[1; 32]), Err(Error::InvalidInput));
        assert_eq!(invalid.state_digest(&[1; 32]), Err(Error::InvalidInput));
    }
}

#[test]
fn expired_future_and_out_of_range_clocks_never_issue_capacity() {
    let p = policy();
    for (created, now, error) in [
        (0, 100, Error::InvalidInput),
        (p.policy_valid_until + 1, 100, Error::InvalidInput),
        (100, MAX_INTEGER + 1, Error::InvalidInput),
        (111, 100, Error::ClockRollback),
        (100, 0, Error::Expired),
        (100, p.policy_valid_until, Error::Expired),
    ] {
        assert_eq!(p.capacity_at(created, now), Err(error.clone()));
        assert_eq!(p.admission_limit_at(created, now), Err(error));
    }
    assert_eq!(p.capacity_at(110, 100), Ok(3));
    assert_eq!(p.admission_limit_at(110, 100), Ok(3));
    assert_eq!(p.capacity_at(110, 209), Ok(3));
    assert_eq!(p.admission_limit_at(110, 209), Ok(3));
    assert_eq!(p.capacity_at(110, 210), Ok(6));
    assert_eq!(p.admission_limit_at(110, 210), Ok(6));
}

#[test]
fn maximum_valid_timestamps_remain_bounded_and_leave_a_settlement_interval() {
    let mut p = policy();
    p.policy_valid_until = MAX_INTEGER;
    p.newcomer_period = MAX_INTEGER;
    p.rate_window = MAX_INTEGER;
    p.refill_period = MAX_INTEGER;
    p.abandon_after = MAX_INTEGER;
    p.validate().unwrap();
    assert_eq!(p.proof_valid_until(MAX_INTEGER - 1), Ok(MAX_INTEGER));
    assert_eq!(p.reservation_deadline(MAX_INTEGER - 1), Err(Error::Expired));
    p.rate_window = 1;
    p.abandon_after = 1;
    assert_eq!(p.reservation_deadline(MAX_INTEGER - 2), Ok(MAX_INTEGER - 1));
    assert_eq!(p.reservation_deadline(MAX_INTEGER - 1), Err(Error::Expired));
    assert_eq!(p.proof_valid_until(MAX_INTEGER), Err(Error::Expired));
}
