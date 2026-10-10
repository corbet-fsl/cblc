use super::*;

#[test]
fn ledger_clock_numeric_bounds_and_floor_are_checked() {
    for now in [0, MAX_INTEGER + 1, u64::MAX] {
        assert_eq!(check_time(now, 0), Err(Error::ClockRollback));
    }
    assert_eq!(check_time(100, 101), Err(Error::ClockRollback));
    for (now, floor) in [(1, 0), (100, 100), (MAX_INTEGER, MAX_INTEGER)] {
        assert_eq!(check_time(now, floor), Ok(()));
    }
}

#[test]
fn observations_survive_new_calls_and_invalid_samples_cannot_lower_or_poison_them() {
    let observed = Arc::new(AtomicU64::new(0));
    assert_eq!(observed_clock(observed.clone(), || 150)(), 150);
    for now in [140, 0, MAX_INTEGER + 1, u64::MAX] {
        assert_eq!(observed_clock(observed.clone(), || now)(), 0);
        assert_eq!(observed.load(Ordering::Acquire), 150);
    }
    assert_eq!(observed_clock(observed.clone(), || 150)(), 150);
    assert_eq!(observed_clock(observed.clone(), || 160)(), 160);
    assert_eq!(observed_clock(observed.clone(), || 155)(), 0);
    assert_eq!(observed.load(Ordering::Acquire), 160);
    assert_eq!(
        observed_clock(observed.clone(), || MAX_INTEGER)(),
        MAX_INTEGER
    );
    assert_eq!(observed_clock(observed.clone(), || MAX_INTEGER - 1)(), 0);
}
