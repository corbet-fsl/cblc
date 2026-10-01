//! Production Budget over the maintained real throttle and memory store.
use super::*;

fn limits() -> ExtensionLimits {
    ExtensionLimits {
        global_burst: 3,
        subject_burst: 1,
        replenish: Duration::from_secs(3600),
        maximum_keys: NonZeroUsize::new(4).unwrap(),
    }
}

#[test]
fn invalid_host_limits_or_namespace_are_refused() {
    for bad in [
        ExtensionLimits {
            global_burst: 0,
            ..limits()
        },
        ExtensionLimits {
            subject_burst: 0,
            ..limits()
        },
        ExtensionLimits {
            replenish: Duration::ZERO,
            ..limits()
        },
    ] {
        assert!(matches!(
            Budget::new("community", bad),
            Err(Error::InvalidInput)
        ));
    }
    assert!(matches!(
        Budget::new("", limits()),
        Err(Error::InvalidInput)
    ));
}

#[test]
fn actual_global_subject_and_store_capacity_fail_closed() {
    let budget = Budget::new("community", limits()).unwrap();
    assert_eq!(budget.check(&[1; 32]), Ok(()));
    assert_eq!(budget.check(&[1; 32]), Err(Error::Capacity));
    assert_eq!(budget.check(&[2; 32]), Ok(()));
    assert_eq!(budget.check(&[3; 32]), Err(Error::Capacity));
    let bounded = Budget::new(
        "community",
        ExtensionLimits {
            maximum_keys: NonZeroUsize::new(1).unwrap(),
            ..limits()
        },
    )
    .unwrap();
    assert_eq!(bounded.check(&[1; 32]), Err(Error::Capacity));
}
