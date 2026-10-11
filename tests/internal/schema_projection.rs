//! Reject valid constraints that the OpenAPI representation cannot preserve.
use super::*;
use serde_json::json;

#[test]
fn unsupported_validation_keywords_never_silently_widen_a_schema() {
    for schema in [
        json!({"type":"integer", "not":{"enum":[0]}}),
        json!({"type":"integer", "if":{"minimum":1}, "then":{"maximum":2},
            "else":{"enum":[0]}}),
        json!({"type":"object", "properties":{"amount":{
            "type":"integer", "not":{"enum":[0]}}}}),
    ] {
        let original = jsonschema::validator_for(&schema).unwrap();
        if schema["type"] == "object" {
            assert!(!original.is_valid(&json!({"amount":0})));
            assert!(original.is_valid(&json!({"amount":1})));
        } else {
            assert!(!original.is_valid(&json!(3)) || !original.is_valid(&json!(0)));
            assert!(original.is_valid(&json!(1)));
        }
        assert!(lossless(schema).is_none());
    }
}

#[test]
fn supported_nested_constraints_roundtrip_without_numeric_normalization() {
    let value = json!({"type":"object", "additionalProperties":false,
        "required":["amount"], "properties":{"amount":{
            "type":"integer", "minimum":0, "maximum":65535}}});
    let projected = lossless(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(projected).unwrap(), value);
    let validator = jsonschema::validator_for(&value).unwrap();
    assert!(validator.is_valid(&json!({"amount":65535})));
    for invalid in [
        json!({"amount":65536}),
        json!({"amount":-1}),
        json!({"amount":null}),
        json!({"amount":1,"extra":true}),
    ] {
        assert!(!validator.is_valid(&invalid));
    }
    let exact = json!({"type":"integer", "minimum":0, "maximum":u64::MAX});
    let original = jsonschema::validator_for(&exact).unwrap();
    assert!(original.is_valid(&json!(u64::MAX)));
    if let Some(projected) = lossless(exact.clone()) {
        assert_eq!(serde_json::to_value(projected).unwrap(), exact);
    } else {
        // A platform whose OpenAPI numeric model cannot carry this exact bound
        // must refuse generation instead of rounding it into a wider schema.
        assert!(std::mem::size_of::<usize>() < std::mem::size_of::<u64>());
    }
}
