//! Serde-compatible owner schemas projected into the maintained OpenAPI model.
//! Utoipa's tagged-enum derive loses container `deny_unknown_fields`; Schemars
//! reads those annotations from the canonical types instead of copied DTOs.
use crate::contracts::{AccountServiceRequest, AccountServiceResponse};
use schemars::{JsonSchema, generate::SchemaSettings, transform};
use serde_json::Value;
use utoipa::openapi::{RefOr, Schema};

fn lossless(value: Value) -> Option<RefOr<Schema>> {
    let projected: RefOr<Schema> = serde_json::from_value(value.clone()).ok()?;
    // Deserialization can ignore unsupported JSON Schema keywords. Refuse a
    // projection that changes any annotation, bound, or nested constraint.
    if serde_json::to_value(&projected).ok()? != value {
        return None;
    }
    Some(projected)
}

fn schema<T: JsonSchema>() -> RefOr<Schema> {
    let schema = SchemaSettings::draft2020_12()
        .with(|settings| {
            settings.meta_schema = None;
            settings.inline_subschemas = true;
        })
        .with_transform(transform::ReplaceConstValue::default())
        .with_transform(transform::ReplaceUnevaluatedProperties::default())
        .into_generator()
        .into_root_schema_for::<T>();
    lossless(schema.into())
        .expect("canonical accounting schemas require lossless OpenAPI projection")
}

impl utoipa::PartialSchema for AccountServiceRequest {
    fn schema() -> RefOr<Schema> {
        schema::<Self>()
    }
}
impl utoipa::ToSchema for AccountServiceRequest {}

impl utoipa::PartialSchema for AccountServiceResponse {
    fn schema() -> RefOr<Schema> {
        schema::<Self>()
    }
}
impl utoipa::ToSchema for AccountServiceResponse {}

#[cfg(feature = "publication")]
impl utoipa::PartialSchema for crate::publication::PublicVerifierMaterial {
    fn schema() -> RefOr<Schema> {
        schema::<Self>()
    }
}
#[cfg(feature = "publication")]
impl utoipa::ToSchema for crate::publication::PublicVerifierMaterial {}

#[cfg(all(test, feature = "host"))]
#[path = "../tests/internal/schema_projection.rs"]
mod tests;
