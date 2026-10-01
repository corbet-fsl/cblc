//! Serde-compatible owner schemas projected into the maintained OpenAPI model.
//! Utoipa's tagged-enum derive loses container `deny_unknown_fields`; Schemars
//! reads those annotations from the canonical types instead of copied DTOs.
use crate::accounting_service::{AccountServiceRequest, AccountServiceResponse};
use schemars::{JsonSchema, generate::SchemaSettings, transform};
use utoipa::openapi::{RefOr, Schema};

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
    serde_json::from_value(schema.into())
        .expect("canonical accounting schemas use supported OpenAPI vocabulary")
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
