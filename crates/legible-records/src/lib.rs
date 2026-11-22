//! Legible Records (<https://github.com/legiblerecords/spec>): legible,
//! portable, pragmatic security records.
//!
//! - [`bundle`]: packing, opening and verifying bundles;
//! - [`short_form`]: the schema language, expanding short-form schemas to
//!   JSON Schema 2020-12 and generating them back;
//! - [`yaml`]: the restricted YAML the short form is written in;
//! - [`lint`]: checks a published type against the published subset;
//! - [`compat`]: checks that a new version of a type is compatible with the
//!   last one;
//! - [`validate`]: validates records against their types (feature
//!   `validate`).

pub mod bundle;
pub mod compat;
pub mod lint;
pub mod short_form;
#[cfg(feature = "validate")]
pub mod validate;
pub mod yaml;

/// The `$id` of `org.legiblerecords.common` version 1.
pub const COMMON_V1_ID: &str =
    "https://legiblerecords.org/schemas/org.legiblerecords.common/v1.json";

/// `org.legiblerecords.common` version 1, as published.
pub const COMMON_V1: &str = include_str!("common-v1.json");
