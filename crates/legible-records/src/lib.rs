//! Legible Records (<https://github.com/legiblerecords/spec>): legible,
//! portable, pragmatic security records.
//!
//! - [`age`]: encrypted bundles and feeds (encrypting and decrypting need
//!   feature `age`);
//! - [`bundle`]: packing, opening and verifying bundles;
//! - [`code`]: the outcome codes readers return;
//! - [`feed`]: feed indexes, connection files, reader state and reading a
//!   feed;
//! - [`keys`]: key sets, endorsement and what a reader trusts;
//! - `net`: reading feeds and key sets over HTTPS and S3 (feature `net`);
//! - [`sign`]: Ed25519 keys, contexts and signature files;
//! - [`time`]: RFC 3339 instants;
//! - [`short_form`]: the schema language, expanding short-form schemas to
//!   JSON Schema 2020-12 and generating them back;
//! - [`yaml`]: the restricted YAML the short form is written in;
//! - [`lint`]: checks a published type against the published subset;
//! - [`compat`]: checks that a new version of a type is compatible with the
//!   last one;
//! - [`validate`]: validates records against their types (feature
//!   `validate`).

pub mod age;
pub mod bundle;
pub mod code;
pub mod compat;
pub mod feed;
pub mod keys;
pub mod lint;
#[cfg(feature = "net")]
pub mod net;
pub mod short_form;
pub mod sign;
pub mod time;
#[cfg(feature = "validate")]
pub mod validate;
pub mod yaml;

/// The `$id` of `org.legiblerecords.common` version 1.
pub const COMMON_V1_ID: &str =
    "https://legiblerecords.org/schemas/org.legiblerecords.common/v1.json";

/// `org.legiblerecords.common` version 1, as published.
pub const COMMON_V1: &str = include_str!("common-v1.json");
