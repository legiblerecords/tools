//! Instants, for `published_at`, `updated_at` and key dates: RFC 3339 in any
//! offset, compared as instants.

use ::time::format_description::well_known::Rfc3339;
use ::time::{OffsetDateTime, UtcOffset};

/// A point in time. Two instants written with different offsets are equal
/// when they are the same moment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(OffsetDateTime);

/// Parses an RFC 3339 date-time with any offset.
pub fn parse(s: &str) -> Result<Instant, String> {
    OffsetDateTime::parse(s, &Rfc3339)
        .map(Instant)
        .map_err(|e| format!("{s:?} is not an RFC 3339 date-time: {e}"))
}

/// Writes an instant in UTC with millisecond precision and a `Z`.
pub fn format(i: Instant) -> String {
    let t = i.0.to_offset(UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
        t.millisecond()
    )
}
