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

/// The instant `millis` after the Unix epoch (before it, when negative).
/// Where there is no system clock, such as WebAssembly in a browser, the
/// caller supplies the time with this; an out-of-range value is the epoch.
pub fn from_unix_millis(millis: i64) -> Instant {
    let nanos = i128::from(millis) * 1_000_000;
    Instant(OffsetDateTime::from_unix_timestamp_nanos(nanos).unwrap_or(OffsetDateTime::UNIX_EPOCH))
}

/// The current instant, from the system clock. On `wasm32-unknown-unknown`
/// the standard library has no clock and this panics: use
/// [`from_unix_millis`] with a time the host supplies.
pub fn now() -> Instant {
    Instant(OffsetDateTime::now_utc())
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

impl Instant {
    /// This instant dropped to a whole number of milliseconds, which is the
    /// precision [`format`] writes.
    pub fn truncated_to_millis(self) -> Instant {
        let nanos = self.0.nanosecond() / 1_000_000 * 1_000_000;
        Instant(self.0.replace_nanosecond(nanos).unwrap_or(self.0))
    }

    /// This instant moved `millis` later (earlier, when negative); an
    /// instant out of the representable range stays as it is.
    pub fn plus_millis(self, millis: i64) -> Instant {
        Instant(
            self.0
                .checked_add(::time::Duration::milliseconds(millis))
                .unwrap_or(self.0),
        )
    }
}
