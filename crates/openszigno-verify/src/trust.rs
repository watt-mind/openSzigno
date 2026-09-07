//! Injected I/O: the clock, the trust source, and the revocation source.
//!
//! This crate performs no I/O of its own. Everything that would need a
//! filesystem, a network, or a wall clock arrives through one of these traits,
//! which is what makes "offline by default" a structural property rather than a
//! runtime flag someone can forget to check.

use serde::Serialize;

/// Seconds since the Unix epoch. The whole crate uses this rather than a date
/// type so that no dependency can quietly change how time is compared.
pub type UnixTime = i64;

/// Where the validation time came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeSource {
    SystemClock,
    Requested,
}

/// The validation time.
pub trait Clock {
    fn unix_time(&self) -> UnixTime;
}

/// The wall clock, used when `--at` is absent.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_time(&self) -> UnixTime {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs() as i64)
    }
}

/// A fixed validation time, used by `--at` and by every test.
#[derive(Clone, Copy, Debug)]
pub struct FixedClock(pub UnixTime);

impl Clock for FixedClock {
    fn unix_time(&self) -> UnixTime {
        self.0
    }
}

/// Certificates the caller trusts, and extra certificates for path building.
///
/// An empty source is legitimate and means "I have no anchors": every chain
/// check is then `unknown` and the verdict `indeterminate`, never `valid`.
pub trait TrustSource {
    /// DER-encoded trust anchors.
    fn anchors(&self) -> &[Vec<u8>];
    /// DER-encoded intermediate CA certificates offered for path building.
    fn intermediates(&self) -> &[Vec<u8>];
    /// Whether the caller configured a store at all, which is different from
    /// configuring an empty one.
    fn configured(&self) -> bool {
        true
    }
}

/// No trust store at all.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoTrust;

impl TrustSource for NoTrust {
    fn anchors(&self) -> &[Vec<u8>] {
        &[]
    }

    fn intermediates(&self) -> &[Vec<u8>] {
        &[]
    }

    fn configured(&self) -> bool {
        false
    }
}

/// An in-memory trust store, which is what the CLI's `--trust-store DIR` loader
/// and every test produce.
#[derive(Clone, Debug, Default)]
pub struct MemoryTrustStore {
    anchors: Vec<Vec<u8>>,
    intermediates: Vec<Vec<u8>>,
}

impl MemoryTrustStore {
    pub fn new(anchors: Vec<Vec<u8>>, intermediates: Vec<Vec<u8>>) -> Self {
        Self {
            anchors,
            intermediates,
        }
    }
}

impl TrustSource for MemoryTrustStore {
    fn anchors(&self) -> &[Vec<u8>] {
        &self.anchors
    }

    fn intermediates(&self) -> &[Vec<u8>] {
        &self.intermediates
    }
}

/// The revocation policy actually applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationPolicy {
    /// Nothing is fetched and no cached data is consulted. Phase 1 only.
    NotChecked,
}

/// Revocation data. Phase 1 has exactly one implementation, which reports that
/// nothing was checked; the trait exists so that phase 3 can add CRL and OCSP
/// sources without changing the pipeline's shape.
pub trait RevocationSource {
    fn policy(&self) -> RevocationPolicy;
}

/// The phase-1 revocation source: none.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoRevocation;

impl RevocationSource for NoRevocation {
    fn policy(&self) -> RevocationPolicy {
        RevocationPolicy::NotChecked
    }
}

/// Parse an RFC 3339 timestamp into seconds since the Unix epoch.
///
/// Deliberately strict and dependency-free: `YYYY-MM-DDThh:mm:ss` followed by
/// `Z` or a numeric offset, with an optional fractional second that is
/// truncated. Anything else is rejected rather than guessed at, because the
/// validation time decides whether a certificate had expired.
pub fn parse_rfc3339(text: &str) -> Option<UnixTime> {
    let bytes = text.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        let slice = text.get(range)?;
        if !slice.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        slice.parse::<i64>().ok()
    };
    if bytes[4] != b'-' || bytes[7] != b'-' || !matches!(bytes[10], b'T' | b't') {
        return None;
    }
    if bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    let year = number(0..4)?;
    let month = number(5..7)?;
    let day = number(8..10)?;
    let hour = number(11..13)?;
    let minute = number(14..16)?;
    let second = number(17..19)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    let mut rest = &text[19..];
    if let Some(stripped) = rest.strip_prefix('.') {
        let digits = stripped.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        rest = &stripped[digits..];
    }
    let offset = match rest.as_bytes().first()? {
        b'Z' | b'z' if rest.len() == 1 => 0,
        sign @ (b'+' | b'-') if rest.len() == 6 => {
            let sign = if *sign == b'-' { -1 } else { 1 };
            let hours = rest.get(1..3)?.parse::<i64>().ok()?;
            let minutes = rest.get(4..6)?.parse::<i64>().ok()?;
            if rest.as_bytes()[3] != b':' || hours > 23 || minutes > 59 {
                return None;
            }
            sign * (hours * 3600 + minutes * 60)
        }
        _ => return None,
    };

    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

/// Format seconds since the Unix epoch as an RFC 3339 UTC timestamp.
pub fn format_rfc3339(time: UnixTime) -> String {
    let days = time.div_euclid(86_400);
    let seconds = time.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3600,
        (seconds / 60) % 60,
        seconds % 60
    )
}

/// Howard Hinnant's `days_from_civil`, which is exact for the proleptic
/// Gregorian calendar and needs no table.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
}
