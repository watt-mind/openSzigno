//! Injected I/O: the clock, the trust source, and the revocation source.
//!
//! This crate performs no I/O of its own. Everything that would need a
//! filesystem, a network, or a wall clock arrives through one of these traits,
//! which is what makes "offline by default" a structural property rather than a
//! runtime flag someone can forget to check.

use serde::Serialize;

use crate::codes::Check;

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

/// Where the caller's trust in one anchor came from.
///
/// The distinction is reported, never inferred: an anchor a human dropped into
/// a directory and an anchor an EU trusted list vouches for are both trusted,
/// but only the second one can make a signature *qualified*.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustAnchorOrigin {
    /// A file under `--trust-store DIR`.
    TrustStore,
    /// A service digital identity in a `--trust-list FILE`.
    TrustList,
}

/// One trust anchor and everything the caller knows about why it is trusted.
#[derive(Clone, Debug)]
pub struct TrustAnchor {
    pub der: Vec<u8>,
    pub origin: TrustAnchorOrigin,
    /// The trusted-list service this anchor is the digital identity of, when
    /// it came from a trusted list. `None` for a trust-store anchor, which is
    /// why a trust-store anchor can never yield `qualified: true`.
    pub service: Option<crate::trustlist::ServiceRecord>,
}

impl TrustAnchor {
    /// An anchor a caller supplied directly, with no qualified status.
    pub fn from_store(der: Vec<u8>) -> Self {
        Self {
            der,
            origin: TrustAnchorOrigin::TrustStore,
            service: None,
        }
    }
}

/// Certificates the caller trusts, and extra certificates for path building.
///
/// An empty source is legitimate and means "I have no anchors": every chain
/// check is then `unknown` and the verdict `indeterminate`, never `valid`.
pub trait TrustSource {
    /// The trust anchors, with their provenance.
    fn anchors(&self) -> &[TrustAnchor];
    /// DER-encoded intermediate CA certificates offered for path building.
    fn intermediates(&self) -> &[Vec<u8>];
    /// Whether the caller configured a store at all, which is different from
    /// configuring an empty one.
    fn configured(&self) -> bool {
        true
    }
    /// Checks the trust material itself produced while it was loaded — a
    /// trusted list whose own signature could not be verified, say. They are
    /// reported at the dossier level, because they are properties of the run
    /// and not of any one signature.
    fn checks(&self) -> &[Check] {
        &[]
    }
}

/// No trust store at all.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoTrust;

impl TrustSource for NoTrust {
    fn anchors(&self) -> &[TrustAnchor] {
        &[]
    }

    fn intermediates(&self) -> &[Vec<u8>] {
        &[]
    }

    fn configured(&self) -> bool {
        false
    }
}

/// An in-memory trust store, which is what the CLI's `--trust-store DIR` and
/// `--trust-list FILE` loaders and every test produce.
#[derive(Clone, Debug, Default)]
pub struct MemoryTrustStore {
    anchors: Vec<TrustAnchor>,
    intermediates: Vec<Vec<u8>>,
    checks: Vec<Check>,
}

impl MemoryTrustStore {
    /// A store of plain anchors, all of trust-store origin.
    pub fn new(anchors: Vec<Vec<u8>>, intermediates: Vec<Vec<u8>>) -> Self {
        Self {
            anchors: anchors.into_iter().map(TrustAnchor::from_store).collect(),
            intermediates,
            checks: Vec::new(),
        }
    }

    /// Add anchors a trusted list vouches for. The combined anchor set is the
    /// union of both sources, each reported with its own origin.
    pub fn extend_anchors(&mut self, anchors: impl IntoIterator<Item = TrustAnchor>) {
        self.anchors.extend(anchors);
    }

    /// Record a check the trust material produced while it was loaded.
    pub fn push_check(&mut self, check: Check) {
        self.checks.push(check);
    }
}

impl TrustSource for MemoryTrustStore {
    fn anchors(&self) -> &[TrustAnchor] {
        &self.anchors
    }

    fn intermediates(&self) -> &[Vec<u8>] {
        &self.intermediates
    }

    fn checks(&self) -> &[Check] {
        &self.checks
    }
}

/// The revocation policy actually applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationPolicy {
    /// The caller switched revocation checking off with `--no-revocation`.
    /// Every verdict is then capped at `indeterminate`, because a signature
    /// whose certificate might have been revoked is not one anything should
    /// call valid.
    NotChecked,
    /// Revocation is checked from material that is already to hand: the
    /// signature's own `xades:RevocationValues` and the revocation store.
    /// Nothing is fetched.
    Offline,
}

impl RevocationPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotChecked => "not_checked",
            Self::Offline => "offline",
        }
    }
}

/// Revocation data, supplied by the caller.
///
/// The crate never fetches: an implementation hands over CRLs and OCSP
/// responses it already has, which is what makes "offline by default" a
/// structural property rather than a flag someone can forget to check.
pub trait RevocationSource {
    fn policy(&self) -> RevocationPolicy;
    /// DER-encoded CRLs.
    fn crls(&self) -> &[Vec<u8>] {
        &[]
    }
    /// DER-encoded OCSP responses, each an `OCSPResponse` or a bare
    /// `BasicOCSPResponse`.
    fn ocsp_responses(&self) -> &[Vec<u8>] {
        &[]
    }
}

/// Revocation checking switched off, which is what `--no-revocation` selects.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoRevocation;

impl RevocationSource for NoRevocation {
    fn policy(&self) -> RevocationPolicy {
        RevocationPolicy::NotChecked
    }
}

/// The offline revocation store: whatever CRLs and OCSP responses the caller
/// loaded, and nothing else. An empty one is normal and means the answer will
/// come from the signature's own `RevocationValues` or not at all.
#[derive(Clone, Debug, Default)]
pub struct MemoryRevocationStore {
    crls: Vec<Vec<u8>>,
    ocsp: Vec<Vec<u8>>,
}

impl MemoryRevocationStore {
    pub fn new(crls: Vec<Vec<u8>>, ocsp: Vec<Vec<u8>>) -> Self {
        Self { crls, ocsp }
    }
}

impl RevocationSource for MemoryRevocationStore {
    fn policy(&self) -> RevocationPolicy {
        RevocationPolicy::Offline
    }

    fn crls(&self) -> &[Vec<u8>] {
        &self.crls
    }

    fn ocsp_responses(&self) -> &[Vec<u8>] {
        &self.ocsp
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
