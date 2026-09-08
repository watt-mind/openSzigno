//! Trusted-list services: the status timeline and the pre-eIDAS rules.
//!
//! A service is granted at an instant, not in general. The current
//! `ServiceStatus` entry and every `ServiceHistoryInstance` are folded into
//! one timeline so that a lookup at a validation time is a single scan, and a
//! pre-eIDAS status counts only at a time before eIDAS applied.

use serde::Serialize;

use crate::trust::UnixTime;

const SVCTYPE_CA_QC: &str = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
const SVCTYPE_TSA_QTST: &str = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST";

/// The statuses that mean "this service may be relied on", at any time.
///
/// `granted` is the eIDAS status; `recognisedatnationallevel` is the national
/// equivalent a member state may publish. Every terminal status —
/// `withdrawn`, `supervisionceased`, the `deprecated*` family — is
/// deliberately absent.
pub const GRANTED_STATUSES: &[&str] = &[
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel",
];

/// The pre-eIDAS statuses, which counted as granted **only while they were
/// the current vocabulary** — that is, at a validation time before eIDAS began
/// to apply.
///
/// Before 2016-07-01 a Hungarian supervised or accredited CA was exactly what
/// a member state published for a CA entitled to issue qualified
/// certificates; the eIDAS `granted` vocabulary did not exist yet. Refusing
/// them outright, as this build did through M2, made every pre-2016 signature
/// report `certificate_not_qualified` for a reason that had nothing to do with
/// the signature. Honouring them *after* the migration would be the real
/// mistake, because a service left at a pre-eIDAS status once the new
/// vocabulary applied has not been granted under it — so the window is closed
/// at [`EIDAS_APPLICATION_DATE`] and the status name is always reported
/// alongside the determination.
pub const PRE_EIDAS_GRANTED_STATUSES: &[&str] = &[
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision",
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited",
];

/// When eIDAS (Regulation (EU) 910/2014) began to apply.
pub const EIDAS_APPLICATION_DATE: UnixTime = 1_467_324_000; // 2016-07-01T00:00:00Z

/// Which kind of service an anchor is the digital identity of.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceType {
    /// A CA issuing qualified certificates.
    CaQc,
    /// A qualified electronic timestamping authority.
    TsaQtst,
}

impl ServiceType {
    pub(super) fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            SVCTYPE_CA_QC => Some(Self::CaQc),
            SVCTYPE_TSA_QTST => Some(Self::TsaQtst),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CaQc => "ca_qc",
            Self::TsaQtst => "tsa_qtst",
        }
    }
}

/// One entry in a service's status timeline.
#[derive(Clone, Debug, Serialize)]
pub struct ServiceStatusEntry {
    pub service_type: ServiceType,
    /// The last path segment of the status URI, sanitised.
    pub status: String,
    /// Whether this status means the service may be relied on at any time.
    pub granted: bool,
    /// Whether this is a pre-eIDAS status that counts as granted only at a
    /// validation time before [`EIDAS_APPLICATION_DATE`].
    pub granted_before_eidas: bool,
    /// RFC 3339 UTC, or `null` when the list gave an unparseable time.
    pub starting_time: Option<String>,
    #[serde(skip)]
    pub(super) starting_unix: Option<UnixTime>,
}

/// One trusted-list service, as far as this build reads it.
#[derive(Clone, Debug, Serialize)]
pub struct ServiceRecord {
    pub service_name: Option<String>,
    pub territory: Option<String>,
    pub sequence_number: Option<u64>,
    /// The status timeline, oldest first. The current `ServiceInformation`
    /// entry and every `ServiceHistoryInstance` are folded into one list, so a
    /// lookup at a validation time is a single scan.
    pub entries: Vec<ServiceStatusEntry>,
}

impl ServiceRecord {
    /// The status in force at `time`: the latest entry whose
    /// `StatusStartingTime` is at or before it.
    ///
    /// An entry with no usable starting time is never in force, because a
    /// status without a date cannot be placed on a timeline and guessing would
    /// mean trusting a CA at an instant nobody stated.
    pub fn status_at(&self, time: UnixTime) -> Option<&ServiceStatusEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.starting_unix.is_some_and(|start| start <= time))
            .max_by_key(|entry| entry.starting_unix)
    }

    /// Whether this service was granted at `time` for the given kind of use.
    ///
    /// A pre-eIDAS status counts only at a `time` before eIDAS applied; see
    /// [`PRE_EIDAS_GRANTED_STATUSES`].
    pub fn granted_at(&self, time: UnixTime, wanted: ServiceType) -> bool {
        self.status_at(time).is_some_and(|entry| {
            entry.service_type == wanted
                && (entry.granted || (entry.granted_before_eidas && time < EIDAS_APPLICATION_DATE))
        })
    }

    /// The name of the status that decided [`granted_at`](Self::granted_at),
    /// so a report can say *which* status was honoured — an eIDAS `granted` and
    /// a pre-eIDAS `accredited` are not the same statement.
    pub fn status_name_at(&self, time: UnixTime) -> Option<&str> {
        self.status_at(time).map(|entry| entry.status.as_str())
    }
}
