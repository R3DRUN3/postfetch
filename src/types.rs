/// The status level of an individual check result.
#[derive(Debug, Clone, PartialEq)]
pub enum Status {
    /// The check passed: configuration looks good.
    Good,
    /// The check found a potential issue or a missing best-practice.
    Warn,
    /// The check found a significant risk or active exposure.
    Bad,
    /// The check could not determine the status (e.g. missing tools, permissions).
    Unknown,
}

/// A single audit result produced by one check function.
#[derive(Debug, Clone)]
pub struct CheckResult {
    /// Short human-readable label (e.g. "Disk Encryption").
    pub label: String,
    /// One-line summary shown in the report.
    pub value: String,
    /// Overall status colour/icon.
    pub status: Status,
    /// Optional extra detail shown when verbose or relevant.
    pub detail: Option<String>,
    /// Which logical module produced this result.
    pub module: String,
}

impl CheckResult {
    pub fn new(
        module: &str,
        label: &str,
        value: &str,
        status: Status,
        detail: Option<&str>,
    ) -> Self {
        CheckResult {
            module: module.to_string(),
            label: label.to_string(),
            value: value.to_string(),
            status,
            detail: detail.map(|s| s.to_string()),
        }
    }
}
