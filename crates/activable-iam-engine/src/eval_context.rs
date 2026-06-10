//! Evaluation context for policy condition evaluation.
//!
//! Provides AWS context variables (region, source IP, source ARN, MFA presence, secure transport)
//! used by condition evaluators.

/// Evaluation context for policy condition evaluation.
///
/// Captures AWS context variables like region, source IP, and MFA status.
/// When a context variable is not available, the field contains an empty string.
#[derive(Debug, Clone, Default)]
pub struct EvalContext {
    /// AWS region (e.g., "us-east-1", "eu-west-1").
    pub region: String,
    /// Source IP address (e.g., "192.168.1.1").
    pub source_ip: String,
    /// Source ARN (e.g., "arn:aws:iam::123456789012:user/alice").
    pub source_arn: String,
    /// Whether MFA is present in the request.
    pub mfa_present: bool,
    /// Whether secure transport (HTTPS/TLS) is used.
    pub secure_transport: bool,
}

impl EvalContext {
    /// Create a new evaluation context with all defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the region.
    pub fn with_region(mut self, region: String) -> Self {
        self.region = region;
        self
    }

    /// Set the source IP.
    pub fn with_source_ip(mut self, source_ip: String) -> Self {
        self.source_ip = source_ip;
        self
    }

    /// Set the source ARN.
    pub fn with_source_arn(mut self, source_arn: String) -> Self {
        self.source_arn = source_arn;
        self
    }

    /// Set MFA presence.
    pub fn with_mfa_present(mut self, mfa_present: bool) -> Self {
        self.mfa_present = mfa_present;
        self
    }

    /// Set secure transport.
    pub fn with_secure_transport(mut self, secure_transport: bool) -> Self {
        self.secure_transport = secure_transport;
        self
    }
}
