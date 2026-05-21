//! ARN parsing and canonicalization.
//!
//! Parses AWS ARNs into canonical form for consistent graph node identity.
//! Phase 3 will populate this with full parser logic.

use std::fmt;

/// Represents a parsed AWS ARN in canonical form.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Arn {
    /// The partition (aws, aws-cn, aws-us-gov).
    pub partition: String,
    /// The service (iam, ec2, s3, etc.).
    pub service: String,
    /// The AWS region.
    pub region: String,
    /// The AWS account ID.
    pub account: String,
    /// The resource type and identifier.
    pub resource: String,
}

impl Arn {
    /// Parses an ARN string into canonical form.
    ///
    /// # Errors
    /// Returns an error if the ARN format is invalid.
    pub fn parse(s: &str) -> Result<Self, String> {
        // Placeholder implementation; Phase 3 expands this.
        if !s.starts_with("arn:") {
            return Err("ARN must start with 'arn:'".to_string());
        }
        Ok(Self {
            partition: "aws".to_string(),
            service: "unknown".to_string(),
            region: String::new(),
            account: String::new(),
            resource: s.to_string(),
        })
    }

    /// Returns the canonical string form of the ARN.
    #[must_use]
    pub fn canonical(&self) -> String {
        format!(
            "arn:{}:{}:{}:{}:{}",
            self.partition, self.service, self.region, self.account, self.resource
        )
    }
}

impl fmt::Display for Arn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.canonical())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arn_parse_placeholder() {
        let arn = Arn::parse("arn:aws:iam::123456789012:user/TestUser").unwrap();
        assert_eq!(arn.partition, "aws");
    }

    #[test]
    fn test_arn_invalid() {
        assert!(Arn::parse("invalid").is_err());
    }
}
