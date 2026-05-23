/// Cross-Account Hops Signal: Number of account boundary crossings via assume-role
///
/// Detects principals that can hop across AWS account boundaries.
/// Each cross-account assume-role edge is counted as one hop.
///
/// Raw value: count of account boundaries crossed
/// Normalized: min(1.0, raw / 5.0) — 5+ hops = max score
/// Uses GraphQueryService to walk CanAssume edges and count account changes.
use super::{linear_cap, GraphQueryService, SignalError, SignalResult};

/// Default max cross-account hops for normalization (5 hops)
const DEFAULT_MAX_HOPS: f64 = 5.0;

/// Cross-account hops signal: count of assume-role chains crossing accounts
pub struct CrossAccountHopsSignal;

impl CrossAccountHopsSignal {
    /// Compute cross-account hops from graph
    pub async fn compute(
        &self,
        principal_id: &str,
        graph: &dyn GraphQueryService,
    ) -> Result<SignalResult, SignalError> {
        let raw_value = graph.cross_account_hop_count(principal_id).await?;

        // Normalize: 5+ hops = max score
        let normalized = linear_cap(raw_value as f64, DEFAULT_MAX_HOPS);

        Ok(SignalResult::new(
            "cross_account_hops",
            raw_value as f64,
            normalized,
            0.20, // moderate weight
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::test_fixtures::MockGraphQueryService;

    #[tokio::test]
    async fn no_cross_account_hops() {
        // Principal in single account
        let graph = MockGraphQueryService::new();
        let signal = CrossAccountHopsSignal;
        let result = signal.compute("alice", &graph).await.unwrap();
        assert_eq!(result.raw_value, 0.0);
        assert_eq!(result.normalized, 0.0);
    }

    #[tokio::test]
    async fn one_cross_account_hop() {
        // Alice can assume into another account (1 hop)
        let graph = MockGraphQueryService::new().with_cross_account_hops("alice".to_string(), 1);
        let signal = CrossAccountHopsSignal;
        let result = signal.compute("alice", &graph).await.unwrap();
        assert_eq!(result.raw_value, 1.0);
        assert!((result.normalized - 0.2).abs() < 0.01); // 1/5
    }

    #[tokio::test]
    async fn two_cross_account_hops() {
        // alice (acct 111) → role (acct 222) → role (acct 333) = 2 hops
        let graph = MockGraphQueryService::new().with_cross_account_hops("alice".to_string(), 2);
        let signal = CrossAccountHopsSignal;
        let result = signal.compute("alice", &graph).await.unwrap();
        assert_eq!(result.raw_value, 2.0);
        assert!((result.normalized - 0.4).abs() < 0.01); // 2/5
    }

    #[tokio::test]
    async fn max_cross_account_hops() {
        // 5+ hops = max score
        let graph = MockGraphQueryService::new().with_cross_account_hops("alice".to_string(), 5);
        let signal = CrossAccountHopsSignal;
        let result = signal.compute("alice", &graph).await.unwrap();
        assert_eq!(result.raw_value, 5.0);
        assert_eq!(result.normalized, 1.0); // 5/5 = 1.0
    }

    #[tokio::test]
    async fn exceeds_max_cross_account_hops() {
        // Beyond 5 hops still caps at 1.0
        let graph = MockGraphQueryService::new().with_cross_account_hops("alice".to_string(), 10);
        let signal = CrossAccountHopsSignal;
        let result = signal.compute("alice", &graph).await.unwrap();
        assert_eq!(result.raw_value, 10.0);
        assert_eq!(result.normalized, 1.0); // capped at 1.0
    }

    #[tokio::test]
    async fn cross_account_signal_has_correct_name() {
        let signal = CrossAccountHopsSignal;
        let graph = MockGraphQueryService::new();
        let result = signal.compute("test", &graph).await.unwrap();
        assert_eq!(result.name, "cross_account_hops");
    }
}
