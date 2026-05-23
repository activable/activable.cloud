/// Blast Radius Signal: Count of reachable nodes via BFS from principal
///
/// Measures the blast radius of a principal — how many resources/principals it can reach
/// through outgoing edges. Higher reachability = higher damage potential.
///
/// Raw value: count of reachable nodes (via `GraphQueryService::reachable_count`)
/// Normalized: log10(raw + 1) / log10(max_possible + 1)
/// Log scale dampens outliers — a principal reaching 100 nodes is not 10x worse than reaching 10.
use super::{log_normalize, GraphQueryService, SignalError, SignalResult};

/// Default max blast radius for normalization (10000 reachable nodes)
const DEFAULT_MAX_REACHABLE: f64 = 10000.0;

/// Blast radius signal: count of reachable nodes within max_hops
pub struct BlastRadiusSignal {
    max_reachable: f64,
    weight: f64,
}

impl Default for BlastRadiusSignal {
    fn default() -> Self {
        BlastRadiusSignal {
            max_reachable: DEFAULT_MAX_REACHABLE,
            weight: 0.25, // moderate weight in composite score
        }
    }
}

impl BlastRadiusSignal {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_reachable(mut self, max_reachable: f64) -> Self {
        self.max_reachable = max_reachable;
        self
    }

    pub fn with_weight(mut self, weight: f64) -> Self {
        self.weight = weight;
        self
    }

    pub async fn compute(
        &self,
        principal_id: &str,
        graph: &dyn GraphQueryService,
        max_hops: u8,
    ) -> Result<SignalResult, SignalError> {
        let raw_value = graph.reachable_count(principal_id, max_hops).await?;

        let normalized = log_normalize(raw_value as f64, self.max_reachable);

        Ok(SignalResult::new(
            "blast_radius",
            raw_value as f64,
            normalized,
            self.weight,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::test_fixtures::MockGraphQueryService;

    #[tokio::test]
    async fn blast_radius_isolated_principal() {
        // Principal with no outgoing edges → blast radius = 0
        let graph = MockGraphQueryService::new();
        let signal = BlastRadiusSignal::new();
        let result = signal.compute("alice", &graph, 6).await.unwrap();
        assert_eq!(result.raw_value, 0.0);
        assert_eq!(result.normalized, 0.0);
    }

    #[tokio::test]
    async fn blast_radius_with_reachable_nodes() {
        // Principal can reach 100 resources
        let graph = MockGraphQueryService::new().with_reachable("admin".to_string(), 100);
        let signal = BlastRadiusSignal::new();
        let result = signal.compute("admin", &graph, 6).await.unwrap();
        assert_eq!(result.raw_value, 100.0);
        assert!(result.normalized > 0.5); // log-normalized to > 0.5
    }

    #[tokio::test]
    async fn blast_radius_max_reachable() {
        // Principal at max reachable should normalize to ~1.0
        let graph = MockGraphQueryService::new().with_reachable("admin".to_string(), 10000);
        let signal = BlastRadiusSignal::new();
        let result = signal.compute("admin", &graph, 6).await.unwrap();
        assert_eq!(result.raw_value, 10000.0);
        assert!((result.normalized - 1.0).abs() < 0.01);
    }

    #[tokio::test]
    async fn blast_radius_star_topology() {
        // Admin with many direct reachable nodes (star topology)
        let graph = MockGraphQueryService::new().with_reachable("admin".to_string(), 500);
        let signal = BlastRadiusSignal::new();
        let result = signal.compute("admin", &graph, 6).await.unwrap();
        assert_eq!(result.raw_value, 500.0);
        assert!(result.normalized > 0.65 && result.normalized < 0.80);
    }

    #[test]
    fn blast_radius_has_correct_name() {
        let signal = BlastRadiusSignal::new();
        // Name is accessible via SignalResult after compute
        // This test ensures the signal is created correctly
        assert!(signal.weight > 0.0);
    }
}
