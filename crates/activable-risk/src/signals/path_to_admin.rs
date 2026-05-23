/// Path to Admin Signal: Shortest path distance to an admin-equivalent principal
///
/// Measures how close a principal is to gaining admin-equivalent privileges.
/// Admin-equivalent = has `iam:*` or `*` effective permission.
///
/// Raw value: shortest path length to admin (0 if IS admin, infinity if unreachable)
/// Normalized: 1.0 - (raw / max_depth) — shorter path = higher risk (closer to admin)
/// If unreachable (infinite distance), normalized = 0.0 (no risk from this signal)
use super::{inverse_normalize, GraphQueryService, SignalError, SignalResult};

/// Default max depth for path-to-admin normalization (8 hops)
#[allow(dead_code)]
const DEFAULT_MAX_DEPTH: u8 = 8;

/// Path to admin signal: shortest path to admin-equivalent principal
pub struct PathToAdminSignal {
    max_depth: u8,
    weight: f64,
}

impl PathToAdminSignal {
    pub fn new(max_depth: u8) -> Self {
        PathToAdminSignal {
            max_depth,
            weight: 0.35, // high weight — proximity to admin is critical
        }
    }

    pub fn with_weight(mut self, weight: f64) -> Self {
        self.weight = weight;
        self
    }

    pub async fn compute(
        &self,
        principal_id: &str,
        graph: &dyn GraphQueryService,
    ) -> Result<SignalResult, SignalError> {
        let maybe_distance = graph
            .shortest_path_to_admin(principal_id, self.max_depth)
            .await?;

        let (raw_value, normalized) = match maybe_distance {
            Some(distance) => {
                // Found a path: 0 (is admin) to max_depth (far from admin)
                let raw = distance as f64;
                let norm = inverse_normalize(raw, self.max_depth as f64);
                (raw, norm)
            }
            None => {
                // No path to admin: infinite distance, zero risk from this signal
                (f64::INFINITY, 0.0)
            }
        };

        Ok(SignalResult::new(
            "path_to_admin",
            raw_value,
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
    async fn path_to_admin_is_admin() {
        // Principal IS admin → distance 0 → highest risk
        let graph =
            MockGraphQueryService::new().with_shortest_path("admin-role".to_string(), Some(0));
        let signal = PathToAdminSignal::new(8);
        let result = signal.compute("admin-role", &graph).await.unwrap();
        assert_eq!(result.raw_value, 0.0);
        assert_eq!(result.normalized, 1.0); // 1.0 - 0/8 = 1.0
    }

    #[tokio::test]
    async fn path_to_admin_two_hops() {
        // Alice → dev-role → admin-role (distance 2)
        let graph = MockGraphQueryService::new().with_shortest_path("alice".to_string(), Some(2));
        let signal = PathToAdminSignal::new(8);
        let result = signal.compute("alice", &graph).await.unwrap();
        assert_eq!(result.raw_value, 2.0);
        assert!((result.normalized - 0.75).abs() < 0.01); // 1.0 - 2/8
    }

    #[tokio::test]
    async fn path_to_admin_max_depth() {
        // Principal at max depth (8 hops)
        let graph = MockGraphQueryService::new().with_shortest_path("distant".to_string(), Some(8));
        let signal = PathToAdminSignal::new(8);
        let result = signal.compute("distant", &graph).await.unwrap();
        assert_eq!(result.raw_value, 8.0);
        assert_eq!(result.normalized, 0.0); // 1.0 - 8/8 = 0.0
    }

    #[tokio::test]
    async fn path_to_admin_unreachable() {
        // No path to admin
        let graph = MockGraphQueryService::new().with_shortest_path("alice".to_string(), None);
        let signal = PathToAdminSignal::new(8);
        let result = signal.compute("alice", &graph).await.unwrap();
        assert_eq!(result.raw_value, f64::INFINITY);
        assert_eq!(result.normalized, 0.0); // no path = no risk from this signal
    }

    #[tokio::test]
    async fn path_to_admin_one_hop() {
        // One hop away from admin
        let graph = MockGraphQueryService::new().with_shortest_path("dev".to_string(), Some(1));
        let signal = PathToAdminSignal::new(8);
        let result = signal.compute("dev", &graph).await.unwrap();
        assert_eq!(result.raw_value, 1.0);
        assert!((result.normalized - 0.875).abs() < 0.01); // 1.0 - 1/8
    }
}
