/// Risk signals computed from graph topology and effective permissions.
///
/// Five signals feed the composite risk scorer:
/// 1. **Blast Radius**: Count of reachable nodes via outgoing edges (BFS)
/// 2. **Path to Admin**: Shortest path to an admin-equivalent principal
/// 3. **Dangerous Action Count**: Tier-weighted count of dangerous IAM actions
/// 4. **Cross-Account Hops**: Number of account boundary crossings via assume-role
/// 5. **Permission Surface**: Total count of effective permissions (expand `*` to catalog size)
use async_trait::async_trait;
use std::error::Error;

pub mod blast_radius;
pub mod cross_account_hops;
pub mod dangerous_action_count;
pub mod path_to_admin;
pub mod permission_surface;

pub use blast_radius::BlastRadiusSignal;
pub use cross_account_hops::CrossAccountHopsSignal;
pub use dangerous_action_count::DangerousActionCountSignal;
pub use path_to_admin::PathToAdminSignal;
pub use permission_surface::PermissionSurfaceSignal;

/// Result type for signal computations
pub type SignalError = Box<dyn Error + Send + Sync>;

/// Result of computing a single risk signal
#[derive(Debug, Clone)]
pub struct SignalResult {
    pub name: &'static str,
    pub raw_value: f64,
    pub normalized: f64, // 0.0–1.0
    pub weight: f64,     // from config
}

impl SignalResult {
    pub fn new(name: &'static str, raw_value: f64, normalized: f64, weight: f64) -> Self {
        SignalResult {
            name,
            raw_value,
            normalized,
            weight,
        }
    }
}

/// Error type for graph query service
#[derive(Debug)]
pub struct GraphQueryError(pub String);

impl std::fmt::Display for GraphQueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for GraphQueryError {}

/// Abstraction over graph query operations needed by signals.
/// Real implementation wraps GraphClient; mock for unit tests.
#[async_trait]
pub trait GraphQueryService: Send + Sync {
    /// Count reachable nodes from principal within max_hops via outgoing edges
    async fn reachable_count(&self, principal_id: &str, max_hops: u8) -> Result<u64, SignalError>;

    /// Shortest path length from principal to any admin-equivalent node.
    /// Returns None if unreachable.
    async fn shortest_path_to_admin(
        &self,
        principal_id: &str,
        max_depth: u8,
    ) -> Result<Option<u32>, SignalError>;

    /// Count cross-account hops (CanAssume edges crossing account boundaries)
    async fn cross_account_hop_count(&self, principal_id: &str) -> Result<u32, SignalError>;

    /// List all principal node IDs in the graph
    async fn list_principal_ids(&self) -> Result<Vec<String>, SignalError>;

    /// Get effective permissions for a principal (action + resource pairs)
    async fn get_effective_permissions(
        &self,
        principal_id: &str,
    ) -> Result<Vec<(String, String)>, SignalError>;

    /// Read a cached risk assessment from a graph node property.
    /// Returns None if no cached assessment exists.
    async fn read_risk_assessment(&self, principal_id: &str)
        -> Result<Option<String>, SignalError>;

    /// Write a risk assessment JSON to a graph node property.
    async fn write_risk_assessment(
        &self,
        principal_id: &str,
        assessment_json: &str,
    ) -> Result<(), SignalError>;
}

/// Normalization: log-scale capped by maximum
/// log10(raw + 1) / log10(max + 1)
///
/// Zero input returns 0.0. At max, returns 1.0.
/// Log scale dampens outliers — useful for unbounded counts (permissions, reachable nodes).
pub fn log_normalize(raw: f64, max: f64) -> f64 {
    if raw <= 0.0 {
        return 0.0;
    }
    if max <= 0.0 {
        return 0.0;
    }
    ((raw + 1.0).log10()) / ((max + 1.0).log10())
}

/// Normalization: inverse (shorter = higher risk)
/// 1.0 - (raw / max)
///
/// Distance 0 (is admin) returns 1.0. At max distance, returns 0.0.
/// Useful for path length: shorter to dangerous state = higher risk.
pub fn inverse_normalize(raw: f64, max: f64) -> f64 {
    if raw <= 0.0 {
        return 1.0; // is admin
    }
    if max <= 0.0 {
        return 0.0;
    }
    let normalized = 1.0 - (raw / max);
    normalized.clamp(0.0, 1.0)
}

/// Normalization: linear cap
/// min(1.0, raw / cap)
///
/// Scales linearly until cap; stays at 1.0 above cap.
pub fn linear_cap(raw: f64, cap: f64) -> f64 {
    if cap <= 0.0 {
        return 0.0;
    }
    (raw / cap).min(1.0)
}

#[cfg(test)]
pub mod test_fixtures {
    use super::*;
    use std::collections::HashMap;

    /// Mock graph service for unit tests
    pub struct MockGraphQueryService {
        pub reachable_counts: HashMap<String, u64>,
        pub shortest_paths: HashMap<String, Option<u32>>,
        pub cross_account_hops: HashMap<String, u32>,
        pub principal_ids: Vec<String>,
        pub effective_permissions: HashMap<String, Vec<(String, String)>>,
        pub risk_assessments: std::sync::Mutex<HashMap<String, String>>,
    }

    impl MockGraphQueryService {
        pub fn new() -> Self {
            Self {
                reachable_counts: HashMap::new(),
                shortest_paths: HashMap::new(),
                cross_account_hops: HashMap::new(),
                principal_ids: Vec::new(),
                effective_permissions: HashMap::new(),
                risk_assessments: std::sync::Mutex::new(HashMap::new()),
            }
        }

        pub fn with_reachable(mut self, principal_id: String, count: u64) -> Self {
            self.reachable_counts.insert(principal_id, count);
            self
        }

        pub fn with_shortest_path(mut self, principal_id: String, distance: Option<u32>) -> Self {
            self.shortest_paths.insert(principal_id, distance);
            self
        }

        pub fn with_cross_account_hops(mut self, principal_id: String, hops: u32) -> Self {
            self.cross_account_hops.insert(principal_id, hops);
            self
        }

        pub fn with_principal_ids(mut self, ids: Vec<String>) -> Self {
            self.principal_ids = ids;
            self
        }

        pub fn with_effective_permissions(
            mut self,
            principal_id: String,
            perms: Vec<(String, String)>,
        ) -> Self {
            self.effective_permissions.insert(principal_id, perms);
            self
        }
    }

    impl Default for MockGraphQueryService {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl GraphQueryService for MockGraphQueryService {
        async fn reachable_count(
            &self,
            principal_id: &str,
            _max_hops: u8,
        ) -> Result<u64, SignalError> {
            Ok(self
                .reachable_counts
                .get(principal_id)
                .copied()
                .unwrap_or(0))
        }

        async fn shortest_path_to_admin(
            &self,
            principal_id: &str,
            _max_depth: u8,
        ) -> Result<Option<u32>, SignalError> {
            Ok(self.shortest_paths.get(principal_id).copied().flatten())
        }

        async fn cross_account_hop_count(&self, principal_id: &str) -> Result<u32, SignalError> {
            Ok(self
                .cross_account_hops
                .get(principal_id)
                .copied()
                .unwrap_or(0))
        }

        async fn list_principal_ids(&self) -> Result<Vec<String>, SignalError> {
            Ok(self.principal_ids.clone())
        }

        async fn get_effective_permissions(
            &self,
            principal_id: &str,
        ) -> Result<Vec<(String, String)>, SignalError> {
            Ok(self
                .effective_permissions
                .get(principal_id)
                .cloned()
                .unwrap_or_default())
        }

        async fn read_risk_assessment(
            &self,
            principal_id: &str,
        ) -> Result<Option<String>, SignalError> {
            let assessments = self.risk_assessments.lock().map_err(|e| {
                Box::new(GraphQueryError(format!("lock failed: {}", e))) as SignalError
            })?;
            Ok(assessments.get(principal_id).cloned())
        }

        async fn write_risk_assessment(
            &self,
            principal_id: &str,
            assessment_json: &str,
        ) -> Result<(), SignalError> {
            let mut assessments = self.risk_assessments.lock().map_err(|e| {
                Box::new(GraphQueryError(format!("lock failed: {}", e))) as SignalError
            })?;
            assessments.insert(principal_id.to_string(), assessment_json.to_string());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_normalize_zero_input() {
        assert_eq!(log_normalize(0.0, 10000.0), 0.0);
    }

    #[test]
    fn log_normalize_max_input() {
        let result = log_normalize(10000.0, 10000.0);
        assert!((result - 1.0).abs() < 0.01);
    }

    #[test]
    fn log_normalize_mid_range() {
        let result = log_normalize(100.0, 10000.0);
        assert!(result > 0.0 && result < 1.0);
    }

    #[test]
    fn inverse_normalize_zero_is_max_risk() {
        assert_eq!(inverse_normalize(0.0, 8.0), 1.0);
    }

    #[test]
    fn inverse_normalize_max_is_zero_risk() {
        assert_eq!(inverse_normalize(8.0, 8.0), 0.0);
    }

    #[test]
    fn inverse_normalize_mid_range() {
        let result = inverse_normalize(2.0, 8.0);
        assert!((result - 0.75).abs() < 0.01); // 1.0 - 2/8
    }

    #[test]
    fn linear_cap_below_cap() {
        let result = linear_cap(3.0, 10.0);
        assert!((result - 0.3).abs() < 0.01);
    }

    #[test]
    fn linear_cap_at_cap() {
        let result = linear_cap(10.0, 10.0);
        assert_eq!(result, 1.0);
    }

    #[test]
    fn linear_cap_above_cap() {
        let result = linear_cap(20.0, 10.0);
        assert_eq!(result, 1.0);
    }
}
