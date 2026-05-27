use crate::handler::JobHandler;
use std::collections::HashMap;
use std::sync::Arc;

/// A registry of job handlers, keyed by job_type.
/// Handlers are registered at construction time and immutable thereafter.
///
/// This is the sole extension point for reusability: adding a new job_type
/// requires only implementing JobHandler and registering it with the registry.
/// No changes to store.rs, worker.rs, or reaper.rs are needed.
pub struct HandlerRegistry {
    /// Map of job_type -> Arc<dyn JobHandler>
    handlers: HashMap<String, Arc<dyn JobHandler + Send + Sync>>,
}

impl HandlerRegistry {
    /// Create a new, empty registry.
    pub fn new() -> Self {
        HandlerRegistry {
            handlers: HashMap::new(),
        }
    }

    /// Register a handler for a job type.
    /// If a handler with the same job_type is already registered, it is replaced.
    /// (Last-wins is explicit: callers should avoid registering the same job_type twice.)
    pub fn register(&mut self, handler: Arc<dyn JobHandler + Send + Sync>) {
        let job_type = handler.job_type().to_string();

        // Note: if a handler with the same job_type is already registered, it is replaced.
        // This is intentional but potentially dangerous; callers should avoid duplicates.
        // In production, this could be changed to error on duplicate.

        self.handlers.insert(job_type, handler);
    }

    /// Return the list of registered job types.
    /// Used by workers to construct their claim filter.
    pub fn registered_types(&self) -> Vec<String> {
        self.handlers.keys().cloned().collect()
    }

    /// Return a vector of all registered handlers.
    /// Used by WorkerPool and Reaper.
    pub fn handlers(&self) -> Vec<Arc<dyn JobHandler + Send + Sync>> {
        self.handlers.values().cloned().collect()
    }

    /// Look up a handler by job_type. Returns None if not registered.
    /// This is a utility for callers that need to find a specific handler.
    pub fn get(&self, job_type: &str) -> Option<Arc<dyn JobHandler + Send + Sync>> {
        self.handlers.get(job_type).cloned()
    }

    /// Return the number of registered handlers.
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }
}

impl Default for HandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::JobError;
    use serde_json::{json, Value};

    /// Test handler for unit tests
    struct TestHandler {
        job_type_name: String,
    }

    #[async_trait::async_trait]
    impl JobHandler for TestHandler {
        async fn handle(&self, _payload: Value) -> Result<Value, JobError> {
            Ok(json!({}))
        }

        fn job_type(&self) -> &str {
            &self.job_type_name
        }

        fn max_attempts(&self) -> i32 {
            3
        }
    }

    #[test]
    fn test_registry_new_empty() {
        let registry = HandlerRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert_eq!(registry.registered_types().len(), 0);
    }

    #[test]
    fn test_registry_register_single_handler() {
        let mut registry = HandlerRegistry::new();
        let handler = Arc::new(TestHandler {
            job_type_name: "test_type".to_string(),
        });

        registry.register(handler.clone());

        assert_eq!(registry.len(), 1);
        assert_eq!(registry.registered_types(), vec!["test_type"]);
        assert!(registry.get("test_type").is_some());
    }

    #[test]
    fn test_registry_register_multiple_handlers() {
        let mut registry = HandlerRegistry::new();

        let handler1 = Arc::new(TestHandler {
            job_type_name: "type_1".to_string(),
        });
        let handler2 = Arc::new(TestHandler {
            job_type_name: "type_2".to_string(),
        });
        let handler3 = Arc::new(TestHandler {
            job_type_name: "type_3".to_string(),
        });

        registry.register(handler1);
        registry.register(handler2);
        registry.register(handler3);

        assert_eq!(registry.len(), 3);
        let types = registry.registered_types();
        assert!(types.contains(&"type_1".to_string()));
        assert!(types.contains(&"type_2".to_string()));
        assert!(types.contains(&"type_3".to_string()));
    }

    #[test]
    fn test_registry_get_existing_handler() {
        let mut registry = HandlerRegistry::new();
        let handler = Arc::new(TestHandler {
            job_type_name: "test_type".to_string(),
        });

        registry.register(handler.clone());

        let retrieved = registry.get("test_type");
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_registry_get_nonexistent_handler() {
        let registry = HandlerRegistry::new();
        let retrieved = registry.get("nonexistent_type");
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_registry_handlers_vector() {
        let mut registry = HandlerRegistry::new();

        let handler1 = Arc::new(TestHandler {
            job_type_name: "type_1".to_string(),
        });
        let handler2 = Arc::new(TestHandler {
            job_type_name: "type_2".to_string(),
        });

        registry.register(handler1);
        registry.register(handler2);

        let handlers = registry.handlers();
        assert_eq!(handlers.len(), 2);
    }

    #[test]
    fn test_registry_duplicate_register_replaces() {
        let mut registry = HandlerRegistry::new();

        let handler1 = Arc::new(TestHandler {
            job_type_name: "type_1".to_string(),
        });
        let handler2 = Arc::new(TestHandler {
            job_type_name: "type_1".to_string(),
        });

        registry.register(handler1);
        assert_eq!(registry.len(), 1);

        // Register again with same job_type (debug_assert fires but doesn't panic in tests)
        registry.register(handler2);

        // Should still have 1 handler (replaced)
        assert_eq!(registry.len(), 1);
        assert!(registry.get("type_1").is_some());
    }
}
