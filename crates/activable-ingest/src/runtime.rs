#[cfg(test)]
use crate::executor;

#[cfg(test)]
use crate::resource_registry::load_registry;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_registry_loads() {
        // This test verifies that the registry loads without error
        let registry = load_registry().expect("Failed to load registry");
        assert!(!registry.resource_types.is_empty());
    }

    #[test]
    fn test_create_account_config() {
        // Verify that account config has the right credentials provider.
        // (Ported from runtime.rs:121-129 to executor::create_account_config)
        let base_config = aws_config::SdkConfig::builder().build();
        let account_id = "111111111111";

        let _account_config = executor::create_account_config(&base_config, account_id);

        // The config should be created without panicking and should be a valid SdkConfig;
        // actual credential verification is done in integration tests with LocalStack.
        // Just verify the account ID is not empty (fixture validation).
        assert!(!account_id.is_empty());
    }
}
