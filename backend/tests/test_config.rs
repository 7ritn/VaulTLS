use std::sync::Once;

static INIT: Once = Once::new();

/// Initialize test environment
pub fn init_test_env() {
    INIT.call_once(|| {
        // Set test environment variables
        std::env::set_var("VAULTLS_LOG_LEVEL", "debug");
        std::env::set_var("VAULTLS_API_SECRET", "test_secret_key_for_testing_only_32_chars");
        std::env::set_var("VAULTLS_DATABASE_URL", ":memory:");
        std::env::set_var("VAULTLS_MAIL_HOST", "localhost");
        std::env::set_var("VAULTLS_MAIL_PORT", "1025");
        std::env::set_var("VAULTLS_MAIL_FROM", "test@vaultls.test");
        
        // Initialize logging for tests
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_test_env() {
        init_test_env();
        assert_eq!(std::env::var("VAULTLS_LOG_LEVEL").unwrap(), "debug");
        assert_eq!(std::env::var("VAULTLS_DATABASE_URL").unwrap(), ":memory:");
    }
}
