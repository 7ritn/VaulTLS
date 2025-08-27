mod common;
mod api;
mod test_config;

#[cfg(test)]
mod integration_tests {
    use crate::test_config::init_test_env;

    #[ctor::ctor]
    fn setup() {
        init_test_env();
    }
}