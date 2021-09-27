use log::LevelFilter;
use std::env;

pub fn setup() {
    if env::var_os("RUST_LOG").is_none() {
        pretty_env_logger::formatted_timed_builder()
            .filter_module("warp", LevelFilter::Info)
            .filter_module("linkje_api", LevelFilter::Trace)
            .filter_level(LevelFilter::Debug)
            .init();
    } else {
        let _ = pretty_env_logger::try_init();
    }

    env::set_var("ENVIRONMENT", "localhost");
    env::set_var("MONGO_USER", "linkje_test");
    env::set_var("MONGO_PASS", "test");
    env::set_var("MONGO_HOST", "localhost");
    env::set_var("MONGO_PORT", "7011");
    env::set_var("MONGO_DB", "linkje-test");
}
