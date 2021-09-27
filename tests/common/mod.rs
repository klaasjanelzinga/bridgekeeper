use log::LevelFilter;
use std::env;
use mongodb::Database;
use linkje_api::config::Config;
use linkje_api::users::User;

pub struct TestFixtures {
    pub db: Database,
    pub config: Config,
}

pub async fn setup() -> TestFixtures {
    if env::var_os("RUST_LOG").is_none() {
        pretty_env_logger::formatted_timed_builder()
            .filter_module("warp", LevelFilter::Info)
            .filter_module("linkje", LevelFilter::Trace)
            .filter_module("test_users", LevelFilter::Trace)
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

    let config = linkje_api::config::create().unwrap();
    let db =     linkje_api::create_mongo_connection(&config)
        .await
        .unwrap();
    log::info!("Emptying the Users collection");
    db
        .collection::<User>("users")
        .drop(None)
        .await
        .unwrap();


    log::trace!("Test setup done!");
    TestFixtures{
        config, db
    }
}

