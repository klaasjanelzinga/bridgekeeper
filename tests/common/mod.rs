use std::env;
use std::fmt::Display;

use log::LevelFilter;
use mongodb::Database;

use fake::faker::internet::en::{Password, SafeEmail};
use fake::faker::name::en::{FirstName, LastName, Name};
use fake::Fake;
use linkje_api::config::Config;
use linkje_api::users::{CreateUserRequest, User};
use rocket::local::asynchronous::Client;
use std::sync::Once;
use std::time::Duration;
use tokio::time::sleep;

pub struct TestFixtures<'a> {
    pub db: Database,
    pub config: Config<'a>,
    pub client: Client,
}

static LOG_INIT: Once = Once::new();

fn set_env_var_if_not_set(env_var: &str, default_value: &str) {
    if env::var(env_var).is_err() {
        env::set_var(env_var, default_value)
    }
}

pub async fn setup<'a>() -> TestFixtures<'a> {
    LOG_INIT.call_once(|| {
        if env::var_os("RUST_LOG").is_none() {
            pretty_env_logger::formatted_timed_builder()
                .filter_module("warp", LevelFilter::Info)
                .filter_module("linkje", LevelFilter::Trace)
                .filter_module("test_users", LevelFilter::Trace)
                .filter_level(LevelFilter::Debug)
                .init();
        } else {
            pretty_env_logger::init();
        }
    });
    set_env_var_if_not_set("ENVIRONMENT", "localhost");
    set_env_var_if_not_set("MONGO_USER", "linkje_test");
    set_env_var_if_not_set("MONGO_PASS", "test");
    set_env_var_if_not_set("MONGO_HOST", "localhost");
    set_env_var_if_not_set("MONGO_PORT", "7011");
    set_env_var_if_not_set("MONGO_DB", "linkje-test");
    set_env_var_if_not_set("JWT_TOKEN_SECRET", "linkje-test");

    let config = linkje_api::config::Config::from_environment();
    let db = linkje_api::create_mongo_connection(&config).await.unwrap();

    let client = Client::tracked(linkje_api::rocket(&db.clone(), &config.clone()))
        .await
        .expect("Client expected");

    TestFixtures { config, db, client }
}

static mut EMPTY_USERS_COLLECTION_BARRIER: u32 = 1;
static mut EMPTIED_USERS_COLLECTION_BARRIER: u32 = 0;

pub async fn empty_users_collection(db: &Database) {
    unsafe {
        if EMPTY_USERS_COLLECTION_BARRIER == 1 {
            EMPTY_USERS_COLLECTION_BARRIER = 0;
            info!("Emptying the Users collection");
            db.collection::<User>("users").drop(None).await.unwrap();
            info!("Emptied the Users collection");
            EMPTIED_USERS_COLLECTION_BARRIER = 1;
        }

        while EMPTIED_USERS_COLLECTION_BARRIER == 0 {
            warn!("Waiting on the emptying of the users collection");
            sleep(Duration::from_millis(100)).await;
        }
    }

    ()
}

pub fn given<R, T>(given_text: &str, func: T) -> R
where
    T: Fn() -> R,
    R: Display,
{
    let result = func();
    trace!("GIVEN: {}; {}", given_text, result);
    result
}

pub fn fake_password() -> String {
    format!("Rr$-{}", Password(10..15).fake::<String>())
}

pub fn create_user_request() -> CreateUserRequest {
    given("CreateUserRequest to create", || CreateUserRequest {
        email_address: SafeEmail().fake::<String>(),
        first_name: FirstName().fake(),
        last_name: LastName().fake(),
        display_name: Name().fake(),
        new_password: fake_password(),
    })
}
