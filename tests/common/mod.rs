pub mod api_calls;

use std::env;
use std::fmt::Display;

use log::LevelFilter;
use mongodb::Database;

use bridgekeeper_api::config::Config;
use bridgekeeper_api::user::{CreateUserRequest, User};
use fake::faker::internet::en::{Password, SafeEmail};
use fake::faker::name::en::{FirstName, LastName, Name};
use fake::Fake;
use rocket::local::asynchronous::Client;
use std::io::Write;
use std::sync::Once;
use std::thread::current;
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
                .format(|buf, record| {
                    writeln!(
                        buf,
                        "{:?} - {} - {}",
                        current().id(),
                        record.level(),
                        record.args()
                    )
                })
                .filter_module("rocket", LevelFilter::Error)
                .filter_module("bridgekeeper_api", LevelFilter::Trace)
                .filter_module("test_users", LevelFilter::Trace)
                .filter_module("test_totp", LevelFilter::Trace)
                .filter_module("test_illegal_access", LevelFilter::Trace)
                .filter_level(LevelFilter::Warn)
                .init();
        } else {
            pretty_env_logger::init();
        }
    });
    set_env_var_if_not_set("ENVIRONMENT", "localhost");
    set_env_var_if_not_set("MONGO_USER", "bridgekeeper_test");
    set_env_var_if_not_set("MONGO_PASS", "bridgekeeper");
    set_env_var_if_not_set("MONGO_HOST", "localhost");
    set_env_var_if_not_set("MONGO_PORT", "7011");
    set_env_var_if_not_set("MONGO_DB", "bridgekeeper-test");
    set_env_var_if_not_set("JWT_TOKEN_SECRET", "bridgekeeper-test");

    let config = bridgekeeper_api::config::Config::from_environment();
    let db = bridgekeeper_api::create_mongo_connection(&config)
        .await
        .unwrap();

    let client = Client::untracked(bridgekeeper_api::rocket(&db.clone(), &config.clone()))
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
            db.collection::<User>("user").drop(None).await.unwrap();
            db.collection::<User>("avatar").drop(None).await.unwrap();
            info!("Emptied the Users collection");
            EMPTIED_USERS_COLLECTION_BARRIER = 1;
        }

        let mut wait_counter = 0;

        while EMPTIED_USERS_COLLECTION_BARRIER == 0 {
            info!("Waiting on the emptying of the users collection");
            sleep(Duration::from_millis(200)).await;
            wait_counter += 1;

            if wait_counter > 100 {
                assert!(false)
            }
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
    format!("Rr$3-{}", Password(10..15).fake::<String>())
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
