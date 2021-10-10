use std::env;
use std::fmt::Display;

use log::LevelFilter;
use mongodb::Database;
use warp::http::Response;
use warp::hyper::body::Bytes;

use fake::faker::internet::en::SafeEmail;
use fake::faker::name::en::{FirstName, LastName, Name};
use fake::Fake;
use linkje_api::config::Config;
use linkje_api::users::User;
use std::sync::Once;
use std::time::Duration;
use tokio::time::sleep;

pub struct TestFixtures {
    pub db: Database,
    pub config: Config,
}

static LOG_INIT: Once = Once::new();

pub async fn setup() -> TestFixtures {
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
    env::set_var("ENVIRONMENT", "localhost");
    env::set_var("MONGO_USER", "linkje_test");
    env::set_var("MONGO_PASS", "test");
    env::set_var("MONGO_HOST", "localhost");
    env::set_var("MONGO_PORT", "7011");
    env::set_var("MONGO_DB", "linkje-test");

    let config = linkje_api::config::create().unwrap();
    let db = linkje_api::create_mongo_connection(&config).await.unwrap();

    TestFixtures { config, db }
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

pub fn deserialize_user(response: &Response<Bytes>) -> User {
    let as_string = String::from_utf8(response.body().to_vec()).unwrap();
    serde_json::from_str(&as_string).unwrap()
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

pub fn user() -> User {
    given("User to create", || User {
        _id: None,
        user_id: None,
        email_address: SafeEmail().fake::<String>(),
        first_name: FirstName().fake(),
        last_name: LastName().fake(),
        display_name: Name().fake(),
        password_hash: String::from("asd"),
        password_salt: String::from("asd"),
        otp_hash: None,
        otp_backup_codes: vec![],
        pending_otp_hash: None,
        pending_backup_codes: vec![],
        is_approved: true,
    })
}
