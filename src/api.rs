extern crate argon2;
#[macro_use]
extern crate rocket;

use std::error::Error;

use mongodb::options::ClientOptions;
use mongodb::Client;
use mongodb::Database;
use rocket::{Build, Rocket};

use crate::config::Config;
use crate::user_api::{
    change_password, confirm_totp_registration, create_user, get_user, login,
    start_totp_registration, update_user, validate_totp,
};

pub mod config;
pub mod errors;
pub mod jwt;
pub mod user;
pub mod user_api;
pub mod user_totp;
mod util;

pub fn rocket(db: &Database, config: &Config<'static>) -> Rocket<Build> {
    rocket::build()
        .manage(db.clone())
        .manage(config.clone())
        .mount(
            "/",
            routes![
                get_user,
                create_user,
                update_user,
                login,
                change_password,
                start_totp_registration,
                confirm_totp_registration,
                validate_totp,
            ],
        )
}

pub async fn create_mongo_connection(config: &Config<'_>) -> Result<Database, Box<dyn Error>> {
    trace!("Connecting mongodb, config {}", config);
    let client_options = ClientOptions::parse(&config.mongo_url).await?;
    let client = Client::with_options(client_options)?;
    info!("Mongo db client connected with config {}", config);
    let db = client.database(&config.mongo_db);
    Ok(db)
}
