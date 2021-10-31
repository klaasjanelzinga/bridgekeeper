#[macro_use]
extern crate log;

use std::env::var_os;
use std::error::Error;

use log::LevelFilter;
use pretty_env_logger::{formatted_timed_builder, init};

#[rocket::main]
async fn main() -> Result<(), Box<dyn Error>> {
    if var_os("RUST_LOG").is_none() {
        formatted_timed_builder()
            .filter_module("warp", LevelFilter::Info)
            .filter_module("linkje_api", LevelFilter::Trace)
            .filter_level(LevelFilter::Info)
            .init();
    } else {
        init()
    }

    let config = linkje_api::config::Config::from_environment();
    let db = linkje_api::create_mongo_connection(&config).await?;

    info!("Starting server on port 8000");
    linkje_api::rocket(&db, &config).launch().await?;

    Ok(())
}
