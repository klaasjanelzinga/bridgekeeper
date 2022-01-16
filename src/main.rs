#[macro_use]
extern crate log;

use std::env::var_os;
use std::error::Error;

use log::LevelFilter;
use pretty_env_logger::{formatted_timed_builder, init};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    if var_os("RUST_LOG").is_none() {
        formatted_timed_builder()
            .filter_module("warp", LevelFilter::Info)
            .filter_module("bridgekeeper", LevelFilter::Trace)
            .filter_level(LevelFilter::Info)
            .init();
    } else {
        init()
    }

    let config = bridgekeeper_api::config::Config::from_environment();
    let db = bridgekeeper_api::create_mongo_connection(&config).await?;

    info!("Starting server on port 8000");
    bridgekeeper_api::launch(&db, &config).await;

    Ok(())
}
