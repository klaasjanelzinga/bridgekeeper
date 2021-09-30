use std::env::var_os;
use std::error::Error;

use log::LevelFilter;
use pretty_env_logger::{init, formatted_timed_builder};
use warp::serve;

#[macro_use]
extern crate log;

#[tokio::main]
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
    let config = linkje_api::config::create().unwrap();
    let db = linkje_api::create_mongo_connection(&config).await?;

    info!("Starting warp server on port 3030");
    serve(linkje_api::all_routes(db))
        .run(([127, 0, 0, 1], 3030))
        .await;

    Ok(())
}
