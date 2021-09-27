use std::env;
use std::error::Error;

use log::LevelFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    if env::var_os("RUST_LOG").is_none() {
        pretty_env_logger::formatted_timed_builder()
            .filter_module("warp", LevelFilter::Info)
            .filter_module("linkje_api", LevelFilter::Trace)
            .filter_level(LevelFilter::Info)
            .init();
    } else {
        pretty_env_logger::init()
    }
    let config = linkje_api::config::create().unwrap();
    let db = linkje_api::create_mongo_connection(&config).await?;

    log::info!("Starting warp server on port 3030");
    warp::serve(linkje_api::all_routes(db))
        .run(([127, 0, 0, 1], 3030))
        .await;

    Ok(())
}
