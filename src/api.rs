#[macro_use]
extern crate log;
extern crate argon2;

use axum::routing::{delete, get, post};
use axum::{AddExtensionLayer, Router};
use hyper::header::AUTHORIZATION;
use std::error::Error;
use std::iter::once;

use crate::authorization_api::{add_authorization, is_authorized, is_jwt_api_valid};
use crate::avatar_api::{create_or_update_avatar, delete_avatar, get_avatar};
use mongodb::options::ClientOptions;
use mongodb::Client;
use mongodb::Database;
use tokio::signal;
use tower::ServiceBuilder;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::trace::TraceLayer;

use crate::config::Config;
use crate::user_api::{
    change_password, confirm_totp_registration, create_jwt_api_token, create_user,
    delete_jwt_api_token, get_user, login, start_totp_registration, update_user, validate_totp,
};

pub mod authorization;
pub mod authorization_api;
pub mod avatar;
pub mod avatar_api;
pub mod config;
pub mod errors;
pub mod jwt;
pub mod request_guards;
pub mod user;
pub mod user_api;
pub mod user_totp;
mod util;

pub fn application_routes(db: &Database, config: &Config<'static>) -> Router {
    Router::new()
        .route("/user", get(get_user).post(create_user).put(update_user))
        .route("/user/login", post(login))
        .route("/user/change-password", post(change_password))
        .route(
            "/user/avatar",
            get(get_avatar)
                .post(create_or_update_avatar)
                .delete(delete_avatar),
        )
        .route(
            "/user/start-totp-registration",
            post(start_totp_registration),
        )
        .route(
            "/user/confirm-totp-registration",
            post(confirm_totp_registration),
        )
        .route("/user/validate-totp", post(validate_totp))
        .route("/authorization", post(add_authorization))
        .route("/authorization/user", post(is_authorized))
        .route("/authorization/jwt-api-token", post(is_jwt_api_valid))
        .route(
            "/user/jwt-api-token",
            post(create_jwt_api_token).delete(delete_jwt_api_token),
        )
        .route(
            "/user/jwt-api-token/:public_token_id",
            delete(delete_jwt_api_token),
        )
        .layer(
            ServiceBuilder::new()
                .layer(SetSensitiveRequestHeadersLayer::new(once(AUTHORIZATION)))
                .layer(AddExtensionLayer::new(db.clone()))
                .layer(AddExtensionLayer::new(config.clone()))
                .layer(TraceLayer::new_for_http()),
        )
}

pub async fn launch(db: &Database, config: &Config<'static>) {
    debug!("listening on {}", config.bind_to);
    axum::Server::bind(&config.bind_to)
        .serve(application_routes(db, &config).into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
    ()
}

pub async fn create_mongo_connection(config: &Config<'_>) -> Result<Database, Box<dyn Error>> {
    trace!("Connecting mongodb, config {}", config);
    let client_options = ClientOptions::parse(&config.mongo_url).await?;
    let client = Client::with_options(client_options)?;
    info!("Mongo db client connected with config {}", config);
    let db = client.database(&config.mongo_db);
    Ok(db)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Signal received, starting graceful shutdown...");
}
