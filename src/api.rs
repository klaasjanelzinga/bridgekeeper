pub mod config;
pub mod errors;
pub mod users;

use config::Config;
use mongodb::options::ClientOptions;
use mongodb::{Client, Database};
use std::error::Error;
use users::User;
use warp::{Reply, Rejection, Filter, path, post, get};
use std::convert::Infallible;

#[macro_use]
extern crate log;

pub mod linkje {
    use mongodb::Database;
    use serde::{Deserialize, Serialize};
    use std::convert::Infallible;

    #[derive(Debug, Deserialize, Serialize, Clone)]
    pub struct Linkje {
        pub description: String,
        pub url: String,
    }

    pub async fn get(_db: Database) -> Result<impl warp::Reply, Infallible> {
        let linkje = Linkje {
            description: String::from("Hi there"),
            url: String::from("http://www.google.com"),
        };

        Ok(warp::reply::json(&linkje))
    }
}

pub mod handlers {
    use mongodb::Database;
    use warp::http::StatusCode;
    use warp::{Rejection, Reply};
    use warp::reject::{not_found, custom};
    use warp::reply::{json, with_status};
    use crate::errors::ErrorKind::*;

    impl warp::reject::Reject for crate::errors::ErrorKind {}

    pub async fn get_user(
        user_id: String,
        db: Database,
    ) -> Result<impl Reply, Rejection> {
        trace!("get_user({}, _)", &user_id);
        let get_user_response = crate::users::get(&user_id, &db).await;
        match get_user_response {
            Ok(user) => Ok(json(&user)),
            Err(error) => {
                info!(
                    "get({}, _) failed: {}",
                    &user_id,
                    error
                );
                match error {
                    EntityNotFound { message: _ } => Err(not_found()),
                    _ => Err(custom(error)),
                }
            }
        }
    }

    pub async fn create_or_update_user(db: Database, user: crate::users::User) -> Result<impl Reply, Rejection> {
        trace!("create_or_update({}, _)", user);
        match user.user_id {
            Some(_) => {
                let update_response = crate::users::update(&user, &db).await;
                match update_response {
                    Ok(updated_user) => Ok(with_status(
                        json(&updated_user),
                        StatusCode::OK,
                    )),
                    Err(error) => {
                        info!("Error updating user {}", error);
                        match error {
                            EntityNotFound { message: _ } => Err(not_found()),
                            _ => Err(custom(error)),
                        }
                    }
                }
            },
            None => {
                let create_response = crate::users::create(&user, &db).await;
                match create_response {
                    Ok(created_user) => Ok(with_status(
                        json(&created_user),
                        StatusCode::CREATED,
                    )),
                    Err(error) => {
                        info!("Error creating user {}", error);
                        Err(custom(error))
                    }
                }
            }
        }
    }
}

fn json_body() -> impl Filter<Extract = (User,), Error = Rejection> + Clone {
    // When accepting a body, we want a JSON body
    // (and to reject huge payloads)...
    warp::body::content_length_limit(1024 * 16).and(warp::body::json())
}

pub fn with_db(
    db: Database,
) -> impl Filter<Extract = (Database,), Error = Infallible> + Clone {
    warp::any().map(move || db.clone())
}

pub fn all_routes(
    db: Database,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    user_routes(&db.clone()).or(linkje_routes(db.clone()))
}

pub fn linkje_routes(
    db: Database,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    path!("linkje")
        .and(get())
        .and(with_db(db))
        .and_then(linkje::get)
}

pub fn user_routes(
    db: &Database,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    path!("user")
        .and(post())
        .and(with_db(db.clone()))
        .and(json_body())
        .and_then(handlers::create_or_update_user)
        .or(path!("user" / String)
            .and(get())
            .and(with_db(db.clone()))
            .and_then(handlers::get_user))
}

pub async fn create_mongo_connection(config: &Config) -> Result<Database, Box<dyn Error>> {
    trace!("Connecting mongodb, config {}", config);
    let client_options = ClientOptions::parse(&config.mongo_url).await?;
    let client = Client::with_options(client_options)?;
    info!("Mongo db client connected with config {}", config);
    let db = client.database(&config.mongo_db);
    Ok(db)
}
