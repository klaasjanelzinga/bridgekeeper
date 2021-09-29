pub mod config;
pub mod errors;
pub mod users;

use config::Config;
use mongodb::options::ClientOptions;
use mongodb::{Client, Database};
use std::error::Error;
use users::User;
use warp::Filter;

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
    use std::convert::Infallible;

    use mongodb::Database;
    use warp::http::StatusCode;
    use warp::Rejection;

    impl warp::reject::Reject for crate::errors::ErrorKind {}

    pub async fn get_by_email_address(email_address: String, db: Database) -> Result<impl warp::Reply, Rejection> {
        log::trace!("get_by_email_address({}, _)", &email_address);
        let get_user_response = crate::users::get_by_email_address(&email_address, db).await;
        match get_user_response {
            Ok(user) => Ok(warp::reply::json(&user)),
            Err(error) => {
                log::info!("get_by_email_address({}, _) failed: {}", &email_address, error);
                match error {
                    crate::errors::ErrorKind::EntityNotFound { message : _} => Err(warp::reject::not_found()),
                    _ => Err(warp::reject::custom(error)),
                }
            },
        }
    }

    pub async fn create(
        db: Database,
        mut user: crate::users::User,
    ) -> Result<impl warp::Reply, Infallible> {
        log::trace!("Creating user, {}", user);
        let result = crate::users::create(&mut user, db).await;
        // TODO error handling
        let user = result.unwrap();
        log::trace!("Inserted {}", user);
        Ok(warp::reply::with_status(
            warp::reply::json(&user),
            StatusCode::CREATED,
        ))
    }
}

fn json_body() -> impl Filter<Extract = (User,), Error = warp::Rejection> + Clone {
    // When accepting a body, we want a JSON body
    // (and to reject huge payloads)...
    warp::body::content_length_limit(1024 * 16).and(warp::body::json())
}

pub fn with_db(
    db: Database,
) -> impl Filter<Extract = (Database,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || db.clone())
}

pub fn all_routes(
    db: Database,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    user_routes(db.clone()).or(linkje_routes(db.clone()))
}

pub fn linkje_routes(
    db: Database,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("linkje")
        .and(warp::get())
        .and(with_db(db))
        .and_then(linkje::get)
}

pub fn user_routes(
    db: Database,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("user")
        .and(warp::post())
        .and(with_db(db.clone()))
        .and(json_body())
        .and_then(handlers::create)
        .or(warp::path!("user" / String)
            .and(warp::get())
            .and(with_db(db.clone()))
            .and_then(handlers::get_by_email_address))

    // post_user_route(db.clone()).or(get_user_route(db.clone()))
}

pub async fn create_mongo_connection(config: &Config) -> Result<Database, Box<dyn Error>> {
    log::trace!("Connecting mongo-db, config {}", config);
    let client_options = ClientOptions::parse(&config.mongo_url).await?;
    let client = Client::with_options(client_options)?;
    log::info!("Mongo db-Client connected with config {}", config);
    let db = client.database(&config.mongo_db);
    Ok(db)
}
