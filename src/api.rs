pub mod config;

use config::Config;
use mongodb::options::ClientOptions;
use mongodb::{Client, Database};
use std::error::Error;
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

pub mod users {
    use std::convert::Infallible;

    use mongodb::bson::doc;
    use mongodb::Database;
    use serde::{Deserialize, Serialize};
    use std::fmt::{Display, Formatter};
    use warp::http::StatusCode;

    #[derive(Debug, Deserialize, Serialize, Clone)]
    pub struct User {
        pub user_id: i32,
        pub email_address: String,
        pub first_name: String,
        pub last_name: String,
    }

    impl Display for User {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("User")
                .field("email_address", &self.email_address)
                .field("first_name", &self.first_name)
                .field("last_name", &self.last_name)
                .field("user_id", &self.user_id)
                .finish()
        }
    }

    pub async fn get(email_address: String, db: Database) -> Result<impl warp::Reply, Infallible> {
        log::trace!("Get a user with email_address {}", email_address);
        let collection = db.collection::<User>("users");
        let find_filter = doc! { "email_address": &email_address };
        let find_result = collection.find_one(find_filter, None).await;

        Ok(warp::reply::json(&find_result.unwrap()))
    }

    pub async fn create(db: Database, user: User) -> Result<impl warp::Reply, Infallible> {
        log::trace!("Creating user, {}", user);
        let collection = db.collection::<User>("users");
        let insert_result = collection.insert_one(user, None).await;
        log::trace!("Inserted {}", insert_result.unwrap().inserted_id);
        Ok(StatusCode::CREATED)
    }
}

fn json_body() -> impl Filter<Extract = (users::User,), Error = warp::Rejection> + Clone {
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

pub fn get_user_route(
    db: Database,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("user" / String)
        .and(warp::get())
        .and(with_db(db))
        .and_then(users::get)
}

pub fn linkje_routes(
    db: Database,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("linkje")
        .and(warp::get())
        .and(with_db(db))
        .and_then(linkje::get)
}

pub fn post_user_route(
    db: Database,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("user")
        .and(warp::post())
        .and(with_db(db))
        .and(json_body())
        .and_then(users::create)
}

pub fn user_routes(
    db: Database,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    post_user_route(db.clone()).or(get_user_route(db.clone()))
}

pub async fn create_mongo_connection(config: &Config) -> Result<Database, Box<dyn Error>> {
    log::trace!("Connecting mongo-db, config {}", config);
    let client_options = ClientOptions::parse(&config.mongo_url).await?;
    let client = Client::with_options(client_options)?;
    log::trace!("Client connected");
    let db = client.database(&config.mongo_db);
    Ok(db)
}
