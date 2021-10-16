pub mod config;
pub mod errors;
pub mod users;

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate log;

use crate::config::Config;
use mongodb::options::ClientOptions;
use mongodb::Client;
use mongodb::Database;
use std::error::Error;

pub mod users_api {
    use crate::errors::ErrorKind::EntityNotFound;
    use crate::users::{GetUserResponse, UpdateUserRequest, CreateUserRequest};
    use mongodb::Database;
    use rocket::http::Status;
    use rocket::serde::json::Json;
    use rocket::State;

    #[get("/user/<user_id>")]
    pub async fn get_user(
        user_id: &str,
        db: &State<Database>,
    ) -> Result<Json<GetUserResponse>, Status> {
        trace!("get_user({}, _)", &user_id);
        let get_user_response = crate::users::get(user_id, &db).await;
        match get_user_response {
            Ok(user) => Ok(Json(user)),
            Err(error) => {
                trace!("Error retrieving user with id {}", user_id);
                match error {
                    EntityNotFound { message: _ } => Err(Status::NotFound),
                    _ => Err(Status::ServiceUnavailable),
                }
            }
        }
    }

    #[put("/user", data = "<update_request>")]
    pub async fn update_user(update_request: Json<UpdateUserRequest>, db: &State<Database>) -> Result<Json<GetUserResponse>, Status> {
        trace!("update_user(db, {}", update_request.user_id);
        let update_response = crate::users::update(&update_request, &db).await;
        match update_response {
            Ok(updated_user) => Ok(Json(updated_user)),
            Err(error) => {
                info!("Error updating user: {}", error);
                match error {
                    EntityNotFound { message: _ } => Err(Status::NotFound),
                    _ => Err(Status::ServiceUnavailable),
                }
            }
        }
    }

    #[post("/user", data = "<create_request>")]
    pub async fn create_user(create_request: Json<CreateUserRequest>, db: &State<Database>) -> Result<Json<GetUserResponse>, Status> {
        trace!("create_user({}, _)", create_request.email_address);
        let create_response = crate::users::create(&create_request, &db).await;
        match create_response {
            Ok(created_user) => Ok(Json(created_user)),
            Err(_) => Err(Status::ServiceUnavailable)
        }
    }
}

use crate::users_api::{get_user, create_user, update_user};
use rocket::{Rocket, Build};


pub fn rocket(db: Database) -> Rocket<Build> {
    rocket::build()
        .manage(db)
        .mount("/", routes![get_user, create_user, update_user])
}

pub async fn create_mongo_connection(config: &Config) -> Result<Database, Box<dyn Error>> {
    trace!("Connecting mongodb, config {}", config);
    let client_options = ClientOptions::parse(&config.mongo_url).await?;
    let client = Client::with_options(client_options)?;
    info!("Mongo db client connected with config {}", config);
    let db = client.database(&config.mongo_db);
    Ok(db)
}
