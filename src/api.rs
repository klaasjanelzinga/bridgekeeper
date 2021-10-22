pub mod config;
pub mod errors;
pub mod users;

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate log;
extern crate argon2;

use crate::config::Config;
use mongodb::options::ClientOptions;
use mongodb::Client;
use mongodb::Database;
use std::error::Error;

pub mod users_api {
    use crate::users::{CreateUserRequest, GetUserResponse, UpdateUserRequest, LoginRequest, LoginResponse};
    use mongodb::Database;
    use rocket::http::Status;
    use rocket::response::status;
    use rocket::serde::json::Json;
    use rocket::State;

    #[get("/user/<user_id>")]
    pub async fn get_user(
        user_id: &str,
        db: &State<Database>,
    ) -> Result<Json<GetUserResponse>, Status> {
        trace!("get_user({}, _)", &user_id);
        let get_user_response = crate::users::get(user_id, &db).await?;
        Ok(Json(get_user_response))
    }

    #[put("/user", data = "<update_request>")]
    pub async fn update_user(
        update_request: Json<UpdateUserRequest>,
        db: &State<Database>,
    ) -> Result<Json<GetUserResponse>, Status> {
        trace!("update_user(db, {}", update_request.user_id);
        let update_response = crate::users::update(&update_request, &db).await?;
        Ok(Json(update_response))
    }

    #[post("/user", data = "<create_request>")]
    pub async fn create_user(
        create_request: Json<CreateUserRequest>,
        db: &State<Database>,
    ) -> Result<status::Custom<Json<GetUserResponse>>, Status> {
        trace!("create_user({}, _)", create_request.email_address);
        let create_response = crate::users::create(&create_request, &db).await?;
        Ok(status::Custom(Status::Created, Json(create_response)))
    }

    #[post("/user/login", data="<login_request>")]
    pub async fn login(login_request: Json<LoginRequest>, db: &State<Database>,) -> Result<Json<LoginResponse>, Status> {
        trace!("login_request({}, _)", login_request.email_address);
        let login_result = crate::users::login(&login_request, &db).await;
        match login_result {
            Ok(login_token) => {
                Ok( Json(LoginResponse{
                    token: login_token
                }))
            },
            Err(error_kind) => {
                trace!("Could not log user in {}", error_kind);
                Err(Status::Unauthorized)
            },
        }
    }

    // #[post("/user/<user_id>/change_password")]
    // fn change_password(change_password_request: Json<ChangePasswordRequest>, db: &State<Database>,) -> Result<Json<LoginResult>, Status> {
    //     trace!("change_password({}, _)", change_password_request);
    //
    //     Ok()
    // }
}

use crate::users_api::{create_user, get_user, update_user, login};
use rocket::{Build, Rocket};

pub fn rocket(db: Database) -> Rocket<Build> {
    rocket::build()
        .manage(db)
        .mount("/", routes![get_user, create_user, update_user, login])
}

pub async fn create_mongo_connection(config: &Config) -> Result<Database, Box<dyn Error>> {
    trace!("Connecting mongodb, config {}", config);
    let client_options = ClientOptions::parse(&config.mongo_url).await?;
    let client = Client::with_options(client_options)?;
    info!("Mongo db client connected with config {}", config);
    let db = client.database(&config.mongo_db);
    Ok(db)
}
