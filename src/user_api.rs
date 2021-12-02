use mongodb::Database;
use rocket::http::Status;
use rocket::response::status;
use rocket::serde::json::Json;
use rocket::State;

use crate::config::Config;
use crate::jwt::ValidJwtToken;
use crate::user::{
    change_password_for_user, get_with_user_id, ChangePasswordRequest, ChangePasswordResponse,
    CreateUserRequest, GetUserResponse, LoginRequest, LoginResponse, UpdateUserRequest,
};
use crate::user_totp::{
    confirm_totp_code_for_user, start_totp_registration_for_user, validate_totp_for_user,
    ConfirmTotpResponse, StartTotpRegistrationResult, ValidateTotpRequest,
};

#[get("/user/<user_id>")]
pub async fn get_user(
    user_id: &str,
    db: &State<Database>,
    valid_jwt_token: ValidJwtToken,
) -> Result<Json<GetUserResponse>, Status> {
    trace!("get_user({}, _, {})", &user_id, valid_jwt_token);
    let user = get_with_user_id(&valid_jwt_token, user_id, db).await?;
    Ok(Json(GetUserResponse::from(&user)))
}

#[put("/user", data = "<update_request>")]
pub async fn update_user(
    update_request: Json<UpdateUserRequest>,
    db: &State<Database>,
    valid_jwt_token: ValidJwtToken,
) -> Result<Json<GetUserResponse>, Status> {
    trace!(
        "update_user(db, {}, {})",
        update_request.user_id,
        valid_jwt_token
    );
    let user = get_with_user_id(&valid_jwt_token, &update_request.user_id, db).await?;
    let update_response = crate::user::update(&user, &update_request, &db).await?;
    Ok(Json(update_response))
}

#[post("/user", data = "<create_request>")]
pub async fn create_user(
    create_request: Json<CreateUserRequest>,
    db: &State<Database>,
) -> Result<status::Custom<Json<GetUserResponse>>, Status> {
    trace!("create_user({}, _)", create_request.email_address);
    let create_response = crate::user::create(&create_request, &db).await?;
    Ok(status::Custom(Status::Created, Json(create_response)))
}

#[post("/user/login", data = "<login_request>")]
pub async fn login(
    login_request: Json<LoginRequest>,
    config: &State<Config<'_>>,
    db: &State<Database>,
) -> Result<Json<LoginResponse>, Status> {
    trace!("login_request({}, _)", login_request.email_address);
    let login_result = crate::user::login(&login_request, config, &db).await;
    match login_result {
        Ok(login_response) => Ok(Json(login_response)),
        Err(error_kind) => {
            trace!("Could not log user in {}", error_kind);
            Err(Status::Unauthorized)
        }
    }
}

#[post("/user/<user_id>/change-password", data = "<change_password_request>")]
pub async fn change_password(
    user_id: &str,
    change_password_request: Json<ChangePasswordRequest>,
    valid_jwt_token: ValidJwtToken,
    db: &State<Database>,
) -> Result<Json<ChangePasswordResponse>, Status> {
    trace!("change_password({}, _, {}, _)", user_id, valid_jwt_token);
    let user = get_with_user_id(&valid_jwt_token, user_id, db).await?;

    let result = change_password_for_user(&user, &change_password_request, db).await?;
    Ok(Json(result))
}

#[post("/user/<user_id>/start-totp-registration")]
pub async fn start_totp_registration(
    user_id: &str,
    valid_jwt_token: ValidJwtToken,
    db: &State<Database>,
) -> Result<Json<StartTotpRegistrationResult>, Status> {
    trace!(
        "start_totp_registration({}, {}, _)",
        user_id,
        valid_jwt_token
    );
    let user = get_with_user_id(&valid_jwt_token, user_id, db).await?;

    let result = start_totp_registration_for_user(&user, db).await?;
    Ok(Json(result))
}

#[post(
    "/user/<user_id>/confirm-totp-registration",
    data = "<validate_totp_request>"
)]
pub async fn confirm_totp_registration(
    user_id: &str,
    validate_totp_request: Json<ValidateTotpRequest>,
    valid_jwt_token: ValidJwtToken,
    db: &State<Database>,
) -> Result<Json<ConfirmTotpResponse>, Status> {
    trace!(
        "confirm_totp_registration({}, {}, _)",
        user_id,
        valid_jwt_token
    );

    let user = get_with_user_id(&valid_jwt_token, user_id, db).await?;
    let result = confirm_totp_code_for_user(&user, &validate_totp_request, db).await?;

    Ok(Json(result))
}

#[post("/user/<user_id>/validate-totp", data = "<validate_totp_request>")]
pub async fn validate_totp(
    user_id: &str,
    config: &State<Config<'_>>,
    validate_totp_request: Json<ValidateTotpRequest>,
    valid_jwt_token: ValidJwtToken,
    db: &State<Database>,
) -> Result<Json<LoginResponse>, Status> {
    trace!("validate_totp({}, {}, _)", user_id, valid_jwt_token);

    let user = get_with_user_id(&valid_jwt_token, user_id, db).await?;
    let result = validate_totp_for_user(&user, &config, &validate_totp_request)?;

    Ok(Json(result))
}
