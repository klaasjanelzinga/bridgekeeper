use mongodb::Database;
use rocket::http::Status;
use rocket::response::status;
use rocket::serde::json::Json;
use rocket::State;

use crate::config::Config;
use crate::jwt::{
    create_api_jwt_token_for_user, delete_jwt_api_token_for_user, CreateJwtApiRequest,
    CreateJwtApiResponse,
};
use crate::request_guards::{JwtToken, OtpValidatedJwtToken};
use crate::user::{
    change_password_for_user, create, update, ChangePasswordRequest, ChangePasswordResponse,
    CreateUserRequest, EmptyOkResponse, GetUserResponse, LoginRequest, LoginResponse,
    UpdateUserRequest,
};
use crate::user_totp::{
    confirm_totp_code_for_user, start_totp_registration_for_user, validate_totp_for_user,
    ConfirmTotpResponse, StartTotpRegistrationResult, ValidateTotpRequest,
};

#[get("/user")]
pub async fn get_user(
    valid_jwt_token: OtpValidatedJwtToken,
) -> Result<Json<GetUserResponse>, Status> {
    trace!("get_user(_, {})", valid_jwt_token);
    Ok(Json(GetUserResponse::from(&valid_jwt_token.user)))
}

#[put("/user", data = "<update_request>")]
pub async fn update_user(
    update_request: Json<UpdateUserRequest>,
    db: &State<Database>,
    valid_jwt_token: OtpValidatedJwtToken,
) -> Result<Json<GetUserResponse>, Status> {
    trace!(
        "update_user(db, {}, {})",
        update_request.user_id,
        valid_jwt_token
    );
    let update_response = update(&valid_jwt_token.user, &update_request, &db).await?;
    Ok(Json(update_response))
}

#[post("/user", data = "<create_request>")]
pub async fn create_user(
    create_request: Json<CreateUserRequest>,
    db: &State<Database>,
) -> Result<status::Custom<Json<GetUserResponse>>, Status> {
    trace!("create_user({}, _)", create_request.email_address);
    let create_response = create(&create_request, &db).await?;
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

#[post("/user/change-password", data = "<change_password_request>")]
pub async fn change_password(
    change_password_request: Json<ChangePasswordRequest>,
    valid_jwt_token: OtpValidatedJwtToken,
    db: &State<Database>,
) -> Result<Json<ChangePasswordResponse>, Status> {
    trace!("change_password(_, {}, _)", valid_jwt_token);
    let result =
        change_password_for_user(&valid_jwt_token.user, &change_password_request, db).await?;
    Ok(Json(result))
}

#[post("/user/start-totp-registration")]
pub async fn start_totp_registration(
    jwt_token: JwtToken,
    db: &State<Database>,
) -> Result<Json<StartTotpRegistrationResult>, Status> {
    trace!("start_totp_registration({}, _)", jwt_token);
    let result = start_totp_registration_for_user(&jwt_token.user, db).await?;
    Ok(Json(result))
}

#[post("/user/confirm-totp-registration", data = "<validate_totp_request>")]
pub async fn confirm_totp_registration(
    validate_totp_request: Json<ValidateTotpRequest>,
    jwt_token: JwtToken,
    db: &State<Database>,
) -> Result<Json<ConfirmTotpResponse>, Status> {
    trace!("confirm_totp_registration({}, _)", jwt_token);

    let result = confirm_totp_code_for_user(&jwt_token.user, &validate_totp_request, db).await?;

    Ok(Json(result))
}

#[post("/user/validate-totp", data = "<validate_totp_request>")]
pub async fn validate_totp(
    config: &State<Config<'_>>,
    validate_totp_request: Json<ValidateTotpRequest>,
    jwt_token: JwtToken,
) -> Result<Json<LoginResponse>, Status> {
    trace!("validate_totp({}, _)", jwt_token);

    let result = validate_totp_for_user(&jwt_token.user, &config, &validate_totp_request)?;
    Ok(Json(result))
}

#[post("/user/jwt-api-token", data = "<create_jwt_api_token_request>")]
pub async fn create_jwt_api_token(
    config: &State<Config<'_>>,
    create_jwt_api_token_request: Json<CreateJwtApiRequest>,
    jwt_token: OtpValidatedJwtToken,
    db: &State<Database>,
) -> Result<Json<CreateJwtApiResponse>, Status> {
    trace!("create_jwt_api_token()");
    let token = create_api_jwt_token_for_user(
        &jwt_token.user,
        &create_jwt_api_token_request.public_token_id,
        &config.encoding_key,
        db,
    )
    .await?;

    Ok(Json(CreateJwtApiResponse { token }))
}

#[delete("/user/jwt-api-token/<public_token_id>")]
pub async fn delete_jwt_api_token(
    public_token_id: String,
    jwt_token: OtpValidatedJwtToken,
    db: &State<Database>,
) -> Result<Json<EmptyOkResponse>, Status> {
    trace!("delete_jwt_api_token({})", public_token_id);
    delete_jwt_api_token_for_user(&jwt_token.user, &public_token_id, db).await?;

    Ok(Json(EmptyOkResponse { success: true }))
}
