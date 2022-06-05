use crate::avatar::delete_avatar_for_user;
use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use mongodb::Database;

use crate::errors::ErrorKind;
use crate::jwt::{create_api_jwt_token_for_user, delete_jwt_api_token_for_user};
use crate::jwt_models::{CreateJwtApiRequest, CreateJwtApiResponse};
use crate::request_guards::{AccessToken, OneShotToken, RefreshToken};
use crate::user::{change_password_for_user, create, delete_for_user, update};
use crate::user_models::{
    ChangePasswordRequest, ChangePasswordResponse, CreateUserRequest, EmptyOkResponse,
    GetUserResponse, LoginRequest, LoginResponse, LoginWithOtpResponse, UpdateUserRequest,
};
use crate::user_totp::{
    confirm_totp_code_for_user, start_totp_registration_for_user, validate_totp_for_user,
    validate_totp_with_backup_code_for_user,
};
use crate::user_totp_models::{
    StartTotpRegistrationResult, ValidateTotpRequest, ValidateTotpWithBackupCodeRequest,
};
use crate::Config;

/// Gets user details.
///
/// Authorization: Access Token.
///
/// Resources: None.
pub async fn get_user(valid_jwt_token: AccessToken) -> Result<Json<GetUserResponse>, ErrorKind> {
    trace!("get_user({})", valid_jwt_token);
    Ok(Json(GetUserResponse::from(&valid_jwt_token.user)))
}

/// Update the user.
///
/// Authorization: Access Token.
///
/// Resources: Database, Config.
pub async fn update_user(
    Json(update_request): Json<UpdateUserRequest>,
    Extension(db): Extension<Database>,
    valid_jwt_token: AccessToken,
) -> Result<Json<GetUserResponse>, ErrorKind> {
    trace!("update_user(_, {}, {})", update_request, valid_jwt_token);
    let update_response = update(&valid_jwt_token.user, &update_request, &db).await?;
    Ok(Json(update_response))
}

/// Creates a user.
///
/// Authorization: None.
///
/// Resources: Database.
pub async fn create_user(
    Json(create_request): Json<CreateUserRequest>,
    Extension(db): Extension<Database>,
) -> Response {
    trace!("create_user({}, _)", create_request);
    let create_response = create(&create_request, &db).await;
    match create_response {
        Ok(get_user_response) => {
            trace!("created user {}", get_user_response);
            (
                StatusCode::CREATED,
                Json(GetUserResponse::from(&get_user_response)),
            )
                .into_response()
        }
        Err(error) => error.into_response(),
    }
}

/// Delete the user.
pub async fn delete_user(
    Extension(db): Extension<Database>,
    valid_jwt_token: AccessToken,
) -> Result<Json<EmptyOkResponse>, ErrorKind> {
    trace!("delete_user(_, {}", valid_jwt_token);

    let result = delete_avatar_for_user(&valid_jwt_token.user, &db).await;
    match result {
        Ok(_) | Err(ErrorKind::EntityNotFound { message: _ }) => {
            delete_for_user(&valid_jwt_token.user, &db).await?;
            Ok(Json(EmptyOkResponse { success: true }))
        }
        Err(error_kind) => Err(error_kind),
    }
}

/// Change password for the user identified by the access token.
///
/// Authorization: None.
///
/// Resources: Database, Config.
pub async fn login(
    Json(login_request): Json<LoginRequest>,
    Extension(db): Extension<Database>,
    Extension(config): Extension<Config<'_>>,
) -> Result<Json<LoginResponse>, ErrorKind> {
    trace!("login_request({}, _)", login_request.email_address);
    let response = crate::user::login(&login_request, &config.clone(), &db).await?;
    Ok(Json(response))
}

/// Refresh the tokens for a user..
///
/// Authorization: Refresh Token.
///
/// Resources: Database, Config.
pub async fn refresh_token(
    Extension(db): Extension<Database>,
    Extension(config): Extension<Config<'_>>,
    valid_jwt_token: RefreshToken,
) -> Result<Json<LoginWithOtpResponse>, ErrorKind> {
    trace!("refresh_token()");
    let response =
        crate::user::refresh_token_for_user(&valid_jwt_token.user, &config.clone(), &db).await?;
    Ok(Json(response))
}

/// Change password for the user identified by the access token.
///
/// Authorization: Access Token.
///
/// Resources: Database.
pub async fn change_password(
    Json(change_password_request): Json<ChangePasswordRequest>,
    valid_jwt_token: AccessToken,
    Extension(db): Extension<Database>,
) -> Result<Json<ChangePasswordResponse>, ErrorKind> {
    trace!("change_password(_, {}, _)", valid_jwt_token);
    let result =
        change_password_for_user(&valid_jwt_token.user, &change_password_request, &db).await?;
    Ok(Json(result))
}

/// Start the totp registration.
///
/// Authorization: Access Token.
///
/// Resources: Database.
pub async fn start_totp_registration(
    jwt_token: AccessToken,
    Extension(db): Extension<Database>,
) -> Result<Json<StartTotpRegistrationResult>, ErrorKind> {
    trace!("start_totp_registration({}, _)", jwt_token);
    let result = start_totp_registration_for_user(&jwt_token.user, &db).await?;
    Ok(Json(result))
}

/// Confirm the totp registration with a totp-challenge.
///
/// Authorization: Access Token.
///
/// Resources: Database.
pub async fn confirm_totp_registration(
    Json(validate_totp_request): Json<ValidateTotpRequest>,
    jwt_token: AccessToken,
    Extension(db): Extension<Database>,
) -> Result<Json<EmptyOkResponse>, ErrorKind> {
    trace!("confirm_totp_registration({}, _)", jwt_token);
    confirm_totp_code_for_user(&jwt_token.user, &validate_totp_request, &db).await?;
    Ok(Json(EmptyOkResponse { success: true }))
}

/// Validate a totp challenge.
///
/// Authorization: One Shot Token.
///
/// Resources: Database, Config.
pub async fn validate_totp(
    Extension(config): Extension<Config<'_>>,
    validate_totp_request: Json<ValidateTotpRequest>,
    jwt_token: OneShotToken,
    Extension(db): Extension<Database>,
) -> Result<Json<LoginWithOtpResponse>, ErrorKind> {
    trace!("validate_totp({}, _)", jwt_token);
    let result =
        validate_totp_for_user(&jwt_token.user, &config, &validate_totp_request, &db).await?;
    Ok(Json(result))
}

/// Validate a totp challenge with a backup code.
///
/// Authorization: One Shot Token.
///
/// Resources: Database, Config.
pub async fn validate_totp_with_backup_code(
    Extension(config): Extension<Config<'_>>,
    validate_totp_request: Json<ValidateTotpWithBackupCodeRequest>,
    jwt_token: OneShotToken,
    Extension(db): Extension<Database>,
) -> Result<Json<LoginWithOtpResponse>, ErrorKind> {
    trace!("validate_totp({}, _)", jwt_token);
    let result = validate_totp_with_backup_code_for_user(
        &jwt_token.user,
        &config,
        &validate_totp_request,
        &db,
    )
    .await?;
    Ok(Json(result))
}

/// Create an api token.
///
/// Authorization: Access Token.
///
/// Resources: Database, Config.
pub async fn create_jwt_api_token(
    Extension(config): Extension<Config<'_>>,
    Json(create_jwt_api_token_request): Json<CreateJwtApiRequest>,
    jwt_token: AccessToken,
    Extension(db): Extension<Database>,
) -> Result<Json<CreateJwtApiResponse>, ErrorKind> {
    trace!("create_jwt_api_token()");
    let token = create_api_jwt_token_for_user(
        &jwt_token.user,
        &create_jwt_api_token_request.public_token_id,
        &config.encoding_key,
        &db,
    )
    .await?;

    Ok(Json(CreateJwtApiResponse { token }))
}

/// Delete an api token..
///
/// Authorization: Access Token.
///
/// Resources: Database.
pub async fn delete_jwt_api_token(
    Path(public_token_id): Path<String>,
    jwt_token: AccessToken,
    Extension(db): Extension<Database>,
) -> Result<Json<EmptyOkResponse>, ErrorKind> {
    trace!("delete_jwt_api_token({})", public_token_id);
    delete_jwt_api_token_for_user(&jwt_token.user, &public_token_id, &db).await?;
    Ok(Json(EmptyOkResponse { success: true }))
}
