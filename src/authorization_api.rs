use crate::authorization::{is_jwt_api_token_valid, is_user_authorized_for};
use axum::extract::Extension;
use axum::Json;
use mongodb::Database;

use crate::authorization::create;
use crate::authorization_models::{
    AddAuthorizationRequest, Authorization, IsAuthorizedRequest, IsAuthorizedResponse,
    IsJwtApiTokenValidRequest,
};
use crate::errors::ErrorKind;
use crate::request_guards::{AccessToken, AuthorizedUser};
use crate::Config;

/// Add authorization to a user by an admin.
///
/// Authorization: Authorized User with Access Token.
///
/// Resources: Database.
pub async fn add_authorization(
    Json(add_authorization_request): Json<AddAuthorizationRequest>,
    Extension(db): Extension<Database>,
    authenticated_user: AuthorizedUser,
) -> Result<Json<Authorization>, ErrorKind> {
    trace!("add_authorization(_, _, {})", authenticated_user);
    let authorization = create(&add_authorization_request, &db).await?;
    Ok(Json(authorization))
}

/// Validate if a user is authorized for a resource.
///
/// Authorization: Access Token.
///
/// Resources: Database.
pub async fn is_authorized(
    Json(is_authorized_request): Json<IsAuthorizedRequest>,
    Extension(db): Extension<Database>,
    valid_jwt_token: AccessToken,
) -> Result<Json<IsAuthorizedResponse>, ErrorKind> {
    trace!(
        "is_authorized({}, _, {})",
        is_authorized_request,
        valid_jwt_token
    );
    is_user_authorized_for(
        &valid_jwt_token.user,
        &is_authorized_request.application,
        &is_authorized_request.method,
        &is_authorized_request.uri,
        &db,
    )
    .await?;

    Ok(Json(IsAuthorizedResponse {
        is_authorized: true,
    }))
}

/// Validate if a jwt api token is valid.
///
/// Authorization: None.
///
/// Resources: Database, Config.
pub async fn is_jwt_api_valid(
    Json(is_jwt_api_token_valid_request): Json<IsJwtApiTokenValidRequest>,
    Extension(db): Extension<Database>,
    Extension(config): Extension<Config<'_>>,
) -> Result<Json<IsAuthorizedResponse>, ErrorKind> {
    trace!("is_jwt_api_valid()");
    is_jwt_api_token_valid(&is_jwt_api_token_valid_request.token, &config, &db).await?;

    Ok(Json(IsAuthorizedResponse {
        is_authorized: true,
    }))
}
