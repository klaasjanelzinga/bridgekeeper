use crate::authorization::{
    is_jwt_api_token_valid, is_user_authorized_for, AddAuthorizationRequest, Authorization,
    IsAuthorizedRequest, IsAuthorizedResponse, IsJwtApiTokenValidRequest,
};
use mongodb::Database;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::State;

use crate::authorization::create;
use crate::request_guards::{AuthenticatedUser, OtpValidatedJwtToken};
use crate::Config;

#[post("/authorization", data = "<add_authorization_request>")]
pub async fn add_authorization(
    add_authorization_request: Json<AddAuthorizationRequest>,
    db: &State<Database>,
    authenticated_user: AuthenticatedUser,
) -> Result<Json<Authorization>, Status> {
    trace!("add_authorization(_, _, {})", authenticated_user);
    is_user_authorized_for(
        &authenticated_user.user,
        "bridgekeeper",
        "POST",
        "/user/authorization",
        db,
    )
    .await?;
    let authorization = create(&add_authorization_request, db).await?;
    Ok(Json(authorization))
}

#[post("/authorization/user", data = "<is_authorized_request>")]
pub async fn is_authorized(
    is_authorized_request: Json<IsAuthorizedRequest>,
    db: &State<Database>,
    valid_jwt_token: OtpValidatedJwtToken,
) -> Result<Json<IsAuthorizedResponse>, Status> {
    trace!(
        "is_authorized({:?}, _, {})",
        is_authorized_request,
        valid_jwt_token
    );
    is_user_authorized_for(
        &valid_jwt_token.user,
        &is_authorized_request.application,
        &is_authorized_request.method,
        &is_authorized_request.uri,
        db,
    )
    .await?;

    Ok(Json(IsAuthorizedResponse {
        is_authorized: true,
    }))
}

#[post(
    "/authorization/jwt-api-token",
    data = "<is_jwt_api_token_valid_request>"
)]
pub async fn is_jwt_api_valid(
    is_jwt_api_token_valid_request: Json<IsJwtApiTokenValidRequest>,
    db: &State<Database>,
    config: &State<Config<'_>>,
) -> Result<Json<IsAuthorizedResponse>, Status> {
    trace!("is_jwt_api_valid()");
    is_jwt_api_token_valid(&is_jwt_api_token_valid_request.token, config, db).await?;

    Ok(Json(IsAuthorizedResponse {
        is_authorized: true,
    }))
}
