use crate::authorization::{
    is_token_authorized_for, AddAuthorizationRequest, Authorization, IsAuthorizedRequest,
    IsAuthorizedResponse,
};
use mongodb::Database;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::State;

use crate::authorization::create;
use crate::jwt::{AuthenticatedUser, ValidJwtToken};

#[post("/user/authorization", data = "<add_authorization_request>")]
pub async fn add_authorization(
    add_authorization_request: Json<AddAuthorizationRequest>,
    db: &State<Database>,
    authenticated_user: AuthenticatedUser,
) -> Result<Json<Authorization>, Status> {
    trace!("add_authorization(_, _, {})", authenticated_user);
    is_token_authorized_for(
        &authenticated_user.valid_jwt_token,
        "bridgekeeper",
        "POST",
        "/user/authorization",
        db,
    )
    .await?;
    let authorization = create(&add_authorization_request, db).await?;
    Ok(Json(authorization))
}

#[post("/user/is_authorized", data = "<is_authorized_request>")]
pub async fn is_authorized(
    is_authorized_request: Json<IsAuthorizedRequest>,
    db: &State<Database>,
    valid_jwt_token: ValidJwtToken,
) -> Result<Json<IsAuthorizedResponse>, Status> {
    trace!(
        "is_authorized({:?}, _, {})",
        is_authorized_request,
        valid_jwt_token
    );
    is_token_authorized_for(
        &valid_jwt_token,
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
