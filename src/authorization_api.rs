use crate::authorization::{
    is_user_authorized_for, AddAuthorizationRequest, Authorization, IsAuthorizedRequest,
    IsAuthorizedResponse,
};
use mongodb::Database;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::State;

use crate::authorization::create;
use crate::errors::ErrorKind;
use crate::jwt::ValidJwtToken;
use crate::user::get_with_user_id;

#[post("/user/authorization", data = "<add_authorization_request>")]
pub async fn add_authorization(
    add_authorization_request: Json<AddAuthorizationRequest>,
    db: &State<Database>,
    valid_jwt_token: ValidJwtToken,
) -> Result<Json<Authorization>, Status> {
    trace!("add_authorization(_, _, {})", valid_jwt_token);
    // needs authorization to execute POST /user/authorize
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
    let user = get_with_user_id(&valid_jwt_token, db).await?;
    let is_authorized = is_user_authorized_for(&user, &is_authorized_request, db).await?;

    Ok(Json(IsAuthorizedResponse { is_authorized }))
}
