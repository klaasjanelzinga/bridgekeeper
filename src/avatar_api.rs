use axum::extract::Extension;
use axum::Json;
use mongodb::Database;

use crate::avatar::{delete_avatar_for_user, get_avatar_for_user, upsert_avatar_for_user};
use crate::avatar_models::{GetAvatarResponse, UpdateAvatarRequest, UpdateAvatarResponse};
use crate::errors::ErrorKind;
use crate::request_guards::AccessToken;

pub async fn get_avatar(
    Extension(db): Extension<Database>,
    jwt_token: AccessToken,
) -> Result<Json<GetAvatarResponse>, ErrorKind> {
    trace!("get_avatar(_, {})", jwt_token);
    let get_avatar = get_avatar_for_user(&jwt_token.user, &db).await?;
    Ok(Json(get_avatar))
}

pub async fn delete_avatar(
    Extension(db): Extension<Database>,
    jwt_token: AccessToken,
) -> Result<Json<UpdateAvatarResponse>, ErrorKind> {
    trace!("delete_avatar(_, {})", jwt_token);
    delete_avatar_for_user(&jwt_token.user, &db).await?;
    Ok(Json(UpdateAvatarResponse { result: true }))
}

pub async fn create_or_update_avatar(
    Json(update_avatar_request): Json<UpdateAvatarRequest>,
    Extension(db): Extension<Database>,
    jwt_token: AccessToken,
) -> Result<Json<UpdateAvatarResponse>, ErrorKind> {
    trace!("create_or_update_avatar(_, {})", jwt_token);
    upsert_avatar_for_user(&jwt_token.user, &update_avatar_request.image_base64, &db).await?;
    Ok(Json(UpdateAvatarResponse { result: true }))
}
