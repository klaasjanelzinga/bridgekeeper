use crate::avatar::{
    delete_avatar_for_user, get_avatar_for_user, upsert_avatar_for_user, GetAvatarResponse,
    UpdateAvatarRequest, UpdateAvatarResponse,
};
use crate::request_guards::OtpValidatedJwtToken;
use mongodb::Database;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::State;

#[get("/user/avatar")]
pub async fn get_avatar(
    db: &State<Database>,
    jwt_token: OtpValidatedJwtToken,
) -> Result<Json<GetAvatarResponse>, Status> {
    trace!("get_avatar(_, {})", jwt_token);
    let get_avatar = get_avatar_for_user(&jwt_token.user, db).await?;
    Ok(Json(get_avatar))
}

#[delete("/user/avatar")]
pub async fn delete_avatar(
    db: &State<Database>,
    jwt_token: OtpValidatedJwtToken,
) -> Result<Json<UpdateAvatarResponse>, Status> {
    trace!("delete_avatar(_, {})", jwt_token);
    delete_avatar_for_user(&jwt_token.user, db).await?;
    Ok(Json(UpdateAvatarResponse { result: true }))
}

#[post("/user/avatar", data = "<update_avatar_request>")]
pub async fn create_or_update_avatar(
    update_avatar_request: Json<UpdateAvatarRequest>,
    db: &State<Database>,
    jwt_token: OtpValidatedJwtToken,
) -> Result<Json<UpdateAvatarResponse>, Status> {
    trace!("create_or_update_avatar(_, {})", jwt_token);
    upsert_avatar_for_user(&jwt_token.user, &update_avatar_request.image_base64, db).await?;
    Ok(Json(UpdateAvatarResponse { result: true }))
}
