use crate::avatar::{
    delete_avatar_for_user, get_avatar_for_user, upsert_avatar_for_user, GetAvatarResponse,
    UpdateAvatarRequest, UpdateAvatarResponse,
};
use crate::jwt::ValidJwtToken;
use crate::user::get_with_user_id;
use mongodb::Database;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::State;

#[get("/user/avatar")]
pub async fn get_avatar(
    db: &State<Database>,
    valid_jwt_token: ValidJwtToken,
) -> Result<Json<GetAvatarResponse>, Status> {
    trace!("get_avatar(_, {})", valid_jwt_token);
    let user = get_with_user_id(&valid_jwt_token, db).await?;
    let get_avatar = get_avatar_for_user(&user, db).await?;
    Ok(Json(get_avatar))
}

#[delete("/user/avatar")]
pub async fn delete_avatar(
    db: &State<Database>,
    valid_jwt_token: ValidJwtToken,
) -> Result<Json<UpdateAvatarResponse>, Status> {
    trace!("delete_avatar(_, {})", valid_jwt_token);
    let user = get_with_user_id(&valid_jwt_token, db).await?;
    delete_avatar_for_user(&user, db).await?;
    Ok(Json(UpdateAvatarResponse { result: true }))
}

#[post("/user/avatar", data = "<update_avatar_request>")]
pub async fn create_or_update_avatar(
    update_avatar_request: Json<UpdateAvatarRequest>,
    db: &State<Database>,
    valid_jwt_token: ValidJwtToken,
) -> Result<Json<UpdateAvatarResponse>, Status> {
    trace!("create_or_update_avatar(_, {})", valid_jwt_token);
    let user = get_with_user_id(&valid_jwt_token, db).await?;
    upsert_avatar_for_user(&user, &update_avatar_request.image_base64, db).await?;
    Ok(Json(UpdateAvatarResponse { result: true }))
}
