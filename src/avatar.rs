use std::fmt::{Display, Formatter};

use mongodb::bson::doc;
use mongodb::bson::Bson;
use mongodb::{Collection, Database};
use rocket::serde::{Deserialize, Serialize};

use crate::errors::ErrorKind;
use crate::user::User;

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct GetAvatarResponse {
    pub user_id: String,
    pub avatar_base64: String,
}

impl Display for GetAvatarResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetAvatarResponse")
            .field("user_id", &self.user_id)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct UpdateAvatarRequest {
    pub image_base64: String,
}

impl Display for UpdateAvatarRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateAvatarRequest").finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct UpdateAvatarResponse {
    pub result: bool,
}

impl Display for UpdateAvatarResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateAvatarResponse").finish()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct Avatar {
    #[serde(skip_serializing)]
    pub _id: Option<Bson>,

    pub user_id: String,
    pub image_base64_blob: String,
}

/// Creates or gets the avatar collection for the database.
fn avatar_collection(db: &Database) -> Collection<Avatar> {
    db.collection::<Avatar>("avatar")
}

async fn get_avatar(
    avatar_collection: &Collection<Avatar>,
    user_id: &str,
) -> Result<Avatar, ErrorKind> {
    let optional_avatar = avatar_collection
        .find_one(doc! {"user_id": user_id}, None)
        .await?;
    match optional_avatar {
        Some(avatar) => Ok(avatar),
        None => Err(ErrorKind::EntityNotFound {
            message: format!("Avatar not found for user {}", user_id),
        }),
    }
}

/// Retrieve the avatar for the user.
///
/// ## Args:
/// - user: The user to retrieve the avatar for.
/// - db: Valid mongo db.
///
/// ## Returns:
/// If user exists a avatar response or else EntityNotFound.
pub async fn get_avatar_for_user(
    user: &User,
    db: &Database,
) -> Result<GetAvatarResponse, ErrorKind> {
    let avatar_collection = avatar_collection(db);
    let avatar = get_avatar(&avatar_collection, &user.user_id).await?;
    Ok(GetAvatarResponse {
        avatar_base64: avatar.image_base64_blob.clone(),
        user_id: avatar.user_id.clone(),
    })
}

/// Insert an avatar if none present or update the avatar.
///
/// ## Args:
/// - user: The user to upsert the avatar for.
/// - image_base64_blob: The new avatar image in base64 encoding.
/// - db: Valid mongo db instance.
///
/// ## Returns:
/// A Avatar response if everything worked, an ErrorKind otherwise.
pub async fn upsert_avatar_for_user(
    user: &User,
    image_base64_blob: &str,
    db: &Database,
) -> Result<bool, ErrorKind> {
    let avatar_collection = avatar_collection(db);
    let avatar = get_avatar(&avatar_collection, &user.user_id).await;
    match avatar {
        Ok(mut avatar) => {
            avatar.image_base64_blob = String::from(image_base64_blob);
            avatar_collection
                .replace_one(doc! {"user_id": &user.user_id}, &avatar, None)
                .await?;
            Ok(true)
        }
        Err(ErrorKind::EntityNotFound { message: _ }) => {
            let new_avatar = Avatar {
                _id: None,
                user_id: user.user_id.clone(),
                image_base64_blob: String::from(image_base64_blob),
            };
            avatar_collection.insert_one(&new_avatar, None).await?;
            Ok(true)
        }
        Err(other_err) => Err(other_err),
    }
}

/// Delete an avatar for the user.
///
/// ##Args:
/// - user: The user to delete the avatar for.
/// - db: Valid mondog db instance.
///
/// ## Returns:
/// True if all well or EntityNotFound if no avatar found for the user.
pub async fn delete_avatar_for_user(user: &User, db: &Database) -> Result<bool, ErrorKind> {
    let delete_result = avatar_collection(db)
        .delete_one(doc! {"user_id": &user.user_id}, None)
        .await?;
    if delete_result.deleted_count == 0 {
        return Err(ErrorKind::EntityNotFound {
            message: format!("Avatar for user {} not found", user.user_id),
        });
    }
    Ok(true)
}
