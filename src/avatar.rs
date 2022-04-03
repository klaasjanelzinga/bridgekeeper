use mongodb::bson::doc;
use mongodb::{Collection, Database};

use crate::avatar_models::{Avatar, GetAvatarResponse};
use crate::errors::ErrorKind;
use crate::user_models::User;

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
        user_id: avatar.user_id,
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
