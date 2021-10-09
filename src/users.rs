use crate::errors::ErrorKind;
use mongodb::bson::doc;
use mongodb::bson::Bson;
use mongodb::{Database, Collection};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct User {
    #[serde(skip_serializing)]
    pub _id: Option<Bson>,
    pub user_id: Option<String>,
    pub email_address: String,
    pub first_name: String,
    pub last_name: String,

    pub display_name: Option<String>,
    pub password_hash: String,
    pub password_salt: String,
    pub otp_hash: Option<String>,
    pub otp_backup_codes: Vec<String>,
    pub pending_otp_hash: Option<String>,
    pub pending_backup_codes: Vec<String>,
    pub is_approved: bool,
}

impl Display for User {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("_id", &self._id)
            .field("user_id", &self.user_id)
            .field("email_address", &self.email_address)
            .field("first_name", &self.first_name)
            .field("last_name", &self.last_name)
            .finish()
    }
}

/// Creates the user collection for the database.
fn user_collection(db: &Database) -> Collection<User> {
    db.collection::<User>("users")
}

/// Creates a new abstract id for entities.
fn create_id() -> Option<String> {
    Some(Uuid::new_v4().to_hyphenated().to_string())
}

/// Create a new user.
///
/// ## Args:
/// - user: The user to create
/// - db: The mongo database instance.
///
/// ## Returns:
/// The created user or an error:
/// - MongoDbError - Something is off with mongo.
pub async fn create(user: &User, db: &Database) -> Result<User, ErrorKind> {
    trace!("create({}, ...)", user);
    let mut new_user = user.clone();
    new_user.user_id = create_id();

    let collection = user_collection(db);
    let insert_result = collection.insert_one(&new_user, None).await?;

    trace!(
        "New user inserted with mongo id {}",
        insert_result.inserted_id
    );
    new_user._id = Some(insert_result.inserted_id);
    Ok(new_user)
}

/// Finds the user for the given id.
///
/// ## Args:
/// - id: The user_id.
/// - db: The mongo database instance.
///
/// ## Returns:
/// User with the given email address or an Error.
/// - EntityNotFound - No user exists for the email address.
/// - MongoDbError - Something is off with mongo.
pub async fn get(id: &String, db: &Database) -> Result<User, ErrorKind> {
    trace!("get({}, ...)", id);
    let collection = user_collection(db);
    let find_filter = doc! { "user_id": &id };
    let optional_user = collection.find_one(find_filter, None).await?;

    match optional_user {
        Some(user) => {
            trace!("get found user {}", user);
            Ok(user)
        }
        None => Err(ErrorKind::EntityNotFound {
            message: format!("User with user_id {} not found", id),
        }),
    }
}

/// Updates the user with the data in user.
///
/// ## Args:
/// - user: The new data for the user object.
/// - db: The mongo database instance.
///
/// ## Returns:
/// User with the updated fields or an Error:
/// - IllegalRequest - the field user_id is None.
/// - EntityNotFound - the user with user_id is not present in the database.
pub async fn update(user: &User, db: &Database) -> Result<User, ErrorKind> {
    trace!("update({}, ...)", user);
    match &user.user_id {
        Some(user_id) => {
            let collection = user_collection(db);
            let update_result = collection
                .replace_one(doc! {"user_id": &user.user_id}, user, None)
                .await?;
            if update_result.matched_count == 0 {
                return Err(ErrorKind::EntityNotFound {
                    message: format!("User with id {} not found", user_id),
                });
            }
            get(user_id, &db).await
        }
        None => Err(ErrorKind::IllegalRequest {
            message: format!("User has no id"),
        }),
    }
}
