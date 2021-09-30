use crate::errors::ErrorKind;
use mongodb::bson::doc;
use mongodb::Database;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct User {
    pub user_id: Option<String>,
    pub email_address: String,
    pub first_name: String,
    pub last_name: String,
}

impl Display for User {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("user_id", &self.user_id)
            .field("email_address", &self.email_address)
            .field("first_name", &self.first_name)
            .field("last_name", &self.last_name)
            .field("user_id", &self.user_id)
            .finish()
    }
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
pub async fn create(user: &User, db: Database) -> Result<User, ErrorKind> {
    trace!("Creating user, {}", user);
    let mut new_user = user.clone();
    new_user.user_id = Some(Uuid::new_v4().to_hyphenated().to_string());

    let collection = db.collection::<User>("users");
    let insert_result = collection.insert_one(&new_user, None).await?;

    trace!(
        "New user inserted with mongo id {}",
        insert_result.inserted_id
    );
    Ok(new_user)
}

/// Finds the user for the given email address.
///
/// ## Args:
/// - email_address: The email address of the user.
/// - db: The mongo database instance.
///
/// ## Returns:
/// Optional user with the given email address or an Error.
/// - EntityNotFound - No user exists for the email address.
/// - MongoDbError - Something is off with mongo.
pub async fn get_by_email_address(email_address: &String, db: Database) -> Result<User, ErrorKind> {
    trace!("Get a user with email_address {}", email_address);
    let collection = db.collection::<User>("users");
    let find_filter = doc! { "email_address": &email_address };
    let optional_user = collection.find_one(find_filter, None).await?;

    match optional_user {
        Some(user) => return Ok(user),
        None => Err(ErrorKind::EntityNotFound {
            message: format!("User with email address {} not found", email_address),
        }),
    }
}
