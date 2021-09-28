use mongodb::Database;
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};
use std::error::Error;
use uuid::Uuid;
use std::fmt::{Display, Formatter};
use crate::errors::ErrorKind;

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

pub async fn create(user: &User, db: Database) -> Result<User, Box<dyn Error>>{
    log::trace!("Creating user, {}", user);
    let mut new_user = user.clone();
    new_user.user_id = Some(Uuid::new_v4().to_hyphenated().to_string());

    let collection = db.collection::<User>("users");
    let insert_result = collection.insert_one(&new_user, None).await?;

    log::trace!("Inserted {}", insert_result.inserted_id);
    Ok(new_user)
}

pub async fn get_by_email_address(email_address: String, db: Database) -> Result<User, ErrorKind> {
    log::trace!("Get a user with email_address {}", email_address);
    let collection = db.collection::<User>("users");
    let find_filter = doc! { "email_address": &email_address };
    let find_result = collection.find_one(find_filter, None).await;
    match find_result {
        Err(error) => Err(ErrorKind::MongoDbError { mongodb_error: error }),
        Ok(optional_user) => match optional_user {
            Some(user) => return Ok(user),
            None => Err(ErrorKind::EntityNotFound { message: String::from("User with email address not found") })
        }
    }
}
