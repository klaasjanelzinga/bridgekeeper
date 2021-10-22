use crate::errors::ErrorKind;
use crate::errors::ErrorKind::EntityNotFound;
use argon2::Config;
use mongodb::bson::doc;
use mongodb::bson::Bson;
use mongodb::{Collection, Database};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use rocket::serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct User {
    #[serde(skip_serializing)]
    pub _id: Option<Bson>,

    pub user_id: Option<String>,
    pub email_address: String,
    pub first_name: String,
    pub last_name: String,

    pub display_name: Option<String>,
    pub password_hash: String,
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

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct GetUserResponse {
    pub user_id: String,
    pub email_address: String,
    pub first_name: String,
    pub last_name: String,
    pub display_name: Option<String>,
}

impl Display for GetUserResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetUserResponse")
            .field("user_id", &self.user_id)
            .field("email_address", &self.email_address)
            .field("first_name", &self.first_name)
            .field("last_name", &self.last_name)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct UpdateUserRequest {
    pub user_id: String,
    pub email_address: String,
    pub first_name: String,
    pub last_name: String,
    pub display_name: Option<String>,
}

impl Display for UpdateUserRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateUserRequest")
            .field("user_id", &self.user_id)
            .field("email_address", &self.email_address)
            .field("first_name", &self.first_name)
            .field("last_name", &self.last_name)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct CreateUserRequest {
    pub email_address: String,
    pub first_name: String,
    pub last_name: String,
    pub display_name: Option<String>,
    pub new_password: String,
}

impl Display for CreateUserRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateUserRequest")
            .field("email_address", &self.email_address)
            .field("first_name", &self.first_name)
            .field("last_name", &self.last_name)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct LoginRequest {
    pub email_address: String,
    pub password: String,
}

impl Display for LoginRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginRequest")
            .field("email_address", &self.email_address)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct LoginResponse {
    pub token: String,
}

impl Display for LoginResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginResponse").finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct ChangePasswordRequest {
    pub email_address: String,
    pub old_password: String,
    pub new_password: String,
}

impl Display for ChangePasswordRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChangePasswordRequest")
            .field("email_address", &self.email_address)
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

/// Hash data with a random salt.
///
/// ## Args:
/// - data: The string value to hash.
///
/// ## Returns:
/// The hashed value.
fn hash_data(data: &str) -> Result<String, ErrorKind> {
    let rng = thread_rng();
    let random_salt = rng
        .sample_iter(Alphanumeric)
        .take(32)
        .map(char::from)
        .collect::<String>();
    let config = Config::default();

    argon2::hash_encoded(data.as_bytes(), random_salt.as_bytes(), &config)
        .or(Err(ErrorKind::CannotEncodePassword))
}

/// Verify the input data with a hashed result.
fn verify_input(data: &str, hash: &str) -> Result<bool, ErrorKind> {
    argon2::verify_encoded(hash, data.as_bytes()).or(Err(ErrorKind::CannotVerifyPassword))
}

/// Fetches the user entity by user_id. Returns EntityNotFound if not found.
async fn get_by_id(user_id: &str, db: &Database) -> Result<User, ErrorKind> {
    let collection = user_collection(db);
    let optional_user = collection
        .find_one(doc! {"user_id": &user_id}, None)
        .await?;
    match optional_user {
        Some(user) => Ok(user),
        None => Err(EntityNotFound {
            message: format!("User with id {} not found", user_id),
        }),
    }
}

/// Fetches the user entity by email_address. Returns EntityNotFound if not found.
async fn get_by_email(email_address: &str, db: &Database) -> Result<User, ErrorKind> {
    let collection = user_collection(db);
    let optional_user = collection
        .find_one(doc! {"email_address": &email_address}, None)
        .await?;
    match optional_user {
        Some(user) => Ok(user),
        None => Err(EntityNotFound {
            message: format!("User with email_address {} not found", email_address),
        }),
    }
}

pub async fn login(login_request: &LoginRequest, db: &Database) -> Result<bool, ErrorKind> {
    trace!("login({}, _)", login_request);
    let user = get_by_email(&login_request.email_address, db).await?;
    trace!("Validating password of user {}", user.email_address);
    let valid_password = verify_input(&login_request.password, &user.password_hash)?;
    Ok(valid_password)
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
pub async fn create(user: &CreateUserRequest, db: &Database) -> Result<GetUserResponse, ErrorKind> {
    trace!("create({}, ...)", user);
    let password_hash_and_salt = hash_data(&user.new_password)?;
    let new_user = User {
        _id: None,
        user_id: create_id(),
        email_address: user.email_address.clone(),
        first_name: user.first_name.clone(),
        last_name: user.last_name.clone(),
        display_name: user.display_name.clone(),
        password_hash: password_hash_and_salt,
        otp_hash: None,
        otp_backup_codes: vec![],
        pending_otp_hash: None,
        pending_backup_codes: vec![],
        is_approved: false,
    };

    let collection = user_collection(db);
    let insert_result = collection.insert_one(&new_user, None).await?;

    trace!(
        "New user inserted with mongo id {}",
        insert_result.inserted_id
    );
    Ok(GetUserResponse {
        user_id: new_user.user_id.unwrap(),
        email_address: new_user.email_address,
        first_name: new_user.first_name,
        last_name: new_user.last_name,
        display_name: new_user.display_name,
    })
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
pub async fn get(id: &str, db: &Database) -> Result<GetUserResponse, ErrorKind> {
    trace!("get({}, ...)", id);
    let user = get_by_id(id, db).await?;
    Ok(GetUserResponse {
        user_id: user.user_id.unwrap(),
        email_address: user.email_address,
        first_name: user.first_name,
        last_name: user.last_name,
        display_name: user.display_name,
    })
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
pub async fn update(user: &UpdateUserRequest, db: &Database) -> Result<GetUserResponse, ErrorKind> {
    trace!("update({}, ...)", user);
    let user_id = user.user_id.clone();
    let mut db_user = get_by_id(&user_id, db).await?;

    db_user.email_address = user.email_address.clone();
    db_user.first_name = user.first_name.clone();
    db_user.last_name = user.last_name.clone();
    db_user.display_name = user.display_name.clone();

    let collection = user_collection(db);
    let update_result = collection
        .replace_one(doc! {"user_id": &user_id}, &db_user, None)
        .await?;
    if update_result.matched_count == 0 {
        return Err(ErrorKind::EntityNotFound {
            message: format!("User with id {} not found", user_id),
        });
    }
    Ok(get(&user_id, db).await?)
}
