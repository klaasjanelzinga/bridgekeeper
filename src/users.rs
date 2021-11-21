use std::fmt::{Display, Formatter};
use std::time::{SystemTime, UNIX_EPOCH};

use mongodb::bson::doc;
use mongodb::bson::Bson;
use mongodb::{Collection, Database};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use rocket::serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::Config;
use crate::errors::ErrorKind;
use crate::errors::ErrorKind::EntityNotFound;
use crate::jwt;
use crate::jwt::ValidJwtToken;
use totp_lite::{totp, Sha512};

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct User {
    #[serde(skip_serializing)]
    pub _id: Option<Bson>,

    pub user_id: String,
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

fn random_string(number_of_chars: usize) -> String {
    let rng = thread_rng();
    rng.sample_iter(Alphanumeric)
        .take(number_of_chars)
        .map(char::from)
        .collect::<String>()
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

impl From<&User> for GetUserResponse {
    fn from(user: &User) -> Self {
        GetUserResponse {
            user_id: user.user_id.clone(),
            email_address: user.email_address.clone(),
            first_name: user.first_name.clone(),
            last_name: user.last_name.clone(),
            display_name: user.display_name.clone(),
        }
    }
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
    pub current_password: String,
    pub new_password: String,
}

impl Display for ChangePasswordRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChangePasswordRequest").finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct ChangePasswordResponse {
    pub success: bool,
    pub error_message: Option<String>,
}

impl Display for ChangePasswordResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChangePasswordResponse")
            .field("success", &self.success)
            .field("error_message", &self.error_message)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct StartTotpRegistrationResult {
    pub secret: String,
    pub uri: String,
    pub backup_codes: Vec<String>,
}

impl Display for StartTotpRegistrationResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartTotpRegistrationResult").finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct ConfirmTotpResponse {
    pub success: bool,
}

impl Display for ConfirmTotpResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfirmTotpResponse")
            .field("success", &self.success)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct ValidateTotpRequest {
    pub totp_challenge: String,
}

impl Display for ValidateTotpRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidateTotpRequest")
            .field("totp_challenge", &self.totp_challenge)
            .finish()
    }
}

/// Creates the user collection for the database.
fn user_collection(db: &Database) -> Collection<User> {
    db.collection::<User>("users")
}

/// Creates a new abstract id for entities.
fn create_id() -> String {
    Uuid::new_v4().to_hyphenated().to_string()
}

/// Hash data with a random salt.
///
/// ## Args:
/// - data: The string value to hash.
///
/// ## Returns:
/// The hashed value.
fn hash_data(data: &str) -> Result<String, ErrorKind> {
    let random_salt = random_string(32);
    let config = argon2::Config::default();

    argon2::hash_encoded(data.as_bytes(), random_salt.as_bytes(), &config)
        .or(Err(ErrorKind::CannotEncodePassword))
}

/// Verify the input data with a hashed result.
fn verify_input(data: &str, hash: &str) -> Result<bool, ErrorKind> {
    argon2::verify_encoded(hash, data.as_bytes()).or(Err(ErrorKind::CannotVerifyPassword))
}

/// Verify a password if it confirms to some minimum requirement.
fn verify_password(password: &str) -> Result<(), ErrorKind> {
    if password.len() < 8 {
        return Err(ErrorKind::PasswordInvalid {
            message: String::from("New password not long enough"),
        });
    }

    if !password.chars().any(char::is_numeric) {
        return Err(ErrorKind::PasswordInvalid {
            message: String::from("New password does not contain any digits"),
        });
    }

    if !password.chars().any(char::is_uppercase) {
        return Err(ErrorKind::PasswordInvalid {
            message: String::from("New password does not contain any capitals"),
        });
    }
    if !password.chars().any(char::is_lowercase) {
        return Err(ErrorKind::PasswordInvalid {
            message: String::from("New password does not contain any lower case letters"),
        });
    }
    if !password.chars().any(|c| char::is_ascii_punctuation(&c)) {
        return Err(ErrorKind::PasswordInvalid {
            message: String::from("New password does not contain any special characters"),
        });
    }

    Ok(())
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

/// Update the user.
async fn update_user(db_user: &User, db: &Database) -> Result<bool, ErrorKind> {
    let collection = user_collection(db);
    let update_result = collection
        .replace_one(doc! {"user_id": &db_user.user_id}, db_user, None)
        .await?;
    if update_result.matched_count == 0 {
        return Err(ErrorKind::EntityNotFound {
            message: format!("User with id {} not found", db_user.user_id),
        });
    }
    Ok(true)
}

/// Finds the user for the given id.
///
/// ## Args:
/// - valid_jwt_token: A valid jwt token. The user id will be validated from the token to the second arg.
/// - id: The user_id, must match token value..
/// - db: The mongo database instance.
///
/// ## Returns:
/// User with the given email address or an Error.
/// - EntityNotFound - No user exists for the email address.
/// - IllegalDataAccess - The user_id in the token does not match the second argument.
/// - MongoDbError - Something is off with mongo.
pub async fn get_with_user_id(
    valid_jwt_token: &ValidJwtToken,
    user_id: &str,
    db: &Database,
) -> Result<User, ErrorKind> {
    trace!("get_with_user_id(({}, {}, _)", valid_jwt_token, user_id);
    if valid_jwt_token.jwt_claims.user_id != user_id {
        return Err(ErrorKind::IllegalDataAccess {
            message: format!(
                "User with id {} made a request for user {}",
                valid_jwt_token.jwt_claims.user_id, user_id
            ),
        });
    }

    get_by_id(user_id, db).await
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

/// Log the user in and create a jwt for the session.
///
/// ## Args:
/// - login_request: The login request containing the email address and the password.
/// - db: The mongo db.
///
/// ## Returns:
/// The jwt token if succeeded or:
/// - PasswordIncorrect - if the password is incorrect.
/// - EntityNotFound - if the email address is not known.
pub async fn login(
    login_request: &LoginRequest,
    config: &Config<'_>,
    db: &Database,
) -> Result<String, ErrorKind> {
    trace!("login({}, _)", login_request);
    let user = get_by_email(&login_request.email_address, db).await?;
    trace!("Validating password of user {}", user.email_address);
    let valid_password = verify_input(&login_request.password, &user.password_hash)?;
    if !valid_password {
        return Err(ErrorKind::PasswordIncorrect);
    }
    let token = jwt::create_jwt_token(&user, &config.encoding_key)?;
    debug!("Successfully logged in user {}", user);
    Ok(token)
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
pub async fn create(
    create_user_request: &CreateUserRequest,
    db: &Database,
) -> Result<GetUserResponse, ErrorKind> {
    trace!("create({}, ...)", create_user_request);
    let password_hash_and_salt = hash_data(&create_user_request.new_password)?;
    let new_user = User {
        _id: None,
        user_id: create_id(),
        email_address: create_user_request.email_address.clone(),
        first_name: create_user_request.first_name.clone(),
        last_name: create_user_request.last_name.clone(),
        display_name: create_user_request.display_name.clone(),
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
    Ok(GetUserResponse::from(&new_user))
}

/// Updates the user with the data in user.
///
/// ## Args:
/// - user: The user to update.
/// - update_user_request: The new data for the user object.
/// - db: The mongo database instance.
///
/// ## Returns:
/// User with the updated fields or an Error:
/// - IllegalRequest - the field user_id is None.
/// - EntityNotFound - the user with user_id is not present in the database.
pub async fn update(
    user: &User,
    update_user_request: &UpdateUserRequest,
    db: &Database,
) -> Result<GetUserResponse, ErrorKind> {
    trace!("update({}, {}, ...)", user, update_user_request);

    let mut db_user = get_by_id(&user.user_id, db).await?;

    db_user.email_address = update_user_request.email_address.clone();
    db_user.first_name = update_user_request.first_name.clone();
    db_user.last_name = update_user_request.last_name.clone();
    db_user.display_name = update_user_request.display_name.clone();

    update_user(&db_user, db).await?;

    Ok(GetUserResponse::from(&db_user))
}

/// Change the password for the user. The user should provide a valid new password and the correct
/// current password.
///
/// ## Args:
/// - user: The user to change the password for.
/// - change_password_request - The new data.
/// - db - The mongo db instance.
///
/// ## Returns:
/// The ChangePasswordResponse or an error:
/// - PasswordIncorrect - if the current_password is not correct.
///
pub async fn change_password_for_user(
    user: &User,
    change_password_request: &ChangePasswordRequest,
    db: &Database,
) -> Result<ChangePasswordResponse, ErrorKind> {
    trace!(
        "change_password_for_user({}, {}, _",
        user,
        change_password_request
    );
    trace!("Validating the password for the user");
    let valid_password = verify_input(
        &change_password_request.current_password,
        &user.password_hash,
    )?;
    if !valid_password {
        return Err(ErrorKind::PasswordIncorrect);
    }
    // validate change_password_request.new_password contains digits etc.
    verify_password(&change_password_request.new_password)?;

    let password_hash_and_salt = hash_data(&change_password_request.new_password)?;
    let mut db_user = get_by_id(&user.user_id, db).await?;

    db_user.password_hash = password_hash_and_salt;

    update_user(&db_user, db).await?;

    Ok(ChangePasswordResponse {
        success: true,
        error_message: None,
    })
}

/// Start the registration process for a TOTP token. The following items will be created:
/// - an uri: For creating a QR code on the client side.
/// - backup_codes: Backup codes that can be used instead of the totp.
/// - secret: The shared secret.
///
/// ## Args:
/// - user: The user to start the totp registration for.
/// - db - The mongo db instance.
///
/// ## Returns:
/// The StartTotpRegistrationResponse or an error.
///
pub async fn start_totp_registration_for_user(
    user: &User,
    db: &Database,
) -> Result<StartTotpRegistrationResult, ErrorKind> {
    trace!("start_totp_registration({})", user);
    let secret = random_string(32);
    let backup_codes = [
        random_string(8),
        random_string(8),
        random_string(8),
        random_string(8),
        random_string(8),
        random_string(8),
    ]
    .to_vec();
    let label = format!("Linkje:{}", user.email_address);
    let uri = format!("otpauth://totp/{}?secret={}&issuer=Linkje", label, secret);

    // store the pending otp codes with the user.
    let mut db_user = get_by_id(&user.user_id, db).await?;
    db_user.pending_backup_codes = backup_codes.clone();
    db_user.pending_otp_hash = Some(secret.clone());

    update_user(&db_user, db).await?;

    Ok(StartTotpRegistrationResult {
        backup_codes,
        uri,
        secret,
    })
}

pub async fn confirm_totp_code_for_user(
    user: &User,
    request: &ValidateTotpRequest,
    db: &Database,
) -> Result<ConfirmTotpResponse, ErrorKind> {
    trace!("confirm_totp_code_for_user({}, _)", user);
    if user.pending_otp_hash.is_none() || user.pending_backup_codes.len() == 0 {
        return Err(ErrorKind::IllegalRequest {
            message: String::from("No pending otp codes found"),
        });
    }

    // Calculate a TOTP for the pending secret.
    let seconds: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let totp_value = totp::<Sha512>(user.pending_otp_hash.as_ref().unwrap().as_bytes(), seconds);
    if totp_value != request.totp_challenge {
        return Err(ErrorKind::TotpChallengeInvalid);
    }

    let mut db_user = get_by_id(&user.user_id, db).await?;
    db_user.otp_hash = db_user.pending_otp_hash.clone();
    db_user.otp_backup_codes = db_user.pending_backup_codes.clone();
    db_user.pending_otp_hash = None;
    db_user.pending_backup_codes = Vec::new();

    update_user(&db_user, db).await?;

    Ok(ConfirmTotpResponse { success: true })
}
