use crate::authorization_models::AddAuthorizationRequest;
use crate::{authorization, Config};
use mongodb::bson::doc;
use mongodb::{Collection, Database};

use crate::errors::ErrorKind;
use crate::errors::ErrorKind::{EntityNotFound, TokenTypeInvalid};
use crate::jwt::{create_access_token, create_one_shot_token, create_refresh_token};
use crate::jwt_models::{JwtClaims, JwtType};
use crate::user_models::{
    ChangePasswordRequest, ChangePasswordResponse, CreateUserRequest, GetUserResponse,
    LoginRequest, LoginResponse, LoginWithOtpResponse, UpdateUserRequest, User,
};
use crate::util::{create_id, random_string};

/// Creates the user collection for the database.
fn user_collection(db: &Database) -> Collection<User> {
    db.collection::<User>("user")
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
            message: String::from("Password not long enough"),
        });
    }

    if !password.chars().any(char::is_numeric) {
        return Err(ErrorKind::PasswordInvalid {
            message: String::from("Password does not contain any digits"),
        });
    }

    if !password.chars().any(char::is_uppercase) {
        return Err(ErrorKind::PasswordInvalid {
            message: String::from("Password does not contain any capitals"),
        });
    }
    if !password.chars().any(char::is_lowercase) {
        return Err(ErrorKind::PasswordInvalid {
            message: String::from("Password does not contain any lower case letters"),
        });
    }
    if !password.chars().any(|c| char::is_ascii_punctuation(&c)) {
        return Err(ErrorKind::PasswordInvalid {
            message: String::from("Password does not contain any special characters"),
        });
    }

    Ok(())
}

/// Fetches the user entity by user_id. Returns EntityNotFound if not found.
pub async fn get_by_id(user_id: &str, db: &Database) -> Result<User, ErrorKind> {
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
pub async fn update_user(db_user: &User, db: &Database) -> Result<bool, ErrorKind> {
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

/// Fetches the user entity by email_address. Returns EntityNotFound if not found.
async fn get_by_email_and_application(
    email_address: &str,
    for_application: &str,
    db: &Database,
) -> Result<User, ErrorKind> {
    let collection = user_collection(db);
    let optional_user = collection
        .find_one(
            doc! {
                "email_address": &email_address,
                "for_application": &for_application,
            },
            None,
        )
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
/// - config: Application configuration.
///
/// ## Returns:
/// If the username password combination is correct,
///     and there is no otp configured -> An access token is returned.
///     and there is an otp configured -> An one-shot token is returned.
///
/// Errors:
/// - PasswordIncorrect - if the password is incorrect.
/// - EntityNotFound - if the email address is not known.
pub async fn login(
    login_request: &LoginRequest,
    config: &Config,
    db: &Database,
) -> Result<LoginResponse, ErrorKind> {
    trace!("login({}, _)", login_request);
    match get_by_email_and_application(
        &login_request.email_address,
        &login_request.for_application,
        db,
    )
    .await
    {
        Err(_) => Err(ErrorKind::LoginUserNotFound),
        Ok(user) => {
            if !user.is_approved {
                return Err(ErrorKind::UserNotApproved);
            }
            let valid_password = verify_input(&login_request.password, &user.password_hash)?;
            if !valid_password {
                return Err(ErrorKind::PasswordIncorrect);
            }
            let otp_is_configured = user.otp_hash.is_some();

            let token = if otp_is_configured {
                create_one_shot_token(&user, &config.encoding_key)
            } else {
                create_access_token(&user, &config.encoding_key)
            }?;

            if otp_is_configured {
                let mut db_user = get_by_id(&user.user_id, db).await?;
                db_user.issued_token_ids.push(token.token_id);
                update_user(&db_user, db).await?;
            }

            Ok(LoginResponse {
                needs_otp: otp_is_configured,
                token: token.token,

                user_id: user.user_id,
                for_application: user.for_application,
                email_address: user.email_address,
                first_name: user.first_name,
                last_name: user.last_name,
                display_name: user.display_name,
            })
        }
    }
}

/// Validates the claims in the jwt for an access token.
///
/// - The user in the token must exist.
/// - The token must be of the type JwtType::AccessToken
/// - The id of the token must match the current user.access_token_id.
pub async fn validate_jwt_claim_for_access_token(
    jwt_claims: &JwtClaims,
    db: &Database,
) -> Result<User, ErrorKind> {
    let user = get_by_id(&jwt_claims.user_id, db).await?;
    match jwt_claims.token_type {
        JwtType::AccessToken => Ok(user),
        _ => {
            clear_session_for_user(&user, db).await?;
            Err(TokenTypeInvalid)
        }
    }
}

/// Validates the claims in the jwt for an one shot token.
///
/// - The user in the token must exist.
/// - The token must be of the type JwtType::OneShotToken
/// - The id of the token must match the current user.access_token_id.
pub async fn validate_jwt_claim_for_one_shot_token(
    jwt_claims: &JwtClaims,
    db: &Database,
) -> Result<User, ErrorKind> {
    let user = get_by_id(&jwt_claims.user_id, db).await?;

    match jwt_claims.token_type {
        JwtType::OneShotToken => {
            check_user_token_id(&user, jwt_claims, db).await?;
            let mut db_user = user.clone();
            let index = user
                .issued_token_ids
                .iter()
                .position(|x| *x == jwt_claims.token_id);
            if index.is_some() {
                db_user.issued_token_ids.swap_remove(index.unwrap());
            }
            update_user(&db_user, db).await?;
            Ok(user)
        }
        _ => {
            clear_session_for_user(&user, db).await?;
            Err(TokenTypeInvalid)
        }
    }
}

/// Validates the claims in the jwt for a refresh token.
///
/// - The user in the token must exist.
/// - The token type must be a JwtType::RefreshToken.
/// - The id of the token must match the current user.refresh_token_id.
pub async fn validate_jwt_claim_for_refresh_token(
    jwt_claims: &JwtClaims,
    db: &Database,
) -> Result<User, ErrorKind> {
    let user = get_by_id(&jwt_claims.user_id, db).await?;
    match jwt_claims.token_type {
        JwtType::RefreshToken => {
            check_user_token_id(&user, jwt_claims, db).await?;
            Ok(user)
        }
        _ => {
            clear_session_for_user(&user, db).await?;
            Err(TokenTypeInvalid)
        }
    }
}

/// Check if the user_token_id is present and matches the token_id in the jwt_claims. If
/// they do not match, the session of the user is cleared and an ErrorKind is returned.
async fn check_user_token_id(
    user: &User,
    jwt_claims: &JwtClaims,
    db: &Database,
) -> Result<bool, ErrorKind> {
    if !user.is_approved {
        return Err(ErrorKind::UserNotApproved);
    }
    if user.issued_token_ids.contains(&jwt_claims.token_id) {
        Ok(true)
    } else {
        clear_session_for_user(user, db).await?;
        Err(ErrorKind::TokenUsedInReplay)
    }
}

/// Clears the registered tokens for the user.
async fn clear_session_for_user(user: &User, db: &Database) -> Result<bool, ErrorKind> {
    let mut db_user = user.clone();
    db_user.issued_token_ids = vec![];
    update_user(&db_user, db).await?;
    Ok(true)
}

/// Registers a new refresh token for the user. The id of the refresh token is saved with the user.
///
/// ## Args:
/// - user: The user to create a refresh jwt token for.
/// - config: The configuration of the application.
/// - db: The mongo db instance.
pub async fn refresh_token_for_user(
    old_token_id: &str,
    user: &User,
    config: &Config,
    db: &Database,
) -> Result<LoginWithOtpResponse, ErrorKind> {
    let refresh_token = create_refresh_token(user, &config.encoding_key)?;
    let access_token = create_access_token(user, &config.encoding_key)?;

    let mut db_user = user.clone();

    let index = user
        .issued_token_ids
        .iter()
        .position(|x| *x == old_token_id);
    if index.is_some() {
        db_user.issued_token_ids.swap_remove(index.unwrap());
    }

    db_user.issued_token_ids.push(refresh_token.token_id);
    update_user(&db_user, db).await?;
    Ok(LoginWithOtpResponse {
        access_token: access_token.token,
        refresh_token: refresh_token.token,
    })
}

/// Create a new user.
///
/// ## Args:
/// - user: The user to create
/// - for_application: The application to create the user for.
/// - db: The mongo database instance.
///
/// ## Returns:
/// The created user or an error:
/// - MongoDbError - Something is off with mongo.
pub async fn create(
    create_user_request: &CreateUserRequest,
    db: &Database,
) -> Result<User, ErrorKind> {
    trace!("create({}, ...)", create_user_request);
    let collection = user_collection(db);
    let optional_user = collection
        .find_one(
            doc! {
                "email_address": &create_user_request.email_address,
                "for_application": &create_user_request.for_application,
            },
            None,
        )
        .await?;
    if optional_user.is_some() {
        return Err(ErrorKind::EmailAddressAlreadyTaken {
            message: format!(
                "User name {} is already taken.",
                create_user_request.email_address
            ),
        });
    }

    verify_password(&create_user_request.new_password)?;

    let password_hash_and_salt = hash_data(&create_user_request.new_password)?;
    let new_user = User {
        _id: None,
        user_id: create_id(),
        email_address: create_user_request.email_address.clone(),
        for_application: create_user_request.for_application.clone(),
        first_name: create_user_request.first_name.clone(),
        last_name: create_user_request.last_name.clone(),
        display_name: create_user_request.display_name.clone(),
        password_hash: password_hash_and_salt,
        otp_hash: None,
        otp_backup_codes: vec![],
        pending_otp_hash: None,
        pending_backup_codes: vec![],
        issued_token_ids: vec![],
        is_approved: false,
        user_jwt_api_token: vec![],
    };

    let insert_result = collection.insert_one(&new_user, None).await?;
    trace!(
        "New user inserted with mongo id {}",
        insert_result.inserted_id
    );

    authorization::create(
        &AddAuthorizationRequest {
            application: create_user_request.for_application.clone(),
            method_regex: ".*".to_string(),
            uri_regex: ".*".to_string(),
            for_user_id: new_user.user_id.clone(),
        },
        db,
    )
    .await?;

    Ok(new_user)
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

/// Delete the user from the datastore.
///
/// ## Args:
/// - user: The user to delete.
/// - db: The mongo db instance.
///
/// ## Returns:
/// Ok if all went well or an Error:
/// - EntityNotFound: if the user is not found in the datastore.
pub async fn delete_for_user(user: &User, db: &Database) -> Result<bool, ErrorKind> {
    let delete_result = user_collection(db)
        .delete_one(doc! {"user_id": &user.user_id}, None)
        .await?;
    if delete_result.deleted_count == 0 {
        return Err(ErrorKind::EntityNotFound {
            message: format!("User {} not found", user.user_id),
        });
    }
    Ok(true)
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
