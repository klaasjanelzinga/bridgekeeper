use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use mongodb::Database;

use crate::errors::ErrorKind;
use crate::jwt_models::{JwtApiClaims, JwtClaims, JwtCreationResponse, JwtType};
use crate::user::update_user;
use crate::user_models::{User, UserJwtApiToken};
use crate::util::{create_id, random_string};

/// Create a specific token for a user. Depending on the type a expiration time will be set.
pub fn create_token_for_user(
    token_type: JwtType,
    user: &User,
    encoding_key: &EncodingKey,
) -> Result<JwtCreationResponse, ErrorKind> {
    let expiration_timestamp = match token_type {
        JwtType::OneShotToken => chrono::Duration::minutes(5),
        JwtType::RefreshToken => chrono::Duration::days(4),
        JwtType::AccessToken => chrono::Duration::hours(3),
    };
    let expiration = Utc::now()
        .checked_add_signed(expiration_timestamp)
        .expect("valid timestamp")
        .timestamp();
    let token_id = create_id();

    let jwt_claims = JwtClaims {
        email_address: user.email_address.clone(),
        user_id: user.user_id.clone(),
        token_id: token_id.clone(),
        token_type,
        exp: expiration as usize,
    };

    let token_result = encode(&Header::default(), &jwt_claims, encoding_key)
        .or(Err(ErrorKind::CannotCreateJwtToken));
    match token_result {
        Ok(token) => Ok(JwtCreationResponse {
            token,
            token_id: token_id.clone(),
        }),
        Err(error) => Err(error),
    }
}

/// Creates a access token for the user. The email address and the user id are in the JwtClaims.
///
/// ## Args:
/// - user: The user to create the JWT for.
/// - encoding_key: The encoding key for the encrypted jwt.
///
/// ## Returns:
/// The JWT as a string or an Error.
pub fn create_access_token(
    user: &User,
    encoding_key: &EncodingKey,
) -> Result<JwtCreationResponse, ErrorKind> {
    trace!("create_access_token({})", user);
    create_token_for_user(JwtType::AccessToken, user, encoding_key)
}

/// Creates a refresh token for the user. The email address and the user id are in the JwtClaims.
///
/// ## Args:
/// - user: The user to create the JWT for.
/// - encoding_key: The encoding key for the encrypted jwt.
///
/// ## Returns:
/// The JWT as a string or an Error.
pub fn create_refresh_token(
    user: &User,
    encoding_key: &EncodingKey,
) -> Result<JwtCreationResponse, ErrorKind> {
    trace!("create_refresh_token({})", user);
    create_token_for_user(JwtType::RefreshToken, user, encoding_key)
}

/// Creates a one shot token for the user. The email address and the user id are in the JwtClaims.
///
/// ## Args:
/// - user: The user to create the JWT for.
/// - encoding_key: The encoding key for the encrypted jwt.
///
/// ## Returns:
/// The JWT as a string or an Error.
pub fn create_one_shot_token(
    user: &User,
    encoding_key: &EncodingKey,
) -> Result<JwtCreationResponse, ErrorKind> {
    trace!("create_one_shot_token({})", user);
    create_token_for_user(JwtType::OneShotToken, user, encoding_key)
}

/// Create an api jwt token. This token can be used for a third party application to act on behalf
/// of the user.
///
/// ## Args:
/// - user: The user to create the token for.
/// - public_token_id: A identifier for this token.
/// - encoding_key: The key with which the jwt is encoded.
///
/// ## Returns:
/// The JWT as a string or an Error.
pub async fn create_api_jwt_token_for_user(
    user: &User,
    public_token_id: &str,
    encoding_key: &EncodingKey,
    db: &Database,
) -> Result<String, ErrorKind> {
    trace!("create_api_jwt_token({}, {})", user, public_token_id);
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::days(360))
        .expect("valid timestamp")
        .timestamp();

    // create a new UserJwtApp token
    let mut new_collection: Vec<UserJwtApiToken> = user
        .user_jwt_api_token
        .iter()
        .filter(|user_jwt_api_token| user_jwt_api_token.public_token_id != public_token_id)
        .cloned()
        .collect();
    let private_token_id = random_string(16);
    new_collection.push(UserJwtApiToken {
        public_token_id: public_token_id.to_string(),
        private_token_id: private_token_id.clone(),
    });

    let jwt_claims = JwtApiClaims {
        user_id: user.user_id.clone(),
        exp: expiration as usize,
        public_token_id: public_token_id.to_string(),
        private_token_id: private_token_id.clone(),
    };
    let mut db_user = user.clone();
    db_user.user_jwt_api_token = new_collection;
    update_user(&db_user, db).await?;
    encode(&Header::default(), &jwt_claims, encoding_key).or(Err(ErrorKind::CannotCreateJwtToken))
}

pub async fn delete_jwt_api_token_for_user(
    user: &User,
    public_token_id: &str,
    db: &Database,
) -> Result<bool, ErrorKind> {
    trace!(
        "delete_jwt_api_token_for_user({}, {})",
        user,
        public_token_id
    );
    // create a new UserJwtApp token
    let new_collection: Vec<UserJwtApiToken> = user
        .user_jwt_api_token
        .iter()
        .filter(|user_jwt_api_token| user_jwt_api_token.public_token_id != public_token_id)
        .cloned()
        .collect();

    let mut db_user = user.clone();
    db_user.user_jwt_api_token = new_collection;
    update_user(&db_user, db).await?;
    Ok(true)
}
