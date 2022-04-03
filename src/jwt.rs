use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use mongodb::Database;

use crate::errors::ErrorKind;
use crate::jwt_models::{JwtApiClaims, JwtClaims};
use crate::user::update_user;
use crate::user_models::{User, UserJwtApiToken};
use crate::util::random_string;

/// Creates a JWT for the user. The email address and the user id are in the JwtClaims.
///
/// ## Args:
/// - user: The user to create the JWT for.
///
/// ## Returns:
/// The JWT as a string or an Error.
pub fn create_jwt_token(user: &User, encoding_key: &EncodingKey) -> Result<String, ErrorKind> {
    trace!("create_jwt_token({})", user);
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::days(20))
        .expect("valid timestamp")
        .timestamp();

    let jwt_claims = JwtClaims {
        email_address: user.email_address.clone(),
        user_id: user.user_id.clone(),
        exp: expiration as usize,
        requires_otp_challenge: user.otp_hash.is_some(),
        otp_is_validated: false,
    };

    encode(&Header::default(), &jwt_claims, encoding_key).or(Err(ErrorKind::CannotCreateJwtToken))
}

/// Creates a JWT for the user. The email address and the user id are in the JwtClaims.
///
/// ## Args:
/// - user: The user to create the JWT for.
///
/// ## Returns:
/// The JWT as a string or an Error.
pub fn create_otp_validated_jwt_token(
    user: &User,
    encoding_key: &EncodingKey,
) -> Result<String, ErrorKind> {
    trace!("create_otp_validated_jwt_token({})", user);
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::days(30))
        .expect("valid timestamp")
        .timestamp();

    let jwt_claims = JwtClaims {
        email_address: user.email_address.clone(),
        user_id: user.user_id.clone(),
        exp: expiration as usize,
        requires_otp_challenge: false,
        otp_is_validated: true,
    };

    encode(&Header::default(), &jwt_claims, encoding_key).or(Err(ErrorKind::CannotCreateJwtToken))
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
