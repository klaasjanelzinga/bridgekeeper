use std::fmt::{Display, Formatter};

use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use rocket::serde::{Deserialize, Serialize};

use crate::errors::ErrorKind;
use crate::user::User;

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub email_address: String,
    pub user_id: String,
    pub exp: usize,
    pub requires_otp_challenge: bool,
    pub otp_is_validated: bool,
}

impl Display for JwtClaims {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtClaims")
            .field("email_address", &self.email_address)
            .field("user_id", &self.user_id)
            .field("requires_otp_challenge", &self.requires_otp_challenge)
            .finish()
    }
}

/// Creates a JWT for the user. The email address and the user id are in the JwtClaims.
///
/// ## Args:
/// - user: The user to create the JWT for.
///
/// ## Returns:
/// The JWT as a string or an Error.
pub fn create_jwt_token(user: &User, encoding_key: &EncodingKey) -> Result<String, ErrorKind> {
    trace!("Creating a jwt for {}", user);
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

    trace!("Encoding the jwt");
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
    trace!("Creating a jwt for {}", user);
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

    trace!("Encoding the jwt");
    encode(&Header::default(), &jwt_claims, encoding_key).or(Err(ErrorKind::CannotCreateJwtToken))
}
