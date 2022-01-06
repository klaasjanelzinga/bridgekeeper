use std::fmt::{Display, Formatter};

use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::errors::ErrorKind;
use crate::errors::ErrorKind::TokenInvalid;
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

#[derive(Debug)]
pub struct ValidJwtToken {
    pub jwt_claims: JwtClaims,
}

impl Display for ValidJwtToken {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.debug_struct("ValidJwtToken")
            .field("claims", &self.jwt_claims)
            .finish()
    }
}

#[derive(Debug)]
pub struct ValidJwtTokenWithOtpChallengeOk {
    pub jwt_claims: JwtClaims,
}

impl Display for ValidJwtTokenWithOtpChallengeOk {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.debug_struct("ValidJwtTokenWithOtpChallengeOk")
            .field("claims", &self.jwt_claims)
            .finish()
    }
}

fn decode_token_to_claims(token: &str, decoding_key: &DecodingKey) -> Result<JwtClaims, ErrorKind> {
    trace!("Validating jwt token {}", token);
    if !token.starts_with("Bearer ") {
        return Err(TokenInvalid);
    }
    let token_message = decode::<JwtClaims>(
        &token[7..token.len()],
        decoding_key,
        &Validation::new(Algorithm::HS256),
    );
    match token_message {
        Ok(token_data) => Ok(token_data.claims),
        Err(_) => Err(TokenInvalid),
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ValidJwtToken {
    type Error = ErrorKind;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let config = req.rocket().state::<Config>().unwrap();

        match req.headers().get_one("Authorization") {
            None => Outcome::Failure((Status::Unauthorized, ErrorKind::NoTokenFound)),
            Some(key) => {
                let check_key = decode_token_to_claims(key, &config.decoding_key);
                match check_key {
                    Ok(claims) => {
                        if claims.requires_otp_challenge {
                            Outcome::Failure((
                                Status::Forbidden,
                                ErrorKind::OtpAuthorizationRequired,
                            ))
                        } else {
                            Outcome::Success(ValidJwtToken { jwt_claims: claims })
                        }
                    }
                    Err(_) => Outcome::Failure((Status::Unauthorized, ErrorKind::TokenInvalid)),
                }
            }
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ValidJwtTokenWithOtpChallengeOk {
    type Error = ErrorKind;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let config = req.rocket().state::<Config>().unwrap();

        match req.headers().get_one("Authorization") {
            None => Outcome::Failure((Status::Unauthorized, ErrorKind::NoTokenFound)),
            Some(key) => {
                let check_key = decode_token_to_claims(key, &config.decoding_key);
                match check_key {
                    Ok(claims) => {
                        Outcome::Success(ValidJwtTokenWithOtpChallengeOk { jwt_claims: claims })
                    }
                    Err(_) => Outcome::Failure((Status::Forbidden, ErrorKind::TokenInvalid)),
                }
            }
        }
    }
}
