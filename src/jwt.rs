use std::fmt::{Display, Formatter};

use chrono::Utc;
use jsonwebtoken::{Algorithm, decode, DecodingKey, encode, EncodingKey, Header, Validation};
use rocket::http::Status;
use rocket::request::{Request, FromRequest, Outcome};
use rocket::serde::{Deserialize, Serialize};

use crate::errors::ErrorKind;
use crate::errors::ErrorKind::TokenInvalid;
use crate::users::User;
use crate::config::Config;

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub email_address: String,
    pub user_id: String,
    pub exp: usize,
}

impl Display for JwtClaims {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtClaims")
            .field("email_address", &self.email_address)
            .field("user_id", &self.user_id)
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
    };

    trace!("Encoding the jwt");
    encode(
        &Header::default(),
        &jwt_claims,
        encoding_key,
    )
    .or(Err(ErrorKind::CannotCreateJwtToken))
}


#[derive(Debug)]
pub struct ValidJwtToken {
    jwt_claims: JwtClaims,
}

impl Display for ValidJwtToken {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.debug_struct("ValidJwtToken")
            .field("claims", &self.jwt_claims)
            .finish()
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ValidJwtToken {

    type Error = ErrorKind;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        fn is_valid(token: &str, decoding_key: &DecodingKey) -> Result<JwtClaims, ErrorKind> {
            trace!("Validating jwt token {}", token);
            if !token.starts_with("Bearer ") {
                return Err(TokenInvalid)
            }
            let token_message = decode::<JwtClaims>(
                &token[7..token.len()],
                decoding_key,
                &Validation::new(Algorithm::HS256)
            );
            match token_message {
                Ok(token_data) => Ok(token_data.claims),
                Err(_) => Err(TokenInvalid)
            }
        }

        let config = req.rocket().state::<Config>().unwrap();

        match req.headers().get_one("Authorization") {
            None => Outcome::Failure((Status::Unauthorized, ErrorKind::NoTokenFound)),
            Some(key) => {
                let check_key = is_valid(key, &config.decoding_key);
                match check_key {
                    Ok(claims) => Outcome::Success(ValidJwtToken{ jwt_claims: claims }),
                    Err(_) => Outcome::Failure((Status::Unauthorized, ErrorKind::TokenInvalid))
                }
            },
        }
    }
}
