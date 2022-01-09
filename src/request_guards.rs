use crate::authorization::is_user_authorized_for;
use crate::errors::ErrorKind;
use crate::jwt::JwtClaims;
use crate::user::{get_by_id, User};
use crate::Config;
use jsonwebtoken::{decode, Algorithm, Validation};
use mongodb::Database;
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome};
use rocket::Request;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub struct AuthorizationHeader {
    pub bearer_token: String,
}

impl Display for AuthorizationHeader {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.debug_struct("AuthorizationHeader")
            .field("bearer_token", &self.bearer_token)
            .finish()
    }
}

/// The token is valid:
/// - Has not been tampered with.
/// - Still recent enougn.
#[derive(Debug)]
pub struct JwtToken {
    pub jwt_claims: JwtClaims,
    pub user: User,
}

impl Display for JwtToken {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.debug_struct("JwtToken")
            .field("claims", &self.jwt_claims)
            .field("user", &self.user)
            .finish()
    }
}

/// If the user needs otp validation, the token is validated.
#[derive(Debug)]
pub struct OtpValidatedJwtToken {
    pub jwt_claims: JwtClaims,
    pub user: User,
}

impl Display for OtpValidatedJwtToken {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.debug_struct("OtpValidatedJwtToken")
            .field("claims", &self.jwt_claims)
            .field("user", &self.user)
            .finish()
    }
}

/// Authenticated user. The token is valid and the user is authorized for the request.
#[derive(Debug)]
pub struct AuthenticatedUser {
    pub jwt_claims: JwtClaims,
    pub user: User,
    pub authentication_rule: String,
}

impl Display for AuthenticatedUser {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.debug_struct("AuthenticatedUser")
            .field("claims", &self.jwt_claims)
            .field("user", &self.user)
            .field("authentication_rule", &self.authentication_rule)
            .finish()
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthorizationHeader {
    type Error = ErrorKind;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match req.headers().get_one("Authorization") {
            None => Outcome::Failure((Status::Unauthorized, ErrorKind::NoTokenFound)),
            Some(bearer_token) => {
                if !bearer_token.starts_with("Bearer ") {
                    return Outcome::Failure((Status::Unauthorized, ErrorKind::NoTokenFound));
                }
                Outcome::Success(AuthorizationHeader {
                    bearer_token: bearer_token[7..bearer_token.len()].to_string(),
                })
            }
        }
    }
}

/// Request guard that validates the jwt token. The result is a JwtToken object.
/// After this guard:
/// - The authorization header is present and syntactically ok.
/// - The claims are decoded from the bearer token.
/// - The user exists in the datastore.
#[rocket::async_trait]
impl<'r> FromRequest<'r> for JwtToken {
    type Error = ErrorKind;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match req.guard::<AuthorizationHeader>().await {
            Outcome::Success(bearer_token) => {
                let config = req
                    .rocket()
                    .state::<Config>()
                    .expect("Configuration required");
                let db = req
                    .rocket()
                    .state::<Database>()
                    .expect("Database not present");

                let token_message = decode::<JwtClaims>(
                    &bearer_token.bearer_token,
                    &config.decoding_key,
                    &Validation::new(Algorithm::HS256),
                )
                .expect("Should work");

                let user = get_by_id(&token_message.claims.user_id, db).await;

                Outcome::Success(JwtToken {
                    jwt_claims: token_message.claims,
                    user: user.expect("What, no user"),
                })
            }
            _ => Outcome::Failure((Status::Unauthorized, ErrorKind::NotAuthorized)),
        }
    }
}

/// Request guard that validates that the user has succeeded the otp challenge if necessary.
/// After this guard:
/// - The user has succeeded the otp if the user has an otp configured.
#[rocket::async_trait]
impl<'r> FromRequest<'r> for OtpValidatedJwtToken {
    type Error = ErrorKind;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match req.guard::<JwtToken>().await {
            Outcome::Success(jwt_token) => {
                let has_otp_configured = jwt_token.user.otp_hash.is_some();
                let succeeded_otp_challenge = jwt_token.jwt_claims.otp_is_validated;
                if has_otp_configured && !succeeded_otp_challenge {
                    return Outcome::Failure((Status::Unauthorized, ErrorKind::NotAuthorized));
                }
                Outcome::Success(OtpValidatedJwtToken {
                    jwt_claims: jwt_token.jwt_claims,
                    user: jwt_token.user,
                })
            }
            _ => Outcome::Failure((Status::Unauthorized, ErrorKind::NotAuthorized)),
        }
    }
}

/// Request guard that checks if the user has access to the resource requested.
#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUser {
    type Error = ErrorKind;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match req.guard::<OtpValidatedJwtToken>().await {
            Outcome::Success(jwt_token) => {
                let config = req
                    .rocket()
                    .state::<Config>()
                    .expect("Configuration required");
                let db = req
                    .rocket()
                    .state::<Database>()
                    .expect("Database not present");
                let is_authorized = is_user_authorized_for(
                    &jwt_token.user,
                    &config.application_name,
                    &req.method().as_str(),
                    &req.uri().path().as_str(),
                    db,
                )
                .await;
                match is_authorized {
                    Ok(authorization_rule) => Outcome::Success(AuthenticatedUser {
                        jwt_claims: jwt_token.jwt_claims,
                        user: jwt_token.user,
                        authentication_rule: authorization_rule,
                    }),
                    Err(_) => Outcome::Failure((Status::Unauthorized, ErrorKind::NotAuthorized)),
                }
            }
            _ => Outcome::Failure((Status::Unauthorized, ErrorKind::NotAuthorized)),
        }
    }
}
