use std::fmt::{Display, Formatter};

use axum::async_trait;
use axum::extract::{FromRequest, RequestParts};
use axum::http::header::AUTHORIZATION;
use jsonwebtoken::{decode, Algorithm, Validation};
use mongodb::Database;

use crate::authorization::is_user_authorized_for;
use crate::errors::ErrorKind;
use crate::jwt::JwtClaims;
use crate::user::{get_by_id, User};
use crate::Config;

#[derive(Debug)]
pub struct AuthorizationHeader {
    pub bearer_token: String,
}

impl Display for AuthorizationHeader {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.debug_struct("AuthorizationHeader").finish()
    }
}

/// The token is valid:
/// - Has not been tampered with.
/// - Still recent enough.
#[derive(Debug)]
pub struct JwtToken {
    pub jwt_claims: JwtClaims,
    pub user: User,
}

impl Display for JwtToken {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.debug_struct("JwtToken")
            .field("claims", &self.jwt_claims)
            .field("user.email_address", &self.user.email_address)
            .field("user.user_id", &self.user.user_id)
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
            .field("user.email_address", &self.user.email_address)
            .field("user.user_id", &self.user.user_id)
            .finish()
    }
}

/// AuthorizedUser user. The token is valid and the user is authorized for the request.
#[derive(Debug)]
pub struct AuthorizedUser {
    pub jwt_claims: JwtClaims,
    pub user: User,
    pub authorization_rule: String,
}

impl Display for AuthorizedUser {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.debug_struct("AuthorizedUser")
            .field("claims", &self.jwt_claims)
            .field("user.user_id", &self.user.user_id)
            .field("user.email_address", &self.user.email_address)
            .field("authentication_rule", &self.authorization_rule)
            .finish()
    }
}

fn config_from_extension<B>(req: &RequestParts<B>) -> Result<Config, ErrorKind> {
    match req.extensions() {
        Some(extension) => match extension.get::<Config>() {
            Some(config) => Ok(config.clone()),
            None => Err(ErrorKind::ApplicationError {
                message: "Configuration not found.".to_string(),
            }),
        },
        None => Err(ErrorKind::ApplicationError {
            message: "No extensions found. Application configuration error.".to_string(),
        }),
    }
}

fn database_from_extension<B>(req: &RequestParts<B>) -> Result<Database, ErrorKind> {
    match req.extensions() {
        Some(extension) => match extension.get::<Database>() {
            Some(database) => Ok(database.clone()),
            None => Err(ErrorKind::ApplicationError {
                message: "Database not found.".to_string(),
            }),
        },
        None => Err(ErrorKind::ApplicationError {
            message: "No extensions found. Application configuration error.".to_string(),
        }),
    }
}

#[async_trait]
impl<B> FromRequest<B> for AuthorizationHeader
where
    B: Send,
{
    type Rejection = ErrorKind;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let headers = if let Some(headers) = req.headers() {
            headers
        } else {
            return Err(ErrorKind::RequiredHeadersNotFound);
        };
        let authorization_header = if let Some(auth_header) = headers.get(AUTHORIZATION) {
            auth_header
        } else {
            return Err(ErrorKind::AuthorizationHeaderNotFound);
        };
        match authorization_header.to_str() {
            Ok(value) => {
                if !value.starts_with("Bearer ") {
                    return Err(ErrorKind::AuthorizationHeaderNotValid);
                }
                Ok(AuthorizationHeader {
                    bearer_token: value[7..value.len()].to_string(),
                })
            }
            Err(_) => Err(ErrorKind::AuthorizationHeaderNotValid),
        }
    }
}

/// Request guard that validates the jwt token. The result is a JwtToken object.
/// After this guard:
/// - The authorization header is present and syntactically ok.
/// - The claims are decoded from the bearer token.
/// - The user exists in the datastore.
#[async_trait]
impl<B> FromRequest<B> for JwtToken
where
    B: Send,
{
    type Rejection = ErrorKind;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let authorization_header = AuthorizationHeader::from_request(req).await?;
        let config = config_from_extension(req).unwrap();
        let db = database_from_extension(req).unwrap();

        match decode::<JwtClaims>(
            &authorization_header.bearer_token,
            &config.decoding_key,
            &Validation::new(Algorithm::HS256),
        ) {
            Ok(token_data) => {
                let jwt_claims = token_data.claims;
                match get_by_id(&jwt_claims.user_id, &db).await {
                    Ok(user) => Ok(JwtToken { user, jwt_claims }),
                    Err(_) => Err(ErrorKind::TokenInvalid),
                }
            }
            Err(_) => Err(ErrorKind::TokenInvalid),
        }
    }
}

/// Request guard that validates that the user has succeeded the otp challenge if necessary.
/// After this guard:
/// - The user has succeeded the otp if the user has an otp configured.
#[async_trait]
impl<B> FromRequest<B> for OtpValidatedJwtToken
where
    B: Send,
{
    type Rejection = ErrorKind;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let jwt_token = JwtToken::from_request(req).await?;
        let user_has_otp_configured = jwt_token.user.otp_hash.is_some();
        let succeeded_otp_challenge = jwt_token.jwt_claims.otp_is_validated;
        if user_has_otp_configured && !succeeded_otp_challenge {
            return Err(ErrorKind::NotAuthorized);
        }
        Ok(OtpValidatedJwtToken {
            jwt_claims: jwt_token.jwt_claims,
            user: jwt_token.user,
        })
    }
}

/// Request guard that checks if the user has access to the resource requested.
#[async_trait]
impl<B> FromRequest<B> for AuthorizedUser
where
    B: Send,
{
    type Rejection = ErrorKind;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let jwt_token = OtpValidatedJwtToken::from_request(req).await?;
        let db = database_from_extension(req).unwrap();
        let config = config_from_extension(req).unwrap();

        let method = req.method().as_str();
        let path = req.uri().path();

        let is_authorized =
            is_user_authorized_for(&jwt_token.user, &config.application_name, method, path, &db)
                .await;
        match is_authorized {
            Ok(authorized_by_rule) => Ok(AuthorizedUser {
                jwt_claims: jwt_token.jwt_claims,
                user: jwt_token.user,
                authorization_rule: authorized_by_rule,
            }),
            Err(_) => Err(ErrorKind::NotAuthorized),
        }
    }
}
