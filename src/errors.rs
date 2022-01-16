use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::fmt::{Debug, Display, Formatter};

#[derive(Debug)]
pub enum ErrorKind {
    /// Authorization errors.
    CannotVerifyPassword,
    CannotEncodePassword,
    CannotCreateJwtToken,
    PasswordIncorrect,
    TokenInvalid,
    RequiredHeadersNotFound,
    AuthorizationHeaderNotFound,
    AuthorizationHeaderNotValid,

    TotpChallengeInvalid,
    OtpAuthorizationRequired,
    /// Generic Not authorized
    NotAuthorized,

    /// Data verification errors
    PasswordInvalid {
        message: String,
    },

    /// Catch all error
    ApplicationError {
        message: String,
    },

    EntityNotFound {
        message: String,
    },
    IllegalRequest {
        message: String,
    },
    MongoDbError {
        mongodb_error: mongodb::error::Error,
    },
    NotImplemented,
}

impl IntoResponse for ErrorKind {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            ErrorKind::PasswordIncorrect => (StatusCode::UNAUTHORIZED, "".to_string()),
            ErrorKind::TotpChallengeInvalid => (StatusCode::UNAUTHORIZED, "".to_string()),
            ErrorKind::NotAuthorized => (StatusCode::UNAUTHORIZED, "".to_string()),
            ErrorKind::RequiredHeadersNotFound => (StatusCode::UNAUTHORIZED, "".to_string()),
            ErrorKind::AuthorizationHeaderNotFound => (StatusCode::UNAUTHORIZED, "".to_string()),
            ErrorKind::AuthorizationHeaderNotValid => (StatusCode::UNAUTHORIZED, "".to_string()),
            ErrorKind::TokenInvalid => (StatusCode::UNAUTHORIZED, "".to_string()),

            ErrorKind::ApplicationError { message } => (StatusCode::SERVICE_UNAVAILABLE, message),

            ErrorKind::PasswordInvalid { message } => {
                info!("PasswordInvalid: {}", message);
                (StatusCode::BAD_REQUEST, message)
            }

            ErrorKind::EntityNotFound { message } => {
                info!("User not found: {}", message);
                (StatusCode::NOT_FOUND, "User not found".to_string())
            }

            error => {
                info!("Unmapped error: {}", error);
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Generic error. Service unavailable.".to_string(),
                )
            }
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

impl std::error::Error for ErrorKind {}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &*self {
            ErrorKind::RequiredHeadersNotFound => write!(f, "RequiredHeadersNotFound"),
            ErrorKind::AuthorizationHeaderNotFound => write!(f, "AuthorizationHeaderNotFound"),
            ErrorKind::AuthorizationHeaderNotValid => write!(f, "AuthorizationHeaderNotValid"),

            ErrorKind::NotAuthorized => write!(f, "NotAuthorized"),

            ErrorKind::ApplicationError { message } => write!(f, "ApplicationError {}", message),

            ErrorKind::EntityNotFound { message } => write!(f, "EntityNotFound: {}", message),
            ErrorKind::IllegalRequest { message } => write!(f, "IllegalRequest: {}", message),
            ErrorKind::PasswordInvalid { message } => write!(f, "PasswordInvalid: {}", message),
            ErrorKind::MongoDbError { mongodb_error } => {
                write!(f, "MongoDbError: {}", mongodb_error)
            }
            ErrorKind::CannotEncodePassword => write!(f, "CannotEncodePassword"),
            ErrorKind::CannotVerifyPassword => write!(f, "CannotVerifyPassword"),
            ErrorKind::PasswordIncorrect => write!(f, "PasswordIncorrect"),
            ErrorKind::TotpChallengeInvalid => write!(f, "TotpChallengeInvalid"),
            ErrorKind::OtpAuthorizationRequired => write!(f, "OtpAuthorizationRequired"),
            ErrorKind::CannotCreateJwtToken => write!(f, "CannotCreateJwtToken"),
            ErrorKind::TokenInvalid => write!(f, "TokenInvalid"),
            ErrorKind::NotImplemented => write!(f, "NotImplemented"),
        }
    }
}

impl From<mongodb::error::Error> for ErrorKind {
    fn from(mongo_error: mongodb::error::Error) -> Self {
        ErrorKind::MongoDbError {
            mongodb_error: mongo_error,
        }
    }
}
