use rocket::http::Status;
use std::fmt::{Debug, Display, Formatter};

#[derive(Debug)]
pub enum ErrorKind {
    EntityNotFound {
        message: String,
    },
    IllegalRequest {
        message: String,
    },
    MongoDbError {
        mongodb_error: mongodb::error::Error,
    },
    PasswordInvalid {
        message: String,
    },
    TotpChallengeInvalid,
    CannotVerifyPassword,
    CannotEncodePassword,
    CannotCreateJwtToken,
    PasswordIncorrect,
    OtpAuthorizationRequired,
    NoTokenFound,
    TokenInvalid,
    IllegalDataAccess {
        message: String,
    },
    NotImplemented,
    NotAuthorized,
}

impl std::error::Error for ErrorKind {}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &*self {
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
            ErrorKind::NoTokenFound => write!(f, "NoTokenFound"),
            ErrorKind::TokenInvalid => write!(f, "TokenInvalid"),
            ErrorKind::NotImplemented => write!(f, "NotImplemented"),
            ErrorKind::NotAuthorized => write!(f, "NotAuthorized"),
            ErrorKind::IllegalDataAccess { message } => write!(f, "IllegalDataAccess: {}", message),
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

impl From<ErrorKind> for Status {
    fn from(error_kind: ErrorKind) -> Self {
        match error_kind {
            ErrorKind::EntityNotFound { message } => {
                trace!("{}", message);
                Status::NotFound
            }
            ErrorKind::MongoDbError { mongodb_error } => {
                warn!("{}", mongodb_error);
                Status::ServiceUnavailable
            }
            ErrorKind::PasswordInvalid { message } => {
                info!("{}", message);
                Status::BadRequest
            }
            ErrorKind::IllegalRequest { message } => {
                info!("{}", message);
                Status::BadRequest
            }
            ErrorKind::CannotVerifyPassword => Status::BadRequest,
            ErrorKind::CannotEncodePassword => Status::BadRequest,
            ErrorKind::PasswordIncorrect => Status::Unauthorized,
            ErrorKind::TotpChallengeInvalid => Status::Unauthorized,
            ErrorKind::OtpAuthorizationRequired => Status::Forbidden,
            ErrorKind::CannotCreateJwtToken => Status::Unauthorized,
            ErrorKind::NoTokenFound => Status::Unauthorized,
            ErrorKind::TokenInvalid => Status::Unauthorized,
            ErrorKind::NotImplemented => Status::InternalServerError,
            ErrorKind::NotAuthorized => Status::Unauthorized,
            ErrorKind::IllegalDataAccess { message } => {
                warn!("An illegal access was made: {}", message);
                Status::Forbidden
            }
        }
    }
}
