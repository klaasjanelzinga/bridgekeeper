use std::fmt::{Debug, Display, Formatter};

#[derive(Debug)]
pub enum ErrorKind {
    EntityNotFound {
        message: String,
    },
    MongoDbError {
        mongodb_error: mongodb::error::Error,
    },
}

impl std::error::Error for ErrorKind {}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &*self {
            ErrorKind::EntityNotFound { message } => write!(f, "EntityNotFound: {}", message),
            ErrorKind::MongoDbError { mongodb_error } => {
                write!(f, "MongoDbError: {}", mongodb_error)
            }
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
