use std::fmt::{Debug, Formatter};

pub enum ErrorKind {
    EntityNotFound {
        message: String,
    },
    MongoDbError {
        mongodb_error: mongodb::error::Error,
    },
}

impl Debug for ErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &*self {
            ErrorKind::EntityNotFound { message } => write!(f, "EntityNotFound: {}", message),
            ErrorKind::MongoDbError { mongodb_error } => {
                write!(f, "MongoDbError: {}", mongodb_error)
            }
        }
    }
}
