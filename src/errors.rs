use strum_macros::Display;

#[derive(Display, Debug)]
pub enum ErrorKind {

    EntityNotFound { message: String },

    MongoDbError { mongodb_error: mongodb::error::Error },
}
