use std::fmt::{Display, Formatter};

use mongodb::bson::doc;
use mongodb::bson::Bson;
use mongodb::{Collection, Database};
use regex::Regex;
use rocket::futures::TryStreamExt;
use rocket::serde::{Deserialize, Serialize};

use crate::errors::ErrorKind;
use crate::jwt::ValidJwtToken;
use crate::user::{get_with_user_id, User};

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct AddAuthorizationRequest {
    pub for_user_id: String,
    pub application: String,
    pub uri_regex: String,
    pub method_regex: String,
}

impl Display for AddAuthorizationRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddAuthorizationRequest")
            .field("for_user_id", &self.for_user_id)
            .field("application", &self.application)
            .field("uri_regex", &self.uri_regex)
            .field("method_regex", &self.method_regex)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct IsAuthorizedRequest {
    pub application: String,
    pub uri: String,
    pub method: String,
}

impl Display for IsAuthorizedRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IsAuthorizedRequest")
            .field("application", &self.application)
            .field("uri", &self.uri)
            .field("method", &self.method)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct IsAuthorizedResponse {
    pub is_authorized: bool,
}

impl Display for IsAuthorizedResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IsAuthorizedResponse")
            .field("is_authorized", &self.is_authorized)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct Authorization {
    #[serde(skip_serializing)]
    pub _id: Option<Bson>,

    pub user_id: String,
    pub application: String,
    pub uri_regex: String,
    pub method_regex: String,
}

impl Display for Authorization {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authorization")
            .field("user_id", &self.user_id)
            .field("application", &self.application)
            .field("uri_regex", &self.uri_regex)
            .field("method_regex", &self.method_regex)
            .finish()
    }
}

/// Creates the authorization collection for the database.
fn authorization_collection(db: &Database) -> Collection<Authorization> {
    db.collection::<Authorization>("authorization")
}

pub async fn create(
    request: &AddAuthorizationRequest,
    db: &Database,
) -> Result<Authorization, ErrorKind> {
    trace!("add_authorization({}, _)", request);
    let collection = authorization_collection(db);

    // check if already exists.
    // Create authorization.
    let authorization = Authorization {
        _id: None,
        user_id: request.for_user_id.clone(),
        application: request.application.clone(),
        uri_regex: request.uri_regex.clone(),
        method_regex: request.method_regex.clone(),
    };

    let insert_result = collection.insert_one(&authorization, None).await?;
    trace!(
        "New authorization added {} with id {}",
        authorization,
        insert_result.inserted_id
    );

    Ok(authorization)
}

/// Check if the user with this token has access to the application / method / uri.
///
/// ## Params:
/// - valid_jwt_token - The token to check the authorization for.
/// - application - The application for which authorization is requested.
/// - method - The method (GET, POST, etc) for which authorization is requested.
/// - uri - The uri for which authorization is requested.
///
/// ## Returns:
/// If the user has authorization for the resource 'true' is returned.
/// - ErrorKind::NotAuthorized - if no authorization is found.
pub async fn is_token_authorized_for(
    valid_jwt_token: &ValidJwtToken,
    application: &str,
    method: &str,
    uri: &str,
    db: &Database,
) -> Result<User, ErrorKind> {
    trace!(
        "is_token_authorized_for({}, {}, {}, {})",
        valid_jwt_token,
        application,
        method,
        uri
    );
    let collection = authorization_collection(db);
    match get_with_user_id(valid_jwt_token, db).await {
        Ok(user) => {
            let mut authorization_records = collection
                .find(
                    doc! {
                        "user_id": user.user_id.clone(),
                        "application": application,
                    },
                    None,
                )
                .await?;
            while let Some(authorization) = authorization_records.try_next().await? {
                let uri_regex = Regex::new(&authorization.uri_regex).unwrap();
                let method_regex = Regex::new(&authorization.method_regex).unwrap();

                // application is matched, user_id is matched.
                let uri_is_matched = uri_regex.is_match(&uri);
                let method_is_matched = method_regex.is_match(&method);
                if uri_is_matched && method_is_matched {
                    return Ok(user);
                }
            }
            Err(ErrorKind::NotAuthorized)
        }
        Err(_) => Err(ErrorKind::NotAuthorized),
    }
}
