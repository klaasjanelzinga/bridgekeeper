use futures::TryStreamExt;
use jsonwebtoken::{decode, Algorithm, Validation};

use crate::authorization_models::{AddAuthorizationRequest, ApproveUserRequest, Authorization};
use crate::Config;
use mongodb::bson::doc;
use mongodb::{Collection, Database};
use regex::Regex;

use crate::errors::ErrorKind;
use crate::jwt_models::JwtApiClaims;
use crate::user::{get_by_id, update_user};
use crate::user_models::User;

/// Creates the authorization collection for the database.
fn authorization_collection(db: &Database) -> Collection<Authorization> {
    db.collection::<Authorization>("authorization")
}

pub async fn approve_user_in_request(
    request: &ApproveUserRequest,
    db: &Database,
) -> Result<bool, ErrorKind> {
    trace!("approve_user_in_request({}, _)", request);
    let mut user = get_by_id(&request.approve_user_id, db).await?;
    user.is_approved = true;
    update_user(&user, db).await?;
    Ok(true)
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

pub async fn is_user_authorized_for(
    user: &User,
    application: &str,
    method: &str,
    uri: &str,
    db: &Database,
) -> Result<String, ErrorKind> {
    trace!(
        "is_user_authorized_for({}, {}, {}, {}, _)",
        user,
        application,
        method,
        uri
    );
    let collection = authorization_collection(db);
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
        let uri_is_matched = uri_regex.is_match(uri);
        let method_is_matched = method_regex.is_match(method);
        if uri_is_matched && method_is_matched {
            return Ok(authorization.to_string());
        }
    }
    Err(ErrorKind::NotAuthorized)
}

/// Checks if the jwt-api-token is valid and that the user exists.
///
/// ## Args:
/// token: The jwt-api-token to validate.
/// config: Configuration of this application.
/// db: A valid database.
///
/// ## Returns:
/// True if:
/// - The token is valid (crypto and date).
/// - The user exists.
/// - And the user has the jwt_api_token with matching private and public token id.
/// other wise an ErrorKind is returned.
pub async fn is_jwt_api_token_valid(
    token: &str,
    config: &Config<'_>,
    db: &Database,
) -> Result<bool, ErrorKind> {
    trace!("is_jwt_api_token_valid(_, _, _)");
    match decode::<JwtApiClaims>(
        token,
        &config.decoding_key,
        &Validation::new(Algorithm::HS256),
    ) {
        Ok(token_data) => {
            let jwt_claims = token_data.claims;
            match get_by_id(&jwt_claims.user_id, db).await {
                Ok(user) => {
                    let user_has_jwt_api = user.user_jwt_api_token.iter().find(|jwt_api_token| {
                        jwt_api_token.public_token_id == jwt_claims.public_token_id
                            && jwt_api_token.private_token_id == jwt_claims.private_token_id
                    });
                    match user_has_jwt_api {
                        None => Err(ErrorKind::NotAuthorized),
                        Some(_) => Ok(true),
                    }
                }
                Err(_) => Err(ErrorKind::NotAuthorized),
            }
        }
        Err(_) => Err(ErrorKind::NotAuthorized),
    }
}
