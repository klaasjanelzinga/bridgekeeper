use mongodb::bson::Bson;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

#[derive(Debug, Deserialize, Serialize)]
pub struct ApproveUserRequest {
    pub approve_user_id: String,
}

impl Display for ApproveUserRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApproveUserRequest")
            .field("approve_user_id", &self.approve_user_id)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
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
pub struct IsJwtApiTokenValidRequest {
    pub token: String,
}

impl Display for IsJwtApiTokenValidRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IsJwtApiTokenValidRequest").finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct IsAuthorizedResponse {
    pub is_authorized: bool,
    pub user_id: String,
    pub email_address: String,
    pub first_name: String,
    pub last_name: String,
    pub display_name: Option<String>,
}

impl Display for IsAuthorizedResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IsAuthorizedResponse")
            .field("is_authorized", &self.is_authorized)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct IsJwtValidResponse {
    pub is_ok: bool,
}

impl Display for IsJwtValidResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IsJwtValidResponse")
            .field("is_ok", &self.is_ok)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
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
