use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

#[derive(Debug, Serialize, Deserialize)]
pub enum JwtType {
    AccessToken,
    RefreshToken,
    OneShotToken,
}

impl Display for JwtType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {
            JwtType::RefreshToken => write!(f, "RefreshToken"),
            JwtType::OneShotToken => write!(f, "OneShotToken"),
            JwtType::AccessToken => write!(f, "AccessToken"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub email_address: String,
    pub user_id: String,
    pub token_id: String,
    pub token_type: JwtType,
    pub exp: usize,
}

impl Display for JwtClaims {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtClaims")
            .field("email_address", &self.email_address)
            .field("user_id", &self.user_id)
            .field("token_type", &self.token_type)
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtApiClaims {
    pub user_id: String,
    pub public_token_id: String,
    pub private_token_id: String,
    pub exp: usize,
}

impl Display for JwtApiClaims {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtClaims")
            .field("user_id", &self.user_id)
            .field("public_token_id", &self.public_token_id)
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateJwtApiRequest {
    pub public_token_id: String,
}

impl Display for CreateJwtApiRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateJwtApiRequest")
            .field("public_token_id", &self.public_token_id)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateJwtApiResponse {
    pub token: String,
}

impl Display for CreateJwtApiResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateJwtApiResponse")
            .field("token", &self.token)
            .finish()
    }
}

pub struct JwtCreationResponse {
    pub token: String,
    pub token_id: String,
}
