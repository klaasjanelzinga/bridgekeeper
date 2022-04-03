use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub email_address: String,
    pub user_id: String,
    pub exp: usize,
    pub requires_otp_challenge: bool,
    pub otp_is_validated: bool,
}

impl Display for JwtClaims {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtClaims")
            .field("email_address", &self.email_address)
            .field("user_id", &self.user_id)
            .field("requires_otp_challenge", &self.requires_otp_challenge)
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
