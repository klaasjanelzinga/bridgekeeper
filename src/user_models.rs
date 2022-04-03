use mongodb::bson::Bson;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UserJwtApiToken {
    pub public_token_id: String,
    pub private_token_id: String,
}

impl Display for UserJwtApiToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("public_token_id", &self.public_token_id)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct User {
    #[serde(skip_serializing)]
    pub _id: Option<Bson>,

    pub user_id: String,
    pub email_address: String,
    pub first_name: String,
    pub last_name: String,
    pub display_name: Option<String>,

    pub password_hash: String,

    pub otp_hash: Option<String>,
    pub otp_backup_codes: Vec<String>,
    pub pending_otp_hash: Option<String>,
    pub pending_backup_codes: Vec<String>,

    pub is_approved: bool,

    pub refresh_token_id: Option<String>,
    pub user_jwt_api_token: Vec<UserJwtApiToken>,
}

impl Display for User {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("_id", &self._id)
            .field("user_id", &self.user_id)
            .field("email_address", &self.email_address)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
pub struct GetUserResponse {
    pub user_id: String,
    pub email_address: String,
    pub first_name: String,
    pub last_name: String,
    pub display_name: Option<String>,
}

impl From<&User> for GetUserResponse {
    fn from(user: &User) -> Self {
        GetUserResponse {
            user_id: user.user_id.clone(),
            email_address: user.email_address.clone(),
            first_name: user.first_name.clone(),
            last_name: user.last_name.clone(),
            display_name: user.display_name.clone(),
        }
    }
}

impl Display for GetUserResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetUserResponse")
            .field("user_id", &self.user_id)
            .field("email_address", &self.email_address)
            .field("first_name", &self.first_name)
            .field("last_name", &self.last_name)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UpdateUserRequest {
    pub user_id: String,
    pub email_address: String,
    pub first_name: String,
    pub last_name: String,
    pub display_name: Option<String>,
}

impl Display for UpdateUserRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateUserRequest")
            .field("user_id", &self.user_id)
            .field("email_address", &self.email_address)
            .field("first_name", &self.first_name)
            .field("last_name", &self.last_name)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LoginRequest {
    pub email_address: String,
    pub password: String,
}

impl Display for LoginRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginRequest")
            .field("email_address", &self.email_address)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub needs_otp: bool,
}

impl Display for LoginResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginResponse").finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LoginWithOtpResponse {
    pub access_token: String,
    pub refresh_token: String,
}

impl Display for LoginWithOtpResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginResponse").finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

impl Display for ChangePasswordRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChangePasswordRequest").finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ChangePasswordResponse {
    pub success: bool,
    pub error_message: Option<String>,
}

impl Display for ChangePasswordResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChangePasswordResponse")
            .field("success", &self.success)
            .field("error_message", &self.error_message)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EmptyOkResponse {
    pub success: bool,
}

impl Display for EmptyOkResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmptyOkResponse")
            .field("success", &self.success)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateUserRequest {
    pub email_address: String,
    pub first_name: String,
    pub last_name: String,
    pub display_name: Option<String>,
    pub new_password: String,
}

impl Display for CreateUserRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateUserRequest")
            .field("email_address", &self.email_address)
            .field("first_name", &self.first_name)
            .field("last_name", &self.last_name)
            .finish()
    }
}
