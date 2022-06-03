use mongodb::bson::Bson;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

#[derive(Serialize, Deserialize)]
pub struct GetAvatarResponse {
    pub user_id: String,
    pub avatar_base64: String,
}

impl Display for GetAvatarResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetAvatarResponse")
            .field("user_id", &self.user_id)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
pub struct UpdateAvatarRequest {
    pub avatar_base64: String,
}

impl Display for UpdateAvatarRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateAvatarRequest").finish()
    }
}

#[derive(Serialize, Deserialize)]
pub struct UpdateAvatarResponse {
    pub result: bool,
}

impl Display for UpdateAvatarResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateAvatarResponse").finish()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Avatar {
    #[serde(skip_serializing)]
    pub _id: Option<Bson>,

    pub user_id: String,
    pub image_base64_blob: String,
}
