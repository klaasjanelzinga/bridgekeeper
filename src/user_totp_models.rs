use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

#[derive(Debug, Deserialize, Serialize)]
pub struct StartTotpRegistrationResult {
    pub secret: String,
    pub uri: String,
    pub backup_codes: Vec<String>,
}

impl Display for StartTotpRegistrationResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartTotpRegistrationResult").finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ConfirmTotpResponse {
    pub success: bool,
}

impl Display for ConfirmTotpResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfirmTotpResponse")
            .field("success", &self.success)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ValidateTotpRequest {
    pub totp_challenge: String,
}

impl Display for ValidateTotpRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidateTotpRequest")
            .field("totp_challenge", &self.totp_challenge)
            .finish()
    }
}
