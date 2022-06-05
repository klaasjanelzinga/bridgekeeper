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

#[derive(Debug, Deserialize, Serialize)]
pub struct ValidateTotpWithBackupCodeRequest {
    pub backup_code: String,
}

impl Display for ValidateTotpWithBackupCodeRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidateTotpWithBackupCodeRequest")
            .field("backup_code", &self.backup_code)
            .finish()
    }
}
