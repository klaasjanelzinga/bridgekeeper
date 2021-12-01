use crate::config::Config;
use crate::errors::ErrorKind;
use crate::user::{LoginResponse, User};
use crate::{jwt, user, util};
use mongodb::Database;
use rocket::serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_lite::{totp, Sha512};

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
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
#[serde(crate = "rocket::serde")]
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
#[serde(crate = "rocket::serde")]
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

/// Start the registration process for a TOTP token. The following items will be created:
/// - an uri: For creating a QR code on the client side.
/// - backup_codes: Backup codes that can be used instead of the totp.
/// - secret: The shared secret.
///
/// ## Args:
/// - user: The user to start the totp registration for.
/// - db - The mongo db instance.
///
/// ## Returns:
/// The StartTotpRegistrationResponse or an error.
///
pub async fn start_totp_registration_for_user(
    user: &User,
    db: &Database,
) -> Result<StartTotpRegistrationResult, ErrorKind> {
    trace!("start_totp_registration({})", user);
    let secret = util::random_string(32);
    let backup_codes = [
        util::random_string(8),
        util::random_string(8),
        util::random_string(8),
        util::random_string(8),
        util::random_string(8),
        util::random_string(8),
    ]
    .to_vec();
    let label = format!("Linkje:{}", user.email_address);
    let uri = format!("otpauth://totp/{}?secret={}&issuer=Linkje", label, secret);

    // store the pending otp codes with the user.
    let mut db_user = user::get_by_id(&user.user_id, db).await?;
    db_user.pending_backup_codes = backup_codes.clone();
    db_user.pending_otp_hash = Some(secret.clone());

    user::update_user(&db_user, db).await?;

    Ok(StartTotpRegistrationResult {
        backup_codes,
        uri,
        secret,
    })
}

fn validate_totp(otp_hash: &Option<String>, challenge: &str) -> Result<bool, ErrorKind> {
    let possible_hash = otp_hash.clone();
    possible_hash.map_or(
        Err(ErrorKind::IllegalRequest {
            message: String::from("No otp codes configured for user."),
        }),
        |otp| {
            // Calculate a TOTP for the pending secret.
            let seconds: u64 = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let totp_value = totp::<Sha512>(otp.as_bytes(), seconds);
            if totp_value != challenge {
                info!("Token value does not match");
                return Err(ErrorKind::TotpChallengeInvalid);
            }
            Ok(true)
        },
    )
}

/// Confirm the totp shared secret in the registration process.
///
/// ## Args:
/// - user: The user to confirm the totp for.
/// - request: The request containing the confirmation code.
/// - db: Valid db mongo instance.
///
/// ## Returns:
/// Either an error code or a success response.
pub async fn confirm_totp_code_for_user(
    user: &User,
    request: &ValidateTotpRequest,
    db: &Database,
) -> Result<ConfirmTotpResponse, ErrorKind> {
    trace!("confirm_totp_code_for_user({}, _)", user);
    if user.pending_otp_hash.is_none() || user.pending_backup_codes.len() == 0 {
        return Err(ErrorKind::IllegalRequest {
            message: String::from("No pending otp codes found"),
        });
    }

    // Calculate a TOTP for the pending secret.
    validate_totp(&user.pending_otp_hash, &request.totp_challenge)?;

    let mut db_user = user::get_by_id(&user.user_id, db).await?;
    db_user.otp_hash = db_user.pending_otp_hash.clone();
    db_user.otp_backup_codes = db_user.pending_backup_codes.clone();
    db_user.pending_otp_hash = None;
    db_user.pending_backup_codes = Vec::new();

    user::update_user(&db_user, db).await?;

    Ok(ConfirmTotpResponse { success: true })
}

/// Validates a totp challenge.
///
/// ## Args:
/// - user: The user to confirm the totp for.
/// - config: The application configuration.
/// - request: The request containing the confirmation code.
///
/// ## Returns:
/// A new token for the user if the challenge succeeds, or an error otherwise.
pub fn validate_totp_for_user(
    user: &User,
    config: &Config<'_>,
    request: &ValidateTotpRequest,
) -> Result<LoginResponse, ErrorKind> {
    validate_totp(&user.otp_hash, &request.totp_challenge)?;
    let token = jwt::create_otp_validated_jwt_token(&user, &config.encoding_key)?;
    Ok(LoginResponse {
        needs_otp: false,
        token: token,
    })
}
