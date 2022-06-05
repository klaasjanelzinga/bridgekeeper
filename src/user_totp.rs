use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE32;
use mongodb::Database;
use totp_lite::{totp_custom, Sha1};

use crate::config::Config;
use crate::errors::ErrorKind;
use crate::user_models::{LoginWithOtpResponse, User};
use crate::user_totp_models::{
    StartTotpRegistrationResult, ValidateTotpRequest, ValidateTotpWithBackupCodeRequest,
};
use crate::{jwt, user, util};

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
    let secret_encoded = BASE32.encode(secret.as_bytes());

    let backup_codes = [
        util::random_string(8),
        util::random_string(8),
        util::random_string(8),
        util::random_string(8),
        util::random_string(8),
        util::random_string(8),
    ]
    .to_vec();
    // Note: period, algorithm, digits ignored by google authenticator.
    let uri = format!(
        "otpauth://totp/{}?secret={}&issuer={}&digits=6&algorithm=sha1&period=30",
        user.email_address, secret_encoded, user.for_application,
    );

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
            let totp_value = totp_custom::<Sha1>(30, 6, otp.as_bytes(), seconds);
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
) -> Result<bool, ErrorKind> {
    trace!("confirm_totp_code_for_user({}, _)", user);
    if user.pending_otp_hash.is_none() || user.pending_backup_codes.is_empty() {
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

    Ok(true)
}

/// Validates a totp challenge.
///
/// ## Args:
/// - user: The user to confirm the totp for.
/// - config: The application configuration.
/// - request: The request containing the confirmation code.
/// - db: Valid db mongo instance.
///
/// ## Returns:
/// A new token set for the user if the challenge succeeds, or an error otherwise.
pub async fn validate_totp_for_user(
    user: &User,
    config: &Config<'_>,
    request: &ValidateTotpRequest,
    db: &Database,
) -> Result<LoginWithOtpResponse, ErrorKind> {
    validate_totp(&user.otp_hash, &request.totp_challenge)?;
    let mut db_user = user::get_by_id(&user.user_id, db).await?;
    let access_token = jwt::create_access_token(user, &config.encoding_key)?;
    let refresh_token = jwt::create_refresh_token(user, &config.encoding_key)?;

    db_user.refresh_token_id = Some(refresh_token.token_id);
    db_user.access_token_id = Some(access_token.token_id);
    user::update_user(&db_user, db).await?;

    Ok(LoginWithOtpResponse {
        access_token: access_token.token,
        refresh_token: refresh_token.token,
    })
}

/// Validates a totp challenge by using a backup code.
///
/// ## Args:
/// - user: The user to confirm the totp for.
/// - config: The application configuration.
/// - request: The request containing the backup code.
/// - db: Valid db mongo instance.
///
/// ## Returns:
/// A new token set for the user if the challenge succeeds, or an error otherwise.
pub async fn validate_totp_with_backup_code_for_user(
    user: &User,
    config: &Config<'_>,
    request: &ValidateTotpWithBackupCodeRequest,
    db: &Database,
) -> Result<LoginWithOtpResponse, ErrorKind> {
    let valid_code = user.otp_backup_codes.contains(&request.backup_code);
    if !valid_code {
        return Err(ErrorKind::NotAuthorized);
    }
    let mut db_user = user::get_by_id(&user.user_id, db).await?;

    let index = db_user
        .otp_backup_codes
        .iter()
        .position(|x| x == &request.backup_code)
        .unwrap();
    db_user.otp_backup_codes.remove(index);

    let access_token = jwt::create_access_token(user, &config.encoding_key)?;
    let refresh_token = jwt::create_refresh_token(user, &config.encoding_key)?;

    db_user.refresh_token_id = Some(refresh_token.token_id);
    db_user.access_token_id = Some(access_token.token_id);
    user::update_user(&db_user, db).await?;

    Ok(LoginWithOtpResponse {
        access_token: access_token.token,
        refresh_token: refresh_token.token,
    })
}
