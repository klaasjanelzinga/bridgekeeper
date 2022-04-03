#[macro_use]
extern crate log;

use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use jsonwebtoken::{decode, Algorithm, Validation};
use totp_lite::{totp, Sha512};

use bridgekeeper_api::jwt_models::{JwtClaims, JwtType};

use crate::common::api_calls::{
    confirm_totp, get_avatar, get_user, login, start_totp, validate_totp,
};
use crate::common::fixtures::{calculate_totp_value, create_and_login_user};

mod common;

/// Test the enabling of the TOTP on a user account.
/// - Create user and login.
/// - Start TOTP registration.
/// - Calculate a TOTP for the secret.
/// - Confirm the TOTP.
/// - Login user, should return a token but not a completed login sequence.
/// - Use the token on another endpoint than validate-otp. This is not possible.
/// - Validate the totp with the login token to create a new token.
#[tokio::test]
async fn test_totp_flow() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let login_data = create_and_login_user(&test_fixtures.app).await;

    // Validate the jwt claims in the token.
    let token_message = decode::<JwtClaims>(
        &login_data.access_token,
        &test_fixtures.config.decoding_key,
        &Validation::new(Algorithm::HS256),
    )
    .unwrap();
    assert_eq!(
        token_message.claims.token_type.to_string(),
        JwtType::AccessToken.to_string()
    );

    // start registration for a otp.
    let registration_response = start_totp(&test_fixtures.app, &login_data.access_token).await;
    assert!(registration_response.is_ok());
    let registration_response_data = registration_response.unwrap();

    // should generate backup codes
    assert_eq!(registration_response_data.backup_codes.len(), 6);
    assert_eq!(
        registration_response_data
            .backup_codes
            .get(0)
            .unwrap()
            .len(),
        8
    );

    // Confirm the totp with the calculated OTP.
    let confirm_response = confirm_totp(
        &test_fixtures.app,
        &login_data.access_token,
        &calculate_totp_value(&registration_response_data.secret),
    )
    .await
    .unwrap();
    assert_eq!(confirm_response.success, true);

    // second login with a required OTP challenge. Should Ok with a token that is only valid for OTP.
    let second_login = login(
        &test_fixtures.app,
        &login_data.email_address,
        &login_data.password,
    )
    .await
    .unwrap();
    assert_eq!(second_login.needs_otp, true);

    let token_second_login = decode::<JwtClaims>(
        &second_login.token,
        &test_fixtures.config.decoding_key,
        &Validation::new(Algorithm::HS256),
    )
    .unwrap();
    assert_eq!(
        token_second_login.claims.token_type.to_string(),
        JwtType::OneShotToken.to_string()
    );

    // Token cannot be used anywhere else since an otp challenge is required.
    let failing_api_call = get_user(&test_fixtures.app, &second_login.token).await;
    assert!(failing_api_call.is_err());
    assert_eq!(failing_api_call.err().unwrap(), StatusCode::UNAUTHORIZED);

    let failing_api_call = get_avatar(&test_fixtures.app, &second_login.token).await;
    assert!(failing_api_call.is_err());
    assert_eq!(failing_api_call.err().unwrap(), StatusCode::UNAUTHORIZED);

    // validate the otp
    let validated_totp_response = validate_totp(
        &test_fixtures.app,
        &login_data.access_token,
        &calculate_totp_value(&registration_response_data.secret),
    )
    .await
    .unwrap();
    assert_ne!(validated_totp_response.access_token, second_login.token);
    assert_ne!(validated_totp_response.refresh_token, second_login.token);

    // dissect the access token.
    let token_otp_validated_login = decode::<JwtClaims>(
        &validated_totp_response.access_token,
        &test_fixtures.config.decoding_key,
        &Validation::new(Algorithm::HS256),
    )
    .unwrap();
    assert_eq!(
        token_otp_validated_login.claims.token_type.to_string(),
        JwtType::AccessToken.to_string()
    );

    // dissect the refresh token.
    let token_otp_validated_login = decode::<JwtClaims>(
        &validated_totp_response.refresh_token,
        &test_fixtures.config.decoding_key,
        &Validation::new(Algorithm::HS256),
    )
    .unwrap();
    assert_eq!(
        token_otp_validated_login.claims.token_type.to_string(),
        JwtType::RefreshToken.to_string()
    );

    let api_call = get_user(&test_fixtures.app, &validated_totp_response.access_token).await;
    assert!(api_call.is_ok());

    ()
}

/// Test the totp with invalid codes
#[tokio::test]
async fn test_totp_flow_with_invalid_codes() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let login_data = create_and_login_user(&test_fixtures.app).await;

    let registration_response = start_totp(&test_fixtures.app, &login_data.access_token)
        .await
        .unwrap();

    // Calculate the correct TOTP for the secret.
    let seconds: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let correct_totp_value = totp::<Sha512>(registration_response.secret.as_bytes(), seconds);

    // Confirm with an invalid token.
    let response = confirm_totp(&test_fixtures.app, &login_data.access_token, "invalid").await;
    assert!(response.is_err());
    assert_eq!(response.err().unwrap(), StatusCode::UNAUTHORIZED);

    // Confirm the totp
    let confirm_response = confirm_totp(
        &test_fixtures.app,
        &login_data.access_token,
        &correct_totp_value,
    )
    .await
    .unwrap();

    assert_eq!(confirm_response.success, true);

    ()
}
