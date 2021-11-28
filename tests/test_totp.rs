#[macro_use]
extern crate log;

use crate::common::api_calls::{
    confirm_totp, create_and_login_user, get_user, start_totp, validate_totp,
};
use common::api_calls::login;
use jsonwebtoken::{decode, Algorithm, Validation};
use linkje_api::jwt::JwtClaims;
use linkje_api::users::ValidateTotpRequest;
use rocket::http::{Header, Status};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_lite::{totp, Sha512};

mod common;

/// Test the enabling of the TOTP on a user account.
/// - Create user and login.
/// - Start TOTP registration.
/// - Calculate a TOTP for the secret.
/// - Confirm the TOTP.
/// - Login user, should return a token but not a completed login sequence.
/// - Use the token on another endpoint than validate-otp. This is not possible.
/// - Validate the totp with the login token to create a new token.
#[rocket::async_test]
async fn test_totp_flow() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let login_data = create_and_login_user(&test_fixtures.client).await;

    // Validate the jwt claims in the token.
    let token_message = decode::<JwtClaims>(
        &login_data.token,
        &test_fixtures.config.decoding_key,
        &Validation::new(Algorithm::HS256),
    )
    .unwrap();
    assert_eq!(token_message.claims.requires_otp_challenge, false);
    assert_eq!(token_message.claims.otp_is_validated, false);

    // start registration for a otp.
    let registration_response = start_totp(
        &test_fixtures.client,
        &login_data.user_id,
        &login_data.token,
    )
    .await;

    // should generate backup codes
    assert_eq!(registration_response.backup_codes.len(), 6);
    assert_eq!(registration_response.backup_codes.get(0).unwrap().len(), 8);

    // Calculate a TOTP for the secret.
    let seconds: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let totp_value = totp::<Sha512>(registration_response.secret.as_bytes(), seconds);

    // Confirm the totp with the calculated OTP.
    let confirm_response = confirm_totp(
        &test_fixtures.client,
        &login_data.user_id,
        &login_data.token,
        &totp_value,
    )
    .await;
    assert_eq!(confirm_response.success, true);

    // second login with a required OTP challenge. Should Ok with a token that is only valid for OTP.
    let second_login = login(
        &test_fixtures.client,
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
    assert_eq!(token_second_login.claims.requires_otp_challenge, true);
    assert_eq!(token_second_login.claims.otp_is_validated, false);

    // Token cannot be used anywhere else since an otp challenge is required.
    let failing_api_call = get_user(
        &test_fixtures.client,
        &login_data.user_id,
        &second_login.token,
    )
    .await;
    assert!(failing_api_call.is_err());
    assert_eq!(failing_api_call.err().unwrap(), Status::Forbidden);

    // validate the otp
    let validated_totp_response = validate_totp(
        &test_fixtures.client,
        &login_data.user_id,
        &login_data.token,
        &totp_value,
    )
    .await;
    assert_ne!(validated_totp_response.token, second_login.token);

    // dissect the token.
    let token_otp_validated_login = decode::<JwtClaims>(
        &validated_totp_response.token,
        &test_fixtures.config.decoding_key,
        &Validation::new(Algorithm::HS256),
    )
    .unwrap();
    assert_eq!(
        token_otp_validated_login.claims.requires_otp_challenge,
        false
    );
    assert_eq!(token_otp_validated_login.claims.otp_is_validated, true);

    let api_call = get_user(
        &test_fixtures.client,
        &login_data.user_id,
        &validated_totp_response.token,
    )
    .await;
    assert!(api_call.is_ok());

    ()
}

/// Test the totp with invalid codes
#[rocket::async_test]
async fn test_totp_flow_with_invalid_codes() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let login_data = create_and_login_user(&test_fixtures.client).await;

    let registration_response = start_totp(
        &test_fixtures.client,
        &login_data.user_id,
        &login_data.token,
    )
    .await;

    // Calculate the correct TOTP for the secret.
    let seconds: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let correct_totp_value = totp::<Sha512>(registration_response.secret.as_bytes(), seconds);

    // Confirm with an invalid token.
    let validate_totp_request = ValidateTotpRequest {
        totp_challenge: String::from("invalid"),
    };
    let response = test_fixtures
        .client
        .post(format!(
            "/user/{}/confirm-totp-registration",
            login_data.user_id
        ))
        .json(&validate_totp_request)
        .header(Header::new(
            "Authorization",
            format!("Bearer {}", login_data.token),
        ))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Unauthorized);

    // Confirm the totp
    let confirm_response = confirm_totp(
        &test_fixtures.client,
        &login_data.user_id,
        &login_data.token,
        &correct_totp_value,
    )
    .await;

    assert_eq!(confirm_response.success, true);

    ()
}
