#[macro_use]
extern crate log;

use crate::common::api_calls::{confirm_totp, create_and_login_user, start_totp};
use common::api_calls::{login};
use std::time::{SystemTime, UNIX_EPOCH};
use rocket::http::{Header, Status};
use totp_lite::{totp, Sha512};
use linkje_api::users::ValidateTotpRequest;

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

    let registration_response = start_totp(
        &test_fixtures.client,
        &login_data.user_id,
        &login_data.token,
    )
    .await;

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

    // login with a required OTP challenge. Should Ok with a token that is only valid for OTP.
    let login_response = login(&test_fixtures.client, &login_data.email_address, &login_data.password).await;
    assert_eq!(login_response.unwrap().needs_otp, true);

    // Token cannot be used anywhere else
    let response = test_fixtures
        .client
        .get(format!("/user/{}", login_data.user_id))
        .header(Header::new("Authorization", format!("Bearer {}", login_data.token)))
        .dispatch()
        .await;
    assert_eq!(Status::Forbidden, response.status()); // token requires otp

    // validate the otp
    let validate_otp_response = validate_otp(&test_fixtures.client, &login_data.token, &totp_value).await;
    assert_ne!(validate_otp_response.token, login_data.token)

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
    let response = test_fixtures.client
        .post(format!("/user/{}/confirm-totp-registration", login_data.user_id))
        .json(&validate_totp_request)
        .header(Header::new("Authorization", format!("Bearer {}", login_data.token)))
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
