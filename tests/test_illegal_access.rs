#[macro_use]
extern crate log;

use crate::common::api_calls::{
    confirm_totp, create_and_login_user, create_or_update_avatar, delete_avatar, get_avatar,
    start_totp,
};
use bridgekeeper_api::avatar::UpdateAvatarRequest;
use fake::faker::lorem::en::Paragraphs;
use fake::Fake;
use rocket::http::Status;
use std::time::{SystemTime, UNIX_EPOCH};
use totp_lite::{totp, Sha512};

mod common;

/// Test illegal access in the avatar module.
///
/// ## Calls:
/// - get_avatar
/// - create_avatar
/// - delete_avarar
#[rocket::async_test]
async fn test_get_avatar_illegal_access() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let login_data = create_and_login_user(&test_fixtures.client).await;
    let login_data_2 = create_and_login_user(&test_fixtures.client).await;

    // get_avatar - Failing call -> Forbidden.
    let response = get_avatar(
        &test_fixtures.client,
        &login_data.user_id,
        &login_data_2.token,
    )
    .await;
    assert!(response.is_err());
    assert_eq!(response.err().unwrap(), Status::Forbidden);

    // get_avatar - Correct call -> NotFound.
    let response = get_avatar(
        &test_fixtures.client,
        &login_data.user_id,
        &login_data.token,
    )
    .await;
    assert!(response.is_err());
    assert_eq!(response.err().unwrap(), Status::NotFound);

    // create_avatar - Failing Call -> Forbidden
    let paragraph: Vec<String> = Paragraphs(1..2).fake();
    let update_avatar_request = UpdateAvatarRequest {
        image_base64: base64::encode(paragraph.first().unwrap()),
    };
    let response = create_or_update_avatar(
        &test_fixtures.client,
        &login_data.user_id,
        &login_data_2.token,
        &update_avatar_request,
    )
    .await;
    assert!(response.is_err());
    assert_eq!(response.err().unwrap(), Status::Forbidden);

    // create avatar - Valid call -> Ok
    let response = create_or_update_avatar(
        &test_fixtures.client,
        &login_data.user_id,
        &login_data.token,
        &update_avatar_request,
    )
    .await;
    assert!(response.is_ok());

    // delete avatar - Failing Call -> Forbidden
    let response = delete_avatar(
        &test_fixtures.client,
        &login_data.user_id,
        &login_data_2.token,
    )
    .await;
    assert!(response.is_err());
    assert_eq!(response.err().unwrap(), Status::Forbidden);

    // delete avatar - Correct Call -> Ok
    let response = delete_avatar(
        &test_fixtures.client,
        &login_data.user_id,
        &login_data.token,
    )
    .await;
    assert!(response.is_ok());

    ()
}

/// Test the totp flow with invalid tokens.
/// - start_totp call - should illegal access.
/// - confirm the totp - should illegal access.
#[rocket::async_test]
async fn test_totp_flow_illegal_access() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let login_data = create_and_login_user(&test_fixtures.client).await;
    let login_data_2 = create_and_login_user(&test_fixtures.client).await;

    let registration_response = start_totp(
        &test_fixtures.client,
        &login_data.user_id,
        &login_data_2.token,
    )
    .await;
    assert!(registration_response.is_err());
    assert_eq!(registration_response.err().unwrap(), Status::Forbidden);

    // correct call -> Should start the totp flow
    let registration_response = start_totp(
        &test_fixtures.client,
        &login_data.user_id,
        &login_data.token,
    )
    .await
    .unwrap();

    // Calculate a TOTP for the secret.
    let seconds: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let totp_value = totp::<Sha512>(registration_response.secret.as_bytes(), seconds);

    // Failed call Confirm the totp with the calculated OTP.
    let confirm_response = confirm_totp(
        &test_fixtures.client,
        &login_data.user_id,
        &login_data_2.token,
        &totp_value,
    )
    .await;
    assert!(confirm_response.is_err());
    assert_eq!(confirm_response.err().unwrap(), Status::Forbidden);

    // Correct call
    let confirm_result = confirm_totp(
        &test_fixtures.client,
        &login_data.user_id,
        &login_data.token,
        &totp_value,
    )
    .await;
    assert!(confirm_result.is_ok());

    ()
}
