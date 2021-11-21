#[macro_use]
extern crate log;

use crate::common::api_calls::{confirm_totp, start_totp};
use common::api_calls::{create_user, login};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_lite::{totp, Sha512};

mod common;

/// Test the enabling of the TOTP on a user account.
/// - Create user and login.
/// - Start TOTP registration.
/// - Calculate a TOTP for the secret.
/// - Confirm the TOTP.
#[rocket::async_test]
async fn test_totp_flow() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let create_user_request = common::create_user_request();
    let created_user = create_user(&test_fixtures.client, &create_user_request).await;
    let login_response = login(&test_fixtures.client, &create_user_request).await;

    let registration_response = start_totp(
        &test_fixtures.client,
        &created_user.user_id,
        &login_response.token,
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

    // Confirm the totp
    let confirm_response = confirm_totp(
        &test_fixtures.client,
        &created_user.user_id,
        &login_response.token,
        &totp_value,
    )
    .await;

    assert_eq!(confirm_response.success, true);

    ()
}
