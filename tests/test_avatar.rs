#[macro_use]
extern crate log;

use axum::http::StatusCode;
use fake::faker::lorem::en::Paragraphs;
use fake::Fake;

use bridgekeeper_api::avatar_models::UpdateAvatarRequest;

use crate::common::api_calls::{create_or_update_avatar, delete_avatar, get_avatar};
use crate::common::fixtures::{
    create_and_login_user, create_and_login_user_with_totp,
    create_and_login_user_with_totp_not_totp_verified,
};

mod common;

/// Test the following avatar flow:
/// - get avatar, while there is none. This should be NotFound.
/// - create an avatar.
/// - get avatar should return the created avatar.
/// - next update the avatar.
/// - get avatar should return the updated avatar.
/// - delete the avatar.
/// - get avatar should return the NotFound.
#[tokio::test]
async fn test_get_avatar_and_create() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let login_data = create_and_login_user(&test_fixtures.app).await;

    // Get while no avatar is available. Should return Not found
    let response = get_avatar(&test_fixtures.app, &login_data.access_token).await;
    assert!(response.is_err());
    assert_eq!(response.err().unwrap(), StatusCode::NOT_FOUND);

    // Create the avatar
    let paragraph: Vec<String> = Paragraphs(1..2).fake();
    let update_avatar_request = UpdateAvatarRequest {
        image_base64: base64::encode(paragraph.first().unwrap()),
    };
    let response = create_or_update_avatar(
        &test_fixtures.app,
        &login_data.access_token,
        &update_avatar_request,
    )
    .await;
    assert!(response.is_ok());

    // The get should now return an avatar.
    let response = get_avatar(&test_fixtures.app, &login_data.access_token)
        .await
        .unwrap();
    assert_eq!(response.user_id, login_data.user_id);
    assert_ne!(response.avatar_base64, "new-avatar-data");

    // Update the avatar to "new-avatar-data"
    let update_avatar_request = UpdateAvatarRequest {
        image_base64: String::from("new-avatar-data"),
    };
    let response = create_or_update_avatar(
        &test_fixtures.app,
        &login_data.access_token,
        &update_avatar_request,
    )
    .await;
    assert!(response.is_ok());

    // The get should now return the avatar "new-avatar-data"
    let response = get_avatar(&test_fixtures.app, &login_data.access_token)
        .await
        .unwrap();
    assert_eq!(response.user_id, login_data.user_id);
    assert_eq!(response.avatar_base64, "new-avatar-data");

    // Delete the avatar.
    let response = delete_avatar(&test_fixtures.app, &login_data.access_token).await;
    assert!(response.is_ok());

    let response = get_avatar(&test_fixtures.app, &login_data.access_token).await;
    assert!(response.is_err());
    assert_eq!(response.err().unwrap(), StatusCode::NOT_FOUND);

    ()
}

/// Test the authentication for the avatar calls.
/// - Access token should work.
/// - Oneshot and refresh tokens should not work.
#[tokio::test]
async fn test_create_avatar_authentication() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let regular_user = create_and_login_user(&test_fixtures.app).await;
    let totp_user = create_and_login_user_with_totp(&test_fixtures.app).await;
    let one_shot_token = create_and_login_user_with_totp_not_totp_verified(&test_fixtures.app)
        .await
        .access_token;

    let paragraph: Vec<String> = Paragraphs(1..2).fake();
    let update_avatar_request = UpdateAvatarRequest {
        image_base64: base64::encode(paragraph.first().unwrap()),
    };
    assert!(create_or_update_avatar(
        &test_fixtures.app,
        &regular_user.access_token,
        &update_avatar_request,
    )
    .await
    .is_ok());
    assert!(create_or_update_avatar(
        &test_fixtures.app,
        &totp_user.access_token,
        &update_avatar_request,
    )
    .await
    .is_ok());

    // refresh and one_shot should not work
    assert!(create_or_update_avatar(
        &test_fixtures.app,
        &totp_user.refresh_token.unwrap(),
        &update_avatar_request,
    )
    .await
    .is_err());
    assert!(
        create_or_update_avatar(&test_fixtures.app, &one_shot_token, &update_avatar_request,)
            .await
            .is_err()
    );
}

/// Test the authentication for the get_avatar function.
#[tokio::test]
async fn test_get_avatar_authentication() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let regular_user = create_and_login_user(&test_fixtures.app).await;
    let totp_user = create_and_login_user_with_totp(&test_fixtures.app).await;
    let one_shot_token = create_and_login_user_with_totp_not_totp_verified(&test_fixtures.app)
        .await
        .access_token;

    assert_eq!(
        get_avatar(&test_fixtures.app, &regular_user.access_token)
            .await
            .err()
            .unwrap(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get_avatar(&test_fixtures.app, &totp_user.access_token)
            .await
            .err()
            .unwrap(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get_avatar(&test_fixtures.app, &totp_user.refresh_token.unwrap())
            .await
            .err()
            .unwrap(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        get_avatar(&test_fixtures.app, &one_shot_token)
            .await
            .err()
            .unwrap(),
        StatusCode::UNAUTHORIZED
    );
}

/// Test authentication on the delete avatar function.
#[tokio::test]
async fn test_delete_avatar_authentication() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let regular_user = create_and_login_user(&test_fixtures.app).await;
    let totp_user = create_and_login_user_with_totp(&test_fixtures.app).await;
    let one_shot_token = create_and_login_user_with_totp_not_totp_verified(&test_fixtures.app)
        .await
        .access_token;

    assert_eq!(
        delete_avatar(&test_fixtures.app, &regular_user.access_token)
            .await
            .err()
            .unwrap(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        delete_avatar(&test_fixtures.app, &totp_user.access_token)
            .await
            .err()
            .unwrap(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        delete_avatar(&test_fixtures.app, &totp_user.refresh_token.unwrap())
            .await
            .err()
            .unwrap(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        delete_avatar(&test_fixtures.app, &one_shot_token)
            .await
            .err()
            .unwrap(),
        StatusCode::UNAUTHORIZED
    );
}
