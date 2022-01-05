#[macro_use]
extern crate log;

use crate::common::api_calls::{
    create_and_login_user, create_or_update_avatar, delete_avatar, get_avatar,
};
use bridgekeeper_api::avatar::UpdateAvatarRequest;
use fake::faker::lorem::en::Paragraphs;
use fake::Fake;
use rocket::http::Status;

mod common;

/// Test the following avatar flow:
/// - get avatar, while there is none. This should be NotFound.
/// - create an avatar.
/// - get avatar should return the created avatar.
/// - next update the avatar.
/// - get avatar should return the updated avatar.
/// - delete the avatar.
/// - get avatar should return the NotFound.
#[rocket::async_test]
async fn test_get_avatar_and_create() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let login_data = create_and_login_user(&test_fixtures.client).await;

    // Get while no avatar is available. Should return Not found
    let response = get_avatar(&test_fixtures.client, &login_data.token).await;
    assert!(response.is_err());
    assert_eq!(response.err().unwrap(), Status::NotFound);

    // Create the avatar
    let paragraph: Vec<String> = Paragraphs(1..2).fake();
    let update_avatar_request = UpdateAvatarRequest {
        image_base64: base64::encode(paragraph.first().unwrap()),
    };
    let response = create_or_update_avatar(
        &test_fixtures.client,
        &login_data.token,
        &update_avatar_request,
    )
    .await;
    assert!(response.is_ok());

    // The get should now return an avatar.
    let response = get_avatar(&test_fixtures.client, &login_data.token)
        .await
        .unwrap();
    assert_eq!(response.user_id, login_data.user_id);
    assert_ne!(response.avatar_base64, "new-avatar-data");

    // Update the avatar to "new-avatar-data"
    let update_avatar_request = UpdateAvatarRequest {
        image_base64: String::from("new-avatar-data"),
    };
    let response = create_or_update_avatar(
        &test_fixtures.client,
        &login_data.token,
        &update_avatar_request,
    )
    .await;
    assert!(response.is_ok());

    // The get should now return the avatar "new-avatar-data"
    let response = get_avatar(&test_fixtures.client, &login_data.token)
        .await
        .unwrap();
    assert_eq!(response.user_id, login_data.user_id);
    assert_eq!(response.avatar_base64, "new-avatar-data");

    // Delete the avatar.
    let response = delete_avatar(&test_fixtures.client, &login_data.token).await;
    assert!(response.is_ok());

    let response = get_avatar(&test_fixtures.client, &login_data.token).await;
    assert!(response.is_err());
    assert_eq!(response.err().unwrap(), Status::NotFound);

    ()
}
