use linkje_api::users::{GetUserResponse, UpdateUserRequest, CreateUserRequest};
use rocket::local::asynchronous::Client;
use rocket::http::Status;
use fake::faker::name::en::Name;
use fake::Fake;

#[macro_use]
extern crate log;

mod common;

// Create the user.
async fn create_user(client: &Client, create_user_request: &CreateUserRequest) -> GetUserResponse {
    let response = client.post("/user").json(&create_user_request).dispatch().await;
    assert_eq!(response.status(), Status::Ok); // TODO Created

    serde_json::from_str(&response.into_string().await.unwrap()).unwrap()
}

// Update  the user.
async fn update_user(client: &Client, update_request: &UpdateUserRequest) -> GetUserResponse {
    let response = client.post("/user").json(&update_request).dispatch().await;
    serde_json::from_str(&response.into_string().await.unwrap()).unwrap()
}

// Get user by the user_id.
async fn get_user(client: &Client, user_id: &String) -> GetUserResponse {
    let response = client.get(format!("/user/{}", user_id)).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    serde_json::from_str(&response.into_string().await.unwrap()).unwrap()
}

/// Test get user:
/// - Create the user.
/// - Get user with the user-id -> OK.
/// - Get user with an unknown user-id -> NOT_FOUND.
#[rocket::async_test]
async fn test_get_user() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let create_user_request = common::create_user_request();
    let created_user = create_user(&test_fixtures.client, &create_user_request).await;
    let existing_user_id = created_user.user_id;
    let get_user = get_user(&test_fixtures.client, &existing_user_id).await;

    assert_eq!(create_user_request.email_address, get_user.email_address);
    assert_eq!(create_user_request.first_name, get_user.first_name);
    assert_eq!(create_user_request.last_name, get_user.last_name);
    assert_eq!(create_user_request.display_name, get_user.display_name);
    assert!(get_user.user_id.len() > 1);

    let response = test_fixtures.client.get(format!("/user/unknown-{}", existing_user_id)).dispatch().await;
    assert_eq!(Status::NotFound, response.status());

    ()
}

/// Test create user:
/// - Create the user.
/// - Validate the response of the get.
/// - Get user with the user id should return the created user.
#[rocket::async_test]
async fn test_create_user() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let create_user_request = common::create_user_request();
    let created_user = create_user(&test_fixtures.client, &create_user_request).await;

    assert_eq!(create_user_request.email_address, created_user.email_address);
    assert_eq!(create_user_request.first_name, created_user.first_name);
    assert_eq!(create_user_request.last_name, created_user.last_name);
    assert_eq!(create_user_request.display_name, created_user.display_name);
    assert!(created_user.user_id.len() > 1);

    let get_result = get_user(&test_fixtures.client, &created_user.user_id).await;

    assert_eq!(created_user.email_address, get_result.email_address);

    ()
}

/// Test update user:
/// - Create the user.
/// - Get the user with the user id.
/// - Update the fields of the user and call update_user.
/// - Validate the response of the update request.
/// - Get the user, should contain the updated fields.
#[rocket::async_test]
async fn test_update_user() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let create_user_request = common::create_user_request();
    let created_user = create_user(&test_fixtures.client, &create_user_request).await;
    let user_id = created_user.user_id;

    let update_user_request = UpdateUserRequest {
        user_id: user_id.clone(),
        first_name: format!("updated-{}", created_user.first_name),
        last_name: format!("updated-{}", created_user.last_name),
        email_address: format!("updated-{}", created_user.email_address),
        display_name: Some(Name().fake()),
    };

    let updated_user = update_user(&test_fixtures.client, &update_user_request).await;
    assert_eq!(updated_user.first_name, update_user_request.first_name);
    assert_eq!(updated_user.last_name, update_user_request.last_name);
    assert_eq!(updated_user.email_address, update_user_request.email_address);
    assert_eq!(updated_user.display_name, update_user_request.display_name);

    let get_user_response = get_user(&test_fixtures.client, &updated_user.user_id).await;
    assert_eq!(get_user_response.first_name, update_user_request.first_name);
    assert_eq!(get_user_response.last_name, update_user_request.last_name);
    assert_eq!(get_user_response.email_address, update_user_request.email_address);
    assert_eq!(get_user_response.display_name, update_user_request.display_name);

    ()
}
//     // -- Validate update with a get.
//     let updated_user_with_get = get_user(&route, &created_user_id).await;
//     assert_eq!(updated_user_with_get.first_name, update_user_request.first_name);
//     assert_eq!(updated_user_with_get.last_name, update_user_request.last_name);
//     assert_eq!(updated_user_with_get.email_address, updated_user.email_address);
//     assert_eq!(updated_user_with_get.display_name, update_user_request.display_name);
//
//     // -- Update a user that was not yet created, just reuse the previous request with another id.
//     update_user_request.user_id = String::from("unknown-user-id");
//     // --- update user
//     let update_response = warp::test::request()
//         .method("PUT")
//         .path("/user")
//         .json(&update_user_request)
//         .reply(&route)
//         .await;
//     assert_eq!(update_response.status(), StatusCode::NOT_FOUND);
//
//     ()
// }
