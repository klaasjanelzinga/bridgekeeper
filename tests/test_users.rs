use warp::http::{StatusCode};

use linkje_api::user_routes;

#[macro_use]
extern crate log;

mod common;

#[tokio::test]
async fn test_create_user() {
    let test_fixtures = common::setup().await;
    let route = user_routes(&test_fixtures.db);
    let user = common::user();
    common::empty_users_collection(&test_fixtures.db).await;

    // -- create user
    let create_response = warp::test::request()
        .method("POST")
        .path("/user")
        .json(&user)
        .reply(&route)
        .await;
    assert_eq!(create_response.status(), StatusCode::CREATED);

    // -- Validate response of create
    let mut response_user = common::deserialize_user(&create_response);
    assert_eq!(user.email_address, response_user.email_address);
    assert_eq!(user.first_name, response_user.first_name);
    assert_eq!(user.last_name, response_user.last_name);
    assert!(response_user.user_id.is_some());

    let created_user_id = response_user.user_id.unwrap();

    // Get the user by the user_id
    let response_get = warp::test::request()
        .method("GET")
        .path(format!("/user/{}", created_user_id).as_str())
        .reply(&route)
        .await;
    assert_eq!(response_get.status(), StatusCode::OK);

    // -- Validate the retrieved user.
    response_user = common::deserialize_user(&response_get);

    assert_eq!(user.email_address, response_user.email_address);
    assert_eq!(user.first_name, response_user.first_name);
    assert_eq!(user.last_name, response_user.last_name);
    assert!(response_user.user_id.is_some());

    // -- Get an user with an unknown user-id
    let response_get_unknown_email_address = warp::test::request()
        .method("GET")
        .path(format!("/user/unknown-{}", created_user_id).as_str())
        .reply(&route)
        .await;

    assert_eq!(
        response_get_unknown_email_address.status(),
        StatusCode::NOT_FOUND
    );

    ()
}

#[tokio::test]
async fn test_update_user() {
    let test_fixtures = common::setup().await;
    let route = user_routes(&test_fixtures.db);
    let user = common::user();
    common::empty_users_collection(&test_fixtures.db).await;

    // --- create user
    let create_response = warp::test::request()
        .method("POST")
        .path("/user")
        .json(&user)
        .reply(&route)
        .await;
    assert_eq!(create_response.status(), StatusCode::CREATED);

    let response_user = common::deserialize_user(&create_response);
    let created_user_id = response_user.user_id.unwrap();

    // --- get user
    let response_get = warp::test::request()
        .method("GET")
        .path(format!("/user/{}", created_user_id).as_str())
        .reply(&route)
        .await;
    assert_eq!(response_get.status(), StatusCode::OK);
    let mut user_to_update = common::deserialize_user(&response_get);
    user_to_update.first_name = format!("updated-{}", user_to_update.first_name);
    user_to_update.last_name = format!("updated-{}", user_to_update.last_name);
    user_to_update.email_address = format!("updated-{}", user_to_update.email_address);

    // --- update user
    let update_response = warp::test::request()
        .method("POST")
        .path("/user")
        .json(&user_to_update)
        .reply(&route)
        .await;
    assert_eq!(update_response.status(), StatusCode::OK);

    // --- get updated user
    let get_update_user_response = warp::test::request()
        .method("GET")
        .path(format!("/user/{}", created_user_id).as_str())
        .reply(&route)
        .await;
    assert_eq!(get_update_user_response.status(), StatusCode::OK);

    // -- Validate update user.
    let updated_user = common::deserialize_user(&get_update_user_response);
    assert_eq!(updated_user.first_name, format!("updated-{}", user.first_name));
    assert_eq!(updated_user.last_name, format!("updated-{}", user.last_name));
    assert_eq!(updated_user.email_address, format!("updated-{}", user.email_address));

    // -- Update a user that was not yet created.
    let mut new_user = common::user();
    new_user.user_id = Some(String::from("unknown-user-id"));
    // --- update user
    let update_response = warp::test::request()
        .method("POST")
        .path("/user")
        .json(&new_user)
        .reply(&route)
        .await;
    assert_eq!(update_response.status(), StatusCode::NOT_FOUND);


    ()
}
