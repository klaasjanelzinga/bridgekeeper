use warp::http::StatusCode;

use linkje_api::user_routes;
use linkje_api::users::User;
use warp::filters::BoxedFilter;
use warp::Reply;

#[macro_use]
extern crate log;

mod common;

// Create the user.
async fn create_user(route: &BoxedFilter<(impl Reply + 'static, )>, user: &User) -> User {
    let create_response = warp::test::request()
        .method("POST")
        .path("/user")
        .json(&user)
        .reply(route)
        .await;
    assert_eq!(create_response.status(), StatusCode::CREATED);

    common::deserialize_user(&create_response)
}

// Update  the user.
async fn update_user(route: &BoxedFilter<(impl Reply + 'static, )>, user: &User) -> User {
    let update_response = warp::test::request()
        .method("POST")
        .path("/user")
        .json(&user)
        .reply(route)
        .await;
    assert_eq!(update_response.status(), StatusCode::OK);

    common::deserialize_user(&update_response)
}

// Get user by the user_id.
async fn get_user(route: &BoxedFilter<(impl Reply + 'static, )>, user_id: &String) -> User {
    let response_get = warp::test::request()
        .method("GET")
        .path(format!("/user/{}", user_id).as_str())
        .reply(route)
        .await;
    assert_eq!(response_get.status(), StatusCode::OK);

    common::deserialize_user(&response_get)
}

#[tokio::test]
async fn test_create_user() {
    let test_fixtures = common::setup().await;
    let route = user_routes(&test_fixtures.db);
    let user = common::user();
    common::empty_users_collection(&test_fixtures.db).await;

    let mut response_user = create_user(&route, &user).await;

    assert_eq!(user.email_address, response_user.email_address);
    assert_eq!(user.first_name, response_user.first_name);
    assert_eq!(user.last_name, response_user.last_name);
    assert!(response_user.user_id.is_some());

    let created_user_id = response_user.user_id.unwrap();

    // -- Validate the retrieved user.
    response_user = get_user(&route, &created_user_id).await;
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

    // -- create a user
    let response_user = create_user(&route, &user).await;
    let created_user_id = response_user.user_id.unwrap();

    // -- get the created a user
    let mut user_to_update = get_user(&route, &created_user_id).await;
    user_to_update.first_name = format!("updated-{}", user_to_update.first_name);
    user_to_update.last_name = format!("updated-{}", user_to_update.last_name);
    user_to_update.email_address = format!("updated-{}", user_to_update.email_address);

    // -- Validate update user response.
    let updated_user = update_user(&route, &user_to_update).await;
    assert_eq!(updated_user.first_name, format!("updated-{}", user.first_name));
    assert_eq!(updated_user.last_name, format!("updated-{}", user.last_name));
    assert_eq!(updated_user.email_address, format!("updated-{}", user.email_address));

    // -- Validate update with a get.
    let updated_user_with_get = get_user(&route, &created_user_id).await;
    assert_eq!(updated_user_with_get.first_name, format!("updated-{}", user.first_name));
    assert_eq!(updated_user_with_get.last_name, format!("updated-{}", user.last_name));
    assert_eq!(updated_user_with_get.email_address, format!("updated-{}", user.email_address));

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
