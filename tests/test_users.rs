use fake::faker::internet::en::SafeEmail;
use fake::faker::name::en::{FirstName, LastName};
use fake::Fake;
use warp::http::StatusCode;

use linkje_api::user_routes;
use linkje_api::users::User;

mod common;

#[tokio::test]
async fn test_create_user() {
    let test_fixtures = common::setup().await;
    let route = user_routes(test_fixtures.db);

    let user = User {
        user_id: None,
        email_address: SafeEmail().fake::<String>(),
        first_name: FirstName().fake(),
        last_name: LastName().fake(),
    };

    let create_response = warp::test::request()
        .method("POST")
        .path("/user")
        .json(&user)
        .reply(&route)
        .await;
    assert_eq!(create_response.status(), StatusCode::CREATED);
    log::trace!("User {} created", user);

    let response_get = warp::test::request()
        .method("GET")
        .path(format!("/user/{}", user.email_address).as_str())
        .reply(&route)
        .await;
    assert_eq!(response_get.status(), StatusCode::OK);

    let str_response = String::from_utf8(response_get.body().to_vec()).unwrap();
    let response_user: User = serde_json::from_str(&str_response).unwrap();

    assert_eq!(user.email_address, response_user.email_address);
    assert_eq!(user.first_name, response_user.first_name);
    assert_eq!(user.last_name, response_user.last_name);
}
