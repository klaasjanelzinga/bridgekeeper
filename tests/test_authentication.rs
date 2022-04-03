#[macro_use]
extern crate log;

use crate::common::api_calls::get_user;
use axum::http;

use crate::common::fixtures::{
    create_and_login_user, create_and_login_user_with_totp,
    create_and_login_user_with_totp_not_totp_verified,
};
use axum::http::{Request, StatusCode};
use hyper::Body;
use mongodb::bson::doc;
use tower::ServiceExt;

mod common;

/// Test authentication.
/// - request with regular token should work.
/// - request with several invalid authorization headers should give UNAUTHORIZED.
/// - request with missing authorization header should give UNAUTHORIZED.
#[tokio::test]
async fn test_invalid_authentication_header() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let regular_user = create_and_login_user(&test_fixtures.app).await;

    let result = get_user(&test_fixtures.app, &regular_user.access_token).await;
    assert!(result.is_ok());

    let invalid_headers = [
        format!("Bearer-{}", regular_user.access_token),
        format!("Bearer {}=", regular_user.access_token),
        "Bearer ".to_string(),
        "Bἐarἐr ὀ".to_string(),
        format!("123123-{}", regular_user.access_token),
        "".to_string(),
        "\tx123".to_string(),
    ];
    for invalid_header in invalid_headers {
        let response = test_fixtures
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/user")
                    .header(
                        http::header::AUTHORIZATION,
                        format!("Bearer-{}", invalid_header),
                    )
                    .method(http::Method::GET)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let response = test_fixtures
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/user")
                .method(http::Method::GET)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    ()
}

/// Test different tokens with different purposes.
/// - Login a regular user (with a bearer token), a totp user (with refresh and bearer) and totp.
/// - Use different tokens in different scenarios.
#[tokio::test]
async fn test_token_types() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let regular_user = create_and_login_user(&test_fixtures.app).await;
    let totp_user = create_and_login_user_with_totp(&test_fixtures.app).await;
    let totp_user_without_totp_validation =
        create_and_login_user_with_totp_not_totp_verified(&test_fixtures.app).await;

    // bearer token should work on resources that require the access token.
    get_user(&test_fixtures.app, &regular_user.access_token)
        .await
        .unwrap();
    get_user(&test_fixtures.app, &totp_user.access_token)
        .await
        .unwrap();

    // refresh token on a resource should not work. => UNAUTHORIZED
    assert_eq!(
        get_user(&test_fixtures.app, &totp_user.refresh_token.unwrap())
            .await
            .err(),
        Some(StatusCode::UNAUTHORIZED)
    );

    // one shot tokens on a resource should not work. => UNAUTHORIZED
    assert_eq!(
        get_user(
            &test_fixtures.app,
            &totp_user_without_totp_validation.access_token
        )
        .await
        .err(),
        Some(StatusCode::UNAUTHORIZED)
    );

    ()
}
