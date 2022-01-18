#[macro_use]
extern crate log;

use crate::common::api_calls::get_user;
use axum::http;

use crate::common::fixtures::create_and_login_user;
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

    let result = get_user(&test_fixtures.app, &regular_user.token).await;
    assert!(result.is_ok());

    let invalid_headers = [
        format!("Bearer-{}", regular_user.token),
        format!("Bearer {}=", regular_user.token),
        "Bearer ".to_string(),
        "Bἐarἐr ὀ".to_string(),
        format!("123123-{}", regular_user.token),
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
