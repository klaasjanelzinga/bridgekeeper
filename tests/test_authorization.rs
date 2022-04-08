#[macro_use]
extern crate log;

use crate::common::api_calls::{
    add_authorization, create_jwt_api, delete_jwt_api_token, get_user, is_authorized,
    is_jwt_api_valid,
};
use crate::common::fixtures::{create_and_login_admin_user, create_and_login_user};
use axum::http::StatusCode;
use bridgekeeper_api::authorization_models::{AddAuthorizationRequest, IsAuthorizedRequest};
use bridgekeeper_api::user_models::User;
use mongodb::bson::doc;

mod common;

/// Test the authorization process.
///
/// - Create an admin user (someone with privileges on bridgekeeper).
/// - Create a regular user.
/// - The admin user gives the regular user some privileges and these are validated.
#[tokio::test]
async fn test_authorization() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let regular_user = create_and_login_user(&test_fixtures.app).await;
    let admin_user = create_and_login_admin_user(&test_fixtures.app, &test_fixtures.db).await;

    // add authorization through api for regular user. Can only:
    // - GET /netherlands/gro.*
    // - POST /germany/berlin
    // - DELETE|PUT /belgium/ant.*
    let regular_priviliges = [
        AddAuthorizationRequest {
            for_user_id: regular_user.user_id.clone(),
            application: String::from("news"),
            method_regex: String::from("GET"),
            uri_regex: String::from("/netherlands/gro.*"),
        },
        AddAuthorizationRequest {
            for_user_id: regular_user.user_id.clone(),
            application: String::from("news"),
            method_regex: String::from("POST"),
            uri_regex: String::from("/germany/berlin"),
        },
        AddAuthorizationRequest {
            for_user_id: regular_user.user_id.clone(),
            application: String::from("news"),
            method_regex: String::from("(DELETE)|(PUT)"),
            uri_regex: String::from("/belgium/ant.*"),
        },
    ];
    for regular_privilege in regular_priviliges {
        let auth_result = add_authorization(
            &test_fixtures.app,
            &admin_user.access_token,
            &regular_privilege,
        )
        .await;
        assert!(auth_result.is_ok());
    }

    let valid_authentications = [
        IsAuthorizedRequest {
            method: "GET".to_string(),
            application: "news".to_string(),
            uri: "/netherlands/groningen/hello".to_string(),
        },
        IsAuthorizedRequest {
            method: "GET".to_string(),
            application: "news".to_string(),
            uri: "/netherlands/groenloo".to_string(),
        },
        IsAuthorizedRequest {
            method: "POST".to_string(),
            application: "news".to_string(),
            uri: "/germany/berlin".to_string(),
        },
        IsAuthorizedRequest {
            method: "DELETE".to_string(),
            application: "news".to_string(),
            uri: "/belgium/antwerp".to_string(),
        },
        IsAuthorizedRequest {
            method: "PUT".to_string(),
            application: "news".to_string(),
            uri: "/belgium/antwerp-city".to_string(),
        },
    ];
    for valid in valid_authentications {
        let is_authorized_response =
            is_authorized(&test_fixtures.app, &regular_user.access_token, &valid).await;
        assert!(is_authorized_response.is_ok());
    }

    let invalids = [
        IsAuthorizedRequest {
            method: "GET".to_string(),
            application: "no-news".to_string(),
            uri: "/netherlands/groningen/hello".to_string(),
        },
        IsAuthorizedRequest {
            method: "GET".to_string(),
            application: "news".to_string(),
            uri: "/netherlands/drenthe".to_string(),
        },
        IsAuthorizedRequest {
            method: "POST".to_string(),
            application: "news".to_string(),
            uri: "/netherlands/groningen".to_string(),
        },
        IsAuthorizedRequest {
            method: "PUT".to_string(),
            application: "news".to_string(),
            uri: "/germany/berlin".to_string(),
        },
        IsAuthorizedRequest {
            method: "GET".to_string(),
            application: "news".to_string(),
            uri: "/germany/berlin".to_string(),
        },
        IsAuthorizedRequest {
            method: "GET".to_string(),
            application: "news".to_string(),
            uri: "/belgium/antwerp".to_string(),
        },
    ];
    for invalid in invalids {
        let is_authorized_response =
            is_authorized(&test_fixtures.app, &regular_user.access_token, &invalid).await;
        assert!(is_authorized_response.is_err());
        assert_eq!(
            is_authorized_response.err().unwrap(),
            StatusCode::UNAUTHORIZED
        );
    }

    ()
}

/// A user cannot add authorization for himself:
/// - Create a regular user and an admin user.
/// - Regular user cannot give privileges.
/// - Admin user can give privileges.
#[tokio::test]
async fn test_add_authorization() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let regular_user = create_and_login_user(&test_fixtures.app).await;
    let admin_user = create_and_login_admin_user(&test_fixtures.app, &test_fixtures.db).await;

    // regular user cannot give privileges
    let result = add_authorization(
        &test_fixtures.app,
        &regular_user.access_token,
        &AddAuthorizationRequest {
            for_user_id: regular_user.user_id.clone(),
            application: "bridgekeeper".to_string(),
            uri_regex: ".*".to_string(),
            method_regex: ".*".to_string(),
        },
    )
    .await;
    assert!(result.is_err());
    assert_eq!(result.err().unwrap(), StatusCode::UNAUTHORIZED);

    // admin_user can.
    let result = add_authorization(
        &test_fixtures.app,
        &admin_user.access_token,
        &AddAuthorizationRequest {
            for_user_id: admin_user.user_id.clone(),
            application: "bridgekeeper".to_string(),
            uri_regex: ".*".to_string(),
            method_regex: ".*".to_string(),
        },
    )
    .await;
    assert!(result.is_ok());

    ()
}

/// Test the jwt-api token flow:
/// - Create a jwt-api token for a certain api.
/// - Check if the is_authorized works for the jwt-api-token.
/// - Delete the jwt-api token for the api.
/// - The is_authorized returns Not-authorized.
#[tokio::test]
async fn test_jwt_api_token_regular_flow() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let regular_user = create_and_login_user(&test_fixtures.app).await;

    let result = create_jwt_api(&test_fixtures.app, &regular_user.access_token, "api")
        .await
        .expect("Should work");
    assert!(result.token.len() > 10);

    let is_valid = is_jwt_api_valid(&test_fixtures.app, &result.token).await;
    assert!(is_valid.is_ok());

    let delete_response =
        delete_jwt_api_token(&test_fixtures.app, &regular_user.access_token, "api").await;
    assert!(delete_response.is_ok());

    let is_valid = is_jwt_api_valid(&test_fixtures.app, &result.token).await;
    assert!(is_valid.is_err());
    assert_eq!(is_valid.err().unwrap(), StatusCode::UNAUTHORIZED);

    ()
}

/// Test the jwt-api token flow with multiple tokens:
/// - Create a jwt-api token for a certain api and one for another api.
/// - Check if the is_authorized works for both api's.
/// - Delete the jwt-api token for one api.
/// - The is_authorized returns Not-authorized and for ok for the other.
/// - Update the still working jwt-api.
/// - The old key should no longer work, the new one should work.
#[tokio::test]
async fn test_multiple_jwt_api_token_regular_flow() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let regular_user = create_and_login_user(&test_fixtures.app).await;

    let result_1 = create_jwt_api(&test_fixtures.app, &regular_user.access_token, "api")
        .await
        .expect("Should work");
    let result_2 = create_jwt_api(&test_fixtures.app, &regular_user.access_token, "api2")
        .await
        .expect("Should work");

    // Both api tokens are valid.
    is_jwt_api_valid(&test_fixtures.app, &result_1.token)
        .await
        .ok()
        .unwrap();
    is_jwt_api_valid(&test_fixtures.app, &result_2.token)
        .await
        .ok()
        .unwrap();

    // delete token with id api
    delete_jwt_api_token(&test_fixtures.app, &regular_user.access_token, "api")
        .await
        .ok()
        .unwrap();

    // api is no longer valid, api2 still is.
    is_jwt_api_valid(&test_fixtures.app, &result_1.token)
        .await
        .err()
        .unwrap();
    is_jwt_api_valid(&test_fixtures.app, &result_2.token)
        .await
        .ok()
        .unwrap();

    // Update api2, result_2 no longer works, result_3 works.
    let result_3 = create_jwt_api(&test_fixtures.app, &regular_user.access_token, "api2")
        .await
        .expect("Should work");
    is_jwt_api_valid(&test_fixtures.app, &result_2.token)
        .await
        .err()
        .unwrap();
    is_jwt_api_valid(&test_fixtures.app, &result_3.token)
        .await
        .ok()
        .unwrap();

    ()
}

/// Test that the token is no longer valid if the user is deleted.
/// - Create the user and request a api-jwt token.
/// - Should be valid.
/// - Delete the user.
/// - Tokens should no longer be valid.
#[tokio::test]
async fn test_validity_token_with_missing_user() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let regular_user = create_and_login_user(&test_fixtures.app).await;

    let result_1 = create_jwt_api(&test_fixtures.app, &regular_user.access_token, "api")
        .await
        .expect("Should work");
    is_jwt_api_valid(&test_fixtures.app, &result_1.token)
        .await
        .ok()
        .unwrap();
    get_user(&test_fixtures.app, &regular_user.access_token)
        .await
        .unwrap();

    let collection = test_fixtures.db.collection::<User>("user");
    let delete_result = collection
        .delete_one(doc! {"user_id": &regular_user.user_id}, None)
        .await;
    assert_eq!(delete_result.ok().unwrap().deleted_count, 1);

    let err = is_jwt_api_valid(&test_fixtures.app, &result_1.token)
        .await
        .err()
        .unwrap();
    assert_eq!(err, StatusCode::UNAUTHORIZED);
    let err = get_user(&test_fixtures.app, &regular_user.access_token)
        .await
        .err()
        .unwrap();
    assert_eq!(err, StatusCode::NOT_FOUND);
}
