#[macro_use]
extern crate log;

use rocket::http::Status;

use bridgekeeper_api::authorization::{AddAuthorizationRequest, IsAuthorizedRequest};

use crate::common::api_calls::{
    add_authorization, create_jwt_api, delete_jwt_api_token, is_authorized, is_jwt_api_valid,
};
use crate::common::fixtures::{create_and_login_admin_user, create_and_login_user};

mod common;

/// Test the authorization process.
///
/// - Create an admin user (someone with privileges on bridgekeeper).
/// - Create a regular user.
/// - The admin user gives the regular user some privileges and these are validated.
#[rocket::async_test]
async fn test_authorization() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let regular_user = create_and_login_user(&test_fixtures.client).await;
    let admin_user = create_and_login_admin_user(&test_fixtures.client, &test_fixtures.db).await;

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
        let auth_result =
            add_authorization(&test_fixtures.client, &admin_user.token, &regular_privilege).await;
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
            is_authorized(&test_fixtures.client, &regular_user.token, &valid).await;
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
            is_authorized(&test_fixtures.client, &regular_user.token, &invalid).await;
        assert!(is_authorized_response.is_err());
        assert_eq!(is_authorized_response.err().unwrap(), Status::Unauthorized);
    }

    ()
}

/// A user cannot add authorization for himself:
/// - Create a regular user and an admin user.
/// - Regular user cannot give privileges.
/// - Admin user can give privileges.
#[rocket::async_test]
async fn test_add_authorization() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let regular_user = create_and_login_user(&test_fixtures.client).await;
    let admin_user = create_and_login_admin_user(&test_fixtures.client, &test_fixtures.db).await;

    // regular user cannot give privileges
    let result = add_authorization(
        &test_fixtures.client,
        &regular_user.token,
        &AddAuthorizationRequest {
            for_user_id: regular_user.user_id.clone(),
            application: "bridgekeeper".to_string(),
            uri_regex: ".*".to_string(),
            method_regex: ".*".to_string(),
        },
    )
    .await;
    assert!(result.is_err());
    assert_eq!(result.err().unwrap(), Status::Unauthorized);

    // admin_user can.
    let result = add_authorization(
        &test_fixtures.client,
        &admin_user.token,
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
#[rocket::async_test]
async fn test_jwt_api_token_flow() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let regular_user = create_and_login_user(&test_fixtures.client).await;

    let result = create_jwt_api(&test_fixtures.client, &regular_user.token, "api")
        .await
        .expect("Should work");
    assert!(result.token.len() > 10);

    let is_valid = is_jwt_api_valid(&test_fixtures.client, &result.token).await;
    assert!(is_valid.is_ok());

    let delete_response =
        delete_jwt_api_token(&test_fixtures.client, &regular_user.token, "api").await;
    assert!(delete_response.is_ok());

    ()
}
