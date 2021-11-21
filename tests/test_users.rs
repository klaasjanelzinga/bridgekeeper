#[macro_use]
extern crate log;

use fake::faker::name::en::Name;
use fake::Fake;
use jsonwebtoken::{decode, Algorithm, Validation};
use rocket::http::{Header, Status};

use common::api_calls::{change_password, create_user, get_user, login, update_user};
use linkje_api::jwt::JwtClaims;
use linkje_api::users::{LoginRequest, UpdateUserRequest};

use crate::common::fake_password;

mod common;

/// Test get user:
/// - Create the user.
/// - Get user with the user-id -> OK.
/// - Get user with an unknown user-id -> FORBIDDEN, since request does not match token.
#[rocket::async_test]
async fn test_get_user() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let create_user_request = common::create_user_request();
    let created_user = create_user(&test_fixtures.client, &create_user_request).await;
    let token = login(&test_fixtures.client, &create_user_request)
        .await
        .token;
    let existing_user_id = created_user.user_id;
    let get_user = get_user(&test_fixtures.client, &existing_user_id, &token).await;

    assert_eq!(create_user_request.email_address, get_user.email_address);
    assert_eq!(create_user_request.first_name, get_user.first_name);
    assert_eq!(create_user_request.last_name, get_user.last_name);
    assert_eq!(create_user_request.display_name, get_user.display_name);
    assert!(get_user.user_id.len() > 1);

    let response = test_fixtures
        .client
        .get(format!("/user/unknown-{}", existing_user_id))
        .header(Header::new("Authorization", format!("Bearer {}", token)))
        .dispatch()
        .await;
    assert_eq!(Status::Forbidden, response.status()); // data mismatches token.

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
    let token = login(&test_fixtures.client, &create_user_request)
        .await
        .token;

    assert_eq!(
        create_user_request.email_address,
        created_user.email_address
    );
    assert_eq!(create_user_request.first_name, created_user.first_name);
    assert_eq!(create_user_request.last_name, created_user.last_name);
    assert_eq!(create_user_request.display_name, created_user.display_name);
    assert!(created_user.user_id.len() > 1);

    let get_result = get_user(&test_fixtures.client, &created_user.user_id, &token).await;

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
    let token = login(&test_fixtures.client, &create_user_request)
        .await
        .token;
    let user_id = created_user.user_id;

    let update_user_request = UpdateUserRequest {
        user_id: user_id.clone(),
        first_name: format!("updated-{}", created_user.first_name),
        last_name: format!("updated-{}", created_user.last_name),
        email_address: format!("updated-{}", created_user.email_address),
        display_name: Some(Name().fake()),
    };

    let updated_user = update_user(&test_fixtures.client, &update_user_request, &token).await;
    assert_eq!(updated_user.first_name, update_user_request.first_name);
    assert_eq!(updated_user.last_name, update_user_request.last_name);
    assert_eq!(
        updated_user.email_address,
        update_user_request.email_address
    );
    assert_eq!(updated_user.display_name, update_user_request.display_name);

    let get_user_response = get_user(&test_fixtures.client, &updated_user.user_id, &token).await;
    assert_eq!(get_user_response.first_name, update_user_request.first_name);
    assert_eq!(get_user_response.last_name, update_user_request.last_name);
    assert_eq!(
        get_user_response.email_address,
        update_user_request.email_address
    );
    assert_eq!(
        get_user_response.display_name,
        update_user_request.display_name
    );

    ()
}

/// Test login the user:
/// - Create the user.
/// - Login and validate the token.
/// - Login with an wrong-password.
/// - Login with an invalid email address.
#[rocket::async_test]
async fn test_login_user() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let create_user_request = common::create_user_request();
    create_user(&test_fixtures.client, &create_user_request).await;

    let login_response = login(&test_fixtures.client, &create_user_request).await;
    let token_message = decode::<JwtClaims>(
        &login_response.token,
        &test_fixtures.config.decoding_key,
        &Validation::new(Algorithm::HS256),
    );
    assert_eq!(
        token_message.unwrap().claims.email_address,
        create_user_request.email_address
    );

    let wrong_password = test_fixtures
        .client
        .post("/user/login")
        .json(&LoginRequest {
            email_address: create_user_request.email_address.clone(),
            password: format!("wrong-{}", create_user_request.new_password.clone()),
        })
        .dispatch()
        .await;
    assert_eq!(wrong_password.status(), Status::Unauthorized);

    let wrong_email_address = test_fixtures
        .client
        .post("/user/login")
        .json(&LoginRequest {
            email_address: format!("invalid-{}", create_user_request.email_address.clone()),
            password: create_user_request.new_password.clone(),
        })
        .dispatch()
        .await;
    assert_eq!(wrong_email_address.status(), Status::Unauthorized);

    ()
}

/// Test authorization:
/// - Two users created. Both logged in.
/// - User one uses the token of the other user, => Forbidden.
#[rocket::async_test]
async fn test_authorization() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let create_first_user_request = common::create_user_request();
    let created_first_user = create_user(&test_fixtures.client, &create_first_user_request).await;
    let login_response_first_user = login(&test_fixtures.client, &create_first_user_request).await;

    let create_second_user_request = common::create_user_request();
    let created_second_user = create_user(&test_fixtures.client, &create_second_user_request).await;
    let login_response_second_user =
        login(&test_fixtures.client, &create_second_user_request).await;

    // get with own tokens
    get_user(
        &test_fixtures.client,
        &created_first_user.user_id,
        &login_response_first_user.token,
    )
    .await;
    get_user(
        &test_fixtures.client,
        &created_second_user.user_id,
        &login_response_second_user.token,
    )
    .await;

    // cross the tokens, should return 403.
    let response = test_fixtures
        .client
        .get(format!("/user/{}", created_first_user.user_id))
        .header(Header::new(
            "Authorization",
            format!("Bearer {}", login_response_second_user.token),
        ))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Forbidden);

    ()
}

/// Test changing of password:
/// - Create user.
/// - Login.
/// - Change password.
/// - Login with old password -> Unauthorized.
/// - Login with new password -> Ok.
/// - Change password with invalid current password -> Unauthorized.
/// - Change password with invalid new passwords -> BadRequest.
#[rocket::async_test]
async fn test_change_password() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let create_user_request = common::create_user_request();
    let created_user = create_user(&test_fixtures.client, &create_user_request).await;

    let login_response = login(&test_fixtures.client, &create_user_request).await;
    let new_password = fake_password();

    let change_password_response_result = change_password(
        &test_fixtures.client,
        &created_user.user_id,
        &login_response.token,
        &create_user_request.new_password,
        &new_password,
    )
    .await;
    assert!(change_password_response_result.is_ok());
    let change_password_response = change_password_response_result.unwrap();
    assert_eq!(change_password_response.success, true);
    assert!(change_password_response.error_message.is_none());

    // login with the old password -> NotAuthorized
    let login_request = LoginRequest {
        email_address: create_user_request.email_address.clone(),
        password: create_user_request.new_password.clone(),
    };
    let response = test_fixtures
        .client
        .post("/user/login")
        .json(&login_request)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Unauthorized);

    // login with the new password -> Ok
    let login_request = LoginRequest {
        email_address: create_user_request.email_address.clone(),
        password: new_password.clone(),
    };
    let response = test_fixtures
        .client
        .post("/user/login")
        .json(&login_request)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);

    // Change password with invalid current password.
    let change_password_response_result = change_password(
        &test_fixtures.client,
        &created_user.user_id,
        &login_response.token,
        &create_user_request.new_password,
        &new_password,
    )
    .await;
    assert!(change_password_response_result.is_err());
    assert_eq!(
        change_password_response_result.err().unwrap(),
        Status::Unauthorized
    );

    // Test several invalid passwords
    let invalid_passwords = [
        "eE$2123",         // not long enough
        "k1ekjekjekje",    // no uppers
        "K1EKJEKJEKJEKJE", // no lowers
        "123123123123",    // no letters
        "kjeKJEkjekje",    // no digits
        "KJEkje123kje",    // no specials
    ];
    for invalid_password in invalid_passwords {
        let change_password_response_result = change_password(
            &test_fixtures.client,
            &created_user.user_id,
            &login_response.token,
            &new_password,
            invalid_password,
        )
        .await;
        assert!(
            change_password_response_result.is_err(),
            "ChangePassword request not in err for {}",
            invalid_password
        );
        assert_eq!(
            change_password_response_result.err().unwrap(),
            Status::BadRequest
        );
    }

    ()
}
