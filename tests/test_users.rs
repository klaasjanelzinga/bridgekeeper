#[macro_use]
extern crate log;

use fake::faker::name::en::Name;
use fake::Fake;
use jsonwebtoken::{decode, Algorithm, Validation};
use rocket::http::{Status};

use common::api_calls::{
    change_password, create_and_login_user, create_user, get_user, login, update_user,
};
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

    let login_data = create_and_login_user(&test_fixtures.client).await;

    let get_user_response = get_user(
        &test_fixtures.client,
        &login_data.user_id,
        &login_data.token,
    )
    .await;
    assert!(get_user_response.is_ok());
    let get_user_data = get_user_response.unwrap();

    assert_eq!(login_data.email_address, get_user_data.email_address);
    assert_eq!(login_data.first_name, get_user_data.first_name);
    assert_eq!(login_data.last_name, get_user_data.last_name);
    assert_eq!(login_data.display_name, get_user_data.display_name);
    assert!(get_user_data.user_id.len() > 1);

    let illegal_response = get_user(
        &test_fixtures.client,
        &format!("unknown-{}", login_data.email_address),
        &login_data.token)
    .await;
    assert!(illegal_response.is_err());
    assert_eq!(illegal_response.err().unwrap(), Status::Forbidden);

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
    let token = login(
        &test_fixtures.client,
        &create_user_request.email_address,
        &create_user_request.new_password,
    )
    .await
    .unwrap()
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
    assert!(get_result.is_ok());

    assert_eq!(created_user.email_address, get_result.unwrap().email_address);

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

    let login_data = create_and_login_user(&test_fixtures.client).await;

    let update_user_request = UpdateUserRequest {
        user_id: login_data.user_id.clone(),
        first_name: format!("updated-{}", login_data.first_name),
        last_name: format!("updated-{}", login_data.last_name),
        email_address: format!("updated-{}", login_data.email_address),
        display_name: Some(Name().fake()),
    };

    let updated_user = update_user(
        &test_fixtures.client,
        &update_user_request,
        &login_data.token,
    )
    .await;
    assert_eq!(updated_user.first_name, update_user_request.first_name);
    assert_eq!(updated_user.last_name, update_user_request.last_name);
    assert_eq!(
        updated_user.email_address,
        update_user_request.email_address
    );
    assert_eq!(updated_user.display_name, update_user_request.display_name);

    let get_user_response = get_user(
        &test_fixtures.client,
        &updated_user.user_id,
        &login_data.token,
    )
    .await;
    assert!(get_user_response.is_ok());
    let get_user = get_user_response.unwrap();
    assert_eq!(get_user.first_name, update_user_request.first_name);
    assert_eq!(get_user.last_name, update_user_request.last_name);
    assert_eq!(
        get_user.email_address,
        update_user_request.email_address
    );
    assert_eq!(
        get_user.display_name,
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

    let login_data = create_and_login_user(&test_fixtures.client).await;

    let token_message = decode::<JwtClaims>(
        &login_data.token,
        &test_fixtures.config.decoding_key,
        &Validation::new(Algorithm::HS256),
    )
    .unwrap();
    assert_eq!(token_message.claims.email_address, login_data.email_address);
    assert_eq!(token_message.claims.requires_otp_challenge, false);

    let wrong_password = login(
        &test_fixtures.client,
        &login_data.email_address,
        &format!("wrong-{}", login_data.password.clone()),
    )
    .await;
    assert!(wrong_password.is_err());
    assert_eq!(wrong_password.err().unwrap(), Status::Unauthorized);

    let wrong_email = login(
        &test_fixtures.client,
        &format!("invalid-{}", login_data.email_address.clone()),
        &login_data.password,
    )
    .await;
    assert!(wrong_email.is_err());
    assert_eq!(wrong_email.err().unwrap(), Status::Unauthorized);

    ()
}

/// Test authorization:
/// - Two users created. Both logged in.
/// - User one uses the token of the other user, => Forbidden.
#[rocket::async_test]
async fn test_authorization() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let login_data_first = create_and_login_user(&test_fixtures.client).await;
    let login_data_second = create_and_login_user(&test_fixtures.client).await;

    // get with own tokens
    let with_own_response_first = get_user(
        &test_fixtures.client,
        &login_data_first.user_id,
        &login_data_first.token,
    )
    .await;
    let with_own_response_second = get_user(
        &test_fixtures.client,
        &login_data_second.user_id,
        &login_data_second.token,
    )
    .await;
    assert!(with_own_response_second.is_ok());
    assert!(with_own_response_first.is_ok());

    // cross the tokens, should return 403.
    let crossed_response = get_user(
        &test_fixtures.client,
        &login_data_first.user_id,
        &login_data_second.token
    ).await;
    assert_eq!(crossed_response.err().unwrap(), Status::Forbidden);

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

    let login_data = create_and_login_user(&test_fixtures.client).await;
    let new_password = fake_password();

    let change_password_response_result = change_password(
        &test_fixtures.client,
        &login_data.user_id,
        &login_data.token,
        &login_data.password,
        &new_password,
    )
    .await;

    assert!(change_password_response_result.is_ok());
    let change_password_response = change_password_response_result.unwrap();
    assert_eq!(change_password_response.success, true);
    assert!(change_password_response.error_message.is_none());

    // login with the old password -> NotAuthorized
    let login_request = LoginRequest {
        email_address: login_data.email_address.clone(),
        password: login_data.password.clone(),
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
        email_address: login_data.email_address.clone(),
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
        &login_data.user_id,
        &login_data.token,
        &login_data.password,
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
            &login_data.user_id,
            &login_data.token,
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
