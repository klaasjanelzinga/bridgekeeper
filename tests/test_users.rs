#[macro_use]
extern crate log;

use axum::http::StatusCode;
use fake::faker::name::en::Name;
use fake::Fake;
use jsonwebtoken::{decode, Algorithm, Validation};

use bridgekeeper_api::jwt_models::{JwtClaims, JwtType};
use bridgekeeper_api::user_models::UpdateUserRequest;

use crate::common::api_calls::{
    approve_user, change_password, create_user, get_user, login, update_user,
};
use crate::common::fixtures::{
    create_and_login_admin_user, create_and_login_user, create_and_login_user_with_totp,
    create_and_login_user_with_totp_not_totp_verified, create_user_request, fake_password,
};

mod common;

/// Test get user:
/// - Create the user.
/// - Get user with the user-id -> OK.
/// - Get user with an unknown user-id -> FORBIDDEN, since request does not match token.
#[tokio::test]
async fn test_get_user() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let login_data = create_and_login_user(&test_fixtures.app, &test_fixtures.db).await;

    let get_user_response = get_user(&test_fixtures.app, &login_data.access_token).await;
    assert!(get_user_response.is_ok());
    let get_user_data = get_user_response.unwrap();

    assert_eq!(login_data.email_address, get_user_data.email_address);
    assert_eq!(login_data.first_name, get_user_data.first_name);
    assert_eq!(login_data.last_name, get_user_data.last_name);
    assert_eq!(login_data.display_name, get_user_data.display_name);
    assert!(get_user_data.user_id.len() > 1);

    ()
}

/// Test the get_user authentication.
#[tokio::test]
async fn test_get_user_authentication() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let regular_user = create_and_login_user(&test_fixtures.app, &test_fixtures.db).await;
    let totp_user = create_and_login_user_with_totp(&test_fixtures.app, &test_fixtures.db).await;
    let one_shot_token =
        create_and_login_user_with_totp_not_totp_verified(&test_fixtures.app, &test_fixtures.db)
            .await
            .access_token;

    assert!(get_user(&test_fixtures.app, &regular_user.access_token)
        .await
        .is_ok());
    assert!(get_user(&test_fixtures.app, &totp_user.access_token)
        .await
        .is_ok());
    assert_eq!(
        get_user(&test_fixtures.app, &totp_user.refresh_token.unwrap())
            .await
            .err()
            .unwrap(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        get_user(&test_fixtures.app, &one_shot_token)
            .await
            .err()
            .unwrap(),
        StatusCode::UNAUTHORIZED
    );
}

/// Test create user:
/// - Create the user.
/// - Validate the response of the get.
/// - Get user with the user id should return the created user.
#[tokio::test]
async fn test_create_user() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let admin_user = create_and_login_admin_user(&test_fixtures.app, &test_fixtures.db).await;

    let create_user_request = create_user_request();
    let created_user_response = create_user(&test_fixtures.app, &create_user_request).await;
    assert!(created_user_response.is_ok());
    let created_user = created_user_response.unwrap();

    assert_eq!(
        create_user_request.email_address,
        created_user.email_address
    );
    assert_eq!(create_user_request.first_name, created_user.first_name);
    assert_eq!(create_user_request.last_name, created_user.last_name);
    assert_eq!(create_user_request.display_name, created_user.display_name);
    assert!(created_user.needs_approval);
    assert!(created_user.user_id.len() > 1);

    // user admin to approve the user.
    assert!(approve_user(
        &test_fixtures.app,
        &admin_user.access_token,
        &created_user.user_id,
    )
    .await
    .unwrap());

    // login and get user
    let token = login(
        &test_fixtures.app,
        &create_user_request.email_address,
        &create_user_request.new_password,
    )
    .await
    .unwrap()
    .token;

    let get_result = get_user(&test_fixtures.app, &token).await;
    assert!(get_result.is_ok());

    assert_eq!(
        created_user.email_address,
        get_result.unwrap().email_address
    );

    // create the user again, should return already created.
    let created_user_second_time = create_user(&test_fixtures.app, &create_user_request).await;

    assert!(created_user_second_time.is_err());

    ()
}

/// Test create user with a weak password.
/// - Create the user.
/// - Validate the response of the get.
/// - Get user with the user id should return the created user.
#[tokio::test]
async fn test_create_user_with_weak_password() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let mut create_user_request = create_user_request();
    create_user_request.new_password = "123".to_string();
    let created_user_response = create_user(&test_fixtures.app, &create_user_request).await;
    assert!(created_user_response.is_err());
    assert_eq!(
        created_user_response.err().unwrap(),
        StatusCode::BAD_REQUEST
    );
}

/// Test the approval of users.
/// - Create a user, the user should not be approved.
/// - Apptove the user.
/// - Login should work
#[tokio::test]
async fn test_approval_user() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let admin_user = create_and_login_admin_user(&test_fixtures.app, &test_fixtures.db).await;

    // create a user.
    let create_user_request = create_user_request();
    let created_user_response = create_user(&test_fixtures.app, &create_user_request)
        .await
        .unwrap();

    // The login should fail, since the user is not yet approved.
    // login and get user
    assert_eq!(
        login(
            &test_fixtures.app,
            &create_user_request.email_address,
            &create_user_request.new_password,
        )
        .await
        .err()
        .unwrap(),
        StatusCode::UNAUTHORIZED
    );

    assert!(approve_user(
        &test_fixtures.app,
        &admin_user.access_token,
        &created_user_response.user_id,
    )
    .await
    .unwrap());

    // The login should succeed, since the user is not yet approved.
    login(
        &test_fixtures.app,
        &create_user_request.email_address,
        &create_user_request.new_password,
    )
    .await
    .unwrap();
}

/// Test update user:
/// - Create the user.
/// - Get the user with the user id.
/// - Update the fields of the user and call update_user.
/// - Validate the response of the update request.
/// - Get the user, should contain the updated fields.
#[tokio::test]
async fn test_update_user() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let login_data = create_and_login_user(&test_fixtures.app, &test_fixtures.db).await;

    let update_user_request = UpdateUserRequest {
        user_id: login_data.user_id.clone(),
        first_name: format!("updated-{}", login_data.first_name),
        last_name: format!("updated-{}", login_data.last_name),
        email_address: format!("updated-{}", login_data.email_address),
        display_name: Some(Name().fake()),
    };

    let updated_user_response = update_user(
        &test_fixtures.app,
        &update_user_request,
        &login_data.access_token,
    )
    .await;
    assert!(updated_user_response.is_ok());

    let updated_user = updated_user_response.unwrap();
    assert_eq!(updated_user.first_name, update_user_request.first_name);
    assert_eq!(updated_user.last_name, update_user_request.last_name);
    assert_eq!(
        updated_user.email_address,
        update_user_request.email_address
    );
    assert_eq!(updated_user.display_name, update_user_request.display_name);

    let get_user_response = get_user(&test_fixtures.app, &login_data.access_token).await;
    assert!(get_user_response.is_ok());
    let get_user = get_user_response.unwrap();
    assert_eq!(get_user.first_name, update_user_request.first_name);
    assert_eq!(get_user.last_name, update_user_request.last_name);
    assert_eq!(get_user.email_address, update_user_request.email_address);
    assert_eq!(get_user.display_name, update_user_request.display_name);
}

/// Test the update_user authentication.
#[tokio::test]
async fn test_update_user_authentication() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let regular_user = create_and_login_user(&test_fixtures.app, &test_fixtures.db).await;
    let totp_user = create_and_login_user_with_totp(&test_fixtures.app, &test_fixtures.db).await;
    let one_shot_token =
        create_and_login_user_with_totp_not_totp_verified(&test_fixtures.app, &test_fixtures.db)
            .await
            .access_token;

    let update_user_request = UpdateUserRequest {
        user_id: regular_user.user_id.clone(),
        first_name: format!("updated-{}", regular_user.first_name),
        last_name: format!("updated-{}", regular_user.last_name),
        email_address: format!("updated-{}", regular_user.email_address),
        display_name: Some(Name().fake()),
    };

    assert!(update_user(
        &test_fixtures.app,
        &update_user_request,
        &regular_user.access_token
    )
    .await
    .is_ok());
    assert!(update_user(
        &test_fixtures.app,
        &update_user_request,
        &totp_user.access_token
    )
    .await
    .is_ok());
    assert_eq!(
        update_user(
            &test_fixtures.app,
            &update_user_request,
            &totp_user.refresh_token.unwrap()
        )
        .await
        .err()
        .unwrap(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        update_user(&test_fixtures.app, &update_user_request, &one_shot_token)
            .await
            .err()
            .unwrap(),
        StatusCode::UNAUTHORIZED
    );
}

/// Test login the user:
/// - Create the user.
/// - Login and validate the token.
/// - Login with an wrong-password.
/// - Login with an invalid email address.
#[tokio::test]
async fn test_login_user() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let login_data = create_and_login_user(&test_fixtures.app, &test_fixtures.db).await;

    let token_message = decode::<JwtClaims>(
        &login_data.access_token,
        &test_fixtures.config.decoding_key,
        &Validation::new(Algorithm::HS256),
    )
    .unwrap();
    assert_eq!(token_message.claims.email_address, login_data.email_address);
    assert_eq!(
        token_message.claims.token_type.to_string(),
        JwtType::AccessToken.to_string()
    );

    let wrong_password = login(
        &test_fixtures.app,
        &login_data.email_address,
        &format!("wrong-{}", login_data.password.clone()),
    )
    .await;
    assert!(wrong_password.is_err());
    assert_eq!(wrong_password.err().unwrap(), StatusCode::UNAUTHORIZED);

    let wrong_email = login(
        &test_fixtures.app,
        &format!("invalid-{}", login_data.email_address.clone()),
        &login_data.password,
    )
    .await;
    assert!(wrong_email.is_err());
    assert_eq!(wrong_email.err().unwrap(), StatusCode::UNAUTHORIZED);

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
#[tokio::test]
async fn test_change_password() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let login_data = create_and_login_user(&test_fixtures.app, &test_fixtures.db).await;
    let new_password = fake_password();

    let change_password_response_result = change_password(
        &test_fixtures.app,
        &login_data.access_token,
        &login_data.password,
        &new_password,
    )
    .await;

    assert!(change_password_response_result.is_ok());
    let change_password_response = change_password_response_result.unwrap();
    assert_eq!(change_password_response.success, true);
    assert!(change_password_response.error_message.is_none());

    // login with the old password -> NotAuthorized
    let login_response = login(
        &test_fixtures.app,
        &login_data.email_address,
        &login_data.password,
    )
    .await;
    assert!(login_response.is_err());
    assert_eq!(login_response.err().unwrap(), StatusCode::UNAUTHORIZED);

    // login with the new password -> Ok
    let login_response = login(&test_fixtures.app, &login_data.email_address, &new_password).await;
    assert!(login_response.is_ok());
    let new_access_token = login_response.unwrap().token;

    // Change password with invalid current password.
    let change_password_response_result = change_password(
        &test_fixtures.app,
        &new_access_token,
        &login_data.password,
        &new_password,
    )
    .await;
    assert!(change_password_response_result.is_err());
    assert_eq!(
        change_password_response_result.err().unwrap(),
        StatusCode::UNAUTHORIZED
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
            &test_fixtures.app,
            &new_access_token,
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
            StatusCode::BAD_REQUEST
        );
    }
}

/// Test authentication on change_password.
#[tokio::test]
async fn test_change_password_authentication() {
    let test_fixtures = common::setup().await;
    common::empty_users_collection(&test_fixtures.db).await;

    let regular_user = create_and_login_user(&test_fixtures.app, &test_fixtures.db).await;
    let totp_user = create_and_login_user_with_totp(&test_fixtures.app, &test_fixtures.db).await;
    let one_shot_token =
        create_and_login_user_with_totp_not_totp_verified(&test_fixtures.app, &test_fixtures.db)
            .await;

    let new_password = fake_password();

    assert!(change_password(
        &test_fixtures.app,
        &regular_user.access_token,
        &regular_user.password,
        &new_password,
    )
    .await
    .is_ok());

    assert!(change_password(
        &test_fixtures.app,
        &totp_user.access_token,
        &totp_user.password,
        &new_password,
    )
    .await
    .is_ok());

    assert_eq!(
        change_password(
            &test_fixtures.app,
            &totp_user.refresh_token.unwrap(),
            &one_shot_token.password,
            &new_password,
        )
        .await
        .err()
        .unwrap(),
        StatusCode::UNAUTHORIZED
    );

    assert_eq!(
        change_password(
            &test_fixtures.app,
            &one_shot_token.access_token,
            &one_shot_token.password,
            &new_password,
        )
        .await
        .err()
        .unwrap(),
        StatusCode::UNAUTHORIZED
    );
}
