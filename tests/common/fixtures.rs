use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use fake::faker::internet::en::{Password, SafeEmail};
use fake::faker::lorem::en::Word;
use fake::faker::name::en::{FirstName, LastName, Name};
use fake::Fake;
use mongodb::Database;
use totp_lite::{totp_custom, Sha1};

use bridgekeeper_api::authorization::create;
use bridgekeeper_api::authorization_models::AddAuthorizationRequest;
use bridgekeeper_api::user::{get_by_id, update_user};
use bridgekeeper_api::user_models::CreateUserRequest;

use crate::common::api_calls::{confirm_totp, create_user, login, start_totp, validate_totp};

pub fn fake_password() -> String {
    format!("Rr$3-{}", Password(10..15).fake::<String>())
}

pub fn fake_application() -> String {
    let app: String = Word().fake();
    format!("app-{}", app)
}

pub struct CreateAndLoginData {
    pub user_id: String,
    pub for_application: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub email_address: String,
    pub password: String,
    pub first_name: String,
    pub last_name: String,
    pub display_name: Option<String>,
    pub totp_secret: Option<String>,
    pub backup_codes: Vec<String>,
}

pub fn create_user_request() -> CreateUserRequest {
    CreateUserRequest {
        email_address: SafeEmail().fake::<String>(),
        for_application: fake_application(),
        first_name: FirstName().fake(),
        last_name: LastName().fake(),
        display_name: Name().fake(),
        new_password: fake_password(),
    }
}

pub fn calculate_totp_value(secret: &str) -> String {
    let seconds: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    totp_custom::<Sha1>(30, 6, secret.as_bytes(), seconds)
}

#[allow(dead_code)]
pub async fn create_and_login_user(router: &Router, db: &Database) -> CreateAndLoginData {
    let create_user_request = create_user_request();
    let created_user = create_user(router, &create_user_request)
        .await
        .expect("Created user");

    // Approve the user
    let mut user = get_by_id(&created_user.user_id, db).await.unwrap();
    user.is_approved = true;
    update_user(&user, db).await.unwrap();

    let login_response = login(
        router,
        &created_user.for_application,
        &create_user_request.email_address,
        &create_user_request.new_password,
    )
    .await
    .unwrap();

    assert_eq!(login_response.needs_otp, false);

    return CreateAndLoginData {
        access_token: login_response.token,
        refresh_token: None,
        user_id: created_user.user_id,
        for_application: created_user.for_application,
        email_address: created_user.email_address,
        password: create_user_request.new_password,
        first_name: create_user_request.first_name,
        last_name: create_user_request.last_name,
        display_name: create_user_request.display_name,
        totp_secret: None,
        backup_codes: Vec::new(),
    };
}

/// Create an admin user. That is a user with full access on application bridgekeeper.
#[allow(dead_code)]
pub async fn create_and_login_admin_user(router: &Router, db: &Database) -> CreateAndLoginData {
    let create_and_login_data = create_and_login_user(router, db).await;
    let authorize_admin_request = AddAuthorizationRequest {
        for_user_id: create_and_login_data.user_id.clone(),
        application: String::from("bridgekeeper"),
        method_regex: String::from(".*"),
        uri_regex: String::from(".*"),
    };

    let result = create(&authorize_admin_request, db).await;
    assert!(result.is_ok());

    return create_and_login_data;
}

/// Create an user with a unvalidated totp challenge.
#[allow(dead_code)]
pub async fn create_and_login_user_with_totp_not_totp_verified(
    router: &Router,
    db: &Database,
) -> CreateAndLoginData {
    let user = create_and_login_user(&router, db).await;
    let totp_start = start_totp(&router, &user.access_token)
        .await
        .expect("Start of the totp should succeed");
    let backup_codes = totp_start.backup_codes.clone();

    confirm_totp(
        &router,
        &user.access_token,
        &calculate_totp_value(&totp_start.secret),
    )
    .await
    .expect("Confirmation totp should succeed");
    let second_login = login(
        &router,
        &user.for_application,
        &user.email_address,
        &user.password,
    )
    .await
    .expect("Login should succeed");

    return CreateAndLoginData {
        user_id: user.user_id.clone(),
        access_token: second_login.token.clone(),
        refresh_token: None,
        for_application: user.for_application,
        email_address: user.email_address.clone(),
        password: user.password.clone(),
        first_name: user.first_name.clone(),
        last_name: user.last_name.clone(),
        display_name: None,
        totp_secret: Some(totp_start.secret.clone()),
        backup_codes: backup_codes,
    };
}

/// Create an user with a validated totp challenge.
#[allow(dead_code)]
pub async fn create_and_login_user_with_totp(router: &Router, db: &Database) -> CreateAndLoginData {
    let unverified = create_and_login_user_with_totp_not_totp_verified(router, db).await;
    let totp_secret = unverified.totp_secret.expect("Secret is needed");
    let validated_totp_response = validate_totp(
        router,
        &unverified.access_token,
        &calculate_totp_value(&totp_secret),
    )
    .await
    .expect("Should be valid");

    return CreateAndLoginData {
        user_id: unverified.user_id.clone(),
        access_token: validated_totp_response.access_token,
        refresh_token: Some(validated_totp_response.refresh_token),
        for_application: unverified.for_application,
        email_address: unverified.email_address,
        password: unverified.password.clone(),
        first_name: unverified.first_name.clone(),
        last_name: unverified.last_name.clone(),
        display_name: None,
        totp_secret: Some(totp_secret.clone()),
        backup_codes: unverified.backup_codes,
    };
}
