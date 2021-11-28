use crate::common::create_user_request;
use linkje_api::users::{
    ChangePasswordRequest, ChangePasswordResponse, ConfirmTotpResponse, CreateUserRequest,
    GetUserResponse, LoginRequest, LoginResponse, StartTotpRegistrationResult, UpdateUserRequest,
    ValidateTotpRequest,
};
use rocket::http::{Header, Status};
use rocket::local::asynchronous::Client;

pub struct CreateAndLoginData {
    pub user_id: String,
    pub token: String,
    pub email_address: String,
    pub password: String,
    pub first_name: String,
    pub last_name: String,
    pub display_name: Option<String>,
}

pub async fn create_and_login_user(client: &Client) -> CreateAndLoginData {
    let create_user_request = create_user_request();
    let created_user = create_user(client, &create_user_request).await;
    let login_response = login(
        client,
        &create_user_request.email_address,
        &create_user_request.new_password,
    )
    .await
    .unwrap();

    assert_eq!(login_response.needs_otp, false);

    return CreateAndLoginData {
        token: login_response.token,
        user_id: created_user.user_id,
        email_address: created_user.email_address,
        password: create_user_request.new_password,
        first_name: create_user_request.first_name,
        last_name: create_user_request.last_name,
        display_name: create_user_request.display_name,
    };
}

/// Create the user.
#[allow(dead_code)]
pub async fn create_user(
    client: &Client,
    create_user_request: &CreateUserRequest,
) -> GetUserResponse {
    let response = client
        .post("/user")
        .json(&create_user_request)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Created);

    serde_json::from_str(&response.into_string().await.unwrap()).unwrap()
}

/// Login the user.
#[allow(dead_code)]
pub async fn login(
    client: &Client,
    email_address: &str,
    password: &str,
) -> Result<LoginResponse, Status> {
    let login_request = LoginRequest {
        email_address: String::from(email_address),
        password: String::from(password),
    };
    let response = client
        .post("/user/login")
        .json(&login_request)
        .dispatch()
        .await;
    if response.status() != Status::Ok {
        return Err(response.status());
    }
    assert_eq!(response.status(), Status::Ok);
    Ok(serde_json::from_str(&response.into_string().await.unwrap()).unwrap())
}

/// Update the user.
#[allow(dead_code)]
pub async fn update_user(
    client: &Client,
    update_request: &UpdateUserRequest,
    token: &str,
) -> GetUserResponse {
    let response = client
        .put("/user")
        .json(&update_request)
        .header(Header::new("Authorization", format!("Bearer {}", token)))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);

    serde_json::from_str(&response.into_string().await.unwrap()).unwrap()
}

/// Change password for a user.
#[allow(dead_code)]
pub async fn change_password(
    client: &Client,
    user_id: &str,
    token: &str,
    current_password: &str,
    new_password: &str,
) -> Result<ChangePasswordResponse, Status> {
    let change_password_request = ChangePasswordRequest {
        current_password: String::from(current_password),
        new_password: String::from(new_password),
    };

    let response = client
        .post(format!("/user/{}/change-password", user_id))
        .json(&change_password_request)
        .header(Header::new("Authorization", format!("Bearer {}", token)))
        .dispatch()
        .await;

    if response.status() == Status::Ok {
        Ok(serde_json::from_str(&response.into_string().await.unwrap()).unwrap())
    } else {
        Err(response.status())
    }
}

/// Get user by the user_id.
#[allow(dead_code)]
pub async fn get_user(
    client: &Client,
    user_id: &String,
    token: &str,
) -> Result<GetUserResponse, Status> {
    let response = client
        .get(format!("/user/{}", user_id))
        .header(Header::new("Authorization", format!("Bearer {}", token)))
        .dispatch()
        .await;
    if response.status() == Status::Ok {
        return Ok(serde_json::from_str(&response.into_string().await.unwrap()).unwrap());
    }
    Err(response.status())
}

/// start the totp registration
#[allow(dead_code)]
pub async fn start_totp(
    client: &Client,
    user_id: &str,
    token: &str,
) -> StartTotpRegistrationResult {
    let response = client
        .post(format!("/user/{}/start-totp-registration", user_id))
        .header(Header::new("Authorization", format!("Bearer {}", token)))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    serde_json::from_str(&response.into_string().await.unwrap()).unwrap()
}

/// confirm the totp code
#[allow(dead_code)]
pub async fn confirm_totp(
    client: &Client,
    user_id: &str,
    token: &str,
    totp_challenge: &str,
) -> ConfirmTotpResponse {
    let validate_totp_request = ValidateTotpRequest {
        totp_challenge: totp_challenge.to_string(),
    };
    let response = client
        .post(format!("/user/{}/confirm-totp-registration", user_id))
        .json(&validate_totp_request)
        .header(Header::new("Authorization", format!("Bearer {}", token)))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    serde_json::from_str(&response.into_string().await.unwrap()).unwrap()
}

/// validate totp code
#[allow(dead_code)]
pub async fn validate_totp(
    client: &Client,
    user_id: &str,
    token: &str,
    totp_challenge: &str,
) -> LoginResponse {
    let validate_totp_request = ValidateTotpRequest {
        totp_challenge: totp_challenge.to_string(),
    };
    let response = client
        .post(format!("/user/{}/validate-totp", user_id))
        .json(&validate_totp_request)
        .header(Header::new("Authorization", format!("Bearer {}", token)))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    serde_json::from_str(&response.into_string().await.unwrap()).unwrap()
}
