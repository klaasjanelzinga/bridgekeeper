use linkje_api::users::{
    ChangePasswordRequest, ChangePasswordResponse, ConfirmTotpResponse, CreateUserRequest,
    GetUserResponse, LoginRequest, LoginResponse, StartTotpRegistrationResult, UpdateUserRequest,
    ValidateTotpRequest,
};
use rocket::http::{Header, Status};
use rocket::local::asynchronous::Client;
use std::clone::Clone;

/// Create the user.
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

// Login the user.
pub async fn login(client: &Client, create_user_request: &CreateUserRequest) -> LoginResponse {
    let login_request = LoginRequest {
        email_address: create_user_request.email_address.clone(),
        password: create_user_request.new_password.clone(),
    };
    let response = client
        .post("/user/login")
        .json(&login_request)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    serde_json::from_str(&response.into_string().await.unwrap()).unwrap()
}

/// Update the user.
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
pub async fn get_user(client: &Client, user_id: &String, token: &str) -> GetUserResponse {
    let response = client
        .get(format!("/user/{}", user_id))
        .header(Header::new("Authorization", format!("Bearer {}", token)))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    serde_json::from_str(&response.into_string().await.unwrap()).unwrap()
}

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
