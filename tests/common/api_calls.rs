use rocket::http::{Header, Status};
use rocket::local::asynchronous::Client;

use bridgekeeper_api::authorization::{
    AddAuthorizationRequest, Authorization, IsAuthorizedRequest, IsAuthorizedResponse,
    IsJwtApiTokenValidRequest,
};
use bridgekeeper_api::avatar::{GetAvatarResponse, UpdateAvatarRequest, UpdateAvatarResponse};
use bridgekeeper_api::jwt::{CreateJwtApiRequest, CreateJwtApiResponse};
use bridgekeeper_api::user::{
    ChangePasswordRequest, ChangePasswordResponse, CreateUserRequest, EmptyOkResponse,
    GetUserResponse, LoginRequest, LoginResponse, UpdateUserRequest,
};
use bridgekeeper_api::user_totp::{
    ConfirmTotpResponse, StartTotpRegistrationResult, ValidateTotpRequest,
};

/// Create the user.
#[allow(dead_code)]
pub async fn create_user(
    client: &Client,
    create_user_request: &CreateUserRequest,
) -> Result<GetUserResponse, Status> {
    let response = client
        .post("/user")
        .json(&create_user_request)
        .dispatch()
        .await;
    if response.status() != Status::Created {
        return Err(response.status());
    }
    assert_eq!(response.status(), Status::Created);
    Ok(serde_json::from_str(&response.into_string().await.unwrap()).unwrap())
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
    token: &str,
    current_password: &str,
    new_password: &str,
) -> Result<ChangePasswordResponse, Status> {
    let change_password_request = ChangePasswordRequest {
        current_password: String::from(current_password),
        new_password: String::from(new_password),
    };

    let response = client
        .post("/user/change-password")
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
pub async fn get_user(client: &Client, token: &str) -> Result<GetUserResponse, Status> {
    let response = client
        .get("/user")
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
    token: &str,
) -> Result<StartTotpRegistrationResult, Status> {
    let response = client
        .post("/user/start-totp-registration")
        .header(Header::new("Authorization", format!("Bearer {}", token)))
        .dispatch()
        .await;
    if response.status() == Status::Ok {
        return Ok(serde_json::from_str(&response.into_string().await.unwrap()).unwrap());
    }
    Err(response.status())
}

/// confirm the totp code
#[allow(dead_code)]
pub async fn confirm_totp(
    client: &Client,
    token: &str,
    totp_challenge: &str,
) -> Result<ConfirmTotpResponse, Status> {
    let validate_totp_request = ValidateTotpRequest {
        totp_challenge: totp_challenge.to_string(),
    };
    let response = client
        .post("/user/confirm-totp-registration")
        .json(&validate_totp_request)
        .header(Header::new("Authorization", format!("Bearer {}", token)))
        .dispatch()
        .await;
    if response.status() == Status::Ok {
        return Ok(serde_json::from_str(&response.into_string().await.unwrap()).unwrap());
    }
    Err(response.status())
}

/// validate totp code
#[allow(dead_code)]
pub async fn validate_totp(client: &Client, token: &str, totp_challenge: &str) -> LoginResponse {
    let validate_totp_request = ValidateTotpRequest {
        totp_challenge: totp_challenge.to_string(),
    };
    let response = client
        .post("/user/validate-totp")
        .json(&validate_totp_request)
        .header(Header::new("Authorization", format!("Bearer {}", token)))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    serde_json::from_str(&response.into_string().await.unwrap()).unwrap()
}

/// Get avatar by the user_id.
#[allow(dead_code)]
pub async fn get_avatar(client: &Client, token: &str) -> Result<GetAvatarResponse, Status> {
    let response = client
        .get("/user/avatar")
        .header(Header::new("Authorization", format!("Bearer {}", token)))
        .dispatch()
        .await;
    if response.status() == Status::Ok {
        return Ok(serde_json::from_str(&response.into_string().await.unwrap()).unwrap());
    }
    Err(response.status())
}

/// Create or update avatar by the user_id.
#[allow(dead_code)]
pub async fn create_or_update_avatar(
    client: &Client,
    token: &str,
    update_avatar_request: &UpdateAvatarRequest,
) -> Result<UpdateAvatarResponse, Status> {
    let response = client
        .post("/user/avatar")
        .json(&update_avatar_request)
        .header(Header::new("Authorization", format!("Bearer {}", token)))
        .dispatch()
        .await;
    if response.status() == Status::Ok {
        return Ok(serde_json::from_str(&response.into_string().await.unwrap()).unwrap());
    }
    Err(response.status())
}

/// Delete avatar by the user_id.
#[allow(dead_code)]
pub async fn delete_avatar(client: &Client, token: &str) -> Result<UpdateAvatarResponse, Status> {
    let response = client
        .delete("/user/avatar")
        .header(Header::new("Authorization", format!("Bearer {}", token)))
        .dispatch()
        .await;
    if response.status() == Status::Ok {
        return Ok(serde_json::from_str(&response.into_string().await.unwrap()).unwrap());
    }
    Err(response.status())
}

/// Add an authorization record for a user.
#[allow(dead_code)]
pub async fn add_authorization(
    client: &Client,
    token: &str,
    add_authorization_request: &AddAuthorizationRequest,
) -> Result<Authorization, Status> {
    let response = client
        .post("/authorization")
        .json(add_authorization_request)
        .header(Header::new("Authorization", format!("Bearer {}", token)))
        .dispatch()
        .await;
    if response.status() == Status::Ok {
        return Ok(serde_json::from_str(&response.into_string().await.unwrap()).unwrap());
    }
    Err(response.status())
}

/// Is user authorized.
#[allow(dead_code)]
pub async fn is_authorized(
    client: &Client,
    token: &str,
    is_authorized_request: &IsAuthorizedRequest,
) -> Result<IsAuthorizedResponse, Status> {
    let response = client
        .post("/authorization/user")
        .json(is_authorized_request)
        .header(Header::new("Authorization", format!("Bearer {}", token)))
        .dispatch()
        .await;
    if response.status() == Status::Ok {
        return Ok(serde_json::from_str(&response.into_string().await.unwrap()).unwrap());
    }
    Err(response.status())
}

/// Create a jwt-api token.
#[allow(dead_code)]
pub async fn create_jwt_api(
    client: &Client,
    token: &str,
    public_token_id: &str,
) -> Result<CreateJwtApiResponse, Status> {
    let response = client
        .post("/user/jwt-api-token")
        .json(&CreateJwtApiRequest {
            public_token_id: public_token_id.to_string(),
        })
        .header(Header::new("Authorization", format!("Bearer {}", token)))
        .dispatch()
        .await;
    if response.status() == Status::Ok {
        return Ok(serde_json::from_str(&response.into_string().await.unwrap()).unwrap());
    }
    Err(response.status())
}

/// Check a jwt-api token.
#[allow(dead_code)]
pub async fn is_jwt_api_valid(
    client: &Client,
    jwt_api_token: &str,
) -> Result<IsAuthorizedResponse, Status> {
    let response = client
        .post("/authorization/jwt-api-token")
        .json(&IsJwtApiTokenValidRequest {
            token: jwt_api_token.to_string(),
        })
        .dispatch()
        .await;
    if response.status() == Status::Ok {
        return Ok(serde_json::from_str(&response.into_string().await.unwrap()).unwrap());
    }
    Err(response.status())
}

/// Delete a jwt-api token.
#[allow(dead_code)]
pub async fn delete_jwt_api_token(
    client: &Client,
    token: &str,
    public_token_id: &str,
) -> Result<EmptyOkResponse, Status> {
    let response = client
        .delete(format!("/user/jwt-api-token/{}", public_token_id))
        .header(Header::new("Authorization", format!("Bearer {}", token)))
        .dispatch()
        .await;
    if response.status() == Status::Ok {
        return Ok(serde_json::from_str(&response.into_string().await.unwrap()).unwrap());
    }
    Err(response.status())
}
