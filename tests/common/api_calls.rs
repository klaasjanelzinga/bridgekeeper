use axum::http::{Request, StatusCode};
use axum::{http, Router};
use hyper::Body;
use serde_json::json;
use tower::ServiceExt;

use bridgekeeper_api::authorization_models::{
    AddAuthorizationRequest, ApproveUserRequest, Authorization, IsAuthorizedRequest,
    IsAuthorizedResponse, IsJwtApiTokenValidRequest,
};
use bridgekeeper_api::avatar_models::{
    GetAvatarResponse, UpdateAvatarRequest, UpdateAvatarResponse,
};
use bridgekeeper_api::jwt_models::{CreateJwtApiRequest, CreateJwtApiResponse};
use bridgekeeper_api::user_models::{
    ChangePasswordRequest, ChangePasswordResponse, EmptyOkResponse, GetUserResponse, LoginRequest,
    LoginResponse, UpdateUserRequest,
};
use bridgekeeper_api::user_models::{CreateUserRequest, LoginWithOtpResponse};
use bridgekeeper_api::user_totp_models::{
    StartTotpRegistrationResult, ValidateTotpRequest, ValidateTotpWithBackupCodeRequest,
};

/// Create the user.
#[allow(dead_code)]
pub async fn create_user(
    router: &Router,
    create_user_request: &CreateUserRequest,
) -> Result<GetUserResponse, StatusCode> {
    let req = Request::builder()
        .uri("/user")
        .method(http::Method::POST)
        .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(
            serde_json::to_string(&json!(create_user_request)).unwrap(),
        ))
        .unwrap();
    let response = router.clone().oneshot(req).await.unwrap();
    if response.status() == StatusCode::CREATED {
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        return Ok(serde_json::from_slice(&body).unwrap());
    }
    return Err(response.status());
}

/// Login the user.
#[allow(dead_code)]
pub async fn login(
    router: &Router,
    email_address: &str,
    password: &str,
) -> Result<LoginResponse, StatusCode> {
    let login_request = LoginRequest {
        email_address: String::from(email_address),
        password: String::from(password),
    };
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/user/login")
                .method(http::Method::POST)
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::from(
                    serde_json::to_string(&json!(login_request)).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    if response.status() == StatusCode::OK {
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        return Ok(serde_json::from_slice(&body).unwrap());
    }
    return Err(response.status());
}

/// Update the user.
#[allow(dead_code)]
pub async fn update_user(
    router: &Router,
    update_request: &UpdateUserRequest,
    token: &str,
) -> Result<GetUserResponse, StatusCode> {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/user")
                .method(http::Method::PUT)
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::from(
                    serde_json::to_string(&json!(update_request)).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    if response.status() == StatusCode::OK {
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        return Ok(serde_json::from_slice(&body).unwrap());
    }
    Err(response.status())
}

/// Change password for a user.
#[allow(dead_code)]
pub async fn change_password(
    router: &Router,
    token: &str,
    current_password: &str,
    new_password: &str,
) -> Result<ChangePasswordResponse, StatusCode> {
    let change_password_request = ChangePasswordRequest {
        current_password: String::from(current_password),
        new_password: String::from(new_password),
    };
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/user/change-password")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
                .method(http::Method::POST)
                .body(Body::from(
                    serde_json::to_string(&json!(change_password_request)).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    if response.status() == StatusCode::OK {
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        return Ok(serde_json::from_slice(&body).unwrap());
    }
    Err(response.status())
}

/// Get user by the user_id.
#[allow(dead_code)]
pub async fn get_user(router: &Router, token: &str) -> Result<GetUserResponse, StatusCode> {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/user")
                .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
                .method(http::Method::GET)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    if response.status() == StatusCode::OK {
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        return Ok(serde_json::from_slice(&body).unwrap());
    }
    Err(response.status())
}

/// Delete the user
#[allow(dead_code)]
pub async fn delete_user(router: &Router, token: &str) -> Result<EmptyOkResponse, StatusCode> {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/user")
                .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
                .method(http::Method::DELETE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    if response.status() == StatusCode::OK {
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        return Ok(serde_json::from_slice(&body).unwrap());
    }
    Err(response.status())
}

/// Get user by the user_id.
#[allow(dead_code)]
pub async fn refresh_token(
    router: &Router,
    token: &str,
) -> Result<LoginWithOtpResponse, StatusCode> {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/user/refresh-token")
                .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
                .method(http::Method::POST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    if response.status() == StatusCode::OK {
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        return Ok(serde_json::from_slice(&body).unwrap());
    }
    Err(response.status())
}

/// start the totp registration
#[allow(dead_code)]
pub async fn start_totp(
    router: &Router,
    token: &str,
) -> Result<StartTotpRegistrationResult, StatusCode> {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/user/start-totp-registration")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
                .method(http::Method::POST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    if response.status() == StatusCode::OK {
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        return Ok(serde_json::from_slice(&body).unwrap());
    }
    Err(response.status())
}

/// confirm the totp code
#[allow(dead_code)]
pub async fn confirm_totp(
    router: &Router,
    token: &str,
    totp_challenge: &str,
) -> Result<EmptyOkResponse, StatusCode> {
    let validate_totp_request = ValidateTotpRequest {
        totp_challenge: totp_challenge.to_string(),
    };
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/user/confirm-totp-registration")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
                .method(http::Method::POST)
                .body(Body::from(
                    serde_json::to_string(&json!(validate_totp_request)).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    if response.status() == StatusCode::OK {
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        return Ok(serde_json::from_slice(&body).unwrap());
    }
    Err(response.status())
}

/// confirm the totp code
#[allow(dead_code)]
pub async fn validate_totp_with_backup_code(
    router: &Router,
    token: &str,
    backup_code: &str,
) -> Result<LoginWithOtpResponse, StatusCode> {
    let validate_totp_request = ValidateTotpWithBackupCodeRequest {
        backup_code: backup_code.to_string(),
    };
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/user/validate-totp-with-backup-code")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
                .method(http::Method::POST)
                .body(Body::from(
                    serde_json::to_string(&json!(validate_totp_request)).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    if response.status() == StatusCode::OK {
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        return Ok(serde_json::from_slice(&body).unwrap());
    }
    Err(response.status())
}

/// validate totp code
#[allow(dead_code)]
pub async fn validate_totp(
    router: &Router,
    token: &str,
    totp_challenge: &str,
) -> Result<LoginWithOtpResponse, StatusCode> {
    let validate_totp_request = ValidateTotpRequest {
        totp_challenge: totp_challenge.to_string(),
    };
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/user/validate-totp")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
                .method(http::Method::POST)
                .body(Body::from(
                    serde_json::to_string(&json!(validate_totp_request)).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    if response.status() == StatusCode::OK {
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        return Ok(serde_json::from_slice(&body).unwrap());
    }
    Err(response.status())
}

/// Get avatar by the user_id.
#[allow(dead_code)]
pub async fn get_avatar(router: &Router, token: &str) -> Result<GetAvatarResponse, StatusCode> {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/user/avatar")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
                .method(http::Method::GET)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    if response.status() == StatusCode::OK {
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        return Ok(serde_json::from_slice(&body).unwrap());
    }
    Err(response.status())
}

/// Create or update avatar by the user_id.
#[allow(dead_code)]
pub async fn create_or_update_avatar(
    router: &Router,
    token: &str,
    update_avatar_request: &UpdateAvatarRequest,
) -> Result<UpdateAvatarResponse, StatusCode> {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/user/avatar")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
                .method(http::Method::POST)
                .body(Body::from(
                    serde_json::to_string(&json!(update_avatar_request)).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    if response.status() == StatusCode::OK {
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        return Ok(serde_json::from_slice(&body).unwrap());
    }
    Err(response.status())
}

/// Delete avatar by the user_id.
#[allow(dead_code)]
pub async fn delete_avatar(
    router: &Router,
    token: &str,
) -> Result<UpdateAvatarResponse, StatusCode> {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/user/avatar")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
                .method(http::Method::DELETE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    if response.status() == StatusCode::OK {
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        return Ok(serde_json::from_slice(&body).unwrap());
    }
    Err(response.status())
}

/// Approve the user.
#[allow(dead_code)]
pub async fn approve_user(router: &Router, token: &str, user_id: &str) -> Result<bool, StatusCode> {
    let request = ApproveUserRequest {
        approve_user_id: user_id.to_string(),
    };
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/authorization/user/approval")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
                .method(http::Method::POST)
                .body(Body::from(serde_json::to_string(&json!(request)).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    if response.status() == StatusCode::OK {
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        return Ok(serde_json::from_slice(&body).unwrap());
    }
    Err(response.status())
}

/// Add an authorization record for a user.
#[allow(dead_code)]
pub async fn add_authorization(
    router: &Router,
    token: &str,
    add_authorization_request: &AddAuthorizationRequest,
) -> Result<Authorization, StatusCode> {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/authorization")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
                .method(http::Method::POST)
                .body(Body::from(
                    serde_json::to_string(&json!(add_authorization_request)).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    if response.status() == StatusCode::OK {
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        return Ok(serde_json::from_slice(&body).unwrap());
    }
    Err(response.status())
}

/// Is user authorized.
#[allow(dead_code)]
pub async fn is_authorized(
    router: &Router,
    token: &str,
    is_authorized_request: &IsAuthorizedRequest,
) -> Result<IsAuthorizedResponse, StatusCode> {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/authorization/user")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
                .method(http::Method::POST)
                .body(Body::from(
                    serde_json::to_string(&json!(is_authorized_request)).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    if response.status() == StatusCode::OK {
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        return Ok(serde_json::from_slice(&body).unwrap());
    }
    Err(response.status())
}

/// Create a jwt-api token.
#[allow(dead_code)]
pub async fn create_jwt_api(
    router: &Router,
    token: &str,
    public_token_id: &str,
) -> Result<CreateJwtApiResponse, StatusCode> {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/user/jwt-api-token")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
                .method(http::Method::POST)
                .body(Body::from(
                    serde_json::to_string(&json!(&CreateJwtApiRequest {
                        public_token_id: public_token_id.to_string(),
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    if response.status() == StatusCode::OK {
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        return Ok(serde_json::from_slice(&body).unwrap());
    }
    Err(response.status())
}

/// Check a jwt-api token.
#[allow(dead_code)]
pub async fn is_jwt_api_valid(
    router: &Router,
    jwt_api_token: &str,
) -> Result<IsAuthorizedResponse, StatusCode> {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/authorization/jwt-api-token")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .method(http::Method::POST)
                .body(Body::from(
                    serde_json::to_string(&json!(&IsJwtApiTokenValidRequest {
                        token: jwt_api_token.to_string(),
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    if response.status() == StatusCode::OK {
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        return Ok(serde_json::from_slice(&body).unwrap());
    }
    Err(response.status())
}

/// Delete a jwt-api token.
#[allow(dead_code)]
pub async fn delete_jwt_api_token(
    router: &Router,
    token: &str,
    public_token_id: &str,
) -> Result<EmptyOkResponse, StatusCode> {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/user/jwt-api-token/{}", public_token_id))
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
                .method(http::Method::DELETE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    if response.status() == StatusCode::OK {
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        return Ok(serde_json::from_slice(&body).unwrap());
    }
    Err(response.status())
}
