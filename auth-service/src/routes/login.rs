use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password, User},
};

pub async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let email =
        Email::parse(request.email.clone()).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let password =
        Password::parse(request.password.clone()).map_err(|_| AuthAPIError::InvalidCredentials)?;

    let user_store = &state.user_store.read().await;

    // TODO: call `user_store.validate_user` and return
    // `AuthAPIError::IncorrectCredentials` if validation fails.
    if user_store.validate_user(&email, &password).await.is_err() {
        return Err(AuthAPIError::IncorrectCredentials);
    }

    // TODO: call `user_store.get_user`. Return AuthAPIError::IncorrectCredentials if the operation fails.
    match user_store.get_user(&email).await {
        Ok(user) => {
            // Add your logic here to create a session or JWT token
            Ok(StatusCode::OK.into_response())
        }
        Err(_) => Err(AuthAPIError::IncorrectCredentials),
    }
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub message: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}
