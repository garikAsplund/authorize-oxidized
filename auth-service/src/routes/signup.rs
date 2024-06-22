use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use secrecy::Secret;
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password, User},
};

#[tracing::instrument(name = "Signup", skip_all)]
pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let email =
        Email::parse(request.email.clone()).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let password =
        Password::parse(request.password.clone()).map_err(|_| AuthAPIError::InvalidCredentials)?;

    // TODO: early return AuthAPIError::InvalidCredentials if:
    // - email is empty or does not contain '@'
    // - password is less than 8 characters
    // if email.is_empty() || password.len() < 8 || !email.contains('@') {
    //     return Err(AuthAPIError::InvalidCredentials);
    // }

    let user = User::new(email, password, request.requires_2fa);

    let mut user_store = state.user_store.write().await;

    // TODO: early return AuthAPIError::UserAlreadyExists if email exists in user_store.
    if user_store.get_user(&user.email).await.is_ok() {
        return Err(AuthAPIError::UserAlreadyExists);
    }

    // TODO: instead of using unwrap, early return AuthAPIError::UnexpectedError if add_user() fails.
    if let Err(e) = user_store.add_user(user).await {
        return Err(AuthAPIError::UnexpectedError(e.into()));
    }

    let response = Json(SignupResponse {
        message: "User created successfully!".to_string(),
    });

    Ok((StatusCode::CREATED, response))
}

#[derive(Serialize)]
pub struct SignupResponse {
    pub message: String,
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: Secret<String>,
    pub password: Secret<String>,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}
