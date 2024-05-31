use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password},
    utils::auth::generate_auth_cookie,
};

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let email = match
        Email::parse(request.email) {
            Ok(email) => email,
            Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
        };
    let password = match
        Password::parse(request.password) {
            Ok(password) => password,
            Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
        };

    let user_store = &state.user_store.read().await;

    // TODO: call `user_store.validate_user` and return
    // `AuthAPIError::IncorrectCredentials` if validation fails.
    if user_store.validate_user(&email, &password).await.is_err() {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }

    // TODO: call `user_store.get_user`. Return AuthAPIError::IncorrectCredentials if the operation fails.
    let user = match user_store.get_user(&email).await {
        Ok(user) => user,
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
    };

     // Call the generate_auth_cookie function defined in the auth module.
    // If the function call fails return AuthAPIError::UnexpectedError.
    let auth_cookie = match generate_auth_cookie(&user.email) {
        Ok(cookie) => cookie,
        Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
    };

    let updated_jar = jar.add(auth_cookie);

    (updated_jar, Ok(StatusCode::OK.into_response()))
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}
