use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::{cookie, CookieJar};

use crate::{
    app_state::AppState, domain::AuthAPIError, utils::{auth::validate_token, constants::JWT_COOKIE_NAME}
};

#[tracing::instrument(name = "Logging out", skip_all)]
pub async fn logout(State(state): State<AppState>, jar: CookieJar) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    // Retrieve JWT cookie from the `CookieJar`
    // Return AuthAPIError::MissingToken is the cookie is not found
    let cookie = match jar.get(JWT_COOKIE_NAME) {
        Some(cookie) => cookie,
        None => return (jar, Err(AuthAPIError::MissingToken)),
    };

    let token = cookie.value().to_owned();

    // TODO: Validate JWT token by calling `validate_token` from the auth service.
    // If the token is valid you can ignore the returned claims for now.
    // Return AuthAPIError::InvalidToken is validation fails.
    if validate_token(&token, state.banned_token_store.clone()).await.is_err() {
        return (jar, Err(AuthAPIError::InvalidToken));
    }

    let jar = jar.remove(cookie::Cookie::from(JWT_COOKIE_NAME));

    if let Err(e) = state.banned_token_store.write().await.ban_token(token).await {
        return (jar, Err(AuthAPIError::UnexpectedError(e.into())));
    }

    (jar, Ok(StatusCode::OK))
}
