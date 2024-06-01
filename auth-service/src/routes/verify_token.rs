use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;

use crate::{app_state::AppState, domain::AuthAPIError, utils::auth::validate_token};

pub async fn verify_token(
    State(state): State<AppState>,
    Json(request): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    match validate_token(&request.token, state.banned_token_store.clone()).await {
        Ok(_) => return Ok(StatusCode::OK.into_response()),
        Err(_) => return Err(AuthAPIError::InvalidToken),
    };
}

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}
