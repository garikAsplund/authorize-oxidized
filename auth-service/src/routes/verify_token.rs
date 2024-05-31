use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;

use crate::{domain::AuthAPIError, utils::auth::validate_token};

pub async fn verify_token( Json(request): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    match validate_token(&request.token).await {
        Ok(_) => return Ok(StatusCode::OK.into_response()),
        Err(_) => return Err(AuthAPIError::InvalidToken),
    };
}

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}