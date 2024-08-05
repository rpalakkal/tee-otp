use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use crate::{otp::TOTP, SharedState, User};

#[derive(Deserialize)]
pub struct GenerateOTPQuery {
    pub account_id: String,
}

#[derive(Serialize)]
pub struct GenerateOTPResponse {
    pub otp_qr_code: String,
}

#[derive(Deserialize)]
pub struct VerifyQuery {
    pub account_id: String,
    pub token: String,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub is_valid: bool,
}

pub async fn generate_otp(
    State(shared_state): State<SharedState<String>>,
    Json(query): Json<GenerateOTPQuery>,
) -> Json<GenerateOTPResponse> {
    let mut users = shared_state.users.lock().unwrap();
    let totp = TOTP::random(query.account_id.clone());
    let user = User {
        secret: totp.secret(),
        enabled: false,
    };
    users.insert(query.account_id, user);
    Json(GenerateOTPResponse {
        otp_qr_code: format!("data:image/png;base64,{}", totp.qr()),
    })
}

pub async fn register(
    State(shared_state): State<SharedState<String>>,
    Json(query): Json<VerifyQuery>,
) -> Json<VerifyResponse> {
    let mut users = shared_state.users.lock().unwrap();
    let user = users.get_mut(&query.account_id).unwrap();
    let totp = TOTP::from_secret(query.account_id.clone(), user.secret.clone());
    let is_valid = totp.verify(query.token);
    if is_valid {
        user.enabled = true;
    }
    Json(VerifyResponse { is_valid })
}

pub async fn verify(
    State(shared_state): State<SharedState<String>>,
    Json(query): Json<VerifyQuery>,
) -> Json<VerifyResponse> {
    let users = shared_state.users.lock().unwrap();
    let user = users.get(&query.account_id).unwrap();
    let totp = TOTP::from_secret(query.account_id.clone(), user.secret.clone());
    let is_valid = totp.verify(query.token);
    Json(VerifyResponse {
        is_valid: is_valid && user.enabled,
    })
}
