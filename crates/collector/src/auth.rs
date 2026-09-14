use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use getrandom::fill;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{CollectorState, bearer_token, hash_token, random_hex, unix_time_ms};

const SESSION_LIFETIME_MS: u64 = 7 * 24 * 60 * 60 * 1_000;

pub(crate) fn router() -> Router<CollectorState> {
    Router::new()
        .route("/internal/auth/status", get(status))
        .route("/internal/auth/setup", post(setup))
        .route("/internal/auth/login", post(login))
        .route("/internal/auth/verify", post(verify))
        .route("/internal/auth/logout", post(logout))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Credentials {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct SessionResponse {
    schema_version: u8,
    data: SessionData,
}

#[derive(Serialize)]
struct SessionData {
    user: UserData,
    session_token: String,
    expires_at: u64,
}

#[derive(Serialize)]
struct UserData {
    id: String,
    username: String,
}

async fn status(State(state): State<CollectorState>) -> Response {
    match state.lock().storage.admin_exists() {
        Ok(exists) => Json(json!({
            "schema_version": 1,
            "data": { "setup_required": !exists }
        }))
        .into_response(),
        Err(_) => auth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            "authentication storage is unavailable",
        ),
    }
}

async fn setup(
    State(state): State<CollectorState>,
    Json(credentials): Json<Credentials>,
) -> Response {
    if let Err(message) = validate_credentials(&credentials) {
        return auth_error(StatusCode::BAD_REQUEST, "invalid_credentials", message);
    }
    match state.lock().storage.admin_exists() {
        Ok(true) => {
            return auth_error(
                StatusCode::CONFLICT,
                "setup_complete",
                "the administrator has already been created",
            );
        }
        Ok(false) => {}
        Err(_) => return storage_error(),
    }

    let password = credentials.password.into_bytes();
    let Ok(Ok(password_hash)) = tokio::task::spawn_blocking(move || hash_password(&password)).await
    else {
        return auth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "hash_error",
            "password hashing failed",
        );
    };
    let Ok(user_id) = random_hex(16) else {
        return random_error();
    };
    let created = state.lock().storage.create_admin(
        &user_id,
        &credentials.username,
        &password_hash,
        unix_time_ms(),
    );
    match created {
        Ok(true) => issue_session(&state, user_id, credentials.username),
        Ok(false) => auth_error(
            StatusCode::CONFLICT,
            "setup_complete",
            "the administrator has already been created",
        ),
        Err(_) => storage_error(),
    }
}

async fn login(
    State(state): State<CollectorState>,
    Json(credentials): Json<Credentials>,
) -> Response {
    if credentials.username.is_empty() || credentials.password.is_empty() {
        return invalid_login();
    }
    let user = match state.lock().storage.user_by_username(&credentials.username) {
        Ok(Some(user)) => user,
        Ok(None) => return invalid_login(),
        Err(_) => return storage_error(),
    };
    let password = credentials.password.into_bytes();
    let encoded = user.password_hash.clone();
    let valid = tokio::task::spawn_blocking(move || verify_password(&password, &encoded))
        .await
        .unwrap_or(false);
    if !valid {
        return invalid_login();
    }
    issue_session(&state, user.id, user.username)
}

async fn verify(State(state): State<CollectorState>, headers: HeaderMap) -> Response {
    let Some(token) = bearer_token(&headers) else {
        return auth_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "a valid session is required",
        );
    };
    match state
        .lock()
        .storage
        .session(&hash_token(token), unix_time_ms())
    {
        Ok(Some(session)) => Json(json!({
            "schema_version": 1,
            "data": {
                "user": { "id": session.user_id, "username": session.username },
                "expires_at": session.expires_at
            }
        }))
        .into_response(),
        Ok(None) => auth_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "a valid session is required",
        ),
        Err(_) => storage_error(),
    }
}

async fn logout(State(state): State<CollectorState>, headers: HeaderMap) -> Response {
    let Some(token) = bearer_token(&headers) else {
        return StatusCode::NO_CONTENT.into_response();
    };
    match state.lock().storage.delete_session(&hash_token(token)) {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => storage_error(),
    }
}

fn issue_session(state: &CollectorState, user_id: String, username: String) -> Response {
    let Ok(session_token) = random_hex(32) else {
        return random_error();
    };
    let now = unix_time_ms();
    let expires_at = now.saturating_add(SESSION_LIFETIME_MS);
    if state
        .lock()
        .storage
        .create_session(&user_id, &hash_token(&session_token), now, expires_at)
        .is_err()
    {
        return storage_error();
    }
    Json(SessionResponse {
        schema_version: 1,
        data: SessionData {
            user: UserData {
                id: user_id,
                username,
            },
            session_token,
            expires_at,
        },
    })
    .into_response()
}

fn validate_credentials(credentials: &Credentials) -> Result<(), &'static str> {
    let username = credentials.username.as_bytes();
    if username.len() < 3
        || username.len() > 32
        || !username
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err("username must be 3-32 ASCII letters, digits, dots, dashes, or underscores");
    }
    if credentials.password.len() < 12 || credentials.password.len() > 128 {
        return Err("password must be between 12 and 128 bytes");
    }
    Ok(())
}

fn hash_password(password: &[u8]) -> Result<String, argon2::password_hash::Error> {
    let mut salt = [0_u8; 16];
    fill(&mut salt).map_err(|_| argon2::password_hash::Error::Crypto)?;
    let salt = SaltString::encode_b64(&salt)?;
    Argon2::default()
        .hash_password(password, &salt)
        .map(|hash| hash.to_string())
}

fn verify_password(password: &[u8], encoded: &str) -> bool {
    PasswordHash::new(encoded)
        .is_ok_and(|hash| Argon2::default().verify_password(password, &hash).is_ok())
}

fn invalid_login() -> Response {
    auth_error(
        StatusCode::UNAUTHORIZED,
        "invalid_login",
        "invalid username or password",
    )
}

fn storage_error() -> Response {
    auth_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "storage_error",
        "authentication storage is unavailable",
    )
}

fn random_error() -> Response {
    auth_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "random_error",
        "secure token generation failed",
    )
}

fn auth_error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(json!({
            "schema_version": 1,
            "error": { "code": code, "message": message }
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_use_argon2id_and_verify() {
        let hash = hash_password(b"correct horse battery staple").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password(b"correct horse battery staple", &hash));
        assert!(!verify_password(b"incorrect", &hash));
    }
}
