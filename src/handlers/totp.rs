use axum::extract::{Path, State};
use axum::Json;
use chrono::Utc;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;
use worker::{query, Env};

use crate::auth::Claims;
use crate::crypto::{base32_decode, generate_totp};
use crate::db;
use crate::error::AppError;
use crate::models::totp_token::{CreateTotpTokenRequest, TotpToken, TotpTokenResponse};

// ============================================================================
// 公开 API（无认证）
// ============================================================================

/// GET /api/totp/{secret} - 无认证 TOTP 计算器，兼容 2fa.live 格式
#[worker::send]
pub async fn get_totp_by_secret(
    Path(secret): Path<String>,
) -> Result<Json<Value>, AppError> {
    // 校验 Base32 格式
    base32_decode(&secret.to_uppercase())?;
    let time_step = (Utc::now().timestamp() / 30) as u64;
    let token = generate_totp(&secret.to_uppercase(), time_step).await?;
    Ok(Json(json!({ "token": token })))
}

// ============================================================================
// 认证 API（需要 JWT）
// ============================================================================

/// GET /api/totp-tokens - 列出当前用户所有 TOTP 令牌并附带实时验证码
#[worker::send]
pub async fn list_totp_tokens(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    let tokens: Vec<TotpToken> = db
        .prepare("SELECT * FROM totp_tokens WHERE user_id = ?1 ORDER BY name")
        .bind(&[claims.sub.clone().into()])?
        .all()
        .await?
        .results()
        .map_err(|_| AppError::Database)?;

    let now = Utc::now().timestamp();
    let mut responses = Vec::with_capacity(tokens.len());
    for t in &tokens {
        let step = (now / t.period as i64) as u64;
        let code = generate_totp(&t.secret, step).await?;
        responses.push(TotpTokenResponse {
            id: t.id.clone(),
            name: t.name.clone(),
            issuer: t.issuer.clone(),
            token: code,
            digits: t.digits,
            period: t.period,
            object: "totpToken".to_string(),
        });
    }

    Ok(Json(json!({
        "data": responses,
        "object": "list",
        "continuationToken": null,
    })))
}

/// GET /api/totp-tokens/{id} - 获取单个令牌及实时验证码
#[worker::send]
pub async fn get_totp_token(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<TotpTokenResponse>, AppError> {
    let db = db::get_db(&env)?;

    let t: TotpToken = query!(
        &db,
        "SELECT * FROM totp_tokens WHERE id = ?1 AND user_id = ?2",
        &id,
        &claims.sub
    )
    .map_err(|_| AppError::Database)?
    .first(None)
    .await?
    .ok_or_else(|| AppError::NotFound("TOTP token not found".to_string()))?;

    let step = (Utc::now().timestamp() / t.period as i64) as u64;
    let code = generate_totp(&t.secret, step).await?;

    Ok(Json(TotpTokenResponse {
        id: t.id,
        name: t.name,
        issuer: t.issuer,
        token: code,
        digits: t.digits,
        period: t.period,
        object: "totpToken".to_string(),
    }))
}

/// POST /api/totp-tokens - 新增 TOTP 令牌
#[worker::send]
pub async fn create_totp_token(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<CreateTotpTokenRequest>,
) -> Result<Json<TotpTokenResponse>, AppError> {
    let db = db::get_db(&env)?;
    let secret = payload.secret.to_uppercase();

    // 校验 Base32 格式
    let decoded = base32_decode(&secret)?;
    if decoded.is_empty() {
        return Err(AppError::BadRequest("Invalid TOTP secret".to_string()));
    }

    let now = Utc::now();
    let now_str = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let id = Uuid::new_v4().to_string();

    query!(
        &db,
        "INSERT INTO totp_tokens (id, user_id, name, secret, issuer, digits, period, algorithm, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        &id,
        &claims.sub,
        &payload.name,
        &secret,
        &payload.issuer.as_deref().unwrap_or(""),
        6,
        30,
        "SHA1",
        &now_str,
        &now_str
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let step = (now.timestamp() / 30) as u64;
    let code = generate_totp(&secret, step).await?;

    Ok(Json(TotpTokenResponse {
        id,
        name: payload.name,
        issuer: payload.issuer,
        token: code,
        digits: 6,
        period: 30,
        object: "totpToken".to_string(),
    }))
}

/// DELETE /api/totp-tokens/{id} - 删除 TOTP 令牌
#[worker::send]
pub async fn delete_totp_token(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;

    query!(
        &db,
        "DELETE FROM totp_tokens WHERE id = ?1 AND user_id = ?2",
        &id,
        &claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    Ok(Json(()))
}
