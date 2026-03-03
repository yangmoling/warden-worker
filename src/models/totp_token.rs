use serde::{Deserialize, Serialize};

/// 独立 TOTP 令牌，明文存储 secret，服务端可直接生成验证码
#[derive(Debug, Serialize, Deserialize)]
pub struct TotpToken {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub secret: String,
    pub issuer: Option<String>,
    pub digits: i32,
    pub period: i32,
    pub algorithm: String,
    pub created_at: String,
    pub updated_at: String,
}

/// API 响应格式
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpTokenResponse {
    pub id: String,
    pub name: String,
    pub issuer: Option<String>,
    pub token: String,
    pub digits: i32,
    pub period: i32,
    pub object: String,
}

/// 创建/更新请求体
#[derive(Debug, Deserialize)]
pub struct CreateTotpTokenRequest {
    pub name: String,
    pub secret: String,
    #[serde(default)]
    pub issuer: Option<String>,
}
