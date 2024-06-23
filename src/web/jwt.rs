use jsonwebtoken::{DecodingKey, EncodingKey};
use once_cell::sync::Lazy;
use std::env;

///环境变量密钥，
pub static KEYS: Lazy<Keys> = Lazy::new(|| {
    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    // Keys::new(secret.as_bytes())
    Keys::new(secret.as_ref())
});

///认证错误类型
#[derive(Debug)]
pub enum AuthError {
    WrongCredentials,   //错误的凭据
    MissingCredentials, //丢失凭据
    TokenCreation,      //令牌创建
    InvalidToken,       //无效令牌
}
pub struct Keys {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
}
impl Keys {
    fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

// auth.rs
use super::jwt::KEYS;
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    Json,
};
use common::{cookie::get_cookie, response::RespVO};

use jsonwebtoken::{decode, Validation};
use serde::{Deserialize, Serialize};
use sqlx::{Decode, Encode, Type};

// An extractor that performs authorization.
#[derive(Debug, Clone, Serialize, Deserialize, Decode, Encode, Type)]
pub struct Claims {
    pub username: String,
    pub password: String,
    pub exp: Option<i32>,
}

#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = Json<RespVO<String>>;
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // let TypedHeader(Authorization(bearer)) = parts
        //     .extract::<TypedHeader<Authorization<Bearer>>>()
        //     .await
        //     .map_err(|_| {
        //         Json(RespVO::<String>::from_error_info(
        //             StatusCode::UNAUTHORIZED,
        //             "未认证",
        //         ))
        //     })?;

        // Decode the user data
        // let token = bearer.token();
        // let token_data = decode::<Claims>(&token.to_string(), &KEYS.decoding, &Validation::default())
        //     .map_err(|_| {
        //     Json(RespVO::<String>::from_error_info(
        //         StatusCode::UNAUTHORIZED,
        //         "token无效",
        //     ))
        // })?;

        // Ok(token_data.claims)
        // 方式二，自动获取token
        let token = get_cookie(&parts.headers, "MERGE_TOKEN");
        // println!("{:#?}",token);
        // println!("{:#?}",bearer.token());
        match token {
            Some(token) => {
                let token_data =
                    decode::<Claims>(&token.to_string(), &KEYS.decoding, &Validation::default())
                        .map_err(|_| {
                            Json(RespVO::<String>::from_error_info(
                                StatusCode::UNAUTHORIZED,
                                "token无效",
                            ))
                        })?;
                Ok(token_data.claims)
            }
            _ => Err(Json(RespVO::<String>::from_error_info(
                StatusCode::UNAUTHORIZED,
                "未认证",
            ))),
        }
    }
}
