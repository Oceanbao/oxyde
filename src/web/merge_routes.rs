use axum::{middleware::from_extractor, routing::MethodRouter, Router};
// api
use super::auth;
use middleware::auth::Claims;
//构建路由公共方法
pub fn handle_router(path: &str, method_router: MethodRouter) -> Router {
    let _path = format!("/api{}", path); // 统一api 路径
    Router::new().route(&_path, method_router)
}

//api 路由入口
pub fn routers() -> Router {
    auth_init_router().merge(init_router())
}

//需要权限认证的路由
fn auth_init_router() -> Router {
    let app = Router::new()
        .merge(auth::get_user_list())
        .layer(from_extractor::<Claims>());
    return app;
}

//不需要权限认证的路由
fn init_router() -> Router {
    let app = Router::new()
        .merge(auth::login()) //登录
        .merge(auth::register()); //注册
    return app;
}

// api.rs
use super::handler::{
    authorize,
    get_user_list as get_user_lists,
    login as user_login,
    // update_user as update_user_info,
};
use crate::init::handle_router;
use axum::{
    routing::{get, post},
    Router,
};

//注册
pub fn register() -> Router {
    //构建注册路由
    handle_router("/register", post(authorize))
}

//登录
pub fn login() -> Router {
    //构建登录路由
    handle_router("/login", post(user_login))
}

//查询用户信息列表
pub fn get_user_list() -> Router {
    //构建登录路由
    handle_router("/user-list", get(get_user_lists))
}

// dto.rs
use serde::{Deserialize, Serialize};
use sqlx::{Decode, Encode, FromRow, Type};

//token结构体
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthToken {
    pub access_token: String,
    pub token_type: String,
}

impl AuthToken {
    pub fn new(access_token: String) -> Self {
        Self {
            access_token,
            token_type: "Bearer".to_string(),
        }
    }
}

//注册请求体
#[derive(Debug, Clone, Deserialize, Serialize, Decode, Encode, Type, FromRow)]
pub struct AuthPayload {
    pub password: String,
    pub username: String,
    pub cred: String,
    pub email: String,
}

// 信息列表请求体
#[derive(Debug, Clone, Deserialize, Serialize, Decode, Encode, Type, FromRow)]
pub struct LianxXiPayload {
    pub name: String,
    pub age: i32,
    pub create_date: String,
    pub update_date: String,
}

//Token 生成
#[derive(Debug, Clone, Deserialize, Serialize, Decode, Encode, Type, FromRow)]
pub struct AuthPayToken {
    pub password: String,
    pub username: String,
    pub exp: Option<i32>,
}
//登录请求体
#[derive(Debug, Clone, Deserialize, Serialize, Decode, Encode, Type, FromRow)]
pub struct LoginPayload {
    pub username: String,
    pub password: String,
}

//登录响应体
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoginResponse {
    pub username: String,
    pub access_token: String,
    pub token_type: String,
}

// handler.rs
use axum::{
    http::{
        header::{
            SET_COOKIE,
            HeaderMap
        }
    },
    response::{
        IntoResponse,
    },
    Json
};
use jsonwebtoken::{encode, Header};
use super::{
    servers,
    dto::{
        AuthPayload,
        AuthToken,
        LoginPayload,
        LoginResponse,
        AuthPayToken,
        LianxXiPayload
    }
};
use common::response::RespVO;
use middleware::{
    jwt::KEYS,
};

const COOKIE_NAME: &'static str = "MERGE_TOKEN";

//注册
pub async fn authorize(Json(payload): Json<AuthPayload>) -> impl IntoResponse {
    // 检查用户名
    if payload.username.is_empty() {
        return Json(RespVO::<AuthToken>::from_error("用户名不能为空！"));
    } else if payload.password.is_empty() {
        return Json(RespVO::<AuthToken>::from_error("密码不能为空！"));
    }
    // 查询用户是否注册过
    let search_result = servers::show(&payload.username).await;
    match search_result {
        Ok(res) => {
            // 查询用户存
            if payload.username == res.username {
                return Json(RespVO::<AuthToken>::from_result_tip("用户名已注册！"));
            };
        },
        Err(_err) => {
            // 查询用户不存在
        }
    }

    let result = servers::create(payload.clone()).await;
    match result {
        Ok(res) => {
            if res == 1 {
                Json(RespVO::<AuthToken>::from_result_tip("注册成功！"))
            } else {
                Json(RespVO::<AuthToken>::from_error("写入数据库失败！"))
            }
        }
        Err(err) => {
            let info = err.to_string();
            Json(RespVO::<AuthToken>::from_error(&info))
        }
    }
}

//创建token
fn init_token(payload: AuthPayload) -> String {
    let claims = AuthPayToken {
        username: payload.username.to_owned(),
        password: payload.password.to_owned(),
        exp: Some(2000000000),
    };
    //创建token， Create the authorization token
    let token = encode(&Header::default(), &claims, &KEYS.encoding)
        .map_err(|_| Json(RespVO::<AuthToken>::from_error("token创建失败！")))
        .unwrap();
    token
}
//登录
pub async fn login(Json(body): Json<LoginPayload>) -> (HeaderMap, Json<RespVO::<LoginResponse>>) {
    let mut headers = HeaderMap::new();
    let result = servers::show(&body.username).await;
    match result {
        Ok(res) => {
            if body.password != res.password {
                return (headers, Json(RespVO::<LoginResponse>::from_error("密码错误！")));
            }
            let token = init_token(res.clone());
            // 3、把token写入cookie
            // response.addHeader("Set-Cookie", "uid=112; Path=/; Secure; HttpOnly");
            let cookie = format!("{}={};HTTPOnly", COOKIE_NAME, &token);
            headers.insert(
                SET_COOKIE,
                cookie.as_str().parse().unwrap(),
            ); // 设置Cookie
            // 4、token 返回给用户
            let arg = AuthToken::new(token);
            let params = LoginResponse {
                username: res.username,
                access_token: arg.access_token,
                token_type: arg.token_type,
            };
            (headers, Json(RespVO::<LoginResponse>::from_result(&params)))
        }
        Err(_err) => {
            (headers, Json(RespVO::<LoginResponse>::from_error("用户名无效！")))
        }
    }
}
//查询用户信息列表
pub async fn get_user_list() -> impl IntoResponse {
   let result = servers::list().await;
   match result {
       Ok(res) => Json(RespVO::<Vec<LianxXiPayload>>::from_result(&res)),
       Err(err) => {
           let info = err.to_string();
           Json(RespVO::<Vec<LianxXiPayload>>::from_error(&info))
       }
   }
}

// server.rs
use sqlx::{self, Error};
use super::dto::{
    AuthPayload,
    LianxXiPayload
};
use db::{
    mysql
};

pub async fn create(user: AuthPayload) -> Result<u64, Error> {
    let sql = "insert into user(email, username, cred, password) values (?, ?, ?, ?)";
    let pool = mysql::get_pool().unwrap();
    let affect_rows = sqlx::query(sql)
        .bind(&user.email)
        .bind(&user.username)
        .bind(&user.cred)
        .bind(&user.password)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(affect_rows)
}

/**
 * 测试接口: 查 列表
 */
// pub async fn list() -> Result<Vec<AuthPayload>, Error> {
//     let pool = mysql::get_pool().unwrap();
//     let sql =
//         "select email, username, cred, password from user";
//     let list = sqlx::query_as::<_, AuthPayload>(sql)
//         .fetch_all(pool)
//         .await?;
//     Ok(list)
// }
/**
 * 测试接口: 查 列表
 */
pub async fn list() -> Result<Vec<LianxXiPayload>, Error> {
    let pool = mysql::get_pool().unwrap();
    let sql =
        "select name, age, create_date, update_date from lianxi_user";
    let list = sqlx::query_as::<_, LianxXiPayload>(sql)
        .fetch_all(pool)
        .await?;
    Ok(list)
}

/**
 * 测试接口: 查
 */
pub async fn show(username: &str) -> Result<AuthPayload, Error> {
    let sql = "select email, username, cred, password from user where username = ?";
    let pool = mysql::get_pool().unwrap();
    let res = sqlx::query_as::<_, AuthPayload>(sql)
        .bind(username)
        .fetch_one(pool)
        .await?;
    Ok(res)
}

