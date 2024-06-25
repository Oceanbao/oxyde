/*
create table "user"
(
    user_id       uuid primary key default gen_random_uuid(),
    username      text unique not null,
    password_hash text        not null
);

create table post (
    post_id uuid primary key default gen_random_uuid(),
    user_id uuid not null references "user"(user_id),
    content text not null,
    created_at timestamptz not null default now()
);

create index on post(created_at desc);

create table comment (
    comment_id uuid primary key default gen_random_uuid(),
    post_id uuid not null references post(post_id),
    user_id uuid not null references "user"(user_id),
    content text not null,
    created_at timestamptz not null default now()
);

create index on comment(post_id, created_at);
*/

// password.rs
use anyhow::{anyhow, Context};
use tokio::task;

use argon2::password_hash::SaltString;
use argon2::{password_hash, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

pub async fn hash(password: String) -> anyhow::Result<String> {
    task::spawn_blocking(move || {
        let salt = SaltString::generate(rand::thread_rng());
        Ok(Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow!(e).context("failed to hash password"))?
            .to_string())
    })
    .await
    .context("panic in hash()")?
}

pub async fn verify(password: String, hash: String) -> anyhow::Result<bool> {
    task::spawn_blocking(move || {
        let hash = PasswordHash::new(&hash)
            .map_err(|e| anyhow!(e).context("BUG: password hash invalid"))?;

        let res = Argon2::default().verify_password(password.as_bytes(), &hash);

        match res {
            Ok(()) => Ok(true),
            Err(password_hash::Error::Password) => Ok(false),
            Err(e) => Err(anyhow!(e).context("failed to verify password")),
        }
    })
    .await
    .context("panic in verify()")?
}

// /http/mod.rs
use anyhow::Context;
use axum::{Extension, Router};
use sqlx::PgPool;

mod error;

mod post;
mod user;

pub use self::error::Error;

pub type Result<T, E = Error> = ::std::result::Result<T, E>;

pub fn app(db: PgPool) -> Router {
    Router::new()
        .merge(user::router())
        .merge(post::router())
        .layer(Extension(db))
}

pub async fn serve(db: PgPool) -> anyhow::Result<()> {
    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app(db).into_make_service())
        .await
        .context("failed to serve API")
}

// errors.rs
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use serde_with::DisplayFromStr;
use validator::ValidationErrors;

/// An API-friendly error type.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// A SQLx call returned an error.
    ///
    /// The exact error contents are not reported to the user in order to avoid leaking
    /// information about databse internals.
    #[error("an internal database error occurred")]
    Sqlx(#[from] sqlx::Error),

    /// Similarly, we don't want to report random `anyhow` errors to the user.
    #[error("an internal server error occurred")]
    Anyhow(#[from] anyhow::Error),

    #[error("validation error in request body")]
    InvalidEntity(#[from] ValidationErrors),

    #[error("{0}")]
    UnprocessableEntity(String),

    #[error("{0}")]
    Conflict(String),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        #[serde_with::serde_as]
        #[serde_with::skip_serializing_none]
        #[derive(serde::Serialize)]
        struct ErrorResponse<'a> {
            // Serialize the `Display` output as the error message
            #[serde_as(as = "DisplayFromStr")]
            message: &'a Error,

            errors: Option<&'a ValidationErrors>,
        }

        let errors = match &self {
            Error::InvalidEntity(errors) => Some(errors),
            _ => None,
        };

        // Normally you wouldn't just print this, but it's useful for debugging without
        // using a logging framework.
        println!("API error: {self:?}");

        (
            self.status_code(),
            Json(ErrorResponse {
                message: &self,
                errors,
            }),
        )
            .into_response()
    }
}

impl Error {
    fn status_code(&self) -> StatusCode {
        use Error::*;

        match self {
            Sqlx(_) | Anyhow(_) => StatusCode::INTERNAL_SERVER_ERROR,
            InvalidEntity(_) | UnprocessableEntity(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Conflict(_) => StatusCode::CONFLICT,
        }
    }
}

// user.rs
use axum::http::StatusCode;
use axum::{routing::post, Extension, Json, Router};
use once_cell::sync::Lazy;
use rand::Rng;
use regex::Regex;
use std::time::Duration;

use serde::Deserialize;
use sqlx::{PgExecutor, PgPool};
use uuid::Uuid;
use validator::Validate;

use crate::http::{Error, Result};

pub type UserId = Uuid;

pub fn router() -> Router {
    Router::new().route("/v1/user", post(create_user))
}

static USERNAME_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[0-9A-Za-z_]+$").unwrap());

// CREATE USER

#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct UserAuth {
    #[validate(length(min = 3, max = 16), regex = "USERNAME_REGEX")]
    username: String,
    #[validate(length(min = 8, max = 32))]
    password: String,
}

// WARNING: this API has none of the checks that a normal user signup flow implements,
// such as email or phone verification.
async fn create_user(db: Extension<PgPool>, Json(req): Json<UserAuth>) -> Result<StatusCode> {
    req.validate()?;

    let UserAuth { username, password } = req;

    // It would be irresponsible to store passwords in plaintext, however.
    let password_hash = crate::password::hash(password).await?;

    sqlx::query!(
        // language=PostgreSQL
        r#"
            insert into "user"(username, password_hash)
            values ($1, $2)
        "#,
        username,
        password_hash
    )
    .execute(&*db)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(dbe) if dbe.constraint() == Some("user_username_key") => {
            Error::Conflict("username taken".into())
        }
        _ => e.into(),
    })?;

    Ok(StatusCode::NO_CONTENT)
}

impl UserAuth {
    // NOTE: normally we wouldn't want to verify the username and password every time,
    // but persistent sessions would have complicated the example.
    pub async fn verify(self, db: impl PgExecutor<'_> + Send) -> Result<UserId> {
        self.validate()?;

        let maybe_user = sqlx::query!(
            r#"select user_id, password_hash from "user" where username = $1"#,
            self.username
        )
        .fetch_optional(db)
        .await?;

        if let Some(user) = maybe_user {
            let verified = crate::password::verify(self.password, user.password_hash).await?;

            if verified {
                return Ok(user.user_id);
            }
        }

        // Sleep a random amount of time to avoid leaking existence of a user in timing.
        let sleep_duration =
            rand::thread_rng().gen_range(Duration::from_millis(100)..=Duration::from_millis(500));
        tokio::time::sleep(sleep_duration).await;

        Err(Error::UnprocessableEntity(
            "invalid username/password".into(),
        ))
    }
}

// post/mod.rs
use axum::{Extension, Json, Router};

use axum::routing::get;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::http::user::UserAuth;
use sqlx::PgPool;
use validator::Validate;

use crate::http::Result;

use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

mod comment;

pub fn router() -> Router {
    Router::new()
        .route("/v1/post", get(get_posts).post(create_post))
        .merge(comment::router())
}

#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
struct CreatePostRequest {
    auth: UserAuth,
    #[validate(length(min = 1, max = 1000))]
    content: String,
}

#[serde_with::serde_as]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Post {
    post_id: Uuid,
    username: String,
    content: String,
    // `OffsetDateTime`'s default serialization format is not standard.
    #[serde_as(as = "Rfc3339")]
    created_at: OffsetDateTime,
}

// #[axum::debug_handler] // very useful!
async fn create_post(
    db: Extension<PgPool>,
    Json(req): Json<CreatePostRequest>,
) -> Result<Json<Post>> {
    req.validate()?;
    let user_id = req.auth.verify(&*db).await?;

    let post = sqlx::query_as!(
        Post,
        // language=PostgreSQL
        r#"
            with inserted_post as (
                insert into post(user_id, content)
                values ($1, $2)
                returning post_id, user_id, content, created_at
            )
            select post_id, username, content, created_at
            from inserted_post
            inner join "user" using (user_id)
        "#,
        user_id,
        req.content
    )
    .fetch_one(&*db)
    .await?;

    Ok(Json(post))
}

/// Returns posts in descending chronological order.
async fn get_posts(db: Extension<PgPool>) -> Result<Json<Vec<Post>>> {
    // Note: normally you'd want to put a `LIMIT` on this as well,
    // though that would also necessitate implementing pagination.
    let posts = sqlx::query_as!(
        Post,
        // language=PostgreSQL
        r#"
            select post_id, username, content, created_at
            from post
            inner join "user" using (user_id)
            order by created_at desc
        "#
    )
    .fetch_all(&*db)
    .await?;

    Ok(Json(posts))
}

// post/comment.rs
use axum::extract::Path;
use axum::{Extension, Json, Router};

use axum::routing::get;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::http::user::UserAuth;
use sqlx::PgPool;
use validator::Validate;

use crate::http::Result;

use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

pub fn router() -> Router {
    Router::new().route(
        "/v1/post/:postId/comment",
        get(get_post_comments).post(create_post_comment),
    )
}

#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
struct CreateCommentRequest {
    auth: UserAuth,
    #[validate(length(min = 1, max = 1000))]
    content: String,
}

#[serde_with::serde_as]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Comment {
    comment_id: Uuid,
    username: String,
    content: String,
    // `OffsetDateTime`'s default serialization format is not standard.
    #[serde_as(as = "Rfc3339")]
    created_at: OffsetDateTime,
}

// #[axum::debug_handler] // very useful!
async fn create_post_comment(
    db: Extension<PgPool>,
    Path(post_id): Path<Uuid>,
    Json(req): Json<CreateCommentRequest>,
) -> Result<Json<Comment>> {
    req.validate()?;
    let user_id = req.auth.verify(&*db).await?;

    let comment = sqlx::query_as!(
        Comment,
        // language=PostgreSQL
        r#"
            with inserted_comment as (
                insert into comment(user_id, post_id, content)
                values ($1, $2, $3)
                returning comment_id, user_id, content, created_at
            )
            select comment_id, username, content, created_at
            from inserted_comment
            inner join "user" using (user_id)
        "#,
        user_id,
        post_id,
        req.content
    )
    .fetch_one(&*db)
    .await?;

    Ok(Json(comment))
}

/// Returns comments in ascending chronological order.
async fn get_post_comments(
    db: Extension<PgPool>,
    Path(post_id): Path<Uuid>,
) -> Result<Json<Vec<Comment>>> {
    // Note: normally you'd want to put a `LIMIT` on this as well,
    // though that would also necessitate implementing pagination.
    let comments = sqlx::query_as!(
        Comment,
        // language=PostgreSQL
        r#"
            select comment_id, username, content, created_at
            from comment
            inner join "user" using (user_id)
            where post_id = $1
            order by created_at
        "#,
        post_id
    )
    .fetch_all(&*db)
    .await?;

    Ok(Json(comments))
}
