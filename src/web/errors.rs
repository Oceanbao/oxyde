#![allow(dead_code)]

use std::fmt::Display;

use axum::{response::IntoResponse, Json};
use hyper::StatusCode;

pub enum AppError {
    BadRequest,
    UserNotFound,
    InternalError,
}

// Example of a full error suit.
// -----------------------------
#[derive(Debug)]
pub(crate) enum MultipartError {
    NoName,
    InvalidValue,
    ReadError,
}

impl Display for MultipartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MultipartError::NoName => f.write_str("No named field in multipart"),
            MultipartError::InvalidValue => f.write_str("Invalid value in multipart"),
            MultipartError::ReadError => f.write_str("Reading multipart error"),
        }
    }
}

impl std::error::Error for MultipartError {}
// -----------------------------

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            Self::InternalError => (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error"),
            Self::BadRequest => (StatusCode::BAD_REQUEST, "Bad Request"),
            Self::UserNotFound => (StatusCode::NOT_FOUND, "User Not Found"),
        };

        (status, Json(serde_json::json!({"error": error_message}))).into_response()
    }
}
