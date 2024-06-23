use axum::{
    // async_trait,
    body::{Body, Bytes},
    error_handling::HandleErrorLayer,
    extract::{Extension, FromRequest, MatchedPath, Path, Query, Request},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
    BoxError,
    Form,
    Json,
    RequestExt,
    Router,
};
use std::time::Duration;
use tower::ServiceBuilder;
use tower_http::{classify::ServerErrorsFailureClass, trace::TraceLayer};
use tracing::{info_span, Span};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    // tracing-subscriber is logger crate to define logger impl `Subscriber` from `tracing`.
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            // RUST_LOG=stockrs=debug,tower_http=debug
            tracing_subscriber::EnvFilter::try_from_default_env()
                // axum logs rejections from built-in extractors with `axum::rejection` target
                // at `TRACE` level. `axum::rejection=trace` enables showing all events.
                .unwrap_or_else(|_| "stockrs=debug,tower_http=debug,axum::rejection=trace".into()),
        )
        .init();

    if !std::path::Path::new("db").exists() {
        std::fs::create_dir("db")?;
    }
    let pool = sqlx::SqlitePool::connect(&std::env::var("DATABASE_URL")?).await?;
    sqlx::migrate!().run(&pool).await?;

    let app = Router::new()
        .route("/", get(root_handler))
        .route("/health", get(healthcheck_handler))
        // NOTE: Extension (layer) is not type safe, while used by handlers, missing to add
        // .layer() still compiles!
        // .layer(Extension(AppState { state: 42 }))
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|error: BoxError| async move {
                    if error.is::<tower::timeout::error::Elapsed>() {
                        Ok(StatusCode::REQUEST_TIMEOUT)
                    } else {
                        Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Unhandled internal error: {}", error),
                        ))
                    }
                }))
                .timeout(Duration::from_secs(10))
                .layer(TraceLayer::new_for_http())
                .into_inner(),
        )
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<_>| {
                    // Log the matched route's path with filled placeholder.
                    // Use request.uri() or OriginalUri for real path.
                    let matched_path = request
                        .extensions()
                        .get::<MatchedPath>()
                        .map(MatchedPath::as_str);

                    info_span!(
                        "http_request",
                        method = ?request.method(),
                        matched_path,
                        some_other_field = tracing::field::Empty,
                    )
                })
                .on_request(|_request: &Request<_>, _span: &Span| {
                    // Can use `_span.record("some_other_field", value)` in one of these
                    // closures to attach a value to the initially empty field in the info_span.
                })
                .on_response(|_response: &Response, _latency: Duration, _span: &Span| {
                    // ...
                })
                .on_body_chunk(|_chunk: &Bytes, _latency: Duration, _span: &Span| {
                    // ...
                })
                .on_eos(
                    |_trailers: Option<&HeaderMap>, _stream_duration: Duration, _span: &Span| {
                        // ...
                    },
                )
                .on_failure(
                    |_error: ServerErrorsFailureClass, _latency: Duration, _span: &Span| {
                        // ...
                    },
                ),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    tracing::debug!("server up and listening on {}", listener.local_addr()?);

    axum::serve(listener, app).await?;

    Ok(())
}

async fn root_handler() -> String {
    "hello world".to_string()
}

async fn healthcheck_handler() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header("Location", "/health")
        .header("Set-Cookie", "lastchecked=justnow; Max-Age=3600")
        .body(Body::from("server running ok"))
        .unwrap()
}
