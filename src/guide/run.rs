#![allow(dead_code)]

use super::asyncer::run_asyncer;
use super::channels_thread::run_channels_thread;

#[tokio::main]
async fn run_all() {
    run_asyncer().await;

    let _ = tokio::task::spawn_blocking(run_channels_thread).await;
}
