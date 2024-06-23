#![allow(dead_code)]
use tokio::sync::{broadcast, oneshot, watch};
use tokio::time::Duration;

// oneshot channel to broadcast one-off cancel to multiple task.
async fn one_off() {
    let (tx, rx) = oneshot::channel();

    let task = tokio::spawn(async move {
        tokio::select! {
            _ = rx => {
                println!("Task is cancelling...");
            }
            _ = tokio::time::sleep(Duration::from_secs(10)) => {
                println!("Task completed normally");
            }
        }
        println!("Task is cleaning up");
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send a cancellation signal
    let _ = tx.send(());

    // Wait for the tasks to finish
    // NOTE: we could do this instead:
    // let _ = tokio::join!(task);
    let _ = task.await;
}

async fn many_to_many() {
    let (tx, mut rx1) = broadcast::channel(1);
    let mut rx2 = tx.subscribe();

    let task1 = tokio::spawn(async move {
        tokio::select! {
            _ = rx1.recv() => {
                println!("Task 1 is cancelling...");
            }
            _ = tokio::time::sleep(Duration::from_secs(10)) => {
                println!("Task 1 completed normally");
            }
        }
        println!("Task 1 is cleaning up");
    });

    let task2 = tokio::spawn(async move {
        tokio::select! {
            _ = rx2.recv() => {
                println!("Task 2 is cancelling...");
            }
            _ = tokio::time::sleep(Duration::from_secs(10)) => {
                println!("Task 2 completed normally");
            }
        }
        println!("Task 2 is cleaning up");
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send a cancellation signal
    let _ = tx.send(());

    // Wait for the tasks to finish
    let _ = tokio::join!(task1, task2);
}

// `watch` one-to-many BUT only most RECENT value sent - meaning
// if task launched after a value has been sent it will miss it and thus
// not get cancelled.
async fn watch_it_recent() {
    let (tx, mut rx1) = watch::channel(false);
    let mut rx2 = tx.subscribe();

    let task1 = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = rx1.changed() => {
                    if *rx1.borrow() {
                        println!("Task 1 is cancelling...");
                        break;
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(10)) => {
                    println!("Task 1 completed normally");
                    break;
                }
            }
        }
        println!("Task 1 is cleaning up");
    });

    let task2 = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = rx2.changed() => {
                    if *rx2.borrow() {
                        println!("Task 2 is cancelling...");
                        break;
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(10)) => {
                    println!("Task 2 completed normally");
                    break;
                }
            }
        }
        println!("Task 2 is cleaning up");
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send a cancellation signal
    let _ = tx.send(true);

    // Wait for the tasks to finish
    let _ = tokio::join!(task1, task2);
}
