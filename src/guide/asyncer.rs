use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};

// Concurrency
// 1) spawn task with `tokio::task::spawn()`
// 2) join many futures with `tokio::join!()` or `futures::future::join_all()`
// 3) using `tokio::select! {...}` to wait on many concurrent code branches
//
// Parallelism
// 1) `tokio::task::spawn()` depending on worker thread config
// #[tokio::main(flavor = "multi_thread", worker_threads = 2)]

// Since main is under tokio
pub async fn run_asyncer() {
    use std::time;

    let duration = time::Duration::from_secs(1);

    tokio::time::sleep(duration).await;
    println!("Awoken");

    spawner().await;
    not_async().await.ok();

    // Gets the runtime handle for the current runtime context.
    let handle = Handle::current();
    std::thread::spawn(move || {
        not_async_block(handle);
    });

    sleeper().await;

    println!("running observers...");
    let mut subject = Subject::new("some subject state");
    let observer1 = MyObserver::new("obs1");
    let observer2 = MyObserver::new("obs2");

    // NOTE: without .clone() it won't work...
    subject.attach(observer1.clone());
    subject.attach(observer2.clone());

    // do sth here
    subject.update().await;

    let result = run_mixed_ops().await;

    match result {
        Ok(_) => println!("run_mixed_ops ok"),
        Err(err) => println!("run_mixed_ops err: {}", err),
    }
}

async fn spawner() {
    async {
        println!("This line prints first");
    }
    .await;

    let _future = async {
        println!("This line never prints");
    };

    tokio::task::spawn(async { println!("This line prints parfois") });

    println!("This line awalys prints, but sometimes last");
}

// JoinHandle impl Future
fn not_async() -> JoinHandle<()> {
    tokio::task::spawn(async { println!("Second print") })
}

fn not_async_block(handle: Handle) {
    handle.block_on(async { println!("block on await on other thread") })
}

#[tracing::instrument]
async fn sleep_non_block(task: &str) {
    // use std::{thread, time::Duration};

    println!("Entering sleep {task}");
    sleep(Duration::from_secs(1)).await;
    // thread::sleep(Duration::from_secs(1));
    println!("Awaken")
}

async fn sleeper() {
    println!("Sequential");
    sleep_non_block("Task 1").await;
    sleep_non_block("Task 2").await;

    println!("Concurrent, same thread");
    tokio::join!(sleep_non_block("Task 3"), sleep_non_block("Task 4"));

    println!("async in parallel");
    let _ = tokio::join!(
        tokio::spawn(sleep_non_block("Task 5")),
        tokio::spawn(sleep_non_block("Task 6"))
    );
}

// Async Observer
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};

trait Observer: Send + Sync {
    type Subject;
    // NOTE: Future is trait NOT a concrete TYPE, thus cannot use
    // associated type this way as return
    // type Output: Future<Output = ()>;
    type Output; // Keep associated type for return type for ease

    // fn observe(&self, subject: &Self::Subject) -> Self::Output;
    // NOTE: poll() or .await needs Pin - a poined pointer cannot move (until unpin)
    fn observe<'a>(
        &'a self,
        subject: &'a Self::Subject,
    ) -> Pin<Box<dyn Future<Output = Self::Output> + 'a + Send>>;
}

struct Subject {
    observer: Vec<Weak<dyn Observer<Subject = Self, Output = ()>>>,
    state: String,
}

impl Subject {
    fn new(state: &str) -> Self {
        Self {
            observer: vec![],
            state: state.into(),
        }
    }

    fn state(&self) -> &str {
        self.state.as_ref()
    }
}

struct MyObserver {
    name: String,
}

impl MyObserver {
    fn new(name: &str) -> Arc<Self> {
        Arc::new(Self { name: name.into() })
    }
}

trait Observable {
    type Observer;

    // This is hard, as need lifetime to pass `self` inside async method.
    // Also need each Observer instance to impl both Send and Sync.
    fn update<'a>(&'a self) -> Pin<Box<dyn Future<Output = ()> + 'a + Send>>;
    fn attach(&mut self, observer: Self::Observer);
    fn detach(&mut self, observer: Self::Observer);
}

impl Observable for Subject {
    type Observer = Arc<dyn Observer<Subject = Self, Output = ()>>;

    fn update<'a>(&'a self) -> Pin<Box<dyn Future<Output = ()> + 'a + Send>> {
        // Generate list of obs to notify OUTSIDE the async context.
        let observers: Vec<_> = self.observer.iter().flat_map(|o| o.upgrade()).collect();

        Box::pin(async move {
            // Each observe called with the same self reference.
            futures::future::join_all(observers.iter().map(|o| o.observe(self))).await;
        })
    }

    fn attach(&mut self, observer: Self::Observer) {
        self.observer.push(Arc::downgrade(&observer))
    }

    fn detach(&mut self, observer: Self::Observer) {
        self.observer
            .retain(|f| !f.ptr_eq(&Arc::downgrade(&observer)));
    }
}

impl Observer for MyObserver {
    type Subject = Subject;
    type Output = ();

    fn observe<'a>(
        &'a self,
        subject: &'a Self::Subject,
    ) -> Pin<Box<dyn Future<Output = Self::Output> + 'a + Send>> {
        Box::pin(async {
            // do some async stuff...
            sleep(Duration::from_millis(100)).await;
            println!(
                "observer `{}` observes subject `{}`",
                self.name,
                subject.state()
            );
        })
    }
}

use tokio::io::{self, AsyncWriteExt};

async fn write_file(filename: &str) -> io::Result<()> {
    let mut f = tokio::fs::File::create(filename).await?;
    let _ = f.write(b"Hello, file!").await?;
    f.flush().await?;

    Ok(())
}

fn read_file(filename: &str) -> io::Result<String> {
    std::fs::read_to_string(filename)
}

async fn run_mixed_ops() -> io::Result<()> {
    let filename = "mixed-async-sync.txt";
    write_file(filename).await?;

    // double ?? as there are two Result returned
    let contents = tokio::task::spawn_blocking(|| read_file(filename)).await??;

    println!("File contents: {}", contents);

    tokio::fs::remove_file(filename).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Instant;
    use tokio::time::sleep;
    use tokio::time::Duration;

    #[tokio::test]
    async fn sleep_test() {
        let start = Instant::now();
        sleep(Duration::from_secs(1)).await;
        let end = Instant::now();
        let seconds = end.checked_duration_since(start).unwrap().as_secs();
        assert_eq!(seconds, 1);
    }
}
