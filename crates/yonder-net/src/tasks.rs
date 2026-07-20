use std::future::Future;
use std::time::Duration;
use thiserror::Error;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

/// A cloneable read-only view of one root cancellation broadcast.
#[derive(Debug, Clone)]
pub struct CancellationHandle(CancellationToken);

impl CancellationHandle {
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.is_cancelled()
    }

    pub fn cancelled(&self) -> impl Future<Output = ()> + '_ {
        self.0.cancelled()
    }
}

/// Tracks every spawned task and provides bounded coordinated shutdown.
#[derive(Debug, Default)]
pub struct TaskGroup {
    tasks: JoinSet<()>,
    cancellation: CancellationToken,
}

/// An abnormal outcome from one owned background task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TaskFailure {
    #[error("a background task panicked")]
    Panicked,
    #[error("a background task was cancelled unexpectedly")]
    Cancelled,
}

/// Complete shutdown evidence for all tasks owned by one group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskShutdown {
    cooperative: bool,
    failure: Option<TaskFailure>,
}

impl TaskShutdown {
    #[must_use]
    pub const fn was_cooperative(self) -> bool {
        self.cooperative
    }

    #[must_use]
    pub const fn failure(self) -> Option<TaskFailure> {
        self.failure
    }
}

impl TaskGroup {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn cancellation(&self) -> CancellationHandle {
        CancellationHandle(self.cancellation.clone())
    }

    pub fn spawn<F>(&mut self, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.tasks.spawn(task);
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// Reaps one completed task so panics and unexpected cancellation cannot be lost.
    pub async fn join_next(&mut self) -> Option<Result<(), TaskFailure>> {
        self.tasks.join_next().await.map(classify_join)
    }

    /// Stops accepting tasks and broadcasts cancellation.
    ///
    /// Tasks receive the whole cooperative timeout. At the absolute deadline,
    /// every remaining async task is aborted and joined before this method
    /// returns. The result records both forced abortion and any task failure.
    pub async fn shutdown(mut self, timeout: Duration) -> TaskShutdown {
        self.cancellation.cancel();

        let deadline = tokio::time::Instant::now() + timeout;
        let mut failure = None;
        while !self.tasks.is_empty() {
            match tokio::time::timeout_at(deadline, self.tasks.join_next()).await {
                Ok(Some(result)) => record_failure(&mut failure, classify_join(result)),
                Ok(None) => break,
                Err(_) => {
                    self.tasks.abort_all();
                    while let Some(result) = self.tasks.join_next().await {
                        let classified = classify_join(result);
                        if !matches!(classified, Err(TaskFailure::Cancelled)) {
                            record_failure(&mut failure, classified);
                        }
                    }
                    return TaskShutdown {
                        cooperative: false,
                        failure,
                    };
                }
            }
        }

        TaskShutdown {
            cooperative: true,
            failure,
        }
    }
}

fn classify_join(result: Result<(), tokio::task::JoinError>) -> Result<(), TaskFailure> {
    result.map_err(|error| {
        if error.is_panic() {
            TaskFailure::Panicked
        } else {
            TaskFailure::Cancelled
        }
    })
}

fn record_failure(slot: &mut Option<TaskFailure>, result: Result<(), TaskFailure>) {
    if slot.is_none() {
        *slot = result.err();
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{TaskFailure, TaskGroup, classify_join};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::sync::{Semaphore, oneshot};

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_reaches_tracked_tasks() {
        let mut tasks = TaskGroup::new();
        let cancellation = tasks.cancellation();
        tasks.spawn(async move { cancellation.cancelled().await });
        let shutdown = tasks.shutdown(Duration::from_secs(1)).await;
        assert!(shutdown.was_cooperative());
        assert_eq!(shutdown.failure(), None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_reports_a_task_that_ignores_cancellation() {
        let mut tasks = TaskGroup::new();
        let cancellation = tasks.cancellation();
        let (dropped_tx, dropped_rx) = oneshot::channel();
        assert!(!cancellation.is_cancelled());
        tasks.spawn(PendingUntilDropped(Some(dropped_tx)));
        let shutdown = tasks.shutdown(Duration::from_millis(1)).await;
        assert!(!shutdown.was_cooperative());
        assert_eq!(shutdown.failure(), None);
        dropped_rx
            .await
            .expect("forced shutdown must drop the aborted task before returning");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn forced_shutdown_aborts_every_remaining_task() {
        let mut tasks = TaskGroup::new();
        let dropped = Arc::new(AtomicUsize::new(0));
        for _ in 0..3 {
            let dropped = Arc::clone(&dropped);
            tasks.spawn(async move {
                let _drop = CountDrop(dropped);
                std::future::pending::<()>().await;
            });
        }

        tokio::task::yield_now().await;
        let shutdown = tasks.shutdown(Duration::ZERO).await;
        assert!(!shutdown.was_cooperative());
        assert_eq!(shutdown.failure(), None);
        assert_eq!(dropped.load(Ordering::Acquire), 3);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn completed_handles_do_not_affect_later_forced_shutdown() {
        let mut tasks = TaskGroup::new();
        tasks.spawn(async {});
        tokio::task::yield_now().await;

        let (dropped_tx, dropped_rx) = oneshot::channel();
        tasks.spawn(PendingUntilDropped(Some(dropped_tx)));
        assert!(!tasks.is_empty());
        let shutdown = tasks.shutdown(Duration::ZERO).await;
        assert!(!shutdown.was_cooperative());
        assert_eq!(shutdown.failure(), None);
        dropped_rx
            .await
            .expect("the remaining task must be aborted and joined");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn completed_task_panics_are_reaped_as_root_failures() {
        let mut tasks = TaskGroup::new();
        let leases = Arc::new(Semaphore::new(1));
        let lease = Arc::clone(&leases).try_acquire_owned().unwrap();
        tasks.spawn(async move {
            let _lease = lease;
            panic!("observable test panic");
        });

        assert_eq!(tasks.join_next().await, Some(Err(TaskFailure::Panicked)));
        assert_eq!(leases.available_permits(), 1);
        assert!(tasks.is_empty());
        assert_eq!(tasks.join_next().await, None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_reports_a_panic_that_races_with_cancellation() {
        let mut tasks = TaskGroup::new();
        tasks.spawn(async { panic!("shutdown test panic") });
        tokio::task::yield_now().await;

        let shutdown = tasks.shutdown(Duration::from_secs(1)).await;
        assert!(shutdown.was_cooperative());
        assert_eq!(shutdown.failure(), Some(TaskFailure::Panicked));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn task_cancellation_is_distinct_from_a_panic() {
        let mut tasks = tokio::task::JoinSet::new();
        let abort = tasks.spawn(std::future::pending::<()>());
        abort.abort();
        let result = tasks
            .join_next()
            .await
            .expect("the cancelled task remains joinable");

        assert_eq!(classify_join(result), Err(TaskFailure::Cancelled));
        assert_eq!(
            TaskFailure::Cancelled.to_string(),
            "a background task was cancelled unexpectedly"
        );
        assert_eq!(
            TaskFailure::Panicked.to_string(),
            "a background task panicked"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn forced_shutdown_retains_a_panic_raised_while_dropping_a_task() {
        let mut tasks = TaskGroup::new();
        tasks.spawn(PanicOnDrop);
        tokio::task::yield_now().await;

        let shutdown = tasks.shutdown(Duration::ZERO).await;
        assert!(!shutdown.was_cooperative());
        assert_eq!(shutdown.failure(), Some(TaskFailure::Panicked));
    }

    struct PendingUntilDropped(Option<oneshot::Sender<()>>);

    impl Future for PendingUntilDropped {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    impl Drop for PendingUntilDropped {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    struct CountDrop(Arc<AtomicUsize>);

    impl Drop for CountDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Release);
        }
    }

    struct PanicOnDrop;

    impl Future for PanicOnDrop {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    impl Drop for PanicOnDrop {
        fn drop(&mut self) {
            panic!("task drop panic");
        }
    }
}
