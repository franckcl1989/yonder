use std::future::Future;
use std::time::Duration;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);

/// Receives type-safe operation milestones without coupling state machines to a UI.
pub trait OperationProgress<Stage> {
    fn update(&mut self, stage: Stage);
    fn clear(&mut self);
}

#[derive(Debug, Default)]
pub(crate) struct NoopProgress;

impl<Stage> OperationProgress<Stage> for NoopProgress {
    fn update(&mut self, _stage: Stage) {}

    fn clear(&mut self) {}
}

pub(crate) async fn wait_with_progress<Stage: Copy, Output>(
    progress: &mut impl OperationProgress<Stage>,
    stage: Stage,
    operation: impl Future<Output = Output>,
) -> Output {
    progress.update(stage);
    tokio::pin!(operation);
    let start = tokio::time::Instant::now() + HEARTBEAT_INTERVAL;
    let mut heartbeat = tokio::time::interval_at(start, HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            result = &mut operation => return result,
            _ = heartbeat.tick() => progress.update(stage),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{OperationProgress, wait_with_progress};
    use std::time::Duration;

    #[derive(Default)]
    struct RecordingProgress {
        updates: usize,
    }

    impl OperationProgress<()> for RecordingProgress {
        fn update(&mut self, (): ()) {
            self.updates += 1;
        }

        fn clear(&mut self) {}
    }

    #[tokio::test]
    async fn progress_is_immediate_and_pulses_during_a_long_operation() {
        let mut immediate = RecordingProgress::default();
        assert_eq!(
            wait_with_progress(&mut immediate, (), std::future::ready(7)).await,
            7
        );
        assert_eq!(immediate.updates, 1);

        let mut long = RecordingProgress::default();
        wait_with_progress(
            &mut long,
            (),
            tokio::time::sleep(Duration::from_millis(1_100)),
        )
        .await;
        assert!(long.updates >= 2);
    }
}
