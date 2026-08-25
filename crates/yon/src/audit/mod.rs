//! Enterprise-session audit recording and offline verification.

use std::future::Future;
use std::pin::Pin;

use session::AuditError;

/// One in-flight audit operation owned by an Active terminal pump. The
/// operation may already have changed durable and protocol state, so Closing
/// must await it instead of treating future drop as cancellation.
pub(crate) type PendingAuditStep<'a, T> = Pin<Box<dyn Future<Output = Result<T, AuditError>> + 'a>>;

pub(crate) async fn settle_pending_step<T>(
    step: &mut Option<PendingAuditStep<'_, T>>,
) -> Result<Option<T>, AuditError> {
    match step.take() {
        Some(step) => step.await.map(Some),
        None => Ok(None),
    }
}

pub mod identity;
pub mod ledger;
pub mod observer;
pub mod replay;
pub mod session;
pub mod verify;
pub mod writer;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use super::{PendingAuditStep, settle_pending_step};

    #[tokio::test(flavor = "current_thread")]
    async fn closing_settles_and_consumes_the_inflight_audit_owner() {
        let completed = Rc::new(Cell::new(false));
        let observed = Rc::clone(&completed);
        let mut step: Option<PendingAuditStep<'_, u8>> = Some(Box::pin(async move {
            tokio::task::yield_now().await;
            observed.set(true);
            Ok(7)
        }));

        assert_eq!(settle_pending_step(&mut step).await.unwrap(), Some(7));
        assert!(completed.get());
        assert!(step.is_none(), "Closing must consume the sole owner");
        assert_eq!(settle_pending_step(&mut step).await.unwrap(), None);
    }
}
