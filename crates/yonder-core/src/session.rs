use thiserror::Error;

/// The target's one-shot session lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetSessionState {
    Advertised,
    Authenticating,
    AwaitingTerminal,
    StartingTerminal,
    Active,
    Spent,
}

/// Events accepted by the target session state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionEvent {
    BeginAuthentication,
    AuthenticationSucceeded,
    AuthenticationFailed,
    TerminalStreamsReady,
    TerminalStartFailed,
    TerminalReadyFlushed,
    ConnectionLost,
    ExtraConnection,
    ShellExited,
}

/// An event that is not legal in the current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("event {event:?} is invalid in target session state {state:?}")]
pub struct TransitionError {
    state: TargetSessionState,
    event: SessionEvent,
}

impl TransitionError {
    /// Returns the state in which the transition was rejected.
    #[must_use]
    pub const fn state(self) -> TargetSessionState {
        self.state
    }

    /// Returns the rejected event.
    #[must_use]
    pub const fn event(self) -> SessionEvent {
        self.event
    }
}

/// Single-owner state machine that makes one-time code consumption explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetSession {
    state: TargetSessionState,
}

impl TargetSession {
    /// Creates a newly advertised target session.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: TargetSessionState::Advertised,
        }
    }

    /// Returns the current state.
    #[must_use]
    pub const fn state(self) -> TargetSessionState {
        self.state
    }

    /// Returns whether the code has crossed its authoritative commit point.
    #[must_use]
    pub const fn is_consumed(self) -> bool {
        matches!(
            self.state,
            TargetSessionState::Active | TargetSessionState::Spent
        )
    }

    /// Applies a validated external event atomically.
    pub fn apply(&mut self, event: SessionEvent) -> Result<TargetSessionState, TransitionError> {
        use SessionEvent::{
            AuthenticationFailed, AuthenticationSucceeded, BeginAuthentication, ConnectionLost,
            ExtraConnection, ShellExited, TerminalReadyFlushed, TerminalStartFailed,
            TerminalStreamsReady,
        };
        use TargetSessionState::{
            Active, Advertised, Authenticating, AwaitingTerminal, Spent, StartingTerminal,
        };

        let next = match (self.state, event) {
            (Advertised, BeginAuthentication) => Authenticating,
            (Authenticating, AuthenticationSucceeded) => AwaitingTerminal,
            (Authenticating, AuthenticationFailed | ConnectionLost | ExtraConnection) => Advertised,
            (AwaitingTerminal, TerminalStreamsReady) => StartingTerminal,
            (
                AwaitingTerminal | StartingTerminal,
                TerminalStartFailed | ConnectionLost | ExtraConnection,
            ) => Advertised,
            (StartingTerminal, TerminalReadyFlushed) => Active,
            (Active, ShellExited | ConnectionLost | ExtraConnection) => Spent,
            (Spent, ShellExited | ConnectionLost) => Spent,
            (state, event) => return Err(TransitionError { state, event }),
        };
        self.state = next;
        Ok(next)
    }
}

impl Default for TargetSession {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{SessionEvent, TargetSession, TargetSessionState};

    #[test]
    fn successful_session_consumes_code_once() {
        let mut session = TargetSession::new();
        assert!(!session.is_consumed());
        assert_eq!(
            session.apply(SessionEvent::BeginAuthentication),
            Ok(TargetSessionState::Authenticating)
        );
        assert_eq!(
            session.apply(SessionEvent::AuthenticationSucceeded),
            Ok(TargetSessionState::AwaitingTerminal)
        );
        assert_eq!(
            session.apply(SessionEvent::TerminalStreamsReady),
            Ok(TargetSessionState::StartingTerminal)
        );
        assert_eq!(
            session.apply(SessionEvent::TerminalReadyFlushed),
            Ok(TargetSessionState::Active)
        );
        assert!(session.is_consumed());
        assert_eq!(
            session.apply(SessionEvent::ShellExited),
            Ok(TargetSessionState::Spent)
        );
        assert!(session.is_consumed());
    }

    #[test]
    fn pre_commit_failures_restore_advertised_state() {
        for event in [
            SessionEvent::AuthenticationFailed,
            SessionEvent::ConnectionLost,
            SessionEvent::ExtraConnection,
        ] {
            let mut session = TargetSession::new();
            session.apply(SessionEvent::BeginAuthentication).unwrap();
            assert_eq!(session.apply(event), Ok(TargetSessionState::Advertised));
            assert!(!session.is_consumed());
        }

        for state_event in [SessionEvent::ConnectionLost, SessionEvent::ExtraConnection] {
            let mut session = TargetSession::new();
            session.apply(SessionEvent::BeginAuthentication).unwrap();
            session
                .apply(SessionEvent::AuthenticationSucceeded)
                .unwrap();
            assert_eq!(
                session.apply(state_event),
                Ok(TargetSessionState::Advertised)
            );
        }
    }

    #[test]
    fn active_failure_never_restores_a_code() {
        for event in [SessionEvent::ConnectionLost, SessionEvent::ExtraConnection] {
            let mut session = active_session();
            assert_eq!(session.apply(event), Ok(TargetSessionState::Spent));
            assert!(session.is_consumed());
        }
    }

    #[test]
    fn invalid_transition_preserves_state() {
        let mut session = TargetSession::new();
        let error = session
            .apply(SessionEvent::TerminalReadyFlushed)
            .unwrap_err();
        assert_eq!(error.state(), TargetSessionState::Advertised);
        assert_eq!(error.event(), SessionEvent::TerminalReadyFlushed);
        assert_eq!(session.state(), TargetSessionState::Advertised);
        assert!(error.to_string().contains("TerminalReadyFlushed"));
    }

    #[test]
    fn every_remaining_recovery_and_terminal_state_transition_is_explicit() {
        let mut starting = TargetSession::default();
        for event in [
            SessionEvent::BeginAuthentication,
            SessionEvent::AuthenticationSucceeded,
            SessionEvent::TerminalStreamsReady,
        ] {
            starting.apply(event).unwrap();
        }
        assert_eq!(
            starting.apply(SessionEvent::TerminalStartFailed),
            Ok(TargetSessionState::Advertised)
        );

        let mut spent = active_session();
        spent.apply(SessionEvent::ShellExited).unwrap();
        assert_eq!(
            spent.apply(SessionEvent::ConnectionLost),
            Ok(TargetSessionState::Spent)
        );
        assert_eq!(
            spent.apply(SessionEvent::ShellExited),
            Ok(TargetSessionState::Spent)
        );
    }

    fn active_session() -> TargetSession {
        let mut session = TargetSession::new();
        for event in [
            SessionEvent::BeginAuthentication,
            SessionEvent::AuthenticationSucceeded,
            SessionEvent::TerminalStreamsReady,
            SessionEvent::TerminalReadyFlushed,
        ] {
            session.apply(event).unwrap();
        }
        session
    }
}
