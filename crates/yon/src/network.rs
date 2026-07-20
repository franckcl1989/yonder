use backon::{BackoffBuilder as _, ExponentialBuilder};
use std::future::Future;
use std::time::Duration;
use thiserror::Error;
use yonder_net::behaviour::EndpointBehaviourEvent;
use yonder_net::swarm::SwarmEvent;
use yonder_net::{
    ApplicationStream, ApplicationStreamError, ApplicationStreams, ConnectedPoint, ConnectionBook,
    ConnectionId, ConnectionSelection, DirectUpgradePolicy, EndpointNode, EndpointRelayAddress,
    EndpointRelaySet, Keypair, Libp2pApplicationStreams, ListenerId, Multiaddr, NetworkBuildError,
    NetworkNodeError, PeerId, WssTransportConfig, multiaddr, ping, relay,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TARGET_SETTLE_TIMEOUT: Duration = Duration::from_secs(30);
const SELECTION_WINDOW: Duration = Duration::from_millis(1_500);
const TARGET_SELECTION_WINDOW: Duration = Duration::from_millis(1_500);
const CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(2);
const CONNECTION_CAPACITY: usize = 8;
const RELAY_DIAL_WINDOW: Duration = Duration::from_millis(1_500);
const RELAY_DRAIN_WINDOW: Duration = Duration::from_millis(500);
const RELAY_BACKOFF_MIN: Duration = Duration::from_millis(250);
const RELAY_BACKOFF_MAX: Duration = Duration::from_secs(5);

/// Endpoint lifecycle failures before an application protocol begins.
#[derive(Debug, Error)]
pub enum EndpointError {
    #[error("failed to construct the endpoint network: {0}")]
    Build(#[from] NetworkBuildError),
    #[error("an endpoint network operation failed")]
    Node(#[from] NetworkNodeError),
    #[error("no configured relay transport became usable")]
    RelayUnavailable,
    #[error("the selected relay connection did not converge")]
    RelayDidNotConverge,
    #[error("the selected relay address was not canonical")]
    InvalidSelectedAddress,
    #[error("an application protocol stream could not be opened")]
    Application(#[from] ApplicationStreamError),
    #[error("the selected physical connection was lost")]
    BoundConnectionLost,
    #[error("an additional physical connection invalidated the session binding")]
    AdditionalBoundConnection,
    #[error("the selected physical connection disappeared during convergence")]
    SelectedConnectionLost,
    #[error("the endpoint-to-endpoint direct upgrade did not settle before its deadline")]
    TargetUpgradeDidNotSettle,
    #[error("the endpoint-to-endpoint direct upgrade failed")]
    DirectUpgradeFailed,
    #[error("the invalidated peer connections did not close before the convergence deadline")]
    ConnectionCloseDidNotConverge,
    #[error("an endpoint already has a relay reservation listener")]
    ReservationAlreadyExists,
    #[error("the selected relay reservation listener closed before becoming usable")]
    ReservationClosed,
    #[error("the bounded relay dial tracker is full or still contains an earlier attempt")]
    RelayDialTrackerUnavailable,
}

/// Relevant events emitted by the single-owner endpoint event pump.
#[derive(Debug, Clone)]
pub enum EndpointEvent {
    Established {
        peer: PeerId,
        connection: ConnectionId,
        endpoint: ConnectedPoint,
    },
    Closed {
        peer: PeerId,
        connection: ConnectionId,
    },
    Ping {
        peer: PeerId,
        connection: ConnectionId,
        round_trip: Result<Duration, ()>,
    },
    DirectUpgradeFinished {
        peer: PeerId,
        outcome: DirectUpgradeOutcome,
    },
    ReservationReady(ReservationListenerId),
    ReservationClosed(ReservationListenerId),
    DialFailed(ConnectionId),
}

/// Terminal outcome of libp2p's bounded DCUtR attempt for one peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectUpgradeOutcome {
    Connected(ConnectionId),
    Failed,
}

/// The exact local physical connection authorized for one endpoint session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionBinding {
    peer: PeerId,
    connection: ConnectionId,
}

impl ConnectionBinding {
    #[must_use]
    pub const fn peer(self) -> PeerId {
        self.peer
    }

    #[must_use]
    pub const fn connection(self) -> ConnectionId {
        self.connection
    }
}

/// The selected, unique physical connection to the configured relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayConnection {
    binding: ConnectionBinding,
    address: EndpointRelayAddress,
}

impl RelayConnection {
    #[must_use]
    pub const fn binding(&self) -> ConnectionBinding {
        self.binding
    }

    #[must_use]
    pub const fn peer(&self) -> PeerId {
        self.binding.peer()
    }

    #[must_use]
    pub const fn address(&self) -> &EndpointRelayAddress {
        &self.address
    }
}

/// The exact libp2p listener that owns one Circuit Relay v2 reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReservationListenerId(ListenerId);

impl ReservationListenerId {
    const fn new(id: ListenerId) -> Self {
        Self(id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReservationSlot {
    listener: ReservationListenerId,
    ready: bool,
}

impl ReservationSlot {
    const fn pending(listener: ReservationListenerId) -> Self {
        Self {
            listener,
            ready: false,
        }
    }

    fn is_ready(self, listener: ReservationListenerId) -> bool {
        self.listener == listener && self.ready
    }

    fn mark_ready(&mut self, listener: ReservationListenerId) -> bool {
        if self.listener != listener {
            return false;
        }
        self.ready = true;
        true
    }

    fn mark_closed(&mut self, listener: ReservationListenerId) -> bool {
        if self.listener != listener {
            return false;
        }
        self.ready = false;
        true
    }
}

/// A usable reservation bound to its selected relay connection and listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationLease {
    relay: RelayConnection,
    listener: ReservationListenerId,
}

impl ReservationLease {
    #[must_use]
    pub const fn relay(&self) -> &RelayConnection {
        &self.relay
    }

    #[must_use]
    pub const fn listener(&self) -> ReservationListenerId {
        self.listener
    }

    #[must_use]
    pub fn is_usable(&self, driver: &EndpointDriver) -> bool {
        driver.reservation_is_ready(self.listener) && driver.has_connection(self.relay.binding())
    }
}

/// A libp2p endpoint whose Swarm and connection book have exactly one owner.
pub struct EndpointDriver {
    node: EndpointNode,
    connections: ConnectionBook,
    reservation: Option<ReservationSlot>,
    pending_relay_dials: PendingRelayDials,
    direct_upgrades: DirectUpgradeTracker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindingState {
    Bound,
    Lost,
    Ambiguous,
}

impl EndpointDriver {
    fn new(node: EndpointNode) -> Self {
        Self {
            node,
            connections: ConnectionBook::new(),
            reservation: None,
            pending_relay_dials: PendingRelayDials::new(),
            direct_upgrades: DirectUpgradeTracker::new(),
        }
    }

    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        self.node.peer_id()
    }

    #[must_use]
    pub fn connection_count(&self, peer: &PeerId) -> usize {
        self.connections.count(peer)
    }

    #[must_use]
    pub fn has_unique_connection(&self, peer: &PeerId) -> bool {
        self.connections.unique(peer).is_some()
    }

    fn direct_upgrade_ready(&self, peer: &PeerId) -> bool {
        match self.direct_upgrades.outcome(peer) {
            Some(DirectUpgradeOutcome::Connected(connection)) => self
                .connections
                .connections(peer)
                .any(|candidate| candidate == connection),
            Some(DirectUpgradeOutcome::Failed) => true,
            None => false,
        }
    }

    pub fn bind(&self, peer: PeerId) -> Result<ConnectionBinding, EndpointError> {
        let connection = match self.connections.unique(&peer) {
            Some(connection) => connection.id(),
            None if self.connections.count(&peer) == 0 => {
                return Err(EndpointError::BoundConnectionLost);
            }
            None => return Err(EndpointError::AdditionalBoundConnection),
        };
        Ok(ConnectionBinding { peer, connection })
    }

    fn has_connection(&self, binding: ConnectionBinding) -> bool {
        self.connections
            .connections(&binding.peer)
            .any(|connection| connection == binding.connection)
    }

    #[cfg(yonder_e2e_rebuild)]
    pub(crate) fn binding_is_relayed(
        &self,
        binding: ConnectionBinding,
    ) -> Result<bool, EndpointError> {
        self.validate_binding(binding)?;
        Ok(self
            .connections
            .unique(&binding.peer)
            .is_some_and(|connection| connection.endpoint().is_relayed()))
    }

    fn validate_binding(&self, binding: ConnectionBinding) -> Result<(), EndpointError> {
        match self.binding_state(binding) {
            BindingState::Bound => Ok(()),
            BindingState::Lost => Err(EndpointError::BoundConnectionLost),
            BindingState::Ambiguous => Err(EndpointError::AdditionalBoundConnection),
        }
    }

    fn binding_state(&self, binding: ConnectionBinding) -> BindingState {
        match self.connections.unique(&binding.peer) {
            Some(connection) if connection.id() == binding.connection => BindingState::Bound,
            None if self.connections.count(&binding.peer) == 0 => BindingState::Lost,
            Some(_) | None => BindingState::Ambiguous,
        }
    }

    pub fn enforce_binding(&mut self, binding: ConnectionBinding) -> Result<(), EndpointError> {
        let result = self.validate_binding(binding);
        if matches!(result, Err(EndpointError::AdditionalBoundConnection)) {
            self.close_bound_peer(binding.peer);
        }
        result
    }

    fn close_bound_peer(&mut self, peer: PeerId) {
        let mut connections = [None; CONNECTION_CAPACITY];
        for (destination, connection) in connections
            .iter_mut()
            .zip(self.connections.connections(&peer))
        {
            *destination = Some(connection);
        }
        for connection in connections.into_iter().flatten() {
            self.close(connection);
        }
    }

    fn close_connections_except(&mut self, binding: ConnectionBinding) {
        let mut connections = [None; CONNECTION_CAPACITY];
        for (destination, connection) in connections
            .iter_mut()
            .zip(self.connections.connections(&binding.peer))
        {
            *destination = Some(connection);
        }
        for connection in connections.into_iter().flatten() {
            if connection != binding.connection {
                self.close(connection);
            }
        }
    }

    pub fn close(&mut self, connection: ConnectionId) {
        self.node.swarm_mut().close_connection(connection);
    }

    /// Closes every physical connection for one peer and waits for roster convergence.
    pub async fn close_peer_and_wait(&mut self, peer: PeerId) -> Result<(), EndpointError> {
        let deadline = tokio::time::Instant::now() + CONVERGENCE_TIMEOUT;
        self.close_peer_and_wait_until(peer, deadline).await
    }

    async fn close_peer_and_wait_until(
        &mut self,
        peer: PeerId,
        deadline: tokio::time::Instant,
    ) -> Result<(), EndpointError> {
        while self.connections.count(&peer) > 0 {
            self.close_bound_peer(peer);
            tokio::time::timeout_at(deadline, self.next())
                .await
                .map_err(|_| EndpointError::ConnectionCloseDidNotConverge)?;
        }
        Ok(())
    }

    pub fn dial(&mut self, address: Multiaddr) -> Result<(), EndpointError> {
        self.node.dial(address).map_err(EndpointError::from)
    }

    pub fn reserve(
        &mut self,
        address: &EndpointRelayAddress,
    ) -> Result<ReservationListenerId, EndpointError> {
        if self.reservation.is_some() {
            return Err(EndpointError::ReservationAlreadyExists);
        }
        let listener = ReservationListenerId::new(self.node.reserve(address)?);
        self.reservation = Some(ReservationSlot::pending(listener));
        Ok(listener)
    }

    pub fn remove_reservation(&mut self, listener: ReservationListenerId) {
        if self
            .reservation
            .is_some_and(|reservation| reservation.listener == listener)
        {
            self.node.swarm_mut().remove_listener(listener.0);
            self.reservation = None;
        }
    }

    #[must_use]
    pub fn reservation_is_ready(&self, listener: ReservationListenerId) -> bool {
        self.reservation
            .is_some_and(|reservation| reservation.is_ready(listener))
    }

    /// Polls until one state-bearing event is available, applying it first.
    pub async fn next(&mut self) -> EndpointEvent {
        loop {
            match self.node.next_event().await {
                SwarmEvent::ConnectionEstablished {
                    peer_id,
                    connection_id,
                    endpoint,
                    ..
                } => {
                    if let Some(event) = self.record_established(peer_id, connection_id, endpoint) {
                        return event;
                    }
                }
                SwarmEvent::ConnectionClosed {
                    peer_id,
                    connection_id,
                    ..
                } => {
                    self.connections.closed(&peer_id, &connection_id);
                    if self.connections.count(&peer_id) == 0 {
                        self.direct_upgrades.remove(&peer_id);
                    }
                    return EndpointEvent::Closed {
                        peer: peer_id,
                        connection: connection_id,
                    };
                }
                SwarmEvent::Behaviour(EndpointBehaviourEvent::Ping(event)) => {
                    return EndpointEvent::Ping {
                        peer: event.peer,
                        connection: event.connection,
                        round_trip: event.result.map_err(|_: ping::Failure| ()),
                    };
                }
                SwarmEvent::Behaviour(EndpointBehaviourEvent::Dcutr(event)) => {
                    let outcome = match event.result {
                        Ok(connection) => DirectUpgradeOutcome::Connected(connection),
                        Err(error) => {
                            tracing::debug!(peer = %event.remote_peer_id, %error, "direct upgrade failed");
                            DirectUpgradeOutcome::Failed
                        }
                    };
                    self.direct_upgrades.finish(event.remote_peer_id, outcome);
                    return EndpointEvent::DirectUpgradeFinished {
                        peer: event.remote_peer_id,
                        outcome,
                    };
                }
                SwarmEvent::Behaviour(EndpointBehaviourEvent::Relay(
                    relay::client::Event::ReservationReqAccepted { .. },
                )) => {}
                SwarmEvent::NewListenAddr { listener_id, .. } => {
                    let listener = ReservationListenerId::new(listener_id);
                    if self
                        .reservation
                        .as_mut()
                        .is_some_and(|reservation| reservation.mark_ready(listener))
                    {
                        return EndpointEvent::ReservationReady(listener);
                    }
                }
                SwarmEvent::ExpiredListenAddr { listener_id, .. }
                | SwarmEvent::ListenerClosed { listener_id, .. } => {
                    let listener = ReservationListenerId::new(listener_id);
                    if self
                        .reservation
                        .as_mut()
                        .is_some_and(|reservation| reservation.mark_closed(listener))
                    {
                        return EndpointEvent::ReservationClosed(listener);
                    }
                }
                SwarmEvent::OutgoingConnectionError {
                    connection_id,
                    peer_id,
                    error,
                } => {
                    self.pending_relay_dials.remove(connection_id);
                    tracing::debug!(peer = ?peer_id, %error, "endpoint dial attempt failed");
                    return EndpointEvent::DialFailed(connection_id);
                }
                SwarmEvent::ListenerError { error, .. } => {
                    tracing::warn!(%error, "endpoint listener failed");
                }
                _ => {}
            }
        }
    }

    fn record_established(
        &mut self,
        peer: PeerId,
        connection: ConnectionId,
        endpoint: ConnectedPoint,
    ) -> Option<EndpointEvent> {
        self.pending_relay_dials.remove(connection);
        if endpoint.is_relayed() && !self.direct_upgrades.begin(peer) {
            tracing::warn!(%peer, %connection, "closing relayed connection beyond direct-upgrade tracker bound");
            self.node.swarm_mut().close_connection(connection);
            return None;
        }
        if let Err(error) = self
            .connections
            .established(peer, connection, endpoint.clone())
        {
            tracing::warn!(%peer, %connection, %error, "closing connection beyond endpoint roster bound");
            self.node.swarm_mut().close_connection(connection);
            return None;
        }
        Some(EndpointEvent::Established {
            peer,
            connection,
            endpoint,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectUpgradeState {
    peer: PeerId,
    outcome: Option<DirectUpgradeOutcome>,
}

struct DirectUpgradeTracker {
    states: [Option<DirectUpgradeState>; CONNECTION_CAPACITY],
}

impl DirectUpgradeTracker {
    const fn new() -> Self {
        Self {
            states: [None; CONNECTION_CAPACITY],
        }
    }

    fn begin(&mut self, peer: PeerId) -> bool {
        if let Some(state) = self
            .states
            .iter_mut()
            .flatten()
            .find(|state| state.peer == peer)
        {
            state.outcome = None;
            return true;
        }
        let Some(slot) = self.states.iter_mut().find(|state| state.is_none()) else {
            return false;
        };
        *slot = Some(DirectUpgradeState {
            peer,
            outcome: None,
        });
        true
    }

    fn finish(&mut self, peer: PeerId, outcome: DirectUpgradeOutcome) {
        if let Some(state) = self
            .states
            .iter_mut()
            .flatten()
            .find(|state| state.peer == peer)
        {
            state.outcome = Some(outcome);
        }
    }

    fn outcome(&self, peer: &PeerId) -> Option<DirectUpgradeOutcome> {
        self.states
            .iter()
            .flatten()
            .find(|state| state.peer == *peer)
            .and_then(|state| state.outcome)
    }

    fn remove(&mut self, peer: &PeerId) {
        if let Some(slot) = self
            .states
            .iter_mut()
            .find(|state| state.as_ref().is_some_and(|state| state.peer == *peer))
        {
            *slot = None;
        }
    }
}

struct PendingRelayDials {
    connections: [Option<ConnectionId>; CONNECTION_CAPACITY],
}

impl PendingRelayDials {
    const fn new() -> Self {
        Self {
            connections: [None; CONNECTION_CAPACITY],
        }
    }

    fn insert(&mut self, connection: ConnectionId) -> Result<(), EndpointError> {
        if let Some(slot) = self.connections.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(connection);
            Ok(())
        } else {
            Err(EndpointError::RelayDialTrackerUnavailable)
        }
    }

    fn remove(&mut self, connection: ConnectionId) {
        if let Some(slot) = self
            .connections
            .iter_mut()
            .find(|slot| **slot == Some(connection))
        {
            *slot = None;
        }
    }

    fn is_empty(&self) -> bool {
        self.connections.iter().all(Option::is_none)
    }
}

fn relay_backoff_builder() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(RELAY_BACKOFF_MIN)
        .with_factor(2.0)
        .with_max_delay(RELAY_BACKOFF_MAX)
        .without_max_times()
}

/// Builds the single frozen relay retry policy shared by controller and host paths.
pub fn relay_backoff() -> impl Iterator<Item = Duration> {
    relay_backoff_builder().with_jitter().build()
}

/// Starts all direct listeners and races every configured transport to the pinned relay.
pub async fn connect_relay(
    identity: Keypair,
    relays: &EndpointRelaySet,
    wss: WssTransportConfig,
) -> Result<(EndpointDriver, Libp2pApplicationStreams, RelayConnection), EndpointError> {
    connect_relay_with_policy(identity, relays, wss, DirectUpgradePolicy::Enabled).await
}

/// Connects an endpoint whose DCUtR policy is fixed for the lifetime of its Swarm.
pub async fn connect_relay_with_policy(
    identity: Keypair,
    relays: &EndpointRelaySet,
    wss: WssTransportConfig,
    direct_upgrade: DirectUpgradePolicy,
) -> Result<(EndpointDriver, Libp2pApplicationStreams, RelayConnection), EndpointError> {
    let (mut driver, streams) = build_endpoint_with_policy(identity, wss, direct_upgrade)?;
    let relay = connect_configured_relay(&mut driver, relays).await?;
    Ok((driver, streams, relay))
}

/// Constructs one endpoint and starts its direct listeners without dialing a relay.
pub fn build_endpoint(
    identity: Keypair,
    wss: WssTransportConfig,
) -> Result<(EndpointDriver, Libp2pApplicationStreams), EndpointError> {
    build_endpoint_with_policy(identity, wss, DirectUpgradePolicy::Enabled)
}

fn build_endpoint_with_policy(
    identity: Keypair,
    wss: WssTransportConfig,
    direct_upgrade: DirectUpgradePolicy,
) -> Result<(EndpointDriver, Libp2pApplicationStreams), EndpointError> {
    let mut node = EndpointNode::with_direct_upgrade(identity, wss, direct_upgrade)?;
    node.listen_on_defaults()?;
    let streams = node.streams().clone();
    Ok((EndpointDriver::new(node), streams))
}

/// Races and retries every configured relay transport within one absolute 10 second attempt.
pub async fn connect_configured_relay(
    driver: &mut EndpointDriver,
    relays: &EndpointRelaySet,
) -> Result<RelayConnection, EndpointError> {
    let connect_deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
    let attempt_deadline = connect_deadline - RELAY_DRAIN_WINDOW;
    let relay_peer = relays.relay().get();
    drain_relay_state(driver, relay_peer, None, connect_deadline).await?;
    let attempt = connect_relay_attempt(driver, relays, attempt_deadline).await;
    match attempt {
        Ok(connection) => {
            drain_relay_state(
                driver,
                relay_peer,
                Some(connection.binding()),
                connect_deadline,
            )
            .await?;
            Ok(connection)
        }
        Err(root) => {
            drain_relay_state(driver, relay_peer, None, connect_deadline).await?;
            Err(root)
        }
    }
}

async fn connect_relay_attempt(
    driver: &mut EndpointDriver,
    relays: &EndpointRelaySet,
    connect_deadline: tokio::time::Instant,
) -> Result<RelayConnection, EndpointError> {
    let relay_peer = relays.relay().get();
    let dial_cutoff = tokio::time::Instant::now() + RELAY_DIAL_WINDOW;
    dial_relay_set(driver, relays)?;

    let mut backoff = relay_backoff();
    let mut next_dial = driver
        .pending_relay_dials
        .is_empty()
        .then(|| next_relay_dial(&mut backoff, dial_cutoff))
        .flatten();

    let mut selection = ConnectionSelection::new();
    let mut addresses = Vec::with_capacity(relays.iter().len());
    let mut selection_deadline = None;

    loop {
        if selection_deadline.is_none()
            && next_dial.is_none()
            && driver.pending_relay_dials.is_empty()
        {
            return Err(EndpointError::RelayUnavailable);
        }
        let deadline = selection_deadline
            .unwrap_or_else(|| connect_deadline.min(next_dial.unwrap_or(connect_deadline)));
        let event = match tokio::time::timeout_at(deadline, driver.next()).await {
            Ok(event) => event,
            Err(_) if selection_deadline.is_some() => break,
            Err(_) if tokio::time::Instant::now() >= connect_deadline => {
                return Err(EndpointError::RelayUnavailable);
            }
            Err(_) => {
                dial_relay_set(driver, relays)?;
                next_dial = None;
                continue;
            }
        };
        if process_relay_selection_event(driver, &mut selection, &mut addresses, relay_peer, event)
        {
            selection_deadline.get_or_insert(
                (tokio::time::Instant::now() + SELECTION_WINDOW).min(connect_deadline),
            );
        }
        if selection_deadline.is_none()
            && next_dial.is_none()
            && driver.pending_relay_dials.is_empty()
        {
            next_dial = next_relay_dial(&mut backoff, dial_cutoff);
        }
    }

    finish_relay_selection(driver, selection, addresses, relay_peer)
}

fn finish_relay_selection(
    driver: &mut EndpointDriver,
    selection: ConnectionSelection,
    addresses: Vec<(ConnectionId, Multiaddr)>,
    relay_peer: PeerId,
) -> Result<RelayConnection, EndpointError> {
    let (winner, losers) = selection.finish().ok_or(EndpointError::RelayUnavailable)?;
    for loser in losers {
        driver.close(loser);
    }
    let binding = ConnectionBinding {
        peer: relay_peer,
        connection: winner,
    };

    let address = selected_relay_address(addresses, winner, relay_peer)?;
    Ok(RelayConnection { binding, address })
}

fn process_relay_selection_event(
    driver: &mut EndpointDriver,
    selection: &mut ConnectionSelection,
    addresses: &mut Vec<(ConnectionId, Multiaddr)>,
    relay_peer: PeerId,
    event: EndpointEvent,
) -> bool {
    match event {
        EndpointEvent::Established {
            peer,
            connection,
            endpoint,
        } if peer == relay_peer => {
            if selection.established(connection, &endpoint).is_ok() {
                addresses.push((connection, endpoint.get_remote_address().clone()));
                true
            } else {
                driver.close(connection);
                false
            }
        }
        EndpointEvent::Ping {
            peer,
            connection,
            round_trip: Ok(round_trip),
        } if peer == relay_peer => {
            let _ = selection.ping(connection, round_trip);
            false
        }
        EndpointEvent::Closed {
            peer, connection, ..
        } if peer == relay_peer => {
            selection.closed(connection);
            false
        }
        _ => false,
    }
}

fn selected_relay_address(
    addresses: Vec<(ConnectionId, Multiaddr)>,
    winner: ConnectionId,
    relay_peer: PeerId,
) -> Result<EndpointRelayAddress, EndpointError> {
    addresses
        .into_iter()
        .find_map(|(connection, mut address)| {
            if connection != winner {
                return None;
            }
            if !matches!(address.iter().last(), Some(multiaddr::Protocol::P2p(_))) {
                address.push(multiaddr::Protocol::P2p(relay_peer));
            }
            EndpointRelayAddress::try_from(address).ok()
        })
        .ok_or(EndpointError::InvalidSelectedAddress)
}

fn next_relay_dial(
    backoff: &mut impl Iterator<Item = Duration>,
    cutoff: tokio::time::Instant,
) -> Option<tokio::time::Instant> {
    let next = tokio::time::Instant::now()
        + backoff
            .next()
            .expect("the frozen relay backoff is unbounded");
    (next <= cutoff).then_some(next)
}

fn dial_relay_set(
    driver: &mut EndpointDriver,
    relays: &EndpointRelaySet,
) -> Result<(), EndpointError> {
    if !driver.pending_relay_dials.is_empty() {
        return Err(EndpointError::RelayDialTrackerUnavailable);
    }
    for address in relays.iter() {
        match driver.node.dial_relay(address) {
            Ok(connection) => driver.pending_relay_dials.insert(connection)?,
            Err(error) => {
                tracing::debug!(%error, address = %address.as_multiaddr(), "relay transport dial was rejected");
            }
        }
    }
    Ok(())
}

async fn drain_relay_state(
    driver: &mut EndpointDriver,
    relay: PeerId,
    keep: Option<ConnectionBinding>,
    deadline: tokio::time::Instant,
) -> Result<(), EndpointError> {
    loop {
        let mut connections = [None; CONNECTION_CAPACITY];
        for (destination, connection) in connections
            .iter_mut()
            .zip(driver.connections.connections(&relay))
        {
            *destination = Some(connection);
        }
        for connection in connections.into_iter().flatten() {
            if keep.is_none_or(|binding| binding.connection != connection) {
                driver.close(connection);
            }
        }

        let roster_ready = match keep {
            Some(binding) => match driver.binding_state(binding) {
                BindingState::Bound => true,
                BindingState::Lost => {
                    return Err(EndpointError::SelectedConnectionLost);
                }
                BindingState::Ambiguous => false,
            },
            None => driver.connection_count(&relay) == 0,
        };
        if roster_ready && driver.pending_relay_dials.is_empty() {
            return Ok(());
        }

        match tokio::time::timeout_at(deadline, driver.next()).await {
            Ok(event) => relay_drain_event(&event, keep)?,
            Err(_) => return Err(EndpointError::RelayDidNotConverge),
        }
    }
}

fn relay_drain_event(
    event: &EndpointEvent,
    keep: Option<ConnectionBinding>,
) -> Result<(), EndpointError> {
    if matches!(
        event,
        EndpointEvent::Closed { peer, connection }
            if keep.is_some_and(|binding| {
                *peer == binding.peer && *connection == binding.connection
            })
    ) {
        return Err(EndpointError::SelectedConnectionLost);
    }
    Ok(())
}

async fn converge_to_binding(
    driver: &mut EndpointDriver,
    binding: ConnectionBinding,
    outer_deadline: tokio::time::Instant,
) -> Result<(), EndpointError> {
    let deadline = (tokio::time::Instant::now() + CONVERGENCE_TIMEOUT).min(outer_deadline);
    loop {
        if !driver.has_connection(binding) {
            return Err(EndpointError::SelectedConnectionLost);
        }
        if driver.validate_binding(binding).is_ok() {
            return Ok(());
        }
        driver.close_connections_except(binding);
        if tokio::time::timeout_at(deadline, driver.next())
            .await
            .is_err()
        {
            return Err(EndpointError::RelayDidNotConverge);
        }
    }
}

/// Restores the selected relay foundation after a temporary AutoNAT or late dial connection.
pub async fn reconverge_relay(
    driver: &mut EndpointDriver,
    relay: &RelayConnection,
) -> Result<(), EndpointError> {
    converge_to_binding(
        driver,
        relay.binding(),
        tokio::time::Instant::now() + CONVERGENCE_TIMEOUT,
    )
    .await
}

/// Waits for the relay to accept the endpoint reservation.
pub async fn wait_for_reservation(
    driver: &mut EndpointDriver,
    relay: RelayConnection,
    listener: ReservationListenerId,
) -> Result<ReservationLease, EndpointError> {
    let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
    wait_for_reservation_until(driver, relay, listener, deadline).await
}

async fn wait_for_reservation_until(
    driver: &mut EndpointDriver,
    relay: RelayConnection,
    listener: ReservationListenerId,
    deadline: tokio::time::Instant,
) -> Result<ReservationLease, EndpointError> {
    loop {
        let event = match tokio::time::timeout_at(deadline, driver.next()).await {
            Ok(event) => event,
            Err(_) => return Err(EndpointError::RelayUnavailable),
        };
        match reservation_decision(
            &event,
            &relay,
            listener,
            driver.has_connection(relay.binding()),
        ) {
            ReservationDecision::Continue => {}
            ReservationDecision::Ready => return Ok(ReservationLease { relay, listener }),
            ReservationDecision::Failed(error) => return Err(error),
        }
    }
}

enum ReservationDecision {
    Continue,
    Ready,
    Failed(EndpointError),
}

fn reservation_decision(
    event: &EndpointEvent,
    relay: &RelayConnection,
    listener: ReservationListenerId,
    relay_connection_present: bool,
) -> ReservationDecision {
    match event {
        EndpointEvent::ReservationReady(ready) if *ready == listener => {
            if relay_connection_present {
                ReservationDecision::Ready
            } else {
                ReservationDecision::Failed(EndpointError::SelectedConnectionLost)
            }
        }
        EndpointEvent::ReservationClosed(closed) if *closed == listener => {
            ReservationDecision::Failed(EndpointError::ReservationClosed)
        }
        EndpointEvent::Closed {
            peer, connection, ..
        } if *peer == relay.peer() && *connection == relay.binding().connection() => {
            ReservationDecision::Failed(EndpointError::SelectedConnectionLost)
        }
        _ => ReservationDecision::Continue,
    }
}

/// Establishes the relay circuit, allows DCUtR to add direct candidates, then keeps one path.
pub async fn connect_target(
    driver: &mut EndpointDriver,
    relay: &EndpointRelayAddress,
    target: PeerId,
) -> Result<ConnectionBinding, EndpointError> {
    connect_target_with_policy(driver, relay, target, DirectUpgradePolicy::Enabled).await
}

/// Establishes a relay-only fallback after the earlier full Swarm has been destroyed.
pub async fn connect_target_via_relay(
    driver: &mut EndpointDriver,
    relay: &EndpointRelayAddress,
    target: PeerId,
) -> Result<ConnectionBinding, EndpointError> {
    connect_target_with_policy(driver, relay, target, DirectUpgradePolicy::Disabled).await
}

async fn connect_target_with_policy(
    driver: &mut EndpointDriver,
    relay: &EndpointRelayAddress,
    target: PeerId,
    direct_upgrade: DirectUpgradePolicy,
) -> Result<ConnectionBinding, EndpointError> {
    driver.dial(relay.circuit_to(target))?;
    let connect_deadline = tokio::time::Instant::now() + TARGET_SETTLE_TIMEOUT;
    connect_target_until(driver, target, connect_deadline, direct_upgrade).await
}

async fn connect_target_until(
    driver: &mut EndpointDriver,
    target: PeerId,
    connect_deadline: tokio::time::Instant,
    direct_upgrade: DirectUpgradePolicy,
) -> Result<ConnectionBinding, EndpointError> {
    let mut selection_deadline = None;
    let mut selection = ConnectionSelection::new();
    let mut has_candidate = false;
    let mut selection_elapsed = false;
    let mut direct_upgrade_outcome = None;
    loop {
        let deadline = if selection_elapsed {
            connect_deadline
        } else {
            selection_deadline.unwrap_or(connect_deadline)
        };
        let event = match tokio::time::timeout_at(deadline, driver.next()).await {
            Ok(event) => event,
            Err(_) if selection_deadline.is_some() && !selection_elapsed => {
                selection_elapsed = true;
                #[cfg(yonder_e2e_rebuild)]
                if direct_upgrade.is_enabled() && has_candidate {
                    direct_upgrade_outcome = Some(DirectUpgradeOutcome::Failed);
                }
                if target_selection_is_settled(
                    &selection,
                    direct_upgrade_outcome,
                    selection_elapsed,
                    direct_upgrade,
                ) {
                    break;
                }
                continue;
            }
            Err(_) => {
                driver.close_peer_and_wait(target).await?;
                return Err(if has_candidate {
                    EndpointError::TargetUpgradeDidNotSettle
                } else {
                    EndpointError::RelayUnavailable
                });
            }
        };
        if let EndpointEvent::DirectUpgradeFinished { peer, outcome } = &event
            && *peer == target
        {
            direct_upgrade_outcome = Some(*outcome);
        }
        if process_target_selection_event(driver, &mut selection, target, event, !selection_elapsed)
        {
            has_candidate = true;
        }
        if has_candidate && selection_deadline.is_none() {
            selection_deadline =
                Some((tokio::time::Instant::now() + TARGET_SELECTION_WINDOW).min(connect_deadline));
        }
        if target_selection_is_settled(
            &selection,
            direct_upgrade_outcome,
            selection_elapsed,
            direct_upgrade,
        ) {
            break;
        }
    }
    if direct_upgrade.is_enabled()
        && matches!(direct_upgrade_outcome, Some(DirectUpgradeOutcome::Failed))
    {
        driver.close_peer_and_wait(target).await?;
        return Err(EndpointError::DirectUpgradeFailed);
    }
    let (winner, losers) = selection.finish().ok_or(EndpointError::RelayUnavailable)?;
    for loser in losers {
        driver.close(loser);
    }
    let binding = ConnectionBinding {
        peer: target,
        connection: winner,
    };
    converge_to_binding(driver, binding, connect_deadline).await?;
    Ok(binding)
}

fn target_selection_is_settled(
    selection: &ConnectionSelection,
    direct_upgrade_outcome: Option<DirectUpgradeOutcome>,
    selection_elapsed: bool,
    direct_upgrade: DirectUpgradePolicy,
) -> bool {
    selection_elapsed
        && (!direct_upgrade.is_enabled()
            || match direct_upgrade_outcome {
                Some(DirectUpgradeOutcome::Connected(connection)) => selection.contains(connection),
                Some(DirectUpgradeOutcome::Failed) => true,
                None => false,
            })
}

fn process_target_selection_event(
    driver: &mut EndpointDriver,
    selection: &mut ConnectionSelection,
    target: PeerId,
    event: EndpointEvent,
    collect_quality: bool,
) -> bool {
    match event {
        EndpointEvent::Established {
            peer,
            connection,
            endpoint,
        } if peer == target => {
            if selection.established(connection, &endpoint).is_ok() {
                true
            } else {
                driver.close(connection);
                false
            }
        }
        EndpointEvent::Ping {
            peer,
            connection,
            round_trip: Ok(round_trip),
        } if peer == target && collect_quality => {
            let _ = selection.ping(connection, round_trip);
            false
        }
        EndpointEvent::Closed {
            peer, connection, ..
        } if peer == target => {
            selection.closed(connection);
            false
        }
        _ => false,
    }
}

/// Waits until an inbound peer has completed DCUtR and converged to one connection.
pub async fn wait_for_target_quiescence(
    driver: &mut EndpointDriver,
    target: PeerId,
) -> Result<ConnectionBinding, EndpointError> {
    let deadline = tokio::time::Instant::now() + TARGET_SETTLE_TIMEOUT;
    loop {
        if driver.direct_upgrade_ready(&target) && driver.has_unique_connection(&target) {
            return driver.bind(target);
        }
        if tokio::time::timeout_at(deadline, driver.next())
            .await
            .is_err()
        {
            driver.close_peer_and_wait(target).await?;
            return Err(EndpointError::TargetUpgradeDidNotSettle);
        }
    }
}

/// Opens a libp2p application stream while continuously polling its owning Swarm.
pub async fn open_stream(
    driver: &mut EndpointDriver,
    streams: &mut Libp2pApplicationStreams,
    peer: PeerId,
    protocol: &'static str,
) -> Result<ApplicationStream, EndpointError> {
    drive(driver, streams.open(peer, protocol))
        .await
        .map_err(EndpointError::from)
}

/// Runs an I/O future while continuously polling the endpoint Swarm.
pub async fn drive<F: Future>(driver: &mut EndpointDriver, future: F) -> F::Output {
    tokio::pin!(future);
    loop {
        tokio::select! {
            output = &mut future => return output,
            _ = driver.next() => {}
        }
    }
}

/// Drives I/O while enforcing that the authorized physical connection stays unique.
pub async fn drive_bound<F: Future>(
    driver: &mut EndpointDriver,
    binding: ConnectionBinding,
    future: F,
) -> Result<F::Output, EndpointError> {
    driver.enforce_binding(binding)?;
    tokio::pin!(future);
    loop {
        tokio::select! {
            biased;
            event = driver.next() => {
                enforce_binding_after_event(driver, binding, &event)?;
            }
            output = &mut future => {
                return finish_bound_output(driver, binding, output);
            }
        }
    }
}

fn enforce_binding_after_event(
    driver: &mut EndpointDriver,
    binding: ConnectionBinding,
    event: &EndpointEvent,
) -> Result<(), EndpointError> {
    let affects_binding = matches!(
        event,
        EndpointEvent::Established { peer, .. } | EndpointEvent::Closed { peer, .. }
            if *peer == binding.peer
    );
    if affects_binding {
        driver.enforce_binding(binding)?;
    }
    Ok(())
}

fn finish_bound_output<T>(
    driver: &mut EndpointDriver,
    binding: ConnectionBinding,
    output: T,
) -> Result<T, EndpointError> {
    driver.enforce_binding(binding)?;
    Ok(output)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        CONNECT_TIMEOUT, CONVERGENCE_TIMEOUT, ConnectionBinding, DirectUpgradeOutcome,
        DirectUpgradeTracker, EndpointDriver, EndpointError, EndpointEvent, PendingRelayDials,
        RELAY_DIAL_WINDOW, RELAY_DRAIN_WINDOW, RelayConnection, ReservationDecision,
        ReservationLease, ReservationListenerId, ReservationSlot, SELECTION_WINDOW,
        TARGET_SELECTION_WINDOW, TARGET_SETTLE_TIMEOUT, connect_relay_attempt,
        connect_target_until, converge_to_binding, dial_relay_set, drain_relay_state, drive,
        drive_bound, enforce_binding_after_event, finish_bound_output, finish_relay_selection,
        next_relay_dial, open_stream, process_relay_selection_event,
        process_target_selection_event, reconverge_relay, relay_backoff_builder, relay_drain_event,
        reservation_decision, selected_relay_address, target_selection_is_settled,
        wait_for_reservation, wait_for_reservation_until,
    };
    use backon::BackoffBuilder as _;
    use std::time::Duration;
    use yonder_net::{
        ConnectedPoint, ConnectionId, ConnectionSelection, DirectUpgradePolicy, EndpointNode,
        EndpointRelayAddress, EndpointRelaySet, Keypair, ListenerId, Multiaddr, WssTransportConfig,
    };

    #[test]
    fn endpoint_time_bounds_are_ordered() {
        assert!(SELECTION_WINDOW < CONVERGENCE_TIMEOUT);
        assert!(CONVERGENCE_TIMEOUT < CONNECT_TIMEOUT);
        assert_eq!(SELECTION_WINDOW, TARGET_SELECTION_WINDOW);
        assert!(TARGET_SELECTION_WINDOW < CONVERGENCE_TIMEOUT);
        assert!(Duration::from_secs(3 * 8) + TARGET_SELECTION_WINDOW < TARGET_SETTLE_TIMEOUT);
        assert_eq!(RELAY_DIAL_WINDOW, SELECTION_WINDOW);
        assert_eq!(RELAY_DRAIN_WINDOW, Duration::from_millis(500));
        assert!(RELAY_DIAL_WINDOW + Duration::from_secs(8) + RELAY_DRAIN_WINDOW <= CONNECT_TIMEOUT);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn target_settlement_requires_policy_specific_direct_upgrade_evidence() {
        let connection = ConnectionId::new_unchecked(700);
        let mut selection = ConnectionSelection::new();
        assert!(target_selection_is_settled(
            &selection,
            None,
            true,
            DirectUpgradePolicy::Disabled,
        ));
        assert!(!target_selection_is_settled(
            &selection,
            None,
            true,
            DirectUpgradePolicy::Enabled,
        ));
        assert!(target_selection_is_settled(
            &selection,
            Some(DirectUpgradeOutcome::Failed),
            true,
            DirectUpgradePolicy::Enabled,
        ));
        assert!(!target_selection_is_settled(
            &selection,
            Some(DirectUpgradeOutcome::Connected(connection)),
            true,
            DirectUpgradePolicy::Enabled,
        ));
        selection
            .established(connection, &listener_endpoint(700))
            .unwrap();
        assert!(target_selection_is_settled(
            &selection,
            Some(DirectUpgradeOutcome::Connected(connection)),
            true,
            DirectUpgradePolicy::Enabled,
        ));
        assert!(!target_selection_is_settled(
            &selection,
            Some(DirectUpgradeOutcome::Connected(connection)),
            false,
            DirectUpgradePolicy::Enabled,
        ));

        let mut driver = endpoint_driver();
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        assert!(!driver.direct_upgrade_ready(&peer));
        assert!(driver.direct_upgrades.begin(peer));
        driver
            .direct_upgrades
            .finish(peer, DirectUpgradeOutcome::Connected(connection));
        assert!(!driver.direct_upgrade_ready(&peer));
        driver
            .connections
            .established(peer, connection, listener_endpoint(700))
            .unwrap();
        assert!(driver.direct_upgrade_ready(&peer));
        driver.connections.closed(&peer, &connection);
        assert!(!driver.direct_upgrade_ready(&peer));
        driver
            .direct_upgrades
            .finish(peer, DirectUpgradeOutcome::Failed);
        assert!(driver.direct_upgrade_ready(&peer));
    }

    #[test]
    fn direct_upgrade_tracker_is_bounded_resettable_and_peer_exact() {
        let mut tracker = DirectUpgradeTracker::new();
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let unknown = Keypair::generate_ed25519().public().to_peer_id();
        assert_eq!(tracker.outcome(&peer), None);
        tracker.finish(unknown, DirectUpgradeOutcome::Failed);
        assert!(tracker.begin(peer));
        tracker.finish(peer, DirectUpgradeOutcome::Failed);
        assert_eq!(tracker.outcome(&peer), Some(DirectUpgradeOutcome::Failed));
        assert!(tracker.begin(peer));
        assert_eq!(tracker.outcome(&peer), None);
        tracker.remove(&unknown);
        tracker.remove(&peer);

        for _ in 0..super::CONNECTION_CAPACITY {
            let peer = Keypair::generate_ed25519().public().to_peer_id();
            assert!(tracker.begin(peer));
        }
        let overflow = Keypair::generate_ed25519().public().to_peer_id();
        assert!(!tracker.begin(overflow));
    }

    #[test]
    fn relay_backoff_is_exponential_jittered_and_bounded() {
        let delays: Vec<_> = relay_backoff_builder()
            .with_jitter_seed(7)
            .with_max_times(8)
            .build()
            .collect();
        let bases = [250_u64, 500, 1_000, 2_000, 4_000, 5_000, 5_000, 5_000];
        assert_eq!(delays.len(), bases.len());
        for (delay, base) in delays.into_iter().zip(bases) {
            assert!(delay >= Duration::from_millis(base));
            assert!(delay < Duration::from_millis(base * 2));
        }
    }

    #[test]
    fn relay_redial_is_rejected_after_the_bounded_dial_window() {
        let mut allowed = [Duration::from_millis(1)].into_iter();
        assert!(
            next_relay_dial(
                &mut allowed,
                tokio::time::Instant::now() + Duration::from_secs(1)
            )
            .is_some()
        );
        let mut rejected = [Duration::from_secs(1)].into_iter();
        assert!(
            next_relay_dial(
                &mut rejected,
                tokio::time::Instant::now() + Duration::from_millis(1)
            )
            .is_none()
        );
    }

    #[test]
    fn reservation_slot_only_tracks_its_exact_listener() {
        let expected = ReservationListenerId::new(ListenerId::next());
        let other = ReservationListenerId::new(ListenerId::next());
        let mut slot = ReservationSlot::pending(expected);

        assert!(!slot.is_ready(expected));
        assert!(!slot.mark_ready(other));
        assert!(!slot.is_ready(expected));
        assert!(slot.mark_ready(expected));
        assert!(slot.is_ready(expected));
        assert!(!slot.mark_closed(other));
        assert!(slot.is_ready(expected));
        assert!(slot.mark_closed(expected));
        assert!(!slot.is_ready(expected));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reservation_lease_survives_temporary_extras_but_not_selected_connection_loss() {
        let identity = Keypair::generate_ed25519();
        let mut driver = EndpointDriver::new(
            EndpointNode::new(identity, WssTransportConfig::client(None)).unwrap(),
        );
        let relay = Keypair::generate_ed25519().public().to_peer_id();
        let first = ConnectionId::new_unchecked(31);
        driver
            .connections
            .established(relay, first, listener(31))
            .unwrap();
        let reservation_listener = ReservationListenerId::new(ListenerId::next());
        let mut reservation = ReservationSlot::pending(reservation_listener);
        assert!(reservation.mark_ready(reservation_listener));
        driver.reservation = Some(reservation);
        let address: EndpointRelayAddress =
            format!("/ip4/127.0.0.1/tcp/1/p2p/{relay}").parse().unwrap();
        let lease = ReservationLease {
            relay: RelayConnection {
                binding: ConnectionBinding {
                    peer: relay,
                    connection: first,
                },
                address,
            },
            listener: reservation_listener,
        };
        assert!(lease.is_usable(&driver));

        driver
            .connections
            .established(relay, ConnectionId::new_unchecked(32), listener(32))
            .unwrap();
        assert!(lease.is_usable(&driver));
        driver.connections.closed(&relay, &first);
        assert!(!lease.is_usable(&driver));
    }

    #[test]
    fn pending_relay_dials_are_removed_by_exact_connection_id() {
        let first = ConnectionId::new_unchecked(11);
        let second = ConnectionId::new_unchecked(12);
        let mut pending = PendingRelayDials::new();
        assert!(pending.is_empty());
        pending.insert(first).unwrap();
        pending.insert(second).unwrap();
        assert!(!pending.is_empty());
        pending.remove(ConnectionId::new_unchecked(13));
        assert!(!pending.is_empty());
        pending.remove(first);
        assert!(!pending.is_empty());
        pending.remove(second);
        assert!(pending.is_empty());

        for connection in 20..28 {
            pending
                .insert(ConnectionId::new_unchecked(connection))
                .unwrap();
        }
        assert!(matches!(
            pending.insert(ConnectionId::new_unchecked(28)),
            Err(EndpointError::RelayDialTrackerUnavailable)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bound_io_rejects_additional_or_lost_physical_connections() {
        let identity = Keypair::generate_ed25519();
        let local_peer = identity.public().to_peer_id();
        let mut driver = EndpointDriver::new(
            EndpointNode::new(identity, WssTransportConfig::client(None)).unwrap(),
        );
        assert_eq!(driver.peer_id(), local_peer);
        assert_eq!(drive(&mut driver, std::future::ready(5)).await, 5);
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        assert_eq!(driver.connection_count(&peer), 0);
        assert!(!driver.has_unique_connection(&peer));
        assert!(matches!(
            driver.bind(peer),
            Err(EndpointError::BoundConnectionLost)
        ));
        driver.close_peer_and_wait(peer).await.unwrap();

        let first = ConnectionId::new_unchecked(1);
        driver
            .connections
            .established(peer, first, listener(1))
            .unwrap();
        assert_eq!(driver.connection_count(&peer), 1);
        assert!(driver.has_unique_connection(&peer));
        let binding = driver.bind(peer).unwrap();
        assert_eq!(binding.peer(), peer);
        assert_eq!(binding.connection(), first);
        assert!(driver.has_connection(binding));
        assert_eq!(
            drive_bound(&mut driver, binding, async { 7 })
                .await
                .unwrap(),
            7
        );

        let second = ConnectionId::new_unchecked(2);
        driver
            .connections
            .established(peer, second, listener(2))
            .unwrap();
        assert_eq!(driver.connection_count(&peer), 2);
        assert!(!driver.has_unique_connection(&peer));
        assert!(matches!(
            driver.bind(peer),
            Err(EndpointError::AdditionalBoundConnection)
        ));
        let wrong = ConnectionBinding {
            peer,
            connection: ConnectionId::new_unchecked(3),
        };
        assert!(matches!(
            driver.enforce_binding(wrong),
            Err(EndpointError::AdditionalBoundConnection)
        ));
        assert!(matches!(
            drive_bound(&mut driver, binding, async { 9 }).await,
            Err(EndpointError::AdditionalBoundConnection)
        ));

        driver.connections.closed(&peer, &first);
        driver.connections.closed(&peer, &second);
        assert!(matches!(
            drive_bound(&mut driver, binding, async { 11 }).await,
            Err(EndpointError::BoundConnectionLost)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn driver_guards_and_absolute_deadlines_cover_failure_paths() {
        let mut driver = endpoint_driver();
        let relay_peer = Keypair::generate_ed25519().public().to_peer_id();
        let relay = relay_connection(relay_peer, 40);
        let listener = ReservationListenerId::new(ListenerId::next());
        driver.reservation = Some(ReservationSlot::pending(listener));
        assert!(matches!(
            driver.reserve(relay.address()),
            Err(EndpointError::ReservationAlreadyExists)
        ));

        let other_listener = ReservationListenerId::new(ListenerId::next());
        driver.remove_reservation(other_listener);
        assert!(driver.reservation.is_some());
        driver.remove_reservation(listener);
        assert!(driver.reservation.is_none());

        let connection = ConnectionId::new_unchecked(40);
        driver
            .connections
            .established(relay_peer, connection, listener_endpoint(40))
            .unwrap();
        assert!(matches!(
            driver
                .close_peer_and_wait_until(relay_peer, tokio::time::Instant::now())
                .await,
            Err(EndpointError::ConnectionCloseDidNotConverge)
        ));

        let binding = ConnectionBinding {
            peer: relay_peer,
            connection,
        };
        driver
            .connections
            .established(
                relay_peer,
                ConnectionId::new_unchecked(41),
                listener_endpoint(41),
            )
            .unwrap();
        assert!(matches!(
            converge_to_binding(&mut driver, binding, tokio::time::Instant::now()).await,
            Err(EndpointError::RelayDidNotConverge)
        ));
        driver.connections.closed(&relay_peer, &connection);
        driver
            .connections
            .closed(&relay_peer, &ConnectionId::new_unchecked(41));
        assert!(matches!(
            converge_to_binding(&mut driver, binding, tokio::time::Instant::now()).await,
            Err(EndpointError::SelectedConnectionLost)
        ));
        let missing_relay = relay_connection(relay_peer, 42);
        assert!(matches!(
            reconverge_relay(&mut driver, &missing_relay).await,
            Err(EndpointError::SelectedConnectionLost)
        ));
        assert!(matches!(
            connect_target_until(
                &mut driver,
                relay_peer,
                tokio::time::Instant::now(),
                DirectUpgradePolicy::Enabled,
            )
            .await,
            Err(EndpointError::RelayUnavailable)
        ));
        assert!(matches!(
            wait_for_reservation_until(&mut driver, relay, listener, tokio::time::Instant::now(),)
                .await,
            Err(EndpointError::RelayUnavailable)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn relay_drain_classifies_lost_extra_and_unselected_connections() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let missing = ConnectionBinding {
            peer,
            connection: ConnectionId::new_unchecked(50),
        };
        let mut driver = endpoint_driver();
        assert!(matches!(
            drain_relay_state(
                &mut driver,
                peer,
                Some(missing),
                tokio::time::Instant::now(),
            )
            .await,
            Err(EndpointError::SelectedConnectionLost)
        ));

        let kept = ConnectionId::new_unchecked(51);
        let extra = ConnectionId::new_unchecked(52);
        driver
            .connections
            .established(peer, kept, listener_endpoint(51))
            .unwrap();
        driver
            .connections
            .established(peer, extra, listener_endpoint(52))
            .unwrap();
        let binding = ConnectionBinding {
            peer,
            connection: kept,
        };
        assert!(matches!(
            drain_relay_state(
                &mut driver,
                peer,
                Some(binding),
                tokio::time::Instant::now(),
            )
            .await,
            Err(EndpointError::RelayDidNotConverge)
        ));
        assert!(matches!(
            drain_relay_state(&mut driver, peer, None, tokio::time::Instant::now()).await,
            Err(EndpointError::RelayDidNotConverge)
        ));

        let mut event_driver = endpoint_driver();
        event_driver
            .connections
            .established(peer, kept, listener_endpoint(51))
            .unwrap();
        event_driver
            .connections
            .established(peer, extra, listener_endpoint(52))
            .unwrap();
        let relay = relay_connection(peer, 53);
        let listener = event_driver.reserve(relay.address()).unwrap();
        assert!(event_driver.node.swarm_mut().remove_listener(listener.0));
        assert!(matches!(
            drain_relay_state(
                &mut event_driver,
                peer,
                Some(binding),
                tokio::time::Instant::now() + Duration::from_millis(100),
            )
            .await,
            Err(EndpointError::RelayDidNotConverge)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn relay_dial_and_stream_failures_are_structured_without_waiting() {
        let mut driver = endpoint_driver();
        let relay_peer = Keypair::generate_ed25519().public().to_peer_id();
        let relays = relay_set(relay_peer);
        driver
            .pending_relay_dials
            .insert(ConnectionId::new_unchecked(60))
            .unwrap();
        assert!(matches!(
            dial_relay_set(&mut driver, &relays),
            Err(EndpointError::RelayDialTrackerUnavailable)
        ));
        driver.pending_relay_dials = PendingRelayDials::new();
        assert!(matches!(
            connect_relay_attempt(&mut driver, &relays, tokio::time::Instant::now()).await,
            Err(EndpointError::RelayUnavailable)
        ));

        let mut streams = driver.node.streams().clone();
        let absent = Keypair::generate_ed25519().public().to_peer_id();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            open_stream(
                &mut driver,
                &mut streams,
                absent,
                "/yonder/test/missing/1.0.0",
            ),
        )
        .await
        .unwrap();
        assert!(matches!(result, Err(EndpointError::Application(_))));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn listener_close_and_drive_consume_real_swarm_events() {
        let mut driver = endpoint_driver();
        let relay_peer = Keypair::generate_ed25519().public().to_peer_id();
        let relay = relay_connection(relay_peer, 70);
        let listener = driver.reserve(relay.address()).unwrap();
        assert!(driver.node.swarm_mut().remove_listener(listener.0));
        let result = wait_for_reservation(&mut driver, relay.clone(), listener).await;
        assert!(matches!(result, Err(EndpointError::ReservationClosed)));
        driver.remove_reservation(listener);

        let stale_listener = driver.reserve(relay.address()).unwrap();
        assert!(driver.node.swarm_mut().remove_listener(stale_listener.0));
        let ignored_listener = ReservationListenerId::new(ListenerId::next());
        assert!(matches!(
            wait_for_reservation_until(
                &mut driver,
                relay,
                ignored_listener,
                tokio::time::Instant::now() + Duration::from_millis(100),
            )
            .await,
            Err(EndpointError::RelayUnavailable)
        ));
        driver.remove_reservation(stale_listener);

        let output = drive(&mut driver, async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            17
        })
        .await;
        assert_eq!(output, 17);
    }

    #[test]
    fn reservation_decisions_cover_every_terminal_and_ignored_event() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let relay = relay_connection(peer, 80);
        let listener = ReservationListenerId::new(ListenerId::next());
        let other = ReservationListenerId::new(ListenerId::next());

        assert!(matches!(
            reservation_decision(
                &EndpointEvent::ReservationReady(listener),
                &relay,
                listener,
                true,
            ),
            ReservationDecision::Ready
        ));
        assert!(matches!(
            reservation_decision(
                &EndpointEvent::ReservationReady(listener),
                &relay,
                listener,
                false,
            ),
            ReservationDecision::Failed(EndpointError::SelectedConnectionLost)
        ));
        assert!(matches!(
            reservation_decision(
                &EndpointEvent::ReservationClosed(listener),
                &relay,
                listener,
                true,
            ),
            ReservationDecision::Failed(EndpointError::ReservationClosed)
        ));
        assert!(matches!(
            reservation_decision(
                &EndpointEvent::Closed {
                    peer,
                    connection: relay.binding().connection(),
                },
                &relay,
                listener,
                true,
            ),
            ReservationDecision::Failed(EndpointError::SelectedConnectionLost)
        ));
        for event in [
            EndpointEvent::ReservationReady(other),
            EndpointEvent::ReservationClosed(other),
            EndpointEvent::DialFailed(ConnectionId::new_unchecked(81)),
        ] {
            assert!(matches!(
                reservation_decision(&event, &relay, listener, true),
                ReservationDecision::Continue
            ));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn selection_event_helpers_cover_accept_reject_ping_close_and_ignore() {
        let mut driver = endpoint_driver();
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let other = Keypair::generate_ed25519().public().to_peer_id();
        let mut relay_selection = ConnectionSelection::new();
        let mut addresses = Vec::new();

        assert!(process_relay_selection_event(
            &mut driver,
            &mut relay_selection,
            &mut addresses,
            peer,
            established(peer, 90, listener_endpoint(90)),
        ));
        assert!(!process_relay_selection_event(
            &mut driver,
            &mut relay_selection,
            &mut addresses,
            peer,
            EndpointEvent::Ping {
                peer,
                connection: ConnectionId::new_unchecked(90),
                round_trip: Ok(Duration::from_millis(1)),
            },
        ));
        assert!(!process_relay_selection_event(
            &mut driver,
            &mut relay_selection,
            &mut addresses,
            peer,
            EndpointEvent::Closed {
                peer,
                connection: ConnectionId::new_unchecked(90),
            },
        ));
        assert!(!process_relay_selection_event(
            &mut driver,
            &mut relay_selection,
            &mut addresses,
            peer,
            EndpointEvent::DialFailed(ConnectionId::new_unchecked(90)),
        ));
        assert!(!process_relay_selection_event(
            &mut driver,
            &mut relay_selection,
            &mut addresses,
            peer,
            established(other, 91, listener_endpoint(91)),
        ));

        for connection in 92..94 {
            assert!(process_relay_selection_event(
                &mut driver,
                &mut relay_selection,
                &mut addresses,
                peer,
                established(peer, connection, listener_endpoint(connection)),
            ));
        }
        assert!(!process_relay_selection_event(
            &mut driver,
            &mut relay_selection,
            &mut addresses,
            peer,
            established(peer, 94, listener_endpoint(94)),
        ));

        let mut target_selection = ConnectionSelection::new();
        assert!(process_target_selection_event(
            &mut driver,
            &mut target_selection,
            peer,
            established(peer, 100, listener_endpoint(100)),
            true,
        ));
        assert!(!process_target_selection_event(
            &mut driver,
            &mut target_selection,
            peer,
            EndpointEvent::Ping {
                peer,
                connection: ConnectionId::new_unchecked(100),
                round_trip: Ok(Duration::from_millis(1)),
            },
            true,
        ));
        assert!(!process_target_selection_event(
            &mut driver,
            &mut target_selection,
            peer,
            EndpointEvent::Closed {
                peer,
                connection: ConnectionId::new_unchecked(100),
            },
            true,
        ));
        assert!(!process_target_selection_event(
            &mut driver,
            &mut target_selection,
            peer,
            EndpointEvent::Ping {
                peer,
                connection: ConnectionId::new_unchecked(100),
                round_trip: Err(()),
            },
            true,
        ));
        for connection in 101..104 {
            let accepted = process_target_selection_event(
                &mut driver,
                &mut target_selection,
                peer,
                established(peer, connection, listener_endpoint(connection)),
                true,
            );
            assert_eq!(accepted, connection < 103);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn selected_relay_address_is_canonical_and_bound_to_the_winner() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let loser = ConnectionId::new_unchecked(110);
        let winner = ConnectionId::new_unchecked(111);
        let selected = selected_relay_address(
            vec![
                (loser, "/ip4/192.0.2.1/tcp/1".parse().unwrap()),
                (winner, "/ip4/192.0.2.2/tcp/2".parse().unwrap()),
            ],
            winner,
            peer,
        )
        .unwrap();
        assert_eq!(selected.relay().get(), peer);

        let canonical: Multiaddr = format!("/ip4/192.0.2.3/tcp/3/p2p/{peer}").parse().unwrap();
        assert_eq!(
            selected_relay_address(vec![(winner, canonical.clone())], winner, peer)
                .unwrap()
                .as_multiaddr(),
            &canonical
        );
        assert!(matches!(
            selected_relay_address(vec![(winner, Multiaddr::empty())], winner, peer),
            Err(EndpointError::InvalidSelectedAddress)
        ));
        assert!(matches!(
            selected_relay_address(Vec::new(), winner, peer),
            Err(EndpointError::InvalidSelectedAddress)
        ));

        let first = ConnectionId::new_unchecked(112);
        let second = ConnectionId::new_unchecked(113);
        let first_endpoint = listener_endpoint(112);
        let second_endpoint = listener_endpoint(113);
        let mut selection = ConnectionSelection::new();
        selection.established(first, &first_endpoint).unwrap();
        selection.established(second, &second_endpoint).unwrap();
        selection.ping(first, Duration::from_millis(1)).unwrap();
        selection.ping(first, Duration::from_millis(1)).unwrap();
        let mut driver = endpoint_driver();
        let selected = finish_relay_selection(
            &mut driver,
            selection,
            vec![
                (first, first_endpoint.get_remote_address().clone()),
                (second, second_endpoint.get_remote_address().clone()),
            ],
            peer,
        )
        .unwrap();
        assert_eq!(selected.peer(), peer);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn established_roster_overflow_and_drain_event_are_bounded() {
        let mut driver = endpoint_driver();
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        for connection in 200..208 {
            assert!(
                driver
                    .record_established(
                        peer,
                        ConnectionId::new_unchecked(connection),
                        listener_endpoint(connection as u16),
                    )
                    .is_some()
            );
        }
        assert!(
            driver
                .record_established(
                    peer,
                    ConnectionId::new_unchecked(208),
                    listener_endpoint(208),
                )
                .is_none()
        );

        let binding = ConnectionBinding {
            peer,
            connection: ConnectionId::new_unchecked(200),
        };
        assert!(matches!(
            relay_drain_event(
                &EndpointEvent::Closed {
                    peer,
                    connection: binding.connection(),
                },
                Some(binding),
            ),
            Err(EndpointError::SelectedConnectionLost)
        ));
        assert!(
            relay_drain_event(
                &EndpointEvent::DialFailed(ConnectionId::new_unchecked(209)),
                Some(binding),
            )
            .is_ok()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bound_event_and_output_helpers_recheck_the_exact_roster() {
        let mut driver = endpoint_driver();
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let connection = ConnectionId::new_unchecked(120);
        driver
            .connections
            .established(peer, connection, listener_endpoint(120))
            .unwrap();
        let binding = ConnectionBinding { peer, connection };
        assert_eq!(finish_bound_output(&mut driver, binding, 5).unwrap(), 5);
        enforce_binding_after_event(
            &mut driver,
            binding,
            &EndpointEvent::Ping {
                peer,
                connection,
                round_trip: Ok(Duration::ZERO),
            },
        )
        .unwrap();

        driver
            .connections
            .established(
                peer,
                ConnectionId::new_unchecked(121),
                listener_endpoint(121),
            )
            .unwrap();
        assert!(matches!(
            enforce_binding_after_event(
                &mut driver,
                binding,
                &EndpointEvent::Established {
                    peer,
                    connection: ConnectionId::new_unchecked(121),
                    endpoint: listener_endpoint(121),
                },
            ),
            Err(EndpointError::AdditionalBoundConnection)
        ));
        driver.connections.closed(&peer, &connection);
        driver
            .connections
            .closed(&peer, &ConnectionId::new_unchecked(121));
        assert!(matches!(
            enforce_binding_after_event(
                &mut driver,
                binding,
                &EndpointEvent::Closed { peer, connection },
            ),
            Err(EndpointError::BoundConnectionLost)
        ));
        assert!(matches!(
            finish_bound_output(&mut driver, binding, 7),
            Err(EndpointError::BoundConnectionLost)
        ));
    }

    fn endpoint_driver() -> EndpointDriver {
        EndpointDriver::new(
            EndpointNode::new(
                Keypair::generate_ed25519(),
                WssTransportConfig::client(None),
            )
            .unwrap(),
        )
    }

    fn relay_set(peer: yonder_net::PeerId) -> EndpointRelaySet {
        EndpointRelaySet::new(vec![relay_connection(peer, 1).address]).unwrap()
    }

    fn relay_connection(peer: yonder_net::PeerId, port: u16) -> RelayConnection {
        RelayConnection {
            binding: ConnectionBinding {
                peer,
                connection: ConnectionId::new_unchecked(usize::from(port)),
            },
            address: format!("/ip4/127.0.0.1/tcp/{port}/p2p/{peer}")
                .parse()
                .unwrap(),
        }
    }

    fn established(
        peer: yonder_net::PeerId,
        connection: u16,
        endpoint: ConnectedPoint,
    ) -> EndpointEvent {
        EndpointEvent::Established {
            peer,
            connection: ConnectionId::new_unchecked(usize::from(connection)),
            endpoint,
        }
    }

    fn listener(port: u16) -> ConnectedPoint {
        listener_endpoint(port)
    }

    fn listener_endpoint(port: u16) -> ConnectedPoint {
        ConnectedPoint::Listener {
            local_addr: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            send_back_addr: format!("/ip4/192.0.2.1/tcp/{port}").parse().unwrap(),
        }
    }
}
