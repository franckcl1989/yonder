use thiserror::Error;

/// A bounded set of physical connection identifiers for one peer.
#[derive(Debug)]
pub struct ConnectionRoster<T, const CAPACITY: usize = 8> {
    entries: [Option<T>; CAPACITY],
    len: usize,
}

/// A roster capacity violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RosterError {
    #[error("the connection roster is full")]
    Full,
}

impl<T: PartialEq, const CAPACITY: usize> ConnectionRoster<T, CAPACITY> {
    /// Creates an empty roster without a heap allocation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: std::array::from_fn(|_| None),
            len: 0,
        }
    }

    /// Inserts a connection. Duplicate establishment events are idempotent.
    pub fn insert(&mut self, connection: T) -> Result<bool, RosterError> {
        if self.contains(&connection) {
            return Ok(false);
        }
        let slot = self
            .entries
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(RosterError::Full)?;
        *slot = Some(connection);
        self.len += 1;
        Ok(true)
    }

    /// Removes a connection. Duplicate close events are idempotent.
    pub fn remove(&mut self, connection: &T) -> bool {
        let Some(slot) = self
            .entries
            .iter_mut()
            .find(|entry| entry.as_ref() == Some(connection))
        else {
            return false;
        };
        *slot = None;
        self.len -= 1;
        true
    }

    /// Returns whether the roster contains a connection.
    #[must_use]
    pub fn contains(&self, connection: &T) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.as_ref() == Some(connection))
    }

    /// Returns the number of active physical connections.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the roster is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the connection only when the roster has converged to exactly one.
    #[must_use]
    pub fn unique(&self) -> Option<&T> {
        if self.len != 1 {
            return None;
        }
        self.entries.iter().find_map(Option::as_ref)
    }

    /// Iterates over all live entries.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.entries.iter().filter_map(Option::as_ref)
    }
}

impl<T: PartialEq, const CAPACITY: usize> Default for ConnectionRoster<T, CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{ConnectionRoster, RosterError};

    #[test]
    fn insert_remove_and_unique_are_bounded_and_idempotent() {
        let mut roster = ConnectionRoster::<u8, 2>::default();
        assert!(roster.is_empty());
        assert_eq!(roster.len(), 0);
        assert_eq!(roster.insert(4), Ok(true));
        assert_eq!(roster.len(), 1);
        assert_eq!(roster.insert(4), Ok(false));
        assert_eq!(roster.unique(), Some(&4));
        assert_eq!(roster.insert(5), Ok(true));
        assert_eq!(roster.unique(), None);
        assert_eq!(roster.insert(6), Err(RosterError::Full));
        assert_eq!(roster.iter().copied().collect::<Vec<_>>(), vec![4, 5]);
        assert!(roster.remove(&4));
        assert!(!roster.remove(&4));
        assert_eq!(roster.unique(), Some(&5));
    }
}
