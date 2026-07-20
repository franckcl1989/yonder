use zeroize::Zeroizing;

/// An owned secret document whose backing allocation is cleared on drop.
pub struct SecretDocument(Zeroizing<Vec<u8>>);

impl SecretDocument {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Transfers the backing allocation across an approved upstream ownership boundary.
    #[must_use]
    pub fn into_upstream_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut *self.0)
    }
}

impl std::fmt::Debug for SecretDocument {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretDocument([REDACTED])")
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::SecretDocument;

    #[test]
    fn document_is_explicitly_redacted() {
        let document = SecretDocument::new(vec![1, 2, 3]);
        assert_eq!(document.as_bytes(), &[1, 2, 3]);
        assert_eq!(format!("{document:?}"), "SecretDocument([REDACTED])");

        let document = SecretDocument::new(vec![4, 5, 6]);
        assert_eq!(document.into_upstream_bytes(), [4, 5, 6]);
    }
}
