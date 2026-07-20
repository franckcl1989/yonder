use rand::RngCore;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A failure to obtain bytes from the operating system CSPRNG.
#[derive(Debug, Error)]
#[error("the operating system secure random source failed")]
pub struct RandomError;

/// Fallible secure randomness supplied directly into a caller-owned buffer.
pub trait SecureRandom {
    /// Fills the whole buffer or returns an error without providing a fallback.
    fn try_fill(&mut self, destination: &mut [u8]) -> Result<(), RandomError>;
}

/// Production secure randomness backed by the operating system.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsSecureRandom;

impl SecureRandom for OsSecureRandom {
    fn try_fill(&mut self, destination: &mut [u8]) -> Result<(), RandomError> {
        rand::rngs::OsRng
            .try_fill_bytes(destination)
            .map_err(|_| RandomError)
    }
}

/// A short-lived Ed25519 seed that clears its first-party buffer on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IdentitySeed([u8; 32]);

impl IdentitySeed {
    /// Obtains a seed from the approved fallible CSPRNG boundary.
    pub fn generate(random: &mut impl SecureRandom) -> Result<Self, RandomError> {
        let mut seed = Self([0_u8; 32]);
        fill_or_zero(random, &mut seed.0)?;
        Ok(seed)
    }

    /// Borrows the seed for immediate import by the Ed25519 implementation.
    pub fn as_mut_bytes(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }
}

fn fill_or_zero(random: &mut impl SecureRandom, destination: &mut [u8]) -> Result<(), RandomError> {
    if let Err(error) = random.try_fill(destination) {
        destination.zeroize();
        return Err(error);
    }
    Ok(())
}

impl std::fmt::Debug for IdentitySeed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("IdentitySeed([REDACTED])")
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{IdentitySeed, OsSecureRandom, RandomError, SecureRandom, fill_or_zero};

    #[derive(Debug)]
    struct FixedRandom(Result<u8, RandomError>);

    impl SecureRandom for FixedRandom {
        fn try_fill(&mut self, destination: &mut [u8]) -> Result<(), RandomError> {
            match self.0 {
                Ok(value) => {
                    destination.fill(value);
                    Ok(())
                }
                Err(_) => Err(RandomError),
            }
        }
    }

    #[test]
    fn identity_seeds_are_fallible_mutable_and_redacted() {
        let mut fixed = FixedRandom(Ok(7));
        let mut seed = IdentitySeed::generate(&mut fixed).unwrap();
        assert_eq!(seed.as_mut_bytes(), &[7; 32]);
        seed.as_mut_bytes()[0] = 9;
        assert_eq!(seed.as_mut_bytes()[0], 9);
        assert_eq!(format!("{seed:?}"), "IdentitySeed([REDACTED])");

        let mut failing = FixedRandom(Err(RandomError));
        assert!(IdentitySeed::generate(&mut failing).is_err());
        assert_eq!(
            RandomError.to_string(),
            "the operating system secure random source failed"
        );
    }

    #[test]
    fn operating_system_random_fills_the_requested_buffer() {
        let mut random = OsSecureRandom;
        let mut bytes = [0_u8; 32];
        random.try_fill(&mut bytes).unwrap();
        assert_ne!(bytes, [0; 32]);
    }

    #[test]
    fn partial_random_failure_clears_every_written_seed_byte() {
        struct PartialFailure;

        impl SecureRandom for PartialFailure {
            fn try_fill(&mut self, destination: &mut [u8]) -> Result<(), RandomError> {
                let written = destination.len() / 2;
                destination[..written].fill(0xA5);
                Err(RandomError)
            }
        }

        let mut destination = [0xFF_u8; 32];
        assert!(fill_or_zero(&mut PartialFailure, &mut destination).is_err());
        assert_eq!(destination, [0; 32]);
        assert!(IdentitySeed::generate(&mut PartialFailure).is_err());
    }
}
