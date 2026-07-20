use crate::error::{CodeError, DomainError};
use crate::random::{RandomError, SecureRandom};
use data_encoding::{Encoding, Specification};
use std::fmt;
use std::str::FromStr;
use std::sync::OnceLock;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const SYMBOLS: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const LOCATOR_MAX: u32 = (1 << 20) - 1;
const SECRET_MAX: u64 = (1 << 60) - 1;

fn crockford() -> &'static Encoding {
    static ENCODING: OnceLock<Encoding> = OnceLock::new();
    ENCODING.get_or_init(|| {
        let mut specification = Specification::new();
        specification.symbols.push_str(SYMBOLS);
        specification
            .encoding()
            .expect("the frozen Crockford alphabet is valid")
    })
}

/// The public 20-bit relay lookup identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Locator(u32);

impl Locator {
    /// The number of possible locator values.
    pub const SPACE: u32 = 1 << 20;

    /// Creates a locator after checking its 20-bit invariant.
    pub const fn new(value: u32) -> Result<Self, DomainError> {
        if value <= LOCATOR_MAX {
            Ok(Self(value))
        } else {
            Err(DomainError::LocatorOutOfRange)
        }
    }

    /// Creates a locator from its three-byte network representation.
    pub const fn from_wire(bytes: [u8; 3]) -> Result<Self, DomainError> {
        if bytes[0] & 0xF0 != 0 {
            return Err(DomainError::LocatorOutOfRange);
        }
        let value = ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32;
        Ok(Self(value))
    }

    /// Generates a uniformly distributed locator starting point.
    pub fn random(random: &mut impl SecureRandom) -> Result<Self, RandomError> {
        let mut bytes = [0_u8; 3];
        random.try_fill(&mut bytes)?;
        bytes[0] &= 0x0F;
        Ok(Self::from_wire(bytes).expect("masking enforces the locator invariant"))
    }

    /// Returns the raw 20-bit value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Returns the three-byte network representation.
    #[must_use]
    pub const fn to_wire(self) -> [u8; 3] {
        [
            ((self.0 >> 16) & 0x0F) as u8,
            (self.0 >> 8) as u8,
            self.0 as u8,
        ]
    }

    /// Advances in the 20-bit ring.
    #[must_use]
    pub const fn wrapping_next(self) -> Self {
        Self((self.0 + 1) & LOCATOR_MAX)
    }

    fn write_symbols(self, output: &mut [u8; 4]) {
        let wire = self.to_wire();
        let packed = [
            wire[0] << 4 | wire[1] >> 4,
            wire[1] << 4 | wire[2] >> 4,
            wire[2] << 4,
        ];
        let mut encoded = [0_u8; 5];
        crockford().encode_mut(&packed, &mut encoded);
        output.copy_from_slice(&encoded[..4]);
    }
}

impl fmt::Display for Locator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut symbols = [0_u8; 4];
        self.write_symbols(&mut symbols);
        let value = std::str::from_utf8(&symbols).map_err(|_| fmt::Error)?;
        formatter.write_str(value)
    }
}

/// The secret 60-bit portion of a connection code.
///
/// Secrets are deliberately move-only so an accidental copy cannot extend their lifetime.
///
/// ```compile_fail
/// use yonder_core::PakeSecret;
///
/// let secret = PakeSecret::from_u64(7).unwrap();
/// let duplicate = secret.clone();
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PakeSecret([u8; 8]);

impl PakeSecret {
    /// Creates a PAKE secret after checking its 60-bit invariant.
    pub const fn from_bytes(bytes: [u8; 8]) -> Result<Self, DomainError> {
        if bytes[0] & 0xF0 == 0 {
            Ok(Self(bytes))
        } else {
            Err(DomainError::PakeSecretOutOfRange)
        }
    }

    /// Creates a PAKE secret from an integer, primarily for deterministic tests.
    pub const fn from_u64(value: u64) -> Result<Self, DomainError> {
        if value <= SECRET_MAX {
            Ok(Self(value.to_be_bytes()))
        } else {
            Err(DomainError::PakeSecretOutOfRange)
        }
    }

    /// Generates a uniformly distributed PAKE secret.
    pub fn random(random: &mut impl SecureRandom) -> Result<Self, RandomError> {
        let mut bytes = Zeroizing::new([0_u8; 8]);
        random.try_fill(bytes.as_mut())?;
        bytes[0] &= 0x0F;
        Ok(Self(std::mem::take(&mut *bytes)))
    }

    /// Exposes the secret only to the PAKE adapter.
    #[must_use]
    pub const fn expose_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl fmt::Debug for PakeSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PakeSecret([REDACTED])")
    }
}

impl fmt::Display for PakeSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

/// A validated 80-bit one-time Yonder connection code.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ConnectionCode {
    #[zeroize(skip)]
    locator: Locator,
    secret: PakeSecret,
}

impl ConnectionCode {
    /// Creates a code from validated domain components.
    #[must_use]
    pub const fn new(locator: Locator, secret: PakeSecret) -> Self {
        Self { locator, secret }
    }

    /// Generates the secret portion for a relay-assigned locator.
    pub fn generate(locator: Locator, random: &mut impl SecureRandom) -> Result<Self, RandomError> {
        PakeSecret::random(random).map(|secret| Self::new(locator, secret))
    }

    /// Returns the public lookup portion.
    #[must_use]
    pub const fn locator(&self) -> Locator {
        self.locator
    }

    /// Borrows the secret for PAKE registration or login.
    #[must_use]
    pub const fn secret(&self) -> &PakeSecret {
        &self.secret
    }

    /// Moves the validated components out of the code.
    #[must_use]
    pub fn into_parts(mut self) -> (Locator, PakeSecret) {
        let locator = self.locator;
        let secret = std::mem::replace(
            &mut self.secret,
            PakeSecret::from_u64(0).expect("zero is a valid secret"),
        );
        (locator, secret)
    }

    /// Returns an explicitly named display wrapper for the user-facing code.
    #[must_use]
    pub const fn expose(&self) -> ExposedConnectionCode<'_> {
        ExposedConnectionCode(self)
    }

    fn packed(&self) -> Zeroizing<[u8; 10]> {
        let locator = self.locator.get();
        let secret = self.secret.expose_bytes();
        let mut packed = Zeroizing::new([0_u8; 10]);
        packed[0] = (locator >> 12) as u8;
        packed[1] = (locator >> 4) as u8;
        packed[2] = ((locator as u8) << 4) | secret[0];
        packed[3..].copy_from_slice(&secret[1..]);
        packed
    }
}

impl FromStr for ConnectionCode {
    type Err = CodeError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let bytes = input.as_bytes();
        let mut normalized = Zeroizing::new([0_u8; 16]);
        match bytes.len() {
            16 => normalize_symbols(bytes, &mut normalized)?,
            19 => {
                if bytes[4] != b'-' || bytes[9] != b'-' || bytes[14] != b'-' {
                    return Err(CodeError::InvalidGrouping);
                }
                let mut compact = Zeroizing::new([0_u8; 16]);
                compact[..4].copy_from_slice(&bytes[..4]);
                compact[4..8].copy_from_slice(&bytes[5..9]);
                compact[8..12].copy_from_slice(&bytes[10..14]);
                compact[12..].copy_from_slice(&bytes[15..]);
                normalize_symbols(compact.as_ref(), &mut normalized)?;
            }
            _ => return Err(CodeError::InvalidLength),
        }

        let mut packed = Zeroizing::new([0_u8; 10]);
        crockford()
            .decode_mut(normalized.as_ref(), packed.as_mut())
            .map_err(|_| CodeError::InvalidEncoding)?;

        let locator = Locator::new(
            (u32::from(packed[0]) << 12) | (u32::from(packed[1]) << 4) | u32::from(packed[2] >> 4),
        )
        .map_err(|_| CodeError::InvalidEncoding)?;
        let mut secret = Zeroizing::new([0_u8; 8]);
        secret[0] = packed[2] & 0x0F;
        secret[1..].copy_from_slice(&packed[3..]);
        let secret = PakeSecret::from_bytes(std::mem::take(&mut *secret))
            .map_err(|_| CodeError::InvalidEncoding)?;
        Ok(Self::new(locator, secret))
    }
}

impl fmt::Debug for ConnectionCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionCode")
            .field("locator", &self.locator)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for ConnectionCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

/// Explicit authorization to render a connection code for its intended user.
///
/// The display capability cannot outlive the code that owns the secret.
///
/// ```compile_fail
/// use yonder_core::{ConnectionCode, Locator, PakeSecret};
///
/// let exposed = {
///     let code = ConnectionCode::new(
///         Locator::new(1).unwrap(),
///         PakeSecret::from_u64(7).unwrap(),
///     );
///     code.expose()
/// };
/// println!("{exposed}");
/// ```
pub struct ExposedConnectionCode<'a>(&'a ConnectionCode);

impl fmt::Display for ExposedConnectionCode<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let packed = self.0.packed();
        let mut symbols = Zeroizing::new([0_u8; 16]);
        crockford().encode_mut(packed.as_ref(), symbols.as_mut());
        let symbols = std::str::from_utf8(symbols.as_ref()).map_err(|_| fmt::Error)?;
        write!(
            formatter,
            "{}-{}-{}-{}",
            &symbols[..4],
            &symbols[4..8],
            &symbols[8..12],
            &symbols[12..]
        )
    }
}

fn normalize_symbols(input: &[u8], output: &mut [u8; 16]) -> Result<(), CodeError> {
    for (destination, source) in output.iter_mut().zip(input.iter().copied()) {
        *destination = match source {
            b'a'..=b'z' => normalize_upper(source - b'a' + b'A')?,
            b'A'..=b'Z' | b'0'..=b'9' => normalize_upper(source)?,
            _ => return Err(CodeError::InvalidCharacter),
        };
    }
    Ok(())
}

const fn normalize_upper(value: u8) -> Result<u8, CodeError> {
    match value {
        b'O' => Ok(b'0'),
        b'I' | b'L' => Ok(b'1'),
        b'U' => Err(CodeError::InvalidCharacter),
        candidate if alphabet_contains(candidate) => Ok(candidate),
        _ => Err(CodeError::InvalidCharacter),
    }
}

const fn alphabet_contains(value: u8) -> bool {
    let bytes = SYMBOLS.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == value {
            return true;
        }
        index += 1;
    }
    false
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{ConnectionCode, Locator, PakeSecret, alphabet_contains, normalize_upper};
    use crate::error::{CodeError, DomainError};
    use crate::random::{RandomError, SecureRandom};
    use proptest::prelude::*;

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
    fn golden_vectors_are_canonical() {
        let zero = ConnectionCode::new(Locator::new(0).unwrap(), PakeSecret::from_u64(0).unwrap());
        assert_eq!(zero.expose().to_string(), "0000-0000-0000-0000");

        let maximum = ConnectionCode::new(
            Locator::new((1 << 20) - 1).unwrap(),
            PakeSecret::from_u64((1 << 60) - 1).unwrap(),
        );
        assert_eq!(maximum.expose().to_string(), "ZZZZ-ZZZZ-ZZZZ-ZZZZ");
    }

    #[test]
    fn parsing_accepts_case_compact_and_aliases() {
        let canonical: ConnectionCode = "01AB-CDEF-GHJK-MNPQ".parse().unwrap();
        assert_eq!(canonical.expose().to_string(), "01AB-CDEF-GHJK-MNPQ");
        let compact: ConnectionCode = "o1ab-cdef-ghjk-mnpq".parse().unwrap();
        assert_eq!(compact.expose().to_string(), "01AB-CDEF-GHJK-MNPQ");
        let aliases: ConnectionCode = "OILI-OILI-OILI-OILI".parse().unwrap();
        assert_eq!(aliases.expose().to_string(), "0111-0111-0111-0111");
    }

    #[test]
    fn parsing_rejects_invalid_forms() {
        assert_eq!(
            "".parse::<ConnectionCode>().unwrap_err(),
            CodeError::InvalidLength
        );
        assert_eq!(
            "00000-0000-0000-000".parse::<ConnectionCode>().unwrap_err(),
            CodeError::InvalidGrouping
        );
        assert_eq!(
            "000000000000000_".parse::<ConnectionCode>().unwrap_err(),
            CodeError::InvalidCharacter
        );
        assert_eq!(
            "0000-0000-0000-000U".parse::<ConnectionCode>().unwrap_err(),
            CodeError::InvalidCharacter
        );
    }

    #[test]
    fn domain_boundaries_are_checked_and_redacted() {
        assert_eq!(Locator::new(1 << 20), Err(DomainError::LocatorOutOfRange));
        assert_eq!(
            Locator::from_wire([0x10, 0, 0]),
            Err(DomainError::LocatorOutOfRange)
        );
        assert!(matches!(
            PakeSecret::from_u64(1 << 60),
            Err(DomainError::PakeSecretOutOfRange)
        ));
        assert!(matches!(
            PakeSecret::from_bytes([0x10, 0, 0, 0, 0, 0, 0, 0]),
            Err(DomainError::PakeSecretOutOfRange)
        ));
        let code = ConnectionCode::new(Locator::new(7).unwrap(), PakeSecret::from_u64(9).unwrap());
        assert_eq!(code.to_string(), "[REDACTED]");
        assert!(!format!("{code:?}").contains("0009"));
        assert_eq!(code.secret().to_string(), "[REDACTED]");
        assert_eq!(format!("{:?}", code.secret()), "PakeSecret([REDACTED])");
    }

    #[test]
    fn locator_and_secret_helpers_preserve_their_invariants() {
        let locator = Locator::new(0xABCDE).unwrap();
        assert_eq!(Locator::from_wire(locator.to_wire()), Ok(locator));
        assert_eq!(locator.get(), 0xABCDE);
        assert_eq!(locator.to_string().len(), 4);
        assert_eq!(
            Locator::new(Locator::SPACE - 1).unwrap().wrapping_next(),
            Locator::new(0).unwrap()
        );

        let mut fixed = FixedRandom(Ok(0xFF));
        let random_locator = Locator::random(&mut fixed).unwrap();
        assert_eq!(random_locator, Locator::new(0xFFFFF).unwrap());
        let random_secret = PakeSecret::random(&mut fixed).unwrap();
        assert_eq!(
            random_secret.expose_bytes(),
            &[0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );

        let mut failing = FixedRandom(Err(RandomError));
        assert!(Locator::random(&mut failing).is_err());
        assert!(PakeSecret::random(&mut failing).is_err());
        assert!(ConnectionCode::generate(locator, &mut failing).is_err());

        let mut zero = FixedRandom(Ok(0));
        let generated = ConnectionCode::generate(locator, &mut zero).unwrap();
        let (actual_locator, actual_secret) = generated.into_parts();
        assert_eq!(actual_locator, locator);
        assert_eq!(actual_secret.expose_bytes(), &[0; 8]);
    }

    #[test]
    fn normalization_helpers_reject_every_non_alphabet_class() {
        assert_eq!(normalize_upper(b'O'), Ok(b'0'));
        assert_eq!(normalize_upper(b'I'), Ok(b'1'));
        assert_eq!(normalize_upper(b'L'), Ok(b'1'));
        assert_eq!(normalize_upper(b'U'), Err(CodeError::InvalidCharacter));
        assert_eq!(normalize_upper(b'!'), Err(CodeError::InvalidCharacter));
        assert_eq!(
            "0000-0000-0000-000u".parse::<ConnectionCode>().unwrap_err(),
            CodeError::InvalidCharacter
        );
        assert!(alphabet_contains(b'Z'));
        assert!(!alphabet_contains(b'I'));
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn arbitrary_eighty_bits_round_trip(bytes in any::<[u8; 10]>()) {
            let locator_value = (u32::from(bytes[0]) << 12)
                | (u32::from(bytes[1]) << 4)
                | u32::from(bytes[2] >> 4);
            let mut secret_bytes = [0_u8; 8];
            secret_bytes[0] = bytes[2] & 0x0f;
            secret_bytes[1..].copy_from_slice(&bytes[3..]);
            let original = ConnectionCode::new(
                Locator::new(locator_value).unwrap(),
                PakeSecret::from_bytes(secret_bytes).unwrap(),
            );
            let text = original.expose().to_string();
            let decoded: ConnectionCode = text.parse().unwrap();
            prop_assert_eq!(decoded.locator(), original.locator());
            prop_assert_eq!(decoded.secret().expose_bytes(), original.secret().expose_bytes());
            prop_assert_eq!(decoded.expose().to_string(), text);
        }
    }
}
