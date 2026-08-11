use crate::error::DomainError;

/// One enterprise authentication platform supported by Yonder 0.1.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnterpriseProvider {
    WeCom,
    Feishu,
}

impl EnterpriseProvider {
    /// Every platform in deterministic display order.
    pub const ALL: [Self; 2] = [Self::WeCom, Self::Feishu];

    /// The canonical lowercase platform name used in configuration, wire and logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WeCom => "wecom",
            Self::Feishu => "feishu",
        }
    }

    /// Parses a canonical lowercase platform name.
    #[must_use]
    pub fn from_name(value: &str) -> Option<Self> {
        match value {
            "wecom" => Some(Self::WeCom),
            "feishu" => Some(Self::Feishu),
            _ => None,
        }
    }

    /// The fixed wire tag of the platform.
    #[must_use]
    pub const fn wire_tag(self) -> u8 {
        match self {
            Self::WeCom => 0x01,
            Self::Feishu => 0x02,
        }
    }

    /// Parses a fixed wire tag.
    #[must_use]
    pub const fn from_wire_tag(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::WeCom),
            0x02 => Some(Self::Feishu),
            _ => None,
        }
    }
}

impl std::fmt::Display for EnterpriseProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The ordered, non-empty set of enterprise providers configured on a relay.
///
/// Enterprise mode requires at least one provider, each platform holds at
/// most one enterprise application, and both platforms may be configured
/// together. The set cannot be constructed empty and never changes after
/// startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnterpriseProviders {
    wecom: bool,
    feishu: bool,
}

impl EnterpriseProviders {
    /// Creates the enterprise-mode provider set; at least one provider is required.
    pub fn new(wecom: bool, feishu: bool) -> Result<Self, DomainError> {
        if !wecom && !feishu {
            return Err(DomainError::NoEnterpriseProvider);
        }
        Ok(Self { wecom, feishu })
    }

    /// Whether the given platform is part of the set.
    #[must_use]
    pub const fn contains(self, provider: EnterpriseProvider) -> bool {
        match provider {
            EnterpriseProvider::WeCom => self.wecom,
            EnterpriseProvider::Feishu => self.feishu,
        }
    }

    /// The number of configured providers.
    #[must_use]
    pub const fn len(self) -> usize {
        (self.wecom as u8 + self.feishu as u8) as usize
    }

    /// Whether the set holds no providers. Always false by construction:
    /// an empty set cannot be created.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        false
    }

    /// Iterates the configured providers in deterministic display order.
    pub fn iter(self) -> impl Iterator<Item = EnterpriseProvider> {
        EnterpriseProvider::ALL
            .into_iter()
            .filter(move |provider| self.contains(*provider))
    }

    /// The fixed wire bitmask of the provider set.
    #[must_use]
    pub const fn wire_mask(self) -> u8 {
        (self.wecom as u8) | ((self.feishu as u8) << 1)
    }

    /// Parses a fixed wire bitmask; only one or two providers are valid.
    #[must_use]
    pub const fn from_wire_mask(mask: u8) -> Option<Self> {
        match mask {
            0x01 => Some(Self {
                wecom: true,
                feishu: false,
            }),
            0x02 => Some(Self {
                wecom: false,
                feishu: true,
            }),
            0x03 => Some(Self {
                wecom: true,
                feishu: true,
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{EnterpriseProvider, EnterpriseProviders};
    use crate::error::DomainError;

    #[test]
    fn provider_names_round_trip_and_display() {
        for provider in EnterpriseProvider::ALL {
            assert_eq!(
                EnterpriseProvider::from_name(provider.as_str()),
                Some(provider)
            );
            assert_eq!(provider.to_string(), provider.as_str());
        }
        assert_eq!(EnterpriseProvider::from_name("wecom "), None);
        assert_eq!(EnterpriseProvider::from_name("WeCom"), None);
        assert_eq!(EnterpriseProvider::from_name(""), None);
        assert_eq!(EnterpriseProvider::from_name("aliyun"), None);
        assert_eq!(EnterpriseProvider::from_wire_tag(0x00), None);
        assert_eq!(
            EnterpriseProvider::from_wire_tag(0x01),
            Some(EnterpriseProvider::WeCom)
        );
        assert_eq!(
            EnterpriseProvider::from_wire_tag(0x02),
            Some(EnterpriseProvider::Feishu)
        );
        assert_eq!(EnterpriseProvider::from_wire_tag(0x03), None);
        assert_eq!(EnterpriseProvider::Feishu.wire_tag(), 0x02);
    }

    #[test]
    fn provider_sets_enforce_non_empty_and_deterministic_order() {
        assert_eq!(
            EnterpriseProviders::new(false, false),
            Err(DomainError::NoEnterpriseProvider)
        );

        let wecom = EnterpriseProviders::new(true, false).unwrap();
        assert_eq!(wecom.len(), 1);
        assert!(wecom.contains(EnterpriseProvider::WeCom));
        assert!(!wecom.contains(EnterpriseProvider::Feishu));
        assert_eq!(
            wecom.iter().collect::<Vec<_>>(),
            [EnterpriseProvider::WeCom]
        );

        let feishu = EnterpriseProviders::new(false, true).unwrap();
        assert_eq!(
            feishu.iter().collect::<Vec<_>>(),
            [EnterpriseProvider::Feishu]
        );

        let both = EnterpriseProviders::new(true, true).unwrap();
        assert_eq!(both.len(), 2);
        assert_eq!(
            both.iter().collect::<Vec<_>>(),
            [EnterpriseProvider::WeCom, EnterpriseProvider::Feishu]
        );
    }

    #[test]
    fn provider_sets_are_value_typed() {
        let both = EnterpriseProviders::new(true, true).unwrap();
        assert_eq!(both, both);
        assert_ne!(both, EnterpriseProviders::new(true, false).unwrap());
    }

    #[test]
    fn provider_set_wire_masks_round_trip() {
        for (wecom, feishu, mask) in [(true, false, 0x01), (false, true, 0x02), (true, true, 0x03)]
        {
            let providers = EnterpriseProviders::new(wecom, feishu).unwrap();
            assert_eq!(providers.wire_mask(), mask);
            assert_eq!(EnterpriseProviders::from_wire_mask(mask), Some(providers));
        }
        for mask in [0x00, 0x04, 0xFF] {
            assert_eq!(EnterpriseProviders::from_wire_mask(mask), None);
        }
    }
}
