#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Strict layered runtime configuration shared by Yonder binaries.

use config::{Config, Environment, File as ConfigFile, FileFormat};
use serde::{Deserialize, de::DeserializeOwned};
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use thiserror::Error;

const MAX_CONFIG_BYTES: u64 = 64 * 1024;

/// The binary whose independently named configuration is being loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Application {
    Yon,
    Relay,
}

/// The precedence of the layer that most recently supplied one field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfigurationLayer {
    SystemFile,
    WorkingFile,
    Environment,
}

impl Application {
    const fn file_name(self) -> &'static str {
        match self {
            Self::Yon => "yon.toml",
            Self::Relay => "yon-relay.toml",
        }
    }

    const fn environment_prefix(self) -> &'static str {
        match self {
            Self::Yon => "YON",
            Self::Relay => "YON_RELAY",
        }
    }

    /// Prefix used by this application's environment-variable layer.
    #[must_use]
    pub const fn configuration_environment_prefix(self) -> &'static str {
        self.environment_prefix()
    }
}

/// One known schema key, used to preserve path provenance without stringly APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConfigurationKey(&'static str);

impl ConfigurationKey {
    #[must_use]
    pub const fn new(key: &'static str) -> Self {
        Self(key)
    }

    const fn as_str(self) -> &'static str {
        self.0
    }
}

/// A normalized environment-backed configuration key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConfigurationEnvironmentKey(String);

impl std::fmt::Display for ConfigurationEnvironmentKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The platform-provided name of one configuration environment variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigurationEnvironmentVariable(String);

impl std::fmt::Display for ConfigurationEnvironmentVariable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Static information required to load one binary's typed schema.
#[derive(Debug, Clone, Copy)]
pub struct ConfigurationSchema {
    application: Application,
    list_keys: &'static [ConfigurationKey],
    parsed_scalar_keys: &'static [ConfigurationKey],
    path_keys: &'static [ConfigurationKey],
}

/// One configuration value or an ordered, non-normalized list of values.
///
/// This lets file configuration stay concise for the common case while still
/// accepting repeated trust anchors or certificate-chain documents.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum ConfigurationValues<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> ConfigurationValues<T> {
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        match self {
            Self::One(value) => std::slice::from_ref(value),
            Self::Many(values) => values,
        }
    }
}

impl ConfigurationSchema {
    #[must_use]
    pub const fn new(
        application: Application,
        list_keys: &'static [ConfigurationKey],
        parsed_scalar_keys: &'static [ConfigurationKey],
        path_keys: &'static [ConfigurationKey],
    ) -> Self {
        Self {
            application,
            list_keys,
            parsed_scalar_keys,
            path_keys,
        }
    }
}

/// Replaceable discovery boundary for process-global configuration sources.
pub trait ConfigurationSources {
    fn current_directory(&self) -> Result<PathBuf, std::io::Error>;
    fn system_directory(&self) -> Result<PathBuf, ConfigurationLocationError>;
    fn environment(&self) -> Vec<(OsString, OsString)>;
}

/// Production configuration discovery backed by the current process.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemConfigurationSources;

impl ConfigurationSources for SystemConfigurationSources {
    fn current_directory(&self) -> Result<PathBuf, std::io::Error> {
        std::env::current_dir()
    }

    fn system_directory(&self) -> Result<PathBuf, ConfigurationLocationError> {
        system_directory(std::env::var_os("PROGRAMDATA"))
    }

    fn environment(&self) -> Vec<(OsString, OsString)> {
        std::env::vars_os().collect()
    }
}

/// A typed configuration loader implemented with static dispatch.
pub trait ConfigLoader<T> {
    fn load(&self) -> Result<LoadedConfiguration<T>, ConfigurationError>;
}

/// The shared system, working-directory and environment loader.
#[derive(Debug)]
pub struct LayeredConfigLoader<S> {
    sources: S,
    schema: ConfigurationSchema,
}

/// The two file locations consulted by a layered configuration loader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigurationLocations {
    system_file: PathBuf,
    working_file: PathBuf,
    application: Application,
}

impl ConfigurationLocations {
    #[must_use]
    pub fn system_file(&self) -> &Path {
        &self.system_file
    }

    #[must_use]
    pub fn working_file(&self) -> &Path {
        &self.working_file
    }

    /// Inspects both file layers without loading or exposing any values.
    pub fn inspect(&self) -> Result<ConfigurationSourceReport<'_>, ConfigurationError> {
        Ok(ConfigurationSourceReport {
            locations: self,
            system_status: configuration_file_status(&self.system_file)?,
            working_status: configuration_file_status(&self.working_file)?,
        })
    }
}

/// A value-free, printable view of the configured precedence layers.
#[derive(Debug)]
pub struct ConfigurationSourceReport<'a> {
    locations: &'a ConfigurationLocations,
    system_status: ConfigurationFileStatus,
    working_status: ConfigurationFileStatus,
}

impl ConfigurationSourceReport<'_> {
    pub fn write_to(&self, output: &mut impl std::io::Write) -> std::io::Result<()> {
        writeln!(output, "Configuration precedence (lowest to highest):")?;
        writeln!(
            output,
            "1. System file: {} ({})",
            self.locations.system_file.display(),
            self.system_status
        )?;
        writeln!(
            output,
            "2. Working-directory file: {} ({})",
            self.locations.working_file.display(),
            self.working_status
        )?;
        writeln!(
            output,
            "3. Environment variables: {}_* (values hidden)",
            self.locations
                .application
                .configuration_environment_prefix()
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigurationFileStatus {
    Present,
    Missing,
    NotRegular,
}

impl std::fmt::Display for ConfigurationFileStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Present => "present",
            Self::Missing => "missing",
            Self::NotRegular => "not a regular file",
        })
    }
}

fn configuration_file_status(path: &Path) -> Result<ConfigurationFileStatus, ConfigurationError> {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(ConfigurationFileStatus::Present),
        Ok(_) => Ok(ConfigurationFileStatus::NotRegular),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(ConfigurationFileStatus::Missing)
        }
        Err(source) => Err(ConfigurationError::Read {
            path: path.to_path_buf(),
            source,
        }),
    }
}

impl<S> LayeredConfigLoader<S> {
    #[must_use]
    pub const fn new(sources: S, schema: ConfigurationSchema) -> Self {
        Self { sources, schema }
    }
}

impl<S> LayeredConfigLoader<S>
where
    S: ConfigurationSources,
{
    /// Resolves configuration file locations without reading their contents.
    pub fn locations(&self) -> Result<ConfigurationLocations, ConfigurationError> {
        let cwd = self
            .sources
            .current_directory()
            .map_err(ConfigurationError::CurrentDirectory)?;
        let system_directory = self.sources.system_directory()?;
        Ok(ConfigurationLocations {
            system_file: system_directory.join(self.schema.application.file_name()),
            working_file: cwd.join(self.schema.application.file_name()),
            application: self.schema.application,
        })
    }
}

impl LayeredConfigLoader<SystemConfigurationSources> {
    #[must_use]
    pub const fn system(schema: ConfigurationSchema) -> Self {
        Self::new(SystemConfigurationSources, schema)
    }
}

impl<T, S> ConfigLoader<T> for LayeredConfigLoader<S>
where
    T: DeserializeOwned,
    S: ConfigurationSources,
{
    fn load(&self) -> Result<LoadedConfiguration<T>, ConfigurationError> {
        let cwd = self
            .sources
            .current_directory()
            .map_err(ConfigurationError::CurrentDirectory)?;
        let system_directory = self.sources.system_directory()?;
        let system_path = system_directory.join(self.schema.application.file_name());
        let cwd_path = cwd.join(self.schema.application.file_name());

        let system = read_layer(&system_path)?;
        let working = read_layer(&cwd_path)?;
        let environment = environment_layers(
            self.schema.application,
            self.schema.list_keys,
            self.schema.parsed_scalar_keys,
            self.sources.environment(),
        )?;

        let mut origins = HashMap::with_capacity(self.schema.path_keys.len());
        record_file_origins(
            &mut origins,
            self.schema.path_keys,
            system.as_ref(),
            &system_directory,
            ConfigurationLayer::SystemFile,
        );
        record_file_origins(
            &mut origins,
            self.schema.path_keys,
            working.as_ref(),
            &cwd,
            ConfigurationLayer::WorkingFile,
        );
        record_environment_origins(&mut origins, self.schema.path_keys, &environment.keys, &cwd);

        let mut builder = Config::builder();
        if let Some(layer) = system {
            builder = builder.add_source(layer.config);
        }
        if let Some(layer) = working {
            builder = builder.add_source(layer.config);
        }
        builder = builder
            .add_source(environment.scalar)
            .add_source(environment.parsed_scalar)
            .add_source(environment.lists);
        let value = builder
            .build()
            .and_then(Config::try_deserialize)
            .map_err(|error| ConfigurationError::Schema(Box::new(error)))?;
        Ok(LoadedConfiguration { value, origins })
    }
}

/// A deserialized configuration plus the base directory of every path field.
#[derive(Debug)]
pub struct LoadedConfiguration<T> {
    value: T,
    origins: HashMap<ConfigurationKey, ConfigurationOrigin>,
}

#[derive(Debug)]
struct ConfigurationOrigin {
    base: PathBuf,
    layer: ConfigurationLayer,
}

impl<T> LoadedConfiguration<T> {
    #[must_use]
    pub const fn value(&self) -> &T {
        &self.value
    }

    #[must_use]
    pub fn into_value(self) -> T {
        self.value
    }

    /// Returns the highest-precedence layer that supplied a path field.
    #[must_use]
    pub fn source_layer(&self, key: ConfigurationKey) -> Option<ConfigurationLayer> {
        self.origins.get(&key).map(|origin| origin.layer)
    }

    /// Compares the layers that supplied two path fields.
    #[must_use]
    pub fn compare_source_precedence(
        &self,
        left: ConfigurationKey,
        right: ConfigurationKey,
    ) -> Option<std::cmp::Ordering> {
        Some(self.source_layer(left)?.cmp(&self.source_layer(right)?))
    }

    /// Resolves a non-empty path relative to the source that supplied the field.
    pub fn resolve_path(
        &self,
        key: ConfigurationKey,
        path: &Path,
    ) -> Result<PathBuf, ConfigurationError> {
        if path.as_os_str().is_empty() {
            return Err(ConfigurationError::EmptyPath(key.as_str()));
        }
        if path.is_absolute() {
            return Ok(path.to_path_buf());
        }
        let base = self
            .origins
            .get(&key)
            .ok_or(ConfigurationError::MissingPathOrigin(key.as_str()))?;
        Ok(base.base.join(path))
    }
}

/// Failures while deriving a platform's machine-wide configuration directory.
#[derive(Debug, Error)]
pub enum ConfigurationLocationError {
    #[error("PROGRAMDATA is unavailable")]
    MissingProgramData,
    #[error("PROGRAMDATA is not Unicode")]
    ProgramDataEncoding,
    #[error("PROGRAMDATA must be an absolute, non-empty path")]
    InvalidProgramData,
    #[error("the current platform is unsupported")]
    UnsupportedPlatform,
}

/// Strict configuration loading and schema failures.
#[derive(Debug, Error)]
pub enum ConfigurationError {
    #[error("failed to determine the current working directory: {0}")]
    CurrentDirectory(#[source] std::io::Error),
    #[error(transparent)]
    Location(#[from] ConfigurationLocationError),
    #[error("configuration path is not a regular file: {0}")]
    NotAFile(PathBuf),
    #[error("configuration file exceeds the 64 KiB limit: {0}")]
    TooLarge(PathBuf),
    #[error("failed to read configuration file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("configuration file is not UTF-8: {0}")]
    Encoding(PathBuf),
    #[error("configuration file is invalid {path}: {source}")]
    FileSchema {
        path: PathBuf,
        #[source]
        source: Box<config::ConfigError>,
    },
    #[error("configuration environment variable is not Unicode: {0}")]
    EnvironmentEncoding(ConfigurationEnvironmentVariable),
    #[error("multiple environment variables configure the same field: {0}")]
    DuplicateEnvironmentKey(ConfigurationEnvironmentKey),
    #[error("configuration schema is invalid: {0}")]
    Schema(#[source] Box<config::ConfigError>),
    #[error("configuration path field is empty: {0}")]
    EmptyPath(&'static str),
    #[error("configuration path field has no source: {0}")]
    MissingPathOrigin(&'static str),
}

#[derive(Debug)]
struct FileLayer {
    config: Config,
}

#[derive(Debug)]
struct EnvironmentLayers {
    scalar: Config,
    parsed_scalar: Config,
    lists: Config,
    keys: HashSet<String>,
}

fn read_layer(path: &Path) -> Result<Option<FileLayer>, ConfigurationError> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(ConfigurationError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if !metadata.is_file() {
        return Err(ConfigurationError::NotAFile(path.to_path_buf()));
    }
    if metadata.len() > MAX_CONFIG_BYTES {
        return Err(ConfigurationError::TooLarge(path.to_path_buf()));
    }
    let file = File::open(path).map_err(|source| ConfigurationError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    read_layer_document(path, file, metadata.len() as usize)
}

fn read_layer_document(
    path: &Path,
    reader: impl Read,
    initial_capacity: usize,
) -> Result<Option<FileLayer>, ConfigurationError> {
    let mut bytes = Vec::with_capacity(initial_capacity);
    reader
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| ConfigurationError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(ConfigurationError::TooLarge(path.to_path_buf()));
    }
    let text =
        String::from_utf8(bytes).map_err(|_| ConfigurationError::Encoding(path.to_path_buf()))?;
    let config = Config::builder()
        .add_source(ConfigFile::from_str(&text, FileFormat::Toml))
        .build()
        .map_err(|source| ConfigurationError::FileSchema {
            path: path.to_path_buf(),
            source: Box::new(source),
        })?;
    Ok(Some(FileLayer { config }))
}

fn environment_layers(
    application: Application,
    list_keys: &[ConfigurationKey],
    parsed_scalar_keys: &[ConfigurationKey],
    variables: Vec<(OsString, OsString)>,
) -> Result<EnvironmentLayers, ConfigurationError> {
    let prefix = application.environment_prefix();
    let pattern = format!("{prefix}_").to_lowercase();
    let excluded = (application == Application::Yon).then_some("yon_relay_");
    let list_keys: HashSet<_> = list_keys.iter().map(|key| key.as_str()).collect();
    let parsed_scalar_keys: HashSet<_> =
        parsed_scalar_keys.iter().map(|key| key.as_str()).collect();
    let mut scalar = config::Map::new();
    let mut parsed_scalar = config::Map::new();
    let mut lists = config::Map::new();
    let mut normalized_keys = HashSet::new();

    for (key, value) in variables {
        let Ok(key) = key.into_string() else {
            continue;
        };
        let lower = key.to_lowercase();
        if !lower.starts_with(&pattern)
            || excluded.is_some_and(|excluded| lower.starts_with(excluded))
        {
            continue;
        }
        let value = value.into_string().map_err(|_| {
            ConfigurationError::EnvironmentEncoding(ConfigurationEnvironmentVariable(key.clone()))
        })?;
        let normalized = lower[pattern.len()..].replace("__", ".");
        if !normalized_keys.insert(normalized.clone()) {
            return Err(ConfigurationError::DuplicateEnvironmentKey(
                ConfigurationEnvironmentKey(normalized),
            ));
        }
        if list_keys.contains(normalized.as_str()) {
            lists.insert(key, value);
        } else if parsed_scalar_keys.contains(normalized.as_str()) {
            parsed_scalar.insert(key, value);
        } else {
            scalar.insert(key, value);
        }
    }

    let scalar = environment_config(prefix, scalar, false, false)?;
    let parsed_scalar = environment_config(prefix, parsed_scalar, true, false)?;
    let lists = environment_config(prefix, lists, true, true)?;
    Ok(EnvironmentLayers {
        scalar,
        parsed_scalar,
        lists,
        keys: normalized_keys,
    })
}

fn environment_config(
    prefix: &str,
    source: config::Map<String, String>,
    parse_scalars: bool,
    lists: bool,
) -> Result<Config, ConfigurationError> {
    let mut environment = Environment::with_prefix(prefix)
        .prefix_separator("_")
        .separator("__")
        .ignore_empty(false)
        .try_parsing(parse_scalars)
        .source(Some(source));
    if lists {
        environment = environment.list_separator(",");
    }
    Config::builder()
        .add_source(environment)
        .build()
        .map_err(|error| ConfigurationError::Schema(Box::new(error)))
}

fn record_file_origins(
    origins: &mut HashMap<ConfigurationKey, ConfigurationOrigin>,
    path_keys: &[ConfigurationKey],
    layer: Option<&FileLayer>,
    base: &Path,
    source_layer: ConfigurationLayer,
) {
    let Some(layer) = layer else {
        return;
    };
    for key in path_keys {
        if layer.config.get::<config::Value>(key.as_str()).is_ok() {
            origins.insert(
                *key,
                ConfigurationOrigin {
                    base: base.to_path_buf(),
                    layer: source_layer,
                },
            );
        }
    }
}

fn record_environment_origins(
    origins: &mut HashMap<ConfigurationKey, ConfigurationOrigin>,
    path_keys: &[ConfigurationKey],
    environment_keys: &HashSet<String>,
    base: &Path,
) {
    for key in path_keys {
        if environment_keys.contains(key.as_str()) {
            origins.insert(
                *key,
                ConfigurationOrigin {
                    base: base.to_path_buf(),
                    layer: ConfigurationLayer::Environment,
                },
            );
        }
    }
}

#[cfg(target_os = "linux")]
fn system_directory(
    _program_data: Option<OsString>,
) -> Result<PathBuf, ConfigurationLocationError> {
    Ok(PathBuf::from("/etc/yonder"))
}

#[cfg(target_os = "macos")]
fn system_directory(
    _program_data: Option<OsString>,
) -> Result<PathBuf, ConfigurationLocationError> {
    Ok(PathBuf::from("/Library/Application Support/Yonder"))
}

#[cfg(windows)]
fn system_directory(program_data: Option<OsString>) -> Result<PathBuf, ConfigurationLocationError> {
    let program_data = program_data.ok_or(ConfigurationLocationError::MissingProgramData)?;
    let program_data = program_data
        .into_string()
        .map_err(|_| ConfigurationLocationError::ProgramDataEncoding)?;
    let path = PathBuf::from(program_data);
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return Err(ConfigurationLocationError::InvalidProgramData);
    }
    Ok(path.join("Yonder"))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn system_directory(
    _program_data: Option<OsString>,
) -> Result<PathBuf, ConfigurationLocationError> {
    Err(ConfigurationLocationError::UnsupportedPlatform)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        Application, ConfigLoader, ConfigurationError, ConfigurationKey, ConfigurationLayer,
        ConfigurationLocationError, ConfigurationSchema, ConfigurationSources, LayeredConfigLoader,
        read_layer, read_layer_document,
    };
    use serde::Deserialize;
    use std::ffi::OsString;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt as _;
    #[cfg(windows)]
    use std::os::windows::ffi::OsStringExt as _;
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;

    const RELAYS: ConfigurationKey = ConfigurationKey::new("relays");
    const CA: ConfigurationKey = ConfigurationKey::new("wss_ca_der");
    const COUNT: ConfigurationKey = ConfigurationKey::new("count");
    const SCHEMA: ConfigurationSchema =
        ConfigurationSchema::new(Application::Yon, &[RELAYS], &[COUNT], &[CA]);

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct Settings {
        relays: Vec<String>,
        wss_ca_der: Option<PathBuf>,
        #[serde(default)]
        count: u32,
    }

    #[derive(Debug)]
    struct Sources {
        cwd: PathBuf,
        system: PathBuf,
        environment: Vec<(OsString, OsString)>,
    }

    impl ConfigurationSources for Sources {
        fn current_directory(&self) -> Result<PathBuf, std::io::Error> {
            Ok(self.cwd.clone())
        }

        fn system_directory(&self) -> Result<PathBuf, ConfigurationLocationError> {
            Ok(self.system.clone())
        }

        fn environment(&self) -> Vec<(OsString, OsString)> {
            self.environment.clone()
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum SourceFailure {
        CurrentDirectory,
        SystemDirectory,
    }

    impl ConfigurationSources for SourceFailure {
        fn current_directory(&self) -> Result<PathBuf, std::io::Error> {
            match self {
                Self::CurrentDirectory => Err(std::io::Error::other("current directory")),
                Self::SystemDirectory => Ok(PathBuf::from(".")),
            }
        }

        fn system_directory(&self) -> Result<PathBuf, ConfigurationLocationError> {
            Err(ConfigurationLocationError::UnsupportedPlatform)
        }

        fn environment(&self) -> Vec<(OsString, OsString)> {
            Vec::new()
        }
    }

    #[test]
    fn every_layer_merges_by_field_and_lists_replace() {
        let root = tempdir().unwrap();
        let system = root.path().join("system");
        let cwd = root.path().join("cwd");
        fs::create_dir_all(&system).unwrap();
        fs::create_dir_all(&cwd).unwrap();
        fs::write(
            system.join("yon.toml"),
            "relays=['system']\nwss_ca_der='system.der'\ncount=1\n",
        )
        .unwrap();
        fs::write(cwd.join("yon.toml"), "relays=['cwd']\ncount=2\n").unwrap();
        let loader = LayeredConfigLoader::new(
            Sources {
                cwd: cwd.clone(),
                system: system.clone(),
                environment: vec![
                    ("YON_RELAYS".into(), "env-a,env-b".into()),
                    ("YON_COUNT".into(), "3".into()),
                ],
            },
            SCHEMA,
        );
        let loaded: super::LoadedConfiguration<Settings> = loader.load().unwrap();
        assert_eq!(loaded.value().relays, ["env-a", "env-b"]);
        assert_eq!(loaded.value().count, 3);
        assert_eq!(
            loaded.source_layer(CA),
            Some(ConfigurationLayer::SystemFile)
        );
        assert_eq!(
            loaded
                .resolve_path(CA, loaded.value().wss_ca_der.as_deref().unwrap())
                .unwrap(),
            system.join("system.der")
        );
    }

    #[test]
    fn source_locations_are_reportable_without_loading_configuration() {
        let root = tempdir().unwrap();
        let cwd = root.path().join("cwd");
        let system = root.path().join("system");
        fs::create_dir_all(&cwd).unwrap();
        fs::create_dir_all(&system).unwrap();
        fs::write(system.join("yon.toml"), "secret = true").unwrap();
        fs::create_dir(cwd.join("yon.toml")).unwrap();
        let loader = LayeredConfigLoader::new(
            Sources {
                cwd: cwd.clone(),
                system: system.clone(),
                environment: vec![("YON_RELAYS".into(), "secret-address".into())],
            },
            SCHEMA,
        );
        let locations = loader.locations().unwrap();
        assert_eq!(locations.system_file(), system.join("yon.toml"));
        assert_eq!(locations.working_file(), cwd.join("yon.toml"));
        assert_eq!(Application::Yon.configuration_environment_prefix(), "YON");
        assert_eq!(
            Application::Relay.configuration_environment_prefix(),
            "YON_RELAY"
        );

        let mut report = Vec::new();
        locations.inspect().unwrap().write_to(&mut report).unwrap();
        let report = String::from_utf8(report).unwrap();
        assert!(report.contains("(present)"));
        assert!(report.contains("(not a regular file)"));
        assert!(report.contains("Environment variables: YON_* (values hidden)"));
        assert!(!report.contains("secret-address"));

        fs::remove_file(system.join("yon.toml")).unwrap();
        fs::remove_dir(cwd.join("yon.toml")).unwrap();
        let mut missing_report = Vec::new();
        locations
            .inspect()
            .unwrap()
            .write_to(&mut missing_report)
            .unwrap();
        assert_eq!(
            String::from_utf8(missing_report)
                .unwrap()
                .matches("(missing)")
                .count(),
            2
        );
    }

    #[test]
    fn environment_paths_resolve_from_cwd_and_relay_namespace_is_excluded() {
        let root = tempdir().unwrap();
        let system = root.path().join("system");
        let cwd = root.path().join("cwd");
        fs::create_dir_all(&system).unwrap();
        fs::create_dir_all(&cwd).unwrap();
        let loader = LayeredConfigLoader::new(
            Sources {
                cwd: cwd.clone(),
                system,
                environment: vec![
                    ("YON_RELAYS".into(), "relay".into()),
                    ("YON_WSS_CA_DER".into(), "123".into()),
                    ("YON_RELAY_IDENTITY".into(), "ignored".into()),
                ],
            },
            SCHEMA,
        );
        let loaded: super::LoadedConfiguration<Settings> = loader.load().unwrap();
        assert_eq!(
            loaded
                .resolve_path(CA, loaded.value().wss_ca_der.as_deref().unwrap())
                .unwrap(),
            cwd.join("123")
        );
        assert_eq!(
            loaded.source_layer(CA),
            Some(ConfigurationLayer::Environment)
        );
    }

    #[test]
    fn missing_optional_files_are_allowed_but_schema_remains_required() {
        let root = tempdir().unwrap();
        let loader = LayeredConfigLoader::new(
            Sources {
                cwd: root.path().join("cwd"),
                system: root.path().join("system"),
                environment: Vec::new(),
            },
            SCHEMA,
        );
        let result: Result<super::LoadedConfiguration<Settings>, _> = loader.load();
        assert!(matches!(result, Err(ConfigurationError::Schema(_))));
    }

    #[test]
    fn source_location_failures_remain_structured() {
        let current: Result<super::LoadedConfiguration<Settings>, _> =
            LayeredConfigLoader::new(SourceFailure::CurrentDirectory, SCHEMA).load();
        assert!(matches!(
            current,
            Err(ConfigurationError::CurrentDirectory(_))
        ));

        let system: Result<super::LoadedConfiguration<Settings>, _> =
            LayeredConfigLoader::new(SourceFailure::SystemDirectory, SCHEMA).load();
        assert!(matches!(
            system,
            Err(ConfigurationError::Location(
                ConfigurationLocationError::UnsupportedPlatform
            ))
        ));

        assert!(matches!(
            LayeredConfigLoader::new(SourceFailure::CurrentDirectory, SCHEMA).locations(),
            Err(ConfigurationError::CurrentDirectory(_))
        ));
        assert!(matches!(
            LayeredConfigLoader::new(SourceFailure::SystemDirectory, SCHEMA).locations(),
            Err(ConfigurationError::Location(
                ConfigurationLocationError::UnsupportedPlatform
            ))
        ));
    }

    #[test]
    fn malformed_unknown_oversized_non_utf8_and_directory_files_fail() {
        for (contents, expected) in [
            (b"relays=[".as_slice(), "invalid"),
            (b"relays=['r']\nunknown=true".as_slice(), "unknown"),
        ] {
            let root = tempdir().unwrap();
            let cwd = root.path().join("cwd");
            fs::create_dir_all(&cwd).unwrap();
            fs::write(cwd.join("yon.toml"), contents).unwrap();
            let result: Result<super::LoadedConfiguration<Settings>, _> = LayeredConfigLoader::new(
                Sources {
                    cwd,
                    system: root.path().join("system"),
                    environment: Vec::new(),
                },
                SCHEMA,
            )
            .load();
            match expected {
                "invalid" => assert!(matches!(result, Err(ConfigurationError::FileSchema { .. }))),
                "unknown" => assert!(matches!(result, Err(ConfigurationError::Schema(_)))),
                _ => unreachable!(),
            }
        }

        let root = tempdir().unwrap();
        let cwd = root.path().join("cwd");
        fs::create_dir_all(&cwd).unwrap();
        fs::write(cwd.join("yon.toml"), vec![b'x'; 64 * 1024 + 1]).unwrap();
        let result: Result<super::LoadedConfiguration<Settings>, _> = LayeredConfigLoader::new(
            Sources {
                cwd,
                system: root.path().join("system"),
                environment: Vec::new(),
            },
            SCHEMA,
        )
        .load();
        assert!(matches!(result, Err(ConfigurationError::TooLarge(_))));

        let root = tempdir().unwrap();
        let cwd = root.path().join("cwd");
        fs::create_dir_all(&cwd).unwrap();
        fs::write(cwd.join("yon.toml"), [0xff]).unwrap();
        let result: Result<super::LoadedConfiguration<Settings>, _> = LayeredConfigLoader::new(
            Sources {
                cwd,
                system: root.path().join("system"),
                environment: Vec::new(),
            },
            SCHEMA,
        )
        .load();
        assert!(matches!(result, Err(ConfigurationError::Encoding(_))));

        let root = tempdir().unwrap();
        let cwd = root.path().join("cwd");
        fs::create_dir_all(cwd.join("yon.toml")).unwrap();
        let result: Result<super::LoadedConfiguration<Settings>, _> = LayeredConfigLoader::new(
            Sources {
                cwd,
                system: root.path().join("system"),
                environment: Vec::new(),
            },
            SCHEMA,
        )
        .load();
        assert!(matches!(result, Err(ConfigurationError::NotAFile(_))));
    }

    #[test]
    fn empty_paths_and_non_unicode_relevant_environment_values_fail() {
        let root = tempdir().unwrap();
        let loader = LayeredConfigLoader::new(
            Sources {
                cwd: root.path().join("cwd"),
                system: root.path().join("system"),
                environment: vec![
                    ("YON_RELAYS".into(), "relay".into()),
                    ("YON_WSS_CA_DER".into(), "".into()),
                ],
            },
            SCHEMA,
        );
        let loaded: super::LoadedConfiguration<Settings> = loader.load().unwrap();
        assert!(matches!(
            loaded.resolve_path(CA, loaded.value().wss_ca_der.as_deref().unwrap()),
            Err(ConfigurationError::EmptyPath("wss_ca_der"))
        ));
    }

    #[test]
    fn absolute_paths_and_consuming_loaded_values_are_supported() {
        let root = tempdir().unwrap();
        let cwd = root.path().join("cwd");
        fs::create_dir_all(&cwd).unwrap();
        let absolute = root.path().join("ca.der");
        fs::write(
            cwd.join("yon.toml"),
            format!(
                "relays=['relay']\nwss_ca_der={}\n",
                toml_literal(&absolute.to_string_lossy())
            ),
        )
        .unwrap();
        let loaded: super::LoadedConfiguration<Settings> = LayeredConfigLoader::new(
            Sources {
                cwd,
                system: root.path().join("system"),
                environment: Vec::new(),
            },
            SCHEMA,
        )
        .load()
        .unwrap();
        assert_eq!(
            loaded
                .resolve_path(CA, loaded.value().wss_ca_der.as_deref().unwrap())
                .unwrap(),
            absolute
        );
        let untracked = ConfigurationKey::new("untracked_path");
        assert!(matches!(
            loaded.resolve_path(untracked, Path::new("relative.der")),
            Err(ConfigurationError::MissingPathOrigin("untracked_path"))
        ));
        assert_eq!(loaded.into_value().relays, ["relay"]);
    }

    #[test]
    fn public_schema_constructors_preserve_runtime_inputs() {
        static KEYS: [ConfigurationKey; 1] = [ConfigurationKey::new("runtime.path")];
        let key = ConfigurationKey::new(std::hint::black_box("runtime.path"));
        let list_keys = std::hint::black_box(&KEYS[..]);
        let path_keys = std::hint::black_box(&KEYS[..]);
        let schema = ConfigurationSchema::new(Application::Relay, list_keys, list_keys, path_keys);

        assert_eq!(key.as_str(), "runtime.path");
        assert_eq!(schema.application, Application::Relay);
        assert_eq!(schema.list_keys, [key]);
        assert_eq!(schema.parsed_scalar_keys, [key]);
        assert_eq!(schema.path_keys, [key]);
    }

    #[test]
    fn metadata_failures_remain_structured_read_errors() {
        let status_error = super::configuration_file_status(Path::new("\0")).unwrap_err();
        assert!(matches!(
            status_error,
            ConfigurationError::Read { source, .. }
                if source.kind() == std::io::ErrorKind::InvalidInput
        ));

        let error = read_layer(Path::new("\0")).unwrap_err();
        assert!(matches!(
            error,
            ConfigurationError::Read { source, .. }
                if source.kind() == std::io::ErrorKind::InvalidInput
        ));
    }

    #[test]
    fn configuration_reads_reject_growth_and_preserve_reader_failures() {
        let path = Path::new("yon.toml");
        assert!(matches!(
            read_layer_document(path, std::io::Cursor::new(vec![b'x'; 64 * 1024 + 1]), 0),
            Err(ConfigurationError::TooLarge(error_path)) if error_path == path
        ));
        assert!(matches!(
            read_layer_document(path, FailingReader, 0),
            Err(ConfigurationError::Read { source, .. })
                if source.kind() == std::io::ErrorKind::Other
        ));
    }

    #[test]
    fn non_unicode_irrelevant_environment_keys_are_ignored() {
        let root = tempdir().unwrap();
        let loaded: super::LoadedConfiguration<Settings> = LayeredConfigLoader::new(
            Sources {
                cwd: root.path().join("cwd"),
                system: root.path().join("system"),
                environment: vec![
                    (non_unicode_os_string(), non_unicode_os_string()),
                    ("YON_RELAYS".into(), "relay".into()),
                ],
            },
            SCHEMA,
        )
        .load()
        .unwrap();

        assert_eq!(loaded.value().relays, ["relay"]);

        let relevant: Result<super::LoadedConfiguration<Settings>, _> = LayeredConfigLoader::new(
            Sources {
                cwd: root.path().join("cwd"),
                system: root.path().join("system"),
                environment: vec![("YON_RELAYS".into(), non_unicode_os_string())],
            },
            SCHEMA,
        )
        .load();
        assert!(matches!(
            relevant,
            Err(ConfigurationError::EnvironmentEncoding(key)) if key.to_string() == "YON_RELAYS"
        ));

        let duplicate: Result<super::LoadedConfiguration<Settings>, _> = LayeredConfigLoader::new(
            Sources {
                cwd: root.path().join("cwd"),
                system: root.path().join("system"),
                environment: vec![
                    ("YON_RELAYS".into(), "first".into()),
                    ("yon_relays".into(), "second".into()),
                ],
            },
            SCHEMA,
        )
        .load();
        assert!(matches!(
            duplicate,
            Err(ConfigurationError::DuplicateEnvironmentKey(key)) if key.to_string() == "relays"
        ));
    }

    #[cfg(windows)]
    #[test]
    fn invalid_program_data_is_rejected_without_lossy_conversion() {
        assert!(matches!(
            super::system_directory(None),
            Err(ConfigurationLocationError::MissingProgramData)
        ));
        assert!(matches!(
            super::system_directory(Some(non_unicode_os_string())),
            Err(ConfigurationLocationError::ProgramDataEncoding)
        ));
        assert!(matches!(
            super::system_directory(Some("relative".into())),
            Err(ConfigurationLocationError::InvalidProgramData)
        ));
    }

    #[cfg(unix)]
    fn non_unicode_os_string() -> OsString {
        OsString::from_vec(vec![0xff])
    }

    #[cfg(windows)]
    fn non_unicode_os_string() -> OsString {
        OsString::from_wide(&[0xd800])
    }

    fn toml_literal(value: &str) -> String {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    }

    struct FailingReader;

    impl std::io::Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("read failed"))
        }
    }
}
