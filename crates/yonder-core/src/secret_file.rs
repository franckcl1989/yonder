use std::fs::File;
use std::path::Path;
use thiserror::Error;

/// Platform secret-file protection behind a replaceable cold-path boundary.
pub trait SecretFilePolicy {
    fn protect_new(&self, path: &Path, file: &File) -> Result<(), SecretFileError>;
    fn validate_existing(&self, path: &Path, file: &File) -> Result<(), SecretFileError>;
}

/// Private-directory protection behind a replaceable cold-path boundary.
pub trait PrivateDirectoryPolicy {
    fn protect(&self, path: &Path) -> Result<(), SecretFileError>;
    fn validate(&self, path: &Path) -> Result<(), SecretFileError>;
}

/// Native secret-file protection shared by relay and endpoint secrets.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemSecretFilePolicy;

/// Native private-directory protection used by enterprise audit storage.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemPrivateDirectoryPolicy;

/// Secret-file permission failures.
#[derive(Debug, Error)]
pub enum SecretFileError {
    #[error("the secret file or its parent directory permits untrusted access")]
    Insecure,
    #[error("the platform secret-file permission check failed")]
    Platform(#[source] std::io::Error),
}

#[cfg(unix)]
impl SecretFilePolicy for SystemSecretFilePolicy {
    fn protect_new(&self, path: &Path, file: &File) -> Result<(), SecretFileError> {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(SecretFileError::Platform)?;
        let metadata = file.metadata().map_err(SecretFileError::Platform)?;
        validate_unix_parent(path, metadata.uid())
    }

    fn validate_existing(&self, path: &Path, file: &File) -> Result<(), SecretFileError> {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let path_metadata = std::fs::symlink_metadata(path).map_err(SecretFileError::Platform)?;
        let metadata = file.metadata().map_err(SecretFileError::Platform)?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.is_file()
            || !metadata.is_file()
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(SecretFileError::Insecure);
        }
        validate_unix_parent(path, metadata.uid())
    }
}

#[cfg(unix)]
fn validate_unix_parent(path: &Path, file_owner: u32) -> Result<(), SecretFileError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = parent.metadata().map_err(SecretFileError::Platform)?;
    let parent_owner = metadata.uid();
    if !metadata.is_dir()
        || metadata.permissions().mode() & 0o022 != 0
        || (parent_owner != 0 && parent_owner != file_owner)
    {
        Err(SecretFileError::Insecure)
    } else {
        Ok(())
    }
}

#[cfg(unix)]
impl PrivateDirectoryPolicy for SystemPrivateDirectoryPolicy {
    fn protect(&self, path: &Path) -> Result<(), SecretFileError> {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(SecretFileError::Insecure);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = std::fs::DirBuilder::new();
                builder.recursive(true).mode(0o700);
                builder.create(path).map_err(SecretFileError::Platform)?;
            }
            Err(error) => return Err(SecretFileError::Platform(error)),
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(SecretFileError::Platform)?;
        self.validate(path)
    }

    fn validate(&self, path: &Path) -> Result<(), SecretFileError> {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let metadata = std::fs::symlink_metadata(path).map_err(SecretFileError::Platform)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.permissions().mode() & 0o777 != 0o700
        {
            return Err(SecretFileError::Insecure);
        }
        validate_unix_parent(path, metadata.uid())
    }
}

#[cfg(windows)]
impl SecretFilePolicy for SystemSecretFilePolicy {
    fn protect_new(&self, path: &Path, _file: &File) -> Result<(), SecretFileError> {
        run_windows_policy(path, WindowsPolicyOperation::Protect)
    }

    fn validate_existing(&self, path: &Path, _file: &File) -> Result<(), SecretFileError> {
        run_windows_policy(path, WindowsPolicyOperation::Validate)
    }
}

#[cfg(windows)]
impl PrivateDirectoryPolicy for SystemPrivateDirectoryPolicy {
    fn protect(&self, path: &Path) -> Result<(), SecretFileError> {
        run_windows_directory_policy(path, WindowsPolicyOperation::Protect)
    }

    fn validate(&self, path: &Path) -> Result<(), SecretFileError> {
        run_windows_directory_policy(path, WindowsPolicyOperation::Validate)
    }
}

#[cfg(not(any(unix, windows)))]
impl SecretFilePolicy for SystemSecretFilePolicy {
    fn protect_new(&self, _path: &Path, _file: &File) -> Result<(), SecretFileError> {
        Err(SecretFileError::Platform(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "secret-file permissions are unsupported on this platform",
        )))
    }

    fn validate_existing(&self, _path: &Path, _file: &File) -> Result<(), SecretFileError> {
        Err(SecretFileError::Platform(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "secret-file permissions are unsupported on this platform",
        )))
    }
}

#[cfg(not(any(unix, windows)))]
impl PrivateDirectoryPolicy for SystemPrivateDirectoryPolicy {
    fn protect(&self, _path: &Path) -> Result<(), SecretFileError> {
        Err(unsupported_permissions())
    }

    fn validate(&self, _path: &Path) -> Result<(), SecretFileError> {
        Err(unsupported_permissions())
    }
}

#[cfg(not(any(unix, windows)))]
fn unsupported_permissions() -> SecretFileError {
    SecretFileError::Platform(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "private permissions are unsupported on this platform",
    ))
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy)]
enum WindowsPolicyOperation {
    Protect,
    Validate,
}

#[cfg(windows)]
impl WindowsPolicyOperation {
    const fn mode(self) -> &'static str {
        match self {
            Self::Protect => "protect",
            Self::Validate => "validate",
        }
    }
}

#[cfg(windows)]
fn run_windows_policy(
    path: &Path,
    operation: WindowsPolicyOperation,
) -> Result<(), SecretFileError> {
    use std::process::{Command, Stdio};

    let executable = windows_powershell_executable(std::env::var_os("SystemRoot"))?;
    let status = Command::new(executable)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            WINDOWS_POLICY_SCRIPT,
        ])
        .env("YONDER_SECRET_PATH", path)
        .env("YONDER_SECRET_MODE", operation.mode())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(SecretFileError::Platform)?;
    windows_policy_status(status.code())
}

#[cfg(windows)]
fn run_windows_directory_policy(
    path: &Path,
    operation: WindowsPolicyOperation,
) -> Result<(), SecretFileError> {
    use std::process::{Command, Stdio};

    let executable = windows_powershell_executable(std::env::var_os("SystemRoot"))?;
    let status = Command::new(executable)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            WINDOWS_DIRECTORY_POLICY_SCRIPT,
        ])
        .env("YONDER_SECRET_PATH", path)
        .env("YONDER_SECRET_MODE", operation.mode())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(SecretFileError::Platform)?;
    windows_policy_status(status.code())
}

#[cfg(windows)]
fn windows_powershell_executable(
    system_root: Option<std::ffi::OsString>,
) -> Result<std::path::PathBuf, SecretFileError> {
    let root = system_root.filter(|root| !root.is_empty()).ok_or_else(|| {
        SecretFileError::Platform(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "SystemRoot does not identify Windows PowerShell",
        ))
    })?;
    Ok(std::path::PathBuf::from(root)
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe"))
}

#[cfg(windows)]
fn windows_policy_status(code: Option<i32>) -> Result<(), SecretFileError> {
    match code {
        Some(0) => Ok(()),
        Some(10..=14) => Err(SecretFileError::Insecure),
        code => Err(SecretFileError::Platform(std::io::Error::other(
            match code {
                Some(code) => format!("Windows secret-file policy exited with status {code}"),
                None => "Windows secret-file policy was terminated".to_owned(),
            },
        ))),
    }
}

#[cfg(windows)]
const WINDOWS_POLICY_SCRIPT: &str = r#"
$ErrorActionPreference='Stop'
$path=$env:YONDER_SECRET_PATH
$mode=$env:YONDER_SECRET_MODE
$current=[Security.Principal.WindowsIdentity]::GetCurrent().User
$system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
$administrators=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$trusted=@{}
@($current,$system,$administrators)|ForEach-Object{$trusted[$_.Value]=$true}
$item=Get-Item -LiteralPath $path -Force
if($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){exit 10}
$parent=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($path))
$parentItem=Get-Item -LiteralPath $parent -Force
if(-not $parentItem.PSIsContainer -or (($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){exit 10}
$parentAcl=[IO.Directory]::GetAccessControl($parent)
$parentOwner=$parentAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value
if(-not $trusted.ContainsKey($parentOwner)){exit 10}
$danger=[Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
foreach($rule in $parentAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and -not $trusted.ContainsKey($rule.IdentityReference.Value) -and ($rule.FileSystemRights -band $danger)){exit 11}}
if($mode -eq 'validate'){
  $acl=[IO.File]::GetAccessControl($path)
  if(-not $acl.AreAccessRulesProtected){exit 12}
  $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  if(-not $trusted.ContainsKey($owner)){exit 13}
  foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and -not $trusted.ContainsKey($rule.IdentityReference.Value)){exit 14}}
  exit 0
}
if($mode -ne 'protect'){exit 15}
$acl=New-Object Security.AccessControl.FileSecurity
$acl.SetOwner($current)
$acl.SetAccessRuleProtection($true,$false)
$rights=[Security.AccessControl.FileSystemRights]::FullControl
$inherit=[Security.AccessControl.InheritanceFlags]::None
$propagate=[Security.AccessControl.PropagationFlags]::None
$allow=[Security.AccessControl.AccessControlType]::Allow
foreach($sid in @($current,$system,$administrators)){$rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,$rights,$inherit,$propagate,$allow);[void]$acl.AddAccessRule($rule)}
[IO.File]::SetAccessControl($path,$acl)
exit 0
"#;

#[cfg(windows)]
const WINDOWS_DIRECTORY_POLICY_SCRIPT: &str = r#"
$ErrorActionPreference='Stop'
$path=[IO.Path]::GetFullPath($env:YONDER_SECRET_PATH)
$mode=$env:YONDER_SECRET_MODE
$current=[Security.Principal.WindowsIdentity]::GetCurrent().User
$system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
$administrators=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$trusted=@{}
@($current,$system,$administrators)|ForEach-Object{$trusted[$_.Value]=$true}
if($mode -eq 'protect'){
  $acl=New-Object Security.AccessControl.DirectorySecurity
  $acl.SetOwner($current)
  $acl.SetAccessRuleProtection($true,$false)
  $rights=[Security.AccessControl.FileSystemRights]::FullControl
  $inherit=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
  $propagate=[Security.AccessControl.PropagationFlags]::None
  $allow=[Security.AccessControl.AccessControlType]::Allow
  foreach($sid in @($current,$system,$administrators)){$rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,$rights,$inherit,$propagate,$allow);[void]$acl.AddAccessRule($rule)}
  if([IO.File]::Exists($path)){exit 10}
  if([IO.Directory]::Exists($path)){
    $item=Get-Item -LiteralPath $path -Force
    if(-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){exit 10}
    [IO.Directory]::SetAccessControl($path,$acl)
  }
  else{
    $directory=New-Object IO.DirectoryInfo($path)
    $directory.Create($acl)
  }
}
elseif($mode -ne 'validate'){exit 15}
$item=Get-Item -LiteralPath $path -Force
if(-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){exit 10}
$acl=[IO.Directory]::GetAccessControl($path)
if(-not $acl.AreAccessRulesProtected){exit 12}
$owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
if(-not $trusted.ContainsKey($owner)){exit 13}
foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and -not $trusted.ContainsKey($rule.IdentityReference.Value)){exit 14}}
exit 0
"#;

/// Replaces a test directory ACL with the trusted-only policy so secret
/// files created inside it pass the Windows parent-directory check.
#[cfg(all(test, windows))]
pub(crate) fn secure_test_directory(path: &std::path::Path) {
    use std::process::{Command, Stdio};

    const SCRIPT: &str = r#"
$ErrorActionPreference='Stop'
$path=$env:YONDER_TEST_DIRECTORY
$current=[Security.Principal.WindowsIdentity]::GetCurrent().User
$system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
$administrators=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetOwner($current)
$acl.SetAccessRuleProtection($true,$false)
$rights=[Security.AccessControl.FileSystemRights]::FullControl
$inherit=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
$propagate=[Security.AccessControl.PropagationFlags]::None
$allow=[Security.AccessControl.AccessControlType]::Allow
foreach($sid in @($current,$system,$administrators)){$rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,$rights,$inherit,$propagate,$allow);[void]$acl.AddAccessRule($rule)}
[IO.Directory]::SetAccessControl($path,$acl)
exit 0
"#;
    let system_root = std::env::var_os("SystemRoot").unwrap();
    let status = Command::new(
        std::path::PathBuf::from(system_root)
            .join("System32/WindowsPowerShell/v1.0/powershell.exe"),
    )
    .args([
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        SCRIPT,
    ])
    .env("YONDER_TEST_DIRECTORY", path)
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .status()
    .unwrap();
    assert!(status.success());
}

#[cfg(all(test, not(windows)))]
pub(crate) fn secure_test_directory(_path: &std::path::Path) {}

// Miri's default isolation intentionally rejects the native filesystem and
// process operations this module exists to validate. Normal platform tests
// and coverage builds continue to execute the complete policy suite.
#[cfg(all(test, not(miri)))]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        PrivateDirectoryPolicy, SecretFileError, SecretFilePolicy, SystemPrivateDirectoryPolicy,
        SystemSecretFilePolicy, secure_test_directory,
    };
    #[cfg(windows)]
    use super::{windows_policy_status, windows_powershell_executable};
    use std::fs::File;
    use tempfile::tempdir;

    #[test]
    fn system_policy_protects_and_validates_a_secret_file() {
        let directory = tempdir().unwrap();
        secure_test_directory(directory.path());
        let path = directory.path().join("secret.key");
        let file = File::create(&path).unwrap();
        SystemSecretFilePolicy.protect_new(&path, &file).unwrap();
        SystemSecretFilePolicy
            .validate_existing(&path, &file)
            .unwrap();
    }

    #[test]
    fn system_policy_protects_and_validates_a_private_directory() {
        let root = tempdir().unwrap();
        secure_test_directory(root.path());
        let path = root.path().join("private");
        SystemPrivateDirectoryPolicy.protect(&path).unwrap();
        SystemPrivateDirectoryPolicy.validate(&path).unwrap();
        assert!(path.is_dir());
    }

    #[cfg(windows)]
    #[test]
    fn windows_policy_platform_boundaries_are_deterministic() {
        for root in [None, Some(std::ffi::OsString::new())] {
            assert!(matches!(
                windows_powershell_executable(root),
                Err(SecretFileError::Platform(error))
                    if error.kind() == std::io::ErrorKind::NotFound
            ));
        }
        assert!(
            windows_powershell_executable(Some(std::ffi::OsString::from("C:\\Windows")))
                .unwrap()
                .ends_with("System32/WindowsPowerShell/v1.0/powershell.exe")
        );

        assert!(windows_policy_status(Some(0)).is_ok());
        for code in 10..=14 {
            assert!(matches!(
                windows_policy_status(Some(code)),
                Err(SecretFileError::Insecure)
            ));
        }
        assert!(matches!(
            windows_policy_status(Some(15)),
            Err(SecretFileError::Platform(error)) if error.to_string().contains("status 15")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unix_policy_rejects_group_read_access() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempdir().unwrap();
        let path = directory.path().join("secret.key");
        let file = File::create(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            SystemSecretFilePolicy.validate_existing(&path, &file),
            Err(SecretFileError::Insecure)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unix_policy_rejects_writable_parent_and_non_regular_files() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempdir().unwrap();
        let path = directory.path().join("secret.key");
        let file = File::create(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o770)).unwrap();
        assert!(matches!(
            SystemSecretFilePolicy.validate_existing(&path, &file),
            Err(SecretFileError::Insecure)
        ));
        assert!(matches!(
            SystemSecretFilePolicy.protect_new(&path, &file),
            Err(SecretFileError::Insecure)
        ));

        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let directory_file = File::open(directory.path()).unwrap();
        assert!(matches!(
            SystemSecretFilePolicy.validate_existing(directory.path(), &directory_file),
            Err(SecretFileError::Insecure)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unix_private_directory_rejects_permissions_parent_and_symlink() {
        use std::fs;
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let root = tempdir().unwrap();
        let private = root.path().join("private");
        SystemPrivateDirectoryPolicy.protect(&private).unwrap();

        fs::set_permissions(&private, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(matches!(
            SystemPrivateDirectoryPolicy.validate(&private),
            Err(SecretFileError::Insecure)
        ));

        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o770)).unwrap();
        assert!(matches!(
            SystemPrivateDirectoryPolicy.validate(&private),
            Err(SecretFileError::Insecure)
        ));
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();

        let link = root.path().join("private-link");
        symlink(&private, &link).unwrap();
        assert!(matches!(
            SystemPrivateDirectoryPolicy.validate(&link),
            Err(SecretFileError::Insecure)
        ));

        let regular = root.path().join("regular-file");
        File::create(&regular).unwrap();
        assert!(matches!(
            SystemPrivateDirectoryPolicy.protect(&regular),
            Err(SecretFileError::Insecure)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_policy_rejects_an_unprotected_dacl() {
        use std::process::{Command, Stdio};

        let directory = tempdir().unwrap();
        secure_test_directory(directory.path());
        let path = directory.path().join("secret.key");
        let file = File::create(&path).unwrap();
        SystemSecretFilePolicy.protect_new(&path, &file).unwrap();
        let system_root = std::env::var_os("SystemRoot").unwrap();
        let status =
            Command::new(std::path::PathBuf::from(system_root).join("System32/icacls.exe"))
                .arg(&path)
                .arg("/inheritance:e")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
        assert!(status.success());
        assert!(matches!(
            SystemSecretFilePolicy.validate_existing(&path, &file),
            Err(SecretFileError::Insecure)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_private_directory_rejects_unprotected_acl_and_regular_file() {
        use std::process::{Command, Stdio};

        let root = tempdir().unwrap();
        secure_test_directory(root.path());
        let private = root.path().join("private");
        SystemPrivateDirectoryPolicy.protect(&private).unwrap();
        let system_root = std::env::var_os("SystemRoot").unwrap();
        let status =
            Command::new(std::path::PathBuf::from(system_root).join("System32/icacls.exe"))
                .arg(&private)
                .arg("/inheritance:e")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
        assert!(status.success());
        assert!(matches!(
            SystemPrivateDirectoryPolicy.validate(&private),
            Err(SecretFileError::Insecure)
        ));

        let regular = root.path().join("regular-file");
        File::create(&regular).unwrap();
        assert!(matches!(
            SystemPrivateDirectoryPolicy.protect(&regular),
            Err(SecretFileError::Insecure)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_policy_rejects_untrusted_file_and_parent_access() {
        use std::process::{Command, Stdio};

        let directory = tempdir().unwrap();
        secure_test_directory(directory.path());
        let path = directory.path().join("secret.key");
        let file = File::create(&path).unwrap();
        SystemSecretFilePolicy.protect_new(&path, &file).unwrap();
        assert!(run_icacls(&path, &["/grant", "*S-1-5-32-545:(R)"]));
        assert!(matches!(
            SystemSecretFilePolicy.validate_existing(&path, &file),
            Err(SecretFileError::Insecure)
        ));

        assert!(run_icacls(
            directory.path(),
            &["/grant", "*S-1-5-32-545:(OI)(CI)(M)"]
        ));
        assert!(matches!(
            SystemSecretFilePolicy.protect_new(&path, &file),
            Err(SecretFileError::Insecure)
        ));

        fn run_icacls(path: &std::path::Path, arguments: &[&str]) -> bool {
            let system_root = std::env::var_os("SystemRoot").unwrap();
            Command::new(std::path::PathBuf::from(system_root).join("System32/icacls.exe"))
                .arg(path)
                .args(arguments)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
        }
    }
}
