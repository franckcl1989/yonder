pub use yonder_core::{SecretFileError, SecretFilePolicy, SystemSecretFilePolicy};

#[cfg(all(test, unix))]
pub(crate) fn secure_test_directory(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .expect("the test directory must be private");
}

#[cfg(all(test, windows))]
pub(crate) fn secure_test_directory(path: &std::path::Path) {
    use yonder_core::{PrivateDirectoryPolicy as _, SystemPrivateDirectoryPolicy};

    SystemPrivateDirectoryPolicy
        .protect(path)
        .expect("the test directory must have a private platform policy");
}
