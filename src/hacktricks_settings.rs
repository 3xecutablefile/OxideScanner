//! Optional Brave credentials, kept separate from serializable scan configuration.

use crate::error::{OxideScannerError, Result};
use inquire::{Confirm, InquireError, Password, PasswordDisplayMode};
use serde::Deserialize;
use std::ffi::OsString;
use std::fmt;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};

const MAX_KEY_BYTES: usize = 512;
const MAX_FILE_BYTES: usize = 16 * 1024;

/// A validated credential. Debug output never contains its value.
pub struct ApiKey(String);

impl ApiKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApiKey([REDACTED])")
    }
}

#[derive(Debug)]
enum Consent {
    Unasked,
    Declined,
    Enabled(ApiKey),
}

// Value makes api_key mandatory: a missing Option field otherwise becomes None.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSettings {
    schema_version: u32,
    api_key: serde_json::Value,
}

fn error(message: &'static str) -> OxideScannerError {
    OxideScannerError::config(message)
}

fn validate_key(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_KEY_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(error(
            "Brave API key must contain 1–512 printable ASCII characters without whitespace",
        ));
    }
    Ok(())
}

fn optional_key(value: String) -> Result<Option<ApiKey>> {
    if value.trim().is_empty() {
        return Ok(None);
    }
    validate_key(&value)?;
    Ok(Some(ApiKey(value)))
}

// Outer None means unset; Some(None) is an explicit environment opt-out.
fn environment_key(value: Option<OsString>) -> Result<Option<Option<ApiKey>>> {
    value
        .map(|value| {
            let value = value
                .into_string()
                .map_err(|_| error("Brave API key environment value is invalid"))?;
            optional_key(value)
        })
        .transpose()
}

fn config_path_from(xdg: Option<OsString>, home: Option<OsString>) -> Result<PathBuf> {
    let base = match xdg.map(PathBuf::from).filter(|path| path.is_absolute()) {
        Some(base) => base,
        None => home
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .ok_or_else(|| error("An absolute HOME or XDG_CONFIG_HOME is required"))?
            .join(".config"),
    };
    Ok(base.join("oxidescanner/hacktricks.json"))
}

fn config_path() -> Result<PathBuf> {
    config_path_from(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    )
}

/// Environment overrides take precedence and are never written to disk.
/// The caller supplies stdin/stdout TTY detection combined with `!json`.
pub fn load_for_scan(interactive: bool) -> Result<Option<ApiKey>> {
    if let Some(key) = environment_key(std::env::var_os("OXIDE_HACKTRICKS_API_KEY"))? {
        return Ok(key);
    }
    load_from_path(&config_path()?, interactive)
}

fn load_from_path(path: &Path, interactive: bool) -> Result<Option<ApiKey>> {
    match storage::load(path)? {
        Consent::Enabled(key) => Ok(Some(key)),
        Consent::Unasked if interactive => ask_and_save(path),
        Consent::Unasked | Consent::Declined => Ok(None),
    }
}

/// Explicitly ask again, retaining existing settings on cancellation or error.
pub fn setup() -> Result<()> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(error(
            "HackTricks setup requires stdin and stdout terminals",
        ));
    }
    let path = config_path()?;
    storage::load(&path)?;
    ask_and_save(&path).map(|_| ())
}

/// Persist an opt-out, removing the stored key and preventing another first-run prompt.
/// Corrupt payloads can be replaced only after the file passes all safety checks.
pub fn reset() -> Result<()> {
    storage::reset(&config_path()?)
}

fn prompt_result<T>(result: std::result::Result<T, InquireError>) -> Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => Ok(None),
        Err(_) => Err(error("HackTricks settings prompt failed")),
    }
}

fn key_prompt() -> Password<'static> {
    Password::new("Brave Search API key (Enter to skip):")
        .with_display_mode(PasswordDisplayMode::Hidden)
        .without_confirmation()
        .with_formatter(&|_| "[REDACTED]".to_owned())
}

fn ask_and_save(path: &Path) -> Result<Option<ApiKey>> {
    let Some(enabled) = prompt_result(
        Confirm::new("Enable HackTricks reference search with Brave?")
            .with_default(false)
            .prompt(),
    )?
    else {
        return Ok(None);
    };
    let key = if enabled {
        let Some(value) = prompt_result(key_prompt().prompt())? else {
            return Ok(None);
        };
        optional_key(value)?
    } else {
        None
    };
    storage::save(path, key.as_ref())?;
    Ok(key)
}

fn decode(bytes: &[u8]) -> Result<Consent> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(error("HackTricks settings exceed the 16 KiB limit"));
    }
    let stored: StoredSettings = serde_json::from_slice(bytes)
        .map_err(|_| error("HackTricks settings contain invalid JSON or schema"))?;
    if stored.schema_version != 1 {
        return Err(error("Unsupported HackTricks settings schema version"));
    }
    match stored.api_key {
        serde_json::Value::Null => Ok(Consent::Declined),
        serde_json::Value::String(value) => {
            validate_key(&value)?;
            Ok(Consent::Enabled(ApiKey(value)))
        }
        _ => Err(error("HackTricks settings contain an invalid API key")),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod storage {
    use super::*;
    use rand::RngCore;
    use std::ffi::{CStr, CString};
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;

    #[cfg(target_os = "macos")]
    mod acl {
        use super::*;
        use libc::{c_int, c_uint, c_void};

        // Missing from Rust libc. Signatures/constants verified against the SDK's
        // sys/acl.h and https://github.com/apple-oss-distributions/Libc/blob/main/include/sys/acl.h
        // Opaque ACL/entry pointers are never dereferenced in Rust.
        const ACL_TYPE_EXTENDED: c_uint = 0x100;
        const ACL_FIRST_ENTRY: c_int = 0;
        const ACL_NEXT_ENTRY: c_int = -1;
        const ACL_EXTENDED_ALLOW: c_uint = 1;
        const ACL_EXTENDED_DENY: c_uint = 2;
        // READ_DATA/LIST_DIRECTORY, EXECUTE/SEARCH, READ_ATTRIBUTES,
        // READ_EXTATTRIBUTES, READ_SECURITY, SYNCHRONIZE. All other allow bits
        // on ancestors are rejected, including delete-child and ACL/owner changes.
        const READ_ONLY_PERMISSIONS: u64 =
            (1 << 1) | (1 << 3) | (1 << 7) | (1 << 9) | (1 << 11) | (1 << 20);

        extern "C" {
            fn acl_get_fd_np(fd: c_int, acl_type: c_uint) -> *mut c_void;
            fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry: *mut *mut c_void) -> c_int;
            fn acl_get_tag_type(entry: *mut c_void, tag: *mut c_uint) -> c_int;
            fn acl_get_permset_mask_np(entry: *mut c_void, permissions: *mut u64) -> c_int;
            fn acl_free(object: *mut c_void) -> c_int;
        }

        pub(super) fn check(file: &File, private: bool) -> Result<()> {
            // SAFETY: file owns a live descriptor; the returned allocation is
            // released below after all borrowed entries have gone out of use.
            let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
            if acl.is_null() {
                // Apple gen/filesec.c reports an absent FILESEC_ACL as ENOENT.
                // Unsupported filesystems and other retrieval failures fail closed.
                return if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                    Ok(())
                } else {
                    Err(error("Cannot inspect HackTricks settings ACL"))
                };
            }
            let result = (|| {
                let mut entry_id = ACL_FIRST_ENTRY;
                loop {
                    let mut entry = std::ptr::null_mut();
                    // SAFETY: acl remains allocated and entry is a valid output pointer.
                    let status = unsafe { acl_get_entry(acl, entry_id, &mut entry) };
                    // Darwin returns 0 for an entry, -1/EINVAL at the end, unlike
                    // Linux. See Apple posix1e/acl_entry.c; this ACL came from the OS.
                    if status == -1
                        && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL)
                    {
                        return Ok(());
                    }
                    if status != 0 || entry.is_null() {
                        return Err(error("Cannot inspect HackTricks settings ACL entry"));
                    }
                    if private {
                        return Err(error(
                            "Private HackTricks settings must not have extended ACL entries",
                        ));
                    }
                    let mut tag = 0;
                    let mut permissions = 0;
                    // SAFETY: entry belongs to the live ACL; outputs match the
                    // header's acl_tag_t enum and uint64_t acl_permset_mask_t.
                    if unsafe { acl_get_tag_type(entry, &mut tag) } != 0
                        || unsafe { acl_get_permset_mask_np(entry, &mut permissions) } != 0
                    {
                        return Err(error("Cannot inspect HackTricks settings ACL permissions"));
                    }
                    if tag != ACL_EXTENDED_DENY
                        && (tag != ACL_EXTENDED_ALLOW || permissions & !READ_ONLY_PERMISSIONS != 0)
                    {
                        return Err(error(
                            "HackTricks settings ancestor has an unsafe ACL grant",
                        ));
                    }
                    entry_id = ACL_NEXT_ENTRY;
                }
            })();
            // SAFETY: acl is the original allocated pointer and is freed once.
            if unsafe { acl_free(acl) } != 0 {
                return Err(error("Cannot release HackTricks settings ACL"));
            }
            result
        }
    }

    // Descriptor-relative operations keep checked directories pinned even if an
    // ancestor is renamed; libc supplies the platform's constants and ABI.
    fn open_at(directory: &File, name: &CStr, flags: libc::c_int) -> io::Result<File> {
        let mode: libc::mode_t = 0o600;
        // SAFETY: directory is live, name is NUL-terminated, and the variadic mode
        // is promoted to unsigned int. Successful descriptors transfer to File.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CLOEXEC,
                mode as libc::c_uint,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    fn check_directory(directory: &File, private: bool) -> Result<()> {
        let metadata = directory
            .metadata()
            .map_err(|_| error("Cannot inspect HackTricks settings directory"))?;
        // SAFETY: geteuid has no arguments or memory preconditions.
        let uid = unsafe { libc::geteuid() };
        let secure = if private {
            metadata.uid() == uid && metadata.mode() & 0o077 == 0
        } else {
            // Existing parents may be 0755; never chmod them. Root/user-owned
            // sticky directories allow macOS /tmp and per-user temporary roots.
            (metadata.uid() == uid || metadata.uid() == 0)
                && (metadata.mode() & 0o022 == 0 || metadata.mode() & 0o1000 != 0)
        };
        if !metadata.is_dir() || !secure {
            return Err(error(
                "HackTricks settings directory has unsafe ownership or permissions",
            ));
        }
        #[cfg(target_os = "macos")]
        acl::check(directory, private)?;
        Ok(())
    }

    fn check_file(file: &File) -> Result<()> {
        let metadata = file
            .metadata()
            .map_err(|_| error("Cannot inspect HackTricks settings file"))?;
        // Reject hard links as well: a credential must not have a second pathname.
        if !metadata.is_file()
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(error(
                "HackTricks settings file has unsafe type, ownership or permissions",
            ));
        }
        // Linux mode bits include the effective POSIX ACL mask; Darwin needs
        // an additional check because extended ACL grants bypass those bits.
        #[cfg(target_os = "macos")]
        acl::check(file, true)?;
        Ok(())
    }

    fn directory(path: &Path, create: bool) -> Result<Option<File>> {
        if !path.is_absolute()
            || path.file_name() != Some(std::ffi::OsStr::new("hacktricks.json"))
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir))
        {
            return Err(error("Invalid HackTricks settings path"));
        }
        let parent = path
            .parent()
            .ok_or_else(|| error("Invalid HackTricks settings path"))?;
        let mut directory = File::open("/")
            .map_err(|_| error("Cannot open HackTricks settings parent directory"))?;
        let components: Vec<_> = parent.components().collect();
        for (index, component) in components.iter().enumerate() {
            let Component::Normal(name) = component else {
                continue;
            };
            let private = index + 1 == components.len();
            check_directory(&directory, false)?;
            let name = CString::new(name.as_bytes())
                .map_err(|_| error("Invalid HackTricks settings path"))?;
            let flags =
                libc::O_RDONLY | libc::O_DIRECTORY | if private { libc::O_NOFOLLOW } else { 0 };
            let next = match open_at(&directory, &name, flags) {
                Ok(next) => next,
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    if !create {
                        return Ok(None);
                    }
                    // SAFETY: both descriptor and C string remain live during mkdirat.
                    if unsafe {
                        libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700 as libc::mode_t)
                    } < 0
                        && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
                    {
                        return Err(error("Cannot create HackTricks settings directory"));
                    }
                    // Never follow a symlink raced into a newly created component.
                    open_at(&directory, &name, flags | libc::O_NOFOLLOW)
                        .map_err(|_| error("Cannot securely open HackTricks settings directory"))?
                }
                Err(_) => return Err(error("Cannot securely open HackTricks settings directory")),
            };
            check_directory(&next, private)?;
            directory = next;
        }
        check_directory(&directory, true)?;
        Ok(Some(directory))
    }

    fn open_current(directory: &File) -> Result<Option<File>> {
        check_directory(directory, true)?;
        let name = CString::new("hacktricks.json").unwrap();
        // NONBLOCK ensures a raced-in FIFO cannot hang the process before fstat.
        let file = match open_at(
            directory,
            &name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        ) {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(error("Cannot securely open HackTricks settings file")),
        };
        check_file(&file)?;
        Ok(Some(file))
    }

    fn read_current(directory: &File) -> Result<Consent> {
        let Some(file) = open_current(directory)? else {
            return Ok(Consent::Unasked);
        };
        let mut bytes = Vec::new();
        (&file)
            .take(MAX_FILE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| error("Cannot read HackTricks settings file"))?;
        check_file(&file)?;
        decode(&bytes)
    }

    pub(super) fn load(path: &Path) -> Result<Consent> {
        match directory(path, false)? {
            Some(directory) => read_current(&directory),
            None => Ok(Consent::Unasked),
        }
    }

    fn temporary_file(directory: &File) -> Result<(CString, File)> {
        for _ in 0..16 {
            let mut random = [0u8; 16];
            rand::rngs::OsRng
                .try_fill_bytes(&mut random)
                .map_err(|_| error("Cannot generate a secure settings temporary filename"))?;
            let name = CString::new(format!(
                ".hacktricks-{:032x}.tmp",
                u128::from_ne_bytes(random)
            ))
            .unwrap();
            // O_CREAT | O_EXCL is create_new, relative to the verified private dir.
            match open_at(
                directory,
                &name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            ) {
                Ok(file) => return Ok((name, file)),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(error("Cannot create HackTricks settings temporary file")),
            }
        }
        Err(error("Cannot allocate HackTricks settings temporary file"))
    }

    pub(super) fn save(path: &Path, key: Option<&ApiKey>) -> Result<()> {
        write_settings(path, key, false)
    }

    pub(super) fn reset(path: &Path) -> Result<()> {
        write_settings(path, None, true)
    }

    fn check_current(directory: &File, recover_payload: bool) -> Result<()> {
        if recover_payload {
            open_current(directory).map(|_| ())
        } else {
            read_current(directory).map(|_| ())
        }
    }

    fn write_settings(path: &Path, key: Option<&ApiKey>, recover_payload: bool) -> Result<()> {
        if let Some(key) = key {
            validate_key(key.as_str())?;
        }
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "api_key": key.map(ApiKey::as_str),
        }))
        .map_err(|_| error("Cannot encode HackTricks settings"))?;
        let directory = directory(path, true)?
            .ok_or_else(|| error("Cannot create HackTricks settings directory"))?;
        check_current(&directory, recover_payload)?;
        let (temporary_name, mut temporary) = temporary_file(&directory)?;
        let result = (|| {
            // Inherited ACL grants must be rejected before any credential bytes.
            check_file(&temporary)?;
            temporary
                .write_all(&bytes)
                .and_then(|_| temporary.sync_all())
                .map_err(|_| error("Cannot write HackTricks settings"))?;
            // Revalidate before committing; failed validation leaves the old file intact.
            check_current(&directory, recover_payload)?;
            check_file(&temporary)?;
            let destination = CString::new("hacktricks.json").unwrap();
            // SAFETY: the directory and both NUL-terminated names remain live.
            if unsafe {
                libc::renameat(
                    directory.as_raw_fd(),
                    temporary_name.as_ptr(),
                    directory.as_raw_fd(),
                    destination.as_ptr(),
                )
            } < 0
            {
                return Err(error("Cannot replace HackTricks settings file"));
            }
            // Rename is the last fallible step: an Err never means a committed write.
            Ok(())
        })();
        if result.is_err() {
            // SAFETY: cleanup is anchored to the same live directory, without following links.
            unsafe { libc::unlinkat(directory.as_raw_fd(), temporary_name.as_ptr(), 0) };
        }
        result
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod storage {
    use super::*;

    pub(super) fn load(_: &Path) -> Result<Consent> {
        Err(error(
            "Secure HackTricks settings persistence is unsupported on this platform",
        ))
    }

    pub(super) fn save(_: &Path, _: Option<&ApiKey>) -> Result<()> {
        Err(error(
            "Secure HackTricks settings persistence is unsupported on this platform",
        ))
    }

    pub(super) fn reset(path: &Path) -> Result<()> {
        save(path, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_environment_and_redaction() {
        let value: String = (b'!'..=b'~').map(char::from).collect();
        let key = optional_key(value.clone()).unwrap().unwrap();
        assert_eq!(key.as_str(), value);
        assert_eq!(format!("{key:?}"), "ApiKey([REDACTED])");
        assert!(validate_key(&"x".repeat(512)).is_ok());
        for invalid in [
            "".to_owned(),
            "x".repeat(513),
            "secret key".into(),
            "secret\n".into(),
            "\tsecret".into(),
            "secret\0".into(),
            "secret\x7f".into(),
            "clé".into(),
        ] {
            let err = validate_key(&invalid).unwrap_err();
            assert!(!format!("{err:?} {err}").contains("secret"));
        }
        assert!(environment_key(None).unwrap().is_none());
        for blank in ["", " \t\n"] {
            assert!(matches!(
                environment_key(Some(blank.into())).unwrap(),
                Some(None)
            ));
        }
        assert_eq!(
            environment_key(Some("arbitrary-prefix".into()))
                .unwrap()
                .unwrap()
                .unwrap()
                .as_str(),
            "arbitrary-prefix"
        );
        assert!(environment_key(Some(" secret".into())).is_err());
    }

    #[test]
    fn test_path_resolution() {
        assert_eq!(
            config_path_from(Some("/config".into()), None).unwrap(),
            PathBuf::from("/config/oxidescanner/hacktricks.json")
        );
        for xdg in [None, Some("relative".into()), Some("".into())] {
            assert_eq!(
                config_path_from(xdg, Some("/home/test".into())).unwrap(),
                PathBuf::from("/home/test/.config/oxidescanner/hacktricks.json")
            );
        }
        assert!(config_path_from(None, None).is_err());
        assert!(config_path_from(None, Some("relative".into())).is_err());
    }

    #[test]
    fn test_hidden_prompt_and_sanitized_cancellation() {
        let prompt = key_prompt();
        assert_eq!(prompt.display_mode, PasswordDisplayMode::Hidden);
        assert!(!prompt.enable_display_toggle);
        assert!(!prompt.enable_confirmation);
        assert_eq!((prompt.formatter)("secret"), "[REDACTED]");
        for err in [
            InquireError::OperationCanceled,
            InquireError::OperationInterrupted,
        ] {
            assert!(prompt_result::<String>(Err(err)).unwrap().is_none());
        }
        let err = prompt_result::<String>(Err(InquireError::InvalidConfiguration("secret".into())))
            .unwrap_err();
        assert!(!format!("{err:?} {err}").contains("secret"));
    }

    #[test]
    fn test_malformed_oversized_and_unversioned_input() {
        for bytes in [
            b"".as_slice(),
            b"{",
            b"[]",
            b"{}",
            b"{\"api_key\":null}",
            b"{\"schema_version\":1}",
            b"{\"schema_version\":2,\"api_key\":null}",
            b"{\"schema_version\":1,\"api_key\":123}",
            b"{\"schema_version\":1,\"api_key\":\"\"}",
            b"{\"schema_version\":1,\"api_key\":\"secret key\"}",
            b"{\"schema_version\":1,\"api_key\":null,\"api_key\":\"secret\"}",
            b"{\"schema_version\":1,\"api_key\":null,\"secret\":true}",
        ] {
            let err = decode(bytes).unwrap_err();
            assert!(!format!("{err:?} {err}").contains("secret"));
        }
        let mut bytes = br#"{"schema_version":1,"api_key":null}"#.to_vec();
        bytes.resize(MAX_FILE_BYTES, b' ');
        assert!(matches!(decode(&bytes).unwrap(), Consent::Declined));
        bytes.push(b' ');
        assert!(decode(&bytes).is_err());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    mod unix {
        use super::*;
        use std::fs::{self, DirBuilder, Permissions};
        use std::os::unix::ffi::OsStringExt;
        use std::os::unix::fs::{symlink, DirBuilderExt, PermissionsExt};

        struct Temp(PathBuf);

        impl Temp {
            fn new() -> Self {
                let path = std::env::temp_dir()
                    .join(format!("oxide-settings-{:032x}", rand::random::<u128>()));
                DirBuilder::new().mode(0o700).create(&path).unwrap();
                Self(path)
            }

            fn path(&self) -> PathBuf {
                self.0.join("config/oxidescanner/hacktricks.json")
            }
        }

        impl Drop for Temp {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        #[test]
        fn test_non_unicode_environment_is_sanitized() {
            let err =
                environment_key(Some(OsString::from_vec(b"secret\xff".to_vec()))).unwrap_err();
            assert!(!format!("{err:?} {err}").contains("secret"));
        }

        #[test]
        fn test_unasked_declined_enabled_and_reset() {
            let temp = Temp::new();
            let path = temp.path();
            assert!(matches!(storage::load(&path).unwrap(), Consent::Unasked));
            assert!(load_from_path(&path, false).unwrap().is_none());
            assert!(!temp.0.join("config").exists());
            storage::save(&path, None).unwrap();
            assert!(matches!(storage::load(&path).unwrap(), Consent::Declined));
            assert!(load_from_path(&path, true).unwrap().is_none()); // Must not prompt.
            let key = ApiKey("test-credential".into());
            storage::save(&path, Some(&key)).unwrap();
            assert_eq!(
                load_from_path(&path, false).unwrap().unwrap().as_str(),
                key.as_str()
            );
            storage::reset(&path).unwrap();
            assert!(matches!(storage::load(&path).unwrap(), Consent::Declined));
            let saved: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            assert_eq!(
                saved,
                serde_json::json!({"schema_version": 1, "api_key": null})
            );
            assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
        }

        #[test]
        fn test_permissions_and_unchanged_existing_parent() {
            let temp = Temp::new();
            let path = temp.path();
            storage::save(&path, None).unwrap();
            let app = path.parent().unwrap();
            let base = app.parent().unwrap();
            for (entry, mode) in [(base, 0o700), (app, 0o700), (path.as_path(), 0o600)] {
                assert_eq!(
                    fs::metadata(entry).unwrap().permissions().mode() & 0o777,
                    mode
                );
            }
            fs::set_permissions(base, Permissions::from_mode(0o755)).unwrap();
            storage::save(&path, None).unwrap();
            assert_eq!(
                fs::metadata(base).unwrap().permissions().mode() & 0o777,
                0o755
            );
            for (entry, unsafe_mode, restored) in [
                (app, 0o750, 0o700),
                (path.as_path(), 0o640, 0o600),
                (app, 0o705, 0o700),
                (path.as_path(), 0o604, 0o600),
                (base, 0o777, 0o755),
            ] {
                fs::set_permissions(entry, Permissions::from_mode(unsafe_mode)).unwrap();
                assert!(storage::load(&path).is_err());
                assert!(storage::save(&path, None).is_err());
                assert!(storage::reset(&path).is_err());
                assert_eq!(
                    fs::metadata(entry).unwrap().permissions().mode() & 0o777,
                    unsafe_mode
                );
                fs::set_permissions(entry, Permissions::from_mode(restored)).unwrap();
            }
        }

        #[test]
        fn test_symlinks_and_hardlinks_are_rejected() {
            let temp = Temp::new();
            let path = temp.path();
            storage::save(&path, Some(&ApiKey("secret".into()))).unwrap();
            let original = fs::read(&path).unwrap();
            let backup = temp.0.join("original.json");
            fs::rename(&path, &backup).unwrap();
            for target in [&backup, &temp.0.join("absent")] {
                symlink(target, &path).unwrap();
                assert!(storage::load(&path).is_err());
                assert!(storage::save(&path, None).is_err());
                assert!(storage::reset(&path).is_err());
                fs::remove_file(&path).unwrap();
            }
            fs::hard_link(&backup, &path).unwrap();
            assert!(storage::load(&path).is_err());
            assert!(storage::save(&path, None).is_err());
            assert!(storage::reset(&path).is_err());
            fs::remove_file(&path).unwrap();
            fs::rename(&backup, &path).unwrap();
            let app = path.parent().unwrap();
            let moved = temp.0.join("moved");
            fs::rename(app, &moved).unwrap();
            for target in [&moved, &temp.0.join("absent")] {
                symlink(target, app).unwrap();
                assert!(storage::load(&path).is_err());
                assert!(storage::save(&path, None).is_err());
                assert!(storage::reset(&path).is_err());
                fs::remove_file(app).unwrap();
            }
            assert_eq!(fs::read(moved.join("hacktricks.json")).unwrap(), original);
        }

        #[test]
        fn test_invalid_writes_preserve_contents_and_reset_recovers_bad_payloads() {
            let temp = Temp::new();
            let path = temp.path();
            storage::save(&path, Some(&ApiKey("old-credential".into()))).unwrap();
            let original = fs::read(&path).unwrap();
            assert!(storage::save(&path, Some(&ApiKey("invalid secret".into()))).is_err());
            assert_eq!(fs::read(&path).unwrap(), original);
            for bytes in [
                b"{".to_vec(),
                b"{\"api_key\":\"secret\"}".to_vec(),
                vec![b' '; MAX_FILE_BYTES + 1],
            ] {
                fs::write(&path, &bytes).unwrap();
                assert!(storage::load(&path).is_err());
                assert!(storage::save(&path, None).is_err());
                assert_eq!(fs::read(&path).unwrap(), bytes);
                assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
                storage::reset(&path).unwrap();
                assert!(matches!(storage::load(&path).unwrap(), Consent::Declined));
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&fs::read(&path).unwrap()).unwrap(),
                    serde_json::json!({"schema_version": 1, "api_key": null})
                );
            }
        }

        #[test]
        fn test_fifo_rejected_without_blocking() {
            use std::os::unix::ffi::OsStrExt;
            use std::os::unix::fs::FileTypeExt;

            let temp = Temp::new();
            let path = temp.path();
            storage::reset(&path).unwrap();
            fs::remove_file(&path).unwrap();
            let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            // SAFETY: name is NUL-terminated and points only inside this private fixture.
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            assert!(storage::reset(&path).is_err());
            assert!(storage::load(&path).is_err());
            assert!(storage::save(&path, None).is_err());
            assert!(fs::symlink_metadata(&path).unwrap().file_type().is_fifo());
            assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn test_macos_acl_grants_and_inherited_file_acl() {
            use std::fs::OpenOptions;
            use std::os::unix::fs::OpenOptionsExt;
            use std::process::Command;

            fn add_acl(path: &Path, entry: &str) -> bool {
                let output = Command::new("/bin/chmod")
                    .args(["+a", entry])
                    .arg(path)
                    .output()
                    .unwrap();
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !output.status.success() && stderr.contains("Operation not supported") {
                    eprintln!(
                        "macOS ACL fixture skipped: temporary filesystem does not support ACLs"
                    );
                    return false;
                }
                assert!(output.status.success(), "ACL fixture failed: {stderr}");
                true
            }

            fn remove_acl(path: &Path) {
                assert!(Command::new("/bin/chmod")
                    .arg("-N")
                    .arg(path)
                    .status()
                    .unwrap()
                    .success());
            }

            let temp = Temp::new();
            if !add_acl(&temp.0, "everyone allow readattr") {
                return;
            }
            remove_acl(&temp.0);
            let path = temp.path();
            storage::save(&path, Some(&ApiKey("fixture-credential".into()))).unwrap();
            let original = fs::read(&path).unwrap();
            let app = path.parent().unwrap();
            let base = app.parent().unwrap();
            for (entry, acl, mode) in [
                (path.as_path(), "everyone allow read", 0o600),
                (app, "everyone allow list,search", 0o700),
                (base, "everyone allow delete_child", 0o700),
                (base, "everyone allow writesecurity", 0o700),
            ] {
                if !add_acl(entry, acl) {
                    return;
                }
                assert_eq!(
                    fs::metadata(entry).unwrap().permissions().mode() & 0o777,
                    mode
                );
                assert!(storage::load(&path).is_err());
                assert!(storage::save(&path, None).is_err());
                assert!(storage::reset(&path).is_err());
                assert_eq!(fs::read(&path).unwrap(), original);
                remove_acl(entry);
            }
            // Normal macOS deny-delete entries and read-only ancestor grants are safe.
            assert!(add_acl(base, "everyone deny delete"));
            assert!(add_acl(base, "everyone allow readattr"));
            assert!(storage::load(&path).is_ok());
            storage::save(&path, Some(&ApiKey("fixture-credential".into()))).unwrap();
            remove_acl(base);

            // A newly created 0600 file can still inherit a read grant. Remove only
            // the fixture parent's ACL to isolate the inherited file's safety check.
            fs::remove_file(&path).unwrap();
            assert!(add_acl(
                app,
                "everyone allow read,file_inherit,only_inherit"
            ));
            let inherited = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            remove_acl(app);
            assert_eq!(
                inherited.metadata().unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert!(storage::reset(&path).is_err());
            assert_eq!(inherited.metadata().unwrap().len(), 0);
            remove_acl(&path);
            storage::reset(&path).unwrap();
            assert!(matches!(storage::load(&path).unwrap(), Consent::Declined));
        }
    }
}
