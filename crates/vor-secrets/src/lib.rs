// SPDX-License-Identifier: MPL-2.0

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use zeroize::Zeroize;

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::ptr::{null, null_mut};
#[cfg(windows)]
use std::slice;
#[cfg(windows)]
use windows_sys::Win32::Foundation::LocalFree;
#[cfg(windows)]
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};

const FILE_MAGIC: &[u8] = b"VOR-SECRET-DPAPI-1\0";
const APP_ENTROPY: &[u8] = b"vor-commander:dpapi:v1";
const MAX_SECRET_BYTES: usize = 1024 * 1024;

pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}
impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}

pub struct FileSecretStore {
    root: PathBuf,
}

impl FileSecretStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, SecretError> {
        fs::create_dir_all(root.as_ref())?;
        let root = fs::canonicalize(root)?;
        Ok(Self { root })
    }

    pub fn put(&self, name: &str, secret: &[u8]) -> Result<(), SecretError> {
        validate_name(name)?;
        if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
            return Err(SecretError::InvalidSecretSize);
        }
        let encrypted = protect(secret, APP_ENTROPY)?;
        let target = self.root.join(format!("{name}.dpapi"));
        let temp = self.root.join(format!(
            ".{name}.{}.tmp",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)?;
        file.write_all(FILE_MAGIC)?;
        file.write_all(&encrypted)?;
        file.sync_all()?;
        drop(file);
        atomic_replace(&temp, &target)?;
        Ok(())
    }
    pub fn get(&self, name: &str) -> Result<SecretBytes, SecretError> {
        validate_name(name)?;
        let path = self.root.join(format!("{name}.dpapi"));
        let bytes = fs::read(path)?;
        if !bytes.starts_with(FILE_MAGIC) || bytes.len() == FILE_MAGIC.len() {
            return Err(SecretError::InvalidBlob);
        }
        let decrypted = unprotect(&bytes[FILE_MAGIC.len()..], APP_ENTROPY)?;
        if decrypted.is_empty() || decrypted.len() > MAX_SECRET_BYTES {
            return Err(SecretError::InvalidBlob);
        }
        Ok(SecretBytes(decrypted))
    }

    pub fn delete(&self, name: &str) -> Result<bool, SecretError> {
        validate_name(name)?;
        let path = self.root.join(format!("{name}.dpapi"));
        match fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    pub fn contains(&self, name: &str) -> Result<bool, SecretError> {
        validate_name(name)?;
        Ok(self.root.join(format!("{name}.dpapi")).is_file())
    }
}

fn validate_name(name: &str) -> Result<(), SecretError> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(SecretError::InvalidName);
    }
    Ok(())
}
#[cfg(windows)]
struct LocalBlob(CRYPT_INTEGER_BLOB);

#[cfg(windows)]
impl LocalBlob {
    fn to_vec(&self) -> Result<Vec<u8>, SecretError> {
        if self.0.cbData == 0 {
            return Ok(Vec::new());
        }
        if self.0.pbData.is_null() {
            return Err(SecretError::InvalidBlob);
        }
        // SAFETY: DPAPI returned pbData with cbData bytes and ownership remains with this wrapper.
        Ok(unsafe { slice::from_raw_parts(self.0.pbData, self.0.cbData as usize) }.to_vec())
    }
}

#[cfg(windows)]
impl Drop for LocalBlob {
    fn drop(&mut self) {
        if !self.0.pbData.is_null() {
            // SAFETY: DPAPI allocates the output buffer with LocalAlloc; LocalFree is its required release.
            unsafe {
                LocalFree(self.0.pbData.cast());
            }
            self.0.pbData = null_mut();
            self.0.cbData = 0;
        }
    }
}

#[cfg(windows)]
fn blob_from_slice(bytes: &[u8]) -> Result<CRYPT_INTEGER_BLOB, SecretError> {
    Ok(CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(bytes.len()).map_err(|_| SecretError::InvalidSecretSize)?,
        pbData: bytes.as_ptr() as *mut u8,
    })
}
#[cfg(windows)]
fn protect(plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, SecretError> {
    let input = blob_from_slice(plaintext)?;
    let entropy = blob_from_slice(entropy)?;
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: all input blobs reference live slices for the duration of the call;
    // UI is forbidden and output ownership is transferred to LocalBlob below.
    let ok = unsafe {
        CryptProtectData(
            &input,
            null(),
            &entropy,
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(SecretError::Dpapi(io::Error::last_os_error()));
    }
    LocalBlob(output).to_vec()
}

#[cfg(windows)]
fn unprotect(ciphertext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, SecretError> {
    let input = blob_from_slice(ciphertext)?;
    let entropy = blob_from_slice(entropy)?;
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: the input slices remain live; no UI or description is requested.
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            null_mut(),
            &entropy,
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(SecretError::Dpapi(io::Error::last_os_error()));
    }
    LocalBlob(output).to_vec()
}

#[cfg(not(windows))]
fn protect(_plaintext: &[u8], _entropy: &[u8]) -> Result<Vec<u8>, SecretError> {
    Err(SecretError::UnsupportedPlatform)
}

#[cfg(not(windows))]
fn unprotect(_ciphertext: &[u8], _entropy: &[u8]) -> Result<Vec<u8>, SecretError> {
    Err(SecretError::UnsupportedPlatform)
}

#[cfg(windows)]
fn atomic_replace(source: &Path, target: &Path) -> Result<(), SecretError> {
    let source_wide: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let target_wide: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: both UTF-16 buffers are NUL-terminated and remain live for the call.
    let ok = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            target_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        Err(io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, target: &Path) -> Result<(), SecretError> {
    if target.exists() {
        fs::remove_file(target)?;
    }
    fs::rename(source, target)?;
    Ok(())
}
#[derive(Debug, Error)]
pub enum SecretError {
    #[error("secret name is invalid")]
    InvalidName,
    #[error("secret size is invalid")]
    InvalidSecretSize,
    #[error("secret blob is invalid")]
    InvalidBlob,
    #[error("Windows DPAPI failed: {0}")]
    Dpapi(io::Error),
    #[error("the configured secret backend is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("secret store I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn dpapi_file_roundtrip_does_not_persist_plaintext() {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::open(dir.path()).unwrap();
        let plaintext = b"super-secret-device-private-key-material";
        store.put("device-key", plaintext).unwrap();
        let path = dir.path().join("device-key.dpapi");
        let disk = fs::read(path).unwrap();
        assert!(disk.starts_with(FILE_MAGIC));
        assert!(
            !disk
                .windows(plaintext.len())
                .any(|window| window == plaintext)
        );
        let loaded = store.get("device-key").unwrap();
        assert_eq!(loaded.as_slice(), plaintext);
    }

    #[test]
    fn invalid_names_fail_closed() {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::open(dir.path()).unwrap();
        assert!(matches!(
            store.put("../escape", b"x"),
            Err(SecretError::InvalidName)
        ));
        assert!(matches!(store.get("a/b"), Err(SecretError::InvalidName)));
    }
    #[test]
    fn dpapi_entropy_is_bound_and_debug_is_redacted() {
        let encrypted = protect(b"secret", b"entropy-a").unwrap();
        assert!(unprotect(&encrypted, b"entropy-b").is_err());
        let secret = SecretBytes(b"secret".to_vec());
        assert_eq!(format!("{secret:?}"), "SecretBytes(<redacted>)");
    }

    #[test]
    fn overwrite_and_delete_work() {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::open(dir.path()).unwrap();
        store.put("relay-token", b"one").unwrap();
        store.put("relay-token", b"two").unwrap();
        assert_eq!(store.get("relay-token").unwrap().as_slice(), b"two");
        assert!(store.contains("relay-token").unwrap());
        assert!(store.delete("relay-token").unwrap());
        assert!(!store.contains("relay-token").unwrap());
        assert!(!store.delete("relay-token").unwrap());
    }
}
