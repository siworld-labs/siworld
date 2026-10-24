//! Bounded, owner-only secret files. These files are not encrypted keystores.

#[cfg(unix)]
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::io::{Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

/// Read a regular file owned by the current user, without following its final
/// symlink. Parent directories must also be trusted by the operator.
#[cfg(unix)]
pub fn read_secret(path: &Path) -> Result<Zeroizing<String>, String> {
    let file = private_file(path)?;
    let mut text = Zeroizing::new(String::with_capacity(4097));
    file.take(4097)
        .read_to_string(&mut text)
        .map_err(|_| "cannot read secret file")?;
    if text.len() > 4096 {
        return Err("secret file is too large".into());
    }
    Ok(text)
}

#[cfg(unix)]
fn private_file(path: &Path) -> Result<File, String> {
    let file = {
        use rustix::fs::{open, Mode, OFlags};
        use std::os::unix::fs::MetadataExt;
        let fd = open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "cannot open secret file (regular owner-only file required)".to_string())?;
        let file = File::from(fd);
        let m = file.metadata().map_err(|_| "cannot inspect secret file")?;
        if !m.is_file()
            || m.uid() != rustix::process::geteuid().as_raw()
            || m.mode() & 0o077 != 0
            || m.nlink() != 1
        {
            return Err("secret file must be regular, owned by this user, have one link and mode 0600 or stricter".into());
        }
        file
    };
    Ok(file)
}

pub(crate) fn read_private_bytes(path: &Path, max: usize) -> Result<Zeroizing<Vec<u8>>, String> {
    #[cfg(unix)]
    {
        let file = private_file(path)?;
        if file
            .metadata()
            .map_err(|_| "cannot inspect private file")?
            .len()
            > max as u64
        {
            return Err("private file is too large".into());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(max as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot read private file")?;
        if bytes.len() > max {
            return Err("private file is too large".into());
        }
        Ok(bytes)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, max);
        Err("private file protection unavailable".into())
    }
}

/// Create a new owner-only file; never overwrite or follow an existing path.
#[cfg(unix)]
pub fn write_secret(path: &Path, contents: &str) -> Result<(), String> {
    write_private_bytes(path, contents.as_bytes())
}

#[cfg(unix)]
pub(crate) fn write_private_bytes(path: &Path, contents: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options
        .open(path)
        .map_err(|_| "cannot create secret file (it may already exist)")?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|_| "cannot save secret file")?;
    Ok(())
}

#[cfg(not(unix))]
pub fn read_secret(_path: &Path) -> Result<Zeroizing<String>, String> {
    Err("owner-only secret file access is not implemented on this platform".into())
}

#[cfg(not(unix))]
pub fn write_secret(_path: &Path, _contents: &str) -> Result<(), String> {
    Err("owner-only secret file creation is not implemented on this platform".into())
}

#[cfg(not(unix))]
pub(crate) fn write_private_bytes(_path: &Path, _contents: &[u8]) -> Result<(), String> {
    Err("private file protection unavailable".into())
}

/// Encode raw key material directly into an erasing buffer, without a normal
/// intermediate hex String. The source remains the caller's responsibility.
pub fn write_secret_bytes(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::fmt::Write;
    let mut text = Zeroizing::new(String::with_capacity(2 * bytes.len() + 1));
    for byte in bytes {
        write!(text, "{byte:02x}").expect("writing a string");
    }
    text.push('\n');
    write_secret(path, &text)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn rejects_permissions_links_and_oversized_files() {
        let dir = std::env::temp_dir().join(format!("siworld-secrets-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("key");
        write_secret(&path, "secret").unwrap();
        assert_eq!(&*read_secret(&path).unwrap(), "secret");
        assert!(write_secret(&path, "replacement").is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_secret(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.join("link");
        symlink(&path, &link).unwrap();
        assert!(read_secret(&link).is_err());
        std::fs::remove_file(&link).unwrap();
        std::fs::hard_link(&path, &link).unwrap();
        assert!(read_secret(&path).is_err());
        std::fs::remove_file(&link).unwrap();
        std::fs::write(&path, "x".repeat(4097)).unwrap();
        assert!(read_secret(&path).is_err());
        assert!(read_secret(&dir).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
