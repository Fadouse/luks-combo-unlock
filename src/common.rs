// SPDX-License-Identifier: GPL-3.0-only
use crate::{Result, fail, linux};
use std::{
    collections::BTreeMap,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};
pub static INTERRUPTED: AtomicBool = AtomicBool::new(false);
extern "C" fn interrupted(_: i32) {
    INTERRUPTED.store(true, Ordering::Relaxed);
}
pub fn harden() -> Result<()> {
    // SAFETY: process-local scalar calls and a static signal handler; Linux x86-64 ABI.
    unsafe {
        if linux::geteuid() != 0 {
            return Err(fail("root is required"));
        }
        linux::umask(0o077);
        let limit = linux::Rlimit {
            current: 0,
            maximum: 0,
        };
        if linux::setrlimit(4, &limit) != 0 || linux::prctl(4, 0, 0, 0, 0) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        for sig in [1, 2, 15] {
            if linux::signal(sig, interrupted as *const () as usize) == usize::MAX {
                return Err(std::io::Error::last_os_error().into());
            }
        }
    }
    Ok(())
}
pub fn cancelled() -> Result<()> {
    if INTERRUPTED.load(Ordering::Relaxed) {
        Err(fail("operation interrupted"))
    } else {
        Ok(())
    }
}
pub fn boot_id() -> Result<String> {
    let id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    if id.len() != 36 || !id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return Err(fail("invalid boot ID"));
    }
    Ok(id)
}
pub fn trusted_parent(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(fail("absolute path required"));
    }
    for parent in path.ancestors().skip(1) {
        let m = fs::symlink_metadata(parent)?;
        // Root-owned sticky directories protect existing root-owned entries (Nix store).
        if !m.is_dir() || m.uid() != 0 || (m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0) {
            return Err(fail("untrusted parent directory"));
        }
    }
    Ok(())
}
pub fn read_trusted(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let path = fs::canonicalize(path)?;
    trusted_parent(&path)?;
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(linux::O_NOFOLLOW | linux::O_CLOEXEC | linux::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 || m.len() > limit {
        return Err(fail("untrusted or oversized file"));
    }
    let mut data = Vec::new();
    f.take(limit + 1).read_to_end(&mut data)?;
    if data.len() as u64 > limit {
        return Err(fail("file exceeded size limit"));
    }
    Ok(data)
}
pub fn private_dir(path: &Path) -> Result<()> {
    trusted_parent(path)?;
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o077 != 0 {
        return Err(fail("runtime directory is not private"));
    }
    Ok(())
}
pub fn unique(parent: &Path, prefix: &str) -> Result<PathBuf> {
    let mut random = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
    Ok(parent.join(format!("{prefix}{suffix}")))
}
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    trusted_parent(path)?;
    let temp = unique(
        path.parent().ok_or_else(|| fail("missing parent"))?,
        ".pending-",
    )?;
    let result = (|| -> Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(linux::O_NOFOLLOW | linux::O_CLOEXEC)
            .open(&temp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        cancelled()?;
        fs::rename(&temp, path)?;
        Ok(())
    })();
    let _ = fs::remove_file(temp);
    result
}
pub type Config = BTreeMap<String, String>;
pub fn parse_config(text: &str, keys: &[&str]) -> Result<Config> {
    let mut values = Config::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| fail("invalid configuration line"))?;
        if !keys.contains(&key)
            || value.is_empty()
            || value.chars().any(char::is_control)
            || values.insert(key.into(), value.into()).is_some()
        {
            return Err(fail("invalid configuration field"));
        }
    }
    if values.len() != keys.len() {
        return Err(fail("incomplete configuration"));
    }
    Ok(values)
}
pub fn config(path: &Path, keys: &[&str]) -> Result<Config> {
    parse_config(std::str::from_utf8(&read_trusted(path, 16384)?)?, keys)
}
pub fn path_field<'a>(config: &'a Config, key: &str) -> Result<&'a Path> {
    let value = config.get(key).ok_or_else(|| fail("missing path"))?;
    let path = Path::new(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        || value.contains(',')
    {
        return Err(fail("invalid absolute path"));
    }
    Ok(path)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn config_rejects_unknown_duplicate_missing_and_control_fields() {
        assert!(parse_config("a=/path\nb=value\n", &["a", "b"]).is_ok());
        for s in [
            "a=x\na=y\n",
            "a=x\n",
            "a=x\nb=\n",
            "a=x\nb=y\nc=z\n",
            "a=x\nb=y\0\n",
        ] {
            assert!(parse_config(s, &["a", "b"]).is_err());
        }
        let c = parse_config("a=/safe,headless=yes", &["a"]).unwrap();
        assert!(path_field(&c, "a").is_err());
    }
}
