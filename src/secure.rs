// SPDX-License-Identifier: GPL-3.0-only
use crate::{Result, fail};
use std::{
    ffi::CString,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

pub static INTERRUPTED: AtomicBool = AtomicBool::new(false);
extern "C" fn interrupted(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::Relaxed);
}

pub fn harden() -> Result<()> {
    // SAFETY: scalar process-local syscalls; no borrowed pointers outlive a call.
    unsafe {
        if libc::geteuid() != 0 {
            return Err(fail("root is required"));
        }
        libc::umask(0o077);
        let limits = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &limits) != 0
            || libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = interrupted as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
    }
    Ok(())
}
pub fn boot_id() -> Result<String> {
    Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned())
}

pub fn trusted_parent(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(fail("absolute path required"));
    }
    // A root-owned sticky store directory cannot have its root-owned entries replaced by other users.
    for parent in path.ancestors().skip(1) {
        let m = fs::symlink_metadata(parent)?;
        if !m.is_dir() || m.uid() != 0 || (m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0) {
            return Err(fail("untrusted parent directory"));
        }
    }
    Ok(())
}
pub fn read_trusted(path: &Path, limit: u64) -> Result<Vec<u8>> {
    // Nix store configuration paths may have symlinked parents. Resolve them,
    // then verify the complete canonical parent chain, ownership and mode.
    let path = fs::canonicalize(path)?;
    trusted_parent(&path)?;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 || m.len() > limit {
        return Err(fail("untrusted or oversized file"));
    }
    let mut data = Vec::new();
    (&mut f).take(limit + 1).read_to_end(&mut data)?;
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
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&temp, path)?;
        Ok(())
    })();
    if temp.exists() {
        let _ = fs::remove_file(temp);
    }
    result
}

pub struct RamSecret {
    pub directory: PathBuf,
    mounted: bool,
}
impl RamSecret {
    pub fn new() -> Result<Self> {
        let path = unique(Path::new("/run"), "luks-secret-")?;
        private_dir(&path)?;
        let mut result = Self {
            directory: path,
            mounted: false,
        };
        let target = CString::new(result.directory.as_os_str().as_encoded_bytes())?;
        // SAFETY: all C strings remain alive during mount; flags disallow execution and device nodes.
        let status = unsafe {
            libc::mount(
                c"ramfs".as_ptr(),
                target.as_ptr(),
                c"ramfs".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                c"mode=0700".as_ptr().cast(),
            )
        };
        if status != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        result.mounted = true;
        Ok(result)
    }
    pub fn load(&self, source: &Path) -> Result<PathBuf> {
        let mut secret = LockedSecret::new()?;
        File::open(source)?.read_exact(secret.bytes.as_mut_slice())?;
        let path = self.directory.join("salt");
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(&path)?;
        f.write_all(secret.bytes.as_slice())?;
        Ok(path)
    }
    pub fn cleanup(&mut self) -> Result<()> {
        let salt = self.directory.join("salt");
        if salt.exists() {
            fs::remove_file(salt)?;
        }
        if self.mounted {
            let path = CString::new(self.directory.as_os_str().as_encoded_bytes())?;
            // SAFETY: path is a valid C string for this instance's private mount.
            if unsafe { libc::umount2(path.as_ptr(), 0) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            self.mounted = false;
        }
        if self.directory.exists() {
            fs::remove_dir(&self.directory)?;
        }
        Ok(())
    }
}
impl Drop for RamSecret {
    fn drop(&mut self) {
        if let Err(e) = self.cleanup() {
            crate::log("ERROR", &format!("secret cleanup: {e}"));
        }
    }
}
struct LockedSecret {
    bytes: Box<[u8; 32]>,
}
impl LockedSecret {
    fn new() -> Result<Self> {
        let bytes = Box::new([0u8; 32]);
        // SAFETY: the Box has a stable address and remains allocated until munlock in Drop.
        if unsafe { libc::mlock(bytes.as_ptr().cast(), bytes.len()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self { bytes })
    }
}
impl Drop for LockedSecret {
    fn drop(&mut self) {
        // SAFETY: each pointer addresses an initialized byte in our exclusive allocation.
        unsafe {
            for byte in self.bytes.iter_mut() {
                std::ptr::write_volatile(byte, 0);
            }
            libc::munlock(self.bytes.as_ptr().cast(), self.bytes.len());
        }
    }
}
