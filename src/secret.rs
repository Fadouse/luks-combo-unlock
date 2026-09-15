// SPDX-License-Identifier: GPL-3.0-only
use crate::{
    Result,
    common::{private_dir, unique},
    linux,
};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
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
            linux::mount(
                c"ramfs".as_ptr(),
                target.as_ptr(),
                c"ramfs".as_ptr(),
                linux::MS_NOSUID | linux::MS_NODEV | linux::MS_NOEXEC,
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
            if unsafe { linux::umount2(path.as_ptr(), 0) } != 0 {
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
        if unsafe { linux::mlock(bytes.as_ptr().cast(), bytes.len()) } != 0 {
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
            linux::munlock(self.bytes.as_ptr().cast(), self.bytes.len());
        }
    }
}
