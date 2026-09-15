// SPDX-License-Identifier: GPL-3.0-only
use crate::{
    Result,
    common::{private_dir, unique},
    linux,
};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Seek, Write},
    ops::{Deref, DerefMut},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    ptr::NonNull,
};

pub struct Secret<const N: usize>(NonNull<u8>);
impl<const N: usize> Secret<N> {
    pub fn new() -> Result<Self> {
        if N == 0 || N > 4096 {
            return Err(crate::fail("invalid secret allocation"));
        }
        // SAFETY: an anonymous page is exclusively owned until Drop. Separate pages
        // avoid overlapping mlock ranges that could be unlocked by another buffer.
        unsafe {
            let p = linux::mmap(std::ptr::null_mut(), 4096, 3, 0x22, -1, 0);
            if p as isize == -1 {
                return Err(std::io::Error::last_os_error().into());
            }
            if linux::mlock(p, 4096) != 0 || linux::madvise(p, 4096, 16) != 0 {
                let error = std::io::Error::last_os_error();
                linux::munmap(p, 4096);
                return Err(error.into());
            }
            Ok(Self(
                NonNull::new(p.cast()).ok_or_else(|| crate::fail("null mapping"))?,
            ))
        }
    }
}
impl<const N: usize> Deref for Secret<N> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.0.as_ptr(), N) }
    }
}
impl<const N: usize> DerefMut for Secret<N> {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.0.as_ptr(), N) }
    }
}
impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        // SAFETY: the whole mapping belongs to this instance; volatile writes precede unmapping.
        unsafe {
            for i in 0..4096 {
                self.0.as_ptr().add(i).write_volatile(0);
            }
            linux::munmap(self.0.as_ptr().cast(), 4096);
        }
    }
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
        // SAFETY: C strings live through mount; flags deny execution and device nodes.
        if unsafe {
            linux::mount(
                c"ramfs".as_ptr(),
                target.as_ptr(),
                c"ramfs".as_ptr(),
                linux::MS_NOSUID | linux::MS_NODEV | linux::MS_NOEXEC,
                c"mode=0700".as_ptr().cast(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        result.mounted = true;
        Ok(result)
    }
    pub fn file(&self, bytes: &[u8]) -> Result<File> {
        let path = self.directory.join("key");
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(linux::O_NOFOLLOW | linux::O_CLOEXEC)
            .open(&path)?;
        fs::remove_file(path)?;
        file.write_all(bytes)?;
        file.rewind()?;
        Ok(file)
    }
    pub fn cleanup(&mut self) -> Result<()> {
        if self.mounted {
            let path = CString::new(self.directory.as_os_str().as_encoded_bytes())?;
            // SAFETY: only this instance's mount is detached.
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
