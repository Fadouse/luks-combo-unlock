// SPDX-License-Identifier: GPL-3.0-only
use crate::{Result, fail};
use std::ffi::{CStr, CString, c_char, c_int, c_void};
#[link(name = "cryptsetup")]
unsafe extern "C" {
    fn crypt_init(cd: *mut *mut c_void, device: *const c_char) -> c_int;
    fn crypt_load(cd: *mut c_void, kind: *const c_char, params: *mut c_void) -> c_int;
    fn crypt_get_uuid(cd: *mut c_void) -> *const c_char;
    fn crypt_keyslot_status(cd: *mut c_void, slot: c_int) -> c_int;
    fn crypt_free(cd: *mut c_void);
    fn crypt_keyslot_add_by_passphrase(
        cd: *mut c_void,
        slot: c_int,
        pass: *const c_char,
        pass_len: usize,
        key: *const c_char,
        key_len: usize,
    ) -> c_int;
}
pub fn check(device: &str, uuid: &str, enrolling: bool) -> Result<()> {
    struct Disk(*mut c_void);
    impl Drop for Disk {
        fn drop(&mut self) {
            unsafe {
                crypt_free(self.0);
            }
        }
    }
    let path = CString::new(device)?;
    unsafe {
        let mut d = Disk(std::ptr::null_mut());
        if crypt_init(&mut d.0, path.as_ptr()) < 0
            || crypt_load(d.0, c"LUKS2".as_ptr(), std::ptr::null_mut()) < 0
        {
            return Err(fail("cannot read LUKS2 header"));
        }
        let id = crypt_get_uuid(d.0);
        if id.is_null() || CStr::from_ptr(id).to_bytes() != uuid.as_bytes() {
            return Err(fail("LUKS UUID mismatch"));
        }
        let state = crypt_keyslot_status(d.0, 4);
        if if enrolling {
            state != 1
        } else {
            ![2, 3].contains(&state)
        } {
            return Err(fail("unexpected combination keyslot state"));
        }
    }
    Ok(())
}

pub fn add(device: &str, uuid: &str, existing: &[u8], key: &[u8]) -> Result<()> {
    check(device, uuid, true)?;
    let path = CString::new(device)?;
    unsafe {
        let mut cd = std::ptr::null_mut();
        if crypt_init(&mut cd, path.as_ptr()) < 0 {
            return Err(fail("cannot open LUKS2 device"));
        }
        let result = if crypt_load(cd, c"LUKS2".as_ptr(), std::ptr::null_mut()) < 0 {
            -1
        } else {
            crypt_keyslot_add_by_passphrase(
                cd,
                4,
                existing.as_ptr().cast(),
                existing.len(),
                key.as_ptr().cast(),
                key.len(),
            )
        };
        crypt_free(cd);
        if result != 4 {
            return Err(fail(
                "adding root slot 4 failed; existing slots were not requested for removal",
            ));
        }
    }
    Ok(())
}
