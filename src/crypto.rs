// SPDX-License-Identifier: GPL-3.0-only
use crate::{Result, fail, secret::Secret};
use std::{
    ffi::{c_int, c_void},
    ptr,
};

#[link(name = "crypto")]
unsafe extern "C" {
    fn SHA256(data: *const u8, len: usize, out: *mut u8) -> *mut u8;
    fn RAND_bytes(out: *mut u8, len: c_int) -> c_int;
    fn EVP_sha256() -> *const c_void;
    fn EVP_PKEY_CTX_new_id(id: c_int, engine: *mut c_void) -> *mut c_void;
    fn EVP_PKEY_CTX_free(ctx: *mut c_void);
    fn EVP_PKEY_derive_init(ctx: *mut c_void) -> c_int;
    fn EVP_PKEY_CTX_set_hkdf_md(ctx: *mut c_void, md: *const c_void) -> c_int;
    fn EVP_PKEY_CTX_set1_hkdf_salt(ctx: *mut c_void, salt: *const u8, len: c_int) -> c_int;
    fn EVP_PKEY_CTX_set1_hkdf_key(ctx: *mut c_void, key: *const u8, len: c_int) -> c_int;
    fn EVP_PKEY_CTX_add1_hkdf_info(ctx: *mut c_void, info: *const u8, len: c_int) -> c_int;
    fn EVP_PKEY_derive(ctx: *mut c_void, out: *mut u8, len: *mut usize) -> c_int;
}
pub fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    // SAFETY: both slices are valid for the supplied lengths; SHA256 writes 32 bytes.
    unsafe {
        SHA256(bytes.as_ptr(), bytes.len(), out.as_mut_ptr());
    }
    out
}
pub fn random(out: &mut [u8]) -> Result<()> {
    let len = c_int::try_from(out.len())?;
    // SAFETY: writable output is valid for len bytes.
    if unsafe { RAND_bytes(out.as_mut_ptr(), len) } != 1 {
        return Err(fail("random generation failed"));
    }
    Ok(())
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn derive(t: &[u8], f: &[u8], context: &[u8]) -> Result<Secret<32>> {
    if t.len() != 32 || f.len() != 32 {
        return Err(fail("invalid factor length"));
    }
    let mut ikm = Secret::<64>::new()?;
    ikm[..32].copy_from_slice(t);
    ikm[32..].copy_from_slice(f);
    hkdf(&ikm[..], &hash(context), b"luks-combo-unlock/v2")
}
fn hkdf<const N: usize>(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<Secret<N>> {
    struct Context(*mut c_void);
    impl Drop for Context {
        fn drop(&mut self) {
            unsafe {
                EVP_PKEY_CTX_free(self.0);
            }
        }
    }
    let mut out = Secret::<N>::new()?;
    // SAFETY: HKDF's OpenSSL identifier is 1036. All pointers are borrowed for each
    // call; OpenSSL copies inputs. The context is freed on every return path.
    unsafe {
        let ctx = Context(EVP_PKEY_CTX_new_id(1036, ptr::null_mut()));
        if ctx.0.is_null() {
            return Err(fail("HKDF allocation failed"));
        }
        let mut len = N;
        if EVP_PKEY_derive_init(ctx.0) <= 0
            || EVP_PKEY_CTX_set_hkdf_md(ctx.0, EVP_sha256()) <= 0
            || EVP_PKEY_CTX_set1_hkdf_salt(ctx.0, salt.as_ptr(), salt.len().try_into()?) <= 0
            || EVP_PKEY_CTX_set1_hkdf_key(ctx.0, ikm.as_ptr(), ikm.len().try_into()?) <= 0
            || EVP_PKEY_CTX_add1_hkdf_info(ctx.0, info.as_ptr(), info.len().try_into()?) <= 0
            || EVP_PKEY_derive(ctx.0, out.as_mut_ptr(), &mut len) <= 0
            || len != N
        {
            return Err(fail("HKDF failed"));
        }
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc5869_case_one() {
        let out = hkdf::<42>(
            &[0x0b; 22],
            &(0..13).collect::<Vec<_>>(),
            &(0xf0..=0xf9).collect::<Vec<_>>(),
        )
        .unwrap();
        assert_eq!(
            hex(&out[..]),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }
    #[test]
    fn both_factors_and_volume_are_bound() {
        let k = derive(&[1; 32], &[2; 32], b"volume1").unwrap();
        for other in [
            derive(&[3; 32], &[2; 32], b"volume1"),
            derive(&[1; 32], &[3; 32], b"volume1"),
            derive(&[1; 32], &[2; 32], b"volume2"),
        ] {
            assert_ne!(&k[..], &other.unwrap()[..]);
        }
    }
}
