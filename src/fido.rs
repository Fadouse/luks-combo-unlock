// SPDX-License-Identifier: GPL-3.0-only
use crate::{Result, common, fail, log, manifest::Manifest, secret::Secret};
use std::{
    ffi::{CString, c_char, c_int, c_void},
    path::Path,
    ptr::{self, NonNull},
};
const RP: &std::ffi::CStr = c"luks-combo-unlock";
const ES256: c_int = -7;
const TRUE: c_int = 2;
macro_rules! opaque { ($($name:ident),*) => { $(#[repr(C)] struct $name { _opaque: [u8;0] })* }; }
opaque!(Dev, Assert, Cred, PublicKey);
#[link(name = "fido2")]
unsafe extern "C" {
    fn fido_init(flags: c_int);
    fn fido_dev_new() -> *mut Dev;
    fn fido_dev_free(p: *mut *mut Dev);
    fn fido_dev_open(p: *mut Dev, path: *const c_char) -> c_int;
    fn fido_dev_close(p: *mut Dev) -> c_int;
    fn fido_dev_set_timeout(p: *mut Dev, milliseconds: c_int) -> c_int;
    fn fido_dev_get_assert(dev: *mut Dev, a: *mut Assert, pin: *const c_char) -> c_int;
    fn fido_dev_make_cred(dev: *mut Dev, c: *mut Cred, pin: *const c_char) -> c_int;
    fn fido_assert_new() -> *mut Assert;
    fn fido_assert_free(p: *mut *mut Assert);
    fn fido_assert_set_rp(p: *mut Assert, rp: *const c_char) -> c_int;
    fn fido_assert_set_up(p: *mut Assert, option: c_int) -> c_int;
    fn fido_assert_set_uv(p: *mut Assert, option: c_int) -> c_int;
    fn fido_assert_set_extensions(p: *mut Assert, flags: c_int) -> c_int;
    fn fido_assert_set_clientdata_hash(p: *mut Assert, bytes: *const u8, len: usize) -> c_int;
    fn fido_assert_set_hmac_salt(p: *mut Assert, bytes: *const u8, len: usize) -> c_int;
    fn fido_assert_allow_cred(p: *mut Assert, bytes: *const u8, len: usize) -> c_int;
    fn fido_assert_count(p: *const Assert) -> usize;
    fn fido_assert_id_ptr(p: *const Assert, idx: usize) -> *const u8;
    fn fido_assert_id_len(p: *const Assert, idx: usize) -> usize;
    fn fido_assert_hmac_secret_ptr(p: *const Assert, idx: usize) -> *const u8;
    fn fido_assert_hmac_secret_len(p: *const Assert, idx: usize) -> usize;
    fn fido_assert_authdata_raw_len(p: *const Assert, idx: usize) -> usize;
    fn fido_assert_verify(p: *const Assert, idx: usize, alg: c_int, pk: *const c_void) -> c_int;
    fn es256_pk_new() -> *mut PublicKey;
    fn es256_pk_free(p: *mut *mut PublicKey);
    fn es256_pk_from_ptr(p: *mut PublicKey, data: *const c_void, len: usize) -> c_int;
    fn fido_cred_new() -> *mut Cred;
    fn fido_cred_free(p: *mut *mut Cred);
    fn fido_cred_set_type(p: *mut Cred, alg: c_int) -> c_int;
    fn fido_cred_set_rp(p: *mut Cred, id: *const c_char, name: *const c_char) -> c_int;
    fn fido_cred_set_user(
        p: *mut Cred,
        id: *const u8,
        len: usize,
        name: *const c_char,
        display: *const c_char,
        icon: *const c_char,
    ) -> c_int;
    fn fido_cred_set_rk(p: *mut Cred, option: c_int) -> c_int;
    fn fido_cred_set_prot(p: *mut Cred, protection: c_int) -> c_int;
    fn fido_cred_set_extensions(p: *mut Cred, flags: c_int) -> c_int;
    fn fido_cred_set_clientdata_hash(p: *mut Cred, hash: *const u8, len: usize) -> c_int;
    fn fido_cred_verify(p: *const Cred) -> c_int;
    fn fido_cred_verify_self(p: *const Cred) -> c_int;
    fn fido_cred_x5c_len(p: *const Cred) -> usize;
    fn fido_cred_prot(p: *const Cred) -> c_int;
    fn fido_cred_id_ptr(p: *const Cred) -> *const u8;
    fn fido_cred_id_len(p: *const Cred) -> usize;
    fn fido_cred_pubkey_ptr(p: *const Cred) -> *const u8;
    fn fido_cred_pubkey_len(p: *const Cred) -> usize;
}
fn check(status: c_int) -> Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(fail(format!(
            "FIDO operation failed ({status}); no automatic PIN retry"
        )))
    }
}
struct Owned<T> {
    p: NonNull<T>,
    free: unsafe extern "C" fn(*mut *mut T),
}
impl<T> Owned<T> {
    fn new(p: *mut T, free: unsafe extern "C" fn(*mut *mut T)) -> Result<Self> {
        Ok(Self {
            p: NonNull::new(p).ok_or_else(|| fail("FIDO allocation failed"))?,
            free,
        })
    }
    fn p(&self) -> *mut T {
        self.p.as_ptr()
    }
}
impl<T> Drop for Owned<T> {
    fn drop(&mut self) {
        unsafe {
            (self.free)(&mut self.p.as_ptr());
        }
    }
}
pub struct Device(Owned<Dev>);
impl Drop for Device {
    fn drop(&mut self) {
        unsafe {
            fido_dev_close(self.0.p());
        }
    }
}
impl Device {
    pub fn open(path: &Path) -> Result<Self> {
        let path = CString::new(path.as_os_str().as_encoded_bytes())?;
        // SAFETY: owned opaque objects come from libfido2; all input pointers live
        // through synchronous calls. No FIDO debug logging or U2F fallback.
        unsafe {
            fido_init(2);
            let d = Owned::new(fido_dev_new(), fido_dev_free)?;
            check(fido_dev_set_timeout(d.p(), 90_000))?;
            check(fido_dev_open(d.p(), path.as_ptr()))?;
            Ok(Self(d))
        }
    }
    pub fn enroll(&self, uuid: String, pin: &Secret<64>) -> Result<Manifest> {
        let mut salt = [0; 32];
        crate::crypto::random(&mut salt)?;
        let mut challenge = [0; 32];
        crate::crypto::random(&mut challenge)?;
        // SAFETY: setters copy inputs; credential remains alive through verification
        // and bounded copies. Enrollment requires a trusted physical connection.
        unsafe {
            let c = Owned::new(fido_cred_new(), fido_cred_free)?;
            check(fido_cred_set_type(c.p(), ES256))?;
            check(fido_cred_set_rp(c.p(), RP.as_ptr(), RP.as_ptr()))?;
            check(fido_cred_set_user(
                c.p(),
                salt.as_ptr(),
                salt.len(),
                c"luks".as_ptr(),
                c"LUKS".as_ptr(),
                ptr::null(),
            ))?;
            check(fido_cred_set_rk(c.p(), 1))?;
            check(fido_cred_set_prot(c.p(), 3))?;
            check(fido_cred_set_extensions(c.p(), 1))?;
            check(fido_cred_set_clientdata_hash(
                c.p(),
                challenge.as_ptr(),
                challenge.len(),
            ))?;
            log(
                "TOUCH",
                "Touch your Security Key when it flashes to register the credential.",
            );
            check(fido_dev_make_cred(self.0.p(), c.p(), pin.as_ptr().cast()))?;
            common::cancelled()?;
            if fido_cred_x5c_len(c.p()) == 0 {
                check(fido_cred_verify_self(c.p()))?;
            } else {
                check(fido_cred_verify(c.p()))?;
            }
            if fido_cred_prot(c.p()) != 3 || fido_cred_pubkey_len(c.p()) != 64 {
                return Err(fail("credential policy or public key mismatch"));
            }
            let cid = bounded(fido_cred_id_ptr(c.p()), fido_cred_id_len(c.p()), 1024)?.to_vec();
            let public_key = bounded(fido_cred_pubkey_ptr(c.p()), 64, 64)?.try_into()?;
            Ok(Manifest {
                uuid,
                salt,
                public_key,
                cid,
            })
        }
    }
    pub fn derive(&self, manifest: &Manifest, pin: &Secret<64>) -> Result<Secret<32>> {
        let challenge = manifest.challenge()?;
        let mut result = Secret::<32>::new()?;
        unsafe {
            let a = request(manifest, &challenge)?;
            log(
                "TOUCH",
                "Touch your Security Key when it flashes to finish authentication.",
            );
            check(fido_dev_get_assert(self.0.p(), a.p(), pin.as_ptr().cast()))?;
            common::cancelled()?;
            if fido_assert_count(a.p()) != 1
                || bounded(
                    fido_assert_id_ptr(a.p(), 0),
                    fido_assert_id_len(a.p(), 0),
                    1024,
                )? != manifest.cid
                || fido_assert_hmac_secret_len(a.p(), 0) != 32
                || fido_assert_authdata_raw_len(a.p(), 0) > 4096
            {
                return Err(fail("unexpected FIDO response"));
            }
            verify(&a, &manifest.public_key)?;
            // This buffer is produced by libfido2 from the verified assertion's
            // encrypted extension in this same session, never from another request.
            result.copy_from_slice(bounded(fido_assert_hmac_secret_ptr(a.p(), 0), 32, 32)?);
        }
        log(
            "VERIFY",
            "Security Key signature, challenge, PIN verification and touch verified.",
        );
        Ok(result)
    }
}
// SAFETY: only call with a libfido2-owned buffer whose reported length is valid.
unsafe fn bounded<'a>(p: *const u8, len: usize, max: usize) -> Result<&'a [u8]> {
    if p.is_null() || len == 0 || len > max {
        return Err(fail("invalid FIDO buffer"));
    }
    Ok(unsafe { std::slice::from_raw_parts(p, len) })
}
fn request(m: &Manifest, challenge: &[u8; 32]) -> Result<Owned<Assert>> {
    unsafe {
        let a = Owned::new(fido_assert_new(), fido_assert_free)?;
        check(fido_assert_set_rp(a.p(), RP.as_ptr()))?;
        check(fido_assert_set_up(a.p(), TRUE))?;
        check(fido_assert_set_uv(a.p(), TRUE))?;
        check(fido_assert_set_extensions(a.p(), 1))?;
        check(fido_assert_set_clientdata_hash(
            a.p(),
            challenge.as_ptr(),
            32,
        ))?;
        check(fido_assert_set_hmac_salt(a.p(), m.salt.as_ptr(), 32))?;
        check(fido_assert_allow_cred(a.p(), m.cid.as_ptr(), m.cid.len()))?;
        Ok(a)
    }
}
fn verify(a: &Owned<Assert>, bytes: &[u8; 64]) -> Result<()> {
    unsafe {
        let pk = Owned::new(es256_pk_new(), es256_pk_free)?;
        check(es256_pk_from_ptr(
            pk.p(),
            bytes.as_ptr().cast(),
            bytes.len(),
        ))?;
        fido_assert_verify(a.p(), 0, ES256, pk.p().cast())
            .eq(&0)
            .then_some(())
            .ok_or_else(|| fail("Security Key assertion verification failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PK: &str = "dbf391698620d36ea14e4e9d8b06a9f4fdf5e885b591a93664b5a665e4749abad9b60a95bfd48187258fa93a9d538e27b86fdc9b4ab7144b09a6ea7a18237b1c";
    const GOOD: (&str, &str) = (
        "2d107e260a792862712b725f6a8f4cf1f45327aef69b35ae5938eca96e4ebf898500000001a16b686d61632d73656372657458205555555555555555555555555555555555555555555555555555555555555555",
        "3045022100995a5223323a997186f13ee0b7ebe8cf95f7e97f687f96d847d2d0edfe446e430220172f53bc82c996532257d515b1b1580975e58929cefd86105be9d6c3d126e6c4",
    );
    const NO_UV: (&str, &str) = (
        "2d107e260a792862712b725f6a8f4cf1f45327aef69b35ae5938eca96e4ebf898100000001a16b686d61632d73656372657458205555555555555555555555555555555555555555555555555555555555555555",
        "30440220627e602e20137fb2a6c09cddb9147d82e34e284a7d2a5545cce77884010f4e1602204d123e94761749bf5d03e71b849180adb3829465625bbf398ae6771cb7d657e5",
    );
    const NO_UP: (&str, &str) = (
        "2d107e260a792862712b725f6a8f4cf1f45327aef69b35ae5938eca96e4ebf898400000001a16b686d61632d73656372657458205555555555555555555555555555555555555555555555555555555555555555",
        "3044022069c6f0728c7662e8dca0721ad7c36140f0cfa70852c3bccda0930d3499e78e2a02200bf2ae05bcf6eaff71077ee78e9dfb31220a71eae385c7ea3792bd0281bf7271",
    );
    #[link(name = "fido2")]
    unsafe extern "C" {
        fn fido_assert_set_count(a: *mut Assert, n: usize) -> c_int;
        fn fido_assert_set_authdata_raw(
            a: *mut Assert,
            idx: usize,
            bytes: *const u8,
            len: usize,
        ) -> c_int;
        fn fido_assert_set_sig(a: *mut Assert, idx: usize, bytes: *const u8, len: usize) -> c_int;
    }
    fn bytes(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }
    fn fixture(pair: (&str, &str), challenge: [u8; 32]) -> (Owned<Assert>, Manifest) {
        let m = Manifest {
            uuid: "12345678-1234-4234-8234-123456789abc".into(),
            salt: [0; 32],
            public_key: bytes(PK).try_into().unwrap(),
            cid: vec![1; 64],
        };
        let a = request(&m, &challenge).unwrap();
        let auth = bytes(pair.0);
        let sig = bytes(pair.1);
        unsafe {
            check(fido_assert_set_count(a.p(), 1)).unwrap();
            check(fido_assert_set_authdata_raw(
                a.p(),
                0,
                auth.as_ptr(),
                auth.len(),
            ))
            .unwrap();
            check(fido_assert_set_sig(a.p(), 0, sig.as_ptr(), sig.len())).unwrap();
        }
        (a, m)
    }
    #[test]
    fn signed_assertion_accepts_only_expected_challenge_and_key() {
        let (a, m) = fixture(GOOD, [0x11; 32]);
        verify(&a, &m.public_key).unwrap();
        let (old, m) = fixture(GOOD, [0x12; 32]);
        assert!(verify(&old, &m.public_key).is_err());
        let mut wrong = m.public_key;
        wrong[0] ^= 1;
        assert!(verify(&a, &wrong).is_err());
        unsafe {
            check(fido_assert_set_rp(a.p(), c"other-rp".as_ptr())).unwrap();
        }
        assert!(verify(&a, &m.public_key).is_err());
    }
    #[test]
    fn signed_missing_presence_or_verification_is_rejected() {
        for pair in [NO_UV, NO_UP] {
            let (a, m) = fixture(pair, [0x11; 32]);
            assert!(verify(&a, &m.public_key).is_err());
        }
    }
    #[test]
    fn changing_encrypted_secret_breaks_signature() {
        let (a, m) = fixture(GOOD, [0x11; 32]);
        let mut auth = bytes(GOOD.0);
        *auth.last_mut().unwrap() ^= 1;
        unsafe {
            check(fido_assert_set_authdata_raw(
                a.p(),
                0,
                auth.as_ptr(),
                auth.len(),
            ))
            .unwrap();
        }
        assert!(verify(&a, &m.public_key).is_err());
    }
}
