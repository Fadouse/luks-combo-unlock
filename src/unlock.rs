// SPDX-License-Identifier: GPL-3.0-only
use crate::{Result, fail, field, log, path_field, process, secure};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    os::unix::fs::{FileTypeExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};
const CAPSULE_MAP: &str = "fde-combo-salt";
const VERIFY_MAP: &str = "cryptroot-combo-check";
const MARKER: &str = "/run/luks-session-guard/unlocked.json";

pub fn valid_cid(cid: &str) -> bool {
    !cid.is_empty()
        && cid.len() <= 4096
        && cid.len() % 4 == 0
        && cid
            .trim_end_matches('=')
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
        && cid.len() - cid.trim_end_matches('=').len() <= 2
}
fn device(config: &Value) -> Result<PathBuf> {
    let identity = field(config, "hid_identity")?;
    let deadline = Instant::now() + Duration::from_secs(30);
    log("USB", "Waiting up to 30 seconds for your Security Key.");
    loop {
        let mut found = Vec::new();
        let entries = match fs::read_dir("/sys/class/hidraw") {
            Ok(entries) => Some(entries),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        for entry in entries.into_iter().flatten() {
            let entry = entry?;
            let uevent = fs::read_to_string(entry.path().join("device/uevent"));
            if uevent.is_ok_and(|text| text.lines().any(|line| line == identity)) {
                let node = Path::new("/dev").join(entry.file_name());
                if fs::metadata(&node).is_ok_and(|m| m.file_type().is_char_device()) {
                    found.push(node);
                }
            }
        }
        if found.len() > 1 {
            return Err(fail(
                "multiple matching Security Keys; connect only the enrolled key",
            ));
        }
        if let Some(node) = found.pop() {
            log("USB", "Security Key detected.");
            return Ok(node);
        }
        if secure::INTERRUPTED.load(Ordering::Relaxed) {
            return Err(fail("device wait interrupted"));
        }
        if Instant::now() >= deadline {
            return Err(fail("Security Key did not appear within 30 seconds"));
        }
        thread::sleep(Duration::from_millis(200));
    }
}
struct Resources<'a> {
    cryptsetup: &'a Path,
    capsule_owned: bool,
    verify_owned: bool,
    scratch: Option<PathBuf>,
    secret: Option<secure::RamSecret>,
}
impl Resources<'_> {
    fn detach(&self, name: &str) -> Result<()> {
        process::cleanup(self.cryptsetup, &["detach", name])?;
        Ok(())
    }
    fn cleanup(&mut self) -> Result<()> {
        // Each resource is ours: preexisting mappings are rejected before ownership is set.
        let mut errors = Vec::new();
        if self.capsule_owned {
            match self.detach(CAPSULE_MAP) {
                Ok(()) => self.capsule_owned = false,
                Err(e) => errors.push(e.to_string()),
            }
        }
        if self.verify_owned {
            match self.detach(VERIFY_MAP) {
                Ok(()) => self.verify_owned = false,
                Err(e) => errors.push(e.to_string()),
            }
        }
        if let Some(secret) = &mut self.secret {
            if let Err(e) = secret.cleanup() {
                errors.push(e.to_string());
            }
        }
        if let Some(scratch) = &self.scratch {
            match fs::remove_file(scratch) {
                Ok(()) => self.scratch = None,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => self.scratch = None,
                Err(e) => errors.push(e.to_string()),
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(fail(errors.join("; ")))
        }
    }
}
impl Drop for Resources<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.cleanup() {
            log("ERROR", &format!("resource cleanup: {e}"));
        }
    }
}

pub fn run(config: &Value, verify: bool) -> Result<()> {
    let cryptsetup = path_field(config, "cryptsetup")?;
    let root = field(config, "root_device")?;
    path_field(config, "root_device")?;
    let state = path_field(config, "state_dir")?;
    secure::private_dir(Path::new("/run/luks-session-guard"))?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/run/luks-session-guard/operation.lock")?;
    use std::os::fd::AsRawFd;
    // SAFETY: the owned fd remains open for the whole unlock/verify operation.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(fail("another combination operation is running"));
    }
    if !verify {
        match fs::remove_file(MARKER) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    let mapping = if verify { VERIFY_MAP } else { "cryptroot" };
    for name in [mapping, CAPSULE_MAP] {
        if Path::new("/dev/mapper").join(name).exists() {
            return Err(fail("refusing preexisting mapping"));
        }
    }
    let slot = String::from_utf8(secure::read_trusted(&state.join("keyslot"), 32)?)?;
    if slot.trim() != "1" {
        return Err(fail("combination must use the configured root slot 1"));
    }
    let cid = String::from_utf8(secure::read_trusted(&state.join("credential-id"), 4096)?)?;
    if !valid_cid(cid.trim()) {
        return Err(fail("invalid credential ID"));
    }
    let key = device(config).map_err(|e| fail(format!("stage=wait-for-security-key: {e}")))?;
    let capsule = state.join("salt.luks");
    // Verify capsule ownership/mode without copying its encrypted contents into memory.
    secure::trusted_parent(&capsule)?;
    let m = fs::symlink_metadata(&capsule)?;
    use std::os::unix::fs::MetadataExt;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err(fail("untrusted capsule"));
    }
    let mut resources = Resources {
        cryptsetup,
        capsule_owned: false,
        verify_owned: false,
        scratch: None,
        secret: None,
    };
    log("TPM", "Checking the measured boot policy.");
    resources.capsule_owned = true;
    process::run(
        cryptsetup,
        &[
            "attach",
            CAPSULE_MAP,
            capsule
                .to_str()
                .ok_or_else(|| fail("invalid capsule path"))?,
            "none",
            "luks,tpm2-device=auto,tpm2-pin=no,headless=yes,readonly,tries=1,password-cache=no,token-timeout=10s",
        ],
        Duration::from_secs(25),
        true,
    ).map_err(|e| fail(format!("stage=tpm-policy: {e}")))?;
    resources.secret = Some(secure::RamSecret::new()?);
    let salt = resources
        .secret
        .as_ref()
        .unwrap()
        .load(Path::new("/dev/mapper/fde-combo-salt"))?;
    resources.detach(CAPSULE_MAP)?;
    resources.capsule_owned = false;
    let data_path = if verify {
        let scratch = secure::unique(Path::new("/run"), "luks-check-")?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&scratch)?
            .set_len(32 * 1024 * 1024)?;
        resources.scratch = Some(scratch.clone());
        scratch
    } else {
        PathBuf::from(root)
    };
    let mut options = if verify {
        format!("luks,readonly,header={root}")
    } else {
        "luks,discard".into()
    };
    options.push_str(&format!(",fido2-device={},fido2-pin=yes,fido2-up=yes,fido2-cid={},key-slot=1,tries=1,password-cache=no,timeout={}",
        key.display(), cid.trim(), if verify { "10min" } else { "90s" }));
    log(
        "AUTH",
        "Enter the Security Key PIN when prompted, then touch the key when it flashes.",
    );
    resources.verify_owned = verify;
    process::run(
        cryptsetup,
        &[
            "attach",
            mapping,
            data_path
                .to_str()
                .ok_or_else(|| fail("invalid data path"))?,
            salt.to_str().ok_or_else(|| fail("invalid salt path"))?,
            &options,
        ],
        Duration::from_secs(if verify { 610 } else { 100 }),
        true,
    )?;
    resources.cleanup()?;
    if verify {
        log(
            "CHECK",
            "COMBO_VERIFY_SUCCESS: TPM + Security Key PIN + touch verified.",
        );
    } else {
        let marker = json!({"boot_id": secure::boot_id()?, "slot": 1, "device": root});
        secure::atomic_write(Path::new(MARKER), &serde_json::to_vec(&marker)?)?;
        log("DONE", "COMBO_UNLOCK_SUCCESS: root volume unlocked.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credential_input_is_bounded_and_not_an_option_string() {
        for bad in ["", "AAAA,discard", "AA=A", "====", "AA\nA", "A"] {
            assert!(!valid_cid(bad), "{bad}");
        }
        assert!(valid_cid("AQIDBA=="));
        assert!(!valid_cid(&"A".repeat(4100)));
    }
}
