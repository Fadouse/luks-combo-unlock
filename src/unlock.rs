// SPDX-License-Identifier: GPL-3.0-only
use crate::{
    Result,
    common::{self as secure, Config, path_field},
    fail, linux, log, process, secret,
};
use std::{
    fs::{self, OpenOptions},
    os::unix::fs::{FileTypeExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};
pub const CAPSULE_MAP: &str = "fde-combo-v2";
const VERIFY_MAP: &str = "cryptroot-combo-check";
const MARKER: &str = "/run/luks-combo-unlock/unlocked";

pub fn device(config: &Config) -> Result<PathBuf> {
    let identity = &config["hid_identity"];
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
    secret: Option<secret::RamSecret>,
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

pub fn run(config: &Config, verify: bool) -> Result<()> {
    let cryptsetup = path_field(config, "cryptsetup")?;
    let root = config["root_device"].as_str();
    path_field(config, "root_device")?;
    let state = path_field(config, "state_dir")?;
    secure::private_dir(Path::new("/run/luks-combo-unlock"))?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(linux::O_NOFOLLOW | linux::O_CLOEXEC)
        .open("/run/luks-combo-unlock/operation.lock")?;
    use std::os::fd::AsRawFd;
    // SAFETY: the owned fd remains open for the whole unlock/verify operation.
    if unsafe { linux::flock(lock.as_raw_fd(), linux::LOCK_EX | linux::LOCK_NB) } != 0 {
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
    let data = secure::read_trusted(&state.join("manifest.bin"), 2048)?;
    if crate::crypto::hex(&crate::crypto::hash(&data)) != config["manifest_hash"] {
        return Err(fail("manifest does not match the measured configuration"));
    }
    let manifest = crate::manifest::Manifest::decode(&data)?;
    if manifest.uuid != config["root_uuid"] {
        return Err(fail("configured root UUID mismatch"));
    }
    crate::disk::check(root, &manifest.uuid, false)?;
    let key = device(config).map_err(|e| fail(format!("stage=wait-for-security-key: {e}")))?;
    let capsule = state.join("tpm.luks");
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
    ).map_err(|e| fail(format!("stage=tpm-policy: {e}")))?;
    resources.secret = Some(secret::RamSecret::new()?);
    let device = crate::fido::Device::open(&key)?;
    let pin = process::pin(path_field(config, "ask_password")?)?;
    let f = device.derive(&manifest, &pin)?;
    drop(pin);
    drop(device);
    let mut t = secret::Secret::<32>::new()?;
    use std::io::Read;
    std::fs::File::open("/dev/mapper/fde-combo-v2")?.read_exact(&mut t[..])?;
    resources.detach(CAPSULE_MAP)?;
    resources.capsule_owned = false;
    let final_key = crate::crypto::derive(&t[..], &f[..], &manifest.encode())?;
    drop(t);
    drop(f);
    let data_path = if verify {
        let scratch = secure::unique(Path::new("/run"), "luks-check-")?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&scratch)?;
        resources.scratch = Some(scratch.clone());
        file.set_len(32 * 1024 * 1024)?;
        scratch
    } else {
        PathBuf::from(root)
    };
    let mut options = if verify {
        format!("luks,readonly,header={root}")
    } else {
        "luks,discard".into()
    };
    options.push_str(",key-slot=2,headless=yes,tries=1,password-cache=no");
    resources.verify_owned = verify;
    let input = resources.secret.as_ref().unwrap().file(&final_key[..])?;
    drop(final_key);
    process::keyed(
        cryptsetup,
        &[
            "attach",
            mapping,
            data_path
                .to_str()
                .ok_or_else(|| fail("invalid data path"))?,
            "/proc/self/fd/0",
            &options,
        ],
        Duration::from_secs(30),
        input,
    )?;
    secure::cancelled()?;
    resources.cleanup()?;
    if verify {
        log(
            "CHECK",
            "COMBO_VERIFY_SUCCESS: TPM + Security Key PIN + touch verified.",
        );
    } else {
        let marker = format!("LUKS-COMBO-2\n{}\n{}\n2\n", secure::boot_id()?, root);
        secure::atomic_write(Path::new(MARKER), marker.as_bytes())?;
        log("DONE", "COMBO_UNLOCK_SUCCESS: root volume unlocked.");
    }
    Ok(())
}
