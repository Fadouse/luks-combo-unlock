// SPDX-License-Identifier: GPL-3.0-only
use crate::{
    Result,
    common::{self, Config, path_field},
    crypto, disk, fail, fido, log, process,
    secret::{RamSecret, Secret},
    unlock,
};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::Duration,
};
struct Mapping<'a> {
    helper: &'a Path,
    owned: bool,
}
impl Mapping<'_> {
    fn close(&mut self) -> Result<()> {
        if self.owned {
            process::cleanup(self.helper, &["detach", unlock::CAPSULE_MAP])?;
            self.owned = false;
        }
        Ok(())
    }
}
impl Drop for Mapping<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.close() {
            log("ERROR", &format!("capsule cleanup: {e}"));
        }
    }
}
pub fn run(c: &Config) -> Result<()> {
    if c["manifest_hash"] != "enroll" {
        return Err(fail("enrollment requires a dedicated configuration"));
    }
    let state = path_field(c, "state_dir")?;
    common::private_dir(state)?;
    // Never overwrite an existing credential, capsule or keyslot.
    if state.join("manifest.bin").try_exists()? || state.join("tpm.luks").try_exists()? {
        return Err(fail("enrollment state already exists"));
    }
    let uuid = &c["root_uuid"];
    crate::manifest::validate_uuid(uuid)?;
    disk::check(&c["root_device"], uuid, true)?;
    if Path::new("/dev/mapper/fde-combo-v2").try_exists()? {
        return Err(fail("capsule mapping already exists"));
    }
    let device = fido::Device::open(&unlock::device(c)?)?;
    let pin = crate::pin::read()?;
    let manifest = device.enroll(uuid.clone(), &pin)?;
    let f = device.derive(&manifest, &pin)?;
    drop(pin);
    drop(device);
    let mut t = Secret::<32>::new()?;
    crypto::random(&mut t[..])?;
    let key = crypto::derive(&t[..], &f[..], &manifest.encode())?;
    drop(f);
    let mut capsule_key = Secret::<32>::new()?;
    crypto::random(&mut capsule_key[..])?;
    let mut ram = RamSecret::new()?;
    let capsule = state.join("tpm.luks");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&capsule)?;
    file.set_len(32 * 1024 * 1024)?;
    drop(file);
    let capsule_path = capsule.to_str().ok_or_else(|| fail("invalid state path"))?;
    let native = path_field(c, "cryptsetup_cli")?;
    log("TPM", "Creating the independent TPM secret capsule.");
    process::keyed(
        native,
        &[
            "luksFormat",
            "--type",
            "luks2",
            "--batch-mode",
            "--pbkdf",
            "pbkdf2",
            "--pbkdf-force-iterations",
            "1000",
            "--key-file",
            "/proc/self/fd/0",
            capsule_path,
        ],
        Duration::from_secs(30),
        ram.file(&capsule_key[..])?,
    )?;
    let helper = path_field(c, "cryptsetup")?;
    let mut mapping = Mapping {
        helper,
        owned: true,
    };
    process::keyed(
        helper,
        &[
            "attach",
            unlock::CAPSULE_MAP,
            capsule_path,
            "/proc/self/fd/0",
            "luks,headless=yes,password-cache=no",
        ],
        Duration::from_secs(30),
        ram.file(&capsule_key[..])?,
    )?;
    let mut target = OpenOptions::new()
        .write(true)
        .open("/dev/mapper/fde-combo-v2")?;
    target.write_all(&t[..])?;
    target.sync_all()?;
    drop(target);
    let t_hash = crypto::hash(&t[..]);
    drop(t);
    mapping.close()?;
    let pcrlock = format!("--tpm2-pcrlock={}", path_field(c, "pcrlock")?.display());
    process::keyed(
        path_field(c, "cryptenroll")?,
        &[
            "--unlock-key-file=/proc/self/fd/0",
            "--tpm2-device=auto",
            "--tpm2-pcrs=",
            "--tpm2-with-pin=no",
            &pcrlock,
            "--wipe-slot=all",
            capsule_path,
        ],
        Duration::from_secs(60),
        ram.file(&capsule_key[..])?,
    )?;
    drop(capsule_key);
    mapping.owned = true;
    process::run(
        helper,
        &[
            "attach",
            unlock::CAPSULE_MAP,
            capsule_path,
            "none",
            "luks,tpm2-device=auto,tpm2-pin=no,headless=yes,readonly,tries=1,password-cache=no,token-timeout=10s",
        ],
        Duration::from_secs(25),
    )?;
    let mut verified_t = Secret::<32>::new()?;
    use std::io::Read;
    fs::File::open("/dev/mapper/fde-combo-v2")?.read_exact(&mut verified_t[..])?;
    if crypto::hash(&verified_t[..]) != t_hash {
        return Err(crate::fail("TPM capsule verification failed"));
    }
    drop(verified_t);
    mapping.close()?;
    common::atomic_write(&state.join("manifest.bin"), &manifest.encode())?;
    log(
        "RECOVERY",
        "Enter an existing LUKS recovery key to authorize adding slot 2.",
    );
    let (recovery, length) = process::prompt::<1024>(
        path_field(c, "ask_password")?,
        "[LUKS] Existing recovery key:",
    )?;
    disk::add(&c["root_device"], uuid, &recovery[..length], &key[..])?;
    drop(recovery);
    drop(key);
    ram.cleanup()?;
    disk::check(&c["root_device"], uuid, false)?;
    log(
        "ENROLL",
        &format!("V2_ENROLLED: manifest_sha256={}", manifest.digest()),
    );
    log(
        "ENROLL",
        "Existing root keyslots remain unchanged; verify v2 before deploying.",
    );
    fs::File::open(state)?.sync_all()?;
    Ok(())
}
