# luks-combo-unlock

Unlocks LUKS2 slot 2 with an independent TPM secret and a FIDO2 `hmac-secret` result. Each attempt verifies a fresh assertion against the enrolled public key, requiring PIN verification and touch. HKDF-SHA-256 binds both factors to the volume and credential. A measured configuration pins the enrollment manifest's SHA-256 digest.

```sh
nix build
luks-combo-unlock enroll CONFIG
luks-combo-unlock verify CONFIG
luks-combo-unlock unlock CONFIG
```

`enroll` creates `tpm.luks` and `manifest.bin` in a new state directory, verifies TPM unsealing, and requests an existing LUKS passphrase to add slot 2. Existing slots remain available. `verify` opens a disposable data device with the real header. `unlock` publishes a boot-bound v2 record after successful cleanup. Recovery is handled by the independent cryptroot service.

CONFIG contains `key=value` lines: `cryptsetup` (systemd-cryptsetup), `cryptsetup_cli`, `cryptenroll`, `ask_password`, `pcrlock`, `root_device`, `root_uuid`, `state_dir`, `hid_identity`, `manifest_hash`. Enrollment requires `manifest_hash=enroll`; unlock and verification require the printed digest.

NixOS: import `nixosModules.default`; configure `boot.initrd.luksComboUnlock.{enable,rootDevice,rootUuid,manifestHash}`. State is loaded from `/var/lib/fde-combo-v2`.

Linux x86-64. No external Rust crates. Uses Nix-pinned libfido2, OpenSSL and cryptsetup. GPL-3.0-only.
