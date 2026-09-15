# luks-session-guard

Linux-only Rust orchestration for TPM + FIDO2 LUKS unlock and conditional Niri autologin. GPL-3.0-only.

## Scope

- Replaces the shell unlock helper: device discovery, bounded subprocess execution, unswappable salt storage, cleanup and `[LUKS]` prompts.
- Calls an absolute `systemd-cryptsetup` path directly. TPM/FIDO2 cryptography and PIN entry remain in systemd and its libraries; no shell, PATH lookup, PIN argument, PIN environment variable or PIN capture.
- Normal unlock uses root slot 1; an independent cryptroot service provides recovery slot 3.
- `login-config` permits autologin once per boot only after the current Rust unlock marker, enforcing Secure Boot, kernel integrity audit and PCR 0/4/7/11 policy checks all pass. Otherwise the manual login configuration remains.

## Build

```sh
nix build
nix develop --command cargo test --locked
```

## Commands

```text
luks-session-guard unlock CONFIG.json
luks-session-guard verify CONFIG.json
luks-session-guard login-config CONFIG.json OUTPUT.toml
```

Run as root through reviewed systemd units. Configuration files must be root-owned and not writable by other users. `verify` uses the real header with disposable data, without mounting data or changing keyslots.

Unlock configuration: absolute `cryptsetup`, `root_device`, `state_dir`; `hid_identity` matching the enrolled USB model. The state directory contains `salt.luks`, `credential-id` and `keyslot`.

Login configuration: `root_device`, absolute `systemctl`, `pcrlock`, `pcr_policy`, `manual_config`, `autologin_config`, and an array of absolute `pcr_components` directories. The service must install the manual TOML first, wait for `kernel-integrity-audit.service`, and disable greetd restart. Only the checker can atomically replace the manual configuration with the reviewed automatic one.

## Review status

This is an audit candidate, not a claim of hardware or reboot verification. Unit tests cover policy rejection, stale markers, skipped audits, subprocess deadlines, error propagation and prompt sequencing. Hardware verification and boot tests are required before deploying the integration.

Changing the success marker intentionally prevents the old shell helper from authorizing the new autologin path. The existing LUKS capsule and keyslots are reused; do not enroll or erase anything during migration.

See [SECURITY.md](SECURITY.md) for the trust boundary.
