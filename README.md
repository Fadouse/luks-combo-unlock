# luks-combo-unlock

TPM unseals a 32-byte salt; systemd uses FIDO2 PIN and touch to unlock LUKS slot 1. `verify` uses a disposable data device with the real header. Successful unlock writes a boot-bound result to `/run/luks-combo-unlock/unlocked`.

```sh
nix build
luks-combo-unlock unlock CONFIG
luks-combo-unlock verify CONFIG
```

CONFIG contains one `key=value` per line: `cryptsetup`, `root_device`, `state_dir`, `hid_identity`. State files: `salt.luks`, `credential-id`, `keyslot`.

NixOS: import `nixosModules.default`; set `boot.initrd.luksComboUnlock.enable` and `rootDevice`. The independent cryptroot service handles recovery.

Linux x86-64, Rust standard library, no external crates. Nix inputs are pinned by revision and NAR hash. GPL-3.0-only.
