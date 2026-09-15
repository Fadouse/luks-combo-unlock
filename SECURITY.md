# Security boundary

This program is a privileged orchestrator, not a replacement for the kernel, firmware, systemd, libcryptsetup, libfido2 or TPM libraries. Rust removes shell parsing and several process dependencies; it does not establish that all remaining code is trusted.

Autologin requires all configured checks to pass. Missing data, malformed JSON, unknown audit state, a recovery boot, interrupted checks or policy changes deny autologin. Root can change configuration and state; a compromised kernel or root account can falsify local checks. Use of a recovery password on an untrusted boot does not make that boot trustworthy.

Only PCR 0, 4, 7 and 11 are covered. IMA measurement is not IMA appraisal. Signed code may contain vulnerabilities. The gate runs before login; it is not a continuous runtime integrity monitor. It checks security state, not every unrelated application or peripheral warning. Signed out-of-tree GPU modules may set taint bit 12; other taints deny autologin.

The program never formats LUKS volumes, enrolls keys, deletes slots or reads a PIN. The 32-byte FIDO2 input is copied through locked, explicitly erased memory to private ramfs. Recovery and normal data volumes are not mounted by verification. Temporary mappings are closed on ordinary failures, timeout and catchable termination signals. SIGKILL, kernel failures and uninterruptible kernel I/O cannot be reliably cleaned up by any userspace destructor.

Unsafe Rust is confined to Linux syscalls with documented lifetimes: process hardening, signal handlers, nonblocking pipes, ramfs mounts and secret-memory locking/erasure. Dependency versions and checksums are locked. There is no network functionality.

For review, pay particular attention to initrd library closure, terminal PIN behavior, clean failure cleanup, current PCR event-log semantics, and the manual greetd configuration surviving a failed checker. Do not enable automatic login without verifying these on the target host.
