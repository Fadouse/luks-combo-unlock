# Security

Runs as root with trusted configuration and absolute helper paths. systemd collects the PIN and performs cryptographic operations. Salt uses locked, erased memory and private ramfs. Failures trigger cleanup and do not publish success. SIGKILL and kernel failures can prevent cleanup. Existing LUKS keyslots are unchanged.
