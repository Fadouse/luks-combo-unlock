# Security

Requires trusted enrollment, host software, TPM policy and measured configuration. Assertions bind a fresh challenge, RP, user verification, touch and the encrypted extension to the pinned credential key. The independent TPM secret and final LUKS key never enter USB messages. Capturing a FIDO result alone does not reveal the final key.

CTAP does not authenticate its USB key exchange. This program does not prevent FIDO-result or PIN-related leakage, live relay, denial of service, host compromise or physical key extraction. Recovery and older keyslots retain their own security properties.

Process memory is locked and core dumps disabled. Owned secret buffers are erased; helper keys use anonymous ramfs descriptors. PINs are masked, are not cached by this program, and are not retried automatically. Failure does not publish success. Interrupted enrollment can leave encrypted state or an added slot for inspection. SIGKILL and kernel failures can prevent cleanup.
