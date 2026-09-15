// SPDX-License-Identifier: GPL-3.0-only
use crate::{Result, fail, field, log, path_field, process, secure};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::{Duration, Instant},
};
const PCRS: [u64; 4] = [0, 4, 7, 11];
const MARKER: &str = "/run/luks-session-guard/unlocked.json";
const USED: &str = "/run/luks-session-guard/autologin-used";

fn require(ok: bool, reason: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(fail(reason)) }
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn validate_pcrs(policy: &Value, eventlog: &Value) -> Result<()> {
    require(policy["pcrBank"] == "sha256", "PCR bank is not sha256")?;
    let entries = policy["pcrValues"]
        .as_array()
        .ok_or_else(|| fail("missing PCR policy values"))?;
    let mut allowed = BTreeMap::new();
    for entry in entries {
        let pcr = entry["pcr"]
            .as_u64()
            .ok_or_else(|| fail("invalid policy PCR index"))?;
        let values = entry["values"]
            .as_array()
            .ok_or_else(|| fail("missing policy digests"))?;
        let mut set = BTreeSet::new();
        for value in values {
            let value = value
                .as_str()
                .ok_or_else(|| fail("invalid policy digest"))?;
            require(
                digest(value) && set.insert(value),
                "invalid or repeated policy digest",
            )?;
        }
        require(
            !set.is_empty() && allowed.insert(pcr, set).is_none(),
            "empty or duplicate PCR policy entry",
        )?;
    }
    require(
        allowed.keys().copied().collect::<Vec<_>>() == PCRS,
        "policy must cover exactly PCR 0/4/7/11",
    )?;
    let states = eventlog["pcrs"]
        .as_array()
        .ok_or_else(|| fail("missing current PCR states"))?;
    let mut seen = BTreeSet::new();
    for state in states {
        let pcr = state["pcr"]
            .as_u64()
            .ok_or_else(|| fail("invalid current PCR index"))?;
        if !PCRS.contains(&pcr) {
            continue;
        }
        require(seen.insert(pcr), "duplicate current PCR entry")?;
        for field in [
            "hashMatchesEventLog",
            "allEventsMatched",
            "noMissingComponents",
        ] {
            require(
                state[field].as_bool() == Some(true),
                &format!("PCR {pcr}: {field} did not pass"),
            )?;
        }
        let observed = state["observedSHA256"]
            .as_str()
            .ok_or_else(|| fail("missing observed PCR digest"))?;
        require(
            digest(observed) && allowed[&pcr].contains(observed),
            &format!("PCR {pcr} is outside the authorized policy"),
        )?;
    }
    require(
        seen.into_iter().collect::<Vec<_>>() == PCRS,
        "incomplete current PCR states",
    )
}
fn validate_marker(marker: &Value, boot: &str, root: &str) -> Result<()> {
    require(
        marker["boot_id"] == boot && marker["device"] == root && marker["slot"].as_u64() == Some(1),
        "this boot was not unlocked through the expected TPM + Security Key slot",
    )
}
fn validate_unit(text: &str) -> Result<()> {
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| fail("invalid audit unit properties"))?;
        require(
            values.insert(key, value).is_none(),
            "duplicate audit unit property",
        )?;
    }
    for (key, expected) in [
        ("LoadState", "loaded"),
        ("Result", "success"),
        ("ExecMainCode", "1"),
        ("ExecMainStatus", "0"),
        ("ConditionResult", "yes"),
        ("AssertResult", "yes"),
    ] {
        require(
            values.get(key).copied() == Some(expected),
            &format!("kernel audit did not pass: {key}"),
        )?;
    }
    let start = values
        .get("ExecMainStartTimestampMonotonic")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let exit = values
        .get("ExecMainExitTimestampMonotonic")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    require(
        start > 0 && exit >= start,
        "kernel audit did not execute to completion in this boot",
    )
}
fn secure_boot() -> Result<()> {
    let root = Path::new("/sys/firmware/efi/efivars");
    for (name, expected) in [("SecureBoot", 1u8), ("SetupMode", 0u8)] {
        let bytes = fs::read(root.join(format!("{name}-8be4df61-93ca-11d2-aa0d-00e098032b8c")))?;
        require(
            bytes.len() == 5 && bytes[4] == expected,
            "UEFI Secure Boot is not enforcing",
        )?;
    }
    Ok(())
}
fn kernel_state() -> Result<()> {
    let lockdown = fs::read_to_string("/sys/kernel/security/lockdown")?;
    require(
        lockdown.contains("[integrity]") || lockdown.contains("[confidentiality]"),
        "kernel lockdown is not enforcing",
    )?;
    require(
        fs::read_to_string("/sys/module/module/parameters/sig_enforce")?.trim() == "Y",
        "module signatures are not enforced",
    )?;
    require(
        fs::read_to_string("/proc/sys/kernel/kexec_load_disabled")?.trim() == "1",
        "legacy kexec is permitted",
    )?;
    let taint: u64 = fs::read_to_string("/proc/sys/kernel/tainted")?
        .trim()
        .parse()?;
    // This host uses signed out-of-tree GPU modules (bit 12). All other taints deny autologin.
    require(taint & !(1 << 12) == 0, "unexpected kernel taint")
}
fn check(config: &Value) -> Result<()> {
    let start = Instant::now();
    require(
        !Path::new(USED).exists(),
        "automatic login has already been granted this boot",
    )?;
    let marker: Value = serde_json::from_slice(&secure::read_trusted(Path::new(MARKER), 4096)?)?;
    validate_marker(&marker, &secure::boot_id()?, field(config, "root_device")?)?;
    secure_boot()?;
    kernel_state()?;
    let unit = String::from_utf8(process::run(
        path_field(config, "systemctl")?,
        &[
            "show",
            "kernel-integrity-audit.service",
            "--property=LoadState,Result,ExecMainCode,ExecMainStatus,ConditionResult,AssertResult,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic",
        ],
        Duration::from_secs(5),
        false,
    )?)?;
    validate_unit(&unit)?;
    let policy_path = path_field(config, "pcr_policy")?;
    let before = secure::read_trusted(policy_path, 1024 * 1024)?;
    let policy: Value = serde_json::from_slice(&before)?;
    let mut args = vec![
        "log".to_owned(),
        "--json=short".into(),
        "--location=770".into(),
    ];
    for pcr in PCRS {
        args.push(format!("--pcr={pcr}"));
    }
    let components = config["pcr_components"]
        .as_array()
        .ok_or_else(|| fail("missing PCR components"))?;
    require(!components.is_empty(), "no PCR components configured")?;
    for component in components {
        let component = component
            .as_str()
            .ok_or_else(|| fail("invalid PCR component path"))?;
        require(
            Path::new(component).is_absolute(),
            "PCR component path must be absolute",
        )?;
        args.push(format!("--components={component}"));
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let eventlog: Value = serde_json::from_slice(&process::run(
        path_field(config, "pcrlock")?,
        &refs,
        Duration::from_secs(20),
        false,
    )?)?;
    validate_pcrs(&policy, &eventlog)?;
    require(
        secure::read_trusted(policy_path, 1024 * 1024)? == before,
        "PCR policy changed during the login check",
    )?;
    kernel_state()?;
    require(
        !secure::INTERRUPTED.load(std::sync::atomic::Ordering::Relaxed)
            && start.elapsed() < Duration::from_secs(30),
        "login check interrupted or exceeded its deadline",
    )?;
    Ok(())
}

/// The unit installs the manual configuration before invoking this command.
/// Only a completely successful check can atomically replace it with autologin.
pub fn write_config(config: &Value, output: &Path) -> Result<()> {
    let manual = secure::read_trusted(path_field(config, "manual_config")?, 65536)?;
    secure::atomic_write(output, &manual)?;
    match check(config) {
        Ok(()) => {
            let auto = secure::read_trusted(path_field(config, "autologin_config")?, 65536)?;
            secure::private_dir(Path::new("/run/luks-session-guard"))?;
            // Consume once, before publishing the automatic configuration. A write failure fails closed.
            let mut used = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(USED)?;
            used.write_all(secure::boot_id()?.as_bytes())?;
            used.sync_all()?;
            secure::atomic_write(output, &auto)?;
            log(
                "LOGIN",
                "All configured boot checks passed; automatic Niri login permitted.",
            );
        }
        Err(error) => log(
            "LOGIN",
            &format!("Automatic login denied: {error}. Use the password login prompt."),
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> (Value, Value) {
        let hash = "a".repeat(64);
        (
            json!({"pcrBank":"sha256","pcrValues":PCRS.map(|p| json!({"pcr":p,"values":[hash]}))}),
            json!({"pcrs":PCRS.map(|p| json!({"pcr":p,"observedSHA256":hash,"hashMatchesEventLog":true,"allEventsMatched":true,"noMissingComponents":true}))}),
        )
    }
    #[test]
    fn every_required_pcr_and_check_must_pass() {
        let (policy, eventlog) = fixture();
        assert!(validate_pcrs(&policy, &eventlog).is_ok());
        for index in 0..4 {
            for field in [
                "hashMatchesEventLog",
                "allEventsMatched",
                "noMissingComponents",
            ] {
                let mut bad = eventlog.clone();
                bad["pcrs"][index][field] = json!(false);
                assert!(validate_pcrs(&policy, &bad).is_err());
                bad["pcrs"][index].as_object_mut().unwrap().remove(field);
                assert!(validate_pcrs(&policy, &bad).is_err());
            }
            let mut bad = eventlog.clone();
            bad["pcrs"][index]["observedSHA256"] = json!("b".repeat(64));
            assert!(validate_pcrs(&policy, &bad).is_err());
        }
    }
    #[test]
    fn reject_incomplete_duplicate_or_wrong_bank_policy() {
        let (policy, log) = fixture();
        let mut bad = policy.clone();
        bad["pcrValues"].as_array_mut().unwrap().pop();
        assert!(validate_pcrs(&bad, &log).is_err());
        let mut bad = policy.clone();
        bad["pcrValues"][1] = bad["pcrValues"][0].clone();
        assert!(validate_pcrs(&bad, &log).is_err());
        let mut bad = policy;
        bad["pcrBank"] = json!("sha1");
        assert!(validate_pcrs(&bad, &log).is_err());
        let (policy, mut bad) = fixture();
        bad["pcrs"][1] = bad["pcrs"][0].clone();
        assert!(validate_pcrs(&policy, &bad).is_err());
    }
    #[test]
    fn recovery_and_stale_boot_cannot_authorize_login() {
        let good = json!({"boot_id":"this-boot","device":"/dev/root","slot":1});
        assert!(validate_marker(&good, "this-boot", "/dev/root").is_ok());
        assert!(validate_marker(&good, "other-boot", "/dev/root").is_err());
        assert!(validate_marker(&good, "this-boot", "/dev/other").is_err());
        let mut recovery = good;
        recovery["slot"] = json!(3);
        assert!(validate_marker(&recovery, "this-boot", "/dev/root").is_err());
    }
    #[test]
    fn success_without_executed_audit_is_not_success() {
        let good = "LoadState=loaded\nResult=success\nExecMainCode=1\nExecMainStatus=0\nConditionResult=yes\nAssertResult=yes\nExecMainStartTimestampMonotonic=20\nExecMainExitTimestampMonotonic=30\n";
        assert!(validate_unit(good).is_ok());
        for (a, b) in [
            ("Monotonic=20", "Monotonic=0"),
            ("ConditionResult=yes", "ConditionResult=no"),
            ("Status=0", "Status=1"),
            ("Code=1", "Code=0"),
            ("Monotonic=30", "Monotonic=10"),
        ] {
            assert!(validate_unit(&good.replace(a, b)).is_err());
        }
        assert!(validate_unit("Result=success\n").is_err());
    }
}
