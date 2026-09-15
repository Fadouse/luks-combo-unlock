// SPDX-License-Identifier: GPL-3.0-only
mod gate;
mod process;
mod secure;
mod unlock;

use serde_json::Value;
use std::{env, path::Path, process::ExitCode};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn fail(message: impl Into<String>) -> Box<dyn std::error::Error> {
    std::io::Error::other(message.into()).into()
}
fn log(stage: &str, message: &str) {
    println!("[LUKS] {stage:<8} {message}");
}
fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| fail(format!("missing configuration field: {key}")))
}
fn path_field<'a>(value: &'a Value, key: &str) -> Result<&'a Path> {
    let p = Path::new(field(value, key)?);
    if !p.is_absolute()
        || p.components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(fail(format!(
            "{key} must be an absolute path without parent traversal"
        )));
    }
    Ok(p)
}
fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() == 2 && args[1] == "--version" {
        println!("luks-session-guard {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if args.len() < 3 || !matches!(args[1].as_str(), "unlock" | "verify" | "login-config") {
        eprintln!(
            "usage: luks-session-guard unlock|verify CONFIG\n       luks-session-guard login-config CONFIG OUTPUT"
        );
        return ExitCode::from(2);
    }
    let result = (|| -> Result<()> {
        secure::harden()?;
        let config: Value =
            serde_json::from_slice(&secure::read_trusted(Path::new(&args[2]), 65536)?)?;
        match args[1].as_str() {
            "unlock" | "verify" if args.len() == 3 => unlock::run(&config, args[1] == "verify"),
            "login-config" if args.len() == 4 => gate::write_config(&config, Path::new(&args[3])),
            _ => Err(fail("invalid arguments")),
        }
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            log("ERROR", &error.to_string());
            if args[1] == "unlock" {
                log(
                    "RECOVERY",
                    "COMBO_UNLOCK_FAILED: enter your LUKS recovery key at the next prompt.",
                );
            }
            // The independent cryptroot recovery service is ordered after this unit.
            // A failed attempt never creates an autologin authorization marker.
            ExitCode::FAILURE
        }
    }
}
