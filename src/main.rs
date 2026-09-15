// SPDX-License-Identifier: GPL-3.0-only
mod common;
mod linux;
mod process;
mod secret;
mod unlock;
use std::{env, path::Path, process::ExitCode};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn fail(s: impl Into<String>) -> Box<dyn std::error::Error> {
    std::io::Error::other(s.into()).into()
}
fn log(stage: &str, message: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stdout(), "[LUKS] {stage:<8} {message}");
}
fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() == 2 && args[1] == "--version" {
        println!("luks-combo-unlock {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if args.len() != 3 || !matches!(args[1].as_str(), "unlock" | "verify") {
        eprintln!("usage: luks-combo-unlock unlock|verify CONFIG");
        return ExitCode::from(2);
    }
    let result = (|| -> Result<()> {
        common::harden()?;
        let config = common::config(
            Path::new(&args[2]),
            &["cryptsetup", "root_device", "state_dir", "hid_identity"],
        )?;
        unlock::run(&config, args[1] == "verify")
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log("ERROR", &e.to_string());
            if args[1] == "unlock" {
                log(
                    "RECOVERY",
                    "COMBO_UNLOCK_FAILED: enter your LUKS recovery key at the next prompt.",
                );
            }
            ExitCode::FAILURE
        }
    }
}
