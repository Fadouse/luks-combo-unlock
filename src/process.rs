// SPDX-License-Identifier: GPL-3.0-only
use crate::{Result, fail, log, secure::INTERRUPTED};
use std::{
    io::{ErrorKind, Read},
    os::fd::AsRawFd,
    path::Path,
    process::{Child, Command, Stdio},
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};
const OUTPUT_LIMIT: usize = 16 * 1024 * 1024;
const LINE_LIMIT: usize = 4096;

#[derive(Default)]
pub struct Formatter {
    pin_requested: bool,
    pending: Vec<u8>,
}
impl Formatter {
    pub fn line(&mut self, line: &str) -> Option<(&'static str, String)> {
        if line.contains("Security token requires PIN.") {
            self.pin_requested = true;
            Some(("PIN", "Enter your Security Key PIN and press Enter.".into()))
        } else if line.contains("Please confirm presence on security token to unlock.")
            || line.contains("Please confirm presence on security to unlock.")
        {
            self.pin_requested.then(|| {
                (
                    "TOUCH",
                    "Touch your Security Key when it flashes to finish unlocking.".into(),
                )
            })
        } else if line.is_empty() {
            None
        } else {
            Some(("AUTH", line.chars().filter(|c| !c.is_control()).collect()))
        }
    }
    fn flush(&mut self) {
        let text = String::from_utf8_lossy(&self.pending).into_owned();
        self.pending.clear();
        if let Some((stage, message)) = self.line(&text) {
            log(stage, &message);
        }
    }
    fn bytes(&mut self, bytes: &[u8]) {
        for byte in bytes {
            if *byte == b'\n' {
                self.flush();
            } else if self.pending.len() < LINE_LIMIT {
                self.pending.push(*byte);
            }
        }
    }
}
struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
fn nonblocking(pipe: &impl AsRawFd) -> Result<()> {
    // SAFETY: fd remains owned by the caller; fcntl only changes its status flags.
    unsafe {
        let flags = libc::fcntl(pipe.as_raw_fd(), libc::F_GETFL);
        if flags < 0 || libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}
fn drain(
    pipe: &mut impl Read,
    output: &mut Vec<u8>,
    formatter: &mut Option<Formatter>,
) -> Result<()> {
    let mut buffer = [0u8; 4096];
    for _ in 0..16 {
        match pipe.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                if let Some(f) = formatter {
                    f.bytes(&buffer[..n]);
                } else {
                    if output.len() + n > OUTPUT_LIMIT {
                        return Err(fail("helper output limit exceeded"));
                    }
                    output.extend_from_slice(&buffer[..n]);
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(()),
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// No shell, PATH lookup, PIN environment, process group change, or stdin pipe.
/// The original systemd password agent / controlling terminal collects the PIN.
pub fn run(program: &Path, args: &[&str], timeout: Duration, interactive: bool) -> Result<Vec<u8>> {
    run_inner(program, args, timeout, interactive, true)
}
pub fn cleanup(program: &Path, args: &[&str]) -> Result<Vec<u8>> {
    run_inner(program, args, Duration::from_secs(10), true, false)
}
fn run_inner(
    program: &Path,
    args: &[&str],
    timeout: Duration,
    interactive: bool,
    cancellable: bool,
) -> Result<Vec<u8>> {
    if !program.is_absolute() {
        return Err(fail("helper executable must be absolute"));
    }
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir("/")
        .env_clear()
        .env("LANG", "C.UTF-8")
        .env("SYSTEMD_LOG_TARGET", "console")
        .env("SYSTEMD_LOG_LEVEL", "notice")
        .env("SYSTEMD_LOG_COLOR", "0")
        .env("SYSTEMD_LOG_LOCATION", "0")
        .env("SYSTEMD_LOG_TIME", "0")
        .env("SYSTEMD_EMOJI", "0")
        .stdin(if interactive {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .stdout(if interactive {
            Stdio::inherit()
        } else {
            Stdio::piped()
        })
        .stderr(Stdio::piped());
    if let Ok(term) = std::env::var("TERM") {
        command.env("TERM", term);
    }
    let mut child = Running(command.spawn()?);
    let mut stderr = child
        .0
        .stderr
        .take()
        .ok_or_else(|| fail("missing diagnostic pipe"))?;
    nonblocking(&stderr)?;
    let mut stdout = child.0.stdout.take();
    if let Some(ref pipe) = stdout {
        nonblocking(pipe)?;
    }
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();
    let mut formatter = interactive.then(Formatter::default);
    let deadline = Instant::now() + timeout;
    loop {
        drain(&mut stderr, &mut diagnostics, &mut formatter)?;
        if let Some(ref mut pipe) = stdout {
            drain(pipe, &mut output, &mut None)?;
        }
        if let Some(status) = child.0.try_wait()? {
            drain(&mut stderr, &mut diagnostics, &mut formatter)?;
            if let Some(ref mut pipe) = stdout {
                drain(pipe, &mut output, &mut None)?;
            }
            if let Some(f) = &mut formatter {
                f.flush();
            }
            if status.success() {
                return Ok(output);
            }
            return Err(fail(format!(
                "{} exited with {status}",
                program.file_name().unwrap_or_default().to_string_lossy()
            )));
        }
        if cancellable && INTERRUPTED.load(Ordering::Relaxed) {
            return Err(fail("operation interrupted"));
        }
        if Instant::now() >= deadline {
            return Err(fail("helper deadline exceeded"));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pin_then_touch_without_claiming_pin_is_valid() {
        let mut f = Formatter::default();
        assert!(
            f.line("Please confirm presence on security token to unlock.")
                .is_none()
        );
        assert_eq!(f.line("Security token requires PIN.").unwrap().0, "PIN");
        assert_eq!(
            f.line("Please confirm presence on security token to unlock.")
                .unwrap()
                .0,
            "TOUCH"
        );
        assert_eq!(
            f.line("PIN of security token incorrect.").unwrap().0,
            "AUTH"
        );
    }
    #[test]
    fn reject_relative_helper() {
        assert!(run(Path::new("sh"), &[], Duration::from_millis(1), false).is_err());
    }
    #[test]
    #[ignore = "subprocess fixture"]
    fn helper_waits() {
        thread::sleep(Duration::from_secs(2));
    }
    #[test]
    fn deadline_kills_and_reaps_child() {
        let started = Instant::now();
        let result = run(
            &std::env::current_exe().unwrap(),
            &["--ignored", "--exact", "process::tests::helper_waits"],
            Duration::from_millis(40),
            false,
        );
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    }
    #[test]
    #[ignore = "subprocess fixture"]
    fn helper_reports_failure() {
        panic!("synthetic helper failure");
    }
    #[test]
    fn failure_is_not_reported_as_success() {
        assert!(
            run(
                &std::env::current_exe().unwrap(),
                &[
                    "--ignored",
                    "--exact",
                    "process::tests::helper_reports_failure"
                ],
                Duration::from_secs(2),
                false
            )
            .is_err()
        );
    }
    #[test]
    fn bounded_formatter() {
        let mut f = Formatter::default();
        f.bytes(&vec![b'x'; LINE_LIMIT * 2]);
        assert_eq!(f.pending.len(), LINE_LIMIT);
    }
}
