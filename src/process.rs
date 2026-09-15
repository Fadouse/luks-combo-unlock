// SPDX-License-Identifier: GPL-3.0-only
use crate::{Result, common, fail, linux, log};
use std::{
    io::{ErrorKind, Read},
    os::fd::AsRawFd,
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
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
pub fn run(program: &Path, args: &[&str], timeout: Duration) -> Result<()> {
    run_inner(program, args, timeout, true, None)
}
pub fn cleanup(program: &Path, args: &[&str]) -> Result<()> {
    run_inner(program, args, Duration::from_secs(10), false, None)
}
pub fn keyed(program: &Path, args: &[&str], timeout: Duration, input: std::fs::File) -> Result<()> {
    run_inner(program, args, timeout, true, Some(input))
}
fn run_inner(
    program: &Path,
    args: &[&str],
    timeout: Duration,
    cancellable: bool,
    input: Option<std::fs::File>,
) -> Result<()> {
    if !program.is_absolute() {
        return Err(fail("helper executable must be absolute"));
    }
    if cancellable {
        common::cancelled()?;
    }
    // Keep stdin and the foreground process group for systemd's native PIN prompt.
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
        .stdin(input.map_or_else(Stdio::inherit, Stdio::from))
        .stdout(Stdio::inherit())
        .stderr(Stdio::piped());
    // systemd hides global credentials in a service's mount namespace. Forward
    // only its explicitly loaded PCR credential directory to the native helper.
    if let Some(directory) = std::env::var_os("CREDENTIALS_DIRECTORY") {
        if !Path::new(&directory).is_absolute() {
            return Err(fail("credential directory must be absolute"));
        }
        command.env("SYSTEMD_ENCRYPTED_SYSTEM_CREDENTIALS_DIRECTORY", directory);
    }
    if let Ok(term) = std::env::var("TERM") {
        command.env("TERM", term);
    }
    let mut child = Running(command.spawn()?);
    let mut stderr = child
        .0
        .stderr
        .take()
        .ok_or_else(|| fail("missing stderr"))?;
    // SAFETY: the owned pipe remains valid for these fcntl calls.
    unsafe {
        let flags = linux::fcntl(stderr.as_raw_fd(), linux::F_GETFL);
        if flags < 0
            || linux::fcntl(
                stderr.as_raw_fd(),
                linux::F_SETFL,
                flags | linux::O_NONBLOCK,
            ) < 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    let mut formatter = Formatter::default();
    let deadline = Instant::now() + timeout;
    loop {
        if cancellable {
            common::cancelled()?;
        }
        if Instant::now() >= deadline {
            return Err(fail("helper deadline exceeded"));
        }
        let mut eof = false;
        let mut buf = [0; 4096];
        for _ in 0..16 {
            match stderr.read(&mut buf) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(n) => formatter.bytes(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => (),
                Err(e) => return Err(e.into()),
            }
        }
        if cancellable {
            common::cancelled()?;
        }
        if let Some(status) = child.0.try_wait()? {
            if !status.success() {
                formatter.flush();
                return Err(fail(format!("helper failed: {status}")));
            }
            if eof {
                formatter.flush();
                return Ok(());
            }
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
        assert!(run(Path::new("sh"), &[], Duration::from_millis(1)).is_err());
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
            )
            .is_err()
        );
    }
    #[test]
    fn credential_directory_reaches_helper() {
        let result = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "process::tests::forward_credentials",
            ])
            .env("CREDENTIALS_DIRECTORY", "/run/credentials/test.service")
            .env("SYSTEMD_ENCRYPTED_SYSTEM_CREDENTIALS_DIRECTORY", "/wrong")
            .output()
            .unwrap();
        assert!(result.status.success(), "{:?}", result);
    }
    #[test]
    #[ignore = "subprocess fixture"]
    fn forward_credentials() {
        run(
            &std::env::current_exe().unwrap(),
            &["--ignored", "--exact", "process::tests::check_credentials"],
            Duration::from_secs(2),
        )
        .unwrap();
    }
    #[test]
    #[ignore = "subprocess fixture"]
    fn check_credentials() {
        assert_eq!(
            std::env::var("SYSTEMD_ENCRYPTED_SYSTEM_CREDENTIALS_DIRECTORY").unwrap(),
            "/run/credentials/test.service"
        );
        assert!(std::env::var_os("CREDENTIALS_DIRECTORY").is_none());
    }
    #[test]
    fn bounded_formatter() {
        let mut f = Formatter::default();
        f.bytes(&vec![b'x'; LINE_LIMIT * 2]);
        assert_eq!(f.pending.len(), LINE_LIMIT);
    }
}

// Only systemd-ask-password's bounded stdout is read into locked memory.
pub fn prompt<const N: usize>(
    program: &Path,
    message: &str,
) -> Result<(crate::secret::Secret<N>, usize)> {
    common::cancelled()?;
    let mut child = Running(
        Command::new(program)
            .args(["--timeout=90s", "--echo=masked", message])
            .env_clear()
            .env("LANG", "C.UTF-8")
            .env("TERM", "linux")
            .stdin(Stdio::inherit())
            .stderr(Stdio::inherit())
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let mut pipe = child
        .0
        .stdout
        .take()
        .ok_or_else(|| fail("missing PIN pipe"))?;
    unsafe {
        let flags = linux::fcntl(pipe.as_raw_fd(), linux::F_GETFL);
        if flags < 0
            || linux::fcntl(pipe.as_raw_fd(), linux::F_SETFL, flags | linux::O_NONBLOCK) < 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    let mut pin = crate::secret::Secret::<N>::new()?;
    let mut used = 0;
    let mut ended = false;
    let deadline = Instant::now() + Duration::from_secs(95);
    loop {
        common::cancelled()?;
        if Instant::now() >= deadline {
            return Err(fail("PIN prompt timed out"));
        }
        if !ended {
            match pipe.read(&mut pin[used..used + 1]) {
                Ok(0) => return Err(fail("PIN prompt closed")),
                Ok(_) if pin[used] == b'\n' => {
                    pin[used] = 0;
                    ended = true;
                }
                Ok(_) if used == N - 1 || pin[used] == 0 => {
                    return Err(fail("invalid PIN length or encoding"));
                }
                Ok(_) => used += 1,
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => (),
                Err(e) => return Err(e.into()),
            }
        }
        if ended {
            if let Some(status) = child.0.try_wait()? {
                if !status.success() || used == 0 {
                    return Err(fail("PIN prompt failed"));
                }
                std::str::from_utf8(&pin[..used]).map_err(|_| fail("PIN is not UTF-8"))?;
                return Ok((pin, used));
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
}
