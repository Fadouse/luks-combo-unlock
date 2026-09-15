// SPDX-License-Identifier: GPL-3.0-only
use crate::{Result, common, crypto, fail, secret::Secret};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::fd::AsRawFd,
    os::unix::fs::OpenOptionsExt,
    time::{Duration, Instant},
};

// Linux x86-64 glibc termios ABI; the crate rejects other targets.
#[repr(C)]
#[derive(Clone, Copy)]
struct Termios {
    input: u32,
    output: u32,
    control: u32,
    local: u32,
    line: u8,
    chars: [u8; 32],
    input_speed: u32,
    output_speed: u32,
}
#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}
unsafe extern "C" {
    fn tcgetattr(fd: i32, value: *mut Termios) -> i32;
    fn tcsetattr(fd: i32, action: i32, value: *const Termios) -> i32;
    fn cfmakeraw(value: *mut Termios);
    fn tcgetpgrp(fd: i32) -> i32;
    fn getpgrp() -> i32;
    fn poll(fds: *mut PollFd, count: usize, timeout: i32) -> i32;
}
struct Terminal {
    file: File,
    saved: Termios,
    active: bool,
}
impl Terminal {
    fn open() -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(crate::linux::O_CLOEXEC | crate::linux::O_NONBLOCK)
            .open("/dev/tty")?;
        let fd = file.as_raw_fd();
        let mut saved = std::mem::MaybeUninit::<Termios>::uninit();
        // SAFETY: tcgetattr initializes the ABI-sized structure on success. Only
        // the foreground controlling terminal is used; no stdin/journal fallback.
        unsafe {
            if tcgetpgrp(fd) != getpgrp() || tcgetattr(fd, saved.as_mut_ptr()) != 0 {
                return Err(fail("PIN requires a foreground controlling terminal"));
            }
            let saved = saved.assume_init();
            let mut raw = saved;
            cfmakeraw(&mut raw);
            if tcsetattr(fd, 2, &raw) != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let mut tty = Self {
                file,
                saved,
                active: true,
            };
            tty.file
                .write_all(b"\x1b[?1049h\x1b[2J\x1b[H\x1b[?25l\x1b[?2004h")?;
            Ok(tty)
        }
    }
    fn restore(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        let output = self
            .file
            .write_all(b"\x1b[2J\x1b[H\x1b[?2004l\x1b[?25h\x1b[?1049l");
        // SAFETY: saved describes this same still-open terminal. TCSAFLUSH also
        // discards queued input before the recovery prompt or subsequent programs.
        if unsafe { tcsetattr(self.file.as_raw_fd(), 2, &self.saved) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        self.active = false;
        output?;
        Ok(())
    }
    fn render(&mut self, entry: &Entry) -> Result<()> {
        let mut keys = String::new();
        for digit in [1, 2, 3, 4, 5, 6, 7, 8, 9, 0] {
            keys.push(char::from(b'0' + entry.map[digit]));
            keys.push_str("  ");
        }
        // Mapping and masked length are written only to /dev/tty, never log().
        write!(
            self.file,
            "\x1b[H[LUKS] Security Key PIN\x1b[K\r\n\r\nFind each PIN digit, then press the key below it.\x1b[K\r\nThe mapping changes after every digit.\x1b[K\r\n\r\nPIN digit:  1  2  3  4  5  6  7  8  9  0\x1b[K\r\nPress key:  {keys}\x1b[K\r\n\r\nEntered: {}\x1b[K\r\n\r\nEnter: submit   Backspace: erase   Ctrl-U: clear   Esc: cancel\x1b[K\r\n",
            "*".repeat(entry.used)
        )?;
        self.file.flush()?;
        Ok(())
    }
}
impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}
struct Entry {
    pin: Secret<64>,
    used: usize,
    map: [u8; 10],
}
impl Entry {
    fn new() -> Result<Self> {
        Ok(Self {
            pin: Secret::new()?,
            used: 0,
            map: permutation()?,
        })
    }
    fn input(&mut self, byte: u8) -> Result<bool> {
        match byte {
            b'0'..=b'9' => {
                if self.used == 63 {
                    return Err(fail("PIN is too long"));
                }
                let digit = self
                    .map
                    .iter()
                    .position(|key| *key == byte - b'0')
                    .ok_or_else(|| fail("invalid PIN mapping"))?;
                self.pin[self.used] = b'0' + digit as u8;
                self.used += 1;
            }
            8 | 127 => {
                if self.used > 0 {
                    self.used -= 1;
                    self.pin[self.used] = 0;
                }
            }
            21 => {
                self.pin.fill(0);
                self.used = 0;
            }
            b'\r' | b'\n' => {
                if self.used < 4 {
                    return Err(fail("PIN must contain at least four digits"));
                }
                return Ok(true);
            }
            3 | 4 | 27 => return Err(fail("PIN entry cancelled")),
            _ => return Err(fail("PIN mapping accepts single ASCII digit keys only")),
        }
        self.map = permutation()?;
        Ok(false)
    }
}
fn permutation() -> Result<[u8; 10]> {
    let mut map = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    for i in (1..10).rev() {
        let bound = (i + 1) as u16;
        let limit = 256 - 256 % bound;
        let j = loop {
            let mut sample = [0];
            crypto::random(&mut sample)?;
            if u16::from(sample[0]) < limit {
                break usize::from(sample[0]) % (i + 1);
            }
        };
        map.swap(i, j);
    }
    Ok(map)
}
pub fn read() -> Result<Secret<64>> {
    read_with_timeout(Duration::from_secs(90))
}
fn read_with_timeout(timeout: Duration) -> Result<Secret<64>> {
    let mut entry = Entry::new()?;
    let mut terminal = Terminal::open()?;
    let deadline = Instant::now() + timeout;
    terminal.render(&entry)?;
    loop {
        common::cancelled()?;
        if Instant::now() >= deadline {
            return Err(fail("PIN entry timed out"));
        }
        let mut event = PollFd {
            fd: terminal.file.as_raw_fd(),
            events: 1,
            revents: 0,
        };
        // SAFETY: poll accesses exactly this single initialized descriptor.
        let ready = unsafe { poll(&mut event, 1, 100) };
        if ready < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e.into());
        }
        if ready == 0 {
            continue;
        }
        if event.revents & (8 | 16 | 32) != 0 {
            return Err(fail("PIN terminal disconnected"));
        }
        let mut bytes = [0; 32];
        let n = match terminal.file.read(&mut bytes) {
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        if n != 1 {
            return Err(fail("batched PIN input is not accepted"));
        }
        if entry.input(bytes[0])? {
            terminal.restore()?;
            return Ok(entry.pin);
        }
        terminal.render(&entry)?;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn permutations_are_complete() {
        for _ in 0..100 {
            let mut map = permutation().unwrap();
            map.sort();
            assert_eq!(map, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        }
    }
    #[test]
    fn decode_edit_and_termination() {
        let mut e = Entry::new().unwrap();
        for d in [1, 1, 2, 2] {
            let key = e.map[d] + b'0';
            assert!(!e.input(key).unwrap());
        }
        assert_eq!(&e.pin[..5], b"1122\0");
        assert!(!e.input(127).unwrap());
        assert_eq!(&e.pin[..5], b"112\0\0");
        let key = e.map[3] + b'0';
        e.input(key).unwrap();
        assert!(e.input(13).unwrap());
        e.input(21).unwrap();
        assert!(e.pin.iter().all(|b| *b == 0));
        assert!(e.input(13).is_err());
        assert!(e.input(27).is_err());
    }
    #[test]
    #[ignore = "PTY integration fixture"]
    fn terminal_fixture() {
        let mode = std::env::var("PIN_TEST_MODE").unwrap();
        let result = read_with_timeout(Duration::from_secs(if mode == "timeout" { 1 } else { 10 }));
        if mode == "submit" {
            let pin = result.unwrap();
            assert_eq!(&pin[..7], b"112203\0");
        } else {
            assert!(result.is_err());
        }
        println!("PIN_TEST_OK");
    }
}
