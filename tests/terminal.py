"""Exercise the real terminal reader with synthetic PINs and redirected logs."""
import errno
import fcntl
import glob
import os
import pty
import re
import select
import subprocess
import sys
import termios
import time

binary = next(p for p in glob.glob(sys.argv[1] + '/luks_combo_unlock-*')
              if os.path.isfile(p) and os.access(p, os.X_OK) and not p.endswith('.d')
              and b'pin::tests::terminal_fixture: test' in subprocess.run(
                  [p, '--list'], capture_output=True, check=False).stdout)


def exercise(mode):
    master, slave = pty.openpty()
    saved = termios.tcgetattr(slave)

    def session():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

    child = subprocess.Popen(
        [binary, '--ignored', '--exact', 'pin::tests::terminal_fixture', '--nocapture'],
        stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        preexec_fn=session, env={**os.environ, 'PIN_TEST_MODE': mode})
    pending = b''

    def frame():
        nonlocal pending
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if b'Esc: cancel\x1b[K\r\n' in pending:
                current, pending = pending.split(b'Esc: cancel\x1b[K\r\n', 1)
                match = re.search(rb'Press key:  ((?:[0-9]  ){10})', current)
                assert match, current
                keys = [int(x) for x in match[1].split()]
                assert sorted(keys) == list(range(10))
                return dict(zip([1,2,3,4,5,6,7,8,9,0], keys))
            if select.select([master], [], [], 0.1)[0]:
                try:
                    data = os.read(master, 8192)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                pending += data
            if child.poll() is not None:
                break
        raise AssertionError(('terminal frame was not rendered', pending, child.poll(), child.communicate(timeout=1) if child.poll() is not None else b'running'))

    try:
        keys = frame()
        if mode == 'submit':
            # Repeated digits, deletion and clearing must survive changing maps.
            for action in [1, 1, 'back', 2, 'clear', 1, 1, 2, 2, 0, 3]:
                if action == 'back':
                    value = b'\x7f'
                elif action == 'clear':
                    value = b'\x15'
                else:
                    value = str(keys[action]).encode()
                os.write(master, value)
                keys = frame()
            os.write(master, b'\r')
        elif mode == 'cancel':
            os.write(master, b'\x1b')
        elif mode == 'paste':
            os.write(master, b'123456')
        output, errors = child.communicate(timeout=12)
        assert child.returncode == 0, (output, errors)
        assert b'PIN_TEST_OK' in output
        assert b'Press key:' not in output + errors
        assert b'PIN digit:' not in output + errors
        assert b'112203' not in output + errors
        assert termios.tcgetattr(slave) == saved, 'terminal settings were not restored'
        print('TERMINAL_' + mode.upper() + '=PASS')
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        os.close(master)
        os.close(slave)


for mode in ['submit', 'cancel', 'paste', 'timeout']:
    exercise(mode)
