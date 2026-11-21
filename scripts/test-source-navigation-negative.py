#!/usr/bin/env python3
"""Negative-only native navigation CLI tests. NEVER send a valid navigation target.

Run with a freshly built debug collector, for example:
  python3 scripts/test-source-navigation-negative.py --binary <debug-collector>
No AppKit/AX gate or activation should be reached: every payload is incomplete,
malformed, or oversized, or stdin is deliberately kept open until cancellation.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def receipt(output, reason):
    assert len(output) <= 1024, len(output)
    assert output.endswith(b"\n") and output.count(b"\n") == 1, repr(output)
    assert json.loads(output) == {
        "version": 1, "outcome": "refused", "reason": reason,
        "captured": False, "launched": False,
    }, repr(output)


def run_negative(binary, args, payload, code, reason=None):
    result = subprocess.run([binary, *args], input=payload, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=6, check=False)
    assert result.returncode == code, (args, result.returncode, result.stdout, result.stderr)
    assert result.stderr == b"", repr(result.stderr)
    if reason is None:
        assert result.stdout == b"", repr(result.stdout)
    else:
        receipt(result.stdout, reason)


def held_stdin(binary, cancel=False):
    child = subprocess.Popen([binary, "--navigate-source"], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        started = time.monotonic()
        child.stdin.write(b"{")  # Incomplete JSON, never a legitimate request.
        child.stdin.flush()
        if cancel:
            child.terminate()
        child.wait(timeout=6)
        output, error = child.communicate(timeout=1)
        assert error == b"", repr(error)
        if cancel:
            assert child.returncode == -signal.SIGTERM, child.returncode
            assert output == b"", repr(output)
        else:
            assert child.returncode == 75, child.returncode
            assert time.monotonic() - started < 3, "stdin deadline did not stop promptly"
            receipt(output, "input-timeout")
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=2)


def stdout_unavailable(binary, full=False):
    read_fd, write_fd = os.pipe()
    try:
        if full:
            os.set_blocking(write_fd, False)
            while True:
                try:
                    os.write(write_fd, b"x" * 4096)
                except BlockingIOError:
                    break
            while True:
                try:
                    os.write(write_fd, b"x")
                except BlockingIOError:
                    break
        else:
            os.close(read_fd)
            read_fd = -1
        started = time.monotonic()
        result = subprocess.run([binary, "--navigate-source"], input=b"{}",
                                stdout=write_fd, stderr=subprocess.PIPE, timeout=6, check=False)
        assert result.returncode == 74, result.returncode
        assert result.stderr == b"", repr(result.stderr)
        assert time.monotonic() - started < 3, "blocked stdout did not stop promptly"
    finally:
        os.close(write_fd)
        if read_fd >= 0:
            os.close(read_fd)


def parent_probe(binary, input_fd, ready_fd):
    # The outer test keeps stdin open. Killing this intermediary cannot turn
    # parent loss into EOF; the collector must notice getppid()/watchdog instead.
    child = subprocess.Popen([binary, "--navigate-source"], stdin=input_fd,
                             stdout=sys.stdout.buffer, stderr=sys.stderr.buffer)
    os.write(ready_fd, str(child.pid).encode("ascii"))
    os.close(ready_fd)
    return child.wait()


def parent_death(binary):
    input_read, input_write = os.pipe()
    ready_read, ready_write = os.pipe()
    parent = None
    try:
        parent = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--binary", binary,
                                   "--parent-probe", str(input_read), str(ready_write)],
                                  pass_fds=(input_read, ready_write), stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, start_new_session=True)
        os.close(input_read); input_read = -1
        os.close(ready_write); ready_write = -1
        import select
        assert select.select([ready_read], [], [], 5)[0], "intermediary never started collector"
        child_pid = os.read(ready_read, 32)
        assert child_pid.isdigit() and int(child_pid) > 1, child_pid
        parent.kill()
        output, error = parent.communicate(timeout=6)
        assert parent.returncode == -signal.SIGKILL, parent.returncode
        assert error == b"", repr(error)
        receipt(output, "parent-unavailable")
    except BaseException:
        if parent is not None:
            try:
                os.killpg(parent.pid, signal.SIGKILL)  # Only this test's new session.
            except ProcessLookupError:
                pass
            parent.wait(timeout=2)
        raise
    finally:
        for fd in [input_read, input_write, ready_read, ready_write]:
            if fd >= 0:
                os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--parent-probe", nargs=2, type=int, help=argparse.SUPPRESS)
    options = parser.parse_args()
    binary = str(Path(options.binary).resolve(strict=True))
    assert Path(binary).name == "computer-access-collector", "not a collector binary"
    if options.parent_probe:
        return parent_probe(binary, *options.parent_probe)

    # All JSON inputs below omit mandatory identity fields, even when testing
    # duplicate keys or parser errors. A permissive parser still cannot navigate.
    for args in [[], ["--navigate-source", "extra"], ["--navigate-source", "--serve"],
                 ["--navigate-source", "--navigate-source"], ["--navigate-source=1"]]:
        run_negative(binary, args, b"{}", 64)
    for payload in [b"", b"{}", b"{", b"null", b"[]", b"not-json", b"\xff", b"\xef\xbb\xbf{}",
                    b'{"version":1,"version":1}', b'{"version":true}', b'{"version":1,"url":"x"}',
                    b"{}\n{}", b"{} trailing"]:
        run_negative(binary, ["--navigate-source"], payload, 64, "invalid-request")
    run_negative(binary, ["--navigate-source"], b" " * 2048, 64, "invalid-request")
    run_negative(binary, ["--navigate-source"], b" " * 2049, 64, "input-too-large")
    closed_input = subprocess.run([binary, "--navigate-source"], stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  preexec_fn=lambda: os.close(0), timeout=6, check=False)
    assert closed_input.returncode == 74, closed_input.returncode
    assert closed_input.stderr == b"", repr(closed_input.stderr)
    receipt(closed_input.stdout, "input-unavailable")
    held_stdin(binary)
    held_stdin(binary, cancel=True)
    parent_death(binary)
    stdout_unavailable(binary)
    stdout_unavailable(binary, full=True)
    print("PASS: navigation negative CLI (26 cases); invalid requests only, activation path not reached")
    return 0


if __name__ == "__main__":
    sys.exit(main())
