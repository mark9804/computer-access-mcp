#!/usr/bin/env python3
"""Synthetic subprocess checks. Never launches --serve or reads live AX/TCC.
Includes an inert session-worker retirement before any read ticket or listener.
Usage: python3 native/macos/collector/Tests/fixture_process.py /absolute/collector
"""
import json
import os
import select
import subprocess
import sys
import time
import uuid

BINARY = os.path.abspath(sys.argv[1])


class Fixture:
    def __init__(self, scenario="allowed", lock=None):
        self.instance = str(uuid.uuid4())
        self.owner = str(uuid.uuid4())
        self.frames = []
        self.buffer = b""
        args = [BINARY, "--fixture", "--owner-id", self.owner,
                "--instance-id", self.instance, "--device-id", "fixture-device",
                "--fixture-scenario", scenario]
        if lock:
            args += ["--fixture-lock-id", lock]
        self.process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.wait(lambda frame: frame["type"] == "hello")

    def send(self, kind, **fields):
        body = dict(protocolVersion=1, type=kind, requestId=str(uuid.uuid4()),
                    ownerId=self.owner, instanceId=self.instance, policyRevision=1)
        body.update(fields)
        self.process.stdin.write((json.dumps(body, separators=(",", ":")) + "\n").encode())
        self.process.stdin.flush()
        return body["requestId"]

    def configure(self, allowed=True, enabled=True, timeout=500):
        request = self.send("configure", policy=dict(enabled=enabled,
            allowedApplicationIds=["test.allowed"] if allowed else ["other.app"],
            maxTextCodeUnits=128, maxPending=8, debounceMs=10, maxWaitMs=50, readTimeoutMs=timeout))
        self.wait(lambda frame: frame.get("type") == "configured" and frame.get("requestId") == request)

    def control(self, command, lease=3000):
        request = self.send("control", command=command, leaseDurationMs=lease)
        return self.wait(lambda frame: frame.get("requestId") == request and frame["type"] in ["state", "error"])

    def read_one(self, timeout):
        deadline = time.monotonic() + timeout
        while b"\n" not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("synthetic fixture timeout")
            if not select.select([self.process.stdout], [], [], remaining)[0]:
                raise TimeoutError("synthetic fixture timeout")
            chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk:
                raise EOFError(f"fixture exited {self.process.poll()}")
            self.buffer += chunk
            assert len(self.buffer) <= 524288
        line, self.buffer = self.buffer.split(b"\n", 1)
        assert len(line) + 1 <= 65536
        frame = json.loads(line)
        assert frame["type"] in ["hello", "configured", "state", "observation", "error"]
        if frame["type"] == "observation":
            assert frame["eventId"] == f'{self.instance}:{frame["seq"]}'
            assert frame["actor"] == "unknown"
        self.frames.append(frame)
        return frame

    def wait(self, predicate, timeout=3):
        deadline = time.monotonic() + timeout
        while True:
            frame = self.read_one(max(0, deadline - time.monotonic()))
            if predicate(frame):
                return frame

    def text(self):
        return self.wait(lambda frame: frame.get("payload", {}).get("kind") == "text.snapshot")

    def finish(self, eof=False):
        if self.process.poll() is None:
            if eof:
                self.process.stdin.close()
            else:
                self.control("stop")
            assert self.process.wait(timeout=2) == 0
        assert self.process.stderr.read() == b""
        self.process.stdout.close()
        self.process.stderr.close()
        if not self.process.stdin.closed:
            self.process.stdin.close()


def children(pid):
    result = subprocess.run(["/bin/ps", "-axo", "pid=,ppid="], check=True, capture_output=True, text=True)
    return [int(parts[0]) for line in result.stdout.splitlines() if len(parts := line.split()) == 2 and int(parts[1]) == pid]


def gone(pid):
    try:
        os.kill(pid, 0)
        return False
    except ProcessLookupError:
        return True


def worker_started(f):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        found = children(f.process.pid)
        if found:
            return found[0]
        select.select([], [], [], 0.01)
    raise AssertionError("synthetic child was not started")


def run():
    count = 0
    f = Fixture()
    assert f.frames[0]["type"] == "hello"
    f.configure(); assert f.control("start")["state"] == "running"
    text = f.text()
    assert text["payload"]["text"] == "Synthetic \U0001f9ea text"
    assert text["payload"]["range"]["length"] == 17
    assert text["target"]["identity"]["deviceId"] == "fixture-device"
    previous = f.frames[-2]
    assert previous["payload"]["kind"] == "context.changed"
    assert previous["stamp"] == text["stamp"] and previous["target"] == text["target"]
    assert f.control("heartbeat")["stamp"] == text["stamp"]
    f.finish(); count += 1

    for scenario, allowed in [("allowed", False), ("sensitive", True), ("browser", True), ("focus-loss", True), ("readerror", True)]:
        f = Fixture(scenario); f.configure(allowed=allowed); f.control("start")
        f.wait(lambda frame: frame.get("payload", {}).get("kind") == "gap")
        assert not any(frame.get("payload", {}).get("kind") == "text.snapshot" for frame in f.frames)
        f.finish(); count += 1

    for scenario in ["locked", "unknown"]:
        f = Fixture(scenario); f.configure(); assert f.control("start")["state"] == "paused"
        assert children(f.process.pid) == []
        f.finish(); count += 1

    # A successful initial empty read establishes context but no longer emits a
    # standalone blank text snapshot. Completion ordering plus heartbeat proves
    # that this is filtering, not waiting for a timed-out/missing fixture reply.
    f = Fixture("empty"); f.configure(); f.control("start")
    f.wait(lambda frame: frame.get("payload", {}).get("kind") == "context.changed")
    assert f.control("heartbeat")["state"] == "running"
    assert not any(frame.get("payload", {}).get("kind") in ["text.snapshot", "gap"] for frame in f.frames)
    f.finish(); count += 1

    for scenario in ["partial", "value"]:
        f = Fixture(scenario); f.configure(); f.control("start"); text = f.text()["payload"]
        if scenario == "partial":
            assert text["scope"] == "accessible-range" and text["coverage"]["status"] == "partial"
        f.finish(); count += 1

    f = Fixture(); f.configure(); f.control("start"); f.text(); f.control("pause")
    before = len(f.frames)
    # Heartbeats process control but a pause does not launch workers or texts.
    for _ in range(3):
        assert f.control("heartbeat")["state"] == "paused"
    assert not any(frame.get("payload", {}).get("kind") == "text.snapshot" for frame in f.frames[before:])
    assert children(f.process.pid) == []
    assert f.control("start")["state"] == "paused"
    assert f.control("resume")["state"] == "running"; f.text(); f.finish(); count += 1

    f = Fixture(); f.configure(enabled=False); assert f.control("start")["code"] == "permission-denied"
    assert children(f.process.pid) == []; f.finish(); count += 1

    # Actual synthetic hung child: EOF, stop, pause and lease all SIGKILL+wait.
    for boundary in ["eof", "stop", "pause", "lease"]:
        f = Fixture("workerhang"); f.configure(timeout=5000)
        f.control("start", lease=300 if boundary == "lease" else 3000)
        child = worker_started(f)
        started = time.monotonic()
        if boundary == "eof":
            f.finish(eof=True)
        elif boundary == "lease":
            f.wait(lambda frame: frame.get("state") == "stopped")
            assert f.process.wait(timeout=2) == 0; f.finish()
        elif boundary == "pause":
            assert f.control("pause")["state"] == "paused"; assert gone(child); f.finish()
        else:
            f.finish()
        assert time.monotonic() - started < 2 and gone(child)
        count += 1

    f = Fixture("workerhang"); f.configure(timeout=200); f.control("start")
    child = worker_started(f)
    f.wait(lambda frame: frame.get("payload", {}).get("reason") == "timeout")
    assert gone(child); f.finish(); count += 1

    # Invalid directions/actions never grant capability; owner cannot be swapped.
    f = Fixture(); f.configure()
    request = f.send("control", command="start", leaseDurationMs=1000, ownerId="other-owner")
    assert f.wait(lambda frame: frame.get("requestId") == request)["code"] == "permission-denied"
    request = f.send("control", command="start", leaseDurationMs=30001)
    assert f.wait(lambda frame: frame.get("type") == "error")["code"] == "invalid-message"
    f.process.stdin.write(b'{"protocolVersion":999,"type":"control"}\n')
    f.process.stdin.flush()
    assert f.wait(lambda frame: frame.get("type") == "error")["code"] == "unsupported-version"
    assert children(f.process.pid) == []; f.finish(); count += 1

    # SIGKILL bypasses all collector cleanup: the child's independent real-parent
    # watchdog must still exit, without an AX call in this synthetic scenario.
    f = Fixture("workerhang"); f.configure(timeout=5000); f.control("start")
    child = worker_started(f)
    f.process.kill(); f.process.wait(timeout=2)
    deadline = time.monotonic() + 2
    while not gone(child) and time.monotonic() < deadline:
        select.select([], [], [], 0.01)
    assert gone(child), "orphan synthetic worker survived collector death"
    f.finish(); count += 1

    # A Host that does not read stdout must not pin the control loop forever.
    f = Fixture(); f.configure()
    command = dict(protocolVersion=1, type="control", requestId="pressure", ownerId=f.owner,
                   instanceId=f.instance, policyRevision=1, command="heartbeat", leaseDurationMs=1000)
    frame = (json.dumps(command, separators=(",", ":")) + "\n").encode()
    os.set_blocking(f.process.stdin.fileno(), False)
    deadline = time.monotonic() + 2
    while f.process.poll() is None and time.monotonic() < deadline:
        try:
            os.write(f.process.stdin.fileno(), frame * 32)
        except (BlockingIOError, BrokenPipeError):
            select.select([], [], [], 0.01)
    assert f.process.wait(timeout=2) == 74
    assert children(f.process.pid) == []; f.finish(); count += 1

    lock = "process-test-" + str(uuid.uuid4())
    first = Fixture(lock=lock); second = Fixture(lock=lock)
    assert second.process.wait(timeout=2) == 73
    second.finish(); first.finish(eof=True); count += 1
    # Exercise the production SessionTransport ACK-write -> _exit path with an
    # inert AXWorkerSession: no read ticket, observer registration, input tap,
    # AppKit workspace or TCC operation is ever requested. Constructors are local.
    session_token, retire_token = str(uuid.uuid4()), str(uuid.uuid4())
    command = dict(retire=retire_token, sessionToken=session_token)
    process = subprocess.Popen([BINARY, "--ax-worker", "--parent-pid", str(os.getpid()),
        "--worker-token", session_token, "--session-worker", "yes"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "DSH_COLLECTOR_WORKER_TOKEN": session_token,
             "DSH_COMPUTER_ACCESS_DEBUG": "1"})
    try:
        # Keep stdin open until the worker has drained ACK and exited; EOF is a
        # different control boundary and must not accidentally stand in for retire.
        process.stdin.write((json.dumps(command) + "\n").encode()); process.stdin.flush()
        assert process.wait(timeout=3) == 0
        stdout, stderr = process.stdout.read(), process.stderr.read()
        assert process.returncode == 0
        assert json.loads(stdout) == dict(retired=retire_token, sessionToken=session_token, inputHealthy=True)
        stages = {json.loads(line)["code"] for line in stderr.splitlines()}
        assert {"session-retire-received", "session-retire-input-ended", "session-retire-observer-detached", "session-retire-written"} <= stages
        assert not any("input-text-tap" in stage or stage == "session-read-end" for stage in stages)
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=2)
        process.stdin.close(); process.stdout.close(); process.stderr.close()
    count += 1
    print(f"PASS: {count} synthetic/inert process cases; no --serve, live AX reads, TCC, input tap or GUI execution")


if __name__ == "__main__":
    run()
