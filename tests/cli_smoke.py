#!/usr/bin/env python3
"""Stdlib release CLI smoke check; no real API key is needed.

Dummy external nmap/searchsploit tools only satisfy dependency lookup and always
fail. Native scans touch only loopback TCP port 1; even an open port cannot yield
fingerprints or Brave search context. All settings and tools live in a temporary
directory. Usage: python3 tests/cli_smoke.py [target/release/oxscan]
"""

import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import termios
import time


SCAN = ["127.0.0.1", "-1", "--scan-timeout", "5", "--no-scripts"]
CONSENT = "Enable HackTricks reference search with Brave?"
PASSWORD = "Brave Search API key (Enter to skip):"
SENTINEL = "SMOKE-FAKE-NOT-A-REAL-BRAVE-KEY-7f3a9d"
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def plain(output):
    return ANSI.sub("", output.decode("utf-8", errors="replace"))


def run(binary, args, env, *, tty=False, answers=(), success=True):
    """Bound each child to ten seconds and kill its process group on every exit."""
    master = slave = None
    child = None
    output = bytearray()
    stderr = b""
    answered = cursor_requests = 0
    prompt_start = 0
    deadline = time.monotonic() + 10
    try:
        if tty:
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 160, 0, 0))
        child = subprocess.Popen(
            [str(binary), *args], env=env, cwd=env["HOME"], start_new_session=True,
            stdin=slave if tty else subprocess.DEVNULL,
            stdout=slave if tty else subprocess.PIPE,
            stderr=slave if tty else subprocess.PIPE,
        )
        if tty:
            os.close(slave)
            slave = None
            while True:
                remaining = deadline - time.monotonic()
                assert remaining > 0, "child exceeded 10 seconds (unexpected prompt or hang)"
                if not select.select([master], [], [], min(remaining, 0.1))[0]:
                    if child.poll() is not None:
                        break
                    continue
                try:
                    chunk = os.read(master, 65536)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    break  # Linux PTYs signal EOF with EIO.
                if not chunk:
                    break
                output.extend(chunk)
                assert len(output) <= 512 * 1024, "unexpectedly large terminal output"
                # Count the full buffer so cursor requests split across reads work.
                requested = output.count(b"\x1b[6n")
                for _ in range(requested - cursor_requests):
                    os.write(master, b"\x1b[1;1R")
                cursor_requests = requested
                text = plain(output)
                if answered < len(answers):
                    prompt, response = answers[answered]
                    found = text.find(prompt, prompt_start)
                    if found >= 0:
                        if prompt == PASSWORD:
                            assert not termios.tcgetattr(master)[3] & termios.ECHO, "key input echo enabled"
                        os.write(master, response)
                        prompt_start = found + len(prompt)
                        answered += 1
            child.wait(timeout=max(0.001, deadline - time.monotonic()))
        else:
            stdout, stderr = child.communicate(timeout=max(0.001, deadline - time.monotonic()))
            output.extend(stdout)

        combined = bytes(output) + stderr
        assert SENTINEL.encode() not in combined and SENTINEL not in plain(combined), "fake key leaked into captured output"
        assert answered == len(answers), "expected prompt never appeared"
        assert (child.returncode == 0) == success, f"unexpected exit status {child.returncode}"
        if not answers:
            assert CONSENT not in plain(combined) and PASSWORD not in plain(combined), "unexpected key prompt"
        return bytes(output), stderr
    except (AssertionError, OSError, subprocess.TimeoutExpired) as error:
        # Include actual settings/ACL failures, but never print environment values.
        captured = plain(bytes(output) + stderr).replace(SENTINEL, "[REDACTED]")
        raise AssertionError(f"{' '.join(args)}: {error}\n{captured[-5000:]}") from None
    finally:
        if child is not None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
            for pipe in (child.stdout, child.stderr):
                if pipe is not None:
                    pipe.close()
        for fd in (master, slave):
            if fd is not None:
                os.close(fd)


def report(binary, env, status, *, tty=False):
    stdout, stderr = run(binary, [*SCAN, "--json"], env, tty=tty)
    try:
        result = json.loads(stdout)
    except ValueError:
        raise AssertionError(f"invalid JSON report: {plain(stdout + stderr)[-5000:]}") from None
    references = result["hacktricks"]
    assert result["target"] == "127.0.0.1", "wrong report target"
    assert result["services"] == [] and result["os"] is None, "dummy tools yielded scan context"
    assert result["nse"]["status"] == "disabled" and result["nse"]["results"] == [], "NSE ran"
    assert references["requests"] == 0 and references["lookups"] == [], "Brave lookup attempted"
    assert references["status"] == status, f"unexpected HackTricks report: {references}; {plain(stderr)}"
    if status != "unavailable":
        assert references["errors"] == [], f"settings/search errors: {references['errors']}"
    return references


def saved(path, key):
    assert path.is_file(), "settings file was not saved"
    assert json.loads(path.read_bytes()) == {"schema_version": 1, "api_key": key}, "wrong saved consent/key"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600, "settings file must be 0600"
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700, "settings directory must be 0700"
    assert sorted(entry.name for entry in path.parent.iterdir()) == [path.name], "stray settings files"


def snapshot(path):
    metadata = path.stat()
    return path.read_bytes(), metadata.st_mode, metadata.st_ino, metadata.st_mtime_ns


def main():
    assert len(sys.argv) <= 2, "usage: cli_smoke.py [binary]"
    binary = Path(sys.argv[1] if len(sys.argv) == 2 else "target/release/oxscan").resolve()
    assert binary.is_file() and os.access(binary, os.X_OK), "release binary missing or not executable"
    with tempfile.TemporaryDirectory(prefix="oxscan-cli-smoke-") as directory:
        root = Path(directory)
        tools = root / "bin"
        tools.mkdir(mode=0o700)
        for name in ("nmap", "searchsploit"):
            tool = tools / name
            tool.write_text("#!/bin/sh\nexit 1\n")
            tool.chmod(0o700)
        config = root / "config"
        settings = config / "oxidescanner" / "hacktricks.json"
        env = {name: value for name, value in os.environ.items() if not name.startswith("OXIDE_")}
        env.update(HOME=str(root), XDG_CONFIG_HOME=str(config),
                   PATH=str(tools) + os.pathsep + os.defpath, TERM="xterm-256color")

        for tty in (False, True):
            report(binary, env, "disabled", tty=tty)
            assert not config.exists(), "fresh JSON run created settings"
        print("PASS 1: fresh JSON (pipe/PTY): disabled, no prompt/write, correct target")

        run(binary, SCAN, env, tty=True, answers=[(CONSENT, b"\r")])
        saved(settings, None)
        before = snapshot(settings)
        run(binary, SCAN, env, tty=True)
        report(binary, env, "disabled")
        assert snapshot(settings) == before, "remembered decline was rewritten"
        print("PASS 2: default Enter remembers opt-out; subsequent interactive run has no key prompt")

        stdout, _ = run(binary, ["--setup-hacktricks"], env, tty=True,
                        answers=[(CONSENT, b"y\r"), (PASSWORD, SENTINEL.encode() + b"\r")])
        assert not any(word in plain(stdout).lower() for word in ("confirmation", "confirm password", "re-enter")), "double key confirmation"
        saved(settings, SENTINEL)
        before = snapshot(settings)
        run(binary, SCAN, env, tty=True)
        report(binary, env, "skipped_no_context")
        assert snapshot(settings) == before, "ordinary reuse changed saved key"
        print("PASS 3: hidden setup, one key entry, 0600/0700, reuse, no output/JSON token leak")

        overridden = dict(env, OXIDE_HACKTRICKS_API_KEY="")
        run(binary, SCAN, overridden, tty=True)
        report(binary, overridden, "disabled")
        assert snapshot(settings) == before, "empty environment override changed saved settings"
        print("PASS 4: empty environment override disables search without changing saved settings")

        run(binary, ["--reset-hacktricks"], env)
        saved(settings, None)
        assert SENTINEL.encode() not in settings.read_bytes(), "reset retained key"
        run(binary, SCAN, env, tty=True)
        report(binary, env, "disabled")
        settings.write_text("{deliberately malformed smoke settings\n")
        malformed = snapshot(settings)
        errors = report(binary, env, "unavailable")["errors"]
        assert any("invalid JSON or schema" in error for error in errors), f"wrong malformed-file error: {errors}"
        assert snapshot(settings) == malformed, "scan changed malformed settings"
        run(binary, ["--reset-hacktricks"], env)
        saved(settings, None)
        run(binary, SCAN, env, tty=True)
        report(binary, env, "disabled")
        print("PASS 5: reset removes key, remembers disabled, and recovers malformed settings")

        before = snapshot(settings)
        fresh = root / "rejected-setup"
        for config_home in (config, fresh):
            isolated = dict(env, XDG_CONFIG_HOME=str(config_home))
            for tty, flags in ((False, []), (False, ["--json"]), (True, ["--json"])):
                run(binary, ["--setup-hacktricks", *flags], isolated, tty=tty, success=False)
                assert not fresh.exists(), "rejected setup created settings"
                assert snapshot(settings) == before, "rejected setup changed settings"
        print("PASS 6: non-TTY/JSON setup rejects without prompting or writing")
    assert not root.exists(), "temporary directory survived cleanup"
    print("PASS: all 6 CLI smoke checks; temporary files and child processes cleaned up")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, ValueError, KeyError) as error:
        print(f"FAIL: {error}".replace(SENTINEL, "[REDACTED]"), file=sys.stderr)
        sys.exit(1)
