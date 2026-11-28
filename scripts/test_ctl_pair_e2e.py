#!/usr/bin/env python3
"""End-to-end test for fatext CLI Controller TOTP 2FA and RAM-only E2EE pairing."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
CLI_BIN = Path(os.environ.get("FATEXT_CLI_BIN", str(ROOT / "build" / "fatext")))
SERVER_BIN = Path(os.environ.get("FATEXT_SERVER_BIN", str(ROOT.parent / "fatext" / "build" / "fatext-server")))
WWW_DIR = Path(os.environ.get("FATEXT_WWW_DIR", str(ROOT.parent / "fatext" / "www")))
TPL_DIR = Path(os.environ.get("FATEXT_TPL_DIR", str(ROOT.parent / "fatext" / "templates")))
HOST = "127.0.0.1"


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        return int(s.getsockname()[1])


def wait_http_ok(url: str, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as r:
                if r.status == 200:
                    return
        except Exception:
            time.sleep(0.05)
    raise RuntimeError(f"server failed to become healthy at {url}")


def assert_eq(a, b, msg: str = "") -> None:
    if a != b:
        raise AssertionError(f"{msg}: {a!r} != {b!r}")


def assert_true(cond: bool, msg: str = "") -> None:
    if not cond:
        raise AssertionError(f"assertion failed: {msg}")


def run_cli(
    args: list[str],
    *,
    agent_home: str,
    api_url: str,
    stdin_data: str | None = None,
    extra_env: dict[str, str] | None = None,
    timeout: float = 30.0,
) -> tuple[int, str, str]:
    env = os.environ.copy()
    env["FATEXT_HOME"] = agent_home
    if extra_env:
        env.update(extra_env)
    cmd = [str(CLI_BIN)]
    if "--api" not in args:
        cmd.extend(["--api", api_url])
    cmd.extend(args)
    res = subprocess.run(
        cmd,
        env=env,
        input=stdin_data,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    return res.returncode, res.stdout, res.stderr


def py_totp(secret_b32: str, step: int) -> str:
    pad = "=" * ((8 - len(secret_b32) % 8) % 8)
    raw = base64.b32decode(secret_b32 + pad, casefold=True)
    msg = struct.pack(">Q", step)
    mac = hmac.new(raw, msg, hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code_int = (struct.unpack(">I", mac[off : off + 4])[0] & 0x7FFFFFFF) % 1000000
    return f"{code_int:06d}"


def wrong_code(good_code: str) -> str:
    n = (int(good_code) + 135791) % 1000000
    return f"{n:06d}"


def open_pair_bg(ctl_home: str, api_url: str, extra_args: list[str]) -> tuple[subprocess.Popen[str], dict]:
    cmd = [str(CLI_BIN), "--json", "--api", api_url, "ctl", "pair"] + extra_args
    env = os.environ.copy()
    env["FATEXT_HOME"] = ctl_home
    proc = subprocess.Popen(
        cmd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=1,
    )
    assert proc.stdout is not None
    first_line = proc.stdout.readline()
    if not first_line:
        rc = proc.wait(timeout=5)
        err = proc.stderr.read() if proc.stderr else ""
        raise AssertionError(f"ctl pair exited early rc={rc}: {err}")
    open_ev = json.loads(first_line)
    assert_eq(open_ev.get("event"), "open", first_line)
    return proc, open_ev


def finish_pair_bg(proc: subprocess.Popen[str], timeout: float = 20.0) -> tuple[int, list[dict], str]:
    out, err = proc.communicate(timeout=timeout)
    events = [json.loads(ln) for ln in out.splitlines() if ln.strip()]
    return proc.returncode, events, err


def main() -> int:
    if not CLI_BIN.is_file() or not SERVER_BIN.is_file():
        print(f"Missing built binaries: cli={CLI_BIN} server={SERVER_BIN}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="fatext-pair-e2e-") as td:
        td_p = Path(td)
        data_dir = td_p / "data"
        log_dir = td_p / "logs"
        data_dir.mkdir(parents=True, exist_ok=True)
        log_dir.mkdir(parents=True, exist_ok=True)

        port = free_tcp_port()
        api_url = f"http://{HOST}:{port}"
        srv_env = os.environ.copy()
        srv_env["FATEXT_ADDR"] = f"{HOST}:{port}"
        srv_env["FATEXT_DATA_DIR"] = str(data_dir)
        srv_env["FATEXT_WWW_DIR"] = str(WWW_DIR)
        srv_env["FATEXT_TEMPLATES_DIR"] = str(TPL_DIR)
        srv_env["FATEXT_POW_BITS"] = "12"
        srv_env["FATEXT_LOG_DIR"] = str(log_dir)

        srv = subprocess.Popen([str(SERVER_BIN)], env=srv_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            wait_http_ok(f"{api_url}/health", timeout=10.0)

            ctl_home = str(td_p / "ctl")
            w1_home = str(td_p / "worker1")
            w2_home = str(td_p / "worker2")
            w_bad_home = str(td_p / "worker_bad")
            w_replay_home = str(td_p / "worker_replay")

            print("[1/6] Init controller & verify ctl pair fails before 2fa init...")
            rc, out, err = run_cli(
                ["--json", "init", "--controller-only", "--name", "MainCtl"],
                agent_home=ctl_home,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"ctl init failed: {err}")
            ctl_id = json.loads(out)["agent_id"]

            rc, out, err = run_cli(["--json", "ctl", "pair"], agent_home=ctl_home, api_url=api_url)
            assert_true(rc != 0, "ctl pair without 2fa must fail")
            assert_eq(json.loads(err)["error"]["code"], "ERR_TOTP_NOT_CONFIGURED", err)

            print("[2/6] Test ctl 2fa init, RFC 6238 code match, status, and file permissions...")
            rc, out, err = run_cli(["--json", "ctl", "2fa", "init"], agent_home=ctl_home, api_url=api_url)
            assert_eq(rc, 0, f"ctl 2fa init failed: {err}")
            t_info = json.loads(out)
            secret_b32 = t_info["secret_b32"]
            assert_eq(len(secret_b32), 32, "160-bit secret should encode to 32 Base32 chars")
            assert_true(t_info["otpauth_uri"].startswith(f"otpauth://totp/fatext%3A{ctl_id}?secret={secret_b32}"), t_info["otpauth_uri"])

            totp_file = Path(ctl_home) / "totp.json"
            assert_eq(stat.S_IMODE(totp_file.stat().st_mode), 0o600, "totp.json must be 0600")

            # Verify CLI TOTP calculation matches Python RFC 6238
            rc, out, err = run_cli(["--json", "ctl", "2fa", "code"], agent_home=ctl_home, api_url=api_url)
            assert_eq(rc, 0, f"ctl 2fa code failed: {err}")
            c_info = json.loads(out)
            assert_eq(c_info["code"], py_totp(secret_b32, c_info["step"]), "CLI TOTP must match RFC 6238 HMAC-SHA1")

            rc, out, err = run_cli(["--json", "ctl", "2fa", "status"], agent_home=ctl_home, api_url=api_url)
            assert_eq(rc, 0, f"ctl 2fa status failed: {err}")
            st_info = json.loads(out)
            assert_eq(st_info["enabled"], True)
            assert_true("secret_b32" not in out, "status must never expose secret_b32")

            print("[3/6] Test wrong code rejection then interactive stdin pairing -> local keygen -> verify...")
            # Ensure we are not right on a 30s boundary so first wrong + right stay predictable, or compute live
            if 30 - (int(time.time()) % 30) < 4:
                time.sleep(5)

            pair_proc, open_ev = open_pair_bg(
                ctl_home,
                api_url,
                ["--label", "worker-alpha", "--scopes", "pub,dm,social", "--ttl", "7d", "--timeout", "120"],
            )
            pair_id = open_ev["pair_id"]
            assert_true(pair_id.startswith("pair_"), pair_id)

            # 1) Wrong code attempt via --code
            bad1 = wrong_code(open_ev["totp_code"])
            rc_w, _, err_w = run_cli(
                ["--json", "init", "--name", "worker-alpha", "--pair", pair_id, "--code", bad1, "--controller", ctl_id],
                agent_home=w_bad_home,
                api_url=api_url,
            )
            assert_true(rc_w != 0, "wrong 2FA code must fail")
            assert_eq(json.loads(err_w)["error"]["code"], "ERR_BAD_PAIR_CODE", err_w)

            # 2) Valid code entered interactively via stdin (tests prompt flow without --code!)
            now_step = int(time.time()) // 30
            live_code = py_totp(secret_b32, now_step)
            rc_w1, out_w1, err_w1 = run_cli(
                ["--json", "init", "--name", "worker-alpha", "--pair", pair_id],
                agent_home=w1_home,
                api_url=api_url,
                stdin_data=live_code + "\n",
            )
            assert_eq(rc_w1, 0, f"worker-1 interactive pairing init failed: {err_w1}")
            w1_info = json.loads(out_w1)
            w1_id = w1_info["agent_id"]
            assert_eq(w1_info["controller_id"], ctl_id)

            rc_ctl, ctl_evs, err_ctl = finish_pair_bg(pair_proc)
            assert_eq(rc_ctl, 0, f"ctl pair failed: {err_ctl}")
            assert_eq(ctl_evs[-1]["event"], "delivered")
            assert_eq(ctl_evs[-1]["cred_id"], w1_info["cred_id"])

            # Verify worker has distinct private key and passes full 1-hop chain verification
            assert_true((Path(w1_home) / "private.pem").read_text() != (Path(ctl_home) / "private.pem").read_text(), "worker must generate its own private key")
            rc_v, out_v, err_v = run_cli(["--json", "verify", w1_id], agent_home=w1_home, api_url=api_url)
            assert_eq(rc_v, 0, f"verify failed: {err_v}")
            vdoc = json.loads(out_v)
            assert_eq(vdoc["chain_valid"], True, out_v)
            assert_eq(vdoc["scopes"], ["dm", "pub", "social"])

            print("[4/6] Test same-step TOTP replay protection...")
            # Wait only if the step JUST rolled over since w1_home paired? No, w1 used live_code in now_step!
            # Open a second session immediately and try reusing the exact same code in the same 30s step.
            used_step = json.loads(Path(ctl_home, "totp.json").read_text())["last_used_step"]
            assert_true(used_step >= now_step, f"last_used_step should be recorded: {used_step}")
            if int(time.time()) // 30 == used_step:
                p2, ev2 = open_pair_bg(ctl_home, api_url, ["--label", "replay-test", "--timeout", "60"])
                pid2 = ev2["pair_id"]
                reused = py_totp(secret_b32, used_step)
                rc_r, _, err_r = run_cli(
                    ["--json", "init", "--name", "replay", "--pair", pid2, "--code", reused],
                    agent_home=w_replay_home,
                    api_url=api_url,
                )
                assert_true(rc_r != 0, "reusing same-step TOTP code must be rejected")
                assert_eq(json.loads(err_r)["error"]["code"], "ERR_BAD_PAIR_CODE", err_r)
                p2.terminate()
                p2.wait(timeout=5)
            else:
                print("  (skipped instant replay check because 30s boundary ticked right between sessions)")

            print("[5/6] Test 3-strike wrong code session burn...")
            p3, ev3 = open_pair_bg(ctl_home, api_url, ["--label", "burn-test", "--no-show-code", "--timeout", "60"])
            assert_true("totp_code" not in ev3, "--no-show-code must omit totp_code from open event")
            pid3 = ev3["pair_id"]
            for attempt in range(1, 4):
                bad_c = wrong_code(py_totp(secret_b32, int(time.time()) // 30))
                rc_b, _, err_b = run_cli(
                    ["--json", "init", "--name", f"bad-{attempt}", "--pair", pid3, "--code", bad_c],
                    agent_home=str(td_p / f"bad_try_{attempt}"),
                    api_url=api_url,
                )
                assert_true(rc_b != 0)
                ecode = json.loads(err_b)["error"]["code"]
                want = "ERR_PAIR_EXHAUSTED" if attempt == 3 else "ERR_BAD_PAIR_CODE"
                assert_eq(ecode, want, f"attempt {attempt}: {err_b}")
            rc_p3, _, err_p3 = finish_pair_bg(p3)
            assert_true(rc_p3 != 0, "burned ctl pair should exit non-zero")
            assert_eq(json.loads(err_p3)["error"]["code"], "ERR_PAIR_EXHAUSTED", err_p3)

            print("[6/6] Test ctl 2fa rm --confirm...")
            rc_rm0, _, err_rm0 = run_cli(["--json", "ctl", "2fa", "rm"], agent_home=ctl_home, api_url=api_url)
            assert_true(rc_rm0 != 0)
            assert_eq(json.loads(err_rm0)["error"]["code"], "ERR_CONFIRM_REQUIRED", err_rm0)

            rc_rm1, out_rm1, err_rm1 = run_cli(["--json", "ctl", "2fa", "rm", "--confirm"], agent_home=ctl_home, api_url=api_url)
            assert_eq(rc_rm1, 0, f"ctl 2fa rm failed: {err_rm1}")
            assert_eq(json.loads(out_rm1)["removed"], True)
            assert_true(not totp_file.exists(), "totp.json should be deleted")

            print("OK: End-to-end Controller TOTP 2FA + Pairing tests passed.")
            return 0
        finally:
            srv.terminate()
            try:
                srv.wait(timeout=5)
            except subprocess.TimeoutExpired:
                srv.kill()
                srv.wait()


if __name__ == "__main__":
    raise SystemExit(main())
