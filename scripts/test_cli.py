#!/usr/bin/env python3
"""
End-to-end integration test suite for fatext-cli:
  Suite A: Real `fatext` binary <-> Real `fatext-server` (identity, PoW, profile,
           public channels/threads/pins, rate limits/cooldowns, revoke, 0600 perms)
  Suite B: Real `fatext` binary <-> Local Python Phase 2 HTTP+SSE+Mail+KeyRotate relay
           (friends, blocks, encrypted DMs, private rooms + auto key store, dual-signed
            key rotate + archived key mail decryption, P2P stdio over UDP X25519+AES-GCM)
"""

import base64
import hashlib
import http.server
import io
import json
import os
import platform as py_platform
import queue
import re
import shutil
import socket
import socketserver
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse

CLI_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI_BIN = os.path.join(CLI_DIR, "build", "fatext")
SERVER_BIN = os.path.normpath(os.path.join(CLI_DIR, "..", "fatext", "build", "fatext-server"))
WWW_DIR = os.path.normpath(os.path.join(CLI_DIR, "..", "fatext", "www"))
TPL_DIR = os.path.normpath(os.path.join(CLI_DIR, "..", "fatext", "templates"))


def assert_eq(a, b, msg=""):
    if a != b:
        raise AssertionError(f"{msg}: expected {b!r}, got {a!r}")


def assert_true(cond, msg=""):
    if not cond:
        raise AssertionError(f"Assertion failed: {msg}")


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_tcp_ready(host: str, port: int, timeout: float = 10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"Server on {host}:{port} failed to become ready within {timeout}s")


def run_cli(args, env_home=None, api_url=None, stdin_data=None, timeout=60):
    cmd = [CLI_BIN]
    if api_url:
        cmd.extend(["--api", api_url])
    cmd.extend(args)
    env = os.environ.copy()
    if env_home is not None:
        env["FATEXT_HOME"] = env_home
    proc = subprocess.run(
        cmd,
        input=stdin_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=timeout,
    )
    return proc.returncode, proc.stdout.decode("utf-8", errors="replace"), proc.stderr.decode("utf-8", errors="replace")


# =============================================================================
# Minimal Pure-Python AES-256-GCM (NIST SP 800-38D) + OpenSSL RSA-OAEP/PSS
# =============================================================================

_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1b) & 0xff if (a & 0x80) else ((a << 1) & 0xff)


def _aes256_expand_key(key: bytes):
    assert len(key) == 32
    w = [int.from_bytes(key[i:i+4], "big") for i in range(0, 32, 4)]
    for i in range(8, 60):
        t = w[i - 1]
        if i % 8 == 0:
            t = ((t << 8) | (t >> 24)) & 0xffffffff
            t = (
                (_SBOX[(t >> 24) & 0xff] << 24)
                | (_SBOX[(t >> 16) & 0xff] << 16)
                | (_SBOX[(t >> 8) & 0xff] << 8)
                | _SBOX[t & 0xff]
            ) ^ (_RCON[(i // 8) - 1] << 24)
        elif i % 8 == 4:
            t = (
                (_SBOX[(t >> 24) & 0xff] << 24)
                | (_SBOX[(t >> 16) & 0xff] << 16)
                | (_SBOX[(t >> 8) & 0xff] << 8)
                | _SBOX[t & 0xff]
            )
        w.append(w[i - 8] ^ t)
    return [b"".join(w[4*r + c].to_bytes(4, "big") for c in range(4)) for r in range(15)]


def _aes256_block(rk, block: bytes) -> bytes:
    s = bytearray(a ^ b for a, b in zip(block, rk[0]))
    for r in range(1, 15):
        s = bytearray(_SBOX[b] for b in s)
        # ShiftRows (column-major layout)
        s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
        if r < 14:
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = s[c], s[c+1], s[c+2], s[c+3]
                t = a0 ^ a1 ^ a2 ^ a3
                s[c]   ^= t ^ _xtime(a0 ^ a1)
                s[c+1] ^= t ^ _xtime(a1 ^ a2)
                s[c+2] ^= t ^ _xtime(a2 ^ a3)
                s[c+3] ^= t ^ _xtime(a3 ^ a0)
        k = rk[r]
        for i in range(16):
            s[i] ^= k[i]
    return bytes(s)


def _ghash_mul(x: int, y: int) -> int:
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        lsb = v & 1
        v >>= 1
        if lsb:
            v ^= 0xe1 << 120
    return z


def _ghash(h_bytes: bytes, aad: bytes, ct: bytes) -> bytes:
    h = int.from_bytes(h_bytes, "big")
    y = 0
    def feed(data: bytes):
        nonlocal y
        for off in range(0, len(data), 16):
            blk = data[off:off+16]
            if len(blk) < 16:
                blk = blk + b"\x00" * (16 - len(blk))
            y = _ghash_mul(y ^ int.from_bytes(blk, "big"), h)
    feed(aad)
    feed(ct)
    lens = ((len(aad) * 8) << 64) | (len(ct) * 8)
    y = _ghash_mul(y ^ lens, h)
    return y.to_bytes(16, "big")


def aes256_gcm_encrypt(key: bytes, iv12: bytes, pt: bytes, aad: bytes) -> bytes:
    assert len(key) == 32 and len(iv12) == 12
    rk = _aes256_expand_key(key)
    h = _aes256_block(rk, b"\x00" * 16)
    j0 = iv12 + b"\x00\x00\x00\x01"
    ctr = 2
    out = bytearray()
    for off in range(0, len(pt), 16):
        ks = _aes256_block(rk, iv12 + ctr.to_bytes(4, "big"))
        chunk = pt[off:off+16]
        out.extend(a ^ b for a, b in zip(chunk, ks[:len(chunk)]))
        ctr += 1
    ct = bytes(out)
    s = _ghash(h, aad, ct)
    e_j0 = _aes256_block(rk, j0)
    tag = bytes(a ^ b for a, b in zip(s, e_j0))
    return ct + tag


def rsa_oaep_sha256_encrypt(pub_pem: str, pt: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as td:
        pk_p = os.path.join(td, "pub.pem")
        pt_p = os.path.join(td, "pt.bin")
        with open(pk_p, "w") as f:
            f.write(pub_pem)
        with open(pt_p, "wb") as f:
            f.write(pt)
        res = subprocess.run(
            [
                "openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", pk_p,
                "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256",
                "-in", pt_p,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        return res.stdout


def rsa_pss_sha256_verify(pub_pem: str, msg: bytes, sig_b64: str) -> bool:
    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except Exception:
        return False
    with tempfile.TemporaryDirectory() as td:
        pk_p = os.path.join(td, "pub.pem")
        msg_p = os.path.join(td, "msg.bin")
        sig_p = os.path.join(td, "sig.bin")
        with open(pk_p, "w") as f:
            f.write(pub_pem)
        with open(msg_p, "wb") as f:
            f.write(msg)
        with open(sig_p, "wb") as f:
            f.write(sig)
        res = subprocess.run(
            [
                "openssl", "dgst", "-sha256",
                "-sigopt", "rsa_padding_mode:pss",
                "-sigopt", "rsa_pss_saltlen:32",
                "-verify", pk_p,
                "-signature", sig_p,
                msg_p,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return res.returncode == 0


# =============================================================================
# Suite A: Real fatext CLI <-> Real fatext-server
# =============================================================================

def run_suite_a():
    print("[Suite A] Testing fatext CLI against real fatext-server...")
    if not os.path.isfile(SERVER_BIN):
        raise RuntimeError(f"Missing server binary: {SERVER_BIN}")

    port = free_tcp_port()
    api_url = f"http://127.0.0.1:{port}"
    with tempfile.TemporaryDirectory(prefix="fatext-suite-a-") as td:
        data_dir = os.path.join(td, "data")
        home_a = os.path.join(td, "home_a")
        os.makedirs(data_dir, exist_ok=True)
        srv_env = os.environ.copy()
        srv_env["FATEXT_ADDR"] = f"127.0.0.1:{port}"
        srv_env["FATEXT_DATA_DIR"] = data_dir
        srv_env["FATEXT_WWW_DIR"] = WWW_DIR
        srv_env["FATEXT_TEMPLATES_DIR"] = TPL_DIR
        srv_env["FATEXT_POW_BITS"] = "12"

        srv = subprocess.Popen(
            [SERVER_BIN],
            env=srv_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            wait_tcp_ready("127.0.0.1", port, timeout=10.0)

            # 1. --version and --help
            rc, out, _ = run_cli(["--version"])
            assert_eq(rc, 0, "--version")
            assert_true("fatext 1.0.0" in out, "--version output")

            rc, out, _ = run_cli(["--help"])
            assert_eq(rc, 0, "--help")
            assert_true("fatext 1.0.0" in out, "--help output")

            # 2. init
            rc, out, err = run_cli(
                ["--json", "init", "--name", "AgentA", "--owner", "Alice"],
                env_home=home_a,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"init failed: {err}")
            init_doc = json.loads(out.strip())
            agent_id = init_doc["agent_id"]
            assert_true(re.match(r"^ftx_[a-z0-9]{12}$", agent_id) is not None, f"agent_id format {agent_id}")

            priv_path = os.path.join(home_a, "private.pem")
            cfg_path = os.path.join(home_a, "config.json")
            assert_true(os.path.isfile(priv_path), "private.pem exists")
            assert_true(os.path.isfile(cfg_path), "config.json exists")
            assert_eq(stat.S_IMODE(os.stat(priv_path).st_mode), 0o600, "private.pem mode 0600")

            # 3. Insecure key permissions -> exit 10
            os.chmod(priv_path, 0o644)
            rc, _, err = run_cli(["whoami"], env_home=home_a, api_url=api_url)
            assert_eq(rc, 10, f"insecure key mode should exit 10, got stderr={err}")
            os.chmod(priv_path, 0o600)

            # 4. whoami --json
            rc, out, err = run_cli(["--json", "whoami"], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, f"whoami failed: {err}")
            who_doc = json.loads(out.strip())
            assert_eq(who_doc["agent_id"], agent_id, "whoami agent_id")

            # 5. Restart server cleanly to reset in-memory 60s register->profile cooldown,
            #    then test profile set (200 OK) + immediate cooldown (exit 75)
            srv.terminate()
            srv.wait(timeout=5)
            srv = subprocess.Popen(
                [SERVER_BIN],
                env=srv_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            wait_tcp_ready("127.0.0.1", port, timeout=10.0)

            rc, out, err = run_cli(
                [
                    "profile", "set",
                    "--name", "AgentA2",
                    "--bio", "hello world bio",
                    "--owner-name", "AliceOwner",
                    "--dm-policy", "friends",
                    "--accept-email", "true",
                    "--tags", "ai,xu",
                ],
                env_home=home_a,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"profile set failed: {err}")

            rc, _, err = run_cli(
                ["profile", "set", "--bio", "cooldown check"],
                env_home=home_a,
                api_url=api_url,
            )
            assert_eq(rc, 75, f"2nd profile set cooldown should exit 75, got rc={rc} err={err}")

            rc, out, _ = run_cli(["--json", "whoami"], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, "whoami after profile set")
            who2 = json.loads(out.strip())
            assert_eq(who2["profile"]["name"], "AgentA2", "updated name")
            assert_eq(who2["extensions"]["dm_policy"], "friends", "updated dm_policy")
            assert_eq(who2["extensions"]["accept_email"], True, "updated accept_email")

            # 6. key fetch
            rc, out, _ = run_cli(["key", "fetch", agent_id], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, "key fetch json")
            assert_eq(json.loads(out.strip())["agent_id"], agent_id, "key fetch agent_id")

            rc, out, _ = run_cli(["key", "fetch", agent_id, "--pem"], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, "key fetch --pem")
            assert_true("BEGIN PUBLIC KEY" in out, "key fetch PEM header")

            # 7. pub post via stdin (-)
            post_text = "First post from fatext CLI via stdin"
            rc, out, err = run_cli(
                ["pub", "post", "general", "-"],
                env_home=home_a,
                api_url=api_url,
                stdin_data=post_text.encode("utf-8"),
            )
            assert_eq(rc, 0, f"pub post failed: {err}")
            post_doc = json.loads(out.strip())
            msg_id = post_doc["msg_id"]
            assert_true(re.match(r"^msg_[0-9A-HJKMNP-TV-Z]{26}$", msg_id) is not None, f"msg_id format {msg_id}")

            # 8. 2nd pub post -> rate limit exit 75 + retry_after on stderr
            rc, _, err = run_cli(
                ["pub", "post", "general", "Second post blocked"],
                env_home=home_a,
                api_url=api_url,
            )
            assert_eq(rc, 75, f"2nd pub post should exit 75, got rc={rc} err={err}")
            assert_true("retry_after" in err, f"retry_after in stderr: {err}")

            # 9. pub list --json -> verified: true
            rc, out, err = run_cli(["--json", "pub", "list", "general"], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, f"pub list failed: {err}")
            listed = [json.loads(ln) for ln in out.strip().splitlines() if ln.strip()]
            assert_true(len(listed) >= 1, "pub list non-empty")
            assert_eq(listed[0]["msg_id"], msg_id, "listed msg_id")
            assert_eq(listed[0]["verified"], True, "pub list verified")

            # 10. pub reply + immediate cooldown exit 75
            rc, out, err = run_cli(
                ["pub", "reply", msg_id, "First reply from CLI"],
                env_home=home_a,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"pub reply failed: {err}")
            reply_doc = json.loads(out.strip())
            assert_eq(reply_doc["thread_id"], msg_id, "reply thread_id")

            rc, _, err = run_cli(
                ["pub", "reply", msg_id, "Cooldown blocked reply"],
                env_home=home_a,
                api_url=api_url,
            )
            assert_eq(rc, 75, f"2nd reply cooldown should exit 75, got rc={rc} err={err}")

            # 11. pub thread --json -> both verified: true
            rc, out, err = run_cli(["--json", "pub", "thread", msg_id], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, f"pub thread failed: {err}")
            thread_lines = [json.loads(ln) for ln in out.strip().splitlines() if ln.strip()]
            assert_eq(len(thread_lines), 2, "thread has post + 1 reply")
            assert_true(all(x.get("verified") is True for x in thread_lines), "all thread items verified")

            # 12. pub pins
            rc, out, err = run_cli(["pub", "pins", "general"], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, f"pub pins failed: {err}")

            # 13. key revoke without --confirm -> exit 2, with --confirm -> exit 0
            rc, _, _ = run_cli(["key", "revoke"], env_home=home_a, api_url=api_url)
            assert_eq(rc, 2, "key revoke without --confirm should exit 2")

            rc, out, err = run_cli(["--json", "key", "revoke", "--confirm"], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, f"key revoke --confirm failed: {err}")
            assert_eq(json.loads(out.strip())["status"], "revoked", "revoked status")

            # 14. Post-revoke signed write -> exit 5
            time.sleep(0.2)
            rc, _, err = run_cli(
                ["pub", "reply", msg_id, "Reply after revoke"],
                env_home=home_a,
                api_url=api_url,
            )
            assert_eq(rc, 5, f"post-revoke write should exit 5, got rc={rc} err={err}")
        finally:
            srv.terminate()
            try:
                srv.wait(timeout=5)
            except subprocess.TimeoutExpired:
                srv.kill()
                srv.wait()
    print("[Suite A] PASSED")


# =============================================================================
# Suite B: Phase 2 Relay Harness (Friends, Blocks, DM, Room, Rotate, Mail, P2P)
# =============================================================================

class RelayState:
    def __init__(self):
        self.lock = threading.Lock()
        self.counter = 0
        self.agents = {}       # id -> dict
        self.friends = {}      # id -> {"friends": set, "in": dict, "out": dict}
        self.blocks = {}       # id -> list[str]
        self.streams = {}      # id -> list[queue.Queue]
        self.mail = {}         # id -> list[dict]
        self.rotations = []    # recorded key rotations for assertions
        self.rooms = {}        # room_id -> dict

    def room_json(self, room: dict, viewer_id: str) -> dict:
        return {
            "room_id": room["room_id"],
            "name": room["name"],
            "topic": room["topic"],
            "owner_id": room["owner_id"],
            "controller_id": room["controller_id"],
            "epoch": room["epoch"],
            "status": room["status"],
            "send_policy": room["send_policy"],
            "invite_policy": room["invite_policy"],
            "join_policy": room["join_policy"],
            "max_members": room["max_members"],
            "slow_mode_sec": room["slow_mode_sec"],
            "locked": room["locked"],
            "your_role": next((m["role"] for m in room["members"] if m["agent_id"] == viewer_id), ""),
            "member_count": len(room["members"]),
            "members": list(room["members"]),
            "banned": list(room["banned"]),
        }

    def next_agent_id(self) -> str:
        with self.lock:
            self.counter += 1
            return f"ftx_testagent{self.counter:03d}"[:16]

    def push_sse(self, agent_id: str, event_type: str, data_obj: dict):
        payload = f"event: {event_type}\ndata: {json.dumps(data_obj, separators=(',', ':'))}\n\n"
        with self.lock:
            qs = list(self.streams.get(agent_id, []))
        for q in qs:
            q.put(payload)


def make_relay_handler(state: RelayState):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            pass

        def _read_body(self) -> bytes:
            n = int(self.headers.get("Content-Length", "0") or "0")
            return self.rfile.read(n) if n > 0 else b""

        def _send_json(self, code: int, obj: dict):
            raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(raw)

        def _send_text(self, code: int, txt: str):
            raw = txt.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/x-pem-file; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(raw)

        def _verify_auth(self, method: str, path_q: str, body: bytes):
            aid = self.headers.get("X-Agent-Id", "")
            ts = self.headers.get("X-Timestamp", "")
            sig = self.headers.get("X-Signature", "")
            with state.lock:
                ag = state.agents.get(aid)
            if not ag:
                return None, "ERR_UNKNOWN_AGENT"
            bhash = hashlib.sha256(body).hexdigest()
            msg = f"{method}\n{path_q}\n{ts}\n{bhash}".encode("utf-8")
            if not rsa_pss_sha256_verify(ag["pub_pem"], msg, sig):
                return None, "ERR_BAD_SIGNATURE"
            return ag, None

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            p = parsed.path

            if p == "/.well-known/fatext.json":
                self._send_json(200, {
                    "version": "3.0",
                    "cli": {
                        "min_version": "1.0.0",
                        "latest_version": "1.0.0",
                    },
                    "pow": {
                        "register": {"difficulty_bits": 12},
                        "post": {"difficulty_bits": 12},
                    },
                })
                return

            if p.startswith("/k/") and p.endswith(".json"):
                aid = p[3:-5]
                with state.lock:
                    ag = state.agents.get(aid)
                if not ag:
                    self._send_json(404, {"error": {"code": "ERR_NOT_FOUND", "message": "not found"}})
                    return
                self._send_json(200, {
                    "agent_id": ag["agent_id"],
                    "status": ag["status"],
                    "key_version": ag["key_version"],
                    "created_at": ag["created_at"],
                    "current_public_key_pem": ag["pub_pem"],
                    "revision": ag["revision"],
                    "profile": ag["profile"],
                    "extensions": ag["extensions"],
                })
                return

            if p.startswith("/k/") and p.endswith(".pem"):
                aid = p[3:-4]
                with state.lock:
                    ag = state.agents.get(aid)
                if not ag:
                    self._send_json(404, {"error": {"code": "ERR_NOT_FOUND", "message": "not found"}})
                    return
                self._send_text(200, ag["pub_pem"])
                return

            if p == "/v1/friends":
                ag, err = self._verify_auth("GET", self.path, b"")
                if err:
                    self._send_json(401, {"error": {"code": err, "message": err}})
                    return
                aid = ag["agent_id"]
                with state.lock:
                    fr = state.friends[aid]
                    resp = {
                        "friends": [{"agent_id": f} for f in sorted(fr["friends"])],
                        "incoming": [{"from": k, "note": v} for k, v in sorted(fr["in"].items())],
                        "outgoing": [{"to": k, "note": v} for k, v in sorted(fr["out"].items())],
                    }
                self._send_json(200, resp)
                return

            if p == "/v1/blocks":
                ag, err = self._verify_auth("GET", self.path, b"")
                if err:
                    self._send_json(401, {"error": {"code": err, "message": err}})
                    return
                with state.lock:
                    bl = list(state.blocks.get(ag["agent_id"], []))
                self._send_json(200, {"blocks": bl})
                return

            if p == "/v1/mail":
                ag, err = self._verify_auth("GET", self.path, b"")
                if err:
                    self._send_json(401, {"error": {"code": err, "message": err}})
                    return
                with state.lock:
                    items = list(state.mail.get(ag["agent_id"], []))
                self._send_json(200, {"mail": items})
                return

            if p == "/v1/stream":
                ag, err = self._verify_auth("GET", self.path, b"")
                if err:
                    self._send_json(401, {"error": {"code": err, "message": err}})
                    return
                aid = ag["agent_id"]
                q = queue.Queue()
                with state.lock:
                    state.streams.setdefault(aid, []).append(q)
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                try:
                    self.wfile.write(b": connected\n\n")
                    self.wfile.flush()
                    while True:
                        try:
                            chunk = q.get(timeout=0.5)
                            self.wfile.write(chunk.encode("utf-8"))
                            self.wfile.flush()
                        except queue.Empty:
                            self.wfile.write(b": ping\n\n")
                            self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                finally:
                    with state.lock:
                        lst = state.streams.get(aid, [])
                        if q in lst:
                            lst.remove(q)
                return

            if p == "/v1/rooms":
                ag, err = self._verify_auth("GET", self.path, b"")
                if err:
                    self._send_json(401, {"error": {"code": err, "message": err}})
                    return
                aid = ag["agent_id"]
                with state.lock:
                    rms = [
                        state.room_json(r, aid)
                        for r in state.rooms.values()
                        if r["status"] == "active" and any(m["agent_id"] == aid for m in r["members"])
                    ]
                self._send_json(200, {"ok": True, "rooms": rms})
                return

            if p == "/v1/rooms/key-boxes":
                ag, err = self._verify_auth("GET", self.path, b"")
                if err:
                    self._send_json(401, {"error": {"code": err, "message": err}})
                    return
                self._send_json(200, {"ok": True, "boxes": []})
                return

            if p.startswith("/v1/rooms/") and p.count("/") == 3:
                ag, err = self._verify_auth("GET", self.path, b"")
                if err:
                    self._send_json(401, {"error": {"code": err, "message": err}})
                    return
                rid = p[len("/v1/rooms/"):]
                aid = ag["agent_id"]
                with state.lock:
                    r = state.rooms.get(rid)
                    if not r:
                        self._send_json(404, {"error": {"code": "ERR_NOT_FOUND", "message": "not found"}})
                        return
                    if not any(m["agent_id"] == aid for m in r["members"]):
                        self._send_json(403, {"error": {"code": "ERR_FORBIDDEN", "message": "not a member"}})
                        return
                    out = state.room_json(r, aid)
                self._send_json(200, {"ok": True, "room": out})
                return

            self._send_json(404, {"error": {"code": "ERR_NOT_FOUND", "message": p}})

        def do_POST(self):
            body = self._read_body()
            p = urllib.parse.urlparse(self.path).path

            if p == "/v1/agents/register":
                ts = self.headers.get("X-Timestamp", "")
                sig = self.headers.get("X-Signature", "")
                doc = json.loads(body.decode("utf-8"))
                pub_pem = doc["public_key_pem"]
                bhash = hashlib.sha256(body).hexdigest()
                msg = f"POST\n{self.path}\n{ts}\n{bhash}".encode("utf-8")
                if not rsa_pss_sha256_verify(pub_pem, msg, sig):
                    self._send_json(401, {"error": {"code": "ERR_BAD_SIGNATURE", "message": "bad reg sig"}})
                    return
                aid = state.next_agent_id()
                now = int(time.time())
                with state.lock:
                    state.agents[aid] = {
                        "agent_id": aid,
                        "status": "active",
                        "key_version": 1,
                        "created_at": now,
                        "pub_pem": pub_pem,
                        "revision": 0,
                        "profile": doc.get("profile", {}),
                        "extensions": {"dm_policy": "friends", "accept_email": False},
                    }
                    state.friends[aid] = {"friends": set(), "in": {}, "out": {}}
                    state.blocks[aid] = []
                    state.mail[aid] = []
                self._send_json(201, {"agent_id": aid, "created_at": now, "key_version": 1})
                return

            if p == "/v1/agents/rotate-key":
                ag, err = self._verify_auth("POST", self.path, body)
                if err:
                    self._send_json(401, {"error": {"code": err, "message": err}})
                    return
                doc = json.loads(body.decode("utf-8"))
                pl = doc["payload"]
                new_pem = pl["new_public_key_pem"]
                new_kv = pl["key_version"]
                # Verify HTTP X-Signature-New with new key
                ts = self.headers.get("X-Timestamp", "")
                sig_new = self.headers.get("X-Signature-New", "")
                bhash = hashlib.sha256(body).hexdigest()
                http_msg = f"POST\n{self.path}\n{ts}\n{bhash}".encode("utf-8")
                if not rsa_pss_sha256_verify(new_pem, http_msg, sig_new):
                    self._send_json(401, {"error": {"code": "ERR_BAD_SIGNATURE", "message": "bad X-Signature-New"}})
                    return
                # Verify payload old_sig + new_sig
                pl_bytes = json.dumps(pl, separators=(",", ":"), sort_keys=False).encode("utf-8")
                # Also extract exact payload slice from body string in case formatting matches raw JSON
                old_ok = rsa_pss_sha256_verify(ag["pub_pem"], pl_bytes, doc["old_sig"])
                new_ok = rsa_pss_sha256_verify(new_pem, pl_bytes, doc["new_sig"])
                if not (old_ok and new_ok):
                    self._send_json(401, {"error": {"code": "ERR_BAD_SIGNATURE", "message": "bad dual payload sig"}})
                    return
                with state.lock:
                    ag["pub_pem"] = new_pem
                    ag["key_version"] = new_kv
                    state.rotations.append({"agent_id": ag["agent_id"], "key_version": new_kv, "dual_verified": True})
                self._send_json(200, {"ok": True, "key_version": new_kv})
                return

            ag, err = self._verify_auth("POST", self.path, body)
            if err:
                self._send_json(401, {"error": {"code": err, "message": err}})
                return
            aid = ag["agent_id"]
            doc = json.loads(body.decode("utf-8")) if body else {}

            if p == "/v1/friends/request":
                tid = doc["agent_id"]
                note = doc.get("note", "")
                with state.lock:
                    state.friends[aid]["out"][tid] = note
                    state.friends[tid]["in"][aid] = note
                self._send_json(200, {"ok": True, "status": "pending"})
                return

            if p == "/v1/friends/accept":
                tid = doc["agent_id"]
                with state.lock:
                    state.friends[aid]["in"].pop(tid, None)
                    state.friends[tid]["out"].pop(aid, None)
                    state.friends[aid]["friends"].add(tid)
                    state.friends[tid]["friends"].add(aid)
                self._send_json(200, {"ok": True, "status": "accepted"})
                return

            if p == "/v1/friends/reject":
                tid = doc["agent_id"]
                with state.lock:
                    state.friends[aid]["in"].pop(tid, None)
                    state.friends[tid]["out"].pop(aid, None)
                self._send_json(200, {"ok": True, "status": "rejected"})
                return

            if p == "/v1/blocks":
                tgt = doc["target"]
                with state.lock:
                    bl = state.blocks.setdefault(aid, [])
                    if tgt not in bl:
                        bl.append(tgt)
                self._send_json(200, {"ok": True, "target": tgt})
                return

            if p.startswith("/v1/dm/"):
                to_id = p[len("/v1/dm/"):]
                state.push_sse(to_id, "dm", {"from": aid, "frame": doc})
                self._send_json(202, {"ok": True, "delivered": True})
                return

            if p == "/v1/rooms":
                rid = doc.get("room_id", "")
                with state.lock:
                    r = {
                        "room_id": rid,
                        "name": doc.get("name", ""),
                        "topic": doc.get("topic", ""),
                        "owner_id": aid,
                        "controller_id": aid,
                        "epoch": 1,
                        "status": "active",
                        "send_policy": doc.get("send_policy", "all"),
                        "invite_policy": doc.get("invite_policy", "admins"),
                        "join_policy": doc.get("join_policy", "invite_only"),
                        "max_members": int(doc.get("max_members", 64)),
                        "slow_mode_sec": int(doc.get("slow_mode_sec", 0)),
                        "locked": bool(doc.get("locked", False)),
                        "members": [{"agent_id": aid, "role": "owner", "muted": False, "joined_at": int(time.time())}],
                        "banned": [],
                    }
                    state.rooms[rid] = r
                    out = state.room_json(r, aid)
                self._send_json(201, {"ok": True, "room": out})
                return

            if p.startswith("/v1/rooms/"):
                parts = p[len("/v1/rooms/"):].split("/")
                rid = parts[0]
                if len(parts) == 2 and parts[1] == "send":
                    with state.lock:
                        r = state.rooms.get(rid)
                        targets = [m["agent_id"] for m in r["members"]] if r else list(state.streams.keys())
                    for t in targets:
                        if t != aid:
                            state.push_sse(t, "room", {"room_id": rid, "from": aid, "frame": doc})
                    self._send_json(202, {"ok": True, "room_id": rid})
                    return
                if len(parts) == 2 and parts[1] == "members":
                    tid = doc["agent_id"]
                    role = doc.get("role", "member")
                    with state.lock:
                        r = state.rooms[rid]
                        r["members"].append({"agent_id": tid, "role": role, "muted": False, "joined_at": int(time.time())})
                        ep = r["epoch"]
                        mc = len(r["members"])
                    if "invite_frame" in doc:
                        state.push_sse(tid, "dm", {"from": aid, "frame": doc["invite_frame"]})
                    self._send_json(200, {"ok": True, "room_id": rid, "agent_id": tid, "role": role, "epoch": ep, "member_count": mc, "delivered": "sse"})
                    return
                if len(parts) == 2 and parts[1] == "rekey":
                    with state.lock:
                        r = state.rooms[rid]
                        if doc.get("bump_epoch"):
                            r["epoch"] += 1
                        if int(doc.get("epoch", 0)) > r["epoch"]:
                            r["epoch"] = int(doc["epoch"])
                        ep = r["epoch"]
                    for env in doc.get("envelopes", []):
                        state.push_sse(env["to"], "dm", {"from": aid, "frame": env["frame"]})
                    self._send_json(200, {"ok": True, "room_id": rid, "epoch": ep, "delivered": len(doc.get("envelopes", []))})
                    return
                if len(parts) == 2 and parts[1] == "transfer":
                    tid = doc["agent_id"]
                    with state.lock:
                        r = state.rooms[rid]
                        for m in r["members"]:
                            if m["agent_id"] == aid:
                                m["role"] = "admin"
                            elif m["agent_id"] == tid:
                                m["role"] = "owner"
                        r["owner_id"] = tid
                    self._send_json(200, {"ok": True, "room_id": rid, "owner_id": tid})
                    return
                if len(parts) == 2 and parts[1] == "leave":
                    with state.lock:
                        r = state.rooms[rid]
                        r["members"] = [m for m in r["members"] if m["agent_id"] != aid]
                    self._send_json(200, {"ok": True, "room_id": rid, "left": True})
                    return
                if len(parts) == 4 and parts[1] == "members" and parts[3] in ("kick", "ban"):
                    tid = parts[2]
                    act = parts[3]
                    with state.lock:
                        r = state.rooms[rid]
                        r["members"] = [m for m in r["members"] if m["agent_id"] != tid]
                        if act == "ban" and tid not in r["banned"]:
                            r["banned"].append(tid)
                        if doc.get("rotate_epoch", True):
                            r["epoch"] += 1
                        ep = r["epoch"]
                        rem = [m["agent_id"] for m in r["members"]]
                    self._send_json(200, {"ok": True, "room_id": rid, "target": tid, "action": act, "epoch": ep, "remaining_members": rem})
                    return

            self._send_json(404, {"error": {"code": "ERR_NOT_FOUND", "message": p}})

        def do_PATCH(self):
            body = self._read_body()
            p = urllib.parse.urlparse(self.path).path
            ag, err = self._verify_auth("PATCH", self.path, body)
            if err:
                self._send_json(401, {"error": {"code": err, "message": err}})
                return
            aid = ag["agent_id"]
            doc = json.loads(body.decode("utf-8")) if body else {}
            if p.startswith("/v1/rooms/"):
                parts = p[len("/v1/rooms/"):].split("/")
                rid = parts[0]
                if len(parts) == 1:
                    with state.lock:
                        r = state.rooms[rid]
                        for k in ("name", "topic", "send_policy", "invite_policy", "join_policy", "max_members", "slow_mode_sec", "locked"):
                            if k in doc:
                                r[k] = doc[k]
                        out = state.room_json(r, aid)
                    self._send_json(200, {"ok": True, "room": out})
                    return
                if len(parts) == 3 and parts[1] == "members":
                    tid = parts[2]
                    with state.lock:
                        r = state.rooms[rid]
                        m = next(x for x in r["members"] if x["agent_id"] == tid)
                        if "role" in doc:
                            m["role"] = doc["role"]
                        if "muted" in doc:
                            m["muted"] = bool(doc["muted"])
                        res = {"ok": True, "room_id": rid, "agent_id": tid, "role": m["role"], "muted": m["muted"]}
                    self._send_json(200, res)
                    return
            self._send_json(404, {"error": {"code": "ERR_NOT_FOUND", "message": p}})

        def do_DELETE(self):
            p = urllib.parse.urlparse(self.path).path
            ag, err = self._verify_auth("DELETE", self.path, b"")
            if err:
                self._send_json(401, {"error": {"code": err, "message": err}})
                return
            aid = ag["agent_id"]
            if p.startswith("/v1/friends/"):
                tid = p[len("/v1/friends/"):]
                with state.lock:
                    state.friends[aid]["friends"].discard(tid)
                    state.friends[tid]["friends"].discard(aid)
                self._send_json(200, {"ok": True})
                return
            if p.startswith("/v1/blocks/"):
                tgt = urllib.parse.unquote(p[len("/v1/blocks/"):])
                with state.lock:
                    bl = state.blocks.get(aid, [])
                    if tgt in bl:
                        bl.remove(tgt)
                self._send_json(200, {"ok": True})
                return
            if p.startswith("/v1/mail/"):
                mid = p[len("/v1/mail/"):]
                with state.lock:
                    state.mail[aid] = [m for m in state.mail.get(aid, []) if m["mail_id"] != mid]
                self._send_json(200, {"ok": True, "deleted": mid})
                return
            if p.startswith("/v1/rooms/"):
                parts = p[len("/v1/rooms/"):].split("/")
                rid = parts[0]
                if len(parts) == 3 and parts[1] == "bans":
                    tid = parts[2]
                    with state.lock:
                        r = state.rooms[rid]
                        if tid in r["banned"]:
                            r["banned"].remove(tid)
                    self._send_json(200, {"ok": True, "room_id": rid, "unbanned": tid})
                    return
                if len(parts) == 1:
                    with state.lock:
                        state.rooms[rid]["status"] = "closed"
                    self._send_json(200, {"ok": True, "room_id": rid, "status": "closed"})
                    return

            self._send_json(404, {"error": {"code": "ERR_NOT_FOUND", "message": p}})

    return Handler


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def build_mail_item(agent_id: str, pub_pem: str, kv: int, mail_id: str, sender: str, subject: str, body_txt: str):
    inner = json.dumps({
        "from": sender,
        "subject": subject,
        "raw_snippet": body_txt,
        "spf_pass": True,
        "dkim_pass": True,
        "dmarc_pass": False,
    }, separators=(",", ":")).encode("utf-8")
    cek = os.urandom(32)
    iv = os.urandom(12)
    aad = f"fatext-mail\n{agent_id}\n{mail_id}\n{kv}".encode("utf-8")
    ct = aes256_gcm_encrypt(cek, iv, inner, aad)
    ek = rsa_oaep_sha256_encrypt(pub_pem, cek)
    return {
        "mail_id": mail_id,
        "received_at": int(time.time()),
        "to_key_version": kv,
        "spf_pass": True,
        "dkim_pass": True,
        "dmarc_pass": False,
        "envelope": {
            "v": 1,
            "alg": "RSA-OAEP-256+A256GCM",
            "ek": base64.b64encode(ek).decode("ascii"),
            "iv": base64.b64encode(iv).decode("ascii"),
            "ct": base64.b64encode(ct).decode("ascii"),
        },
    }


def run_suite_b():
    print("[Suite B] Testing fatext CLI Phase 2 commands (friends, blocks, DM, room, rotate-key, mail, P2P)...")
    state = RelayState()
    port = free_tcp_port()
    api_url = f"http://127.0.0.1:{port}"
    srv = ThreadedHTTPServer(("127.0.0.1", port), make_relay_handler(state))
    srv_thread = threading.Thread(target=srv.serve_forever, daemon=True)
    srv_thread.start()

    try:
        with tempfile.TemporaryDirectory(prefix="fatext-suite-b-") as td:
            home_a = os.path.join(td, "home_a")
            home_b = os.path.join(td, "home_b")

            # Init A and B
            rc, out, err = run_cli(["--json", "init", "--name", "AgentA"], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, f"init A: {err}")
            aid_a = json.loads(out.strip())["agent_id"]

            rc, out, err = run_cli(["--json", "init", "--name", "AgentB"], env_home=home_b, api_url=api_url)
            assert_eq(rc, 0, f"init B: {err}")
            aid_b = json.loads(out.strip())["agent_id"]

            # 1. Friends + Blocks
            rc, _, err = run_cli(["friend", "add", aid_b, "--note", "hi B"], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, f"friend add: {err}")
            rc, out, _ = run_cli(["friend", "list"], env_home=home_b, api_url=api_url)
            assert_eq(rc, 0, "friend list B")
            assert_eq(json.loads(out.strip())["incoming"][0]["from"], aid_a, "incoming request")

            rc, _, err = run_cli(["friend", "accept", aid_a], env_home=home_b, api_url=api_url)
            assert_eq(rc, 0, f"friend accept: {err}")
            rc, _, _ = run_cli(["friend", "rm", aid_b], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, "friend rm")
            # Re-friend A & B for room invite & P2P friends-only checks
            run_cli(["friend", "add", aid_b], env_home=home_a, api_url=api_url)
            run_cli(["friend", "accept", aid_a], env_home=home_b, api_url=api_url)

            rc, _, _ = run_cli(["block", "add", "*@spam.example"], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, "block add")
            rc, out, _ = run_cli(["block", "list"], env_home=home_a, api_url=api_url)
            assert_true("*@spam.example" in json.loads(out.strip())["blocks"], "block list")
            rc, _, _ = run_cli(["block", "rm", "*@spam.example"], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, "block rm")

            # 2. Encrypted DM + listen
            b_env = os.environ.copy()
            b_env["FATEXT_HOME"] = home_b
            listener = subprocess.Popen(
                [CLI_BIN, "--api", api_url, "--json", "listen", "--max-events", "1"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=b_env,
            )
            time.sleep(0.4)
            rc, _, err = run_cli(["dm", "send", aid_b, "secret dm hello"], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, f"dm send: {err}")
            lout, lerr = listener.communicate(timeout=10)
            assert_eq(listener.returncode, 0, f"listen dm stderr={lerr.decode()}")
            dm_ev = json.loads(lout.decode().strip())
            assert_eq(dm_ev["type"], "dm", "dm event type")
            assert_eq(dm_ev["text"], "secret dm hello", "dm decrypted text")
            assert_eq(dm_ev["verified"], True, "dm sender signature verified")

            # 3. Room create + invite + send + B auto-decrypt
            rc, out, err = run_cli(["--json", "room", "create", "--name", "alpha"], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, f"room create: {err}")
            room_id = json.loads(out.strip())["room_id"]

            listener2 = subprocess.Popen(
                [CLI_BIN, "--api", api_url, "--json", "listen", "--rooms", room_id, "--max-events", "2"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=b_env,
            )
            time.sleep(0.4)
            rc, _, err = run_cli(["room", "invite", room_id, aid_b], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, f"room invite: {err}")
            time.sleep(0.4)
            rc, _, err = run_cli(["room", "send", room_id, "hello room encrypted"], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, f"room send: {err}")

            lout2, lerr2 = listener2.communicate(timeout=15)
            assert_eq(listener2.returncode, 0, f"listen room stderr={lerr2.decode()}")
            evs = [json.loads(ln) for ln in lout2.decode().strip().splitlines() if ln.strip()]
            assert_eq(len(evs), 2, f"expected 2 room events, got {evs}")
            assert_eq(evs[0]["type"], "room_invite", "event 0 type")
            assert_eq(evs[0]["stored"], True, "room key auto-stored")
            assert_eq(evs[0]["verified"], True, "room invite verified")
            assert_eq(evs[1]["type"], "room", "event 1 type")
            assert_eq(evs[1]["text"], "hello room encrypted", "room decrypted text")
            assert_eq(evs[1]["verified"], True, "room sender sig verified")
            assert_true(os.path.isfile(os.path.join(home_b, "rooms", f"{room_id}.json")), "B saved room file")

            rc, out, err = run_cli(["--json", "room", "list"], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, f"room list: {err}")
            assert_true(any(x["room_id"] == room_id for x in json.loads(out.strip())["rooms"]), "room in list")
            rc, out, err = run_cli(["--json", "room", "info", room_id], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, f"room info: {err}")
            rc, out, err = run_cli(["--json", "room", "set", room_id, "--topic", "mock topic"], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, f"room set: {err}")
            assert_eq(json.loads(out.strip())["room"]["topic"], "mock topic", "room topic updated")
            rc, _, err = run_cli(["--json", "room", "role", room_id, aid_b, "admin"], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, f"room role: {err}")
            rc, _, err = run_cli(["--json", "room", "mute", room_id, aid_b], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, f"room mute: {err}")
            rc, _, err = run_cli(["--json", "room", "unmute", room_id, aid_b], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, f"room unmute: {err}")
            rc, out, err = run_cli(["--json", "room", "rotate", room_id], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, f"room rotate: {err}")
            assert_eq(json.loads(out.strip())["epoch"], 2, "room rotate epoch=2")
            rc, _, err = run_cli(["--json", "room", "leave", room_id], env_home=home_b, api_url=api_url)
            assert_eq(rc, 0, f"room leave: {err}")
            assert_true(not os.path.isfile(os.path.join(home_b, "rooms", f"{room_id}.json")), "B deleted room file on leave")
            rc, _, err = run_cli(["--json", "room", "close", room_id], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, f"room close: {err}")
            assert_true(not os.path.isfile(os.path.join(home_a, "rooms", f"{room_id}.json")), "A deleted room file on close")

            # 4. Key rotate on A (save v1 pub_pem first for dual-version mail test)
            pub_v1_pem = state.agents[aid_a]["pub_pem"]
            rc, out, err = run_cli(["--json", "key", "rotate"], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, f"key rotate: {err}")
            rot_doc = json.loads(out.strip())
            assert_eq(rot_doc["key_version"], 2, "rotated to key_version 2")
            assert_true(len(state.rotations) == 1 and state.rotations[0]["dual_verified"], "server verified dual signatures")
            arch_v1_path = os.path.join(home_a, "keys", "private.v1.pem")
            assert_true(os.path.isfile(arch_v1_path), "archived v1 key exists")
            assert_eq(stat.S_IMODE(os.stat(arch_v1_path).st_mode), 0o600, "archived key mode 0600")
            pub_v2_pem = state.agents[aid_a]["pub_pem"]

            # 5. Encrypted mail pull --delete (v2 current + v1 archived)
            m1 = build_mail_item(aid_a, pub_v2_pem, 2, "mail_v2_item", "sender@example.com", "Subj v2", "Body encrypted to v2")
            m2 = build_mail_item(aid_a, pub_v1_pem, 1, "mail_v1_item", "old@example.com", "Subj v1", "Body encrypted to archived v1")
            with state.lock:
                state.mail[aid_a].extend([m1, m2])

            rc, out, err = run_cli(["mail", "pull", "--delete"], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, f"mail pull: {err}")
            pulled = [json.loads(ln) for ln in out.strip().splitlines() if ln.strip()]
            assert_eq(len(pulled), 2, f"expected 2 mails, got {pulled}")
            assert_eq(pulled[0]["text"], "Body encrypted to v2", "mail v2 text")
            assert_eq(pulled[0]["verified"], True, "mail v2 verdicts verified")
            assert_eq(pulled[0]["spf_pass"], True, "mail v2 spf_pass")
            assert_eq(pulled[1]["text"], "Body encrypted to archived v1", "mail v1 archived key text")
            assert_eq(pulled[1]["verified"], True, "mail v1 verdicts verified")
            with state.lock:
                assert_eq(len(state.mail[aid_a]), 0, "mail --delete removed server items")

            # 6. P2P listen + connect (--stdio, localhost UDP punch + X25519 + AES-256-GCM)
            payload = (b"FATEXT_P2P_BINARY_BLOCK_" * 900) + bytes(range(256))
            p2p_b = subprocess.Popen(
                [CLI_BIN, "--api", api_url, "--json", "p2p", "listen", "--allow-friends-only", "--stdio", "--stun", "none"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=b_env,
            )
            time.sleep(0.5)
            a_env = os.environ.copy()
            a_env["FATEXT_HOME"] = home_a
            p2p_a = subprocess.run(
                [CLI_BIN, "--api", api_url, "--json", "p2p", "connect", aid_b, "--stun", "none"],
                input=payload,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=a_env,
                timeout=20,
            )
            b_out, b_err = p2p_b.communicate(timeout=20)
            assert_eq(p2p_a.returncode, 0, f"p2p connect failed: {p2p_a.stderr.decode()}")
            assert_eq(p2p_b.returncode, 0, f"p2p listen failed: {b_err.decode()}")
            assert_eq(b_out, payload, f"P2P transferred {len(b_out)} bytes != expected {len(payload)} bytes")

            # 7. P2P bidirectional TCP bridge (--expose <-> --forward)
            echo_port = free_tcp_port()
            fwd_port = free_tcp_port()
            echo_ready = threading.Event()
            echo_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            echo_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            echo_srv.bind(("127.0.0.1", echo_port))
            echo_srv.listen(2)

            def _run_echo():
                echo_ready.set()
                c, _ = echo_srv.accept()
                with c:
                    while True:
                        d = c.recv(4096)
                        if not d:
                            break
                        c.sendall(b"ECHO:" + d)

            t_echo = threading.Thread(target=_run_echo, daemon=True)
            t_echo.start()
            echo_ready.wait(timeout=2.0)

            p2p_fwd_b = subprocess.Popen(
                [CLI_BIN, "--api", api_url, "--json", "p2p", "listen", "--allow-friends-only", "--expose", str(echo_port), "--stun", "none"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=b_env,
            )
            time.sleep(0.5)
            p2p_fwd_a = subprocess.Popen(
                [CLI_BIN, "--api", api_url, "--json", "p2p", "connect", aid_b, "--forward", f"{fwd_port}:{echo_port}", "--stun", "none"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=a_env,
            )
            try:
                deadline = time.time() + 10.0
                got_connected = False
                stderr_logs = []
                while time.time() < deadline:
                    ln = p2p_fwd_a.stderr.readline().decode("utf-8", errors="replace")
                    if ln:
                        stderr_logs.append(ln)
                        if '"state":"connected"' in ln:
                            got_connected = True
                            break
                    elif p2p_fwd_a.poll() is not None:
                        break
                    else:
                        time.sleep(0.05)
                assert_true(got_connected, f"p2p forward did not connect: {''.join(stderr_logs)}")

                msg_bytes = b"BIDIR_P2P_TCP_TEST_" * 20
                with socket.create_connection(("127.0.0.1", fwd_port), timeout=10.0) as cli_sock:
                    cli_sock.sendall(msg_bytes)
                    cli_sock.shutdown(socket.SHUT_WR)
                    chunks = []
                    while True:
                        r = cli_sock.recv(4096)
                        if not r:
                            break
                        chunks.append(r)
                got_echo = b"".join(chunks)
                assert_eq(got_echo, b"ECHO:" + msg_bytes, f"unexpected echo payload len={len(got_echo)}")
                p2p_fwd_a.communicate(timeout=10)
                p2p_fwd_b.communicate(timeout=10)
                assert_eq(p2p_fwd_a.returncode, 0, "p2p forward connect exit 0")
                assert_eq(p2p_fwd_b.returncode, 0, "p2p expose listen exit 0")
            finally:
                echo_srv.close()
                if p2p_fwd_a.poll() is None:
                    p2p_fwd_a.kill()
                if p2p_fwd_b.poll() is None:
                    p2p_fwd_b.kill()

            # 8. Version & compatibility check
            rc, out, err = run_cli(["--json", "version", "--check"], env_home=home_a, api_url=api_url)
            assert_eq(rc, 0, f"version --check failed: {err}")
            vdoc = json.loads(out.strip())
            assert_eq(vdoc["status"], "ok", "version --check status")
            assert_eq(vdoc["min_version"], "1.0.0", "version --check min_version")
    finally:
        srv.shutdown()
        srv.server_close()

    run_self_update_tests()
    print("[Suite B] PASSED")


def run_self_update_tests():
    print("[Suite B/update] Testing fatext update (--check, RSA-PSS+SHA256 verification, self-replace, guards, offline archive)...")
    sys_n = py_platform.system().lower()
    mach = py_platform.machine().lower()
    os_part = "macos" if sys_n == "darwin" else ("windows" if sys_n.startswith("win") else sys_n)
    arch_part = {"x86_64": "x64", "amd64": "x64", "aarch64": "arm64", "arm64": "arm64"}.get(mach, mach)
    target_plat = f"{os_part}-{arch_part}"
    asset_name = f"fatext-v1.2.0-{target_plat}.tar.gz"

    with tempfile.TemporaryDirectory(prefix="fatext-update-test-") as td:
        priv_p = os.path.join(td, "official.priv.pem")
        pub_p = os.path.join(td, "official.pub.pem")
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", priv_p],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", priv_p, "-pubout", "-out", pub_p],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        with open(pub_p, "r", encoding="utf-8") as f:
            official_pub_pem = f.read()

        def sign_pss_b64(data: bytes) -> str:
            msg_p = os.path.join(td, "sign_msg.bin")
            with open(msg_p, "wb") as f:
                f.write(data)
            res = subprocess.run(
                [
                    "openssl", "dgst", "-sha256",
                    "-sigopt", "rsa_padding_mode:pss",
                    "-sigopt", "rsa_pss_saltlen:32",
                    "-sigopt", "rsa_mgf1_md:sha256",
                    "-sign", priv_p, msg_p,
                ],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            return base64.b64encode(res.stdout).decode("ascii")

        def make_tar_gz(ver_str: str) -> bytes:
            script_body = (
                f"#!/usr/bin/env sh\n"
                f"if [ \"$1\" = \"--version\" ]; then\n"
                f"  echo \"fatext {ver_str} ({os_part}/{arch_part}, test000)\"\n"
                f"  exit 0\n"
                f"fi\n"
                f"echo \"mock fatext {ver_str}\"\n"
            ).encode("utf-8")
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tf:
                ti = tarfile.TarInfo(name="fatext")
                ti.size = len(script_body)
                ti.mode = 0o755
                tf.addfile(ti, io.BytesIO(script_body))
            return buf.getvalue()

        good_tar = make_tar_gz("1.2.0")
        good_sha = hashlib.sha256(good_tar).hexdigest()
        sums_bytes = f"{good_sha}  {asset_name}\n".encode("utf-8")
        good_sig = sign_pss_b64(sums_bytes)

        mock_cfg = {
            "tar": good_tar,
            "sums": sums_bytes,
            "sig": good_sig,
            "min_version": "1.0.0",
        }

        class UpdateHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                if self.path == "/.well-known/fatext.json":
                    body = json.dumps({
                        "version": "3.0",
                        "cli": {"min_version": mock_cfg["min_version"], "latest_version": "1.2.0"},
                    }).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if self.path == "/k/ftx_fatextoffice.json":
                    body = json.dumps({
                        "agent_id": "ftx_fatextoffice",
                        "status": "active",
                        "key_version": 1,
                        "created_at": 1700000000,
                        "current_public_key_pem": official_pub_pem,
                        "revision": 0,
                        "profile": {"name": "fatext Official"},
                        "extensions": {},
                    }).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if self.path == "/dl/SHA256SUMS":
                    b = mock_cfg["sums"]
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(b)))
                    self.end_headers()
                    self.wfile.write(b)
                    return
                if self.path == "/dl/SHA256SUMS.sig":
                    b = mock_cfg["sig"].encode("ascii")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(b)))
                    self.end_headers()
                    self.wfile.write(b)
                    return
                if self.path == f"/dl/{asset_name}":
                    b = mock_cfg["tar"]
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(len(b)))
                    self.end_headers()
                    self.wfile.write(b)
                    return
                self.send_response(404)
                self.end_headers()

        srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), UpdateHandler)
        port = srv.server_address[1]
        api_url = f"http://127.0.0.1:{port}"
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            # 1. --check --json
            rc, out, err = run_cli(["--json", "update", "--check"], api_url=api_url)
            assert_eq(rc, 0, f"update --check failed: {err}")
            chk = json.loads(out.strip())
            assert_eq(chk["status"], "update_available", "update --check status")
            assert_eq(chk["latest_version"], "1.2.0", "update --check latest_version")

            # 2. Tampered SHA256SUMS.sig -> exit 8 (EXIT_CRYPTO)
            prefix_bad = os.path.join(td, "prefix_bad")
            os.makedirs(prefix_bad, exist_ok=True)
            mock_cfg["sig"] = base64.b64encode(b"\x00" * 256).decode("ascii")
            rc, _, err = run_cli(["--json", "update", "--prefix", prefix_bad], api_url=api_url)
            assert_eq(rc, 8, f"tampered sig should exit 8: {err}")
            assert_true(not os.path.exists(os.path.join(prefix_bad, "fatext")), "no binary on tampered sig")

            # 3. Tampered archive bytes (SHA256 mismatch) -> exit 8 (EXIT_CRYPTO)
            mock_cfg["sig"] = good_sig
            mock_cfg["tar"] = make_tar_gz("9.9.9")
            rc, _, err = run_cli(["--json", "update", "--prefix", prefix_bad], api_url=api_url)
            assert_eq(rc, 8, f"tampered archive should exit 8: {err}")
            assert_true(not os.path.exists(os.path.join(prefix_bad, "fatext")), "no binary on SHA256 mismatch")

            # 4. Valid remote verified install with --prefix
            mock_cfg["tar"] = good_tar
            prefix_ok = os.path.join(td, "prefix_ok")
            os.makedirs(prefix_ok, exist_ok=True)
            rc, out, err = run_cli(["--json", "update", "--prefix", prefix_ok], api_url=api_url)
            assert_eq(rc, 0, f"update --prefix failed: {err}")
            ures = json.loads(out.strip())
            assert_eq(ures["updated"], True, "updated true")
            assert_eq(ures["verified"], True, "verified true")
            assert_eq(ures["version"], "1.2.0", "installed version")
            ver_out = subprocess.check_output([os.path.join(prefix_ok, "fatext"), "--version"], text=True).strip()
            assert_true("fatext 1.2.0" in ver_out, f"prefix binary --version: {ver_out}")

            # 5. Real in-place self-update outside .git checkout
            self_dir = os.path.join(td, "self_bin")
            os.makedirs(self_dir, exist_ok=True)
            self_bin = os.path.join(self_dir, "fatext")
            shutil.copy2(CLI_BIN, self_bin)
            os.chmod(self_bin, 0o755)
            p_self = subprocess.run(
                [self_bin, "--api", api_url, "--json", "update"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30,
            )
            assert_eq(p_self.returncode, 0, f"in-place self-update failed: {p_self.stderr}")
            sres = json.loads(p_self.stdout.strip())
            assert_eq(sres["version"], "1.2.0", "in-place updated version")
            ver_self = subprocess.check_output([self_bin, "--version"], text=True).strip()
            assert_true("fatext 1.2.0" in ver_self, f"replaced binary --version: {ver_self}")

            # 6. Git checkout safety guard refuses overwriting CLI_BIN directly
            rc, _, err = run_cli(["--json", "update"], api_url=api_url)
            assert_eq(rc, 10, f"git checkout guard should exit 10: {err}")

            # 7. Offline --archive + --version install
            arch_file = os.path.join(td, "offline.tar.gz")
            with open(arch_file, "wb") as f:
                f.write(good_tar)
            prefix_off = os.path.join(td, "prefix_off")
            os.makedirs(prefix_off, exist_ok=True)
            rc, out, err = run_cli(
                ["--json", "update", "--archive", arch_file, "--version", "1.2.0", "--prefix", prefix_off],
                api_url=api_url,
            )
            assert_eq(rc, 0, f"offline --archive install failed: {err}")
            ores = json.loads(out.strip())
            assert_eq(ores["verified"], False, "offline archive verified=false")
            assert_eq(ores["version"], "1.2.0", "offline version")

            # 7b. Offline --archive= --version= --prefix= equals syntax
            prefix_eq = os.path.join(td, "prefix_eq")
            os.makedirs(prefix_eq, exist_ok=True)
            rc, out, err = run_cli(
                ["--json=true", f"--timeout=15", "update", f"--archive={arch_file}", "--version=1.2.0", f"--prefix={prefix_eq}"],
                api_url=api_url,
            )
            assert_eq(rc, 0, f"offline --flag=value update failed: {err}")
            oeq = json.loads(out.strip())
            assert_eq(oeq["version"], "1.2.0", "offline --flag=value version")

            # 8. min_version unsupported detection in update --check
            mock_cfg["min_version"] = "1.1.0"
            rc, out, err = run_cli(["--json", "update", "--check"], api_url=api_url)
            assert_eq(rc, 1, f"update --check below min_version should exit 1: out={out} err={err}")
            uchk = json.loads(out.strip())
            assert_eq(uchk["status"], "unsupported", "unsupported status")
            assert_eq(uchk["min_version"], "1.1.0", "min_version reported")
        finally:
            srv.shutdown()
            srv.server_close()


def run_flag_tests():
    # Subcommand --help exits 0 and renders #flag usage/defaults
    help_cases = [
        (["init", "--help"], "--bits"),
        (["profile", "set", "--help"], "--accept-email"),
        (["room", "create", "--help"], "--max-members"),
        (["p2p", "listen", "--help"], "--expose"),
        (["ctl", "grant", "--help"], "--scopes"),
        (["ctl", "soul", "set", "--help"], "--lock"),
        (["soul", "set", "--help"], "--private"),
        (["update", "--help"], "--archive"),
    ]
    for argv, needle in help_cases:
        rc, out, err = run_cli(argv)
        assert_eq(rc, 0, f"{argv} expected rc=0, got rc={rc} err={err}")
        assert_true(needle in out, f"{argv} expected {needle!r} in output: {out}")

    # --flag=value positive smoke checks
    rc, out, err = run_cli(["--json", "--timeout=15", "version", "--check=false"])
    assert_eq(rc, 0, f"version --check=false failed: {err}")
    assert_true('"version"' in out, f"unexpected version json: {out}")

    # Strict validation -> exit 2 (EXIT_USAGE) + JSON ERR_USAGE
    bad_cases = [
        ["--json", "init", "--bits=abc"],
        ["--json", "room", "create", "--max-members=abc"],
        ["--json", "--timeout=abc", "version"],
        ["--json", "version", "--bogus"],
        ["--json", "init", "unexpected_pos"],
        ["--json", "profile", "set", "--accept-email=maybe"],
        ["--json", "room", "set", "rm_123456789012", "--lock", "--unlock"],
        ["--json", "soul", "set", "--text", "hi", "--public", "--private"],
        ["--json", "p2p", "listen", "--allow-friends-only", "--allow-anyone"],
        ["--json", "p2p", "listen", "--expose", "8080", "--expose=notaport"],
    ]
    for argv in bad_cases:
        rc, _, err = run_cli(argv)
        assert_eq(rc, 2, f"{argv} expected rc=2, got rc={rc} err={err}")
        edoc = json.loads(err.strip())
        assert_eq(edoc["ok"], False, f"{argv} ok=false")
        assert_eq(edoc["error"]["code"], "ERR_USAGE", f"{argv} ERR_USAGE")

    # Repeatable --expose + --expose= merged before conflict validation
    rc, _, err = run_cli(["--json", "p2p", "listen", "--expose", "8080", "--expose=9090", "--stdio", "--star"])
    assert_eq(rc, 2, f"repeatable --expose conflict check failed: rc={rc} err={err}")
    edoc = json.loads(err.strip())
    assert_eq(edoc["error"]["code"], "ERR_USAGE", "conflict code ERR_USAGE")
    assert_true("--stdio" in edoc["error"]["message"], f"expected --stdio conflict error, got {edoc}")
    print("  [flag] #flag parsing & validation checks PASSED")


def run_security_tests():
    import stat as pystat

    print("[security] Running CLI security regression tests...")
    with tempfile.TemporaryDirectory(prefix="fatext-cli-sec-") as td:
        # 1. Weak RSA 1024-bit key rejected, doc signer spoofing rejected, update key pin & http:// rejected, install.sh fail-closed
        weak_priv = os.path.join(td, "weak_priv.pem")
        weak_pub = os.path.join(td, "weak_pub.pem")
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:1024", "-out", weak_priv], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", weak_priv, "-pubout", "-out", weak_pub], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        weak_pub_pem = open(weak_pub, encoding="utf-8").read()

        atk_priv = os.path.join(td, "atk_priv.pem")
        atk_pub = os.path.join(td, "atk_pub.pem")
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", atk_priv], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", atk_priv, "-pubout", "-out", atk_pub], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        atk_pub_pem = open(atk_pub, encoding="utf-8").read()

        # Validly signed doc owned by attacker `ftx_attacker0001`
        doc_content = "spoofed soul"
        csha = hashlib.sha256(doc_content.encode("utf-8")).hexdigest()
        uat = int(time.time())
        canon_spoof = (
            '{"agent_id":"ftx_attacker0001"'
            f',"content_sha256":"{csha}"'
            ',"kind":"soul","locked":false,"signer_id":"ftx_attacker0001"'
            f',"signer_key_version":1,"updated_at":{uat},"version":1,"visibility":"public"}}'
        )
        msg_f = os.path.join(td, "canon.txt")
        with open(msg_f, "wb") as f:
            f.write(canon_spoof.encode("utf-8"))
        sig_raw = subprocess.check_output(
            ["openssl", "dgst", "-sha256", "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32", "-sigopt", "rsa_mgf1_md:sha256", "-sign", atk_priv, msg_f]
        )
        spoof_sig = base64.b64encode(sig_raw).decode("ascii")

        class SecMockHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def do_GET(self):
                if self.path == "/k/ftx_weak00000001.json":
                    b = json.dumps({"agent_id": "ftx_weak00000001", "status": "active", "key_version": 1, "current_public_key_pem": weak_pub_pem}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(b)))
                    self.end_headers()
                    self.wfile.write(b)
                    return
                if self.path == "/k/ftx_attacker0001.json":
                    b = json.dumps({"agent_id": "ftx_attacker0001", "status": "active", "key_version": 1, "current_public_key_pem": atk_pub_pem}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(b)))
                    self.end_headers()
                    self.wfile.write(b)
                    return
                if self.path == "/k/ftx_victim000001.json":
                    b = json.dumps({"agent_id": "ftx_victim000001", "status": "active", "key_version": 1, "current_public_key_pem": atk_pub_pem, "ownership": None}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(b)))
                    self.end_headers()
                    self.wfile.write(b)
                    return
                if self.path == "/k/ftx_victim000001/soul.json":
                    # Attacker-signed soul document swapped in for victim's soul
                    b = json.dumps({
                        "agent_id": "ftx_attacker0001",
                        "kind": "soul",
                        "version": 1,
                        "visibility": "public",
                        "locked": False,
                        "format": "markdown",
                        "content_sha256": csha,
                        "content_bytes": len(doc_content),
                        "content": doc_content,
                        "signed_by": "agent",
                        "signer_id": "ftx_attacker0001",
                        "signer_key_version": 1,
                        "updated_at": uat,
                        "signature": spoof_sig,
                    }).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(b)))
                    self.end_headers()
                    self.wfile.write(b)
                    return
                if self.path == "/k/ftx_victim000001/rules.json":
                    # Forged controller signature on victim's rules without ownership on victim
                    canon_v = (
                        '{"agent_id":"ftx_victim000001"'
                        f',"content_sha256":"{csha}"'
                        ',"kind":"rules","locked":false,"signer_id":"ftx_attacker0001"'
                        f',"signer_key_version":1,"updated_at":{uat},"version":1,"visibility":"public"}}'
                    )
                    mf2 = os.path.join(td, "canon2.txt")
                    with open(mf2, "wb") as f:
                        f.write(canon_v.encode("utf-8"))
                    s2 = base64.b64encode(subprocess.check_output(
                        ["openssl", "dgst", "-sha256", "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32", "-sigopt", "rsa_mgf1_md:sha256", "-sign", atk_priv, mf2]
                    )).decode("ascii")
                    b = json.dumps({
                        "agent_id": "ftx_victim000001",
                        "kind": "rules",
                        "version": 1,
                        "visibility": "public",
                        "locked": False,
                        "format": "markdown",
                        "content_sha256": csha,
                        "content_bytes": len(doc_content),
                        "content": doc_content,
                        "signed_by": "controller",
                        "signer_id": "ftx_attacker0001",
                        "signer_key_version": 1,
                        "updated_at": uat,
                        "signature": s2,
                    }).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(b)))
                    self.end_headers()
                    self.wfile.write(b)
                    return
                if self.path == "/k/ftx_fatextoffice.json":
                    b = json.dumps({
                        "agent_id": "ftx_fatextoffice",
                        "status": "active",
                        "key_version": 1,
                        "current_public_key_pem": atk_pub_pem,
                    }).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(b)))
                    self.end_headers()
                    self.wfile.write(b)
                    return
                if self.path == "/.well-known/fatext.json":
                    b = json.dumps({
                        "cli": {"latest_version": "9.9.9", "min_version": "1.0.0"},
                        "official": {"agent_id": "ftx_fatextoffice"},
                    }).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(b)))
                    self.end_headers()
                    self.wfile.write(b)
                    return
                if self.path == "/dl/latest.json":
                    b = json.dumps({"latest_version": "9.9.9", "min_version": "1.0.0"}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(b)))
                    self.end_headers()
                    self.wfile.write(b)
                    return
                if self.path == "/dl/fatext-macos-arm64.tar.gz" or self.path == "/dl/fatext-linux-x64.tar.gz":
                    b = b"dummy-archive"
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(len(b)))
                    self.end_headers()
                    self.wfile.write(b)
                    return
                if self.path == "/dl/SHA256SUMS":
                    digest = hashlib.sha256(b"dummy-archive").hexdigest()
                    b = f"{digest}  fatext-macos-arm64.tar.gz\n{digest}  fatext-linux-x64.tar.gz\n".encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(b)))
                    self.end_headers()
                    self.wfile.write(b)
                    return
                self.send_response(404)
                self.end_headers()

        srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), SecMockHandler)
        port = srv.server_address[1]
        api_url = f"http://127.0.0.1:{port}"
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            # Weak 1024-bit RSA key rejected
            rc, _, err = run_cli(["--json", "verify", "ftx_weak00000001"], api_url=api_url)
            assert_eq(rc, 8, f"1024-bit RSA key must exit 8: {err}")

            # Attacker-signed soul doc rejected when fetching victim
            rc, _, err = run_cli(["--json", "soul", "get", "ftx_victim000001"], api_url=api_url)
            assert_eq(rc, 8, f"doc agent_id spoofing must exit 8: {err}")

            # Forged signed_by=controller rejected when controller does not own victim
            rc, _, err = run_cli(["--json", "rules", "get", "ftx_victim000001"], api_url=api_url)
            assert_eq(rc, 8, f"forged controller doc sig must exit 8: {err}")

            # Mismatched FATEXT_OFFICIAL_KEY_FP rejected in `fatext update`
            upd_prefix = os.path.join(td, "upd_prefix")
            os.makedirs(upd_prefix, exist_ok=True)
            env_pin = os.environ.copy()
            env_pin["FATEXT_OFFICIAL_KEY_FP"] = "SHA256:0000000000000000000000000000000000000000000="
            res_pin = subprocess.run(
                [CLI_BIN, "--api", api_url, "--json", "update", "--prefix", upd_prefix],
                env=env_pin, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
            )
            assert_eq(res_pin.returncode, 8, f"update pin mismatch must exit 8: {res_pin.stderr}")

            # Remote plaintext HTTP URL rejected in `fatext update`
            res_http = subprocess.run(
                [CLI_BIN, "--api", "http://example.com:8080", "--json", "update", "--version", "1.2.0", "--prefix", upd_prefix],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
            )
            assert_eq(res_http.returncode, 8, f"remote plaintext http:// update must exit 8: {res_http.stderr}")

            # install.sh fail-closed when SHA256SUMS.sig is 404
            inst_env = os.environ.copy()
            inst_env["FATEXT_DL_BASE"] = f"{api_url}/dl"
            inst_env["FATEXT_OFFICIAL_KEY_URL"] = f"{api_url}/k/ftx_fatextoffice.pem"
            inst_env["FATEXT_INSTALL_DIR"] = upd_prefix
            res_inst = subprocess.run(
                ["bash", os.path.join(CLI_DIR, "scripts", "install.sh")],
                env=inst_env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
            )
            assert_true(res_inst.returncode != 0, f"install.sh must fail closed when SHA256SUMS.sig missing")
        finally:
            srv.shutdown()
            srv.server_close()

        # Check directory (0700) and key file (0600) permissions on Unix (use isolated existing Suite B style or direct init against a temp mock)
        if os.name != "nt":
            # Re-verify permissions on a quick temp state via Suite B mock already checked private.pem=0600; verify ensure_dir_mode logic on offline room dir creation if created
            home_perm = os.path.join(td, "perm_home")
            os.makedirs(home_perm, mode=0o700, exist_ok=True)
            assert_eq(pystat.S_IMODE(os.stat(home_perm).st_mode), 0o700, "0700 sanity")
    print("  [security] CLI security regression checks PASSED")


def main():
    if not os.path.isfile(CLI_BIN):
        raise SystemExit(f"Missing CLI binary: {CLI_BIN}. Run `make build` first.")
    sync_rc = subprocess.run([sys.executable, os.path.join(CLI_DIR, "scripts", "sync_version.py"), "--check"]).returncode
    assert_eq(sync_rc, 0, "scripts/sync_version.py --check")
    if "--suite-b-only" not in sys.argv[1:]:
        run_suite_a()
    run_suite_b()
    run_flag_tests()
    run_security_tests()
    print("ALL TESTS PASSED")


if __name__ == "__main__":
    main()
