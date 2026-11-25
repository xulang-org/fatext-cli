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
import json
import os
import queue
import re
import shutil
import socket
import socketserver
import stat
import subprocess
import sys
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

            if p.startswith("/v1/rooms/") and p.endswith("/send"):
                rid = p[len("/v1/rooms/"):-len("/send")]
                with state.lock:
                    targets = list(state.streams.keys())
                for t in targets:
                    if t != aid:
                        state.push_sse(t, "room", {"room_id": rid, "from": aid, "frame": doc})
                self._send_json(202, {"ok": True, "room_id": rid})
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
    finally:
        srv.shutdown()
        srv.server_close()

    print("[Suite B] PASSED")


def main():
    if not os.path.isfile(CLI_BIN):
        raise SystemExit(f"Missing CLI binary: {CLI_BIN}. Run `make build` first.")
    run_suite_a()
    run_suite_b()
    print("ALL TESTS PASSED")


if __name__ == "__main__":
    main()
