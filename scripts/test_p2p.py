#!/usr/bin/env python3
"""
Comprehensive P2P test suite for `fatext` CLI:
  - Built-in RFC 5389 STUN server (XOR-MAPPED-ADDRESS, MAPPED-ADDRESS, noise/failover)
  - General-purpose UDP NAT & Network Impairment simulator (latency/jitter, random &
    deterministic packet loss, duplication, reordering, noise/tamper injection,
    port-restricted cone NAT, symmetric NAT, and mid-session NAT port migration)
  - Full signaling + SSE relay (or optional --api external fatext-server)
  - 12 targeted tests covering STUN, NAT traversal, reliability, server-first TCP
    banners, unreachable targets, slow streams, zombies, security, and key rotation.
"""

import argparse
import base64
import hashlib
import http.server
import json
import os
import queue
import random
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request

CLI_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI_BIN = os.environ.get("FATEXT_CLI_BIN") or os.environ.get("FATEXT_BIN") or os.path.join(CLI_DIR, "build", "fatext")
STUN_MAGIC = 0x2112A442


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


def rsa_pss_sha256_verify(pub_pem: str, msg: bytes, sig_b64: str) -> bool:
    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except Exception:
        return False
    with tempfile.TemporaryDirectory() as td:
        pk_p = os.path.join(td, "pub.pem")
        msg_p = os.path.join(td, "msg.bin")
        sig_p = os.path.join(td, "sig.bin")
        with open(pk_p, "w", encoding="utf-8") as f:
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


def rsa_pss_sha256_sign(priv_path: str, msg: bytes) -> str:
    with tempfile.TemporaryDirectory() as td:
        msg_p = os.path.join(td, "msg.bin")
        with open(msg_p, "wb") as f:
            f.write(msg)
        res = subprocess.run(
            [
                "openssl", "dgst", "-sha256",
                "-sigopt", "rsa_padding_mode:pss",
                "-sigopt", "rsa_pss_saltlen:32",
                "-sign", priv_path,
                msg_p,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        return base64.b64encode(res.stdout).decode("ascii")


# Pure-Python AES-256-GCM (NIST SP 800-38D) for crafting synthetic signaling frames
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
    w = [int.from_bytes(key[i:i+4], "big") for i in range(0, 32, 4)]
    for i in range(8, 60):
        t = w[i - 1]
        if i % 8 == 0:
            t = ((t << 8) | (t >> 24)) & 0xffffffff
            t = ((_SBOX[(t >> 24) & 0xff] << 24) | (_SBOX[(t >> 16) & 0xff] << 16) |
                 (_SBOX[(t >> 8) & 0xff] << 8) | _SBOX[t & 0xff]) ^ (_RCON[(i // 8) - 1] << 24)
        elif i % 8 == 4:
            t = ((_SBOX[(t >> 24) & 0xff] << 24) | (_SBOX[(t >> 16) & 0xff] << 16) |
                 (_SBOX[(t >> 8) & 0xff] << 8) | _SBOX[t & 0xff])
        w.append(w[i - 8] ^ t)
    return [b"".join(w[4*r + c].to_bytes(4, "big") for c in range(4)) for r in range(15)]


def _aes256_block(rk, block: bytes) -> bytes:
    s = bytearray(a ^ b for a, b in zip(block, rk[0]))
    for r in range(1, 15):
        s = bytearray(_SBOX[b] for b in s)
        s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
        if r < 14:
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = s[c], s[c+1], s[c+2], s[c+3]
                t = a0 ^ a1 ^ a2 ^ a3
                s[c] ^= t ^ _xtime(a0 ^ a1)
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
    for data in (aad, ct):
        for off in range(0, len(data), 16):
            blk = data[off:off+16]
            if len(blk) < 16:
                blk = blk + b"\x00" * (16 - len(blk))
            y = _ghash_mul(y ^ int.from_bytes(blk, "big"), h)
    lens = ((len(aad) * 8) << 64) | (len(ct) * 8)
    y = _ghash_mul(y ^ lens, h)
    return y.to_bytes(16, "big")


def aes256_gcm_encrypt(key: bytes, iv12: bytes, pt: bytes, aad: bytes) -> bytes:
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
    return ct + bytes(a ^ b for a, b in zip(s, e_j0))


def build_dm_frame(sender_id: str, sender_priv: str, to_id: str, to_pub_pem: str, to_kv: int,
                   msg_type: str, body_obj: dict, ts: int, nonce: str = None) -> bytes:
    if nonce is None:
        nonce = base64.b64encode(os.urandom(16)).decode("ascii")
    body_s = json.dumps(body_obj, separators=(",", ":"), sort_keys=True)
    nosig = (
        f'{{"body":{body_s},"conversation_state":"open","from":{json.dumps(sender_id)},'
        f'"nonce":{json.dumps(nonce)},"to":{json.dumps(to_id)},"ts":{ts},'
        f'"type":{json.dumps(msg_type)},"v":1}}'
    ).encode("utf-8")
    sig = rsa_pss_sha256_sign(sender_priv, nosig)
    pt = (
        f'{{"body":{body_s},"conversation_state":"open","from":{json.dumps(sender_id)},'
        f'"nonce":{json.dumps(nonce)},"sig":{json.dumps(sig)},"to":{json.dumps(to_id)},'
        f'"ts":{ts},"type":{json.dumps(msg_type)},"v":1}}'
    ).encode("utf-8")
    cek = os.urandom(32)
    iv = os.urandom(12)
    with tempfile.TemporaryDirectory() as td:
        pk_p = os.path.join(td, "pub.pem")
        cek_p = os.path.join(td, "cek.bin")
        with open(pk_p, "w", encoding="utf-8") as f:
            f.write(to_pub_pem)
        with open(cek_p, "wb") as f:
            f.write(cek)
        ek = subprocess.run(
            [
                "openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", pk_p,
                "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256",
                "-in", cek_p,
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        ).stdout
    aad = f"fatext-dm\n{sender_id}\n{to_id}\n{to_kv}".encode("utf-8")
    ct = aes256_gcm_encrypt(cek, iv, pt, aad)
    return json.dumps({
        "v": 1,
        "alg": "RSA-OAEP-256+A256GCM",
        "to_key_version": to_kv,
        "ek": base64.b64encode(ek).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
    }, separators=(",", ":")).encode("utf-8")


# =============================================================================
# Local Signaling Relay (friends, keys, DMs, SSE stream, key rotation)
# =============================================================================

class RelayState:
    def __init__(self):
        self.lock = threading.Lock()
        self.counter = 0
        self.agents = {}
        self.friends = {}
        self.streams = {}

    def next_agent_id(self) -> str:
        with self.lock:
            self.counter += 1
            return f"ftx_p2p{self.counter:09d}"

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
            p = urllib.parse.urlparse(self.path).path
            if p == "/.well-known/fatext.json":
                self._send_json(200, {
                    "version": "3.0",
                    "cli": {"min_version": "1.0.0", "latest_version": "1.0.1"},
                    "pow": {"register": {"difficulty_bits": 12}, "post": {"difficulty_bits": 12}},
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
                    "key_history": ag.get("key_history", []),
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
                        "incoming": [],
                        "outgoing": [],
                    }
                self._send_json(200, resp)
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
                        "key_history": [],
                        "revision": 0,
                        "profile": doc.get("profile", {}),
                        "extensions": {"dm_policy": "friends", "accept_email": False},
                    }
                    state.friends[aid] = {"friends": set(), "in": {}, "out": {}}
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
                now = int(time.time())
                with state.lock:
                    ag.setdefault("key_history", []).append({
                        "version": ag["key_version"],
                        "public_key_pem": ag["pub_pem"],
                        "valid_from": ag["created_at"],
                        "valid_until": now,
                        "rotated_by_old_sig": doc["old_sig"],
                        "rotated_by_new_sig": doc["new_sig"],
                    })
                    ag["pub_pem"] = new_pem
                    ag["key_version"] = new_kv
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
            if p.startswith("/v1/dm/"):
                to_id = p[len("/v1/dm/"):]
                state.push_sse(to_id, "dm", {"from": aid, "frame": doc})
                self._send_json(202, {"ok": True, "delivered": True})
                return
            self._send_json(404, {"error": {"code": "ERR_NOT_FOUND", "message": p}})

    return Handler


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


# =============================================================================
# RFC 5389 Mock STUN + Full NAT / Network Impairment Simulator
# =============================================================================

class UdpNatSim:
    """
    Combines an RFC 5389 STUN server with dynamic external NAT port mappings.
    Every CLI UDP socket querying STUN receives its own simulated external port `127.0.0.1:E`.
    Packets sent between CLI real sockets `R` and simulated external endpoints `E` traverse
    a configurable network model: delay/jitter, random loss, deterministic first-N packet drop,
    duplication, reordering, noise/tamper injection, Port-Restricted NAT, Symmetric NAT, and
    mid-session NAT port migration.
    """

    def __init__(
        self,
        nat_mode: str = "port_restricted",
        stun_attr_mode: str = "xor",
        stun_garbage_first: bool = False,
        delay_ms: float = 0.0,
        jitter_ms: float = 0.0,
        loss_rate: float = 0.0,
        dup_rate: float = 0.0,
        reorder_rate: float = 0.0,
        drop_first_packets: int = 0,
        drop_first_direction: str = "both",
        tamper_inject: bool = False,
        migrate_after_packets: int = 0,
        migrate_target_index: int = 0,
        replay_spoof_after: int = 0,
        replay_target_index: int = 1,
        drop_real_after_replay: bool = False,
    ):
        self.nat_mode = nat_mode
        self.stun_attr_mode = stun_attr_mode
        self.stun_garbage_first = stun_garbage_first
        self.delay_ms = delay_ms
        self.jitter_ms = jitter_ms
        self.loss_rate = loss_rate
        self.dup_rate = dup_rate
        self.reorder_rate = reorder_rate
        self.drop_first_packets = drop_first_packets
        self.drop_first_direction = drop_first_direction
        self.tamper_inject = tamper_inject
        self.migrate_after_packets = migrate_after_packets
        self.migrate_target_index = migrate_target_index
        self.replay_spoof_after = replay_spoof_after
        self.replay_target_index = replay_target_index
        self.drop_real_after_replay = drop_real_after_replay

        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._rng = random.Random(20261127)

        self._stun_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._stun_sock.bind(("127.0.0.1", 0))
        self.stun_port = self._stun_sock.getsockname()[1]

        # Real peer endpoints and simulated external NAT mappings
        self._ext_by_real = {}   # (ip, real_port) -> ext_port
        self._real_by_ext = {}   # ext_port -> (ip, real_port)
        self._sock_by_ext = {}   # ext_port -> socket
        self._dead_ext = set()   # migrated/retired ext_ports
        self._nat_opened = set() # (owner_real, allowed_remote_ext)
        self._sym_socks = {}     # (src_real, dst_ext) -> sym_ext_port
        self._real_order = []    # registration order [R0, R1, ...]
        self._tx_counts = {}     # src_real -> count of forwarded packets
        self._drop_remaining = drop_first_packets
        self._migrated_real = set()
        self._captured_pkts = []
        self._replay_started = False
        self._blackhole = False
        self._atk_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._atk_sock.bind(("127.0.0.1", 0))
        self._atk_rx_count = 0
        self._threads = []
        self.stats = {
            "stun_reqs": 0, "tx": 0, "dropped": 0, "tampered": 0,
            "migrated": 0, "replayed_sent": 0, "atk_replies": 0,
        }

    def start(self):
        t = threading.Thread(target=self._stun_loop, daemon=True)
        t.start()
        self._threads.append(t)
        ta = threading.Thread(target=self._atk_rx_loop, daemon=True)
        ta.start()
        self._threads.append(ta)
        return self

    def stop(self):
        self._stop.set()
        try:
            self._stun_sock.close()
        except OSError:
            pass
        try:
            self._atk_sock.close()
        except OSError:
            pass
        with self._lock:
            socks = list(self._sock_by_ext.values())
            self._sock_by_ext.clear()
        for s in socks:
            try:
                s.close()
            except OSError:
                pass

    def _atk_rx_loop(self):
        while not self._stop.is_set():
            try:
                data, _ = self._atk_sock.recvfrom(65535)
            except OSError:
                break
            if data:
                with self._lock:
                    self.stats["atk_replies"] += 1

    def _spawn_replay_storm(self, target_real, pkts):
        def _run():
            # Wait past in-flight NAT delay so captured packets are genuine historical replays.
            time.sleep(max(0.25, (self.delay_ms + self.jitter_ms) / 1000.0 + 0.15))
            for _ in range(150):
                if self._stop.is_set():
                    break
                for p in pkts:
                    try:
                        self._atk_sock.sendto(p, target_real)
                        with self._lock:
                            self.stats["replayed_sent"] += 1
                    except OSError:
                        pass
                time.sleep(0.02)
        t = threading.Thread(target=_run, daemon=True)
        t.start()
        self._threads.append(t)

    def _build_stun_resp(self, txid: bytes, src_ip: str, ext_port: int) -> bytes:
        ip_b = socket.inet_aton(src_ip)
        if self.stun_attr_mode == "mapped":
            # MAPPED-ADDRESS (0x0001)
            attr = struct.pack("!BBH", 0, 1, ext_port) + ip_b
            attr_hdr = struct.pack("!HH", 0x0001, len(attr)) + attr
        else:
            # XOR-MAPPED-ADDRESS (0x0020)
            xport = ext_port ^ (STUN_MAGIC >> 16)
            xip = bytes(a ^ b for a, b in zip(ip_b, struct.pack("!I", STUN_MAGIC)))
            attr = struct.pack("!BBH", 0, 1, xport) + xip
            attr_hdr = struct.pack("!HH", 0x0020, len(attr)) + attr
        return struct.pack("!HHI", 0x0101, len(attr_hdr), STUN_MAGIC) + txid + attr_hdr

    def _alloc_ext_socket(self, real_addr):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        ext_port = s.getsockname()[1]
        self._sock_by_ext[ext_port] = s
        self._real_by_ext[ext_port] = real_addr
        t = threading.Thread(target=self._ext_loop, args=(s, ext_port), daemon=True)
        t.start()
        self._threads.append(t)
        return ext_port, s

    def _stun_loop(self):
        while not self._stop.is_set():
            try:
                data, addr = self._stun_sock.recvfrom(2048)
            except OSError:
                break
            if len(data) < 20:
                continue
            mtype, _, magic = struct.unpack("!HHI", data[:8])
            if mtype != 0x0001 or magic != STUN_MAGIC:
                continue
            txid = data[8:20]
            with self._lock:
                self.stats["stun_reqs"] += 1
                ext_port = self._ext_by_real.get(addr)
                if ext_port is None:
                    ext_port, _ = self._alloc_ext_socket(addr)
                    self._ext_by_real[addr] = ext_port
                    self._real_order.append(addr)
            if self.stun_garbage_first:
                # Wrong-txid packet + short junk packet before real STUN response
                bad_tx = os.urandom(12)
                if bad_tx == txid:
                    bad_tx = b"\x00" * 12
                try:
                    self._stun_sock.sendto(b"JUNK_UDP", addr)
                    self._stun_sock.sendto(self._build_stun_resp(bad_tx, addr[0], 11111), addr)
                except OSError:
                    pass
            resp = self._build_stun_resp(txid, addr[0], ext_port)
            try:
                self._stun_sock.sendto(resp, addr)
            except OSError:
                pass

    def _deliver_after(self, delay_sec: float, out_sock: socket.socket, pkt: bytes, target_addr):
        def _send():
            if self._stop.is_set():
                return
            try:
                out_sock.sendto(pkt, target_addr)
            except OSError:
                pass
        if delay_sec <= 0.0:
            _send()
        else:
            t = threading.Timer(delay_sec, _send)
            t.daemon = True
            t.start()

    def _ext_loop(self, sock: socket.socket, dst_ext: int):
        while not self._stop.is_set():
            try:
                data, src_real = sock.recvfrom(65535)
            except OSError:
                break
            self._forward_packet(dst_ext, src_real, data)

    def _forward_packet(self, dst_ext: int, src_real, data: bytes):
        with self._lock:
            if dst_ext in self._dead_ext:
                self.stats["dropped"] += 1
                return
            dst_real = self._real_by_ext.get(dst_ext)
            if dst_real is None:
                return

            # Ensure sender also has an external port mapping
            src_ext = self._ext_by_real.get(src_real)
            if src_ext is None:
                src_ext, _ = self._alloc_ext_socket(src_real)
                self._ext_by_real[src_real] = src_ext
                self._real_order.append(src_real)

            # Symmetric NAT uses a destination-specific unannounced port when forwarding
            if self.nat_mode == "symmetric":
                sym_port = self._sym_socks.get((src_real, dst_ext))
                if sym_port is None:
                    sym_port, _ = self._alloc_ext_socket(src_real)
                    self._sym_socks[(src_real, dst_ext)] = sym_port
                # Record outbound hole from src_real -> dst_ext, using sym_port
                self._nat_opened.add((src_real, dst_ext))
                # Peer only knows src's STUN port; its firewall only accepts from announced src_ext
                if (dst_real, sym_port) not in self._nat_opened:
                    self.stats["dropped"] += 1
                    return
                out_sock = self._sock_by_ext.get(sym_port)
            else:
                # Open NAT pinhole for outbound traffic src_real -> dst_ext
                self._nat_opened.add((src_real, dst_ext))

                # Port-Restricted NAT check on destination side: dst_real must have sent to src_ext
                if self.nat_mode == "port_restricted" and (dst_real, src_ext) not in self._nat_opened:
                    self.stats["dropped"] += 1
                    return

                # Connection migration trigger
                cnt = self._tx_counts.get(src_real, 0) + 1
                self._tx_counts[src_real] = cnt
                if (
                    self.migrate_after_packets > 0
                    and cnt >= self.migrate_after_packets
                    and src_real not in self._migrated_real
                    and len(self._real_order) > self.migrate_target_index
                    and src_real == self._real_order[self.migrate_target_index]
                ):
                    old_ext = self._ext_by_real[src_real]
                    new_ext, _ = self._alloc_ext_socket(src_real)
                    self._dead_ext.add(old_ext)
                    self._ext_by_real[src_real] = new_ext
                    self._nat_opened.add((dst_real, new_ext))
                    self._migrated_real.add(src_real)
                    src_ext = new_ext
                    self.stats["migrated"] += 1

                # Deterministic initial packet drop
                src_idx = self._real_order.index(src_real) if src_real in self._real_order else 0
                dir_match = (
                    self.drop_first_direction == "both"
                    or (self.drop_first_direction == "0to1" and src_idx == 0)
                    or (self.drop_first_direction == "1to0" and src_idx == 1)
                )
                if self._drop_remaining > 0 and dir_match:
                    self._drop_remaining -= 1
                    self.stats["dropped"] += 1
                    return

                if self.loss_rate > 0.0 and self._rng.random() < self.loss_rate:
                    self.stats["dropped"] += 1
                    return

                # Capture packets for replay spoof test
                replay_batch = None
                replay_target = None
                if (
                    self.replay_spoof_after > 0
                    and len(self._real_order) > self.replay_target_index
                    and src_real == self._real_order[self.replay_target_index]
                ):
                    self._captured_pkts.append(data)
                    if (not self._replay_started) and len(self._captured_pkts) >= self.replay_spoof_after:
                        self._replay_started = True
                        replay_target = dst_real
                        if self.drop_real_after_replay:
                            self._blackhole = True
                            replay_batch = list(self._captured_pkts[:-1])
                        else:
                            replay_batch = list(self._captured_pkts[:-1])
                if self._blackhole:
                    if replay_batch:
                        self._spawn_replay_storm(replay_target, replay_batch)
                    self.stats["dropped"] += 1
                    return

                out_sock = self._sock_by_ext.get(src_ext)

            if out_sock is None:
                return
            self.stats["tx"] += 1

        if replay_batch:
            self._spawn_replay_storm(replay_target, replay_batch)

        base_d = max(0.0, (self.delay_ms + self._rng.uniform(-self.jitter_ms, self.jitter_ms)) / 1000.0)
        if self.reorder_rate > 0.0 and self._rng.random() < self.reorder_rate:
            base_d += self._rng.uniform(0.04, 0.10)

        self._deliver_after(base_d, out_sock, data, dst_real)
        if self.dup_rate > 0.0 and self._rng.random() < self.dup_rate:
            self._deliver_after(base_d + 0.015, out_sock, data, dst_real)
        if self.tamper_inject and self._rng.random() < 0.20:
            self.stats["tampered"] += 1
            bad = bytearray(data)
            if len(bad) > 12:
                bad[-1] ^= 0xff
            self._deliver_after(base_d + 0.002, out_sock, bytes(bad), dst_real)
            self._deliver_after(base_d + 0.004, out_sock, os.urandom(32), dst_real)


# =============================================================================
# Process & Agent Helpers
# =============================================================================

class LineProc:
    def __init__(self, args, home: str, api_url: str, binary_stdout: bool = False, extra_env=None):
        cmd = [CLI_BIN, "--api", api_url] + list(args)
        env = os.environ.copy()
        env["FATEXT_HOME"] = home
        if extra_env:
            env.update(extra_env)
        self.binary_stdout = binary_stdout
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        self.out_lines = queue.Queue()
        self.err_lines = queue.Queue()
        self.out_bytes = bytearray()
        self._out_history = []
        self._err_history = []
        self._lock = threading.Lock()
        self._out_done = threading.Event()
        self._t_out = threading.Thread(target=self._pump_out, daemon=True)
        self._t_err = threading.Thread(target=self._pump_err, daemon=True)
        self._t_out.start()
        self._t_err.start()

    def _pump_out(self):
        try:
            if self.binary_stdout:
                while True:
                    chunk = self.proc.stdout.read(4096)
                    if not chunk:
                        break
                    with self._lock:
                        self.out_bytes.extend(chunk)
            else:
                for raw in iter(self.proc.stdout.readline, b""):
                    ln = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                    with self._lock:
                        self._out_history.append(ln)
                    self.out_lines.put(ln)
        finally:
            self._out_done.set()

    def _pump_err(self):
        for raw in iter(self.proc.stderr.readline, b""):
            ln = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            with self._lock:
                self._err_history.append(ln)
            self.err_lines.put(ln)

    def send_stdin(self, data: bytes):
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def send_line(self, line: str):
        self.send_stdin((line + "\n").encode("utf-8"))

    def close_stdin(self):
        try:
            self.proc.stdin.close()
        except OSError:
            pass

    def wait_err_state(self, state: str, timeout: float = 12.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                for ln in self._err_history:
                    if f'"state":"{state}"' in ln:
                        return json.loads(ln)
            try:
                ln = self.err_lines.get(timeout=0.1)
                if f'"state":"{state}"' in ln:
                    return json.loads(ln)
            except queue.Empty:
                if self.proc.poll() is not None:
                    break
        raise AssertionError(f"Timed out waiting for stderr state={state}; stderr={self.err_dump()}")

    def wait_out_json(self, pred, timeout: float = 12.0, desc: str = ""):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                ln = self.out_lines.get(timeout=0.1)
            except queue.Empty:
                if self.proc.poll() is not None and self.out_lines.empty():
                    break
                continue
            try:
                obj = json.loads(ln)
            except Exception:
                continue
            if pred(obj):
                return obj
        raise AssertionError(f"Timed out waiting for stdout ({desc}); out={self.out_dump()} err={self.err_dump()}")

    def err_dump(self) -> str:
        with self._lock:
            return "\n".join(self._err_history)

    def out_dump(self) -> str:
        with self._lock:
            return "\n".join(self._out_history)

    def drain_out_json(self):
        out = []
        while True:
            try:
                ln = self.out_lines.get_nowait()
                try:
                    out.append(json.loads(ln))
                except Exception:
                    pass
            except queue.Empty:
                return out

    def kill_now(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=5)

    def close(self, timeout: float = 5.0):
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
        except OSError:
            pass
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        self._out_done.wait(timeout=2.0)


def run_cli(args, home: str, api_url: str, stdin_data=None, timeout: float = 30.0, extra_env=None):
    cmd = [CLI_BIN, "--api", api_url] + list(args)
    env = os.environ.copy()
    env["FATEXT_HOME"] = home
    if extra_env:
        env.update(extra_env)
    p = subprocess.run(cmd, input=stdin_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=timeout)
    return p.returncode, p.stdout.decode("utf-8", errors="replace"), p.stderr.decode("utf-8", errors="replace")


def init_agent(home: str, name: str, api_url: str) -> str:
    rc, out, err = run_cli(["--json", "--pow-bits", "12", "init", "--name", name], home=home, api_url=api_url)
    assert_eq(rc, 0, f"init {name} stderr={err}")
    return json.loads(out)["agent_id"]


def befriend(home_a: str, aid_a: str, home_b: str, aid_b: str, api_url: str):
    rc1, _, err1 = run_cli(["--json", "friend", "add", aid_b], home=home_a, api_url=api_url)
    assert_eq(rc1, 0, f"friend add {err1}")
    rc2, _, err2 = run_cli(["--json", "friend", "accept", aid_a], home=home_b, api_url=api_url)
    assert_eq(rc2, 0, f"friend accept {err2}")


def cli_supports_no_host_candidates() -> bool:
    _, out, err = run_cli(["p2p", "connect", "--help"], home="/tmp", api_url="http://127.0.0.1:1")
    return "--no-host-candidates" in (out + err)


def _cand_args(use_no_host: bool):
    return ["--no-host-candidates"] if use_no_host else []


def _start_echo_server(banner: bytes = b"", hold_before_reply: float = 0.0, conn_timeout: float = 30.0):
    port = free_tcp_port()
    stop = threading.Event()
    ready = threading.Event()

    def _srv():
        ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind(("127.0.0.1", port))
        ls.listen(16)
        ls.settimeout(0.2)
        ready.set()
        try:
            while not stop.is_set():
                try:
                    c, _ = ls.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                def _conn(cs=c):
                    try:
                        cs.settimeout(conn_timeout)
                        if banner:
                            cs.sendall(banner)
                        while True:
                            d = cs.recv(4096)
                            if not d:
                                break
                            if hold_before_reply > 0:
                                time.sleep(hold_before_reply)
                            cs.sendall(d)
                    except OSError:
                        pass
                    finally:
                        cs.close()

                threading.Thread(target=_conn, daemon=True).start()
        finally:
            ls.close()

    t = threading.Thread(target=_srv, daemon=True)
    t.start()
    ready.wait(timeout=2.0)
    return port, stop


# =============================================================================
# 12 P2P Test Cases
# =============================================================================

def t01_stun_discovery_and_failover(ctx):
    sim = UdpNatSim(nat_mode="port_restricted", stun_attr_mode="mapped", stun_garbage_first=True).start()
    dead_port = free_tcp_port()  # UDP port with nobody listening
    stun_arg = f"127.0.0.1:{dead_port},127.0.0.1:{sim.stun_port}"
    payload = os.urandom(8192)
    rx = tx = None
    try:
        rx = LineProc(
            ["--json", "p2p", "listen", "--stdio", "--stun", stun_arg] + _cand_args(ctx["no_host"]),
            home=ctx["hb"], api_url=ctx["api"], binary_stdout=True,
        )
        rx.wait_err_state("listening")
        tx = LineProc(
            ["--json", "p2p", "connect", ctx["bid"], "--stun", stun_arg] + _cand_args(ctx["no_host"]),
            home=ctx["ha"], api_url=ctx["api"],
        )
        tx.wait_err_state("connected", timeout=15.0)
        rx.wait_err_state("connected", timeout=15.0)
        tx.send_stdin(payload)
        tx.close_stdin()
        assert_eq(tx.proc.wait(timeout=15), 0, f"t01 tx exit stderr={tx.err_dump()}")
        assert_eq(rx.proc.wait(timeout=15), 0, f"t01 rx exit stderr={rx.err_dump()}")
        rx._out_done.wait(timeout=2.0)
        assert_eq(bytes(rx.out_bytes), payload, "t01 payload mismatch")
        assert_true(sim.stats["stun_reqs"] >= 2, f"STUN failover used ({sim.stats})")
    finally:
        if tx:
            tx.close()
        if rx:
            rx.close()
        sim.stop()


def t02_port_restricted_nat_and_noise(ctx):
    sim = UdpNatSim(nat_mode="port_restricted", stun_attr_mode="xor", tamper_inject=True).start()
    stun_arg = f"127.0.0.1:{sim.stun_port}"
    payload = os.urandom(32768)
    rx = tx = None
    try:
        rx = LineProc(
            ["--json", "p2p", "listen", "--stdio", "--stun", stun_arg] + _cand_args(ctx["no_host"]),
            home=ctx["hb"], api_url=ctx["api"], binary_stdout=True,
        )
        rx.wait_err_state("listening")
        tx = LineProc(
            ["--json", "p2p", "connect", ctx["bid"], "--stun", stun_arg] + _cand_args(ctx["no_host"]),
            home=ctx["ha"], api_url=ctx["api"],
        )
        tx.wait_err_state("connected", timeout=12.0)
        tx.send_stdin(payload)
        tx.close_stdin()
        assert_eq(tx.proc.wait(timeout=20), 0, f"t02 tx exit stderr={tx.err_dump()}")
        assert_eq(rx.proc.wait(timeout=20), 0, f"t02 rx exit stderr={rx.err_dump()}")
        rx._out_done.wait(timeout=2.0)
        assert_eq(hashlib.sha256(bytes(rx.out_bytes)).hexdigest(), hashlib.sha256(payload).hexdigest(), "t02 SHA-256")
        assert_true(sim.stats["tampered"] > 0, "tamper packets were injected and ignored")
    finally:
        if tx:
            tx.close()
        if rx:
            rx.close()
        sim.stop()


def t03_high_rtt_and_packet_loss_stdio(ctx):
    sim = UdpNatSim(
        nat_mode="port_restricted",
        delay_ms=90.0,
        jitter_ms=20.0,
        loss_rate=0.15,
        dup_rate=0.10,
        reorder_rate=0.10,
        drop_first_packets=1,
        drop_first_direction="0to1",
    ).start()
    stun_arg = f"127.0.0.1:{sim.stun_port}"
    payload = os.urandom(32768)
    rx = tx = None
    try:
        rx = LineProc(
            ["--json", "p2p", "listen", "--stdio", "--stun", stun_arg] + _cand_args(ctx["no_host"]),
            home=ctx["hb"], api_url=ctx["api"], binary_stdout=True,
        )
        rx.wait_err_state("listening")
        tx = LineProc(
            ["--json", "p2p", "connect", ctx["bid"], "--stun", stun_arg] + _cand_args(ctx["no_host"]),
            home=ctx["ha"], api_url=ctx["api"],
        )
        tx.wait_err_state("connected", timeout=12.0)
        tx.send_stdin(payload)
        tx.close_stdin()
        assert_eq(tx.proc.wait(timeout=35), 0, f"t03 tx exit stderr={tx.err_dump()}")
        assert_eq(rx.proc.wait(timeout=35), 0, f"t03 rx exit stderr={rx.err_dump()}")
        rx._out_done.wait(timeout=2.0)
        assert_eq(len(rx.out_bytes), len(payload), "t03 payload len")
        assert_eq(hashlib.sha256(bytes(rx.out_bytes)).hexdigest(), hashlib.sha256(payload).hexdigest(), "t03 SHA-256")
    finally:
        if tx:
            tx.close()
        if rx:
            rx.close()
        sim.stop()


def t04_high_rtt_and_loss_tcp_forward(ctx):
    echo_port, stop_echo = _start_echo_server()
    fwd_port = free_tcp_port()
    sim = UdpNatSim(
        nat_mode="port_restricted",
        delay_ms=80.0,
        jitter_ms=15.0,
        loss_rate=0.12,
        dup_rate=0.08,
    ).start()
    stun_arg = f"127.0.0.1:{sim.stun_port}"
    payload = os.urandom(49152)
    rx = tx = None
    try:
        rx = LineProc(
            ["--json", "p2p", "listen", "--expose", str(echo_port), "--stun", stun_arg] + _cand_args(ctx["no_host"]),
            home=ctx["hb"], api_url=ctx["api"],
        )
        rx.wait_err_state("listening")
        tx = LineProc(
            ["--json", "p2p", "connect", ctx["bid"], "--forward", f"{fwd_port}:{echo_port}", "--stun", stun_arg] + _cand_args(ctx["no_host"]),
            home=ctx["ha"], api_url=ctx["api"],
        )
        tx.wait_err_state("connected", timeout=12.0)
        with socket.create_connection(("127.0.0.1", fwd_port), timeout=10.0) as cs:
            cs.settimeout(25.0)
            cs.sendall(payload)
            cs.shutdown(socket.SHUT_WR)
            got = bytearray()
            while True:
                d = cs.recv(8192)
                if not d:
                    break
                got.extend(d)
        assert_eq(len(got), len(payload), "t04 echo len")
        assert_eq(hashlib.sha256(bytes(got)).hexdigest(), hashlib.sha256(payload).hexdigest(), "t04 echo SHA-256")
        assert_eq(tx.proc.wait(timeout=20), 0, f"t04 tx exit stderr={tx.err_dump()}")
        assert_eq(rx.proc.wait(timeout=20), 0, f"t04 rx exit stderr={rx.err_dump()}")
    finally:
        if tx:
            tx.close()
        if rx:
            rx.close()
        stop_echo.set()
        sim.stop()


def t05_server_first_banner_delayed_accept(ctx):
    banner = b"SSH-2.0-FATEXT_BANNER_TEST_" + (b"B" * 2048) + b"\n"
    echo_port, stop_echo = _start_echo_server(banner=banner)
    fwd_port = free_tcp_port()
    rx = tx = None
    try:
        rx = LineProc(
            ["--json", "p2p", "listen", "--expose", str(echo_port), "--stun", "none"],
            home=ctx["hb"], api_url=ctx["api"],
        )
        rx.wait_err_state("listening")
        tx = LineProc(
            ["--json", "p2p", "connect", ctx["bid"], "--forward", f"{fwd_port}:{echo_port}", "--stun", "none"],
            home=ctx["ha"], api_url=ctx["api"],
        )
        tx.wait_err_state("connected", timeout=10.0)
        # Wait 1.2s BEFORE dialing local forward port; server banner packets are already arriving
        time.sleep(1.2)
        ping_msg = b"CLIENT_AFTER_BANNER_MSG"
        with socket.create_connection(("127.0.0.1", fwd_port), timeout=5.0) as cs:
            cs.settimeout(5.0)
            cs.sendall(ping_msg)
            cs.shutdown(socket.SHUT_WR)
            got = bytearray()
            while True:
                d = cs.recv(4096)
                if not d:
                    break
                got.extend(d)
        assert_eq(bytes(got), banner + ping_msg, "t05 server banner + echo")
        assert_eq(tx.proc.wait(timeout=10), 0, f"t05 tx exit stderr={tx.err_dump()}")
        assert_eq(rx.proc.wait(timeout=10), 0, f"t05 rx exit stderr={rx.err_dump()}")
    finally:
        if tx:
            tx.close()
        if rx:
            rx.close()
        stop_echo.set()


def t06_target_port_unreachable(ctx):
    dead_target_port = free_tcp_port()  # nothing listening
    fwd_port = free_tcp_port()
    rx = tx = None
    try:
        rx = LineProc(
            ["--json", "p2p", "listen", "--expose", str(dead_target_port), "--stun", "none"],
            home=ctx["hb"], api_url=ctx["api"],
        )
        rx.wait_err_state("listening")
        tx = LineProc(
            ["--json", "p2p", "connect", ctx["bid"], "--forward", f"{fwd_port}:{dead_target_port}", "--stun", "none"],
            home=ctx["ha"], api_url=ctx["api"],
        )
        rx_rc = rx.proc.wait(timeout=10.0)
        tx_rc = tx.proc.wait(timeout=10.0)
        assert_true(rx_rc != 0, f"t06 listener failed cleanly on unreachable target (rc={rx_rc})")
        assert_true(tx_rc == 9 or "target_dial_failed" in rx.err_dump(), f"t06 initiator notified/closed cleanly (tx_rc={tx_rc} rx_err={rx.err_dump()})")
    finally:
        if tx:
            tx.close()
        if rx:
            rx.close()


def t07_slow_stdio_stream_and_empty_eof(ctx):
    # (a) Slow sender pauses 6.5s mid-stream (exceeding old 5.5s receiver idle timeout)
    p1 = b"CHUNK_ONE_BEFORE_PAUSE_" * 30
    p2 = b"CHUNK_TWO_AFTER_6P5S_PAUSE_" * 30
    env_fast_ping = {"FATEXT_P2P_PING_MS": "1000", "FATEXT_P2P_IDLE_TIMEOUT_MS": "12000"}
    rx = tx = None
    try:
        rx = LineProc(
            ["--json", "p2p", "listen", "--stdio", "--stun", "none"],
            home=ctx["hb"], api_url=ctx["api"], binary_stdout=True, extra_env=env_fast_ping,
        )
        rx.wait_err_state("listening")
        tx = LineProc(
            ["--json", "p2p", "connect", ctx["bid"], "--stun", "none"],
            home=ctx["ha"], api_url=ctx["api"], extra_env=env_fast_ping,
        )
        tx.wait_err_state("connected", timeout=10.0)
        tx.send_stdin(p1)
        time.sleep(6.5)
        tx.send_stdin(p2)
        tx.close_stdin()
        assert_eq(tx.proc.wait(timeout=12), 0, f"t07a tx exit stderr={tx.err_dump()}")
        assert_eq(rx.proc.wait(timeout=12), 0, f"t07a rx exit stderr={rx.err_dump()}")
        rx._out_done.wait(timeout=2.0)
        assert_eq(bytes(rx.out_bytes), p1 + p2, "t07a slow pause stdio payload")
    finally:
        if tx:
            tx.close()
        if rx:
            rx.close()

    # (b) Empty 0-byte EOF
    rx2 = tx2 = None
    try:
        rx2 = LineProc(["--json", "p2p", "listen", "--stdio", "--stun", "none"], home=ctx["hb"], api_url=ctx["api"], binary_stdout=True)
        rx2.wait_err_state("listening")
        tx2 = LineProc(["--json", "p2p", "connect", ctx["bid"], "--stun", "none"], home=ctx["ha"], api_url=ctx["api"])
        tx2.wait_err_state("connected", timeout=10.0)
        tx2.close_stdin()
        assert_eq(tx2.proc.wait(timeout=8), 0, "t07b empty tx exit")
        assert_eq(rx2.proc.wait(timeout=8), 0, "t07b empty rx exit")
        rx2._out_done.wait(timeout=2.0)
        assert_eq(len(rx2.out_bytes), 0, "t07b empty rx bytes")
    finally:
        if tx2:
            tx2.close()
        if rx2:
            rx2.close()


def t08_nat_port_migration(ctx):
    sim = UdpNatSim(
        nat_mode="port_restricted",
        migrate_after_packets=8,
        migrate_target_index=1,  # migrate peer A (initiator, registered after listener)
    ).start()
    stun_arg = f"127.0.0.1:{sim.stun_port}"
    payload = os.urandom(32768)
    rx = tx = None
    try:
        rx = LineProc(
            ["--json", "p2p", "listen", "--stdio", "--stun", stun_arg] + _cand_args(ctx["no_host"]),
            home=ctx["hb"], api_url=ctx["api"], binary_stdout=True,
        )
        rx.wait_err_state("listening")
        tx = LineProc(
            ["--json", "p2p", "connect", ctx["bid"], "--stun", stun_arg] + _cand_args(ctx["no_host"]),
            home=ctx["ha"], api_url=ctx["api"],
        )
        tx.wait_err_state("connected", timeout=12.0)
        tx.send_stdin(payload)
        tx.close_stdin()
        assert_eq(tx.proc.wait(timeout=20), 0, f"t08 tx exit stderr={tx.err_dump()}")
        assert_eq(rx.proc.wait(timeout=20), 0, f"t08 rx exit stderr={rx.err_dump()}")
        rx._out_done.wait(timeout=2.0)
        assert_true(sim.stats["migrated"] >= 1, f"NAT migration occurred: {sim.stats}")
        assert_eq(hashlib.sha256(bytes(rx.out_bytes)).hexdigest(), hashlib.sha256(payload).hexdigest(), "t08 SHA-256")
    finally:
        if tx:
            tx.close()
        if rx:
            rx.close()
        sim.stop()


def t09_symmetric_nat_punch_timeout(ctx):
    sim = UdpNatSim(nat_mode="symmetric").start()
    stun_arg = f"127.0.0.1:{sim.stun_port}"
    env_to = {"FATEXT_P2P_PUNCH_TIMEOUT_MS": "2000"}
    rx = tx = None
    try:
        rx = LineProc(
            ["--json", "p2p", "listen", "--stdio", "--stun", stun_arg] + _cand_args(ctx["no_host"]),
            home=ctx["hb"], api_url=ctx["api"], extra_env=env_to,
        )
        rx.wait_err_state("listening")
        t0 = time.time()
        tx = LineProc(
            ["--json", "p2p", "connect", ctx["bid"], "--stun", stun_arg] + _cand_args(ctx["no_host"]),
            home=ctx["ha"], api_url=ctx["api"], extra_env=env_to,
        )
        tx_rc = tx.proc.wait(timeout=10.0)
        rx_rc = rx.proc.wait(timeout=10.0)
        elapsed = time.time() - t0
        assert_eq(tx_rc, 9, f"t09 tx punch timeout exit=9 stderr={tx.err_dump()}")
        assert_eq(rx_rc, 9, f"t09 rx punch timeout exit=9 stderr={rx.err_dump()}")
        assert_true("punch_timeout" in tx.err_dump() and "punch_timeout" in rx.err_dump(), "t09 punch_timeout logged")
        assert_true(elapsed < 6.0, f"t09 completed quickly ({elapsed:.2f}s)")
    finally:
        if tx:
            tx.close()
        if rx:
            rx.close()
        sim.stop()


def t10_star_bus_loss_large_msg_and_ack_drop(ctx):
    sim = UdpNatSim(
        nat_mode="port_restricted",
        delay_ms=40.0,
        jitter_ms=10.0,
        loss_rate=0.10,
        drop_first_packets=1,
        drop_first_direction="1to0",  # drop first PUNCH ACK from client->hub
    ).start()
    stun_arg = f"127.0.0.1:{sim.stun_port}"
    hub = None
    spokes = []
    try:
        hub = LineProc(
            ["--json", "p2p", "listen", "--star", "--bus", "--max-peers", "4", "--stun", stun_arg] + _cand_args(ctx["no_host"]),
            home=ctx["hb"], api_url=ctx["api"],
        )
        hub.wait_err_state("listening")
        for shome in (ctx["ha"], ctx["hc"]):
            sp = LineProc(
                ["--json", "p2p", "connect", ctx["bid"], "--bus", "--stun", stun_arg] + _cand_args(ctx["no_host"]),
                home=shome, api_url=ctx["api"],
            )
            sp.wait_err_state("connected", timeout=15.0)
            spokes.append(sp)

        big_text = "LARGE_MULTI_CHUNK_BUS_" + ("X" * 4000)
        spokes[0].send_line(json.dumps({"to": "*", "text": big_text}))
        ev_h = hub.wait_out_json(lambda e: e.get("text") == big_text, timeout=15.0, desc="hub got 4KB broadcast")
        assert_eq(ev_h["from"], ctx["aid"], "t10 from aid")
        ev_c = spokes[1].wait_out_json(lambda e: e.get("text") == big_text, timeout=15.0, desc="spoke C got 4KB broadcast")
        assert_eq(ev_c["from"], ctx["aid"], "t10 forwarded from aid")

        hub.send_line(json.dumps({"to": ctx["cid"], "text": "HUB_UNICAST_OK"}))
        spokes[1].wait_out_json(lambda e: e.get("text") == "HUB_UNICAST_OK", timeout=10.0, desc="spoke C got hub unicast")
        time.sleep(0.3)
        assert_true(all(e.get("text") != "HUB_UNICAST_OK" for e in spokes[0].drain_out_json()), "spoke A isolated from unicast to C")
    finally:
        for sp in spokes:
            sp.close()
        if hub:
            hub.close()
        sim.stop()


def t11_star_max_peers_and_zombie_reap(ctx):
    echo_port, stop_echo = _start_echo_server()
    env_reap = {"FATEXT_P2P_PING_MS": "300", "FATEXT_P2P_IDLE_TIMEOUT_MS": "1500"}
    hub = s1 = s2 = s3 = None
    try:
        hub = LineProc(
            ["--json", "p2p", "listen", "--star", "--max-peers", "2", "--expose", str(echo_port), "--stun", "none"],
            home=ctx["hb"], api_url=ctx["api"], extra_env=env_reap,
        )
        hub.wait_err_state("listening")

        f1, f2, f3 = free_tcp_port(), free_tcp_port(), free_tcp_port()
        s1 = LineProc(["--json", "p2p", "connect", ctx["bid"], "--forward", f"{f1}:{echo_port}", "--stun", "none"],
                      home=ctx["ha"], api_url=ctx["api"], extra_env=env_reap)
        s1.wait_err_state("connected", timeout=10.0)
        s2 = LineProc(["--json", "p2p", "connect", ctx["bid"], "--forward", f"{f2}:{echo_port}", "--stun", "none"],
                      home=ctx["hc"], api_url=ctx["api"], extra_env=env_reap)
        s2.wait_err_state("connected", timeout=10.0)

        # 3rd peer rejected immediately when 2/2 slots are occupied
        rc3, _, err3 = run_cli(
            ["--json", "p2p", "connect", ctx["bid"], "--forward", f"{f3}:{echo_port}", "--stun", "none"],
            home=ctx["hd"], api_url=ctx["api"], timeout=15.0,
        )
        assert_eq(rc3, 9, f"t11 3rd peer rejected (err={err3})")
        assert_true("max_peers_reached" in err3, f"t11 max_peers_reached in err={err3}")

        # Abruptly SIGKILL spoke 1 (no FIN sent!) -> hub must reap via heartbeat timeout and free 1 slot
        s1.kill_now()
        hub.wait_err_state("closed", timeout=3.5)

        f3b = free_tcp_port()
        s3 = LineProc(["--json", "p2p", "connect", ctx["bid"], "--forward", f"{f3b}:{echo_port}", "--stun", "none"],
                      home=ctx["hd"], api_url=ctx["api"], extra_env=env_reap)
        s3.wait_err_state("connected", timeout=10.0)
        with socket.create_connection(("127.0.0.1", f3b), timeout=5.0) as cs:
            cs.sendall(b"AFTER_ZOMBIE_REAP_OK")
            cs.shutdown(socket.SHUT_WR)
            assert_eq(cs.recv(4096), b"AFTER_ZOMBIE_REAP_OK", "t11 spoke 3 echo after zombie reap")
    finally:
        for sp in (s1, s2, s3):
            if sp:
                sp.close()
        if hub:
            hub.close()
        stop_echo.set()


def t12_signaling_security_and_key_rotation(ctx):
    # 1. Conflicting flags -> EXIT_USAGE (2)
    for bad_args in [
        ["p2p", "listen", "--allow-friends-only", "--allow-anyone"],
        ["p2p", "listen", "--stdio", "--star"],
        ["p2p", "connect", ctx["bid"], "--relay", "turn:127.0.0.1:3478"],
        ["p2p", "connect", ctx["bid"], "--forward", "1000:2000", "--bus"],
    ]:
        rc, _, _ = run_cli(bad_args, home=ctx["ha"], api_url=ctx["api"])
        assert_eq(rc, 2, f"t12 conflicting flags {bad_args}")

    # 2. Friends-only rejection, port_not_exposed, malformed offers, and --allow-anyone
    stranger_home = os.path.join(ctx["td"], "stranger")
    sid = init_agent(stranger_home, "p2p-stranger", ctx["api"])
    echo_port, stop_echo = _start_echo_server()
    bad_port = free_tcp_port()
    rx = None
    try:
        rx = LineProc(
            ["--json", "p2p", "listen", "--star", "--allow-friends-only", "--expose", str(echo_port), "--stun", "none"],
            home=ctx["hb"], api_url=ctx["api"],
        )
        rx.wait_err_state("listening")

        # Stranger rejected (not_friend)
        rc_s, _, err_s = run_cli(
            ["--json", "p2p", "connect", ctx["bid"], "--forward", f"{free_tcp_port()}:{echo_port}", "--stun", "none"],
            home=stranger_home, api_url=ctx["api"], timeout=15.0,
        )
        assert_eq(rc_s, 9, f"t12 stranger rejected rc={rc_s} err={err_s}")
        assert_true("not_friend" in err_s, f"t12 not_friend in {err_s}")

        # Friend requesting unexposed port rejected
        rc_p, _, err_p = run_cli(
            ["--json", "p2p", "connect", ctx["bid"], "--forward", f"{free_tcp_port()}:{bad_port}", "--stun", "none"],
            home=ctx["ha"], api_url=ctx["api"], timeout=15.0,
        )
        assert_eq(rc_p, 9, f"t12 unexposed port rc={rc_p}")
        assert_true("port_not_exposed" in err_p, f"t12 port_not_exposed in {err_p}")

        # Malformed synthetic offers (stale ts, expired, bad x25519_pub, bad candidate, replay nonce) -> listener stays alive
        b_pub = json.loads(urllib.request.urlopen(f"{ctx['api']}/k/{ctx['bid']}.json").read().decode())["current_public_key_pem"]
        b_kv = json.loads(urllib.request.urlopen(f"{ctx['api']}/k/{ctx['bid']}.json").read().decode())["key_version"]
        now = int(time.time())
        a_priv = os.path.join(ctx["ha"], "private.pem")
        malformed_bodies = [
            (now - 120, "nonce-stale", {"session": "s_stale", "candidates": [{"t": "host", "a": "127.0.0.1:1"}], "x25519_pub": "AAAA", "mode": "forward", "remote_port": echo_port, "expires_at": now + 60}),
            (now, "nonce-exp", {"session": "s_exp", "candidates": [{"t": "host", "a": "127.0.0.1:1"}], "x25519_pub": "AAAA", "mode": "forward", "remote_port": echo_port, "expires_at": now - 5}),
            (now, "nonce-badcand", {"session": "s_badc", "candidates": [{"t": "host", "a": "0.0.0.0:1234"}, {"t": "host", "a": "::1:1234"}], "x25519_pub": base64.b64encode(os.urandom(32)).decode(), "mode": "forward", "remote_port": echo_port, "expires_at": now + 60}),
            (now, "nonce-replay", {"session": "s_rep", "candidates": [], "x25519_pub": "not-base64!!!", "mode": "forward", "remote_port": echo_port, "expires_at": now + 60}),
            (now, "nonce-replay", {"session": "s_rep2", "candidates": [], "x25519_pub": "not-base64!!!", "mode": "forward", "remote_port": echo_port, "expires_at": now + 60}),
        ]
        if ctx.get("relay_state") is not None:
            for ts_f, n_f, bo in malformed_bodies:
                fr = json.loads(build_dm_frame(ctx["aid"], a_priv, ctx["bid"], b_pub, b_kv, "p2p_offer", bo, ts_f, nonce=n_f).decode())
                ctx["relay_state"].push_sse(ctx["bid"], "dm", {"from": ctx["aid"], "frame": fr})

        # Verify listener stayed alive and still serves valid friend
        time.sleep(0.4)
        assert_true(rx.proc.poll() is None, "t12 listener stayed alive after malformed offers")
        rx.close()
        rx = None

        # Offer without proto="fatext-p2p-v3" must be rejected as unsupported_p2p_proto
        rx_proto = LineProc(["--json", "p2p", "listen", "--allow-anyone", "--stdio", "--stun", "none"], home=ctx["hb"], api_url=ctx["api"], binary_stdout=True)
        rx_proto.wait_err_state("listening")
        if ctx.get("relay_state") is not None:
            old_offer = {"session": "s_old_proto", "candidates": [{"t": "host", "a": "127.0.0.1:1"}], "x25519_pub": base64.b64encode(os.urandom(32)).decode(), "mode": "stdio", "remote_port": 0, "expires_at": now + 60}
            fr_old = json.loads(build_dm_frame(ctx["aid"], a_priv, ctx["bid"], b_pub, b_kv, "p2p_offer", old_offer, now, nonce="nonce-old-proto").decode())
            ctx["relay_state"].push_sse(ctx["bid"], "dm", {"from": ctx["aid"], "frame": fr_old})
            time.sleep(0.4)
            assert_true(rx_proto.proc.poll() is None, "t12 listener stayed alive after old proto offer")
        rx_proto.close()
        rx_proto = None

        # Rotate key on A, then verify --allow-anyone with stranger and post-rotation friend P2P
        rc_rot, _, err_rot = run_cli(["--json", "key", "rotate"], home=ctx["ha"], api_url=ctx["api"])
        assert_eq(rc_rot, 0, f"t12 key rotate err={err_rot}")

        rx_any = LineProc(["--json", "p2p", "listen", "--allow-anyone", "--stdio", "--stun", "none"], home=ctx["hb"], api_url=ctx["api"], binary_stdout=True)
        rx_any.wait_err_state("listening")
        rc_ok1, _, err_ok1 = run_cli(["--json", "p2p", "connect", ctx["bid"], "--stun", "none"], home=stranger_home, api_url=ctx["api"], stdin_data=b"STRANGER_OK")
        assert_eq(rc_ok1, 0, f"t12 allow-anyone stranger err={err_ok1}")
        assert_eq(rx_any.proc.wait(timeout=10), 0, "t12 rx_any exit")
        rx_any._out_done.wait(timeout=2.0)
        assert_eq(bytes(rx_any.out_bytes), b"STRANGER_OK", "t12 stranger payload")

        rx_rot = LineProc(["--json", "p2p", "listen", "--allow-friends-only", "--stdio", "--stun", "none"], home=ctx["hb"], api_url=ctx["api"], binary_stdout=True)
        rx_rot.wait_err_state("listening")
        rc_ok2, _, err_ok2 = run_cli(["--json", "p2p", "connect", ctx["bid"], "--stun", "none"], home=ctx["ha"], api_url=ctx["api"], stdin_data=b"POST_ROTATE_OK")
        assert_eq(rc_ok2, 0, f"t12 post-rotate err={err_ok2}")
        assert_eq(rx_rot.proc.wait(timeout=10), 0, "t12 rx_rot exit")
        rx_rot._out_done.wait(timeout=2.0)
        assert_eq(bytes(rx_rot.out_bytes), b"POST_ROTATE_OK", "t12 post-rotate payload")
    finally:
        if rx:
            rx.close()
        stop_echo.set()


def t13_replay_migration_and_zombie_spoof(ctx):
    # Subtest A: Replay captured DATA/PING packets from spoofed attacker socket mid-transfer;
    # peer B must NOT migrate peer_addr, must send ZERO packets to attacker socket, and transfer succeeds.
    sim = UdpNatSim(
        nat_mode="cone",
        delay_ms=15,
        replay_spoof_after=6,
        replay_target_index=1,
        drop_real_after_replay=False,
    ).start()
    stun_arg = f"127.0.0.1:{sim.stun_port}"
    payload = os.urandom(32768)
    rx = tx = None
    try:
        rx = LineProc(
            ["--json", "p2p", "listen", "--stdio", "--stun", stun_arg] + _cand_args(ctx["no_host"]),
            home=ctx["hb"], api_url=ctx["api"], binary_stdout=True,
        )
        rx.wait_err_state("listening")
        tx = LineProc(
            ["--json", "p2p", "connect", ctx["bid"], "--stun", stun_arg] + _cand_args(ctx["no_host"]),
            home=ctx["ha"], api_url=ctx["api"],
        )
        tx.wait_err_state("connected", timeout=12.0)
        tx.send_stdin(payload)
        tx.close_stdin()
        assert_eq(tx.proc.wait(timeout=20), 0, f"t13a tx exit stderr={tx.err_dump()}")
        assert_eq(rx.proc.wait(timeout=20), 0, f"t13a rx exit stderr={rx.err_dump()}")
        rx._out_done.wait(timeout=2.0)
        assert_true(sim.stats["replayed_sent"] >= 10, f"t13a replay storm ran: {sim.stats}")
        assert_eq(sim.stats["atk_replies"], 0, f"t13a zero packets reflected to replay attacker: {sim.stats}")
        assert_eq(hashlib.sha256(bytes(rx.out_bytes)).hexdigest(), hashlib.sha256(payload).hexdigest(), "t13a SHA-256")
    finally:
        if tx:
            tx.close()
        if rx:
            rx.close()
        sim.stop()

    # Subtest B: Real peer goes dead while attacker keeps replaying captured packets;
    # receiver must NOT refresh last_rx_ns on replays and must exit after idle timeout.
    sim2 = UdpNatSim(
        nat_mode="cone",
        replay_spoof_after=4,
        replay_target_index=1,
        drop_real_after_replay=True,
    ).start()
    stun_arg2 = f"127.0.0.1:{sim2.stun_port}"
    rx2 = tx2 = None
    try:
        env2 = {"FATEXT_P2P_IDLE_TIMEOUT_MS": "900", "FATEXT_P2P_PING_MS": "200"}
        rx2 = LineProc(
            ["--json", "p2p", "listen", "--stdio", "--stun", stun_arg2] + _cand_args(ctx["no_host"]),
            home=ctx["hb"], api_url=ctx["api"], binary_stdout=True, extra_env=env2,
        )
        rx2.wait_err_state("listening")
        tx2 = LineProc(
            ["--json", "p2p", "connect", ctx["bid"], "--stun", stun_arg2] + _cand_args(ctx["no_host"]),
            home=ctx["ha"], api_url=ctx["api"], extra_env=env2,
        )
        tx2.wait_err_state("connected", timeout=12.0)
        tx2.send_stdin(b"BEFORE_BLACKHOLE\n")
        rx2_rc = rx2.proc.wait(timeout=8)
        assert_eq(rx2_rc, 0, f"t13b rx2 idle reap rc={rx2_rc}")
        assert_true(sim2.stats["replayed_sent"] >= 10, f"t13b replay storm ran: {sim2.stats}")
        assert_eq(sim2.stats["atk_replies"], 0, f"t13b zero packets reflected on zombie spoof: {sim2.stats}")
    finally:
        if tx2:
            tx2.close()
        if rx2:
            rx2.close()
        sim2.stop()


TESTS = [
    ("T01_stun_discovery_and_failover", t01_stun_discovery_and_failover),
    ("T02_port_restricted_nat_and_noise", t02_port_restricted_nat_and_noise),
    ("T03_high_rtt_and_packet_loss_stdio", t03_high_rtt_and_packet_loss_stdio),
    ("T04_high_rtt_and_loss_tcp_forward", t04_high_rtt_and_loss_tcp_forward),
    ("T05_server_first_banner_delayed_accept", t05_server_first_banner_delayed_accept),
    ("T06_target_port_unreachable", t06_target_port_unreachable),
    ("T07_slow_stdio_stream_and_empty_eof", t07_slow_stdio_stream_and_empty_eof),
    ("T08_nat_port_migration", t08_nat_port_migration),
    ("T09_symmetric_nat_punch_timeout", t09_symmetric_nat_punch_timeout),
    ("T10_star_bus_loss_large_msg_and_ack_drop", t10_star_bus_loss_large_msg_and_ack_drop),
    ("T11_star_max_peers_and_zombie_reap", t11_star_max_peers_and_zombie_reap),
    ("T12_signaling_security_and_key_rotation", t12_signaling_security_and_key_rotation),
    ("T13_replay_migration_and_zombie_spoof", t13_replay_migration_and_zombie_spoof),
]


def main():
    ap = argparse.ArgumentParser(description="Comprehensive P2P test suite for fatext")
    ap.add_argument("--api", default="", help="Optional external API URL instead of built-in relay")
    ap.add_argument("--only", default="", help="Comma-separated test prefixes to run (e.g. T03,T05)")
    ap.add_argument("--keep-going", action="store_true", help="Run all selected tests even if some fail")
    args = ap.parse_args()

    if not os.path.isfile(CLI_BIN):
        raise SystemExit(f"Missing CLI binary: {CLI_BIN} (run make build first)")

    relay_srv = None
    relay_state = None
    api_url = args.api.strip()
    if not api_url:
        relay_state = RelayState()
        port = free_tcp_port()
        relay_srv = ThreadingHTTPServer(("127.0.0.1", port), make_relay_handler(relay_state))
        threading.Thread(target=relay_srv.serve_forever, daemon=True).start()
        api_url = f"http://127.0.0.1:{port}"

    with tempfile.TemporaryDirectory(prefix="fatext-p2p-suite-") as td:
        ha = os.path.join(td, "ha")
        hb = os.path.join(td, "hb")
        hc = os.path.join(td, "hc")
        hd = os.path.join(td, "hd")
        aid = init_agent(ha, "p2p-a", api_url)
        bid = init_agent(hb, "p2p-b", api_url)
        cid = init_agent(hc, "p2p-c", api_url)
        did = init_agent(hd, "p2p-d", api_url)
        befriend(ha, aid, hb, bid, api_url)
        befriend(hc, cid, hb, bid, api_url)
        befriend(hd, did, hb, bid, api_url)

        ctx = {
            "td": td,
            "api": api_url,
            "relay_state": relay_state,
            "ha": ha, "hb": hb, "hc": hc, "hd": hd,
            "aid": aid, "bid": bid, "cid": cid, "did": did,
            "no_host": cli_supports_no_host_candidates(),
        }

        only_prefixes = [x.strip() for x in args.only.split(",") if x.strip()] if args.only else []
        selected = [
            (name, fn) for name, fn in TESTS
            if not only_prefixes or any(name.startswith(p) for p in only_prefixes)
        ]

        failures = []
        print(f"[P2P] Running {len(selected)} P2P tests against {CLI_BIN} (no_host_flag={ctx['no_host']})...")
        for idx, (name, fn) in enumerate(selected, 1):
            t0 = time.time()
            try:
                fn(ctx)
                print(f"  [{idx}/{len(selected)}] PASS {name} ({time.time() - t0:.2f}s)")
            except Exception as e:
                print(f"  [{idx}/{len(selected)}] FAIL {name} ({time.time() - t0:.2f}s): {e}")
                failures.append((name, str(e)))
                if not args.keep_going:
                    break

        if relay_srv:
            relay_srv.shutdown()
            relay_srv.server_close()

        if failures:
            print(f"[P2P] FAILED ({len(failures)}/{len(selected)}).")
            sys.exit(1)
        print(f"ALL {len(selected)} P2P TESTS PASSED.")


if __name__ == "__main__":
    main()
