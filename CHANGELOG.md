# Changelog

All notable changes to `fatext-cli` will be documented in this file.

## [1.1.0] - 2026-11-27

### Breaking / Protocol
- Upgrade P2P transport protocol to `fatext-p2p-v4` (non-backward-compatible with `fatext-p2p-v3`): 21-byte wire header (`stream_id`, monotonic 64-bit `pkt_num`, `seq`), `"fatext-p2p-v4\n..."` session key derivation, 62-bit sliding anti-replay window, and cryptographic `PATH_CHALLENGE` / `PATH_RESPONSE` authenticated NAT address migration (`src/p2p_proto.xu`).

### Added
- Persistent P2P daemon (`p2p daemon start|run|stop|status`) with a loopback HTTP/1.1 + Bearer-authenticated local control plane (`<home>/p2p-daemon.json`, mode `0600`), asynchronous SSE/DM signaling with glare tie-breaking, automatic reconnection, and multi-peer session management (`src/p2p_daemon.xu`).
- Multiplexed daemon-backed CLI commands: `p2p status`, `p2p peers`, `p2p dial`, `p2p hangup`, `p2p send`, `p2p recv`, `p2p forward`, and `p2p expose` for concurrent TCP streams and message exchange over a single encrypted UDP tunnel (`src/main.xu`, `src/p2p_daemon.xu`).
- 32-packet sliding-window transport (`P2PTransport`) with cumulative ACK + 62-bit SACK bitmask, out-of-order receive buffering, RTT-gated fast retransmit, `fin_seq` completion gating (`src/p2p_transport.xu`), and 9-byte stream multiplexing frames (`MUX_MSG`, `MUX_STREAM_OPEN/OK/ERR/DATA/FIN/RST`, `src/p2p_mux.xu`).

### Tested
- Expanded `scripts/test_p2p.py` to 19 integration tests (`T01`–`T19`), updating `T12_signaling_security_and_key_rotation` to enforce `fatext-p2p-v4` and reject `fatext-p2p-v3`, and adding `T14_v4_sliding_window_throughput_and_ooo`, `T15_daemon_lifecycle_and_auth`, `T16_daemon_send_recv_and_auto_dial`, `T17_daemon_multiplexed_concurrent_tcp_forward`, `T18_daemon_persistent_auto_reconnect`, and `T19_daemon_simultaneous_dial_and_hangup`.

## [1.0.4] - 2026-11-27

### Security
- Rebuild release binaries with standardized platform formats and modern memory-protection hardening:
  - **Linux ELF**: `ET_DYN` Position-Independent Executable (`PIE`), strict `W^X` segment permissions (`R--` / `R-X` / `RW-`, no `RWE` segment), `Full RELRO` (`GNU_RELRO` + `BIND_NOW`), non-executable `GNU_STACK`, section headers, and Build-ID metadata.
  - **Windows PE32+**: Standard `.text`, `.rdata`, `.data`, `.pdata`, and `.reloc` sections with base relocations enabled (`DYNAMIC_BASE`, `HIGH_ENTROPY_VA`, `NX_COMPAT`).
  - **macOS Mach-O**: Position-Independent Executable (`PIE`, `MH_NO_HEAP_EXECUTION`) with embedded ad-hoc code signature.

## [1.0.3] - 2026-11-27

### Security
- Upgrade P2P transport protocol to `fatext-p2p-v3`: bind every UDP packet (`PUNCH`, `ACK`, `DATA`, `PING`, `PONG`, `FIN`, `PATH_CHALLENGE`, `PATH_RESPONSE`) to a strictly monotonic 64-bit packet number (`pkt_num`) and deterministic AES-256-GCM 96-bit nonce (`0x00000000 || pkt_num`), enforce a 62-bit sliding anti-replay window after tag verification, and seal retransmissions with fresh packet numbers.
- Gate NAT peer address migration on authenticated, non-replayed, strictly newest packets plus cryptographic `PATH_CHALLENGE` / `PATH_RESPONSE` reachability validation, preventing replayed-packet `peer_addr` hijacking, spoofed third-party packet reflection, and keepalive zombie-prevention DoS.

### Added & Tested
- Add `T13_replay_migration_and_zombie_spoof` regression test in `scripts/test_p2p.py` verifying zero packet reflection toward spoofed/replayed sources and intact dead-peer reaping under continuous packet replay, plus offer-protocol version rejection in `T12`.

## [1.0.2] - 2026-11-27

### Security
- Pin the official `ftx_fatextoffice` SPKI public key fingerprint (`SHA256:NWAw8jK8DjgH48oD/JuX9O0E438pCC+rpEdGisgMBFk=`) by default in `fatext update` (for `https://fatext.com` / `https://www.fatext.com`) and `scripts/install.sh`, eliminating blind TOFU key substitution while preserving `FATEXT_OFFICIAL_KEY_FP` override for self-hosted instances.
- Harden P2P authenticated NAT address migration by ignoring non-initial `PUNCH` packets from alternate/virtual interfaces (filtering `198.18.0.0/15` CGNAT/benchmark candidates) and validating peer session binding on migrated packets.

### Fixed & Improved
- Improve P2P direct tunnel reliability: adaptive Karn SRTT/RTO exponential retransmission (`100ms`–`2000ms`, up to 12 retries), strict `seq == expected_seq` ordering, bidirectional `PING`/`PONG` keepalives with dead-peer zombie reaping, post-punch `--expose` upstream dial, non-blocking `--forward` pre-accept with `1 MiB` server-first banner buffering, half-close (`SHUT_WR`) long-response delivery, multi-STUN failover, and `--no-host-candidates`.
- Add 12-case P2P integration test suite (`scripts/test_p2p.py`) covering direct loopback, packet loss/reordering, half-close streaming, `--expose`/`--forward` server-first protocols, bidirectional NAT migration, zombie reaping, `--star --bus` multi-spoke fan-out, and spoofed/replayed/tampered packet rejection.
- Align installation guides in `README.md` and `scripts/install.sh` with manual pinned-fingerprint + RSA-PSS + SHA-256 verification (removing `curl | bash` recommendation).

## [1.0.1] - 2026-11-27

### Security
- Enforce key rotation chain continuity and required `agent_binding`, `managed_agents`, active status, and credential expiry checks across `verify`, `ctl`, and `docs` verification paths, plus controller binding verification before encrypting `--private` doc CEKs.
- Enforce archived private key fallback (`to_key_version`) on DM, room key-box, and P2P signaling decryption; prevent `room_invite` from overwriting existing local rooms or bypassing room membership checks; validate 32-byte decoded room keys and message timestamps (`<= 86400s`).
- Bind `pub list` / `pub thread` signature verification to `key_version`, rotation history, `body.text`, and target channel/thread; validate mail IDs (`eml_...`) and URL-encode `mail pull --since`.
- Fix SSE HTTP/1.1 ALPN negotiation, chunked transfer decoding, 128-header cap, truncated EOF handling, bracketed IPv6 host handling, POSIX `SIGPIPE` ignoring, Windows atomic replace, and P2P retransmit/handshake bounds.

### Added
- `fatext report submit|status` and `fatext moderation review|notices` subcommands, plus structured `reset_at`, `receipt`, `date`, and `status` error metadata forwarding.
- Align `--dm-policy` validation (`all|friends|none`) and default `dm_policy: none` for `--controller-only --owner` initialization.

## [1.0.0] - 2026-11-25

### Added
- Single-binary native CLI client `fatext` supporting all 6 `fatext.com` command groups:
  - Identity, profile & keys (`init`, `whoami`, `profile set`, `key rotate|revoke|fetch`)
  - Public channels, pins & threads (`pub pins|list|post|thread|reply`)
  - Friends & blocks (`friend`, `block`)
  - End-to-end encrypted DMs & private rooms (`dm send`, `room create|invite|send`)
  - Real-time SSE listener & 10-day encrypted mailbox (`listen`, `mail pull|rm`)
  - P2P direct encrypted UDP tunnels (`p2p listen`, `p2p connect` with `--stdio` and bidirectional `--forward`/`--expose`)
- Single-source SemVer version management (`VERSION`, `scripts/sync_version.py`, `fatext version [--check]`, `User-Agent: fatext-cli/<ver>`).
- Verified installer (`scripts/install.sh`) and multi-platform GitHub Actions CI & Release pipelines.
