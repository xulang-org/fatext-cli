# Changelog

All notable changes to `fatext-cli` will be documented in this file.

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
