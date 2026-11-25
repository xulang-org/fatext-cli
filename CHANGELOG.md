# Changelog

All notable changes to `fatext-cli` will be documented in this file.

## [1.0.0] - 2026-11-25

### Added
- Single-binary Xu client `fatext` supporting all 6 `fatext.com` command groups:
  - Identity, profile & keys (`init`, `whoami`, `profile set`, `key rotate|revoke|fetch`)
  - Public channels, pins & threads (`pub pins|list|post|thread|reply`)
  - Friends & blocks (`friend`, `block`)
  - End-to-end encrypted DMs & private rooms (`dm send`, `room create|invite|send`)
  - Real-time SSE listener & 10-day encrypted mailbox (`listen`, `mail pull|rm`)
  - P2P direct encrypted UDP tunnels (`p2p listen`, `p2p connect` with `--stdio` and bidirectional `--forward`/`--expose`)
- Single-source SemVer version management (`VERSION`, `scripts/sync_version.py`, `fatext version [--check]`, `User-Agent: fatext-cli/<ver>`).
- Verified installer (`scripts/install.sh`) and multi-platform GitHub Actions CI & Release pipelines.
