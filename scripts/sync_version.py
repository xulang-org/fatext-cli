#!/usr/bin/env python3
"""
Synchronize fatext-cli version metadata from VERSION into src/xu.xun and src/version.xu.
Supports --check [--tag vX.Y.Z] for CI/Release gates.
"""

import argparse
import os
import platform
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERSION_FILE = os.path.join(ROOT, "VERSION")
XUN_FILE = os.path.join(ROOT, "src", "xu.xun")
VERSION_XU_FILE = os.path.join(ROOT, "src", "version.xu")

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")


def read_version() -> str:
    with open(VERSION_FILE, "r", encoding="utf-8") as f:
        v = f.read().strip()
    if not SEMVER_RE.match(v):
        raise SystemExit(f"Invalid VERSION {v!r}; expected SemVer X.Y.Z")
    return v


def git_short_commit() -> str:
    env_sha = os.environ.get("GITHUB_SHA", "").strip()
    if env_sha:
        return env_sha[:7]
    try:
        out = subprocess.check_output(
            ["git", "-C", ROOT, "rev-parse", "--short", "HEAD"],
            stderr=subprocess.DEVNULL,
        )
        return out.decode("utf-8").strip() or "dev"
    except Exception:
        return "dev"


def detect_target() -> str:
    override = os.environ.get("FATEXT_BUILD_TARGET", "").strip()
    if override:
        return override
    sys_name = platform.system().lower()
    mach = platform.machine().lower()
    os_part = "macos" if sys_name == "darwin" else ("windows" if sys_name.startswith("win") else sys_name)
    arch_map = {
        "x86_64": "x64",
        "amd64": "x64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    arch_part = arch_map.get(mach, mach or "unknown")
    return f"{os_part}-{arch_part}"


def expected_xun(ver: str) -> str:
    return f"module: fatext/cli\nversion: !ver {ver}\nxu: !ver 0.14.3\n"


def expected_version_xu(ver: str, commit: str, target: str) -> str:
    return (
        "@main\n\n"
        f"pub const CLI_VERSION = \"{ver}\"\n"
        f"pub const BUILD_COMMIT = \"{commit}\"\n"
        f"pub const BUILD_TARGET = \"{target}\"\n"
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="Verify files match VERSION without modifying them")
    ap.add_argument("--tag", default="", help="Optional git tag (e.g. v1.0.0) to assert against VERSION")
    ap.add_argument("--stamp", action="store_true", help="Stamp git commit and host target into src/version.xu (default: keep dev in local builds)")
    args = ap.parse_args()

    ver = read_version()
    if args.tag:
        want = f"v{ver}"
        if args.tag != want:
            raise SystemExit(f"Tag mismatch: tag={args.tag!r} != expected {want!r}")

    want_xun = expected_xun(ver)

    if args.check:
        with open(XUN_FILE, "r", encoding="utf-8") as f:
            got_xun = f.read()
        if got_xun != want_xun:
            raise SystemExit(f"src/xu.xun out of sync with VERSION={ver}. Run python3 scripts/sync_version.py")
        with open(VERSION_XU_FILE, "r", encoding="utf-8") as f:
            got_vxu = f.read()
        m = re.search(r'pub const CLI_VERSION = "([^"]+)"', got_vxu)
        if not m or m.group(1) != ver:
            raise SystemExit(f"src/version.xu CLI_VERSION out of sync with VERSION={ver}")
        print(f"version-check ok: {ver}")
        return

    should_stamp = args.stamp or bool(
        os.environ.get("CI")
        or os.environ.get("GITHUB_ACTIONS")
        or os.environ.get("FATEXT_BUILD_TARGET", "").strip()
    )
    if should_stamp:
        commit = git_short_commit()
        target = detect_target()
    else:
        commit = "dev"
        target = "dev"
    want_vxu = expected_version_xu(ver, commit, target)

    with open(XUN_FILE, "w", encoding="utf-8") as f:
        f.write(want_xun)
    with open(VERSION_XU_FILE, "w", encoding="utf-8") as f:
        f.write(want_vxu)
    print(f"synced version={ver} commit={commit} target={target}")


if __name__ == "__main__":
    main()
