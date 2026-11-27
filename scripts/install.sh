#!/usr/bin/env bash
set -euo pipefail

# Optional installer for fatext-cli (`fatext`)
# Recommended: inspect this script before running, or verify manually per https://fatext.com/dl/#verify
# Usage: curl -fsSL https://fatext.com/dl/install.sh -o install.sh && less install.sh && bash install.sh

BASE_URL="${FATEXT_DL_BASE:-https://fatext.com/dl}"
KEY_URL="${FATEXT_OFFICIAL_KEY_URL:-https://fatext.com/k/ftx_fatextoffice.pem}"
OFFICIAL_KEY_PIN_FP="SHA256:NWAw8jK8DjgH48oD/JuX9O0E438pCC+rpEdGisgMBFk="
INSTALL_DIR="${FATEXT_INSTALL_DIR:-/usr/local/bin}"
VERSION="${FATEXT_VERSION:-latest}"

uname_s="$(uname -s | tr '[:upper:]' '[:lower:]')"
uname_m="$(uname -m)"

case "$uname_s" in
  linux) os="linux" ;;
  darwin) os="macos" ;;
  *) echo "Unsupported OS: $uname_s" >&2; exit 1 ;;
esac

case "$uname_m" in
  x86_64|amd64) arch="x64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) echo "Unsupported architecture: $uname_m" >&2; exit 1 ;;
esac

if [ "$VERSION" = "latest" ]; then
  asset="fatext-${os}-${arch}.tar.gz"
else
  asset="fatext-v${VERSION#v}-${os}-${arch}.tar.gz"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading ${BASE_URL}/${asset}..."
curl -fsSL "${BASE_URL}/${asset}" -o "${tmp}/${asset}"
curl -fsSL "${BASE_URL}/SHA256SUMS" -o "${tmp}/SHA256SUMS"

expected_sha="$(awk -v f="${asset}" '$2 == f || $2 == ("./" f) { print $1; exit }' "${tmp}/SHA256SUMS")"
if [ -z "$expected_sha" ]; then
  echo "Checksum entry for ${asset} not found in SHA256SUMS" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  actual_sha="$(sha256sum "${tmp}/${asset}" | awk '{print $1}')"
else
  actual_sha="$(shasum -a 256 "${tmp}/${asset}" | awk '{print $1}')"
fi

if [ "$expected_sha" != "$actual_sha" ]; then
  echo "SHA256 mismatch for ${asset}: expected=${expected_sha} actual=${actual_sha}" >&2
  exit 1
fi
echo "SHA256 verified: ${actual_sha}"

if [ "${FATEXT_INSECURE_SKIP_SIG:-0}" = "1" ]; then
  echo "Warning: skipping RSA-PSS signature verification because FATEXT_INSECURE_SKIP_SIG=1" >&2
else
  if ! command -v openssl >/dev/null 2>&1; then
    echo "Error: openssl is required to verify official RSA-PSS signature" >&2
    exit 1
  fi
  if ! curl -fsSL "${BASE_URL}/SHA256SUMS.sig" -o "${tmp}/SHA256SUMS.sig"; then
    echo "Error: failed to download ${BASE_URL}/SHA256SUMS.sig" >&2
    exit 1
  fi
  if ! curl -fsSL "${KEY_URL}" -o "${tmp}/official.pem"; then
    echo "Error: failed to download official key ${KEY_URL}" >&2
    exit 1
  fi
  expected_fp="${FATEXT_OFFICIAL_KEY_FP:-}"
  if [ -z "$expected_fp" ]; then
    case "$KEY_URL" in
      https://fatext.com/k/ftx_fatextoffice.pem|https://www.fatext.com/k/ftx_fatextoffice.pem)
        expected_fp="$OFFICIAL_KEY_PIN_FP"
        ;;
    esac
  fi
  if [ -n "$expected_fp" ]; then
    actual_fp="SHA256:$(openssl pkey -pubin -in "${tmp}/official.pem" -outform DER 2>/dev/null | openssl dgst -sha256 -binary | openssl base64 -A)"
    if [ "$actual_fp" != "$expected_fp" ]; then
      echo "Error: official key fingerprint mismatch (expected=${expected_fp} actual=${actual_fp})" >&2
      exit 1
    fi
    echo "Official key fingerprint verified: ${actual_fp}"
  fi
  openssl base64 -d -A -in "${tmp}/SHA256SUMS.sig" -out "${tmp}/sig.bin" 2>/dev/null || cp "${tmp}/SHA256SUMS.sig" "${tmp}/sig.bin"
  if openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sigopt rsa_mgf1_md:sha256 -verify "${tmp}/official.pem" -signature "${tmp}/sig.bin" "${tmp}/SHA256SUMS" >/dev/null 2>&1; then
    echo "Official RSA-PSS signature verified"
  else
    echo "SHA256SUMS.sig verification failed" >&2
    exit 1
  fi
fi

tar -xzf "${tmp}/${asset}" -C "${tmp}"
bin_src="$(find "${tmp}" -type f -name fatext | head -n 1)"
if [ -z "$bin_src" ]; then
  echo "fatext binary not found inside ${asset}" >&2
  exit 1
fi

if [ -d "$INSTALL_DIR" ] && [ -w "$INSTALL_DIR" ]; then
  install -m 0755 "$bin_src" "${INSTALL_DIR}/fatext"
elif [ ! -d "$INSTALL_DIR" ] && mkdir -p "$INSTALL_DIR" 2>/dev/null && [ -w "$INSTALL_DIR" ]; then
  install -m 0755 "$bin_src" "${INSTALL_DIR}/fatext"
else
  sudo mkdir -p "$INSTALL_DIR"
  sudo install -m 0755 "$bin_src" "${INSTALL_DIR}/fatext"
fi

echo "Installed fatext to ${INSTALL_DIR}/fatext"
"${INSTALL_DIR}/fatext" --version
