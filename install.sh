#!/bin/sh
set -eu
umask 077

RELEASE_TAG=installer-v0.1.0
RELEASE_REPOSITORY=Dartsnut/dartsnut-cli
RELEASE_ROOT="https://github.com/$RELEASE_REPOSITORY/releases/download/$RELEASE_TAG"

die() {
    printf '%s\n' "dartsnut-rpi-installer: $*" >&2
    exit 1
}

command -v uname >/dev/null 2>&1 || die 'uname is required to select a release asset.'
os=$(uname -s) || die 'Could not determine the operating system with uname -s.'
arch=$(uname -m) || die 'Could not determine the CPU architecture with uname -m.'

case "$os/$arch" in
    Linux/x86_64)
        asset=dartsnut-rpi-installer-x86_64-unknown-linux-gnu
        ;;
    Linux/aarch64|Linux/arm64)
        asset=dartsnut-rpi-installer-aarch64-unknown-linux-gnu
        ;;
    Darwin/x86_64)
        asset=dartsnut-rpi-installer-x86_64-apple-darwin
        ;;
    Darwin/arm64|Darwin/aarch64)
        asset=dartsnut-rpi-installer-aarch64-apple-darwin
        ;;
    *)
        die "Unsupported OS/CPU '$os/$arch'. See https://github.com/$RELEASE_REPOSITORY/releases/tag/$RELEASE_TAG for supported assets."
        ;;
esac

command -v curl >/dev/null 2>&1 || die 'curl is required to download the verified release asset.'
if command -v shasum >/dev/null 2>&1; then
    hash_tool=shasum
elif command -v sha256sum >/dev/null 2>&1; then
    hash_tool=sha256sum
else
    die 'Neither shasum nor sha256sum is available; refusing to run an unverified binary.'
fi

case "$asset" in
    dartsnut-rpi-installer-x86_64-unknown-linux-gnu) expected_sha256=03374580febaea66b38801c4e25fe3cfb188d58671b69a64dbcaccd106fad90c ;;
    dartsnut-rpi-installer-aarch64-unknown-linux-gnu) expected_sha256=4bbadeddfb5d2f2c84f6f5b7b8ac04175ee34c02b1b447b1c64f2de869d056a3 ;;
    dartsnut-rpi-installer-x86_64-apple-darwin) expected_sha256=c8fdc8009ad71306f4c2831d1596da2de31f3d615a55a9e3f0a91153898a803f ;;
    dartsnut-rpi-installer-aarch64-apple-darwin) expected_sha256=21cd3f3a76dcc22b452a40bae1882342ccba4dc89149f66a4e1e54b907a0ddf7 ;;
esac
if [ -z "$expected_sha256" ]; then
    die "No verified SHA-256 pin is available for '$asset'; refusing to run an unverified binary."
fi
case "$expected_sha256" in
    *[!0123456789abcdefABCDEF]*|'')
        die "Invalid SHA-256 pin configured for '$asset'; refusing to execute it."
        ;;
esac
[ "${#expected_sha256}" -eq 64 ] || die "Invalid SHA-256 pin configured for '$asset'; refusing to execute it."

if ! ( : </dev/tty ) 2>/dev/null; then
    die 'A readable controlling /dev/tty is required to run the installer interactively.'
fi

tmpdir=
cleanup() {
    if [ -n "$tmpdir" ]; then
        rm -rf "$tmpdir"
    fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/dartsnut-rpi-installer.XXXXXX") || die 'Could not create a private temporary directory.'
binary="$tmpdir/$asset"
url="$RELEASE_ROOT/$asset"
curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' --tlsv1.2 "$url" --output "$binary" || die "Download failed for '$asset'."

if [ "$hash_tool" = shasum ]; then
    hash_line=$(shasum -a 256 "$binary") || die "Could not calculate SHA-256 for '$asset'."
else
    hash_line=$(sha256sum "$binary") || die "Could not calculate SHA-256 for '$asset'."
fi
actual_sha256=${hash_line%% *}
[ "$actual_sha256" = "$expected_sha256" ] || die "SHA-256 mismatch for '$asset'; refusing to execute the downloaded file."
chmod 700 "$binary" || die "Could not mark '$asset' executable."

# curl | sh consumes stdin; the verified program must read from the user's terminal.
"$binary" "$@" </dev/tty
