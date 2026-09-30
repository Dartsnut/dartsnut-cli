# Dartsnut Raspberry Pi installer

Standalone Rust host initializer for a Dartsnut Raspberry Pi. This repository has no source or build dependency on the Raspberry Pi runtime repository. After authentication, the installer clones that repository onto the Pi and runs its existing `setup.sh` there.

## Local build

Requires Rust 1.88 or newer (`ratatui` 0.30 requires 1.88 in the locked dependency graph):

```sh
cargo test --locked
cargo build --locked --release
./target/release/dartsnut-rpi-installer --ip <Pi IPv4 address or hostname>
```

Without `--ip`, the TUI scans non-loopback IPv4 `/24` networks and `dartsnut.local` / `raspberrypi.local`. It shows port-22 results before asking for credentials. `--user` only prefills the custom username prompt; there is no password command-line argument. Unknown SSH host keys require explicit fingerprint approval; changed known keys are rejected. The account must support SSH password authentication and sudo. An alternate sudo password can be entered once if the SSH password is rejected by sudo.

The installer uses the target's fixed `/home/rpi/dartsnut_rpi` path. Recovery preserves the existing `device.json` in a root-owned `/home/rpi/.dartsnut-device.json.backup.*` file and verifies its bytes before setup. Keep this backup if setup fails. A successful reboot request is never repeated by verification retries.

## Release publication prerequisite

The `installer-v0.1.0` release in `Dartsnut/dartsnut-prepare` must contain the six platform binaries and `SHA256SUMS` from `.github/workflows/release.yml`. Both root bootstraps intentionally refuse to run until their **actual release-asset SHA-256 hashes** are pinned. At preparation time that GitHub repository/release did not exist and the available GitHub identity cannot create a repository under the separate `Dartsnut` user. Do not publish the pipe-to-run commands or replace the empty pins with guessed hashes. Once the owner publishes the release, verify each binary with `--version`, copy its SHA-256 from `SHA256SUMS` into the matching `install.sh` or `install.ps1` case, and publish those updated bootstraps on `main`.
