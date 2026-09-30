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

## Release

`Dartsnut/dartsnut-cli` publishes `installer-v0.1.2` through `.github/workflows/release.yml`. The release contains six platform binaries and `SHA256SUMS`; each root bootstrap pins the corresponding published SHA-256 value and refuses to run an unverified download. Version 0.1.2 bounds optional mDNS discovery and supports interactive input when `curl | sh` reopens `/dev/tty`. For future releases, update the Cargo version and tag, publish and verify all six assets, pin their hashes in both bootstraps, and update the expected version in `.github/workflows/bootstrap-smoke.yml` before directing users to the new release.

```sh
curl -fsSL https://raw.githubusercontent.com/Dartsnut/dartsnut-cli/main/install.sh | sh
```

```powershell
irm https://raw.githubusercontent.com/Dartsnut/dartsnut-cli/main/install.ps1 | iex
```
