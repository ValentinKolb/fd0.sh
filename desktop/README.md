# fd0 Desktop

fd0 Desktop is the Electron and SolidJS client for the existing fd0 agent. It presents passwords, general secrets, SSH access, kubeconfigs, and Talos contexts without moving private-key ownership into the renderer.

## Architecture

```text
Solid renderer
    | typed, allowlisted IPC
sandboxed preload
    | ipcMain handlers and native dialogs
Electron main process
    | newline-delimited JSON over private stdio
fd0-desktop-bridge
    | existing internal/cli and domain packages
fd0-agent
```

The agent remains the long-lived key holder. The renderer has no Node.js access, network access, filesystem access, or direct agent socket access. Secret clipboard writes, attachment export, recovery files, and external links cross native main-process handlers.

## Develop

Prerequisites: Go from `go.mod`, Bun 1.3.14 or newer, and macOS PC/SC support. Linux also needs the PC/SC development package.

```sh
cd desktop
bun install --frozen-lockfile
bun run dev
```

For a persistent local command, link the repository-owned launcher once:

```sh
mkdir -p ~/.local/bin
ln -s "$PWD/bin/fd0-desktop-dev" ~/.local/bin/fd0-desktop-dev
fd0-desktop-dev
```

The development app uses a separate fd0 instance:

- fd0 home: `~/Library/Application Support/fd0 Desktop Dev` on macOS
- Electron data: `~/Library/Application Support/fd0 Desktop Dev UI` on macOS
- SSH socket: `/tmp/fd0-desktop-dev-ssh-$UID.sock`
- passphrase: `fd0-desktop-dev`
- automatic sync: disabled in the agent process

Both development directories carry exact isolation markers. `bun run dev:reset` refuses to remove either directory when its marker is missing or changed. It never resolves or edits `~/.fd0`.

Set `FD0_DESKTOP_FLAVOR=standard` to build without YubiKey support. Desktop builds include YubiKey support by default.

## Verify

```sh
bun run typecheck
bun run test:e2e
bun run package
```

The Electron test launches real temporary fd0 agents and vaults. It covers renderer sandboxing, inventory views, password editing, duplicate protection, general-secret and SSH-host editing, file export, recovery export and restore, lock/unlock, native shortcuts, and responsive layout.

`bun run package` creates an unpacked app under `desktop/dist`. On macOS, local packages receive an ad-hoc signature after Electron fuses are applied so they can be launched without a Developer ID. It does not launch the app. A packaged app uses system mode and defaults to `~/.fd0`; use a temporary `FD0_HOME` and `FD0_SSH_SOCK` for packaged smoke tests.

## Security invariants

- Development and tests require `FD0_DESKTOP_MODE=isolated`, a non-production `FD0_HOME`, an exact marker, a dedicated `FD0_SSH_SOCK`, and `FD0_AGENT_SYNC_DISABLED=1`.
- Packaged builds use `FD0_DESKTOP_MODE=system` and bundled `fd0`, `fd0-agent`, and bridge binaries.
- IPC channels and bridge methods are explicit allowlists with strict decoding and 1 MiB frame limits.
- Renderer navigation, new windows, permissions, and network connections are denied.
- Copied secrets clear after 30 seconds when the clipboard still contains the copied value.
- Electron production fuses disable RunAsNode, Node options, and inspector arguments and require the embedded ASAR.
- macOS releases require Developer ID signing, hardened runtime, and notarization. The release workflow fails when signing credentials are absent.

## Release

Push `desktop-vX.Y.Z`. `.github/workflows/release-desktop.yml` verifies the repository, builds YubiKey-enabled macOS and Linux artifacts, signs and notarizes macOS bundles, signs the checksum manifest with Cosign, and publishes one GitHub release.

Required GitHub secrets:

- `MACOS_CERTIFICATE`: base64 PKCS#12 Developer ID Application certificate
- `MACOS_CERTIFICATE_PASSWORD`
- `APPLE_API_KEY_P8`: base64 App Store Connect API key
- `APPLE_API_KEY_ID`
- `APPLE_API_ISSUER`

The updater filters GitHub releases to `desktop-v*`. macOS uses architecture-specific update metadata; Linux uses AppImage metadata. Before installing an update, Desktop stops the running agent so the bundled app, CLI, and agent cannot drift across versions.

`scripts/install-desktop.sh` verifies SHA-256 for every install and verifies the Cosign manifest when Cosign is available. On macOS it also verifies the app signature and Gatekeeper assessment before replacing the current app. The installer creates desktop-managed `fd0` and `fd0-agent` commands in `~/.local/bin` or `/usr/local/bin`; Linux commands relay into the installed AppImage, while macOS commands resolve into the stable app bundle path. `--uninstall` removes only the app and marked wrappers and preserves `~/.fd0`.
