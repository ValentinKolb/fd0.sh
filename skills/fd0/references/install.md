# Installing fd0 and this skill

The fd0 product and this agent skill are installed separately. Install either the CLI-only product or the Desktop bundle; install the skill so an agent can operate fd0 correctly.

## The fd0 CLI

```bash
brew install cosign
curl -fsSL https://fd0.sh/install | sh
```

Supported platforms: Linux and macOS on amd64 and arm64. Installs `fd0` + `fd0-agent` to `~/.local/bin` (or `/usr/local/bin` with `--system`). Cosign is required. On Linux, use the distribution package or the [official Cosign installation instructions](https://docs.sigstore.dev/cosign/system_config/installation/). The installer authenticates the manifest against the exact fd0 release workflow and tag before writing binaries.

Verify:
```bash
fd0 version
which fd0
```

`fd0 version` prints the release flavor:

```bash
fd0 0.11.0 standard
fd0 0.11.0 yubikey
```

The default flavor is `standard`. It is the pure-Go client and does not include YubiKey/PIV support.

Install the official YubiKey/PIV flavor when the user wants `fd0 auth add --yubikey` or `fd0 unlock --method=yubikey`:

```bash
curl -fsSL https://fd0.sh/install | sh -s -- --yubikey
fd0 doctor
```

Switch an existing install deliberately:

```bash
fd0 update --flavor=yubikey
fd0 agent restart
```

Normal `fd0 update` preserves the installed flavor. A `yubikey` install stays on the `yubikey` archive; a `standard` install stays standard.

`fd0 update --yes` never authorizes a rollback. An older release must be selected explicitly and also requires `--allow-downgrade`; `latest` resolution cannot downgrade.

If `fd0` is not on PATH, the install script prints a one-line fix for the user's shell rc — read it back to them, do not invent your own.

Windows: not yet built by the release pipeline. The binaries cross-compile but the agent's AF_UNIX socket is unvalidated. Track at https://github.com/k2b-dev/fd0.sh/issues.

## fd0 Desktop

```bash
curl -fsSL https://fd0.sh/install | sh -s -- --desktop
```

Desktop is one versioned bundle containing the app, YubiKey-capable CLI, and agent. Its installer bootstraps a SHA-256-pinned release verifier when needed, then creates marked `fd0` and `fd0-agent` wrappers in `~/.local/bin` or `/usr/local/bin`. Existing standalone commands are preserved and restored on uninstall. Desktop updates the app, CLI, and agent together from **Support**; Linux uses the verifier bundled in the app, so users do not install Cosign. A bundled `fd0 update` opens that same updater instead of modifying the signed app itself.

A directly installed DMG or launched AppImage provides the GUI and its bundled service without replacing shell commands. Use the script when Desktop should own the `fd0` and `fd0-agent` command paths too.

Uninstall the app and its marked wrappers without deleting `~/.fd0`:

```bash
curl -fsSL https://fd0.sh/install-desktop | sh -s -- --uninstall
```

## This skill

This skill lives at `skills/fd0/` inside the `k2b-dev/fd0.sh` repository. The expected install path on the user's machine is `~/.claude/skills/fd0/` (or whatever skill directory their agent runtime reads from).

### Recommended — `bunx skills`

```bash
bunx skills add k2b-dev/fd0.sh
```

The installer clones the repo, finds the `skills/fd0/` directory, and copies it to the local skill directory. After install, the agent loads the SKILL.md on the next session start.

### Manual

```bash
# Clone the repo
git clone https://github.com/k2b-dev/fd0.sh.git /tmp/fd0.sh

# Copy the skill
mkdir -p ~/.claude/skills
cp -r /tmp/fd0.sh/skills/fd0 ~/.claude/skills/

# Verify
ls ~/.claude/skills/fd0/SKILL.md
```

### Verification

After install, the agent should recognise prompts like "save my deploy key" or "share the prod password with bob" as fd0 territory. If it doesn't, the skill description didn't load — check the file path and the agent runtime's skill directory.

## Updating

The CLI-only release, Desktop release, and skill use separate update channels: `client-vX.Y.Z`, `desktop-vX.Y.Z`, and the repository version containing the skill.

```bash
# Update a CLI-only installation
fd0 update

# Update a Desktop installation (opens Desktop > Support)
fd0 update

# Update the skill (re-run the install)
bunx skills add k2b-dev/fd0.sh
```

Both product installers are idempotent. `fd0 update` detects the installation: standalone clients update their two binaries, while Desktop-managed clients hand off to the app updater so the app, CLI, and agent stay on one signed version.
