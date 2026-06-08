# Installing the fd0 client and this skill

Two separate installs: the **fd0 CLI** itself (binaries on the user's machine), and the **skill** (these files, so an agent can use the CLI correctly).

## The fd0 CLI

```bash
curl -fsSL https://fd0.sh/install | sh
```

Supported platforms: Linux and macOS on amd64 and arm64. Installs `fd0` + `fd0-agent` to `~/.local/bin` (or `/usr/local/bin` with `--system`). Cosign-verifies the release manifest when cosign is available.

Verify:
```bash
fd0 version
which fd0
```

If `fd0` is not on PATH, the install script prints a one-line fix for the user's shell rc — read it back to them, do not invent your own.

Windows: not yet built by the release pipeline. The binaries cross-compile but the agent's AF_UNIX socket is unvalidated. Track at https://github.com/ValentinKolb/fd0.sh/issues.

## This skill

This skill lives at `skills/fd0/` inside the `ValentinKolb/fd0.sh` repository. The expected install path on the user's machine is `~/.claude/skills/fd0/` (or whatever skill directory their agent runtime reads from).

### Recommended — `bunx skills`

```bash
bunx skills add ValentinKolb/fd0.sh
```

The installer clones the repo, finds the `skills/fd0/` directory, and copies it to the local skill directory. After install, the agent loads the SKILL.md on the next session start.

### Manual

```bash
# Clone the repo
git clone https://github.com/ValentinKolb/fd0.sh.git /tmp/fd0.sh

# Copy the skill
mkdir -p ~/.claude/skills
cp -r /tmp/fd0.sh/skills/fd0 ~/.claude/skills/

# Verify
ls ~/.claude/skills/fd0/SKILL.md
```

### Verification

After install, the agent should recognise prompts like "save my deploy key" or "share the prod password with bob" as fd0 territory. If it doesn't, the skill description didn't load — check the file path and the agent runtime's skill directory.

## Updating

Both the CLI and the skill are version-tracked separately under the project's scoped tag scheme (`client-vX.Y.Z` for the CLI; the skill ships alongside the repo and updates when the repo does).

```bash
# Update the CLI
curl -fsSL https://fd0.sh/install | sh

# Update the skill (re-run the install)
bunx skills add ValentinKolb/fd0.sh
```

The CLI installer is idempotent — running it when the latest is already installed is a no-op.
