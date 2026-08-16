# agent-password

`agent-password` is a local, cross-platform password manager for agent workflows. It runs on **macOS**, **Windows**, and **Linux**.

Secrets are encrypted at rest in a local SQLite vault. A per-machine vault key is stored in the operating system's credential store, and an OS-level authentication prompt (Touch ID, Windows Hello, or your account password) gates every approval. Agents and humans use the same CLI.

## Architecture

```
┌─────────────┐   JSON over IPC    ┌──────────────────┐
│  CLI client  │ ─────────────────▶ │  background daemon │
│ (agent/human)│ ◀───────────────── │  (auto-started)    │
└─────────────┘                    └────────┬─────────┘
                                            │
                             ┌──────────────┼──────────────┐
                             ▼              ▼              ▼
                       OS auth gate   OS credential   SQLite vault
                     (Hello/TouchID/    store (vault    (XChaCha20-
                       password)          key)          Poly1305)
```

- The first CLI invocation spawns a detached daemon that holds session state in memory.
- CLI ↔ daemon transport: Unix-domain socket (macOS/Linux, mode 0600) or Named Pipe (Windows).
- Secret fields are encrypted with XChaCha20-Poly1305; metadata stays readable so agents can discover what exists without seeing plaintext.
- The unlocked vault key lives only in daemon memory, wrapped in `Zeroizing` so it is wiped when the session closes.

## Platform support

| | macOS | Windows | Linux |
|---|---|---|---|
| **Approval gate** | Touch ID (LocalAuthentication) | Windows Hello (UserConsentVerifier) | Account password via PAM (root auto-approves) |
| **Vault key storage** | login Keychain | Credential Manager | key file in app dir, mode 0600 |
| **Daemon IPC** | Unix socket, 0600 | Named pipe `\\.\pipe\.agent-password` | Unix socket, 0600 |
| **Daemon detach** | `setsid()` | `DETACHED_PROCESS` | `setsid()` |

Android is **not supported**: a plain CLI process cannot reach the Android Keystore or BiometricPrompt APIs (both require an app context via JNI), and PAM does not exist there. Running under Termux with file-based keys would work mechanically but offers no OS-backed approval gate, so it is intentionally out of scope.

## Model

- There is one shared local session per OS user.
- `secrets list` exposes metadata only.
- Agents request the secret IDs they need.
- The user reviews a numbered request and approves `all` or a subset such as `1,4,3-6`.
- Approved secrets remain readable until `session clear` or `session close`.

## Install

Build the binary (requires Rust 1.71+; on Linux also `libpam0g-dev` or your distro's PAM headers):

```bash
cargo build
```

Run the debug binary directly:

```bash
./target/debug/agent-password --help
```

Or install it into your Cargo bin directory:

```bash
cargo install --path .
```

On Windows, build from a normal PowerShell or CMD prompt with the MSVC toolchain (`rustup default stable-msvc`); no extra system dependencies are needed.

## Storage

| | macOS / Linux | Windows |
|---|---|---|
| App state directory | `~/.agent-password` | `%USERPROFILE%\.agent-password` |
| Vault database | `~/.agent-password/vault.db` | `%USERPROFILE%\.agent-password\vault.db` |
| Daemon transport | `~/.agent-password/daemon.sock` | `\\.\pipe\.agent-password` |
| Vault key | Keychain (macOS) / `<app dir>/<service>.key` (Linux) | Credential Manager |

## Important limitations

- **macOS**: Touch ID is the unlock gate before loading the vault key into daemon memory. The key is stored as a normal login-keychain item rather than a biometric-ACL item, because unsigned CLI binaries are not a reliable target for Keychain biometry ACLs.
- **Windows**: the vault key is a generic Credential Manager credential readable by any process running as your user; Windows Hello gates the daemon's approval flow, not the credential itself. The named pipe relies on the default same-user ACL.
- **Linux**: the key file is not hardware-backed; it is protected only by file permissions (0600). The approval gate verifies your account password via PAM, and running as root auto-approves.

## Typical workflow

Initialize the vault:

```bash
agent-password vault init
```

Add a login secret:

```bash
printf '%s\n' 'super-secret-password' \
  | agent-password login add github \
      --username tartavull \
      --url https://github.com \
      --password-stdin \
      --tag work
```

Create the shared session:

```bash
agent-password session create
```

Let the agent discover metadata:

```bash
agent-password secrets list
```

Let the agent request what it needs:

```bash
agent-password secrets request github slack notion \
  --requester codex \
  --reason "repo setup"
```

Review the numbered request:

```bash
agent-password requests show 1
```

Approve everything:

```bash
agent-password requests approve 1 all
```

Approve only part of the request:

```bash
agent-password requests approve 1 1,3-4
```

Read an approved secret:

```bash
agent-password secrets get github --field username --field password --json
```

Write approved fields into an env file:

```bash
agent-password secrets get github \
  --field username \
  --field password \
  --env-file /tmp/github.env
```

End access:

```bash
agent-password session close
```

## Command reference

### `agent-password vault`

- `agent-password vault init`
  Creates the local vault database and stores a generated vault key in the OS credential store.

### `agent-password session`

- `agent-password session create`
  Creates the shared session.
- `agent-password session create --replace`
  Replaces any existing shared session.
- `agent-password session status`
  Shows whether the session exists, whether it is unlocked, approved secret IDs, and pending request IDs.
- `agent-password session clear`
  Clears approved secret access but keeps the session object.
- `agent-password session close`
  Drops the session, pending requests, approvals, and unlocked key material.

### `agent-password login`

- `agent-password login add <id> --username <value> --password-stdin [--url <url>] [--title <title>] [--tag <tag>]...`
  Convenience command for common website or app credentials. The password must come from stdin.

Example:

```bash
printf '%s\n' 'hunter2' \
  | agent-password login add github \
      --username alice \
      --url https://github.com \
      --password-stdin
```

### `agent-password secret`

- `agent-password secret put <id> --type <type> --field <key=value> [--field <key=value>]... [--title <title>] [--service <service>] [--username <username>] [--tag <tag>]...`
  Creates or updates a generic secret.
- `agent-password secret show <id>`
  Shows metadata only.
- `agent-password secret show <id> --json`
  Shows metadata as JSON.
- `agent-password secret delete <id>`
  Deletes a secret and removes any related approvals or pending request references.

Supported initial secret types:

- `login`
- `api_key`
- `note`

### `agent-password secrets`

- `agent-password secrets list`
  Lists metadata for all secrets while a shared session exists.
- `agent-password secrets list --json`
  Lists metadata as JSON.
- `agent-password secrets request <id>... --requester <label> [--reason <text>]`
  Creates a pending request for one or more secret IDs.
- `agent-password secrets get <id> [--field <field>]...`
  Reads approved fields. If no `--field` arguments are passed, all secret fields are returned.
- `agent-password secrets get <id> --json`
  Returns the selected fields as JSON.
- `agent-password secrets get <id> --env-file <path>`
  Writes the selected fields as shell-compatible environment assignments.

### `agent-password requests`

- `agent-password requests list`
  Lists pending requests.
- `agent-password requests list --json`
  Lists pending requests as JSON.
- `agent-password requests show <request_id>`
  Shows a numbered approval view for a request.
- `agent-password requests show <request_id> --json`
  Shows the request and numbered metadata as JSON.
- `agent-password requests approve <request_id> all`
  Prompts for OS authentication and approves every requested secret.
- `agent-password requests approve <request_id> <selection>`
  Prompts for OS authentication and approves only the numbered subset.
- `agent-password requests deny <request_id>`
  Denies and removes the full request.
- `agent-password requests deny <request_id> <selection>`
  Denies only the selected items and leaves the rest pending.

Selection syntax:

- `all`
- Comma-separated indexes: `1,4,6`
- Ranges: `3-6`
- Mixed: `1,4,3-6`

### `agent-password grants`

- `agent-password grants list`
  Lists metadata for secrets currently approved in the shared session.
- `agent-password grants list --json`
  Lists approved metadata as JSON.

## Agent usage notes

- Use `agent-password secrets list` for discovery.
- Request the smallest set of secret IDs needed.
- Read only the specific fields needed with `secrets get --field ...`.
- Prefer `--env-file` when another command needs environment variables.
- Do not ask the user to paste secrets if the request/approval workflow can satisfy the need.

A ready-to-use Claude Code skill describing this workflow lives at `.claude/skills/agent-password/SKILL.md`.

## Development overrides

These environment variables are useful for isolated testing:

- `PASSWORD_APP_DIR`
  Override the app state directory.
- `PASSWORD_KEYCHAIN_SERVICE`
  Override the credential-store service name (also names the Linux key file).
- `PASSWORD_KEYCHAIN_ACCOUNT`
  Override the credential-store account name.
- `PASSWORD_PIPE_NAME` (Windows only)
  Override the full named-pipe path, e.g. `\\.\pipe\agent-password-test`.

Example:

```bash
env PASSWORD_APP_DIR=/tmp/agent-password-demo \
    PASSWORD_KEYCHAIN_SERVICE=tartavull.agent-password.demo \
    ./target/debug/agent-password session status
```

## CI

GitHub Actions runs `cargo test` on Linux, macOS, and Windows plus a `rustfmt`/`clippy` lint job on every push and pull request (`.github/workflows/ci.yml`).
