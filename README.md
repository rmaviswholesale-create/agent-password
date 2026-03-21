# agent-password

`agent-password` is a local macOS password manager for agent workflows.

Secrets are encrypted at rest in a local SQLite vault. The vault key is stored in the macOS login keychain, and Touch ID is used to unlock that key into memory for the shared session. Agents and humans use the same CLI.

## Model

- There is one shared local session per macOS user.
- `secrets list` exposes metadata only.
- Agents request secret IDs they need.
- The user reviews a numbered request and approves `all` or a subset such as `1,4,3-6`.
- Approved secrets remain readable until `session clear` or `session close`.

## Install

Build the binary:

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

## Storage

- App state directory: `~/.agent-password`
- Vault database: `~/.agent-password/vault.db`
- Internal daemon socket: `~/.agent-password/daemon.sock`

Sensitive fields are encrypted with XChaCha20-Poly1305. Secret metadata stays readable so the agent can discover what exists without seeing plaintext.

## Important Limitation

This CLI uses Touch ID as the unlock gate before loading the vault key into daemon memory. The key itself is stored as a normal login-keychain item instead of a biometric ACL keychain item, because unsigned CLI binaries are not a reliable target for Keychain biometry ACLs on macOS.

## Typical Workflow

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

## Command Reference

### `agent-password vault`

- `agent-password vault init`
  Creates the local vault database and stores a generated vault key in the macOS login keychain.

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
  Prompts for Touch ID and approves every requested secret.
- `agent-password requests approve <request_id> <selection>`
  Prompts for Touch ID and approves only the numbered subset.
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

## Agent Usage Notes

- Use `agent-password secrets list` for discovery.
- Request the smallest set of secret IDs needed.
- Read only the specific fields needed with `secrets get --field ...`.
- Prefer `--env-file` when another command needs environment variables.
- Do not ask the user to paste secrets if the request/approval workflow can satisfy the need.

## Development Overrides

These environment variables are useful for isolated testing:

- `PASSWORD_APP_DIR`
  Override the app state directory.
- `PASSWORD_KEYCHAIN_SERVICE`
  Override the keychain service name.
- `PASSWORD_KEYCHAIN_ACCOUNT`
  Override the keychain account name.

Example:

```bash
env PASSWORD_APP_DIR=/tmp/agent-password-demo \
    PASSWORD_KEYCHAIN_SERVICE=tartavull.agent-password.demo \
    ./target/debug/agent-password session status
```
