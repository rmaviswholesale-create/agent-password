---
name: agent-password
description: Use when you need to access or request local secrets through the agent-password CLI on this Mac, including metadata discovery, secret requests, approval review, session inspection, and approved secret reads.
---

# agent-password

Use the local `agent-password` CLI instead of asking the user to paste secrets.

## Workflow

1. Check session state with `agent-password session status`.
2. If no shared session exists, ask the user to run `agent-password session create`.
3. Discover metadata with `agent-password secrets list --json`.
4. Request only the secret IDs you need with `agent-password secrets request <ids> --requester <label> --reason <text>`.
5. Tell the user to review the numbered request with `agent-password requests show <request_id>`.
6. After approval, read only the fields you need with `agent-password secrets get <id> --field <field>...`.

## Rules

- Never ask for plaintext secrets directly if the CLI can request them.
- Keep requests narrow: smallest set of secret IDs, smallest set of fields.
- `agent-password secret show` returns metadata only. Use `agent-password secrets get` for approved plaintext.
- If `agent-password secrets get` says a secret is not approved, create or revisit a request instead of retrying blindly.
- Prefer `--env-file <path>` when another command expects environment variables.
- Treat JSON output and env files as sensitive. Remove temporary files when they are no longer needed.

## Useful Commands

Discovery:

```bash
agent-password secrets list --json
```

Create a request:

```bash
agent-password secrets request github slack --requester codex --reason "repo setup"
```

Inspect pending requests:

```bash
agent-password requests list
agent-password requests show 1
```

Read approved fields:

```bash
agent-password secrets get github --field username --field password --json
```

Write approved fields to an env file:

```bash
agent-password secrets get github --field token --env-file /tmp/github.env
```
