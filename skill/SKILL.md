---
name: secret-broker
description: Get, store or request passwords, API keys and tokens through the secret-broker CLI backed by the user's KeePass vault. Use whenever a task needs a credential, instead of reading .env files or searching the disk.
---

# secret-broker

The sanctioned way to obtain or save secrets. Values live in the user's KeePass vault; you see entry names only. Depending on the user's settings, a value is released after approval in a window, through a standing approval, or at once with a notification to the user.

## Workflow

1. Run from the project directory (approvals are per project): `secret-broker list` shows `Group/Title (fields)` without values. `[no-file]` marks entries that must never be written to files.
2. **Always** fetch the value inside the same command that uses it, never in a separate call, and never write it to a file:
   `curl -H "Authorization: Bearer $(secret-broker get "Group/Title" --reason "why")" https://...`
   Keep `--reason` short and specific: the user sees it in the window or notification.
3. Entry missing → let the user type it in a window (you never see the value):
   `secret-broker ask "Group/Title" [--username U] [--url U] [--attr k=v] --reason "why"`, then `get` it.
   Add `--print` only when the value is needed immediately; the window tells the user.
4. A secret you produced (new password, rotated key) → save it instead of writing it to a file:
   `printf %s "$VAL" | secret-broker set "Group/Title" --stdin [--username U] --reason "why"` or `--generate [LEN]`.
5. When creating an entry, add `--no-file` if the value must never land in a file (API keys, tokens, production passwords).

## Rules

- Exit code `1` means the user declined or cancelled: do not retry without asking. Read stderr first: after `User comment:` the user may say what to do instead, and that comes first.
- `2` missing entry/field, `3` vault locked or missing, `4` forbidden (a `no-file` value redirected to a file).
- Never print secret values in the conversation or logs.
- Never change the broker's mode, approvals, settings or state files; that is the user's decision. Do not run `secret-broker mode notify`.
- The master password is set and typed by the user only.
- `no-file` entries stay in variables/processes; `guard-hook` blocks writes that contain them.
