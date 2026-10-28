# account

Accounts for services, used blindly: the user (or the assistant, with the user's confirmation) creates them, secrets are typed only into a hidden input, and the assistant and other modules use an account by its name without its secrets ever reaching the chat, the console or the logs. Kind: internal (planned manifest field). A yena plugin; depends on `core` (for the hidden input).

## Kinds

Every account has a kind: the service it is for and the fields it holds. A field is public (shown, typed on the command line) or secret (never shown, typed only into the hidden input).

Fields are optional unless marked required (`!`). A kind may also have one-of groups: at least one member of each must be set (`ssh` in a group stands for the account's SSH key). An account that lacks something is still saved (secrets come after `add`), and is shown as `[incomplete: …]` until it is filled in.

- `github` is built in: `login`, `email`, `token` (secret), an SSH key generated with the account unless `--no-ssh`, and the group `ssh | token` (a key for git, a token for the API; either is enough). It is the default kind.
- Your own: `account kind add svc user! password:secret apiKey:secret --one-of password,apiKey` (`:secret` marks a secret, a trailing `!` a required field; names are a letter then letters, digits or `_`, at most 32 characters, `ssh` reserved; at most 20 fields and 10 groups; a group has two or more fields that are not required). Kinds live in `kinds.json`; one with accounts cannot be removed.

## Commands

| Command | Agent policy | What it does |
|---|---|---|
| `account new` | confirm | The step-by-step form (as in settings → Accounts) in the console panel; needs the app |
| `account list [kind]` (`ls`) | safe | `name · kind · public fields`, `[disabled]`, `[incomplete: …]` |
| `account show <name>` | safe | Public fields, `set (hidden)` / `not set` for each secret (`!` on required ones), the SSH key fingerprint or `none`, `Missing: …` |
| `account fields <name>` | safe | Every field of the account's kind, the SSH key included, as `✓` (filled in) or `✗` (empty), `!` on required ones, `(secret)` on secrets; no values at all; then `Complete` or `Missing: …` |
| `account add <name> [--kind <kind>] [--<field> <value>]… [--no-ssh]` | confirm | Creates an account (kind `github` by default, which also gets an ed25519 key unless `--no-ssh`: the public key is printed with a link to add it on GitHub) and says what is still needed. A secret field given here is refused |
| `account set <name> --<field> <value>…` | confirm | Changes public fields (merged; the kind cannot change) |
| `account secret <name> <field>` | confirm | Opens the hidden input in the console panel; what is typed is saved and only `✓ <name>: <field> saved` is printed. Needs the app (`./yena`), refused from the host terminal |
| `account secret <name> <field> --clear` | confirm | Removes the secret |
| `account kinds` | safe | The kinds, their fields (`!` required), SSH key, one-of groups |
| `account kind add <kind> <field>[:secret][!]… [--one-of <a,b>]…`, `kind remove <kind>` | confirm | Defines or removes a kind of your own |
| `account key <name>` | safe | The public SSH key |
| `account use <name> [repo dir]` | confirm | In that repository (default: the current directory): `core.sshCommand` through `bin/ssh-as`, `user.name` (login, else name), `user.email`, `yena.account`; then plain `git push` goes out as the account |
| `account unuse [repo dir]` | confirm | Unsets those four keys (a local `user.name`/`user.email` set before `use` is gone too) |
| `account which [repo dir]` | safe | The account a repository uses |
| `account disable <name>`, `enable <name>` | confirm | A disabled account gives no secrets to modules and fails in every repository that uses it |
| `account remove <name>` (`rm`) | confirm | Deletes the account with its secrets and key |
| `account help` | safe | The usage |

Account names: `a-z`, `0-9`, `-`, `_`, at most 32 characters. Values are single words (the console splits on whitespace).

When the assistant runs `account secret`, the hidden input opens in the console panel for the user to type; the assistant gets only the `saved` or `Cancelled` line.

## Settings

An `Accounts` tab, read when the settings screen opens:
- `▸ Add account…` opens the step-by-step form in place of the list: pick the kind, type the name, then each public field (`(optional)` ones are skipped with an empty Enter), for `github` choose whether to generate an SSH key, then each secret in core's hidden input (empty Enter skips one; Esc skips the rest and keeps the account). The last screen shows what was created, the public key with the GitHub link (`c` copies it), and what is still needed. Esc before the account is created cancels without saving anything. Closing the form returns to the list with the new account in it.
- One row per account (`name · kind`, public fields) with `Active`, `Disabled` and `Delete`.

The same form is `account new`. The commands remain for scripts and the assistant.

## For other modules

Add `"account": "account"` to `dependencies`, re-export what you use from `src/deps/account.ts`, and import `src/public.ts` there:

- `accountsFor(ownDataDir)`: `kinds()`, `list(kind?)` and `get(name)` give `{name, kind, fields, secrets: string[] (names of the set ones), disabled, ssh, missing: string[]}` (`missing`: required fields not set and `a|b` for an unmet group, so a module can tell the user what to add, e.g. `account secret <name> token`); `kinds()` gives `{name, fields: [{key, secret, required}], ssh, oneOf, builtin}`; `secret(name, field)` gives the value for in-process use, `undefined` when unset or the account is disabled. Never print, log or hand the value to an assistant; register it with `log.addRedactor` if it may end up in text.
- `secretDirsFor(ownDataDir)`: the directories that hold credentials, for a policy that guards an assistant.
- `accountDataDirFor(ownDataDir)`: this module's data dir; only account knows the layout.

## Private modules

At load the plugin registers a resolver with the host (`host.registerGitSsh`, hosts that have it): `mod install --account <name> <module>…` then fetches over ssh with `GIT_SSH_COMMAND` set to the same `bin/ssh-as` wrapper `account use` writes (`git.ts` `gitSshResolver`). The account must exist, be enabled and have an SSH key with read access to the repository; the host keeps the account name in `yena-modules.json` for restores and updates. The container has no host ssh-agent, so this is how private modules are installed (the official ones are public and need no account).

## How secrets stay blind

- Secrets are typed into core's `SecretInput` (the value lives in a ref and is never rendered) and written straight to `secrets/<name>.json`. No command takes a secret as an argument, and no command prints one.
- SSH private keys are written by `ssh-keygen` straight into `keys/` and never read by yena's code; git uses them through `bin/ssh-as` (`ssh -i <key> -o IdentitiesOnly=yes -o IdentityAgent=none -o StrictHostKeyChecking=accept-new`), so the user's own ssh-agent is never involved and `.git/config` holds only the wrapper and the account name.
- Each enabled account with a key gets its own `ssh-agent`, started by the plugin and brought in line after every add, disable, enable and remove (`src/agent.ts`; the agent of a disabled or removed account is killed). `bin/ssh-as` uses the key file where it can read it (yena itself, `mod install --account`) and the account's agent where it cannot (the claude chat's Bash sandbox, which hides `keys/`), so plain `git push` works from the chat while the key never leaves yena. The agents get only `PATH` from yena's environment.
- A log redactor replaces private key blocks with `[private key]` and every stored secret value of 6 or more characters with `[secret]` (refreshed when a secret changes). Log records carry no names, fields or values.
- The claude chat lets its Read, Glob, Grep and Edit tools reach only the project, the md hub and its config dir, so this data dir is out of their reach. Its Bash check only names `accounts.json`; see the risks.

## Environment

None.

## Data

Under `<YENA_DATA>/account` (dir 0700; files 0600, written atomically):
- `accounts.json`: `{v: 2, accounts: [{name, kind, fields: {public…}, publicKey?, fingerprint?, createdAt}]}` (version 1 of 0.1.0, GitHub only, is read as kind `github`).
- `kinds.json`: `{v: 1, kinds: [{name, fields: [{key, secret, required}], oneOf?: [[key…]…]}]}` (built-in kinds are not stored; a field without `required`, as written by 0.2.0, is optional).
- `secrets/<name>.json` (dir 0700): `{field: value}`.
- `keys/` (0700): `<name>` (private key), `<name>.pub`, `<name>.disabled` (marker `ssh-as` checks).
- `disabled/<name>`: marker of a disabled account.

Outside it, on tmpfs (unix sockets may not work on a folder mounted from the host): `/tmp/yena-account-<uid>-<12 hex of sha256(data dir)>/` (0700) with `<name>.sock` and `<name>.pid` of each agent; `bin/ssh-as` builds the same path.

## Events

None.

## Dependencies

`core` (its kit's `SecretInput`, loaded only by `account secret`). Needs `ssh`, `ssh-keygen`, `ssh-agent`, `ssh-add`, `sha256sum` and `git` on `PATH` (in the yena image).

## Limits and known risks

- The assistant runs as root in the same container: the files are protected by the chat's policy, not by the operating system. The chat's Bash check does not name `secrets/` and `keys/` yet, so a shell command that reads them is not stopped (the fix belongs in the claude module, through `secretDirsFor`). Full isolation needs the secrets outside the container (planned).
- Anything that can reach an agent socket can sign as that account (never read the key): in the container that is yena, and the chat's Bash, whose sandbox allows unix sockets for this. Disable an account to take its agent away.
- A module that receives a secret through `secret()` holds it in memory; what it does with it is up to that module.
- `bin/ssh-as` is referenced by its absolute path in each repository's `.git/config`: moving the module breaks `git push` there until `account use` runs again. Only ssh remotes use the account; `https://` remotes keep the user's own credentials. `StrictHostKeyChecking=accept-new` trusts a host key on first use.
- Two yena processes changing accounts at the same moment can lose one change (each write is atomic, read-modify-write is not).

## Layout

`src/`: `index.ts` (plugin, redactors), `commands.ts` (the `account` command, the settings tab), `kinds.ts` (built-in and own kinds), `store.ts` (accounts, secrets, keys), `git.ts` (`use`, `unuse`, `which`, the `mod install --account` resolver), `agent.ts` (the ssh-agents), `public.ts` (entry for other modules), `ui/secret-view.tsx` and `ui/kit.ts` (adapter to core's kit). `bin/ssh-as`. Tests: `tests/{store,kinds,git,agent,commands,public}.test.ts` (`agent.test.ts` also runs the real `ssh-agent`). Tests that load the plugin use `createPlugin({agents: false})`.

## Development

`npm run typecheck`, `npm test` (inside the yena tree with core installed; `tsc` and `tsx` come from `/app/node_modules`).
