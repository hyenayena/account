# account

Every credential of yena, used blindly: the user (or the assistant, with the user's confirmation) creates accounts, secrets are typed only into a hidden input or set by a module through the host's credential channel, everything secret is encrypted at rest, and other modules use an account by its name without its secrets reaching the chat, the console or the logs. Kind: internal (planned manifest field). A yena plugin; depends on `core` (for the hidden input).

## Kinds

Every account has a kind: the service it is for and the fields it holds. A field is public (shown, typed on the command line) or secret (never shown, typed only into the hidden input).

Fields are optional unless marked required (`!`). A kind may also have one-of groups: at least one member of each must be set (`ssh` in a group stands for the account's SSH key). An account that lacks something is still saved (secrets come after `add`), and is shown as `[incomplete: …]` until it is filled in.

Built in:
- `github`: `login`, `email`, `token` (secret), an SSH key generated with the account unless `--no-ssh`, and the group `ssh | token` (a key for git, a token for the API; either is enough). It is the default kind.
- `anthropic-key`: `key` (secret, required): an Anthropic API key, checked to look like `sk-ant-…` (not a subscription token).
- `anthropic-token`: `token` (secret, required): a subscription (setup) token, checked to look like `sk-ant-oat…`.
- `claude-login`: `email`, `method` (`claude.ai` or `console`), `login` (secret, required, **managed**): a Claude Code login as a JSON blob of at most 64 KiB (`credentials.claudeAiOauth` or `primaryApiKey`). A managed field is set only by the module that uses it, through the credential channel (`claude auth login`); `account secret` refuses it, `account add` and the form do not make `claude-login` accounts.

Checks and `managed` exist only on built-in kinds; the kinds file cannot set them or shadow a built-in kind. Your own kinds: `account kind add svc user! password:secret apiKey:secret --one-of password,apiKey` (`:secret` marks a secret, a trailing `!` a required field; names are a letter then letters, digits or `_`, at most 32 characters, `ssh` reserved; at most 20 fields and 10 groups; a group has two or more fields that are not required). Kinds live in `kinds.json`; one with accounts cannot be removed. Values of secret fields are 1 to 8192 characters (64 KiB for a login blob); messages about a refused value never repeat it.

## Commands

`help account` (and `account <subcommand> help`) gives the generated usage; in short:

| Command | Agent policy | What it does |
|---|---|---|
| `account new` | confirm | The step-by-step form (as in settings → Accounts) in the console panel; needs the app |
| `account list [kind]` (`ls`) | safe | `name · kind · public fields`, `[disabled]`, `[incomplete: …]` |
| `account show <name>` | safe | Public fields, `set (hidden)` / `not set` / `set (cannot be decrypted)` for each secret, the SSH key fingerprint or `none`, `Missing: …` |
| `account fields <name>` | safe | Every field of the kind as `✓`/`✗`, no values; then `Complete` or `Missing: …` |
| `account add <name> [--kind <kind>] [--<field> <value>]… [--no-ssh]` | confirm | Creates an account (a `github` one gets an ed25519 key unless `--no-ssh`; the public key is printed with a link). Secret fields and `claude-login` are refused |
| `account set <name> --<field> <value>…` | confirm | Changes public fields |
| `account secret <name> <field> [--clear]` | confirm | Opens the hidden input in the console panel (value checked by its kind), or clears the secret. Needs the app; refuses a managed field |
| `account kinds`, `account kind add|remove …` | safe / confirm | The kinds; define or remove your own |
| `account key <name>` | safe | The public SSH key |
| `account use <name> [dir]`, `unuse [dir]`, `which [dir]` | confirm / confirm / safe | Make git in a repository push, pull and commit as the account (`core.sshCommand` through `bin/ssh-as`, `user.name`, `user.email`, `yena.account`), undo it, or show it |
| `account disable|enable <name>` | confirm | A disabled account gives no secrets to modules and fails in every repository that uses it |
| `account remove <name>` (`rm`) | confirm | Deletes the account with its secrets and key |
| `account grants` | safe | `module · kind · declared … · granted …|not granted` for every installed module that declares credentials |
| `account grant <module> [kind]…` | deny | Gives the module the access its `yena.json` declares, for the given kinds (none: all declared); refuses modules that are not installed and kinds they did not declare |
| `account revoke <module> [kind]…` | deny | Takes the grants away (none: all of them) |
| `account vault status` | safe | Whether the key is there, its id, how many entries are encrypted, still plaintext, or cannot be decrypted |
| `account vault rotate` | deny | A new key; everything re-encrypted and verified; the old key dropped only when all succeeded (run again to resume) |
| `account vault reset` | deny | After you type `reset`: drops the secrets and SSH keys that cannot be decrypted and makes a new key when none is usable. Needs the app |

`grant`, `revoke`, `vault rotate` and `vault reset` are also refused for any assistant run (`ctx.signal`), and the scheduler refuses them through their `deny` policy. There is no export command.

Account names: `a-z`, `0-9`, `-`, `_`, at most 32 characters. Values are single words (the console splits on whitespace). When the assistant runs `account secret`, the hidden input opens in the console panel for the user to type; the assistant gets only the `saved` or `Cancelled` line.

## Settings

An `Accounts` tab, read when the settings screen opens:
- `▸ Add account…` opens the step-by-step form: pick the kind (`claude-login` is not offered), type the name, then each public field, for `github` choose whether to generate an SSH key, then each secret in core's hidden input (empty Enter skips one; Esc skips the rest and keeps the account; a value its kind refuses shows the reason and the input asks again). The last screen shows what was created, the public key with the GitHub link (`c` copies it), and what is still needed.
- One row per account (`name · kind`, public fields) with `Active`, `Disabled` and `Delete`.

## For other modules

Secret values go only through the host's credential channel, never through an import:
- Declare the kinds you use in your `yena.json`: `"credentials": {"anthropic-key": "write", "claude-login": "read"}` (`write` includes read, create and remove).
- Use `host.credentials` (`grants()`, `list(kind?)`, `read(account, field)`, `write(account, field, value | undefined)`, `create({name, kind, fields?})`, `remove(account)`). Nothing works until the user runs `account grant <module>`; a refusal throws with `code: 'CREDENTIAL_ACCESS'` and the hint `account grant <module>`. Register a redactor for every value you read and never print, log or hand it to an assistant.

The public entry (`src/public.ts`, through your adapter `src/deps/account.ts`, with `account` in `dependencies`) has no values any more:
- `accountsFor(ownDataDir)`: `kinds()`, `list(kind?)`, `get(name)` → `{name, kind, fields, secrets (names of the set ones), disabled, ssh, missing}`.
- `deniedPathsFor(ownDataDir)`: everything in the account data dir an assistant must not reach: the accounts file, the kinds file, `secrets`, `keys`, `disabled`, `vault` and the grants file (not `ssh_config`, which ssh reads in the chat's sandboxed Bash). `secretDirsFor` is a deprecated alias of it.
- `accountDataDirFor(ownDataDir)`: this module's data dir; only account knows the layout.

## Grants

The user decides which module may use which kinds; account keeps that decision, applies it and logs every use. The host only binds identity: each call to the provider carries the calling module's name and its `yena.json` declaration.
- Effective access to a kind = the lower of what the module declares and what was granted. An undeclared kind is refused (`<module> did not declare credentials of kind "<kind>" in yena.json`) even when the grants file names it; no access, or read-only access for a change, is refused with `CREDENTIAL_ACCESS`. `list` returns only kinds the caller may read; for `read`, `write` and `remove` the kind comes from the stored account. A caller that may not use any kind at all is refused before the store is read.
- The grants live in `grants.json` (0600, written atomically, never through a symlink, at most 64 KiB, re-read when it changes). A file that cannot be read or parsed counts as no grants (one warning). At load the grants of modules that are no longer installed are dropped.
- Audit record per call: `credential access` `{module, op, kind?, account?, outcome: ok|denied|missing|error, errClass?}`; never values or lengths.
- Honest scope: in one process this is a guard and an audit point, not a hard boundary; the boundary against the model is the chat's policy and sandbox.

## Private modules

At load the plugin registers a resolver with the host (`host.registerGitSsh`): `mod install --account <name> <module>…` fetches over ssh with `GIT_SSH_COMMAND` set to `bin/ssh-as` (`git.ts` `gitSshResolver`). The account must exist, be enabled and have an SSH key with read access to the repository; it signs through the account's agent, which yena runs.

## How secrets stay blind

- Secrets are typed into core's `SecretInput` (the value lives in a ref and is never rendered) or written by a granted module, checked by their kind, and stored encrypted. No command takes a secret as an argument, and no command prints one.
- **Encryption at rest** (`src/vault.ts`, the only code that touches the key): every secret value and SSH private key is encrypted with AES-256-GCM under a 32-byte key in `vault/key`, with a fresh 12-byte IV per write, in a versioned envelope `{v: 1, kid, iv, ct, tag}`. The associated data binds an envelope to its place (`account-secret\0<account>\0<field>`, `account-ssh\0<account>`), so a blob moved to another account or field does not decrypt. Any problem (tampering, another key, an unknown key id, a bad version) fails closed with `A stored secret of account "<name>" cannot be decrypted (tampered or a different vault key)`; there is no plaintext fallback. A missing or unusable key while encrypted data exists is never replaced silently: `The account vault key is missing or does not match; stored secrets cannot be read. Restore the vault folder from a backup, or run: account vault reset (drops the unreadable secrets)`. The key file is made exclusively (`link`, never overwritten), read only when it is a regular file (no symlinks), at most 4 KiB; its base64 is masked in the log once loaded.
- Honest scope: the key next to the data protects copies of the secrets (backups, a copied folder, accidental output, a single deny gap on `secrets/` or `keys/`), not code running as the same user that can read both. Against the model the boundary stays the deny rules, which now have two separate things to reach. The one plaintext exception is Claude Code's working copy of a login in the claude module's `config/` (the CLI reads it; denied to the model).
- SSH keys are generated in node (`generateKeyPairSync('ed25519')`, serialized in memory to OpenSSH format by `src/openssh.ts`) and stored only encrypted; the public key and its SHA256 fingerprint are computed in code. Each enabled account with a key gets its own `ssh-agent` (`src/agent.ts`), into which the decrypted key is loaded with `ssh-add -` over stdin: no plaintext key file ever exists, not in `/tmp` either. `bin/ssh-as` signs only through that agent; inside Claude Code's Bash sandbox git does not run `ssh-as` (the sandbox sets its own `GIT_SSH_COMMAND`), so the plugin also writes `ssh_config` (a `Match exec` on the repository's `yena.account` per agent, setting `IdentityAgent`), included by the image's `/etc/ssh/ssh_config`. The agents get only `PATH` from yena's environment.
- **Migration** (`src/migrate.ts`, at plugin load before the agents start, under `vault/migrate.lock`, stale after 2 minutes): a plaintext secrets file of 0.5.0 is encrypted field by field into a temp file, read back, decrypted and compared byte for byte, then renamed over the old file; a plaintext private key is encrypted to `<name>.enc`, read back and compared, then unlinked. Idempotent and resumable (an `.enc` left by a crash is verified against the plaintext before the plaintext goes). Until an entry is migrated it is read as plaintext; a warning at start and `account vault status` count what is left. Logs `vault migrated {secrets, keys}` / `vault migration failed {errClass, step}`, no names or values.
- A log redactor masks private key blocks, the vault key, every stored secret value of 6 or more characters and every string of 16 or more characters inside a stored JSON secret (the tokens of a login blob; not e-mail addresses and not text with whitespace, so display and organization names stay visible in tool output), refreshed when a secret changes; undecryptable secrets are skipped with a warning.
- Policies: `deniedPathsFor` gives the claude module the paths its chat denies.

## Environment

None.

## Data

Under `<YENA_DATA>/account` (dir 0700; files 0600, written atomically through an exclusive temp file):
- `accounts.json`: `{v: 2, accounts: [{name, kind, fields: {public…}, publicKey?, fingerprint?, createdAt}]}` (version 1 of 0.1.0, GitHub only, is read as kind `github`).
- `kinds.json`: `{v: 1, kinds: [{name, fields: [{key, secret, required}], oneOf?}]}` (built-in kinds are not stored).
- `secrets/<name>.json` (dir 0700): `{v: 2, fields: {field: envelope}}` (0.5.0's plaintext `{field: value}` is still read until migrated). A `claude-login` secret is a JSON blob of up to 64 KiB.
- `keys/` (0700): `<name>.enc` (encrypted private key), `<name>.pub` (public key, 0644), `<name>.disabled` (marker `ssh-as` checks).
- `vault/` (0700): `key` (0600: `{v: 1, current, keys: [{kid, key}]}`; two keys only during a rotation), `migrate.lock` while migrating, `key.unusable` after a reset moved an unusable key aside.
- `grants.json`: `{v: 1, grants: {module: {kind: 'read'|'write'}}}`.
- `disabled/<name>`: marker of a disabled account.
- `ssh_config` (0644): rewritten after every agent sync; included by the image's ssh config.

Outside it, on tmpfs: `/tmp/yena-account-<uid>-<12 hex of sha256(data dir)>/` (0700) with `<name>.sock` and `<name>.pid` of each agent; `bin/ssh-as` builds the same path.

## Events

None.

## Dependencies

`core` (its kit's `SecretInput` and `TextField`). Needs `ssh`, `ssh-agent`, `ssh-add`, `sha256sum` and `git` on `PATH` (in the yena image); `ssh-keygen` is no longer used.

## Limits and known risks

- **Losing the key loses the secrets.** Back up the `vault` folder together with `secrets/` and `keys/`; without it, restore it from a backup or run `account vault reset` (drops what cannot be decrypted; SSH keys must then be made again and added on GitHub).
- The plaintext files removed by the migration are unlinked, not securely wiped: their blocks may stay on the disk.
- `git push` as an account (from yena, a shell or the chat) needs the account's agent, which yena starts at plugin load (headless console lines too): after the container started, start yena once. `mod install --account` runs inside yena and is unaffected.
- The assistant runs as root in the same container: the files are protected by the chat's policy and sandbox, not by the operating system; the key next to the data does not stop code that can read both.
- Anything that can reach an agent socket can sign as that account (never read the key): yena, and the chat's Bash, whose sandbox allows unix sockets for this. Disable an account to take its agent away.
- A module that receives a secret through the channel holds it in memory; grants guard and log the access in one process, they are not a hard boundary.
- `bin/ssh-as` is referenced by its absolute path in each repository's `.git/config`; only ssh remotes use the account. `StrictHostKeyChecking=accept-new` trusts a host key on first use.
- Two yena processes changing the same account at the same moment can lose one change (each write is atomic, read-modify-write of one secrets file is not locked).

## Layout

`src/`: `index.ts` (plugin, redactors, migration at load, provider registration, grant pruning), `commands.ts` (the `account` command, the settings tab), `kinds.ts` (built-in and own kinds), `validate.ts` (secret checks, JSON leaves for the redactor), `store.ts` (accounts, encrypted secrets and keys), `vault.ts` (key and envelopes), `openssh.ts` (key generation), `migrate.ts` (migration, rotation, reset, counts), `grants.ts` (the grants file), `provider.ts` (the credential provider: checks and audit), `git.ts`, `agent.ts` (the ssh-agents), `public.ts` (entry for other modules), `ui/` (form, hidden input, typed confirmation, kit adapter). `bin/ssh-as`. Tests: `tests/{store,kinds,validate,vault,migrate,openssh,provider,git,agent,commands,public}.test.ts`, `tests/ui/wizard.test.tsx` (`agent.test.ts` and `openssh.test.ts` also run the real `ssh-agent`). Tests that load the plugin use `createPlugin({agents: false})`.

## Development

`npm run typecheck`, `npm test` (inside the yena tree with core installed; `tsc` and `tsx` come from `/app/node_modules`).
