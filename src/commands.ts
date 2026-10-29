import type {BuildInfo, Command, CommandContext, CredentialAccess, Logger, MountControl, Setting, SettingsTab, Subcommand, UiElement} from '../../../src/api.js';
import {accountOf, runGit, unuseAccount, useAccount, type Git} from './git.js';
import {createGrants, type Grants} from './grants.js';
import {DEFAULT_KIND, fieldStatus, isManagedKind, missingOf, SSH_KEY, type Kind, type Kinds} from './kinds.js';
import {inventory, reset, rotate} from './migrate.js';
import {checkName, type Account, type Store} from './store.js';

export type Deps = {
	dataDir: string;
	store: Store;
	kinds: Kinds;
	log: Logger;
	grants?: Grants;
	build?: BuildInfo;
	onSecretsChanged?: () => void;
	git?: Git;
	sshAs?: string;
};

const NAME = {name: 'name', description: 'The account'};
const MODULE = {name: 'module', description: 'An installed module'};
const DIR = {name: 'dir', description: 'A directory in the repository (default: the current one)'};
const FIELD_OPTION = {name: '--<field>', value: '<value>', description: 'A public field of the kind (one word)', repeatable: true};

const subcommands: Subcommand[] = [
	{name: 'new', usage: 'account new', description: 'Add an account step by step (also in settings → Accounts)', agent: 'confirm'},
	{
		name: 'list',
		aliases: ['ls'],
		usage: 'account list [kind]',
		description: 'Show the accounts',
		args: [{name: 'kind', description: 'Only accounts of this kind'}],
		agent: 'safe',
	},
	{name: 'show', usage: 'account show <name>', description: 'Public fields, which secrets are set, the SSH key fingerprint', args: [NAME], agent: 'safe'},
	{name: 'fields', usage: 'account fields <name>', description: 'Every field of the account kind: filled in or empty (no values)', args: [NAME], agent: 'safe'},
	{
		name: 'add',
		usage: 'account add <name> [--kind <kind>] [--<field> <value>]… [--no-ssh]',
		description: 'Create an account',
		args: [{name: 'name', description: 'Name of the new account'}],
		options: [
			{name: '--kind', value: '<kind>', description: `Kind of the account (default ${DEFAULT_KIND}); see account kinds`},
			FIELD_OPTION,
			{name: '--no-ssh', description: `No SSH key for a ${DEFAULT_KIND} account`},
		],
		notes: [`A ${DEFAULT_KIND} account gets a new SSH key unless --no-ssh`, 'Secrets are entered afterwards: account secret <name> <field>'],
		agent: 'confirm',
	},
	{
		name: 'set',
		usage: 'account set <name> [--<field> <value>]…',
		description: 'Change public fields of an account',
		args: [NAME],
		options: [FIELD_OPTION],
		notes: ['At least one field'],
		agent: 'confirm',
	},
	{
		name: 'secret',
		usage: 'account secret <name> <field> [--clear]',
		description: 'Enter a secret in a hidden input (never on the command line), or clear it',
		args: [NAME, {name: 'field', description: 'A secret field of the kind'}],
		options: [{name: '--clear', description: 'Remove the secret instead'}],
		agent: 'confirm',
	},
	{name: 'kinds', usage: 'account kinds', description: 'Show the kinds of accounts and their fields', agent: 'safe'},
	{
		name: 'kind',
		usage: 'account kind <subcommand>',
		description: 'Define your own kinds of accounts, or remove them',
		args: [{name: 'subcommand', description: 'add or remove'}],
		agent: 'confirm',
		subcommands: [
			{
				name: 'add',
				usage: 'account kind add <kind> <field>… [--one-of <a,b>]…',
				description: 'Define a kind with its fields',
				args: [
					{name: 'kind', description: 'Name of the new kind'},
					{name: 'field', description: 'A field: <name>, <name>:secret, with a trailing ! when required'},
				],
				options: [{name: '--one-of', value: '<a,b>', description: 'At least one of these fields must be set', repeatable: true}],
				notes: [
					':secret marks a secret field: entered in a hidden input, never shown',
					'A trailing ! marks a required field',
					'Example: account kind add stripe accountId! token:secret!',
				],
				agent: 'confirm',
			},
			{
				name: 'remove',
				aliases: ['rm'],
				usage: 'account kind remove <kind>',
				description: 'Remove a kind that no account uses',
				args: [{name: 'kind', description: 'The kind'}],
				agent: 'confirm',
			},
		],
	},
	{name: 'key', usage: 'account key <name>', description: 'Print the public SSH key of an account', args: [NAME], agent: 'safe'},
	{
		name: 'use',
		usage: 'account use <name> [dir]',
		description: 'Make git in a repository push, pull and commit as the account',
		args: [NAME, DIR],
		agent: 'confirm',
	},
	{name: 'unuse', usage: 'account unuse [dir]', description: 'Stop using an account in a repository', args: [DIR], agent: 'confirm'},
	{name: 'which', usage: 'account which [dir]', description: 'Show which account a repository uses', args: [DIR], agent: 'safe'},
	{name: 'disable', usage: 'account disable <name>', description: 'Stop the account working anywhere', args: [NAME], agent: 'confirm'},
	{name: 'enable', usage: 'account enable <name>', description: 'Let a disabled account work again', args: [NAME], agent: 'confirm'},
	{name: 'remove', aliases: ['rm'], usage: 'account remove <name>', description: 'Delete an account with its secrets and key', args: [NAME], agent: 'confirm'},
	{
		name: 'grants',
		usage: 'account grants',
		description: 'Which modules may use which kinds of credentials',
		notes: ['One line per installed module that declares credentials in its yena.json'],
		agent: 'safe',
	},
	{
		name: 'grant',
		usage: 'account grant <module> [kind]…',
		description: 'Let a module use the credentials it declares',
		args: [MODULE, {name: 'kind', description: 'A declared kind (default: every declared kind)'}],
		notes: ['The module gets the access its yena.json declares: read, or write (also create and remove)', 'Only you can run it, never an assistant'],
		agent: 'deny',
	},
	{
		name: 'revoke',
		usage: 'account revoke <module> [kind]…',
		description: 'Take credential access away from a module',
		args: [MODULE, {name: 'kind', description: 'A granted kind (default: all of them)'}],
		notes: ['Only you can run it, never an assistant'],
		agent: 'deny',
	},
	{
		name: 'vault',
		usage: 'account vault <subcommand>',
		description: 'The key that encrypts the stored secrets',
		args: [{name: 'subcommand', description: 'status, rotate or reset'}],
		agent: 'confirm',
		subcommands: [
			{name: 'status', usage: 'account vault status', description: 'Whether the key is there and how many entries it encrypts', agent: 'safe'},
			{
				name: 'rotate',
				usage: 'account vault rotate',
				description: 'Encrypt everything under a new key and drop the old one',
				notes: ['Resumes when run again after an interruption; the old key goes only when all succeeded'],
				agent: 'deny',
			},
			{
				name: 'reset',
				usage: 'account vault reset',
				description: 'Drop the secrets that cannot be decrypted; make a new key if needed',
				notes: ['Asks you to type reset; what can be decrypted stays', 'For a lost key: restore the vault folder from a backup first if you can'],
				agent: 'deny',
			},
		],
	},
];

const USAGE = 'account <subcommand>';

const clip = (s: string) => s.slice(0, 40);

const MADE_BY: Record<string, string> = {'claude-login': 'claude auth login'};

function parseFlags(words: string[], allowKind: boolean): {kind?: string; fields: Record<string, string>} {
	const fields: Record<string, string> = {};
	let kind: string | undefined;
	for (let i = 0; i < words.length; i += 2) {
		const flag = words[i]!;
		const value = words[i + 1];
		if (!flag.startsWith('--') || flag.length < 3) throw new Error(`Expected --<field> <value>, got "${clip(flag)}"`);
		if (value === undefined || value.startsWith('--')) throw new Error(`${clip(flag)} needs a value`);
		const key = flag.slice(2);
		if (key === 'kind') {
			if (!allowKind) throw new Error('The kind of an account cannot change');
			kind = value;
		} else if (key in fields) throw new Error(`${clip(flag)} is given twice`);
		else fields[key] = value;
	}
	return {...(kind !== undefined && {kind}), fields};
}

const fieldText = (a: Account) =>
	Object.entries(a.fields)
		.map(([k, v]) => `${k}=${v}`)
		.join(' ');

const line = (a: Account, missing: string[]) =>
	`  ${a.name} · ${a.kind}${a.disabled ? ' [disabled]' : ''}${missing.length ? ` [incomplete: ${missing.join(', ')}]` : ''}${Object.keys(a.fields).length ? ` · ${fieldText(a)}` : ''}`;

const kindLine = (k: Kind) => {
	const fields = k.fields.map(f => `${f.key}${f.required ? '!' : ''}${f.secret ? ' (secret)' : ''}`);
	const groups = k.oneOf.map(g => `one of ${g.join(' | ')}`);
	return `  ${k.name}${k.builtin ? ' (built in)' : ''}: ${[...fields, ...(k.ssh ? ['SSH key'] : []), ...groups].join(', ')}`;
};

type OpenWizard = (control: MountControl) => UiElement;

function accountsTab(store: Store, openWizard: OpenWizard): SettingsTab {
	const options = [
		{value: 'active', label: 'Active'},
		{value: 'disabled', label: 'Disabled', description: 'Its secrets and key stop working until enabled'},
		{value: 'delete', label: 'Delete', description: 'Removes the account with its secrets and key for good'},
	];
	const settingFor = (a: Account): Setting => ({
		key: `account.${a.name}`,
		label: `${a.name} · ${a.kind}`,
		...(Object.keys(a.fields).length > 0 && {description: fieldText(a)}),
		options,
		get: async () => ((await store.list()).find(x => x.name === a.name)?.disabled ? 'disabled' : 'active'),
		set: async value => {
			if (value === 'delete') await store.remove(a.name);
			else await store.setDisabled(a.name, value === 'disabled');
		},
	});
	return {
		title: 'Accounts',
		actions: [{key: 'account.add', label: 'Add account…', description: 'step by step: kind, name, fields, secrets', open: openWizard}],
		settings: store.listSync().map(settingFor),
	};
}

async function enterSecret(ctx: CommandContext, label: string, save: (value: string) => Promise<void>): Promise<boolean> {
	if (!ctx.mount || ctx.headless) throw new Error('"account secret" needs the app (./yena): the secret is typed into a hidden input there');
	const {secretView} = await import('./ui/secret-view.js');
	let result: {saved: boolean; error?: Error} = {saved: false};
	await ctx.mount(control => secretView(control, label, save, (saved, error) => (result = {saved, ...(error && {error})})), {target: 'panel'});
	if (result.error) throw result.error;
	return result.saved;
}

export function createCommand(deps: Deps): Command {
	const {store, kinds, log} = deps;
	const git = deps.git ?? runGit;

	const sshAccount = async (name: string | undefined) => {
		const account = await store.get(checkName(name));
		if (!account.publicKey) throw new Error(`Account "${account.name}" (${account.kind}) has no SSH key`);
		return account;
	};

	const missingFor = async (a: Account): Promise<string[]> => {
		const kind = await kinds.get(a.kind).catch(() => undefined);
		return kind ? missingOf(kind, a, await store.secretNames(a.name)) : [];
	};

	let wizard: typeof import('./ui/add-wizard.js') | undefined;
	const loadWizard = async () => (wizard ??= await import('./ui/add-wizard.js'));
	const wizardDeps = {store, kinds, ...(deps.onSecretsChanged && {onSecretsChanged: deps.onSecretsChanged})};
	const openWizard: OpenWizard = control => {
		if (!wizard) throw new Error('The form is still loading; press Enter again');
		return wizard.addWizard(control, wizardDeps);
	};

	const grants = deps.grants ?? createGrants(deps.dataDir, log);
	const declarers = () => (deps.build?.modules ?? []).filter(m => Object.keys(m.credentials ?? {}).length > 0);

	async function showGrants(ctx: CommandContext): Promise<void> {
		if (!deps.build) return ctx.print('This yena does not tell which modules declare credentials (an older host)');
		const modules = declarers();
		if (modules.length === 0) return ctx.print('No installed module declares credentials');
		const table = await grants.all();
		for (const m of modules) {
			for (const [kind, declared] of Object.entries(m.credentials ?? {})) {
				const granted = table[m.name]?.[kind];
				const effective: CredentialAccess | undefined = granted === undefined ? undefined : declared === 'read' ? 'read' : granted;
				ctx.print(`  ${m.name} · ${kind} · declared ${declared} · ${effective ? `granted ${effective}` : 'not granted'}`);
			}
		}
	}

	async function changeGrants(sub: 'grant' | 'revoke', args: string[], ctx: CommandContext): Promise<void> {
		if (ctx.signal) throw new Error(`"account ${sub}" is only for you to run in the console, never for an assistant`);
		const [module, ...kindArgs] = args;
		if (!module) throw new Error(`Specify the module. Usage: account ${sub} <module> [kind]…`);
		if (sub === 'revoke') {
			const removed = await grants.revoke(module, kindArgs.length > 0 ? kindArgs : undefined);
			log.info('credential grants revoked', {kinds: removed.length});
			return ctx.print(removed.length > 0 ? `✓ ${clip(module)}: ${removed.join(', ')} revoked` : `${clip(module)} had no such grants`);
		}
		if (!deps.build) throw new Error('This yena does not tell which modules declare credentials (an older host); grants need a newer one');
		const installed = deps.build.modules.find(m => m.name === module);
		if (!installed) throw new Error(`Module "${clip(module)}" is not installed. See: mod list`);
		const declared = installed.credentials ?? {};
		if (Object.keys(declared).length === 0) throw new Error(`${installed.name} declares no credentials in its yena.json`);
		const kinds = kindArgs.length > 0 ? kindArgs : Object.keys(declared);
		const allow: Record<string, CredentialAccess> = {};
		for (const kind of kinds) {
			const access = Object.prototype.hasOwnProperty.call(declared, kind) ? declared[kind] : undefined;
			if (!access) throw new Error(`${installed.name} did not declare credentials of kind "${clip(kind)}" in yena.json (declared: ${Object.keys(declared).join(', ')})`);
			allow[kind] = access;
		}
		await grants.allow(installed.name, allow);
		log.info('credential grants given', {kinds: Object.keys(allow).length});
		ctx.print(`✓ ${installed.name} may now use: ${Object.entries(allow).map(([k, a]) => `${k} (${a})`).join(', ')}`);
	}

	async function vaultCommand(args: string[], ctx: CommandContext): Promise<void> {
		const [action] = args;
		switch (action) {
			case 'status': {
				const st = await store.vault.status();
				const counts = await inventory(store);
				ctx.print(`Vault key: ${st.state === 'ok' ? `present (key ${st.current}${st.kids.length > 1 ? ', a rotation is unfinished' : ''})` : st.state === 'none' ? 'not made yet' : 'missing or unusable'}`);
				ctx.print(`  Encrypted: ${counts.encrypted}`);
				if (counts.plaintext > 0) ctx.print(`  ${counts.plaintext} secret${counts.plaintext === 1 ? ' is' : 's are'} not encrypted yet (encrypted at the next start of yena)`);
				if (counts.undecryptable > 0) ctx.print(`  Cannot be decrypted: ${counts.undecryptable} (restore the vault folder from a backup, or: account vault reset)`);
				return;
			}
			case 'rotate': {
				if (ctx.signal) throw new Error('"account vault rotate" is only for you to run in the console, never for an assistant');
				const r = await rotate(store, log);
				deps.onSecretsChanged?.();
				return ctx.print(`✓ Vault key ${r.kid}: ${r.secrets} secret file${r.secrets === 1 ? '' : 's'} and ${r.keys} SSH key${r.keys === 1 ? '' : 's'} re-encrypted, the old key dropped`);
			}
			case 'reset': {
				if (ctx.signal) throw new Error('"account vault reset" is only for you to run in the console, never for an assistant');
				if (!ctx.mount || ctx.headless) throw new Error('"account vault reset" needs the app (./yena): you confirm it by typing there');
				const counts = await inventory(store);
				const {confirmView} = await import('./ui/confirm-view.js');
				let confirmed = false;
				const question = `Drop ${counts.undecryptable} entr${counts.undecryptable === 1 ? 'y' : 'ies'} that cannot be decrypted and make a new key if needed? Type reset`;
				await ctx.mount(control => confirmView(control, question, 'reset', ok => (confirmed = ok)), {target: 'panel'});
				if (!confirmed) return ctx.print('Cancelled, nothing changed');
				const r = await reset(store, log);
				deps.onSecretsChanged?.();
				return ctx.print(`✓ Vault reset: ${r.secrets} secret${r.secrets === 1 ? '' : 's'} and ${r.keys} SSH key${r.keys === 1 ? '' : 's'} dropped${r.newKey ? ', a new key made' : ''}`);
			}
			case undefined:
				if (ctx.showHelp) return ctx.showHelp(['vault']);
				throw new Error('Usage: account vault status | account vault rotate | account vault reset');
			default:
				throw new Error(`Unknown subcommand "vault ${clip(action)}". See: account vault help`);
		}
	}

	return {
		name: 'account',
		description: 'Accounts for services; secrets are never shown',
		usage: USAGE,
		args: [{name: 'subcommand', description: 'What to do; see the subcommands'}],
		subcommands,
		agent: 'confirm',
		get settings() {
			void loadWizard().catch(error => log.warn('account form failed to load', {err: error}));
			return accountsTab(store, openWizard);
		},
		run: async ([sub, ...args], ctx) => {
			switch (sub) {
				case 'new': {
					if (!ctx.mount || ctx.headless) throw new Error('"account new" needs the app (./yena); from a terminal use: account add <name> [--<field> <value>]…');
					await loadWizard();
					await ctx.mount(control => openWizard(control), {target: 'panel'});
					return;
				}
				case 'list':
				case 'ls': {
					const accounts = (await store.list()).filter(a => args[0] === undefined || a.kind === args[0]);
					if (accounts.length === 0) return ctx.print(args[0] ? `No ${clip(args[0])} accounts` : 'No accounts. Add one: account new (step by step) or settings → Accounts');
					for (const a of accounts) ctx.print(line(a, await missingFor(a)));
					return;
				}
				case 'show': {
					const a = await store.get(checkName(args[0]));
					const kind = await kinds.get(a.kind).catch(() => undefined);
					const states = await store.secretStates(a.name);
					const set = Object.keys(states);
					ctx.print(`${a.name} · ${a.kind}${a.disabled ? ' [disabled]' : ''}`);
					for (const f of kind?.fields ?? []) {
						const mark = f.required ? '!' : '';
						if (f.secret) ctx.print(`  ${f.key}${mark}: ${states[f.key] === undefined ? 'not set' : states[f.key] === 'broken' ? 'set (cannot be decrypted)' : 'set (hidden)'}`);
						else ctx.print(`  ${f.key}${mark}: ${a.fields[f.key] ?? '-'}`);
					}
					if (kind?.ssh) ctx.print(`  SSH key: ${a.fingerprint ?? 'none'}`);
					const missing = kind ? missingOf(kind, a, set) : [];
					if (missing.length > 0) ctx.print(`  Missing: ${missing.join(', ')}`);
					return;
				}
				case 'fields': {
					const a = await store.get(checkName(args[0]));
					const kind = await kinds.get(a.kind);
					const states = await store.secretStates(a.name);
					const set = Object.keys(states);
					ctx.print(`${a.name} · ${a.kind}${a.disabled ? ' [disabled]' : ''}`);
					for (const f of fieldStatus(kind, a, set)) {
						const broken = states[f.key] === 'broken' ? ', cannot be decrypted' : '';
						const label = f.key === SSH_KEY ? 'SSH key' : `${f.key}${f.required ? '!' : ''}${f.secret ? ` (secret${broken})` : ''}`;
						ctx.print(`  ${f.set ? '✓' : '✗'} ${label}`);
					}
					const missing = missingOf(kind, a, set);
					ctx.print(missing.length > 0 ? `  Missing: ${missing.join(', ')}` : '  Complete');
					return;
				}
				case 'add': {
					const [name, ...words] = args;
					const noSsh = words.includes('--no-ssh');
					const flags = parseFlags(
						words.filter(w => w !== '--no-ssh'),
						true,
					);
					const kind = await kinds.get(flags.kind ?? DEFAULT_KIND);
					if (isManagedKind(kind)) throw new Error(`Accounts of kind ${kind.name} are made by: ${MADE_BY[kind.name] ?? 'the module that uses them'}`);
					if (noSsh && !kind.ssh) throw new Error(`--no-ssh: kind "${kind.name}" has no SSH key anyway`);
					const account = await store.add({name: checkName(name), kind, fields: flags.fields, ...(noSsh && {ssh: false})});
					log.info('account added', {kind: kind.builtin ? kind.name : 'custom', fields: Object.keys(flags.fields).length, ssh: account.publicKey !== undefined});
					ctx.print(`✓ Account "${account.name}" (${kind.name}) created`);
					if (account.publicKey) {
						const login = account.fields.login;
						ctx.print(`  Add this public key to the GitHub account${login ? ` ${login}` : ''}: https://github.com/settings/ssh/new`);
						ctx.print(`  ${account.publicKey}`);
						ctx.print(`  Fingerprint: ${account.fingerprint}`);
						ctx.print(`  Then in a repository: account use ${account.name} <repo dir>`);
					}
					const secrets = kind.fields.filter(f => f.secret).map(f => f.key);
					if (secrets.length > 0) ctx.print(`  Secrets (${secrets.join(', ')}): account secret ${account.name} <field>`);
					const missing = missingOf(kind, account, []);
					if (missing.length > 0) ctx.print(`  Still needed: ${missing.join(', ')}`);
					return;
				}
				case 'set': {
					const [name, ...rest] = args;
					const account = await store.get(checkName(name));
					const {fields} = parseFlags(rest, false);
					if (Object.keys(fields).length === 0) throw new Error('Nothing to set. Usage: account set <name> --<field> <value>…');
					await store.setFields(account.name, await kinds.get(account.kind), fields);
					ctx.print(`✓ ${account.name}: ${Object.keys(fields).join(', ')} updated`);
					return;
				}
				case 'secret': {
					const [name, field, flag] = args;
					const account = await store.get(checkName(name));
					const kind = await kinds.get(account.kind);
					const def = kind.fields.find(f => f.key === field);
					if (!field) throw new Error(`Specify the field: ${kind.fields.filter(f => f.secret).map(f => f.key).join(', ') || 'this kind has no secret fields'}`);
					if (!def?.secret) throw new Error(`"${clip(field)}" is not a secret field of ${kind.name} (secret fields: ${kind.fields.filter(f => f.secret).map(f => f.key).join(', ') || 'none'})`);
					if (def.managed) throw new Error(`"${field}" is set by the module that uses it (${MADE_BY[kind.name] ?? 'not by hand'}); it cannot be typed`);
					if (flag !== undefined && flag !== '--clear') throw new Error(`Unknown option "${clip(flag)}"`);
					if (flag === '--clear') {
						await store.setSecret(account.name, field, undefined);
						deps.onSecretsChanged?.();
						return ctx.print(`✓ ${account.name}: ${field} cleared`);
					}
					const saved = await enterSecret(ctx, `${field} for ${account.name} (${kind.name})`, value => store.setSecret(account.name, field, value));
					if (!saved) return ctx.print('Cancelled, nothing saved');
					deps.onSecretsChanged?.();
					log.info('secret saved');
					ctx.print(`✓ ${account.name}: ${field} saved`);
					return;
				}
				case 'kinds':
					for (const k of await kinds.list()) ctx.print(kindLine(k));
					return;
				case 'kind': {
					const [action, name, ...fields] = args;
					if (action === 'add') {
						const kind = await kinds.add(name ?? '', fields);
						return ctx.print(`✓ Kind added:${kindLine(kind).slice(1)}`);
					}
					if (action === 'remove' || action === 'rm') {
						if (!name) throw new Error('Specify the kind');
						if (await store.usesKind(name)) throw new Error(`Accounts of kind "${clip(name)}" exist; remove them first`);
						await kinds.remove(name);
						return ctx.print(`✓ Kind "${name}" removed`);
					}
					if (action === undefined && ctx.showHelp) return ctx.showHelp(['kind']);
					throw new Error('Usage: account kind add <kind> <field>[:secret]… | account kind remove <kind>');
				}
				case 'key':
					return ctx.print((await sshAccount(args[0])).publicKey!);
				case 'use': {
					const account = await sshAccount(args[0]);
					if (account.disabled) throw new Error(`Account "${account.name}" is disabled. Enable it first: account enable ${account.name}`);
					const root = await useAccount(git, args[1] ?? '.', account, deps.dataDir, deps.sshAs);
					log.info('account used in a repository');
					const email = account.fields.email;
					ctx.print(`✓ ${root} now uses "${account.name}" for ssh remotes and commits as ${account.fields.login ?? account.name}${email ? ` <${email}>` : ''}`);
					if (!email) ctx.print(`  No email set, so commits keep the repository's or the global user.email. Set one: account set ${account.name} --email <email>`);
					return;
				}
				case 'unuse':
					return ctx.print(`✓ ${await unuseAccount(git, args[0] ?? '.')} no longer uses a yena account`);
				case 'which': {
					const {root, name} = await accountOf(git, args[0] ?? '.');
					return ctx.print(name ? `${root}: ${name}` : `${root}: no yena account`);
				}
				case 'disable':
				case 'enable': {
					const name = checkName(args[0]);
					await store.setDisabled(name, sub === 'disable');
					return ctx.print(`✓ Account "${name}" ${sub === 'disable' ? 'disabled' : 'enabled'}`);
				}
				case 'remove':
				case 'rm': {
					const name = checkName(args[0]);
					await store.remove(name);
					deps.onSecretsChanged?.();
					log.info('account removed');
					return ctx.print(`✓ Account "${name}" deleted with its secrets and key`);
				}
				case 'grants':
					return showGrants(ctx);
				case 'grant':
				case 'revoke':
					return changeGrants(sub, args, ctx);
				case 'vault':
					return vaultCommand(args, ctx);
				case 'help':
				case undefined:
					return ctx.showHelp ? ctx.showHelp() : ctx.print(USAGE);
				default:
					throw new Error(`Unknown subcommand "${clip(String(sub))}". See: account help`);
			}
		},
	};
}
