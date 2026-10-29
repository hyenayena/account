import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {readFile, rm} from 'node:fs/promises';
import path from 'node:path';
import {test} from 'node:test';
import type {BuildInfo, Command, CommandContext, CredentialProvider, Logger, MountControl, MountOptions, PluginHost, SettingsTab} from '../../../src/api.js';
import {createGrants} from '../src/grants.js';
import {createPlugin, redactPrivateKeys, redactValues} from '../src/index.js';
import {BUILTIN_KINDS} from '../src/kinds.js';
import {createStore} from '../src/store.js';
import {makeCtx, tmp} from './helpers.js';

const plugin = createPlugin({agents: false});

const load = async (dataDir: string, extra: Partial<PluginHost> = {}): Promise<Command> => {
	const commands = await plugin({dataDir, events: {emit() {}, on: () => () => {}}, log: undefined as never, ...extra});
	assert.equal(commands.length, 1);
	return commands[0]!;
};
const run = async (command: Command, line: string, extra: Partial<CommandContext> = {}) => {
	const {out, ctx} = makeCtx();
	await command.run(line.split(' ').filter(Boolean), {...ctx, ...extra});
	return out;
};

type InputProps = {label: string; onSubmit: (v: string) => void; onCancel: () => void};

// A mount that "types" into the hidden input by calling the element's handlers, as the UI would.
function typing(answer: string | null) {
	const seen: {label?: string; target?: string} = {};
	const mount = (build: (c: MountControl) => object, options?: MountOptions) =>
		new Promise<void>(resolve => {
			const element = build({close: resolve}) as {props: InputProps};
			seen.label = element.props.label;
			if (options?.target) seen.target = options.target;
			if (answer === null) element.props.onCancel();
			else element.props.onSubmit(answer);
		});
	return {mount, seen};
}

test('registers "account": reads are safe, everything that changes something asks', async () => {
	const command = await load(await tmp());
	assert.equal(command.name, 'account');
	assert.equal(command.agent, 'confirm');
	assert.deepEqual(command.subcommands!.filter(s => s.agent === 'safe').map(s => s.name), ['list', 'show', 'fields', 'kinds', 'key', 'which', 'grants']);
	assert.deepEqual(command.subcommands!.filter(s => s.agent === 'deny').map(s => s.name), ['grant', 'revoke']);
	const vault = command.subcommands!.find(s => s.name === 'vault')!;
	assert.deepEqual(vault.subcommands!.map(s => [s.name, s.agent]), [['status', 'safe'], ['rotate', 'deny'], ['reset', 'deny']]);
});

test('no subcommand shows the help through ctx.showHelp, or the usage without it', async () => {
	const command = await load(await tmp());
	let shown = 0;
	assert.deepEqual(await run(command, '', {showHelp: () => void shown++}), []);
	assert.equal(shown, 1);
	assert.deepEqual(await run(command, 'help'), ['account <subcommand>']);
	const kind = command.subcommands!.find(s => s.name === 'kind')!;
	assert.deepEqual(kind.subcommands!.map(s => [s.name, s.agent]), [['add', 'confirm'], ['remove', 'confirm']]);
	let path: string[] | undefined;
	assert.deepEqual(await run(command, 'kind', {showHelp: p => void (path = p)}), []);
	assert.deepEqual(path, ['kind']);
	await assert.rejects(run(command, 'kind'), /Usage: account kind add/);
});

test('a github account by default: add prints the public key and nothing like a private one', async () => {
	const command = await load(await tmp());
	assert.deepEqual(await run(command, 'list'), ['No accounts. Add one: account new (step by step) or settings → Accounts']);
	const added = await run(command, 'add yena --login yena-bot --email yena@example.com');
	const printed = [...added, ...(await run(command, 'list')), ...(await run(command, 'key yena')), ...(await run(command, 'show yena'))].join('\n');
	assert.doesNotMatch(printed, /PRIVATE KEY|BEGIN OPENSSH/);
	assert.match(added[0]!, /Account "yena" \(github\) created/);
	assert.match(added.join('\n'), /^ {2}ssh-ed25519 \S+ yena@example\.com$/m);
	assert.match(added.join('\n'), /Secrets \(token\): account secret yena <field>/);
	assert.deepEqual(await run(command, 'list'), ['  yena · github · login=yena-bot email=yena@example.com']);
});

test('a kind of your own: fields on the command line, secrets only through the hidden input', async () => {
	const command = await load(await tmp());
	assert.deepEqual(await run(command, 'kind add stripe accountId! token:secret!'), ['✓ Kind added: stripe: accountId!, token! (secret)']);
	assert.deepEqual(await run(command, 'kinds'), [
		'  github (built in): login, email, token (secret), SSH key, one of ssh | token',
		'  anthropic-key (built in): key! (secret)',
		'  anthropic-token (built in): token! (secret)',
		'  claude-login (built in): email, method, login! (secret)',
		'  stripe: accountId!, token! (secret)',
	]);
	await assert.rejects(run(command, 'add pay --kind stripe --token sk_live_x'), /"token" is secret and is never typed in a command line/);
	await assert.rejects(run(command, 'add pay --kind stripe --no-ssh'), /has no SSH key anyway/);
	const added = await run(command, 'add pay --kind stripe --accountId acct_1');
	assert.deepEqual(added, ['✓ Account "pay" (stripe) created', '  Secrets (token): account secret pay <field>', '  Still needed: token']);
	assert.deepEqual(await run(command, 'list'), ['  pay · stripe [incomplete: token] · accountId=acct_1']);
	const {mount, seen} = typing('sk_test_secret_value');
	const out = await run(command, 'secret pay token', {mount});
	assert.deepEqual(out, ['✓ pay: token saved']);
	assert.equal(seen.target, 'panel');
	assert.equal(seen.label, 'token for pay (stripe)');
	const shown = await run(command, 'show pay');
	assert.deepEqual(shown, ['pay · stripe', '  accountId!: acct_1', '  token!: set (hidden)']);
	assert.ok(!shown.join('\n').includes('sk_test'));
	assert.deepEqual(await run(command, 'list'), ['  pay · stripe · accountId=acct_1']);
	assert.deepEqual(await run(command, 'secret pay token --clear'), ['✓ pay: token cleared']);
	assert.deepEqual((await run(command, 'show pay')).slice(2), ['  token!: not set', '  Missing: token']);
	await assert.rejects(run(command, 'kind remove stripe'), /Accounts of kind "stripe" exist/);
	await run(command, 'remove pay');
	assert.deepEqual(await run(command, 'kind remove stripe'), ['✓ Kind "stripe" removed']);
});

test('a github account without SSH needs its token; with a key it is complete', async () => {
	const command = await load(await tmp());
	const added = await run(command, 'add api --no-ssh --login yena-bot');
	assert.ok(!added.join('\n').includes('ssh-ed25519'), 'no key was made');
	assert.equal(added.at(-1), '  Still needed: ssh|token');
	assert.deepEqual(await run(command, 'list'), ['  api · github [incomplete: ssh|token] · login=yena-bot']);
	assert.equal((await run(command, 'show api')).find(l => l.startsWith('  SSH key')), '  SSH key: none');
	await run(command, 'secret api token', {mount: typing('ghp_token_value').mount});
	assert.deepEqual(await run(command, 'list'), ['  api · github · login=yena-bot']);
	await run(command, 'add pusher');
	assert.match((await run(command, 'list'))[1]!, /^ {2}pusher · github$/);
});

test('fields: every field of the kind, filled in or empty, never a value', async () => {
	const command = await load(await tmp());
	await run(command, 'add api --no-ssh --login yena-bot');
	assert.deepEqual(await run(command, 'fields api'), ['api · github', '  ✓ login', '  ✗ email', '  ✗ token (secret)', '  ✗ SSH key', '  Missing: ssh|token']);
	await run(command, 'secret api token', {mount: typing('ghp_token_value').mount});
	const shown = await run(command, 'fields api');
	assert.deepEqual(shown.slice(3), ['  ✓ token (secret)', '  ✗ SSH key', '  Complete']);
	assert.ok(!shown.join('\n').includes('ghp_') && !shown.join('\n').includes('yena-bot'));
	await run(command, 'kind add stripe accountId! token:secret!');
	await run(command, 'add pay --kind stripe');
	assert.deepEqual(await run(command, 'fields pay'), ['pay · stripe', '  ✗ accountId!', '  ✗ token! (secret)', '  Missing: accountId, token']);
	await assert.rejects(run(command, 'fields nobody'));
});

test('secret: cancelling saves nothing; without the app it says what it needs', async () => {
	const command = await load(await tmp());
	await run(command, 'add yena');
	const {mount} = typing(null);
	assert.deepEqual(await run(command, 'secret yena token', {mount}), ['Cancelled, nothing saved']);
	assert.equal((await run(command, 'show yena'))[3], '  token: not set');
	await assert.rejects(run(command, 'secret yena token'), /needs the app/);
	await assert.rejects(run(command, 'secret yena token', {mount, headless: true}), /needs the app/);
	await assert.rejects(run(command, 'secret yena login', {mount}), /"login" is not a secret field of github \(secret fields: token\)/);
	await assert.rejects(run(command, 'secret yena', {mount}), /Specify the field: token/);
});

test('set changes public fields only', async () => {
	const command = await load(await tmp());
	await run(command, 'add yena');
	assert.deepEqual(await run(command, 'set yena --email yena@example.com'), ['✓ yena: email updated']);
	assert.match((await run(command, 'list'))[0]!, /email=yena@example\.com/);
	await assert.rejects(run(command, 'set yena --kind other'), /cannot change/);
	await assert.rejects(run(command, 'set yena'), /Nothing to set/);
	await assert.rejects(run(command, 'set yena --token x'), /never typed in a command line/);
});

test('use and which work on a repository; a disabled account cannot be used', async () => {
	const command = await load(await tmp());
	await run(command, 'add yena');
	const repo = await tmp();
	execFileSync('git', ['init', '-q', repo]);
	const used = await run(command, `use yena ${repo}`);
	assert.match(used[0]!, /now uses "yena"/);
	assert.match(used[1]!, /No email set/);
	assert.deepEqual(await run(command, `which ${repo}`), [`${repo}: yena`]);
	await run(command, 'disable yena');
	await assert.rejects(run(command, `use yena ${repo}`), /is disabled/);
	assert.match((await run(command, 'list'))[0]!, /\[disabled\]/);
});

test('use and key need an account with an SSH key', async () => {
	const command = await load(await tmp());
	await run(command, 'kind add svc token:secret');
	await run(command, 'add s1 --kind svc');
	await assert.rejects(run(command, 'key s1'), /has no SSH key/);
	await assert.rejects(run(command, 'use s1 .'), /has no SSH key/);
});

test('errors name the problem', async () => {
	const command = await load(await tmp());
	await assert.rejects(run(command, 'nope'), {message: 'Unknown subcommand "nope". See: account help'});
	await assert.rejects(run(command, 'add'), {message: 'Specify the account name'});
	await assert.rejects(run(command, 'add yena --kind ghost'), /Unknown kind "ghost"/);
	await assert.rejects(run(command, 'add yena login'), /Expected --<field> <value>/);
	await assert.rejects(run(command, 'add yena --login'), {message: '--login needs a value'});
	await assert.rejects(run(command, 'key ghost'), /Account "ghost" does not exist/);
	await assert.rejects(run(command, 'kind'), /Usage: account kind add/);
});

test('the settings tab lists accounts as they are when it opens and manages them', async () => {
	const command = await load(await tmp());
	const tab = () => command.settings as SettingsTab;
	assert.deepEqual(tab().settings, []);
	assert.deepEqual(tab().actions?.map(a => [a.key, a.label]), [['account.add', 'Add account…']]);
	await run(command, 'add yena --login yena-bot');
	await run(command, 'add other');
	const [yena] = tab().settings;
	assert.equal(yena!.label, 'yena · github');
	assert.equal(yena!.description, 'login=yena-bot');
	assert.deepEqual(yena!.options.map(o => o.value), ['active', 'disabled', 'delete']);
	assert.equal(await yena!.get(), 'active');
	await yena!.set('disabled');
	assert.equal(await yena!.get(), 'disabled');
	await yena!.set('delete');
	assert.deepEqual(tab().settings.map(s => s.key), ['account.other']);
});

test('the "Add account…" row and "account new" open the step-by-step form in the panel', async () => {
	const command = await load(await tmp());
	const action = (command.settings as SettingsTab).actions![0]!;
	// The form loads when the tab is read; until then opening it asks to press Enter again.
	let element: object | undefined;
	for (let i = 0; i < 100 && element === undefined; i++) {
		try {
			element = action.open({close() {}});
		} catch (error) {
			assert.match((error as Error).message, /still loading/);
			await new Promise(r => setTimeout(r, 20));
		}
	}
	assert.equal(typeof element, 'object');
	await assert.rejects(run(command, 'new'), /needs the app/);
	let target: string | undefined;
	const mount = (build: (c: MountControl) => object, options?: MountOptions) => {
		target = options?.target;
		assert.equal(typeof build({close() {}}), 'object');
		return Promise.resolve();
	};
	await run(command, 'new', {mount});
	assert.equal(target, 'panel');
});

test('the log redactor cuts private key blocks and stored secret values', () => {
	const begin = '-----BEGIN OPENSSH PRIVATE KEY-----';
	const end = '-----END OPENSSH PRIVATE KEY-----';
	assert.equal(redactPrivateKeys(`before ${begin}\nabc\n${end} after`), 'before [private key] after');
	assert.equal(redactPrivateKeys('x -----BEGIN RSA PRIVATE KEY-----\ncut off'), 'x [private key]');
	const redact = redactValues(['sk_live_abcdef', 'sk_live_abcdef_longer', 'abc']);
	assert.equal(redact('a sk_live_abcdef_longer b sk_live_abcdef c abc'), 'a [secret] b [secret] c abc');
});

// Generated shapes, not real credentials.
const FAKE_KEY = 'sk-ant-api03-' + 'Cmd7est_'.repeat(5);
const ACCESS = 'sk-ant-oat01-' + 'L0ginAcc_'.repeat(5);

const build: BuildInfo = {
	version: '0.0.0',
	modules: [
		{name: 'account', version: '0.6.0'},
		{name: 'claude', version: '0.12.0', credentials: {'anthropic-key': 'write', 'anthropic-token': 'read'}},
		{name: 'core', version: '1.0.0'},
	],
};

function capture() {
	const records: {msg: string; fields?: unknown}[] = [];
	const redactors: ((t: string) => string)[] = [];
	const log: Logger = {
		error: (msg, fields) => void records.push({msg, fields}),
		warn: (msg, fields) => void records.push({msg, fields}),
		info: (msg, fields) => void records.push({msg, fields}),
		debug: (msg, fields) => void records.push({msg, fields}),
		child: () => log,
		addRedactor: r => void redactors.push(r),
	};
	let provider: CredentialProvider | undefined;
	return {
		records,
		redact: (t: string) => redactors.reduce((x, r) => r(x), t),
		host: {log, build, registerCredentialProvider: (p: CredentialProvider) => void (provider = p)},
		provider: () => provider!,
	};
}

test('Anthropic kinds: a login cannot be typed or made by hand; a bad key is refused; nothing prints a value', async () => {
	const command = await load(await tmp());
	await assert.rejects(run(command, 'add c1 --kind claude-login'), {message: 'Accounts of kind claude-login are made by: claude auth login'});
	await run(command, 'add k1 --kind anthropic-key');
	await assert.rejects(run(command, 'secret k1 key', {mount: typing('not-a-key').mount}), {message: 'Not an Anthropic API key (sk-ant-…)'});
	assert.deepEqual(await run(command, 'secret k1 key', {mount: typing(FAKE_KEY).mount}), ['✓ k1: key saved']);
	const shown = [...(await run(command, 'show k1')), ...(await run(command, 'list')), ...(await run(command, 'fields k1'))].join('\n');
	assert.match(shown, /key!: set \(hidden\)/);
	assert.ok(!shown.includes(FAKE_KEY));
});

test('account secret refuses the managed login field', async () => {
	const dir = await tmp();
	const command = await load(dir);
	await createStore(dir).add({name: 'c2', kind: BUILTIN_KINDS.find(k => k.name === 'claude-login')!});
	await assert.rejects(run(command, 'secret c2 login', {mount: typing('{}').mount}), {message: '"login" is set by the module that uses it (claude auth login); it cannot be typed'});
	assert.deepEqual((await run(command, 'show c2')).slice(1), ['  email: -', '  method: -', '  login!: not set', '  Missing: login']);
});

test('grants: listed per declaring module; grant and revoke change them; assistants are refused', async () => {
	const c = capture();
	const command = await load(await tmp(), c.host);
	assert.deepEqual(await run(command, 'grants'), ['  claude · anthropic-key · declared write · not granted', '  claude · anthropic-token · declared read · not granted']);
	const signal = new AbortController().signal;
	await assert.rejects(run(command, 'grant claude', {signal}), /only for you to run in the console, never for an assistant/);
	await assert.rejects(run(command, 'revoke claude', {signal}), /never for an assistant/);
	await assert.rejects(run(command, 'grant ghost'), {message: 'Module "ghost" is not installed. See: mod list'});
	await assert.rejects(run(command, 'grant core'), {message: 'core declares no credentials in its yena.json'});
	await assert.rejects(run(command, 'grant claude github'), /claude did not declare credentials of kind "github" in yena.json/);
	await assert.rejects(run(command, 'grant'), /Specify the module/);
	assert.deepEqual(await run(command, 'grant claude anthropic-token'), ['✓ claude may now use: anthropic-token (read)']);
	assert.deepEqual(await run(command, 'grant claude'), ['✓ claude may now use: anthropic-key (write), anthropic-token (read)']);
	assert.deepEqual(await run(command, 'grants'), ['  claude · anthropic-key · declared write · granted write', '  claude · anthropic-token · declared read · granted read']);
	const me = {module: 'claude', declared: build.modules[1]!.credentials!};
	assert.deepEqual((await c.provider().list(undefined, me)).length, 0);
	assert.deepEqual(await run(command, 'revoke claude anthropic-key'), ['✓ claude: anthropic-key revoked']);
	await assert.rejects(c.provider().list('anthropic-key', me), {code: 'CREDENTIAL_ACCESS'});
	assert.deepEqual(await run(command, 'revoke claude'), ['✓ claude: anthropic-token revoked']);
	assert.deepEqual(await run(command, 'revoke claude'), ['claude had no such grants']);
	assert.deepEqual(await run(await load(await tmp()), 'grants'), ['This yena does not tell which modules declare credentials (an older host)']);
});

test('grants of modules that are no longer installed are pruned at load', async () => {
	const dir = await tmp();
	await createGrants(dir).allow('removed', {'anthropic-key': 'read'});
	await createGrants(dir).allow('claude', {'anthropic-key': 'read'});
	await load(dir, capture().host);
	assert.deepEqual(await createGrants(dir).all(), {claude: {'anthropic-key': 'read'}});
	await load(dir);
	assert.deepEqual(Object.keys(await createGrants(dir).all()), ['claude'], 'without build info nothing is pruned');
});

test('vault: status shows counts only; rotate and reset refuse assistants; reset asks to type reset', async () => {
	const dir = await tmp();
	const command = await load(dir);
	await run(command, 'add k1 --kind anthropic-key');
	await run(command, 'secret k1 key', {mount: typing(FAKE_KEY).mount});
	await run(command, 'add gh');
	assert.deepEqual(await run(command, 'vault status'), ['Vault key: present (key 1)', '  Encrypted: 2']);
	const signal = new AbortController().signal;
	await assert.rejects(run(command, 'vault rotate', {signal}), /never for an assistant/);
	await assert.rejects(run(command, 'vault reset', {signal}), /never for an assistant/);
	assert.deepEqual(await run(command, 'vault rotate'), ['✓ Vault key 2: 1 secret file and 1 SSH key re-encrypted, the old key dropped']);
	assert.deepEqual(await run(command, 'vault status'), ['Vault key: present (key 2)', '  Encrypted: 2']);
	await assert.rejects(run(command, 'vault reset'), /needs the app/);
	assert.deepEqual(await run(command, 'vault reset', {mount: typing(null).mount}), ['Cancelled, nothing changed']);
	await rm(path.join(dir, 'vault', 'key'));
	const status = await run(command, 'vault status');
	assert.deepEqual(status, ['Vault key: not made yet', '  Encrypted: 0', '  Cannot be decrypted: 2 (restore the vault folder from a backup, or: account vault reset)']);
	assert.match((await run(command, 'show k1'))[1]!, /key!: set \(cannot be decrypted\)/);
	const {mount, seen} = typing('reset');
	assert.deepEqual(await run(command, 'vault reset', {mount}), ['✓ Vault reset: 1 secret and 1 SSH key dropped, a new key made']);
	assert.match(seen.label!, /Drop 2 entries that cannot be decrypted/);
	assert.deepEqual(await run(command, 'vault status'), ['Vault key: present (key 1)', '  Encrypted: 0']);
	let shown: string[] | undefined;
	await run(command, 'vault', {showHelp: p => void (shown = p)});
	assert.deepEqual(shown, ['vault']);
	await assert.rejects(run(command, 'vault nope'), /Unknown subcommand "vault nope"/);
});

test('the log redactor masks a token inside a stored login blob and the vault key', async () => {
	const dir = await tmp();
	const c = capture();
	await load(dir, c.host);
	await createGrants(dir).allow('claude', {'claude-login': 'write'});
	const me = {module: 'claude', declared: {'claude-login': 'write' as const}};
	await c.provider().create({name: 'c1', kind: 'claude-login'}, me);
	await c.provider().write('c1', 'login', JSON.stringify({credentials: {claudeAiOauth: {accessToken: ACCESS}}}), me);
	await new Promise(r => setTimeout(r, 50));
	assert.equal(c.redact(`token ${ACCESS} end`), 'token [secret] end');
	const key = (JSON.parse(await readFile(path.join(dir, 'vault', 'key'), 'utf8')) as {keys: {key: string}[]}).keys[0]!.key;
	assert.equal(c.redact(`k=${key}`), 'k=[vault key]');
	assert.ok(!JSON.stringify(c.records).includes(ACCESS));
});
