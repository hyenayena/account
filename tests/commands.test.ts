import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {test} from 'node:test';
import type {Command, CommandContext, MountControl, MountOptions, SettingsTab} from '../../../src/api.js';
import {createPlugin, redactPrivateKeys, redactValues} from '../src/index.js';
import {makeCtx, tmp} from './helpers.js';

const plugin = createPlugin({agents: false});

const load = async (dataDir: string): Promise<Command> => {
	const commands = await plugin({dataDir, events: {emit() {}, on: () => () => {}}, log: undefined as never});
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
	assert.deepEqual(command.subcommands!.filter(s => s.agent === 'safe').map(s => s.name), ['list', 'show', 'fields', 'kinds', 'key', 'which']);
	assert.ok(command.subcommands!.every(s => s.agent === 'safe' || s.agent === 'confirm'));
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
