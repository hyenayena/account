import assert from 'node:assert/strict';
import {readdir, readFile, stat, writeFile} from 'node:fs/promises';
import path from 'node:path';
import {test} from 'node:test';
import {BUILTIN_KINDS} from '../src/kinds.js';
import {createStore} from '../src/store.js';
import {github, stripe, tmp} from './helpers.js';

const mode = async (p: string) => (await stat(p)).mode & 0o777;
const kind = (name: string) => BUILTIN_KINDS.find(k => k.name === name)!;

test('a github account gets an ed25519 key stored encrypted; only the public half is recorded', async () => {
	const dir = await tmp();
	const store = createStore(dir);
	const a = await store.add({name: 'yena', kind: github, fields: {login: 'yena-bot', email: 'yena@example.com'}}, 1000);
	assert.match(a.publicKey!, /^ssh-ed25519 \S+ yena@example\.com$/);
	assert.match(a.fingerprint!, /^SHA256:/);
	assert.deepEqual((await readdir(store.dirs.keys)).sort(), ['yena.enc', 'yena.pub']);
	const enc = await readFile(path.join(store.dirs.keys, 'yena.enc'), 'utf8');
	assert.doesNotMatch(enc, /PRIVATE KEY/);
	assert.equal(JSON.parse(enc).v, 1);
	assert.equal(await mode(path.join(store.dirs.keys, 'yena.enc')), 0o600);
	assert.equal(await mode(store.dirs.keys), 0o700);
	assert.equal(await mode(dir), 0o700);
	assert.equal(await mode(path.join(dir, 'accounts.json')), 0o600);
	assert.equal(await mode(path.join(dir, 'vault', 'key')), 0o600);
	assert.equal(await mode(path.join(dir, 'vault')), 0o700);
	const key = await store.privateKey('yena');
	assert.match(key.toString('utf8'), /^-----BEGIN OPENSSH PRIVATE KEY-----\n/);
	key.fill(0);
	assert.doesNotMatch(await readFile(path.join(dir, 'accounts.json'), 'utf8'), /PRIVATE KEY/);
	assert.deepEqual(await store.list(), [
		{name: 'yena', kind: 'github', fields: {login: 'yena-bot', email: 'yena@example.com'}, publicKey: a.publicKey, fingerprint: a.fingerprint, createdAt: 1000, disabled: false},
	]);
	assert.deepEqual(store.listSync(), await store.list());
});

test('secrets are stored encrypted (v2), 0600, and read back in memory', async () => {
	const dir = await tmp();
	const store = createStore(dir);
	const a = await store.add({name: 'pay', kind: stripe, fields: {accountId: 'acct_1'}});
	assert.equal(a.publicKey, undefined);
	await store.setSecret('pay', 'token', 'sk_test_123456');
	const file = path.join(store.dirs.secrets, 'pay.json');
	const raw = JSON.parse(await readFile(file, 'utf8'));
	assert.equal(raw.v, 2);
	assert.deepEqual(Object.keys(raw.fields), ['token']);
	assert.ok(!(await readFile(file, 'utf8')).includes('sk_test_123456'), 'the value is not on disk');
	assert.deepEqual(await store.secretNames('pay'), ['token']);
	assert.equal(await store.secret('pay', 'token'), 'sk_test_123456');
	assert.deepEqual(await store.secretStates('pay'), {token: 'ok'});
	assert.equal(await mode(file), 0o600);
	assert.equal(await mode(store.dirs.secrets), 0o700);
	assert.deepEqual(await store.allSecretValues(), ['sk_test_123456']);
	await store.setDisabled('pay', true);
	assert.equal(await store.secret('pay', 'token'), undefined, 'a disabled account gives no secrets');
	await store.setDisabled('pay', false);
	await store.setSecret('pay', 'token', undefined);
	assert.deepEqual(await store.secretNames('pay'), []);
});

test('a secret is validated by its kind; size caps hold', async () => {
	const store = createStore(await tmp());
	await store.add({name: 'key', kind: kind('anthropic-key')});
	await store.add({name: 'tok', kind: kind('anthropic-token')});
	await store.add({name: 'cl', kind: kind('claude-login'), fields: {email: 'me@example.com', method: 'claude.ai'}});
	await store.add({name: 'pay', kind: stripe});
	await assert.rejects(store.setSecret('key', 'key', 'not-a-key'), {message: 'Not an Anthropic API key (sk-ant-…)'});
	await assert.rejects(store.setSecret('key', 'key', 'sk-ant-oat01-' + 'a'.repeat(30)), /Not an Anthropic API key/);
	await store.setSecret('key', 'key', 'sk-ant-api03-' + 'b'.repeat(30));
	await assert.rejects(store.setSecret('tok', 'token', 'sk-ant-api03-' + 'c'.repeat(30)), {message: 'Not an Anthropic subscription token (sk-ant-oat…)'});
	await store.setSecret('tok', 'token', 'sk-ant-oat01-' + 'd'.repeat(30));
	await assert.rejects(store.setSecret('cl', 'login', '{"x":1}'), /Not a Claude Code login/);
	const blob = JSON.stringify({credentials: {claudeAiOauth: {accessToken: 'e'.repeat(40), refreshToken: 'f'.repeat(40)}}, pad: 'g'.repeat(20_000)});
	await store.setSecret('cl', 'login', blob);
	assert.equal(await store.secret('cl', 'login'), blob);
	await assert.rejects(store.setSecret('pay', 'token', 'x'.repeat(8193)), /1 to 8192 characters/);
	await assert.rejects(store.add({name: 'bad', kind: kind('claude-login'), fields: {method: 'web'}}), /Invalid method/);
	const values = await store.allSecretValues();
	assert.ok(values.includes('e'.repeat(40)) && values.includes('f'.repeat(40)), 'tokens inside a login blob are masked one by one');
});

test('fields are checked against the kind; secrets are refused as plain fields', async () => {
	const store = createStore(await tmp());
	await assert.rejects(store.add({name: '../x', kind: github}), /Invalid account name/);
	await assert.rejects(store.add({name: 'a.pub', kind: github}), /Invalid account name/);
	await assert.rejects(store.add({name: 'ok', kind: github, fields: {login: 'bad login'}}), /Invalid login/);
	await assert.rejects(store.add({name: 'ok', kind: github, fields: {email: 'nope'}}), /Invalid email/);
	await assert.rejects(store.add({name: 'ok', kind: stripe, fields: {plan: 'x'}}), /Kind "stripe" has no field "plan" \(fields: accountId, token\)/);
	await assert.rejects(store.add({name: 'ok', kind: stripe, fields: {token: 'x'}}), /"token" is secret and is never typed in a command line/);
	assert.deepEqual(await store.list(), []);
});

test('setFields merges public fields; a second account with the same name is refused', async () => {
	const store = createStore(await tmp());
	await store.add({name: 'pay', kind: stripe, fields: {accountId: 'acct_1'}});
	await assert.rejects(store.add({name: 'pay', kind: stripe}), /already exists/);
	const a = await store.setFields('pay', stripe, {accountId: 'acct_2'});
	assert.deepEqual(a.fields, {accountId: 'acct_2'});
});

test('disable, enable and remove; remove takes the secrets and the key along', async () => {
	const store = createStore(await tmp());
	await store.add({name: 'yena', kind: github});
	await store.setSecret('yena', 'token', 'ghp_abcdef');
	await store.setDisabled('yena', true);
	assert.equal((await store.get('yena')).disabled, true);
	await stat(path.join(store.dirs.keys, 'yena.disabled'));
	await store.setDisabled('yena', false);
	assert.equal((await store.get('yena')).disabled, false);
	await store.remove('yena');
	assert.deepEqual(await store.list(), []);
	assert.deepEqual(await readdir(store.dirs.keys), []);
	await assert.rejects(stat(path.join(store.dirs.secrets, 'yena.json')), {code: 'ENOENT'});
	await assert.rejects(store.remove('yena'), /does not exist/);
});

test('an accounts file of version 0.1.0 reads as github accounts', async () => {
	const dir = await tmp();
	await writeFile(
		path.join(dir, 'accounts.json'),
		JSON.stringify({v: 1, accounts: [{name: 'old', login: 'me', email: 'me@example.com', fingerprint: 'SHA256:x', publicKey: 'ssh-ed25519 AAAA', createdAt: 5}]}),
	);
	assert.deepEqual(await createStore(dir).list(), [
		{name: 'old', kind: 'github', fields: {login: 'me', email: 'me@example.com'}, publicKey: 'ssh-ed25519 AAAA', fingerprint: 'SHA256:x', createdAt: 5, disabled: false},
	]);
});

test('a plaintext secrets file of 0.5.0 is still read, and the next write encrypts every field', async () => {
	const dir = await tmp();
	const store = createStore(dir);
	await store.add({name: 'pay', kind: stripe});
	await store.setSecret('pay', 'token', 'sk_first_value');
	await writeFile(path.join(store.dirs.secrets, 'pay.json'), JSON.stringify({token: 'sk_plain_value', accountId: 'x'}));
	assert.equal(await store.secret('pay', 'token'), 'sk_plain_value');
	assert.deepEqual(await store.secretStates('pay'), {token: 'plain', accountId: 'plain'});
	await store.setSecret('pay', 'token', 'sk_new_value');
	const text = await readFile(path.join(store.dirs.secrets, 'pay.json'), 'utf8');
	assert.equal(JSON.parse(text).v, 2);
	assert.ok(!text.includes('sk_') && !text.includes('"x"'));
	assert.equal(await store.secret('pay', 'token'), 'sk_new_value');
	assert.equal(await store.secret('pay', 'accountId'), 'x');
});
