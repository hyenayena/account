import assert from 'node:assert/strict';
import {readFile, stat, writeFile} from 'node:fs/promises';
import path from 'node:path';
import {test} from 'node:test';
import {createStore} from '../src/store.js';
import {github, stripe, tmp} from './helpers.js';

const mode = async (p: string) => (await stat(p)).mode & 0o777;

test('a github account gets an ed25519 key that only its owner can read; only the public half is recorded', async () => {
	const dir = await tmp();
	const store = createStore(dir);
	const a = await store.add({name: 'yena', kind: github, fields: {login: 'yena-bot', email: 'yena@example.com'}}, 1000);
	assert.match(a.publicKey!, /^ssh-ed25519 \S+ yena@example\.com$/);
	assert.match(a.fingerprint!, /^SHA256:/);
	assert.equal(await mode(store.keyPath('yena')), 0o600);
	assert.equal(await mode(store.dirs.keys), 0o700);
	assert.equal(await mode(dir), 0o700);
	assert.equal(await mode(path.join(dir, 'accounts.json')), 0o600);
	assert.doesNotMatch(await readFile(path.join(dir, 'accounts.json'), 'utf8'), /PRIVATE KEY/);
	assert.deepEqual(await store.list(), [
		{name: 'yena', kind: 'github', fields: {login: 'yena-bot', email: 'yena@example.com'}, publicKey: a.publicKey, fingerprint: a.fingerprint, createdAt: 1000, disabled: false},
	]);
	assert.deepEqual(store.listSync(), await store.list());
});

test('an account of a kind without SSH gets no key; its secrets live apart, 0600', async () => {
	const dir = await tmp();
	const store = createStore(dir);
	const a = await store.add({name: 'pay', kind: stripe, fields: {accountId: 'acct_1'}});
	assert.equal(a.publicKey, undefined);
	await assert.rejects(stat(store.keyPath('pay')), {code: 'ENOENT'});
	await store.setSecret('pay', 'token', 'sk_test_123456');
	assert.deepEqual(await store.secretNames('pay'), ['token']);
	assert.equal(await store.secret('pay', 'token'), 'sk_test_123456');
	assert.equal(await mode(path.join(store.dirs.secrets, 'pay.json')), 0o600);
	assert.equal(await mode(store.dirs.secrets), 0o700);
	assert.doesNotMatch(await readFile(path.join(dir, 'accounts.json'), 'utf8'), /sk_test/);
	assert.deepEqual(await store.allSecretValues(), ['sk_test_123456']);
	await store.setDisabled('pay', true);
	assert.equal(await store.secret('pay', 'token'), undefined, 'a disabled account gives no secrets');
	await store.setDisabled('pay', false);
	await store.setSecret('pay', 'token', undefined);
	assert.deepEqual(await store.secretNames('pay'), []);
});

test('fields are checked against the kind; secrets are refused as plain fields', async () => {
	const store = createStore(await tmp());
	await assert.rejects(store.add({name: '../x', kind: github}), /Invalid account name/);
	await assert.rejects(store.add({name: 'a.pub', kind: github}), /Invalid account name/);
	await assert.rejects(store.add({name: 'ok', kind: github, fields: {login: 'bad login'}}), /Invalid login/);
	await assert.rejects(store.add({name: 'ok', kind: github, fields: {email: 'nope'}}), /Invalid email/);
	await assert.rejects(store.add({name: 'ok', kind: stripe, fields: {plan: 'x'}}), /Kind "stripe" has no field "plan" \(fields: accountId, token\)/);
	await assert.rejects(store.add({name: 'ok', kind: stripe, fields: {token: 'x'}}), /"token" is secret and is never typed in a command line/);
	await assert.rejects(stat(store.keyPath('ok')), {code: 'ENOENT'});
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
	await stat(`${store.keyPath('yena')}.disabled`);
	await store.setDisabled('yena', false);
	assert.equal((await store.get('yena')).disabled, false);
	await store.remove('yena');
	assert.deepEqual(await store.list(), []);
	for (const p of [store.keyPath('yena'), `${store.keyPath('yena')}.pub`, path.join(store.dirs.secrets, 'yena.json')]) {
		await assert.rejects(stat(p), {code: 'ENOENT'});
	}
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
