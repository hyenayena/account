import assert from 'node:assert/strict';
import {stat, writeFile} from 'node:fs/promises';
import path from 'node:path';
import {test} from 'node:test';
import {createKinds, isManagedKind, missingOf, parseFields} from '../src/kinds.js';
import {github, tmp} from './helpers.js';

const BUILT_IN = ['github', 'anthropic-key', 'anthropic-token', 'claude-login'];

test('github is built in: login, email, a secret token, an SSH key, and one of key or token', async () => {
	const [first] = await createKinds(await tmp()).list();
	assert.deepEqual(first, {
		name: 'github',
		fields: [
			{key: 'login', secret: false, required: false},
			{key: 'email', secret: false, required: false},
			{key: 'token', secret: true, required: false},
		],
		ssh: true,
		oneOf: [['ssh', 'token']],
		builtin: true,
	});
});

test('a kind of your own with required fields and a one-of group is saved, listed and removed', async () => {
	const dir = await tmp();
	const kinds = createKinds(dir);
	const svc = await kinds.add('svc', ['user!', 'password:secret', '--one-of', 'password,apiKey', 'apiKey:secret']);
	assert.deepEqual(svc, {
		name: 'svc',
		fields: [
			{key: 'user', secret: false, required: true},
			{key: 'password', secret: true, required: false},
			{key: 'apiKey', secret: true, required: false},
		],
		ssh: false,
		oneOf: [['password', 'apiKey']],
		builtin: false,
	});
	assert.equal((await stat(path.join(dir, 'kinds.json'))).mode & 0o777, 0o600);
	assert.deepEqual(await createKinds(dir).get('svc'), svc);
	assert.deepEqual(createKinds(dir).listSync().map(k => k.name), [...BUILT_IN, 'svc']);
	await kinds.remove('svc');
	assert.deepEqual((await kinds.list()).map(k => k.name), BUILT_IN);
});

test('a kinds file of 0.2.0 (no required, no groups) still reads', async () => {
	const dir = await tmp();
	await writeFile(path.join(dir, 'kinds.json'), JSON.stringify({v: 1, kinds: [{name: 'old', fields: [{key: 'token', secret: true}]}]}));
	assert.deepEqual(await createKinds(dir).get('old'), {name: 'old', fields: [{key: 'token', secret: true, required: false}], ssh: false, oneOf: [], builtin: false});
});

test('bad kinds, fields and groups are refused', async () => {
	const kinds = createKinds(await tmp());
	await assert.rejects(kinds.add('github', ['x']), /already exists/);
	await assert.rejects(kinds.add('Bad Name', ['x']), /Invalid kind name/);
	await assert.rejects(kinds.remove('github'), /built in/);
	await assert.rejects(kinds.remove('ghost'), /Unknown kind "ghost"/);
	await assert.rejects(kinds.add('k', ['a', '--one-of', 'a']), /two or more fields/);
	await assert.rejects(kinds.add('k', ['a', '--one-of', 'a,b']), /no field "b"/);
	await assert.rejects(kinds.add('k', ['a!', 'b', '--one-of', 'a,b']), /"a" is already required/);
	await assert.rejects(kinds.add('k', ['a', 'b', '--one-of', 'a,a']), /two or more|twice/);
	await assert.rejects(kinds.add('k', ['a', '--one-of']), /needs a value/);
	await assert.rejects(kinds.add('k', ['a', '--other']), /Unknown option "--other"/);
	assert.throws(() => parseFields([]), /at least one field/);
	assert.throws(() => parseFields(['a:public']), /Invalid field "a:public"/);
	assert.throws(() => parseFields(['1a']), /Invalid field name "1a"/);
	assert.throws(() => parseFields(['a', 'a:secret']), /listed twice/);
	assert.throws(() => parseFields(['ssh']), /reserved/);
});

test('missingOf names required fields and unmet groups', () => {
	const svc = {name: 'svc', fields: parseFields(['user!', 'password:secret', 'apiKey:secret']), ssh: false, oneOf: [['password', 'apiKey']], builtin: false};
	assert.deepEqual(missingOf(svc, {fields: {}}, []), ['user', 'password|apiKey']);
	assert.deepEqual(missingOf(svc, {fields: {user: 'me'}}, ['apiKey']), []);
	assert.deepEqual(missingOf(github, {fields: {}}, []), ['ssh|token']);
	assert.deepEqual(missingOf(github, {fields: {}, publicKey: 'ssh-ed25519 AAAA'}, []), []);
	assert.deepEqual(missingOf(github, {fields: {}}, ['token']), []);
});

test('the Anthropic kinds are built in, with checks and a managed login', async () => {
	const kinds = createKinds(await tmp());
	assert.deepEqual((await kinds.get('anthropic-key')).fields, [{key: 'key', secret: true, required: true, check: 'anthropic-key'}]);
	assert.deepEqual((await kinds.get('anthropic-token')).fields, [{key: 'token', secret: true, required: true, check: 'anthropic-token'}]);
	const login = await kinds.get('claude-login');
	assert.deepEqual(login.fields, [
		{key: 'email', secret: false, required: false},
		{key: 'method', secret: false, required: false},
		{key: 'login', secret: true, required: true, check: 'claude-login', managed: true},
	]);
	assert.equal(login.ssh, false);
	assert.equal(isManagedKind(login), true);
	assert.equal(isManagedKind(await kinds.get('anthropic-key')), false);
	for (const name of ['anthropic-key', 'anthropic-token', 'claude-login']) await assert.rejects(kinds.add(name, ['x']), /already exists/);
});

test('the kinds file cannot shadow a built-in kind or set check and managed', async () => {
	const dir = await tmp();
	await writeFile(
		path.join(dir, 'kinds.json'),
		JSON.stringify({
			v: 1,
			kinds: [
				{name: 'anthropic-key', fields: [{key: 'key', secret: false}]},
				{name: 'mine', fields: [{key: 'token', secret: true, required: true, check: 'claude-login', managed: true}]},
			],
		}),
	);
	const kinds = createKinds(dir);
	assert.deepEqual((await kinds.get('anthropic-key')).fields[0], {key: 'key', secret: true, required: true, check: 'anthropic-key'});
	assert.deepEqual((await kinds.get('mine')).fields, [{key: 'token', secret: true, required: true}]);
	assert.throws(() => parseFields(['token:managed']), /Invalid field/);
	assert.throws(() => parseFields(['token:check']), /Invalid field/);
});
