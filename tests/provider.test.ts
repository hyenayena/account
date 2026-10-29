import assert from 'node:assert/strict';
import {rm, stat, symlink, writeFile} from 'node:fs/promises';
import path from 'node:path';
import {test} from 'node:test';
import type {CredentialAccess, CredentialCaller, Logger} from '../../../src/api.js';
import {createGrants} from '../src/grants.js';
import {BUILTIN_KINDS, createKinds} from '../src/kinds.js';
import {createProvider} from '../src/provider.js';
import {createStore, type Store} from '../src/store.js';
import {tmp} from './helpers.js';

const kind = (name: string) => BUILTIN_KINDS.find(k => k.name === name)!;
const KEY = 'sk-ant-api03-' + 'Gen3rated_'.repeat(4);
const TOKEN = 'sk-ant-oat01-' + 'Gen3rated_'.repeat(4);
const LOGIN = JSON.stringify({credentials: {claudeAiOauth: {accessToken: 'sk-ant-oat01-' + 'Acc3ss_'.repeat(6), refreshToken: 'sk-ant-ort01-' + 'Refr3sh_'.repeat(6)}}});

const caller = (declared: Record<string, CredentialAccess>, module = 'claude'): CredentialCaller => ({module, declared: Object.freeze({...declared})});

function recordingLog() {
	const records: {level: string; msg: string; fields?: Record<string, unknown>}[] = [];
	const log: Logger = {
		error: (msg, fields) => void records.push({level: 'error', msg, ...(fields && {fields: fields as Record<string, unknown>})}),
		warn: (msg, fields) => void records.push({level: 'warn', msg, ...(fields && {fields: fields as Record<string, unknown>})}),
		info: (msg, fields) => void records.push({level: 'info', msg, ...(fields && {fields: fields as Record<string, unknown>})}),
		debug: (msg, fields) => void records.push({level: 'debug', msg, ...(fields && {fields: fields as Record<string, unknown>})}),
		child: () => log,
		addRedactor() {},
	};
	return {log, records};
}

function counting(store: Store): {store: Store; calls: string[]} {
	const calls: string[] = [];
	const wrapped = {...store} as Record<string, unknown>;
	for (const [name, fn] of Object.entries(store)) {
		if (typeof fn === 'function') wrapped[name] = (...args: unknown[]) => (calls.push(name), (fn as (...a: unknown[]) => unknown)(...args));
	}
	return {store: wrapped as Store, calls};
}

async function setup() {
	const dir = await tmp();
	const raw = createStore(dir);
	await raw.add({name: 'key1', kind: kind('anthropic-key')});
	await raw.setSecret('key1', 'key', KEY);
	await raw.add({name: 'tok1', kind: kind('anthropic-token')});
	await raw.setSecret('tok1', 'token', TOKEN);
	await raw.add({name: 'gh', kind: kind('github'), ssh: false});
	await raw.setSecret('gh', 'token', 'ghp_' + 'g'.repeat(36));
	const {store, calls} = counting(raw);
	const {log, records} = recordingLog();
	const grants = createGrants(dir, log);
	let refreshed = 0;
	const provider = createProvider({store, kinds: createKinds(dir), grants, log, onSecretsChanged: () => void refreshed++});
	return {dir, raw, calls, provider, grants, records, refreshed: () => refreshed};
}

const all = {'anthropic-key': 'write', 'anthropic-token': 'write', 'claude-login': 'write'} as const;

test('an ungranted module gets nothing: every call is refused with CREDENTIAL_ACCESS and the store is never touched', async () => {
	const {provider, calls, records} = await setup();
	const me = caller(all);
	const denied = {code: 'CREDENTIAL_ACCESS', message: /^claude may not (read|change) credentials.*Allow it \(only you can, not an assistant\): account grant claude$/};
	await assert.rejects(provider.list(undefined, me), denied);
	await assert.rejects(provider.list('anthropic-key', me), {code: 'CREDENTIAL_ACCESS', message: 'claude may not read credentials of kind "anthropic-key". Allow it (only you can, not an assistant): account grant claude'});
	await assert.rejects(provider.read('key1', 'key', me), denied);
	await assert.rejects(provider.write('key1', 'key', KEY, me), denied);
	await assert.rejects(provider.create({name: 'n', kind: 'anthropic-key'}, me), {code: 'CREDENTIAL_ACCESS', message: /may not change credentials of kind "anthropic-key"/});
	await assert.rejects(provider.remove('key1', me), denied);
	assert.deepEqual(calls, []);
	assert.deepEqual(await provider.grants(me), [
		{kind: 'anthropic-key', declared: 'write'},
		{kind: 'anthropic-token', declared: 'write'},
		{kind: 'claude-login', declared: 'write'},
	]);
	assert.deepEqual(records.filter(r => r.msg === 'credential access').map(r => r.fields!.outcome), ['denied', 'denied', 'denied', 'denied', 'denied', 'denied', 'ok']);
});

test('an undeclared kind is refused even when the grants file has it', async () => {
	const {provider, grants} = await setup();
	await grants.allow('claude', {'anthropic-key': 'write', github: 'write'});
	const me = caller({'anthropic-key': 'write'});
	await assert.rejects(provider.list('github', me), {message: 'claude did not declare credentials of kind "github" in yena.json'});
	await assert.rejects(provider.read('gh', 'token', me), {message: 'claude did not declare credentials of kind "github" in yena.json'});
	assert.deepEqual((await provider.list(undefined, me)).map(a => a.name), ['key1'], 'list shows only granted, declared kinds');
	await assert.rejects(provider.list(undefined, caller({})), {message: 'claude did not declare any credentials in yena.json'});
});

test('granted: list, read, write, create and remove; read of a disabled account is undefined', async () => {
	const {provider, grants, raw, refreshed} = await setup();
	await grants.allow('claude', {...all});
	const me = caller(all);
	assert.deepEqual(await provider.list('anthropic-key', me), [{name: 'key1', kind: 'anthropic-key', fields: {}, secrets: ['key'], disabled: false, missing: []}]);
	assert.deepEqual((await provider.list(undefined, me)).map(a => a.name), ['key1', 'tok1']);
	assert.ok(!JSON.stringify(await provider.list(undefined, me)).includes('sk-ant'), 'list carries no values');
	assert.equal(await provider.read('key1', 'key', me), KEY);
	assert.equal(await provider.read('tok1', 'token', me), TOKEN);
	const made = await provider.create({name: 'login1', kind: 'claude-login', fields: {email: 'me@example.com', method: 'claude.ai'}}, me);
	assert.deepEqual(made, {name: 'login1', kind: 'claude-login', fields: {email: 'me@example.com', method: 'claude.ai'}, secrets: [], disabled: false, missing: ['login']});
	await provider.write('login1', 'login', LOGIN, me);
	assert.equal(refreshed(), 1, 'a write refreshes the redactor');
	assert.equal(await provider.read('login1', 'login', me), LOGIN);
	assert.equal(await provider.read('login1', 'email', me).catch((e: Error) => e.message), 'Kind "claude-login" has no secret field "email"');
	await assert.rejects(provider.write('key1', 'key', 'not-a-key', me), {message: 'Not an Anthropic API key (sk-ant-…)'});
	await assert.rejects(provider.write('login1', 'login', '{"x":1}', me), /Not a Claude Code login/);
	await raw.setDisabled('key1', true);
	assert.equal(await provider.read('key1', 'key', me), undefined);
	await provider.write('tok1', 'token', undefined, me);
	assert.equal(await provider.read('tok1', 'token', me), undefined);
	await provider.remove('login1', me);
	await assert.rejects(provider.read('login1', 'login', me), /does not exist/);
	assert.equal(refreshed(), 3);
});

test('a module cannot create SSH accounts', async () => {
	const {provider, grants} = await setup();
	await grants.allow('claude', {github: 'write'});
	await assert.rejects(provider.create({name: 'x', kind: 'github'}, caller({github: 'write'})), /are made by the user \(account add\), not by a module/);
});

test('a read grant cannot write, create or remove; effective access is min(declared, granted)', async () => {
	const {provider, grants} = await setup();
	await grants.allow('claude', {'anthropic-key': 'read', 'anthropic-token': 'write'});
	const me = caller({'anthropic-key': 'write', 'anthropic-token': 'read'});
	assert.equal(await provider.read('key1', 'key', me), KEY);
	await assert.rejects(provider.write('key1', 'key', KEY, me), {code: 'CREDENTIAL_ACCESS', message: 'claude may not change credentials. Allow it (only you can, not an assistant): account grant claude'});
	await assert.rejects(provider.remove('key1', me), {code: 'CREDENTIAL_ACCESS'});
	await assert.rejects(provider.create({name: 'k2', kind: 'anthropic-key'}, me), {code: 'CREDENTIAL_ACCESS'});
	assert.equal(await provider.read('tok1', 'token', me), TOKEN);
	await assert.rejects(provider.write('tok1', 'token', TOKEN, me), {code: 'CREDENTIAL_ACCESS'}, 'declared read caps a write grant');
	assert.deepEqual(await provider.grants(me), [
		{kind: 'anthropic-key', declared: 'write', granted: 'read'},
		{kind: 'anthropic-token', declared: 'read', granted: 'read'},
	]);
});

test('a revoke takes effect on the next call', async () => {
	const {provider, grants} = await setup();
	await grants.allow('claude', {'anthropic-key': 'read'});
	const me = caller({'anthropic-key': 'read'});
	assert.equal(await provider.read('key1', 'key', me), KEY);
	await createGrants(path.dirname(grants.file)).revoke('claude');
	await assert.rejects(provider.read('key1', 'key', me), {code: 'CREDENTIAL_ACCESS'});
});

test('a corrupt or symlinked grants file means no grants', async () => {
	const {provider, grants, records} = await setup();
	const me = caller({'anthropic-key': 'read'});
	await writeFile(grants.file, '{"v":1,"grants":');
	await assert.rejects(provider.read('key1', 'key', me), {code: 'CREDENTIAL_ACCESS'});
	assert.ok(records.some(r => r.level === 'warn' && r.msg.startsWith('grants file unreadable')));
	const real = path.join(await tmp(), 'grants.json');
	await writeFile(real, JSON.stringify({v: 1, grants: {claude: {'anthropic-key': 'read'}}}));
	await rm(grants.file);
	await symlink(real, grants.file);
	await assert.rejects(provider.read('key1', 'key', me), {code: 'CREDENTIAL_ACCESS'});
});

test('grants are pruned for modules that are not installed; written 0600, atomically', async () => {
	const {grants} = await setup();
	await grants.allow('claude', {'anthropic-key': 'read'});
	await grants.allow('gone', {'anthropic-key': 'read'});
	assert.deepEqual(await grants.prune(['claude', 'core']), ['gone']);
	assert.deepEqual(await grants.all(), {claude: {'anthropic-key': 'read'}});
	assert.equal((await stat(grants.file)).mode & 0o777, 0o600);
});

test('one audit record per call, metadata only: no value, no length', async () => {
	const {provider, grants, records} = await setup();
	await grants.allow('claude', {...all});
	const me = caller(all);
	await provider.read('key1', 'key', me);
	await provider.write('tok1', 'token', TOKEN, me);
	await provider.create({name: 'login1', kind: 'claude-login'}, me);
	await provider.write('login1', 'login', LOGIN, me);
	await provider.read('ghost', 'key', me).catch(() => undefined);
	await provider.list(undefined, me);
	const audit = records.filter(r => r.msg === 'credential access');
	assert.equal(audit.length, 6);
	assert.deepEqual(audit[0]!.fields, {module: 'claude', op: 'read', kind: 'anthropic-key', account: 'key1', outcome: 'ok'});
	assert.deepEqual(audit[4]!.fields, {module: 'claude', op: 'read', account: 'ghost', outcome: 'missing'});
	const text = JSON.stringify(records);
	for (const secret of [KEY, TOKEN, LOGIN, 'Acc3ss_', 'Refr3sh_']) assert.ok(!text.includes(secret));
	assert.ok(audit.every(r => !Object.keys(r.fields!).some(k => /length|size|value/i.test(k))));
});
