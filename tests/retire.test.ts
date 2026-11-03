import assert from 'node:assert/strict';
import {lstat, mkdir, readFile, readdir, stat, symlink, writeFile} from 'node:fs/promises';
import path from 'node:path';
import {test} from 'node:test';
import type {Logger} from '../../../src/api.js';
import {createGrants} from '../src/grants.js';
import {BUILTIN_KINDS, RETIRED_KINDS, type Kind} from '../src/kinds.js';
import {readRetired, retireKinds} from '../src/retire.js';
import {createStore} from '../src/store.js';
import {github, stripe, tmp} from './helpers.js';

const retiredKind = (name: string): Kind => ({name, fields: [{key: 'secret', secret: true, required: true}], ssh: false, oneOf: [], builtin: false});
const keyKind = BUILTIN_KINDS.find(k => k.name === 'anthropic-key')!;
const KEY = 'sk-ant-api03-' + 'Retire_'.repeat(5);
const SECRET = 'sk-ant-oat01-' + 'Gone_'.repeat(8);

function recording() {
	const records: {level: string; msg: string; fields?: Record<string, unknown>}[] = [];
	const rec = (level: string) => (msg: string, fields?: Record<string, unknown>) => void records.push({level, msg, ...(fields && {fields})});
	const log: Logger = {error: rec('error'), warn: rec('warn'), info: rec('info'), debug: rec('debug'), child: () => log, addRedactor() {}};
	return {log, records};
}

async function setup() {
	const dir = await tmp();
	const store = createStore(dir);
	await store.add({name: 'key1', kind: keyKind});
	await store.setSecret('key1', 'key', KEY);
	await store.add({name: 'gh', kind: github, ssh: false});
	await store.setSecret('gh', 'token', 'ghp_' + 'g'.repeat(36));
	await store.add({name: 'pay', kind: stripe, fields: {accountId: 'acct_1'}});
	await store.setSecret('pay', 'token', 'sk_test_123456');
	await store.add({name: 'login1', kind: retiredKind('claude-login')});
	await store.setSecret('login1', 'secret', SECRET);
	await store.add({name: 'login2', kind: retiredKind('claude-login')});
	await store.add({name: 'tok1', kind: retiredKind('anthropic-token')});
	await store.setSecret('tok1', 'secret', SECRET);
	await store.setDisabled('tok1', true);
	const grants = createGrants(dir);
	await grants.allow('claude', {'anthropic-key': 'write', 'claude-login': 'write', 'anthropic-token': 'read'});
	await grants.allow('other', {'claude-login': 'read'});
	return {dir, store, grants};
}

const mode = async (p: string) => (await stat(p)).mode & 0o777;
const SECRET_FILES = ['gh.json', 'key1.json', 'pay.json'];

test('retired kinds are removed with their secrets, disabled ones too; other accounts stay untouched', async () => {
	const {dir, store, grants} = await setup();
	const {log} = recording();
	const before = await Promise.all(SECRET_FILES.map(n => readFile(path.join(dir, 'secrets', n), 'utf8')));
	assert.deepEqual(await retireKinds({store, grants, dataDir: dir, log}), {logins: 2, tokens: 1});
	assert.deepEqual((await store.list()).map(a => a.name), ['key1', 'gh', 'pay']);
	assert.deepEqual((await readdir(path.join(dir, 'secrets'))).sort(), SECRET_FILES);
	assert.deepEqual(await Promise.all(SECRET_FILES.map(n => readFile(path.join(dir, 'secrets', n), 'utf8'))), before);
	assert.equal(await store.secret('key1', 'key'), KEY);
	assert.deepEqual(await readdir(path.join(dir, 'disabled')).catch(() => []), []);
});

test('the record holds counts only, 0600; a second run is a no-op that does not rewrite it', async () => {
	const {dir, store, grants} = await setup();
	const {log, records} = recording();
	await retireKinds({store, grants, dataDir: dir, log});
	const file = path.join(dir, 'retired.json');
	assert.equal(await mode(file), 0o600);
	const first = JSON.parse(await readFile(file, 'utf8')) as Record<string, unknown>;
	assert.deepEqual(Object.keys(first).sort(), ['at', 'logins', 'tokens', 'v']);
	assert.equal(first.v, 1);
	assert.equal(first.logins, 2);
	assert.equal(first.tokens, 1);
	assert.ok(!Number.isNaN(Date.parse(first.at as string)));
	const before = await stat(file);
	assert.equal(await retireKinds({store, grants, dataDir: dir, log}), undefined);
	const after = await stat(file);
	assert.equal(after.ino, before.ino);
	assert.equal(after.mtimeMs, before.mtimeMs);
	assert.deepEqual(readRetired(dir), {at: first.at, logins: 2, tokens: 1});
	assert.deepEqual(records.map(r => [r.level, r.msg, r.fields]), [['info', 'retired credentials removed', {logins: 2, tokens: 1}]]);
	assert.ok(!JSON.stringify(records).includes(SECRET));
});

test('a later removal adds to the counts', async () => {
	const {dir, store, grants} = await setup();
	const {log} = recording();
	await retireKinds({store, grants, dataDir: dir, log});
	await store.add({name: 'late', kind: retiredKind('anthropic-token')});
	assert.deepEqual(await retireKinds({store, grants, dataDir: dir, log}), {logins: 0, tokens: 1});
	const record = readRetired(dir)!;
	assert.deepEqual([record.logins, record.tokens], [2, 2]);
});

test('grants of the retired kinds are dropped for every module, the others kept', async () => {
	const {dir, store, grants} = await setup();
	await retireKinds({store, grants, dataDir: dir, log: recording().log});
	assert.deepEqual(await createGrants(dir).all(), {claude: {'anthropic-key': 'write'}});
	assert.equal(await mode(path.join(dir, 'grants.json')), 0o600);
	assert.equal(RETIRED_KINDS.length, 2);
});

test('grants are dropped even when no retired account is left', async () => {
	const dir = await tmp();
	const grants = createGrants(dir);
	await grants.allow('claude', {'claude-login': 'write', 'anthropic-key': 'read'});
	assert.equal(await retireKinds({store: createStore(dir), grants, dataDir: dir, log: recording().log}), undefined);
	assert.deepEqual(await grants.all(), {claude: {'anthropic-key': 'read'}});
	assert.equal(readRetired(dir), undefined);
});

test('nothing to retire writes nothing', async () => {
	const dir = await tmp();
	const store = createStore(dir);
	await store.add({name: 'key1', kind: keyKind});
	const {log, records} = recording();
	assert.equal(await retireKinds({store, grants: createGrants(dir), dataDir: dir, log}), undefined);
	assert.deepEqual(await readdir(dir), ['accounts.json']);
	assert.deepEqual(records, []);
});

test('a symlinked retired.json is refused: the failure is a warning with the error class only', async () => {
	const {dir, store, grants} = await setup();
	const elsewhere = path.join(await tmp(), 'target.json');
	await writeFile(elsewhere, 'untouched');
	await symlink(elsewhere, path.join(dir, 'retired.json'));
	const {log, records} = recording();
	assert.equal(await retireKinds({store, grants, dataDir: dir, log}), undefined);
	assert.equal(await readFile(elsewhere, 'utf8'), 'untouched');
	assert.ok((await lstat(path.join(dir, 'retired.json'))).isSymbolicLink());
	assert.deepEqual(records.map(r => [r.level, r.msg, Object.keys(r.fields ?? {})]), [['warn', 'retired credentials not removed', ['errClass']]]);
	assert.equal(readRetired(dir), undefined);
});

test('a failure in the store is a warning and the next run retries', async () => {
	const {dir, store, grants} = await setup();
	const {log, records} = recording();
	const broken = {...store, remove: async () => Promise.reject(new Error(`boom ${SECRET}`))} as typeof store;
	assert.equal(await retireKinds({store: broken, grants, dataDir: dir, log}), undefined);
	assert.deepEqual(records.map(r => [r.level, r.msg, r.fields]), [['warn', 'retired credentials not removed', {errClass: 'Error'}]]);
	assert.ok(!JSON.stringify(records).includes(SECRET));
	assert.equal((await store.list()).length, 6);
	assert.deepEqual(await retireKinds({store, grants, dataDir: dir, log}), {logins: 2, tokens: 1});
});

test('retired.json is read only when regular, small and well-formed', async () => {
	const dir = await tmp();
	const file = path.join(dir, 'retired.json');
	assert.equal(readRetired(dir), undefined);
	const good = {v: 1, at: '2026-11-03T10:00:00.000Z', logins: 1, tokens: 0};
	await writeFile(file, JSON.stringify(good));
	assert.deepEqual(readRetired(dir), {at: good.at, logins: 1, tokens: 0});
	const bads = ['not json', '[]', JSON.stringify({...good, v: 2}), JSON.stringify({...good, logins: -1}), JSON.stringify({...good, tokens: 1.5}), JSON.stringify({...good, at: 'yesterday'}), JSON.stringify({...good, at: 5}), JSON.stringify({...good, pad: 'x'.repeat(5000)})];
	for (const bad of bads) {
		await writeFile(file, bad);
		assert.equal(readRetired(dir), undefined, bad.slice(0, 30));
	}
	await mkdir(path.join(dir, 'sub'));
	assert.equal(readRetired(path.join(dir, 'sub')), undefined);
});
