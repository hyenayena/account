import assert from 'node:assert/strict';
import {mkdir, readdir, readFile, rm, utimes, writeFile} from 'node:fs/promises';
import path from 'node:path';
import {test} from 'node:test';
import type {Logger} from '../../../src/api.js';
import {inventory, migrate, reset, rotate} from '../src/migrate.js';
import {generateEd25519} from '../src/openssh.js';
import {createStore} from '../src/store.js';
import {secretAad} from '../src/vault.js';
import {github, stripe, tmp} from './helpers.js';

const SECRET = 'sk_test_migrate_value_123';

function recordingLog() {
	const records: {level: string; msg: string; fields?: unknown}[] = [];
	const log: Logger = {
		error: (msg, fields) => void records.push({level: 'error', msg, fields}),
		warn: (msg, fields) => void records.push({level: 'warn', msg, fields}),
		info: (msg, fields) => void records.push({level: 'info', msg, fields}),
		debug: (msg, fields) => void records.push({level: 'debug', msg, fields}),
		child: () => log,
		addRedactor() {},
	};
	return {log, records};
}

async function legacy() {
	const dir = await tmp();
	const key = generateEd25519('legacy');
	const accounts = [
		{name: 'pay', kind: stripe.name, fields: {accountId: 'acct_1'}, createdAt: 0},
		{name: 'bot', kind: github.name, fields: {}, publicKey: key.publicKey, fingerprint: key.fingerprint, createdAt: 0},
	];
	await writeFile(path.join(dir, 'accounts.json'), JSON.stringify({v: 2, accounts}), {mode: 0o600});
	await writeFile(path.join(dir, 'kinds.json'), JSON.stringify({v: 1, kinds: [{name: stripe.name, fields: stripe.fields}]}), {mode: 0o600});
	const store = createStore(dir);
	await mkdir(store.dirs.secrets, {recursive: true, mode: 0o700});
	await writeFile(path.join(store.dirs.secrets, 'pay.json'), JSON.stringify({token: SECRET}), {mode: 0o600});
	await mkdir(store.dirs.keys, {recursive: true, mode: 0o700});
	await writeFile(path.join(store.dirs.keys, 'bot'), key.privateKey, {mode: 0o600});
	await writeFile(path.join(store.dirs.keys, 'bot.pub'), key.publicKey + '\n');
	return {dir, store, privateKey: key.privateKey};
}

test('migration is lossless, a second run is a no-op, and logs carry counts only', async () => {
	const {store, privateKey} = await legacy();
	assert.deepEqual(await inventory(store), {encrypted: 0, plaintext: 2, undecryptable: 0});
	const {log, records} = recordingLog();
	assert.deepEqual(await migrate(store, log), {secrets: 1, keys: 1, failed: 0});
	assert.equal(await store.secret('pay', 'token'), SECRET);
	assert.ok((await store.privateKey('bot')).equals(privateKey));
	assert.deepEqual((await readdir(store.dirs.keys)).sort(), ['bot.enc', 'bot.pub']);
	assert.equal(JSON.parse(await readFile(path.join(store.dirs.secrets, 'pay.json'), 'utf8')).v, 2);
	assert.deepEqual(await inventory(store), {encrypted: 2, plaintext: 0, undecryptable: 0});
	assert.deepEqual(await migrate(store, log), {secrets: 0, keys: 0, failed: 0});
	assert.deepEqual(records.map(r => r.msg), ['vault migrated']);
	assert.deepEqual(records[0]!.fields, {secrets: 1, keys: 1});
	const text = JSON.stringify(records);
	assert.ok(!text.includes(SECRET) && !text.includes('pay') && !text.includes('bot'));
	assert.deepEqual((await readdir(path.join(store.vault.dir))).sort(), ['key'], 'the lock is gone');
});

test('a crash after the .enc was written resumes: the .enc is verified, then the plaintext goes', async () => {
	const {store, privateKey} = await legacy();
	await store.files.writeEncryptedKey('bot', privateKey);
	assert.deepEqual((await readdir(store.dirs.keys)).sort(), ['bot', 'bot.enc', 'bot.pub']);
	assert.equal((await migrate(store))?.keys, 1);
	assert.deepEqual((await readdir(store.dirs.keys)).sort(), ['bot.enc', 'bot.pub']);
	assert.ok((await store.privateKey('bot')).equals(privateKey));
});

test('a failure keeps the plaintext readable and logs the step, never a value', async () => {
	const {store} = await legacy();
	await writeFile(path.join(store.dirs.secrets, 'other.json'), JSON.stringify({v: 2, fields: {x: {v: 1, kid: 1, iv: 'AAAAAAAAAAAAAAAA', ct: 'AA==', tag: 'AAAAAAAAAAAAAAAAAAAAAA=='}}}));
	const {log, records} = recordingLog();
	const result = await migrate(store, log);
	assert.equal(result?.failed, 2);
	assert.equal(await store.secret('pay', 'token'), SECRET);
	assert.deepEqual((await readdir(store.dirs.keys)).sort(), ['bot', 'bot.pub']);
	assert.deepEqual(new Set(records.map(r => r.msg)), new Set(['vault migration failed']));
	assert.deepEqual(records.map(r => (r.fields as {step: string}).step), ['secrets', 'keys']);
	assert.ok(!JSON.stringify(records).includes(SECRET));
});

test('a fresh lock held by another process skips the run; a stale one is taken over', async () => {
	const {store} = await legacy();
	await mkdir(store.vault.dir, {recursive: true, mode: 0o700});
	const lock = path.join(store.vault.dir, 'migrate.lock');
	await writeFile(lock, '1');
	assert.equal(await migrate(store), undefined);
	const old = new Date(Date.now() - 3 * 60_000);
	await utimes(lock, old, old);
	assert.equal((await migrate(store))?.secrets, 1);
});

test('rotate re-encrypts everything under a new key and drops the old one', async () => {
	const {store, privateKey} = await legacy();
	await migrate(store);
	const before = JSON.parse(await readFile(path.join(store.dirs.secrets, 'pay.json'), 'utf8')).fields.token;
	const {log, records} = recordingLog();
	assert.deepEqual(await rotate(store, log), {kid: 2, secrets: 1, keys: 1});
	assert.deepEqual(await store.vault.status(), {state: 'ok', current: 2, kids: [2]});
	assert.equal(await store.secret('pay', 'token'), SECRET);
	assert.ok((await store.privateKey('bot')).equals(privateKey));
	await assert.rejects(store.vault.decrypt(before, secretAad('pay', 'token'), 'pay'), /cannot be decrypted/);
	assert.ok(!JSON.stringify(records).includes(SECRET));
});

test('rotate keeps the old key when something cannot be re-encrypted; reset drops it and makes things usable', async () => {
	const {store} = await legacy();
	await migrate(store);
	await writeFile(path.join(store.dirs.secrets, 'pay.json'), JSON.stringify({v: 2, fields: {token: {v: 1, kid: 1, iv: 'AAAAAAAAAAAAAAAA', ct: 'AA==', tag: 'AAAAAAAAAAAAAAAAAAAAAA=='}}}));
	await assert.rejects(rotate(store), /1 stored entry could not be re-encrypted; the old key is kept/);
	assert.deepEqual((await store.vault.status()).kids, [1, 2]);
	assert.deepEqual(await inventory(store), {encrypted: 1, plaintext: 0, undecryptable: 1});
	assert.deepEqual(await reset(store), {secrets: 1, keys: 0, newKey: false});
	assert.deepEqual(await store.secretNames('pay'), []);
	assert.deepEqual(await rotate(store), {kid: 2, secrets: 0, keys: 1});
});

test('reset after a lost key drops the unreadable entries and the SSH key, and makes a new key', async () => {
	const {store} = await legacy();
	await migrate(store);
	await rm(path.join(store.vault.dir, 'key'));
	await assert.rejects(store.secret('pay', 'token'), /vault key is missing/);
	assert.deepEqual(await inventory(store), {encrypted: 0, plaintext: 0, undecryptable: 2});
	assert.deepEqual(await reset(store), {secrets: 1, keys: 1, newKey: true});
	assert.equal((await store.get('bot')).publicKey, undefined);
	assert.deepEqual(await readdir(store.dirs.keys), []);
	await store.setSecret('pay', 'token', SECRET);
	assert.equal(await store.secret('pay', 'token'), SECRET);
});
