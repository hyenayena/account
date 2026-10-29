import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {mkdir, readFile, rm, stat, symlink, writeFile} from 'node:fs/promises';
import path from 'node:path';
import {test} from 'node:test';
import {createVault, LOCKED_MESSAGE, secretAad, sshAad, type Envelope} from '../src/vault.js';
import {tmp} from './helpers.js';

const mode = async (p: string) => (await stat(p)).mode & 0o777;
const vaultIn = (dir: string, encrypted = false) => createVault(dir, {encryptedDataExists: async () => encrypted});
const VALUE = 'generated-test-value-0123456789';
const keyText = async (dir: string) => readFile(path.join(dir, 'vault', 'key'), 'utf8');
const keyB64 = async (dir: string) => (JSON.parse(await keyText(dir)) as {keys: {key: string}[]}).keys[0]!.key;

const failsClosed = (key: string | undefined, re: RegExp) => (error: Error) => {
	assert.match(error.message, re);
	assert.ok(!error.message.includes(VALUE));
	if (key) assert.ok(!error.message.includes(key));
	return true;
};

test('round trip; a fresh IV for every write; key file 0600 in a 0700 folder', async () => {
	const dir = await tmp();
	const vault = vaultIn(dir);
	const a = await vault.encrypt(VALUE, secretAad('acc', 'token'));
	const b = await vault.encrypt(VALUE, secretAad('acc', 'token'));
	assert.notEqual(a.iv, b.iv);
	assert.notEqual(a.ct, b.ct);
	assert.equal(Buffer.from(a.iv, 'base64').length, 12);
	assert.deepEqual(Object.keys(a).sort(), ['ct', 'iv', 'kid', 'tag', 'v']);
	assert.ok(!JSON.stringify(a).includes(VALUE));
	assert.equal((await vault.decrypt(a, secretAad('acc', 'token'), 'acc')).toString('utf8'), VALUE);
	assert.equal(await mode(path.join(dir, 'vault')), 0o700);
	assert.equal(await mode(path.join(dir, 'vault', 'key')), 0o600);
	assert.deepEqual(await vault.status(), {state: 'ok', current: 1, kids: [1]});
});

test('tampered ciphertext, tag or IV, a moved blob and a bad version are refused with no fallback', async () => {
	const dir = await tmp();
	const vault = vaultIn(dir);
	const env = await vault.encrypt(VALUE, secretAad('acc', 'token'));
	const flip = (b64: string) => {
		const buf = Buffer.from(b64, 'base64');
		buf[0] = buf[0]! ^ 1;
		return buf.toString('base64');
	};
	const bad: [unknown, string][] = [
		[{...env, ct: flip(env.ct)}, secretAad('acc', 'token')],
		[{...env, tag: flip(env.tag)}, secretAad('acc', 'token')],
		[{...env, iv: flip(env.iv)}, secretAad('acc', 'token')],
		[env, secretAad('other', 'token')],
		[env, secretAad('acc', 'password')],
		[env, sshAad('acc')],
		[{...env, v: 2}, secretAad('acc', 'token')],
		[{...env, kid: 9}, secretAad('acc', 'token')],
		[{...env, iv: 'not base64!'}, secretAad('acc', 'token')],
		[VALUE, secretAad('acc', 'token')],
	];
	const key = await keyB64(dir);
	for (const [envelope, aad] of bad) {
		await assert.rejects(vault.decrypt(envelope, aad, 'acc'), failsClosed(key, /^A stored secret of account "acc" cannot be decrypted \(tampered or a different vault key\)$/));
	}
});

test('a wrong key fails closed', async () => {
	const dir = await tmp();
	const env = await vaultIn(dir).encrypt(VALUE, secretAad('acc', 'token'));
	await writeFile(path.join(dir, 'vault', 'key'), JSON.stringify({v: 1, current: 1, keys: [{kid: 1, key: randomBytes(32).toString('base64')}]}));
	const key = await keyB64(dir);
	await assert.rejects(vaultIn(dir, true).decrypt(env, secretAad('acc', 'token'), 'acc'), failsClosed(key, /cannot be decrypted/));
});

test('a missing or corrupt key with encrypted data fails closed, and no new key is made', async () => {
	const dir = await tmp();
	const env: Envelope = await vaultIn(dir).encrypt(VALUE, secretAad('acc', 'token'));
	await rm(path.join(dir, 'vault', 'key'));
	const vault = vaultIn(dir, true);
	await assert.rejects(vault.decrypt(env, secretAad('acc', 'token'), 'acc'), {message: LOCKED_MESSAGE, code: 'VAULT_LOCKED'});
	await assert.rejects(vault.encrypt('new', secretAad('acc', 'token')), {message: LOCKED_MESSAGE});
	await assert.rejects(stat(path.join(dir, 'vault', 'key')), {code: 'ENOENT'});
	await writeFile(path.join(dir, 'vault', 'key'), '{"v":1,');
	await assert.rejects(vault.encrypt('new', secretAad('acc', 'token')), {message: LOCKED_MESSAGE});
	assert.equal(await keyText(dir), '{"v":1,', 'an unusable key file is never overwritten');
	assert.equal((await vault.status()).state, 'unusable');
});

test('a key file that is a symlink, too large or not a file is refused', async () => {
	const dir = await tmp();
	const elsewhere = await tmp();
	await vaultIn(elsewhere).encrypt(VALUE, secretAad('a', 'b'));
	await mkdir(path.join(dir, 'vault'), {mode: 0o700});
	await symlink(path.join(elsewhere, 'vault', 'key'), path.join(dir, 'vault', 'key'));
	await assert.rejects(vaultIn(dir).encrypt(VALUE, secretAad('a', 'b')), {message: LOCKED_MESSAGE});
	await rm(path.join(dir, 'vault', 'key'));
	await writeFile(path.join(dir, 'vault', 'key'), 'x'.repeat(5000));
	await assert.rejects(vaultIn(dir).encrypt(VALUE, secretAad('a', 'b')), {message: LOCKED_MESSAGE});
	await rm(path.join(dir, 'vault', 'key'));
	await mkdir(path.join(dir, 'vault', 'key'));
	await assert.rejects(vaultIn(dir).encrypt(VALUE, secretAad('a', 'b')), {message: LOCKED_MESSAGE});
});

test('two vaults making the first key at once agree on one key (exclusive create)', async () => {
	const dir = await tmp();
	const [a, b] = [vaultIn(dir), vaultIn(dir)];
	const [ea, eb] = await Promise.all([a.encrypt('one', secretAad('x', 'y')), b.encrypt('two', secretAad('x', 'y'))]);
	assert.equal((await vaultIn(dir).decrypt(ea, secretAad('x', 'y'), 'x')).toString(), 'one');
	assert.equal((await vaultIn(dir).decrypt(eb, secretAad('x', 'y'), 'x')).toString(), 'two');
});

test('rotation keeps old envelopes readable until it finishes; unknown kids then fail', async () => {
	const dir = await tmp();
	const vault = vaultIn(dir);
	const old = await vault.encrypt(VALUE, secretAad('a', 'b'));
	assert.equal(await vault.beginRotation(), 2);
	assert.equal(await vault.beginRotation(), 2, 'an unfinished rotation is resumed');
	const fresh = await vault.encrypt(VALUE, secretAad('a', 'b'));
	assert.equal(fresh.kid, 2);
	assert.equal((await vault.decrypt(old, secretAad('a', 'b'), 'a')).toString(), VALUE);
	await vault.finishRotation();
	assert.deepEqual(await vault.status(), {state: 'ok', current: 2, kids: [2]});
	await assert.rejects(vault.decrypt(old, secretAad('a', 'b'), 'a'), /cannot be decrypted/);
});

test('the redactor masks the key once it is loaded', async () => {
	const dir = await tmp();
	const vault = vaultIn(dir);
	await vault.encrypt(VALUE, secretAad('a', 'b'));
	const key = await keyB64(dir);
	assert.equal(vault.redact(`x ${key} y`), 'x [vault key] y');
});
