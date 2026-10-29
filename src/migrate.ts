import {lstat, mkdir, rm, stat, writeFile} from 'node:fs/promises';
import path from 'node:path';
import type {Logger} from '../../../src/api.js';
import {noopLog} from './log.js';
import {secretAad, sshAad} from './vault.js';
import type {SecretEntry, Store} from './store.js';

const LOCK = 'migrate.lock';
const STALE_MS = 2 * 60_000;

const errClass = (error: unknown) => (error instanceof Error ? error.constructor.name : typeof error);

async function withLock<T>(store: Store, fn: () => Promise<T>): Promise<T | undefined> {
	await mkdir(store.vault.dir, {recursive: true, mode: 0o700});
	if (!(await lstat(store.vault.dir)).isDirectory()) throw new Error('The account vault folder is not a directory');
	const lock = path.join(store.vault.dir, LOCK);
	for (let attempt = 0; attempt < 2; attempt++) {
		try {
			await writeFile(lock, String(process.pid), {mode: 0o600, flag: 'wx'});
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
			const age = Date.now() - (await stat(lock).then(s => s.mtimeMs, () => Date.now()));
			if (age < STALE_MS) return undefined;
			await rm(lock, {force: true});
			continue;
		}
		try {
			return await fn();
		} finally {
			await rm(lock, {force: true});
		}
	}
	return undefined;
}

const busy = () => new Error('Another yena process is changing the account vault; try again in a moment');

async function rewriteSecrets(store: Store, name: string, entries: Map<string, SecretEntry>, kid?: number): Promise<boolean> {
	const needs = [...entries.values()].some(e => e.state === 'plain' || (kid !== undefined && e.state === 'encrypted' && e.envelope.kid !== kid));
	if (!needs) return false;
	const fields: Record<string, unknown> = {};
	const expect = new Map<string, string>();
	for (const [field, entry] of entries) {
		if (entry.state === 'bad') fields[field] = entry.raw;
		else if (entry.state === 'encrypted' && (kid === undefined || entry.envelope.kid === kid)) fields[field] = entry.envelope;
		else {
			const value = entry.state === 'plain' ? entry.value : (await store.vault.decrypt(entry.envelope, secretAad(name, field), name)).toString('utf8');
			fields[field] = await store.vault.encrypt(value, secretAad(name, field));
			expect.set(field, value);
		}
	}
	await store.files.replaceSecrets(name, fields, expect);
	return true;
}

async function migrateKey(store: Store, name: string, encrypted: boolean): Promise<void> {
	const plain = await store.files.readPlainKey(name);
	if (!plain) return;
	try {
		let done = false;
		if (encrypted) {
			const existing = await store.privateKey(name).catch(() => undefined);
			done = existing?.equals(plain) ?? false;
			existing?.fill(0);
		}
		if (!done) await store.files.writeEncryptedKey(name, plain);
	} finally {
		plain.fill(0);
	}
	await store.files.removePlainKey(name);
}

export async function migrate(store: Store, log: Logger = noopLog): Promise<{secrets: number; keys: number; failed: number} | undefined> {
	let step = 'lock';
	try {
		return await withLock(store, async () => {
			let secrets = 0;
			let keys = 0;
			let failed = 0;
			step = 'secrets';
			for (const name of await store.files.secretFiles()) {
				const file = await store.files.readSecrets(name);
				if (file.encrypted && ![...file.entries.values()].some(e => e.state === 'plain')) continue;
				try {
					if (await rewriteSecrets(store, name, file.entries)) secrets++;
				} catch (error) {
					failed++;
					log.warn('vault migration failed', {errClass: errClass(error), step});
				}
			}
			step = 'keys';
			for (const k of await store.files.keyFiles()) {
				if (!k.plain) continue;
				try {
					await migrateKey(store, k.name, k.encrypted);
					keys++;
				} catch (error) {
					failed++;
					log.warn('vault migration failed', {errClass: errClass(error), step});
				}
			}
			if (secrets + keys > 0) log.info('vault migrated', {secrets, keys});
			return {secrets, keys, failed};
		});
	} catch (error) {
		log.warn('vault migration failed', {errClass: errClass(error), step});
		return undefined;
	}
}

export type Inventory = {encrypted: number; plaintext: number; undecryptable: number};

export async function inventory(store: Store): Promise<Inventory> {
	const counts: Inventory = {encrypted: 0, plaintext: 0, undecryptable: 0};
	for (const name of await store.files.secretFiles()) {
		for (const state of Object.values(await store.secretStates(name))) {
			if (state === 'ok') counts.encrypted++;
			else if (state === 'plain') counts.plaintext++;
			else counts.undecryptable++;
		}
	}
	for (const k of await store.files.keyFiles()) {
		if (k.plain) counts.plaintext++;
		else if (k.encrypted) {
			const key = await store.privateKey(k.name).catch(() => undefined);
			if (key) counts.encrypted++;
			else counts.undecryptable++;
			key?.fill(0);
		}
	}
	return counts;
}

export async function rotate(store: Store, log: Logger = noopLog): Promise<{kid: number; secrets: number; keys: number}> {
	const result = await withLock(store, async () => {
		const kid = await store.vault.beginRotation();
		let secrets = 0;
		let keys = 0;
		let failed = 0;
		for (const name of await store.files.secretFiles()) {
			try {
				const {entries} = await store.files.readSecrets(name);
				if ([...entries.values()].some(e => e.state === 'bad')) failed++;
				if (await rewriteSecrets(store, name, entries, kid)) secrets++;
			} catch {
				failed++;
			}
		}
		for (const k of await store.files.keyFiles()) {
			try {
				if (k.plain) await migrateKey(store, k.name, k.encrypted);
				else {
					const key = await store.privateKey(k.name);
					try {
						await store.files.writeEncryptedKey(k.name, key);
					} finally {
						key.fill(0);
					}
				}
				keys++;
			} catch {
				failed++;
			}
		}
		if (failed > 0) {
			log.warn('vault rotation incomplete', {failed});
			throw new Error(`${failed} stored entr${failed === 1 ? 'y' : 'ies'} could not be re-encrypted; the old key is kept. Run again, or drop them: account vault reset`);
		}
		await store.vault.finishRotation();
		log.info('vault rotated', {secrets, keys});
		return {kid, secrets, keys};
	});
	if (!result) throw busy();
	return result;
}

export async function reset(store: Store, log: Logger = noopLog): Promise<{secrets: number; keys: number; newKey: boolean}> {
	const result = await withLock(store, async () => {
		let secrets = 0;
		let keys = 0;
		for (const name of await store.files.secretFiles()) {
			const states = await store.secretStates(name);
			const broken = Object.keys(states).filter(f => states[f] === 'broken');
			if (broken.length > 0) await store.files.dropSecrets(name, broken);
			secrets += broken.length;
		}
		for (const k of await store.files.keyFiles()) {
			if (k.plain || !k.encrypted) continue;
			const key = await store.privateKey(k.name).catch(() => undefined);
			if (key) key.fill(0);
			else {
				await store.files.forgetKey(k.name);
				keys++;
			}
		}
		const newKey = await store.vault.discardUnusable();
		const before = await store.vault.status();
		await store.vault.currentKid();
		log.info('vault reset', {secrets, keys, newKey: newKey || before.state === 'none'});
		return {secrets, keys, newKey: newKey || before.state === 'none'};
	});
	if (!result) throw busy();
	return result;
}
