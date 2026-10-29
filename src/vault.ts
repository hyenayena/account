import {createCipheriv, createDecipheriv, randomBytes} from 'node:crypto';
import {constants as fsConstants} from 'node:fs';
import {chmod, link, lstat, mkdir, open, rename, rm, writeFile} from 'node:fs/promises';
import path from 'node:path';

export type Envelope = {v: 1; kid: number; iv: string; ct: string; tag: string};

type KeyEntry = {kid: number; key: Buffer};
type KeyFile = {current: number; keys: KeyEntry[]};

export type VaultStatus = {state: 'none' | 'ok' | 'unusable'; current?: number; kids: number[]};

const MAX_KEY_FILE = 4096;
const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;

export const VAULT_DIR = 'vault';
export const KEY_FILE = 'key';

export const secretAad = (account: string, field: string): string => `account-secret\0${account}\0${field}`;
export const sshAad = (account: string): string => `account-ssh\0${account}`;

export const LOCKED_MESSAGE =
	'The account vault key is missing or does not match; stored secrets cannot be read. Restore the vault folder from a backup, or run: account vault reset (drops the unreadable secrets)';

const lockedError = (): Error => Object.assign(new Error(LOCKED_MESSAGE), {code: 'VAULT_LOCKED'});
const decryptError = (account: string): Error =>
	Object.assign(new Error(`A stored secret of account "${account.slice(0, 40)}" cannot be decrypted (tampered or a different vault key)`), {code: 'VAULT_DECRYPT'});

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

function base64(text: unknown, bytes?: number): Buffer | undefined {
	if (typeof text !== 'string') return undefined;
	const buf = Buffer.from(text, 'base64');
	if (buf.toString('base64') !== text) return undefined;
	if (bytes !== undefined && buf.length !== bytes) return undefined;
	return buf;
}

export const isEnvelope = (v: unknown): v is Envelope =>
	isObject(v) && v.v === 1 && Number.isInteger(v.kid) && typeof v.iv === 'string' && typeof v.ct === 'string' && typeof v.tag === 'string';

function parseKeyFile(text: string): KeyFile | undefined {
	let raw: unknown;
	try {
		raw = JSON.parse(text);
	} catch {
		return undefined;
	}
	if (!isObject(raw) || raw.v !== 1 || !Number.isInteger(raw.current) || !Array.isArray(raw.keys) || raw.keys.length === 0) return undefined;
	const keys: KeyEntry[] = [];
	for (const k of raw.keys) {
		if (!isObject(k) || !Number.isInteger(k.kid) || (k.kid as number) < 1) return undefined;
		const key = base64(k.key, KEY_BYTES);
		if (!key || keys.some(e => e.kid === k.kid)) return undefined;
		keys.push({kid: k.kid as number, key});
	}
	if (!keys.some(k => k.kid === raw.current)) return undefined;
	return {current: raw.current as number, keys};
}

const keyFileText = (file: KeyFile): string =>
	JSON.stringify({v: 1, current: file.current, keys: file.keys.map(k => ({kid: k.kid, key: k.key.toString('base64')}))}) + '\n';

export function createVault(dataDir: string, opts: {encryptedDataExists: () => Promise<boolean>}) {
	const dir = path.join(dataDir, VAULT_DIR);
	const file = path.join(dir, KEY_FILE);
	let cache: {stamp: string; keys: KeyFile} | undefined;
	const seen = new Set<string>();

	const remember = (keys: KeyFile) => {
		for (const k of keys.keys) seen.add(k.key.toString('base64'));
		return keys;
	};

	async function ensureDir(): Promise<void> {
		await mkdir(dataDir, {recursive: true, mode: 0o700});
		await chmod(dataDir, 0o700);
		await mkdir(dir, {recursive: true, mode: 0o700});
		const st = await lstat(dir);
		if (!st.isDirectory()) throw lockedError();
		await chmod(dir, 0o700);
	}

	async function load(): Promise<KeyFile | undefined> {
		try {
			const d = await lstat(dir);
			if (!d.isDirectory()) throw lockedError();
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
			throw error;
		}
		let st;
		try {
			st = await lstat(file);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
			throw lockedError();
		}
		if (!st.isFile() || st.size > MAX_KEY_FILE) throw lockedError();
		const stamp = `${st.ino}:${st.mtimeMs}:${st.size}`;
		if (cache?.stamp === stamp) return cache.keys;
		let text: string;
		try {
			const handle = await open(file, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
			try {
				text = await handle.readFile('utf8');
			} finally {
				await handle.close();
			}
		} catch {
			throw lockedError();
		}
		const keys = parseKeyFile(text);
		if (!keys) throw lockedError();
		cache = {stamp, keys: remember(keys)};
		return keys;
	}

	async function replace(keys: KeyFile): Promise<void> {
		await ensureDir();
		const tmp = path.join(dir, `${KEY_FILE}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`);
		await writeFile(tmp, keyFileText(remember(keys)), {mode: 0o600, flag: 'wx'});
		await rename(tmp, file);
		cache = undefined;
	}

	async function create(): Promise<KeyFile> {
		if (await opts.encryptedDataExists()) throw lockedError();
		await ensureDir();
		const keys: KeyFile = {current: 1, keys: [{kid: 1, key: randomBytes(KEY_BYTES)}]};
		const tmp = path.join(dir, `${KEY_FILE}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`);
		await writeFile(tmp, keyFileText(remember(keys)), {mode: 0o600, flag: 'wx'});
		try {
			await link(tmp, file);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
		} finally {
			await rm(tmp, {force: true});
		}
		const loaded = await load();
		if (!loaded) throw lockedError();
		return loaded;
	}

	const keysForWrite = async (): Promise<KeyFile> => (await load()) ?? (await create());

	async function encrypt(plain: Buffer | string, aad: string): Promise<Envelope> {
		const keys = await keysForWrite();
		const key = keys.keys.find(k => k.kid === keys.current)!;
		const iv = randomBytes(IV_BYTES);
		const cipher = createCipheriv('aes-256-gcm', key.key, iv, {authTagLength: TAG_BYTES});
		cipher.setAAD(Buffer.from(aad, 'utf8'));
		const ct = Buffer.concat([cipher.update(typeof plain === 'string' ? Buffer.from(plain, 'utf8') : plain), cipher.final()]);
		return {v: 1, kid: key.kid, iv: iv.toString('base64'), ct: ct.toString('base64'), tag: cipher.getAuthTag().toString('base64')};
	}

	async function decrypt(envelope: unknown, aad: string, account: string): Promise<Buffer> {
		const keys = await load();
		if (!keys) throw lockedError();
		if (!isEnvelope(envelope)) throw decryptError(account);
		const key = keys.keys.find(k => k.kid === envelope.kid);
		const iv = base64(envelope.iv, IV_BYTES);
		const tag = base64(envelope.tag, TAG_BYTES);
		const ct = base64(envelope.ct);
		if (!key || !iv || !tag || !ct) throw decryptError(account);
		try {
			const decipher = createDecipheriv('aes-256-gcm', key.key, iv, {authTagLength: TAG_BYTES});
			decipher.setAAD(Buffer.from(aad, 'utf8'));
			decipher.setAuthTag(tag);
			return Buffer.concat([decipher.update(ct), decipher.final()]);
		} catch {
			throw decryptError(account);
		}
	}

	async function status(): Promise<VaultStatus> {
		try {
			const keys = await load();
			if (!keys) return {state: 'none', kids: []};
			return {state: 'ok', current: keys.current, kids: keys.keys.map(k => k.kid)};
		} catch {
			return {state: 'unusable', kids: []};
		}
	}

	const currentKid = async (): Promise<number> => (await keysForWrite()).current;

	async function beginRotation(): Promise<number> {
		const keys = await load();
		if (!keys) throw lockedError();
		if (keys.keys.length > 1) return keys.current;
		const kid = Math.max(...keys.keys.map(k => k.kid)) + 1;
		await replace({current: kid, keys: [...keys.keys, {kid, key: randomBytes(KEY_BYTES)}]});
		return kid;
	}

	async function finishRotation(): Promise<void> {
		const keys = await load();
		if (!keys) throw lockedError();
		await replace({current: keys.current, keys: keys.keys.filter(k => k.kid === keys.current)});
	}

	async function discardUnusable(): Promise<boolean> {
		if ((await status()).state !== 'unusable') return false;
		try {
			const d = await lstat(dir);
			if (!d.isDirectory()) await rm(dir, {force: true});
			else await rename(file, path.join(dir, `${KEY_FILE}.unusable`));
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
		}
		cache = undefined;
		return true;
	}

	const redact = (text: string): string => {
		let out = text;
		for (const k of seen) out = out.split(k).join('[vault key]');
		return out;
	};

	return {dir, encrypt, decrypt, status, currentKid, beginRotation, finishRotation, discardUnusable, redact};
}

export type Vault = ReturnType<typeof createVault>;

