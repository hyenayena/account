import {randomBytes} from 'node:crypto';
import {constants as fsConstants, existsSync, readFileSync} from 'node:fs';
import {chmod, mkdir, open, readdir, readFile, rename, rm, writeFile} from 'node:fs/promises';
import path from 'node:path';
import type {Logger} from '../../../src/api.js';
import {createKinds, type Kind} from './kinds.js';
import {noopLog} from './log.js';
import {generateEd25519} from './openssh.js';
import {checkSecret, secretLeaves} from './validate.js';
import {createVault, isEnvelope, secretAad, sshAad, type Envelope} from './vault.js';

export type Account = {
	name: string;
	kind: string;
	// Public fields only; secrets are never part of an Account.
	fields: Record<string, string>;
	publicKey?: string;
	fingerprint?: string;
	createdAt: number;
	disabled: boolean;
};

type Stored = Omit<Account, 'disabled'>;
type AccountsFile = {v: 2; accounts: Stored[]};

export const ACCOUNTS_FILE = 'accounts.json';
export const SECRETS_DIR = 'secrets';
export const KEYS_DIR = 'keys';
export const DISABLED_DIR = 'disabled';

export const NAME = /^[a-z0-9][a-z0-9_-]{0,31}$/;
const LOGIN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const EMAIL = /^[^\s'"<>@]{1,64}@[^\s'"<>@]{1,190}$/;
const MAX_VALUE = 1024;
const CONTROL = new RegExp('[\\u0000-\\u001f\\u007f-\\u009f]');
const LOGIN_METHODS = ['claude.ai', 'console'];

export function checkName(name: string | undefined): string {
	if (!name) throw new Error('Specify the account name');
	if (!NAME.test(name)) throw new Error(`Invalid account name "${name.slice(0, 40)}": use a-z, 0-9, "-" and "_", at most 32 characters`);
	return name;
}

/** Checks public values against the kind; github's login and email have their own shapes. */
export function checkFields(kind: Kind, fields: Record<string, string>): Record<string, string> {
	for (const [key, value] of Object.entries(fields)) {
		const field = kind.fields.find(f => f.key === key);
		if (!field) throw new Error(`Kind "${kind.name}" has no field "${key.slice(0, 40)}" (fields: ${kind.fields.map(f => f.key).join(', ')})`);
		if (field.secret) throw new Error(`"${key}" is secret and is never typed in a command line. Enter it with: account secret <name> ${key}`);
		if (value === '' || value.length > MAX_VALUE || CONTROL.test(value)) throw new Error(`Invalid value for "${key}"`);
		if (kind.name === 'github' && key === 'login' && !LOGIN.test(value)) throw new Error('Invalid login: letters, digits and "-", at most 39 characters');
		if (kind.name === 'claude-login' && key === 'method' && !LOGIN_METHODS.includes(value)) throw new Error(`Invalid method: ${LOGIN_METHODS.join(' or ')}`);
		if (key === 'email' && !EMAIL.test(value)) throw new Error('Invalid email');
	}
	return fields;
}

const validStored = (a: unknown): a is Record<string, unknown> & {name: string} => {
	const r = a as {name?: unknown} | null;
	return typeof r?.name === 'string' && NAME.test(r.name);
};

// Version 1 (0.1.0) had only GitHub accounts with login and email at the top level.
function normalize(raw: Record<string, unknown> & {name: string}): Stored {
	const fields: Record<string, string> = {};
	const source = raw.fields && typeof raw.fields === 'object' ? (raw.fields as Record<string, unknown>) : {login: raw.login, email: raw.email};
	for (const [k, v] of Object.entries(source)) if (typeof v === 'string') fields[k] = v;
	return {
		name: raw.name,
		kind: typeof raw.kind === 'string' ? raw.kind : 'github',
		fields,
		...(typeof raw.publicKey === 'string' && {publicKey: raw.publicKey}),
		...(typeof raw.fingerprint === 'string' && {fingerprint: raw.fingerprint}),
		createdAt: typeof raw.createdAt === 'number' ? raw.createdAt : 0,
	};
}

const parseAccounts = (raw: unknown): Stored[] => {
	const accounts = (raw as {accounts?: unknown} | null)?.accounts;
	return Array.isArray(accounts) ? accounts.filter(validStored).map(normalize) : [];
};

/** One secret field as stored: encrypted, plaintext from before 0.6.0, or something that is neither. */
export type SecretEntry = {state: 'encrypted'; envelope: Envelope} | {state: 'plain'; value: string} | {state: 'bad'; raw: unknown};
export type SecretsFile = {encrypted: boolean; entries: Map<string, SecretEntry>};

/** `{v: 2, fields: {field: envelope}}`; a file without `v: 2` is the plaintext `{field: value}` of 0.5.0. */
export function decodeSecrets(text: string): SecretsFile {
	let raw: unknown;
	try {
		raw = JSON.parse(text);
	} catch {
		return {encrypted: false, entries: new Map()};
	}
	const entries = new Map<string, SecretEntry>();
	if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {encrypted: false, entries};
	const r = raw as Record<string, unknown>;
	if (r.v === 2 && r.fields && typeof r.fields === 'object' && !Array.isArray(r.fields)) {
		for (const [k, v] of Object.entries(r.fields)) entries.set(k, isEnvelope(v) ? {state: 'encrypted', envelope: v} : {state: 'bad', raw: v});
		return {encrypted: true, entries};
	}
	for (const [k, v] of Object.entries(r)) if (typeof v === 'string') entries.set(k, {state: 'plain', value: v});
	return {encrypted: false, entries};
}

export const encodeSecrets = (fields: Record<string, unknown>): string => JSON.stringify({v: 2, fields}) + '\n';

/** Reads a file only when it is not a symlink; undefined when it does not exist. */
export async function readPrivate(file: string): Promise<Buffer | undefined> {
	let handle;
	try {
		handle = await open(file, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
		throw error;
	}
	try {
		return await handle.readFile();
	} finally {
		await handle.close();
	}
}

const tmpName = (file: string) => `${file}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;

/** Writes a temp file next to `file` (exclusive, 0600) and returns its path; the caller renames it. */
export async function writeTemp(file: string, data: string | Buffer, mode = 0o600): Promise<string> {
	const tmp = tmpName(file);
	await writeFile(tmp, data, {mode, flag: 'wx'});
	return tmp;
}

async function writePrivate(file: string, data: string | Buffer, mode = 0o600): Promise<void> {
	await rename(await writeTemp(file, data, mode), file);
}

const sameBytes = (a: Buffer | string, b: Buffer | string) => Buffer.from(a).equals(Buffer.from(b));

export type SecretState = 'ok' | 'plain' | 'broken';

export function createStore(dataDir: string, opts: {log?: Logger} = {}) {
	const log = opts.log ?? noopLog;
	const file = path.join(dataDir, ACCOUNTS_FILE);
	const keysDir = path.join(dataDir, KEYS_DIR);
	const secretsDir = path.join(dataDir, SECRETS_DIR);
	const kinds = createKinds(dataDir);
	const keyBase = (name: string) => path.join(keysDir, checkName(name));
	const encKeyPath = (name: string) => `${keyBase(name)}.enc`;
	const secretsPath = (name: string) => path.join(secretsDir, `${checkName(name)}.json`);
	const disabledPath = (name: string) => path.join(dataDir, DISABLED_DIR, checkName(name));

	async function encryptedDataExists(): Promise<boolean> {
		for (const entry of await readdir(keysDir).catch(() => [] as string[])) if (entry.endsWith('.enc')) return true;
		for (const entry of await readdir(secretsDir).catch(() => [] as string[])) {
			if (!entry.endsWith('.json')) continue;
			const data = await readPrivate(path.join(secretsDir, entry)).catch(() => undefined);
			const decoded = data && decodeSecrets(data.toString('utf8'));
			if (decoded && decoded.encrypted && decoded.entries.size > 0) return true;
		}
		return false;
	}

	const vault = createVault(dataDir, {encryptedDataExists});

	async function read(): Promise<Stored[]> {
		try {
			return parseAccounts(JSON.parse(await readFile(file, 'utf8')));
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
			throw new Error(`Failed to read ${ACCOUNTS_FILE}: ${(error as Error).message}`);
		}
	}

	async function write(accounts: Stored[]): Promise<void> {
		await mkdir(dataDir, {recursive: true, mode: 0o700});
		await chmod(dataDir, 0o700);
		const data: AccountsFile = {v: 2, accounts};
		await writePrivate(file, JSON.stringify(data, null, '\t') + '\n');
	}

	// A disabled account has a marker in disabled/ and, for SSH, next to its key, where ssh-as looks.
	const isDisabled = (name: string) => existsSync(disabledPath(name));

	async function list(): Promise<Account[]> {
		return (await read()).map(a => ({...a, disabled: isDisabled(a.name)}));
	}

	// The settings screen collects its tabs synchronously.
	function listSync(): Account[] {
		try {
			return parseAccounts(JSON.parse(readFileSync(file, 'utf8'))).map(a => ({...a, disabled: isDisabled(a.name)}));
		} catch {
			return [];
		}
	}

	async function get(name: string): Promise<Account> {
		const account = (await list()).find(a => a.name === checkName(name));
		if (!account) throw new Error(`Account "${name}" does not exist. See: account list`);
		return account;
	}

	async function ensureKeysDir(): Promise<void> {
		await mkdir(keysDir, {recursive: true, mode: 0o700});
		await chmod(dataDir, 0o700);
		await chmod(keysDir, 0o700);
	}

	/** Encrypts a private key to `<name>.enc`: written aside, read back and compared, then renamed in. */
	async function writeEncryptedKey(name: string, privateKey: Buffer): Promise<void> {
		await ensureKeysDir();
		const target = encKeyPath(name);
		const tmp = await writeTemp(target, JSON.stringify(await vault.encrypt(privateKey, sshAad(name))) + '\n');
		try {
			const back = await vault.decrypt(JSON.parse(await readFile(tmp, 'utf8')), sshAad(name), name);
			const same = back.equals(privateKey);
			back.fill(0);
			if (!same) throw new Error('The encrypted SSH key did not read back the same');
			await rename(tmp, target);
		} catch (error) {
			await rm(tmp, {force: true});
			throw error;
		}
	}

	/** For a kind with SSH (unless `ssh: false`), an ed25519 key pair made in memory; the private half is stored encrypted only. */
	async function add(input: {name: string; kind: Kind; fields?: Record<string, string>; ssh?: boolean}, now = Date.now()): Promise<Account> {
		const name = checkName(input.name);
		const fields = checkFields(input.kind, input.fields ?? {});
		if (input.ssh === true && !input.kind.ssh) throw new Error(`Kind "${input.kind.name}" has no SSH key`);
		const accounts = await read();
		if (accounts.some(a => a.name === name)) throw new Error(`Account "${name}" already exists`);
		let ssh: {publicKey: string; fingerprint: string} | undefined;
		if (input.kind.ssh && input.ssh !== false) {
			await ensureKeysDir();
			for (const p of [keyBase(name), encKeyPath(name), `${keyBase(name)}.pub`]) await rm(p, {force: true});
			const key = generateEd25519(fields.email ?? `yena-${name}`);
			try {
				await writeEncryptedKey(name, key.privateKey);
			} finally {
				key.privateKey.fill(0);
			}
			await writePrivate(`${keyBase(name)}.pub`, key.publicKey + '\n', 0o644);
			ssh = {publicKey: key.publicKey, fingerprint: key.fingerprint};
		}
		const stored: Stored = {name, kind: input.kind.name, fields, ...ssh, createdAt: now};
		await write([...accounts, stored]);
		return {...stored, disabled: false};
	}

	async function setFields(name: string, kind: Kind, fields: Record<string, string>): Promise<Account> {
		checkFields(kind, fields);
		const accounts = await read();
		const i = accounts.findIndex(a => a.name === checkName(name));
		if (i === -1) throw new Error(`Account "${name}" does not exist. See: account list`);
		accounts[i] = {...accounts[i]!, fields: {...accounts[i]!.fields, ...fields}};
		await write(accounts);
		return {...accounts[i]!, disabled: isDisabled(name)};
	}

	async function readSecrets(name: string): Promise<SecretsFile> {
		try {
			const data = await readPrivate(secretsPath(name));
			return data ? decodeSecrets(data.toString('utf8')) : {encrypted: false, entries: new Map()};
		} catch {
			return {encrypted: false, entries: new Map()};
		}
	}

	const decryptEntry = async (name: string, field: string, entry: SecretEntry): Promise<string> => {
		if (entry.state === 'plain') return entry.value;
		return (await vault.decrypt(entry.state === 'encrypted' ? entry.envelope : entry.raw, secretAad(name, field), name)).toString('utf8');
	};

	/** Names of the secret fields that hold a value; never the values, and no key needed. */
	const secretNames = async (name: string): Promise<string[]> => [...(await readSecrets(name)).entries.keys()].sort();

	/** Per set secret field: readable, still plaintext (not migrated yet), or not decryptable. */
	async function secretStates(name: string): Promise<Record<string, SecretState>> {
		const states: Record<string, SecretState> = {};
		for (const [field, entry] of (await readSecrets(name)).entries) {
			if (entry.state === 'plain') states[field] = 'plain';
			else states[field] = await decryptEntry(name, field, entry).then(() => 'ok' as const, () => 'broken' as const);
		}
		return states;
	}

	/**
	 * Writes the whole secrets file encrypted: the plaintext fields of 0.5.0 are encrypted on the way, fields
	 * that cannot be decrypted are kept as they are. Read-modify-write is not locked across processes.
	 */
	async function setSecret(name: string, field: string, value: string | undefined): Promise<void> {
		const account = await get(name);
		const kind = await kinds.get(account.kind).catch(() => undefined);
		if (value !== undefined) checkSecret(kind, field, value);
		const {entries} = await readSecrets(account.name);
		const out: Record<string, unknown> = {};
		for (const [k, entry] of entries) {
			if (k === field) continue;
			if (entry.state === 'encrypted') out[k] = entry.envelope;
			else if (entry.state === 'bad') out[k] = entry.raw;
			else out[k] = await vault.encrypt(entry.value, secretAad(account.name, k));
		}
		if (value !== undefined) out[field] = await vault.encrypt(value, secretAad(account.name, field));
		await mkdir(secretsDir, {recursive: true, mode: 0o700});
		await chmod(secretsDir, 0o700);
		await writePrivate(secretsPath(account.name), encodeSecrets(out));
	}

	/** A secret for in-process use; undefined when unset or the account is disabled; throws when it cannot be decrypted. */
	async function secret(name: string, field: string): Promise<string | undefined> {
		if (isDisabled(checkName(name))) return undefined;
		const entry = (await readSecrets(name)).entries.get(field);
		return entry ? decryptEntry(name, field, entry) : undefined;
	}

	/** Every stored secret and the long string leaves of JSON ones, for the log redactor; undecryptable ones are skipped. */
	async function allSecretValues(): Promise<string[]> {
		const values: string[] = [];
		let skipped = 0;
		for (const a of await read()) {
			for (const [field, entry] of (await readSecrets(a.name)).entries) {
				try {
					const value = await decryptEntry(a.name, field, entry);
					values.push(value, ...secretLeaves(value));
				} catch {
					skipped++;
				}
			}
		}
		if (skipped > 0) log.warn('secrets skipped by the redactor', {count: skipped});
		return values;
	}

	/** The private SSH key, decrypted in memory (a plaintext key not migrated yet is read as it is). The caller wipes it. */
	async function privateKey(name: string): Promise<Buffer> {
		const enc = await readPrivate(encKeyPath(name));
		if (enc) {
			let envelope: unknown;
			try {
				envelope = JSON.parse(enc.toString('utf8'));
			} catch {
				envelope = undefined;
			}
			return vault.decrypt(envelope, sshAad(name), name);
		}
		const plain = await readPrivate(keyBase(name));
		if (plain) return plain;
		throw new Error(`Account "${name}" has no SSH key file`);
	}

	async function setDisabled(name: string, disabled: boolean): Promise<void> {
		const account = await get(name);
		const markers = [disabledPath(account.name), ...(account.publicKey ? [`${keyBase(account.name)}.disabled`] : [])];
		for (const marker of markers) {
			if (disabled) {
				await mkdir(path.dirname(marker), {recursive: true, mode: 0o700});
				await writeFile(marker, '', {mode: 0o600});
			} else await rm(marker, {force: true});
		}
	}

	async function remove(name: string): Promise<void> {
		await get(name);
		await write((await read()).filter(a => a.name !== name));
		const key = keyBase(name);
		for (const p of [key, `${key}.enc`, `${key}.pub`, `${key}.disabled`, secretsPath(name), disabledPath(name)]) await rm(p, {force: true});
	}

	const usesKind = async (kind: string) => (await read()).some(a => a.kind === kind);

	/** Names that have a secrets file, and the SSH key files in the keys folder, for migration and the vault commands. */
	async function secretFiles(): Promise<string[]> {
		const entries = await readdir(secretsDir).catch(() => [] as string[]);
		return entries.filter(e => e.endsWith('.json') && NAME.test(e.slice(0, -5))).map(e => e.slice(0, -5));
	}

	async function keyFiles(): Promise<{name: string; encrypted: boolean; plain: boolean}[]> {
		const entries = new Set(await readdir(keysDir).catch(() => [] as string[]));
		const names = new Set<string>();
		for (const e of entries) {
			const base = e.endsWith('.enc') ? e.slice(0, -4) : e;
			if (NAME.test(base) && (e === base || e.endsWith('.enc'))) names.add(base);
		}
		return [...names].sort().map(name => ({name, encrypted: entries.has(`${name}.enc`), plain: entries.has(name)}));
	}

	/**
	 * Replaces a secrets file with `fields` (envelopes, or kept raw entries): written aside, read back, every
	 * field in `expect` decrypted and compared byte for byte, then renamed over the old file.
	 */
	async function replaceSecrets(name: string, fields: Record<string, unknown>, expect: Map<string, string>): Promise<void> {
		const target = secretsPath(name);
		const tmp = await writeTemp(target, encodeSecrets(fields));
		try {
			const back = decodeSecrets(await readFile(tmp, 'utf8'));
			for (const [field, value] of expect) {
				const entry = back.entries.get(field);
				if (!entry || entry.state !== 'encrypted' || !sameBytes(await decryptEntry(name, field, entry), value)) {
					throw new Error('An encrypted secret did not read back the same');
				}
			}
			await rename(tmp, target);
		} catch (error) {
			await rm(tmp, {force: true});
			throw error;
		}
	}

	/** Drops an SSH key that cannot be used any more: its files and the public half in accounts.json. */
	async function forgetKey(name: string): Promise<void> {
		for (const p of [keyBase(name), encKeyPath(name), `${keyBase(name)}.pub`, `${keyBase(name)}.disabled`]) await rm(p, {force: true});
		const accounts = await read();
		const i = accounts.findIndex(a => a.name === name);
		if (i !== -1) {
			const {publicKey: _publicKey, fingerprint: _fingerprint, ...rest} = accounts[i]!;
			accounts[i] = rest;
			await write(accounts);
		}
	}

	const removePlainKey = (name: string) => rm(keyBase(name), {force: true});

	/** Removes fields of an encrypted secrets file without decrypting the others. */
	async function dropSecrets(name: string, drop: string[]): Promise<void> {
		const file = await readSecrets(name);
		if (!file.encrypted) throw new Error('Only an encrypted secrets file drops fields this way');
		const out: Record<string, unknown> = {};
		for (const [k, entry] of file.entries) {
			if (drop.includes(k)) continue;
			out[k] = entry.state === 'encrypted' ? entry.envelope : entry.state === 'bad' ? entry.raw : undefined;
		}
		if (Object.keys(out).length === 0) await rm(secretsPath(name), {force: true});
		else await writePrivate(secretsPath(name), encodeSecrets(out));
	}

	return {
		list,
		listSync,
		get,
		add,
		setFields,
		secretNames,
		secretStates,
		setSecret,
		secret,
		allSecretValues,
		privateKey,
		setDisabled,
		remove,
		usesKind,
		vault,
		dirs: {secrets: secretsDir, keys: keysDir},
		files: {secretFiles, keyFiles, readSecrets, replaceSecrets, dropSecrets, writeEncryptedKey, removePlainKey, forgetKey, readPlainKey: (name: string) => readPrivate(keyBase(name))},
	};
}

export type Store = ReturnType<typeof createStore>;
