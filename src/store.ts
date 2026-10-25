import {execFile} from 'node:child_process';
import {existsSync, readFileSync} from 'node:fs';
import {chmod, mkdir, readFile, rename, rm, writeFile} from 'node:fs/promises';
import path from 'node:path';
import type {Kind} from './kinds.js';

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

export const NAME = /^[a-z0-9][a-z0-9_-]{0,31}$/;
const LOGIN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const EMAIL = /^[^\s'"<>@]{1,64}@[^\s'"<>@]{1,190}$/;
const MAX_VALUE = 1024;
const CONTROL = new RegExp('[\\u0000-\\u001f\\u007f-\\u009f]');
const MAX_SECRET = 8192;
const KEYGEN_TIMEOUT_MS = 15_000;

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
		if (key === 'email' && !EMAIL.test(value)) throw new Error('Invalid email');
	}
	return fields;
}

type Run = (file: string, args: string[]) => Promise<string>;

const runFile: Run = (file, args) =>
	new Promise((resolve, reject) => {
		execFile(file, args, {timeout: KEYGEN_TIMEOUT_MS, maxBuffer: 64 * 1024}, (error, stdout) => {
			// stderr is left out of the message; ssh-keygen prints no key material anyway.
			if (error) reject(new Error(`${path.basename(file)} failed (${error.code ?? error.signal ?? 'error'})`));
			else resolve(stdout);
		});
	});

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

async function writePrivate(file: string, text: string): Promise<void> {
	const tmp = `${file}.${process.pid}.tmp`;
	await writeFile(tmp, text, {mode: 0o600});
	await rename(tmp, file);
}

export function createStore(dataDir: string, run: Run = runFile) {
	const file = path.join(dataDir, 'accounts.json');
	const keysDir = path.join(dataDir, 'keys');
	const secretsDir = path.join(dataDir, 'secrets');
	const keyPath = (name: string) => path.join(keysDir, checkName(name));
	const secretsPath = (name: string) => path.join(secretsDir, `${checkName(name)}.json`);
	const disabledPath = (name: string) => path.join(dataDir, 'disabled', checkName(name));

	async function read(): Promise<Stored[]> {
		try {
			return parseAccounts(JSON.parse(await readFile(file, 'utf8')));
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
			throw new Error(`Failed to read accounts.json: ${(error as Error).message}`);
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

	/** For a kind with SSH (unless `ssh: false`), generates an ed25519 key pair; only the public half is ever read. */
	async function add(input: {name: string; kind: Kind; fields?: Record<string, string>; ssh?: boolean}, now = Date.now()): Promise<Account> {
		const name = checkName(input.name);
		const fields = checkFields(input.kind, input.fields ?? {});
		if (input.ssh === true && !input.kind.ssh) throw new Error(`Kind "${input.kind.name}" has no SSH key`);
		const accounts = await read();
		if (accounts.some(a => a.name === name)) throw new Error(`Account "${name}" already exists`);
		let ssh: {publicKey: string; fingerprint: string} | undefined;
		if (input.kind.ssh && input.ssh !== false) {
			await mkdir(keysDir, {recursive: true, mode: 0o700});
			await chmod(dataDir, 0o700);
			await chmod(keysDir, 0o700);
			const key = keyPath(name);
			await rm(key, {force: true});
			await rm(`${key}.pub`, {force: true});
			await run('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', fields.email ?? `yena-${name}`, '-f', key]);
			await chmod(key, 0o600);
			const publicKey = (await readFile(`${key}.pub`, 'utf8')).trim();
			const fingerprint = (await run('ssh-keygen', ['-l', '-E', 'sha256', '-f', `${key}.pub`])).trim().split(/\s+/)[1] ?? '';
			ssh = {publicKey, fingerprint};
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

	async function readSecrets(name: string): Promise<Record<string, string>> {
		try {
			const raw = JSON.parse(await readFile(secretsPath(name), 'utf8')) as unknown;
			if (!raw || typeof raw !== 'object') return {};
			return Object.fromEntries(Object.entries(raw).filter((e): e is [string, string] => typeof e[1] === 'string'));
		} catch {
			return {};
		}
	}

	/** Names of the secret fields that hold a value; never the values. */
	const secretNames = async (name: string): Promise<string[]> => Object.keys(await readSecrets(name)).sort();

	async function setSecret(name: string, field: string, value: string | undefined): Promise<void> {
		const account = await get(name);
		if (value !== undefined && (value === '' || value.length > MAX_SECRET)) throw new Error('A secret is 1 to 8192 characters');
		const secrets = await readSecrets(account.name);
		if (value === undefined) delete secrets[field];
		else secrets[field] = value;
		await mkdir(secretsDir, {recursive: true, mode: 0o700});
		await chmod(secretsDir, 0o700);
		await writePrivate(secretsPath(account.name), JSON.stringify(secrets) + '\n');
	}

	/** A secret for in-process use by modules; undefined when unset or the account is disabled. */
	async function secret(name: string, field: string): Promise<string | undefined> {
		if (isDisabled(checkName(name))) return undefined;
		return (await readSecrets(name))[field];
	}

	async function allSecretValues(): Promise<string[]> {
		const values: string[] = [];
		for (const a of await read()) values.push(...Object.values(await readSecrets(a.name)));
		return values;
	}

	async function setDisabled(name: string, disabled: boolean): Promise<void> {
		const account = await get(name);
		const markers = [disabledPath(account.name), ...(account.publicKey ? [`${keyPath(account.name)}.disabled`] : [])];
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
		const key = keyPath(name);
		for (const p of [key, `${key}.pub`, `${key}.disabled`, secretsPath(name), disabledPath(name)]) await rm(p, {force: true});
	}

	const usesKind = async (kind: string) => (await read()).some(a => a.kind === kind);

	return {list, listSync, get, add, setFields, secretNames, setSecret, secret, allSecretValues, setDisabled, remove, usesKind, keyPath, dirs: {secrets: secretsDir, keys: keysDir}};
}

export type Store = ReturnType<typeof createStore>;
