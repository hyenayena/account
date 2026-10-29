import {randomBytes} from 'node:crypto';
import {constants as fsConstants} from 'node:fs';
import {chmod, lstat, mkdir, open, rename, rm, writeFile} from 'node:fs/promises';
import path from 'node:path';
import type {CredentialAccess, Logger} from '../../../src/api.js';
import {KIND_NAME} from './kinds.js';
import {noopLog} from './log.js';

export const GRANTS_FILE = 'grants.json';
const MAX_FILE = 64 * 1024;
// The host's module name rule, capped.
export const MODULE_NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;

export type ModuleGrants = Record<string, CredentialAccess>;
export type GrantTable = Record<string, ModuleGrants>;

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

function parse(text: string): GrantTable | undefined {
	let raw: unknown;
	try {
		raw = JSON.parse(text);
	} catch {
		return undefined;
	}
	if (!isObject(raw) || raw.v !== 1 || !isObject(raw.grants)) return undefined;
	const table: GrantTable = {};
	for (const [module, kinds] of Object.entries(raw.grants)) {
		if (!MODULE_NAME.test(module) || !isObject(kinds)) return undefined;
		const own: ModuleGrants = {};
		for (const [kind, access] of Object.entries(kinds)) {
			if (!KIND_NAME.test(kind) || (access !== 'read' && access !== 'write')) return undefined;
			own[kind] = access;
		}
		table[module] = own;
	}
	return table;
}

/**
 * What the user allowed each module: `grants.json` in the account data dir (`{v: 1, grants: {module: {kind:
 * access}}}`). Re-read when it changes; a file that is not a plain, valid file counts as no grants.
 */
export function createGrants(dataDir: string, log: Logger = noopLog) {
	const file = path.join(dataDir, GRANTS_FILE);
	let cache: {stamp: string; table: GrantTable} | undefined;
	let warned: string | undefined;

	const refuse = (stamp: string): GrantTable => {
		if (warned !== stamp) log.warn('grants file unreadable: no module has credential access');
		warned = stamp;
		cache = {stamp, table: {}};
		return {};
	};

	async function load(): Promise<GrantTable> {
		let st;
		try {
			st = await lstat(file);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
				cache = undefined;
				return {};
			}
			return refuse('lstat');
		}
		const stamp = `${st.ino}:${st.mtimeMs}:${st.size}:${st.mode}`;
		if (cache?.stamp === stamp) return cache.table;
		if (!st.isFile() || st.size > MAX_FILE) return refuse(stamp);
		let text: string;
		try {
			const handle = await open(file, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
			try {
				text = await handle.readFile('utf8');
			} finally {
				await handle.close();
			}
		} catch {
			return refuse(stamp);
		}
		const table = parse(text);
		if (!table) return refuse(stamp);
		cache = {stamp, table};
		return table;
	}

	async function save(table: GrantTable): Promise<void> {
		await mkdir(dataDir, {recursive: true, mode: 0o700});
		await chmod(dataDir, 0o700);
		const sorted: GrantTable = {};
		for (const module of Object.keys(table).sort()) if (Object.keys(table[module]!).length > 0) sorted[module] = table[module]!;
		const tmp = `${file}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
		await writeFile(tmp, JSON.stringify({v: 1, grants: sorted}, null, '\t') + '\n', {mode: 0o600, flag: 'wx'});
		try {
			await rename(tmp, file);
		} catch (error) {
			await rm(tmp, {force: true});
			throw error;
		}
		cache = undefined;
	}

	const copy = (table: GrantTable): GrantTable => Object.fromEntries(Object.entries(table).map(([m, k]) => [m, {...k}]));

	return {
		file,
		all: async (): Promise<GrantTable> => copy(await load()),
		get: async (module: string): Promise<ModuleGrants> => ({...((await load())[module] ?? {})}),
		async allow(module: string, kinds: ModuleGrants): Promise<void> {
			if (!MODULE_NAME.test(module)) throw new Error(`Invalid module name "${module.slice(0, 40)}"`);
			const table = copy(await load());
			table[module] = {...(table[module] ?? {}), ...kinds};
			await save(table);
		},
		/** Without `kinds`, every grant of the module. */
		async revoke(module: string, kinds?: string[]): Promise<string[]> {
			const table = copy(await load());
			const own = table[module] ?? {};
			const removed = Object.keys(own).filter(k => kinds === undefined || kinds.includes(k));
			if (removed.length === 0) return [];
			for (const k of removed) delete own[k];
			table[module] = own;
			await save(table);
			return removed;
		},
		/** Drops the grants of modules that are no longer installed. */
		async prune(installed: string[]): Promise<string[]> {
			const table = copy(await load());
			const gone = Object.keys(table).filter(m => !installed.includes(m));
			if (gone.length === 0) return [];
			for (const m of gone) delete table[m];
			await save(table);
			return gone;
		},
	};
}

export type Grants = ReturnType<typeof createGrants>;
