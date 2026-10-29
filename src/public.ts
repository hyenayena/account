// The account module's public entry: other modules import only this file (through one adapter file of
// their own, with account in their yena.json dependencies). Pure: no host values, no React or Ink.
import path from 'node:path';
import {GRANTS_FILE} from './grants.js';
import {createKinds, KINDS_FILE, missingOf, type Field} from './kinds.js';
import {ACCOUNTS_FILE, createStore, DISABLED_DIR, KEYS_DIR, SECRETS_DIR} from './store.js';
import {VAULT_DIR} from './vault.js';

export type {Field};

/** What another module may know about an account: public fields and which secrets are set. */
export type AccountInfo = {
	name: string;
	kind: string;
	fields: Record<string, string>;
	secrets: string[];
	disabled: boolean;
	ssh: boolean;
	/** Required fields not set, and `a|b` for a one-of group with none set; empty when complete. */
	missing: string[];
};

export type KindInfo = {name: string; fields: Field[]; ssh: boolean; oneOf: string[][]; builtin: boolean};

export type Accounts = {
	kinds(): Promise<KindInfo[]>;
	list(kind?: string): Promise<AccountInfo[]>;
	get(name: string): Promise<AccountInfo>;
};

// Module data dirs are siblings under YENA_DATA, and this module's is "account". Only account knows this.
export const accountDataDirFor = (moduleDataDir: string): string => path.join(path.dirname(moduleDataDir), 'account');

/**
 * Everything in the account data dir an assistant must not reach: all of it except `ssh_config`, which ssh
 * reads from the chat's sandboxed Bash. The vault key and the grants file are named explicitly.
 */
export const deniedPathsFor = (moduleDataDir: string): string[] => {
	const dir = accountDataDirFor(moduleDataDir);
	return [ACCOUNTS_FILE, KINDS_FILE, SECRETS_DIR, KEYS_DIR, DISABLED_DIR, VAULT_DIR, GRANTS_FILE].map(p => path.join(dir, p));
};

/** @deprecated Use `deniedPathsFor`; the same list, kept until the data-root deny replaces both. */
export const secretDirsFor = deniedPathsFor;

/** The accounts, from any module's own data dir. */
export function accountsFor(moduleDataDir: string): Accounts {
	const dir = accountDataDirFor(moduleDataDir);
	const store = createStore(dir);
	const kinds = createKinds(dir);
	const info = async (a: Awaited<ReturnType<typeof store.list>>[number]): Promise<AccountInfo> => {
		const secrets = await store.secretNames(a.name);
		const kind = await kinds.get(a.kind).catch(() => undefined);
		return {
			name: a.name,
			kind: a.kind,
			fields: {...a.fields},
			secrets,
			disabled: a.disabled,
			ssh: a.publicKey !== undefined,
			missing: kind ? missingOf(kind, a, secrets) : [],
		};
	};
	return {
		kinds: async () => (await kinds.list()).map(k => ({...k, fields: k.fields.map(f => ({...f})), oneOf: k.oneOf.map(g => [...g])})),
		list: async kind => Promise.all((await store.list()).filter(a => kind === undefined || a.kind === kind).map(info)),
		get: async name => info(await store.get(name)),
	};
}
