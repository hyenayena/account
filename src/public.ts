import path from 'node:path';
import {GRANTS_FILE} from './grants.js';
import {createKinds, KINDS_FILE, missingOf, type Field} from './kinds.js';
import {ACCOUNTS_FILE, createStore, DISABLED_DIR, KEYS_DIR, SECRETS_DIR} from './store.js';
import {VAULT_DIR} from './vault.js';

export type {Field};

export type AccountInfo = {
	name: string;
	kind: string;
	fields: Record<string, string>;
	secrets: string[];
	disabled: boolean;
	ssh: boolean;
	missing: string[];
};

export type KindInfo = {name: string; fields: Field[]; ssh: boolean; oneOf: string[][]; builtin: boolean};

export type Accounts = {
	kinds(): Promise<KindInfo[]>;
	list(kind?: string): Promise<AccountInfo[]>;
	get(name: string): Promise<AccountInfo>;
};

export const accountDataDirFor = (moduleDataDir: string): string => path.join(path.dirname(moduleDataDir), 'account');

export const deniedPathsFor = (moduleDataDir: string): string[] => {
	const dir = accountDataDirFor(moduleDataDir);
	return [ACCOUNTS_FILE, KINDS_FILE, SECRETS_DIR, KEYS_DIR, DISABLED_DIR, VAULT_DIR, GRANTS_FILE].map(p => path.join(dir, p));
};

export const secretDirsFor = deniedPathsFor;

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
