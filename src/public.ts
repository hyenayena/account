// The account module's public entry: other modules import only this file (through one adapter file of
// their own, with account in their yena.json dependencies). Pure: no host values, no React or Ink.
import path from 'node:path';
import {createKinds, missingOf, type Field} from './kinds.js';
import {createStore} from './store.js';

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
	/**
	 * A secret value for in-process use (an API call, a child's environment). Undefined when unset or
	 * the account is disabled. Never print, log or return it to an assistant; register it with
	 * `log.addRedactor` if it may end up in text.
	 */
	secret(name: string, field: string): Promise<string | undefined>;
};

// Module data dirs are siblings under YENA_DATA, and this module's is "account". Only account knows this.
export const accountDataDirFor = (moduleDataDir: string): string => path.join(path.dirname(moduleDataDir), 'account');

/** Directories that hold credentials; a policy that guards an assistant denies everything in them. */
export const secretDirsFor = (moduleDataDir: string): string[] => {
	const dir = accountDataDirFor(moduleDataDir);
	return [path.join(dir, 'secrets'), path.join(dir, 'keys')];
};

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
		secret: (name, field) => store.secret(name, field),
	};
}
