import type {CredentialAccess, CredentialAccount, CredentialCaller, CredentialProvider, Logger} from '../../../src/api.js';
import type {Grants} from './grants.js';
import {missingOf, type Kinds} from './kinds.js';
import type {Account, Store} from './store.js';

type Op = 'grants' | 'list' | 'read' | 'write' | 'create' | 'remove';
type Outcome = 'ok' | 'denied' | 'missing' | 'error';

const rank = (a: CredentialAccess | undefined) => (a === 'write' ? 2 : a === 'read' ? 1 : 0);
const min = (a: CredentialAccess | undefined, b: CredentialAccess | undefined): CredentialAccess | undefined => (rank(a) <= rank(b) ? a : b);

const declaredOf = (caller: CredentialCaller, kind: string): CredentialAccess | undefined =>
	Object.prototype.hasOwnProperty.call(caller.declared, kind) ? caller.declared[kind] : undefined;

const hint = (module: string) => `Allow it (only you can, not an assistant): account grant ${module}`;

class Denied extends Error {
	readonly code = 'CREDENTIAL_ACCESS';
}
class Undeclared extends Error {}
class Missing extends Error {}

const undeclared = (module: string, kind: string) => new Undeclared(`${module} did not declare credentials of kind "${kind.slice(0, 40)}" in yena.json`);

/**
 * The credential store as other modules see it through `host.credentials`. Every call is checked against
 * the caller: effective access to a kind is the lower of what its yena.json declares and what the user
 * granted (`write` includes read, create and remove). Each call leaves one audit record, metadata only.
 */
export function createProvider(deps: {store: Store; kinds: Kinds; grants: Grants; log: Logger; onSecretsChanged?: () => void}): CredentialProvider {
	const {store, kinds, grants, log} = deps;

	async function accessTo(caller: CredentialCaller, kind: string): Promise<CredentialAccess | undefined> {
		const declared = declaredOf(caller, kind);
		if (!declared) return undefined;
		return min(declared, (await grants.get(caller.module))[kind]);
	}

	async function require(caller: CredentialCaller, kind: string, need: CredentialAccess): Promise<void> {
		if (!declaredOf(caller, kind)) throw undeclared(caller.module, kind);
		if (rank(await accessTo(caller, kind)) < rank(need)) {
			throw new Denied(`${caller.module} may not ${need === 'read' ? 'read' : 'change'} credentials of kind "${kind}". ${hint(caller.module)}`);
		}
	}

	/** Refuses before the store is read when the caller may not do `need` with any kind at all. */
	async function requireAny(caller: CredentialCaller, need: CredentialAccess): Promise<void> {
		const declared = Object.keys(caller.declared);
		if (declared.length === 0) throw new Undeclared(`${caller.module} did not declare any credentials in yena.json`);
		for (const kind of declared) if (rank(await accessTo(caller, kind)) >= rank(need)) return;
		throw new Denied(`${caller.module} may not ${need === 'read' ? 'read' : 'change'} credentials. ${hint(caller.module)}`);
	}

	async function audited<T>(caller: CredentialCaller, op: Op, meta: {kind?: string; account?: string}, fn: () => Promise<T>): Promise<T> {
		const record = (outcome: Outcome, error?: unknown) =>
			log.info('credential access', {
				module: caller.module,
				op,
				...(meta.kind !== undefined && {kind: meta.kind.slice(0, 40)}),
				...(meta.account !== undefined && {account: meta.account.slice(0, 40)}),
				outcome,
				...(error !== undefined && {errClass: error instanceof Error ? error.constructor.name : typeof error}),
			});
		try {
			const result = await fn();
			record('ok');
			return result;
		} catch (error) {
			if (error instanceof Denied || error instanceof Undeclared) record('denied');
			else if (error instanceof Missing) record('missing');
			else record('error', error);
			throw error;
		}
	}

	async function account(name: string): Promise<Account> {
		try {
			return await store.get(name);
		} catch (error) {
			throw new Missing((error as Error).message);
		}
	}

	async function info(a: Account): Promise<CredentialAccount> {
		const secrets = await store.secretNames(a.name);
		const kind = await kinds.get(a.kind).catch(() => undefined);
		return {
			name: a.name,
			kind: a.kind,
			fields: {...a.fields},
			secrets,
			disabled: a.disabled,
			missing: kind ? missingOf(kind, a, secrets) : [],
		};
	}

	async function secretField(a: Account, field: string): Promise<void> {
		const kind = await kinds.get(a.kind);
		if (!kind.fields.some(f => f.key === field && f.secret)) throw new Error(`Kind "${kind.name}" has no secret field "${field.slice(0, 40)}"`);
	}

	return {
		grants: caller =>
			audited(caller, 'grants', {}, async () => {
				const own = await grants.get(caller.module);
				return Object.entries(caller.declared).map(([kind, declared]) => {
					const granted = min(declared, own[kind]);
					return {kind, declared, ...(granted && {granted})};
				});
			}),

		list: (kind, caller) =>
			audited(caller, 'list', kind === undefined ? {} : {kind}, async () => {
				if (kind !== undefined) await require(caller, kind, 'read');
				else await requireAny(caller, 'read');
				const readable = new Set<string>();
				for (const k of Object.keys(caller.declared)) if (rank(await accessTo(caller, k)) >= 1) readable.add(k);
				const accounts = (await store.list()).filter(a => (kind === undefined ? readable.has(a.kind) : a.kind === kind));
				return Promise.all(accounts.map(info));
			}),

		read: (name, field, caller) => {
			const meta: {kind?: string; account?: string} = {account: name};
			return audited(caller, 'read', meta, async () => {
				await requireAny(caller, 'read');
				const a = await account(name);
				meta.kind = a.kind;
				await require(caller, a.kind, 'read');
				await secretField(a, field);
				return store.secret(a.name, field);
			});
		},

		write: (name, field, value, caller) => {
			const meta: {kind?: string; account?: string} = {account: name};
			return audited(caller, 'write', meta, async () => {
				await requireAny(caller, 'write');
				const a = await account(name);
				meta.kind = a.kind;
				await require(caller, a.kind, 'write');
				await secretField(a, field);
				await store.setSecret(a.name, field, value);
				deps.onSecretsChanged?.();
			});
		},

		create: (input, caller) =>
			audited(caller, 'create', {kind: input.kind, account: input.name}, async () => {
				await require(caller, input.kind, 'write');
				const kind = await kinds.get(input.kind);
				if (kind.ssh) throw new Error(`Accounts of kind "${kind.name}" are made by the user (account add), not by a module`);
				return info(await store.add({name: input.name, kind, ...(input.fields && {fields: {...input.fields}}), ssh: false}));
			}),

		remove: (name, caller) => {
			const meta: {kind?: string; account?: string} = {account: name};
			return audited(caller, 'remove', meta, async () => {
				await requireAny(caller, 'write');
				const a = await account(name);
				meta.kind = a.kind;
				await require(caller, a.kind, 'write');
				await store.remove(a.name);
				deps.onSecretsChanged?.();
			});
		},
	};
}
