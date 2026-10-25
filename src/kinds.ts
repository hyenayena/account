import {readFileSync} from 'node:fs';
import {mkdir, readFile, rename, writeFile} from 'node:fs/promises';
import path from 'node:path';

export type Field = {key: string; secret: boolean; required: boolean};
/**
 * A kind of account: the service it is for and the fields an account of it holds. `oneOf` lists groups
 * of which at least one member must be set; `ssh` stands for the account's SSH key.
 */
export type Kind = {name: string; fields: Field[]; ssh: boolean; oneOf: string[][]; builtin: boolean};

export const KIND_NAME = /^[a-z0-9][a-z0-9_-]{0,31}$/;
export const FIELD_KEY = /^[A-Za-z][A-Za-z0-9_]{0,31}$/;
export const SSH_KEY = 'ssh';
const MAX_FIELDS = 20;
const MAX_GROUPS = 10;

export const BUILTIN_KINDS: Kind[] = [
	{
		name: 'github',
		fields: [
			{key: 'login', secret: false, required: false},
			{key: 'email', secret: false, required: false},
			{key: 'token', secret: true, required: false},
		],
		ssh: true,
		oneOf: [[SSH_KEY, 'token']],
		builtin: true,
	},
];

export const DEFAULT_KIND = 'github';

/** `accountId! token:secret` → fields; `:secret` marks a secret, a trailing `!` a required field. */
export function parseFields(specs: string[]): Field[] {
	if (specs.length === 0) throw new Error('A kind needs at least one field, e.g.: account kind add stripe accountId! token:secret!');
	if (specs.length > MAX_FIELDS) throw new Error(`A kind has at most ${MAX_FIELDS} fields`);
	const fields: Field[] = [];
	for (const spec of specs) {
		const required = spec.endsWith('!');
		const [key = '', mark, ...rest] = (required ? spec.slice(0, -1) : spec).split(':');
		if (rest.length > 0 || (mark !== undefined && mark !== 'secret')) {
			throw new Error(`Invalid field "${spec.slice(0, 40)}": use <name>, <name>:secret, and a trailing ! for a required one`);
		}
		if (!FIELD_KEY.test(key)) throw new Error(`Invalid field name "${key.slice(0, 40)}": a letter, then letters, digits or "_", at most 32 characters`);
		if (key === SSH_KEY) throw new Error(`"${SSH_KEY}" is reserved for SSH keys`);
		if (fields.some(f => f.key === key)) throw new Error(`Field "${key}" is listed twice`);
		fields.push({key, secret: mark === 'secret', required});
	}
	return fields;
}

/** `password,apiKey` → a group of which at least one must be set. */
export function parseGroup(spec: string, fields: Field[], ssh: boolean): string[] {
	const keys = spec.split(',');
	if (keys.length < 2) throw new Error(`--one-of needs two or more fields, e.g. --one-of password,apiKey`);
	for (const key of keys) {
		const field = fields.find(f => f.key === key);
		if (!(field || (ssh && key === SSH_KEY))) throw new Error(`--one-of: no field "${key.slice(0, 40)}"`);
		if (field?.required) throw new Error(`--one-of: "${key}" is already required`);
	}
	if (new Set(keys).size !== keys.length) throw new Error('--one-of lists a field twice');
	return keys;
}

/** What an account still needs: required fields not set, and `a|b` for a group with none set. */
export function missingOf(kind: Kind, account: {fields: Record<string, string>; publicKey?: string}, secrets: string[]): string[] {
	const has = (key: string) =>
		key === SSH_KEY ? account.publicKey !== undefined : account.fields[key] !== undefined || secrets.includes(key);
	return [...kind.fields.filter(f => f.required && !has(f.key)).map(f => f.key), ...kind.oneOf.filter(g => !g.some(has)).map(g => g.join('|'))];
}

export type FieldStatus = {key: string; secret: boolean; required: boolean; set: boolean};

/** Every field of the kind (the SSH key as `ssh`) and whether the account has it; never the values. */
export function fieldStatus(kind: Kind, account: {fields: Record<string, string>; publicKey?: string}, secrets: string[]): FieldStatus[] {
	const status = kind.fields.map(f => ({...f, set: f.secret ? secrets.includes(f.key) : account.fields[f.key] !== undefined}));
	return kind.ssh ? [...status, {key: SSH_KEY, secret: false, required: false, set: account.publicKey !== undefined}] : status;
}

type StoredKind ={name: string; fields: Field[]; oneOf?: string[][]};
type KindsFile = {v: 1; kinds: StoredKind[]};

const validField = (f: unknown): boolean => {
	const r = f as Partial<Field> | null;
	return typeof r?.key === 'string' && FIELD_KEY.test(r.key) && r.key !== SSH_KEY && typeof r.secret === 'boolean' && (r.required === undefined || typeof r.required === 'boolean');
};

const validStored = (k: unknown): k is StoredKind => {
	const r = k as {name?: unknown; fields?: unknown; oneOf?: unknown} | null;
	return (
		typeof r?.name === 'string' &&
		KIND_NAME.test(r.name) &&
		Array.isArray(r.fields) &&
		r.fields.every(validField) &&
		(r.oneOf === undefined || (Array.isArray(r.oneOf) && r.oneOf.every(g => Array.isArray(g) && g.every(x => typeof x === 'string'))))
	);
};

const fromFile = (raw: unknown): Kind[] => {
	const kinds = (raw as Partial<KindsFile> | null)?.kinds;
	if (!Array.isArray(kinds)) return [];
	return kinds
		.filter(validStored)
		.filter(k => !BUILTIN_KINDS.some(b => b.name === k.name))
		.map(k => {
			const fields = k.fields.map(f => ({key: f.key, secret: f.secret, required: f.required === true}));
			// A group naming a field the kind does not have could never be satisfied.
			const oneOf = (k.oneOf ?? []).filter(g => g.every(key => fields.some(f => f.key === key)));
			return {name: k.name, fields, ssh: false, oneOf, builtin: false};
		});
};

export function createKinds(dataDir: string) {
	const file = path.join(dataDir, 'kinds.json');

	async function custom(): Promise<Kind[]> {
		try {
			return fromFile(JSON.parse(await readFile(file, 'utf8')));
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
			throw new Error(`Failed to read kinds.json: ${(error as Error).message}`);
		}
	}

	function listSync(): Kind[] {
		try {
			return [...BUILTIN_KINDS, ...fromFile(JSON.parse(readFileSync(file, 'utf8')))];
		} catch {
			return [...BUILTIN_KINDS];
		}
	}

	async function save(kinds: Kind[]): Promise<void> {
		await mkdir(dataDir, {recursive: true, mode: 0o700});
		const data: KindsFile = {v: 1, kinds: kinds.map(k => ({name: k.name, fields: k.fields, ...(k.oneOf.length > 0 && {oneOf: k.oneOf})}))};
		const tmp = `${file}.${process.pid}.tmp`;
		await writeFile(tmp, JSON.stringify(data, null, '\t') + '\n', {mode: 0o600});
		await rename(tmp, file);
	}

	const list = async (): Promise<Kind[]> => [...BUILTIN_KINDS, ...(await custom())];

	async function get(name: string): Promise<Kind> {
		const kind = (await list()).find(k => k.name === name);
		if (!kind) throw new Error(`Unknown kind "${name.slice(0, 40)}". See: account kinds`);
		return kind;
	}

	/** `specs` are field specs and `--one-of a,b` pairs, in any order. */
	async function add(name: string, specs: string[]): Promise<Kind> {
		if (!KIND_NAME.test(name)) throw new Error(`Invalid kind name "${name.slice(0, 40)}": use a-z, 0-9, "-" and "_", at most 32 characters`);
		const fieldSpecs: string[] = [];
		const groupSpecs: string[] = [];
		for (let i = 0; i < specs.length; i++) {
			if (specs[i] === '--one-of') {
				const group = specs[++i];
				if (group === undefined) throw new Error('--one-of needs a value, e.g. --one-of password,apiKey');
				groupSpecs.push(group);
			} else if (specs[i]!.startsWith('--')) throw new Error(`Unknown option "${specs[i]!.slice(0, 40)}"`);
			else fieldSpecs.push(specs[i]!);
		}
		const fields = parseFields(fieldSpecs);
		if (groupSpecs.length > MAX_GROUPS) throw new Error(`A kind has at most ${MAX_GROUPS} --one-of groups`);
		const oneOf = groupSpecs.map(g => parseGroup(g, fields, false));
		const existing = await custom();
		if (BUILTIN_KINDS.some(k => k.name === name) || existing.some(k => k.name === name)) throw new Error(`Kind "${name}" already exists`);
		const kind: Kind = {name, fields, ssh: false, oneOf, builtin: false};
		await save([...existing, kind]);
		return kind;
	}

	async function remove(name: string): Promise<void> {
		if (BUILTIN_KINDS.some(k => k.name === name)) throw new Error(`Kind "${name}" is built in`);
		const existing = await custom();
		if (!existing.some(k => k.name === name)) throw new Error(`Unknown kind "${name.slice(0, 40)}". See: account kinds`);
		await save(existing.filter(k => k.name !== name));
	}

	return {list, listSync, get, add, remove};
}

export type Kinds = ReturnType<typeof createKinds>;
