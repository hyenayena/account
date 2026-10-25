import {mkdtemp, realpath, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {after} from 'node:test';
import {BUILTIN_KINDS, type Kind} from '../src/kinds.js';

export const github: Kind = BUILTIN_KINDS.find(k => k.name === 'github')!;
export const stripe: Kind = {
	name: 'stripe',
	fields: [
		{key: 'accountId', secret: false, required: true},
		{key: 'token', secret: true, required: true},
	],
	ssh: false,
	oneOf: [],
	builtin: false,
};

const dirs: string[] = [];
export const tmp = async () => {
	const d = await realpath(await mkdtemp(path.join(tmpdir(), 'yena-account-')));
	dirs.push(d);
	return d;
};
after(() => Promise.all(dirs.map(d => rm(d, {recursive: true, force: true}))));

export const makeCtx = () => {
	const out: string[] = [];
	return {out, ctx: {print: (t: string) => void out.push(t), clear() {}, exit() {}}};
};
