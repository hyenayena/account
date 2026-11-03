import {randomBytes} from 'node:crypto';
import {closeSync, constants as fsConstants, fstatSync, lstatSync, openSync, readFileSync} from 'node:fs';
import {chmod, lstat, mkdir, rename, rm, writeFile} from 'node:fs/promises';
import path from 'node:path';
import type {Logger} from '../../../src/api.js';
import type {Grants} from './grants.js';
import {RETIRED_KINDS} from './kinds.js';
import type {Store} from './store.js';

export const RETIRED_FILE = 'retired.json';
export const MAX_RETIRED_FILE = 4096;

export type RetiredRecord = {at: string; logins: number; tokens: number};

const count = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;

export function parseRetired(text: string): RetiredRecord | undefined {
	let raw: unknown;
	try {
		raw = JSON.parse(text);
	} catch {
		return undefined;
	}
	const r = raw as {v?: unknown; at?: unknown; logins?: unknown; tokens?: unknown} | null;
	if (!r || typeof r !== 'object' || r.v !== 1) return undefined;
	if (typeof r.at !== 'string' || r.at.length > 40 || Number.isNaN(Date.parse(r.at)) || !count(r.logins) || !count(r.tokens)) return undefined;
	return {at: r.at, logins: r.logins, tokens: r.tokens};
}

export function readRetired(dataDir: string): RetiredRecord | undefined {
	const file = path.join(dataDir, RETIRED_FILE);
	try {
		const st = lstatSync(file);
		if (!st.isFile() || st.size > MAX_RETIRED_FILE) return undefined;
		const fd = openSync(file, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
		try {
			if (fstatSync(fd).size > MAX_RETIRED_FILE) return undefined;
			return parseRetired(readFileSync(fd, 'utf8'));
		} finally {
			closeSync(fd);
		}
	} catch {
		return undefined;
	}
}

async function writeRetired(dataDir: string, added: {logins: number; tokens: number}): Promise<void> {
	const file = path.join(dataDir, RETIRED_FILE);
	await mkdir(dataDir, {recursive: true, mode: 0o700});
	await chmod(dataDir, 0o700);
	const st = await lstat(file).catch(() => undefined);
	if (st && !st.isFile()) throw new Error(`${RETIRED_FILE} is not a regular file`);
	const before = st ? readRetired(dataDir) : undefined;
	const record = {v: 1, at: new Date().toISOString(), logins: (before?.logins ?? 0) + added.logins, tokens: (before?.tokens ?? 0) + added.tokens};
	const tmp = `${file}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
	await writeFile(tmp, JSON.stringify(record) + '\n', {mode: 0o600, flag: 'wx'});
	try {
		await rename(tmp, file);
	} catch (error) {
		await rm(tmp, {force: true});
		throw error;
	}
}

export async function retireKinds(opts: {store: Store; grants: Grants; dataDir: string; log: Logger}): Promise<{logins: number; tokens: number} | undefined> {
	const {store, grants, dataDir, log} = opts;
	const retired: readonly string[] = RETIRED_KINDS;
	try {
		const removed = {logins: 0, tokens: 0};
		for (const account of (await store.list()).filter(a => retired.includes(a.kind))) {
			try {
				await store.remove(account.name);
			} catch (error) {
				if ((await store.list()).some(a => a.name === account.name)) throw error;
			}
			if (account.kind === 'claude-login') removed.logins++;
			else removed.tokens++;
		}
		const any = removed.logins + removed.tokens > 0;
		if (any) await writeRetired(dataDir, removed);
		await grants.dropKinds(RETIRED_KINDS);
		if (!any) return undefined;
		log.info('retired credentials removed', removed);
		return removed;
	} catch (error) {
		log.warn('retired credentials not removed', {errClass: error instanceof Error ? error.constructor.name : typeof error});
		return undefined;
	}
}
