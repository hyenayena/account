import type {Kind} from './kinds.js';

export const MAX_SECRET = 8192;
export const MAX_LOGIN = 64 * 1024;
// Shorter leaves of a login blob are ids and flags, not credentials, and would cut ordinary words out of logs.
const MIN_LEAF = 16;
const MAX_DEPTH = 8;

const ANTHROPIC_KEY = /^sk-ant-(?!oat)[A-Za-z0-9_-]{20,}$/;
const ANTHROPIC_TOKEN = /^sk-ant-oat[0-9A-Za-z_-]{20,}$/;

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

function parseObject(value: string): Record<string, unknown> | undefined {
	try {
		const parsed = JSON.parse(value) as unknown;
		return isObject(parsed) ? parsed : undefined;
	} catch {
		return undefined;
	}
}

function isLogin(value: string): boolean {
	const blob = parseObject(value);
	if (!blob) return false;
	const credentials = blob.credentials;
	if (isObject(credentials) && isObject(credentials.claudeAiOauth)) return true;
	return typeof blob.primaryApiKey === 'string' && blob.primaryApiKey !== '';
}

/** The size cap of a secret field; a Claude Code login blob is larger than any typed secret. */
export const maxSecretOf = (kind: Kind | undefined, field: string): number =>
	kind?.fields.find(f => f.key === field)?.check === 'claude-login' ? MAX_LOGIN : MAX_SECRET;

/** Throws when the value cannot be the field's secret. Messages never contain the value. */
export function checkSecret(kind: Kind | undefined, field: string, value: string): void {
	const check = kind?.fields.find(f => f.key === field)?.check;
	if (check === 'claude-login') {
		if (value === '' || Buffer.byteLength(value) > MAX_LOGIN || !isLogin(value)) {
			throw new Error('Not a Claude Code login (a JSON object with credentials.claudeAiOauth or primaryApiKey, at most 64 KiB)');
		}
		return;
	}
	if (value === '' || value.length > MAX_SECRET) throw new Error(`A secret is 1 to ${MAX_SECRET} characters`);
	if (check === 'anthropic-key' && !ANTHROPIC_KEY.test(value)) throw new Error('Not an Anthropic API key (sk-ant-…)');
	if (check === 'anthropic-token' && !ANTHROPIC_TOKEN.test(value)) throw new Error('Not an Anthropic subscription token (sk-ant-oat…)');
}

// A login keeps its owner's email beside the tokens; redacting it would hide the account everywhere it is shown.
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** For a value that is a JSON object: every string leaf long enough to be a credential (not an email), for the log redactor. */
export function secretLeaves(value: string): string[] {
	const root = parseObject(value);
	if (!root) return [];
	const leaves: string[] = [];
	const walk = (v: unknown, depth: number) => {
		if (typeof v === 'string') {
			if (v.length >= MIN_LEAF && !EMAIL.test(v)) leaves.push(v);
		} else if (depth < MAX_DEPTH && typeof v === 'object' && v !== null) {
			for (const child of Object.values(v)) walk(child, depth + 1);
		}
	};
	walk(root, 0);
	return leaves;
}
