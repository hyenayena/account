import type {Kind} from './kinds.js';

export const MAX_SECRET = 8192;
const MIN_LEAF = 16;
const MAX_DEPTH = 8;

const ANTHROPIC_KEY = /^sk-ant-(?!oat)[A-Za-z0-9_-]{20,}$/;

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

function parseObject(value: string): Record<string, unknown> | undefined {
	try {
		const parsed = JSON.parse(value) as unknown;
		return isObject(parsed) ? parsed : undefined;
	} catch {
		return undefined;
	}
}

export function checkSecret(kind: Kind | undefined, field: string, value: string): void {
	const check = kind?.fields.find(f => f.key === field)?.check;
	if (value === '' || value.length > MAX_SECRET) throw new Error(`A secret is 1 to ${MAX_SECRET} characters`);
	if (check === 'anthropic-key' && !ANTHROPIC_KEY.test(value)) throw new Error('Not an Anthropic API key (sk-ant-…)');
}

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const PUBLIC_LEAF_KEYS = new Set(['displayName', 'organizationName']);

export function secretLeaves(value: string): string[] {
	const root = parseObject(value);
	if (!root) return [];
	const leaves: string[] = [];
	const walk = (v: unknown, depth: number) => {
		if (typeof v === 'string') {
			if (v.length >= MIN_LEAF && !EMAIL.test(v)) leaves.push(v);
		} else if (depth < MAX_DEPTH && typeof v === 'object' && v !== null) {
			for (const [key, child] of Object.entries(v)) {
				if (!Array.isArray(v) && PUBLIC_LEAF_KEYS.has(key)) continue;
				walk(child, depth + 1);
			}
		}
	};
	walk(root, 0);
	return leaves;
}
