import {execFile} from 'node:child_process';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {NAME, type Account} from './store.js';

export const SSH_AS = fileURLToPath(new URL('../bin/ssh-as', import.meta.url));
const GIT_TIMEOUT_MS = 10_000;
// Marks a repository as using a yena account, so `which` can name it.
const ACCOUNT_KEY = 'yena.account';

export type Git = (args: string[]) => Promise<string>;

export const runGit: Git = args =>
	new Promise((resolve, reject) => {
		execFile('git', args, {timeout: GIT_TIMEOUT_MS, maxBuffer: 256 * 1024}, (error, stdout) => {
			if (error) reject(new Error(`git failed (${error.code ?? error.signal ?? 'error'})`));
			else resolve(stdout);
		});
	});

// Single quotes keep the paths as one word each; git runs core.sshCommand through the shell.
const shellQuote = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;

export const sshCommand = (dataDir: string, name: string, sshAs = SSH_AS) =>
	`sh ${shellQuote(sshAs)} ${shellQuote(dataDir)} ${name}`;

async function repoRoot(git: Git, dir: string): Promise<string> {
	try {
		return (await git(['-C', dir, 'rev-parse', '--show-toplevel'])).trim();
	} catch {
		throw new Error(`${dir} is not a git repository`);
	}
}

/** The ssh command `mod install --account` fetches with: only an enabled account with an SSH key. */
export function gitSshResolver(get: (name: string) => Promise<Account>, dataDir: string, sshAs = SSH_AS) {
	return async (name: string): Promise<string> => {
		const account = await get(name);
		if (account.disabled) throw new Error(`Account "${account.name}" is disabled`);
		if (account.publicKey === undefined) throw new Error(`Account "${account.name}" has no SSH key`);
		return sshCommand(dataDir, account.name, sshAs);
	};
}

/** Makes git in the repository at `dir` push and pull as `account` and commit under its name. */
export async function useAccount(git: Git, dir: string, account: Account, dataDir: string, sshAs = SSH_AS): Promise<string> {
	const root = await repoRoot(git, path.resolve(dir));
	const set = (key: string, value: string) => git(['-C', root, 'config', '--local', key, value]);
	await set('core.sshCommand', sshCommand(dataDir, account.name, sshAs));
	await set(ACCOUNT_KEY, account.name);
	await set('user.name', account.fields.login ?? account.name);
	if (account.fields.email) await set('user.email', account.fields.email);
	return root;
}

/** The yena account the repository at `dir` uses, if any. */
export async function accountOf(git: Git, dir: string): Promise<{root: string; name?: string}> {
	const root = await repoRoot(git, path.resolve(dir));
	let name: string | undefined;
	try {
		name = (await git(['-C', root, 'config', '--local', '--get', ACCOUNT_KEY])).trim();
	} catch {
		name = undefined;
	}
	return {root, ...(name && NAME.test(name) && {name})};
}

/** Removes what `useAccount` set, so git falls back to the user's own setup. */
export async function unuseAccount(git: Git, dir: string): Promise<string> {
	const root = await repoRoot(git, path.resolve(dir));
	for (const key of ['core.sshCommand', ACCOUNT_KEY, 'user.name', 'user.email']) {
		await git(['-C', root, 'config', '--local', '--unset-all', key]).catch(() => undefined);
	}
	return root;
}
