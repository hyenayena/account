import {execFile} from 'node:child_process';
import {createHash} from 'node:crypto';
import {lstatSync, readFileSync} from 'node:fs';
import {mkdir, readdir, rm, writeFile} from 'node:fs/promises';
import path from 'node:path';
import {checkName, type Account} from './store.js';

/**
 * One ssh-agent per enabled account with a key, so git can sign with the key from places that cannot read
 * it (the chat's Bash sandbox): `bin/ssh-as` uses the agent when the key file is out of reach. On tmpfs,
 * because unix sockets may not work on a folder mounted from the host; named after the data dir, so another
 * yena data dir (a test) never touches these agents. `bin/ssh-as` builds the same path.
 */
export const agentDirFor = (dataDir: string, uid: number = process.getuid?.() ?? 0): string =>
	`/tmp/yena-account-${uid}-${createHash('sha256').update(dataDir).digest('hex').slice(0, 12)}`;

export type ToolResult = {code: number; stdout: string};
export type AgentRun = (file: string, args: string[], socket?: string) => Promise<ToolResult>;

const TOOL_TIMEOUT_MS = 10_000;

// Only PATH (and the agent socket for ssh-add): nothing from yena's environment reaches the agent.
export const runAgentTool: AgentRun = (file, args, socket) =>
	new Promise(resolve => {
		const env: Record<string, string> = {PATH: process.env.PATH ?? '/usr/bin:/bin'};
		if (socket) env.SSH_AUTH_SOCK = socket;
		execFile(file, args, {timeout: TOOL_TIMEOUT_MS, maxBuffer: 64 * 1024, env}, (error, stdout) => {
			const code = error ? (typeof error.code === 'number' ? error.code : -1) : 0;
			resolve({code, stdout: String(stdout)});
		});
	});

export type Agents = {
	/** Starts or refreshes the agents of usable accounts and stops every other one. */
	sync(accounts: Account[]): Promise<void>;
	socketOf(name: string): string;
};

// ssh-add -l: 0 holds keys, 1 holds none, 2 cannot reach the agent.
const NO_KEYS = 1;

export function createAgents(opts: {dir: string; keyPath: (name: string) => string; run?: AgentRun; kill?: (pid: number) => void}): Agents {
	const dir = opts.dir;
	const run = opts.run ?? runAgentTool;
	const kill = opts.kill ?? killAgent;
	const socketOf = (name: string) => path.join(dir, `${checkName(name)}.sock`);
	const pidOf = (name: string) => path.join(dir, `${checkName(name)}.pid`);

	async function start(name: string): Promise<void> {
		const socket = socketOf(name);
		await rm(socket, {force: true});
		const r = await run('ssh-agent', ['-s', '-a', socket]);
		if (r.code !== 0) throw new Error(`ssh-agent failed (${r.code})`);
		const pid = /SSH_AGENT_PID=(\d+)/.exec(r.stdout)?.[1];
		if (pid) await writeFile(pidOf(name), pid, {mode: 0o600});
	}

	async function ensure(account: Account): Promise<void> {
		const socket = socketOf(account.name);
		let listed = await run('ssh-add', ['-l', '-E', 'sha256'], socket);
		if (listed.code !== 0 && listed.code !== NO_KEYS) {
			await stop(account.name);
			await start(account.name);
			listed = {code: NO_KEYS, stdout: ''};
		}
		// A key of an account removed and created again under the same name is replaced.
		const loaded = listed.code === 0 ? listed.stdout.trim().split('\n') : [];
		if (loaded.length === 1 && account.fingerprint !== undefined && loaded[0]!.split(/\s+/)[1] === account.fingerprint) return;
		if (listed.code === 0) await run('ssh-add', ['-D'], socket);
		const added = await run('ssh-add', ['-q', opts.keyPath(account.name)], socket);
		if (added.code !== 0) throw new Error(`ssh-add failed (${added.code})`);
	}

	async function stop(name: string): Promise<void> {
		let pid: number | undefined;
		try {
			pid = Number(readFileSync(pidOf(name), 'utf8').trim()) || undefined;
		} catch {
			pid = undefined;
		}
		if (pid !== undefined) kill(pid);
		await rm(socketOf(name), {force: true});
		await rm(pidOf(name), {force: true});
	}

	return {
		socketOf,
		async sync(accounts) {
			await mkdir(dir, {recursive: true, mode: 0o700});
			const st = lstatSync(dir);
			if (!st.isDirectory() || (st.mode & 0o077) !== 0) throw new Error('The ssh-agent folder is not a private directory');
			const usable = accounts.filter(a => a.publicKey !== undefined && !a.disabled);
			const keep = new Set(usable.map(a => a.name));
			for (const entry of await readdir(dir)) {
				const name = entry.replace(/\.(sock|pid)$/, '');
				if (!keep.has(name) && entry !== name) await stop(name).catch(() => undefined);
			}
			const failed: string[] = [];
			for (const a of usable) await ensure(a).catch(() => failed.push(a.name));
			if (failed.length > 0) throw new Error(`ssh-agent could not be started for ${failed.length} account(s)`);
		},
	};
}

// Only an ssh-agent is killed: a pid file left from an earlier container may name another process now.
function killAgent(pid: number): void {
	try {
		if (readFileSync(`/proc/${pid}/comm`, 'utf8').trim() !== 'ssh-agent') return;
		process.kill(pid);
	} catch {
		// Already gone.
	}
}
