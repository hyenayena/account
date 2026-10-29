import assert from 'node:assert/strict';
import {execFileSync, spawnSync} from 'node:child_process';
import {existsSync, readdirSync, readFileSync, statSync, writeFileSync, type Dirent} from 'node:fs';
import {tmpdir} from 'node:os';
import {chmod, mkdir} from 'node:fs/promises';
import path from 'node:path';
import {test} from 'node:test';
import {agentDirFor, createAgents, sshConfigFor, type AgentRun} from '../src/agent.js';
import {createStore, type Account} from '../src/store.js';
import {github, tmp} from './helpers.js';

const FAKE_KEY = 'fake key bytes';
const HEADER = 'BEGIN OPENSSH PRIVATE KEY';

/** Files under `dir` (recursively, unreadable ones skipped) whose content holds an OpenSSH private key header. */
function filesWithKeys(dir: string, depth = 4): string[] {
	const found: string[] = [];
	let entries: Dirent[];
	try {
		entries = readdirSync(dir, {withFileTypes: true});
	} catch {
		return found;
	}
	for (const e of entries) {
		const p = path.join(dir, e.name);
		if (e.isDirectory() && depth > 0) found.push(...filesWithKeys(p, depth - 1));
		else if (e.isFile()) {
			try {
				if (statSync(p).size < 1_000_000 && readFileSync(p, 'utf8').includes(HEADER)) found.push(p);
			} catch {
				// Not ours to read.
			}
		}
	}
	return found;
}

const account = (name: string, extra: Partial<Account> = {}): Account => ({
	name,
	kind: 'github',
	fields: {},
	publicKey: 'ssh-ed25519 AAAA',
	fingerprint: `SHA256:${name}`,
	createdAt: 0,
	disabled: false,
	...extra,
});

// A fake ssh-agent/ssh-add: `agents` maps a socket to the fingerprints it holds; absent = unreachable.
function fakeTools() {
	const agents = new Map<string, string[]>();
	const calls: string[] = [];
	const inputs: (string | undefined)[] = [];
	let pid = 100;
	const run: AgentRun = async (file, args, socket, input) => {
		calls.push(`${file} ${args.join(' ')}`);
		if (file === 'ssh-agent') {
			agents.set(args[2]!, []);
			return {code: 0, stdout: `SSH_AUTH_SOCK=${args[2]}; export SSH_AUTH_SOCK;\nSSH_AGENT_PID=${++pid}; export SSH_AGENT_PID;\n`};
		}
		const held = socket === undefined ? undefined : agents.get(socket);
		if (held === undefined) return {code: 2, stdout: ''};
		if (args[0] === '-l') return held.length ? {code: 0, stdout: held.map(f => `256 ${f} c (ED25519)`).join('\n') + '\n'} : {code: 1, stdout: ''};
		if (args[0] === '-D') return (held.length = 0), {code: 0, stdout: ''};
		assert.deepEqual(args, ['-q', '-'], 'the key comes on stdin, never as a file');
		inputs.push(input?.toString('utf8'));
		held.push(`SHA256:${path.basename(socket!, '.sock')}`);
		return {code: 0, stdout: ''};
	};
	return {agents, calls, run, inputs};
}

test('the agent dir is private to the user and the data dir', () => {
	assert.equal(agentDirFor('/data/account', 0), agentDirFor('/data/account', 0));
	assert.notEqual(agentDirFor('/data/account', 0), agentDirFor('/tmp/other', 0));
	assert.match(agentDirFor('/data/account', 7), /^\/tmp\/yena-account-7-[0-9a-f]{12}$/);
});

test('sync starts an agent with the key of each usable account and nothing for the others', async () => {
	const dir = path.join(await tmp(), 'agents');
	const tools = fakeTools();
	const agents = createAgents({dir, privateKey: async () => Buffer.from(FAKE_KEY), run: tools.run, kill: () => {}});
	await agents.sync([account('bot'), account('off', {disabled: true}), account('nokey', {publicKey: undefined})]);
	assert.deepEqual(tools.agents.get(agents.socketOf('bot')), ['SHA256:bot']);
	assert.equal(tools.agents.has(agents.socketOf('off')), false);
	assert.equal(tools.agents.has(agents.socketOf('nokey')), false);
	assert.ok(existsSync(path.join(dir, 'bot.pid')));
	tools.calls.length = 0;
	await agents.sync([account('bot')]);
	assert.deepEqual(tools.calls, ['ssh-add -l -E sha256'], 'an agent that holds the right key is left alone');
});

test('sync replaces a key that is not the account one', async () => {
	const dir = path.join(await tmp(), 'agents');
	const tools = fakeTools();
	const agents = createAgents({dir, privateKey: async () => Buffer.from(FAKE_KEY), run: tools.run, kill: () => {}});
	await agents.sync([account('bot')]);
	tools.agents.get(agents.socketOf('bot'))!.splice(0, 1, 'SHA256:old');
	await agents.sync([account('bot')]);
	assert.deepEqual(tools.agents.get(agents.socketOf('bot')), ['SHA256:bot']);
});

test('sync stops the agent of an account that was disabled or removed', async () => {
	const dir = path.join(await tmp(), 'agents');
	const tools = fakeTools();
	const killed: number[] = [];
	const agents = createAgents({dir, privateKey: async () => Buffer.from(FAKE_KEY), run: tools.run, kill: pid => killed.push(pid)});
	await agents.sync([account('bot'), account('gone')]);
	await agents.sync([account('bot', {disabled: true})]);
	assert.equal(killed.length, 2);
	for (const f of ['bot.sock', 'bot.pid', 'gone.sock', 'gone.pid']) assert.equal(existsSync(path.join(dir, f)), false, f);
});

test('sync refuses an agent dir that others can open', async () => {
	const dir = path.join(await tmp(), 'agents');
	await mkdir(dir, {mode: 0o755});
	await chmod(dir, 0o755);
	const agents = createAgents({dir, privateKey: async () => Buffer.from(FAKE_KEY), run: fakeTools().run, kill: () => {}});
	await assert.rejects(agents.sync([account('bot')]), /not a private directory/);
});

test('the key reaches the agent decrypted on stdin only', async () => {
	const dir = path.join(await tmp(), 'agents');
	const tools = fakeTools();
	const agents = createAgents({dir, privateKey: async () => Buffer.from(FAKE_KEY), run: tools.run, kill: () => {}});
	await agents.sync([account('bot')]);
	assert.deepEqual(tools.inputs, [FAKE_KEY]);
});

test('with the real ssh-agent, git signs through the agent and a disabled account loses it; no plaintext key file ever appears', async () => {
	const data = await tmp();
	const store = createStore(data);
	const watched = [data, tmpdir(), agentDirFor(data)];
	const before = new Set(watched.flatMap(d => filesWithKeys(d)));
	const bot = await store.add({name: 'bot', kind: github});
	const dir = path.join(await tmp(), 'agents');
	const agents = createAgents({dir, privateKey: n => store.privateKey(n)});
	try {
		await agents.sync([bot]);
		assert.deepEqual(readdirSync(store.dirs.keys).sort(), ['bot.enc', 'bot.pub']);
		assert.deepEqual(
			watched.flatMap(d => filesWithKeys(d)).filter(f => !before.has(f)),
			[],
			'a private key in plaintext was written',
		);
		const listed = spawnSync('ssh-add', ['-l', '-E', 'sha256'], {encoding: 'utf8', env: {PATH: process.env.PATH!, SSH_AUTH_SOCK: agents.socketOf('bot')}});
		assert.equal(listed.status, 0);
		assert.match(listed.stdout, new RegExp(bot.fingerprint!.replace(/[+/]/g, '\\$&')));
	} finally {
		await agents.sync([{...bot, disabled: true}]);
	}
	assert.equal(existsSync(agents.socketOf('bot')), false);
	const gone = spawnSync('ssh-add', ['-l'], {env: {PATH: process.env.PATH!, SSH_AUTH_SOCK: agents.socketOf('bot')}});
	assert.equal(gone.status, 2);
});

test('sync writes an ssh config that gives a repository its account agent, and only for live agents', async () => {
	const base = await tmp();
	const dir = path.join(base, 'agents');
	const configFile = path.join(base, 'data', 'ssh_config');
	const tools = fakeTools();
	const agents = createAgents({dir, configFile, privateKey: async () => Buffer.from(FAKE_KEY), run: tools.run, kill: () => {}});
	await agents.sync([account('bot'), account('off', {disabled: true})]);
	assert.equal(readFileSync(configFile, 'utf8'), sshConfigFor([{name: 'bot', socket: agents.socketOf('bot')}]));
	await agents.sync([]);
	assert.equal(readFileSync(configFile, 'utf8'), sshConfigFor([]));
});

test('ssh picks the agent of the account the repository uses from that config', async () => {
	const base = await tmp();
	const config = path.join(base, 'ssh_config');
	writeFileSync(config, sshConfigFor([{name: 'bot', socket: '/run/bot.sock'}, {name: 'other', socket: '/run/other.sock'}]));
	const repo = path.join(base, 'repo');
	execFileSync('git', ['init', '-q', repo]);
	const agentIn = (cwd: string) =>
		/^identityagent (.*)$/m.exec(execFileSync('ssh', ['-G', '-F', config, 'git@github.com'], {cwd, encoding: 'utf8'}))?.[1];
	assert.equal(agentIn(repo), undefined, 'a repository without an account gets no agent');
	execFileSync('git', ['-C', repo, 'config', 'yena.account', 'bot']);
	assert.equal(agentIn(repo), '/run/bot.sock');
	assert.equal(agentIn(path.join(base)), undefined);
});
