import assert from 'node:assert/strict';
import {execFileSync, spawnSync} from 'node:child_process';
import {once} from 'node:events';
import {chmod, mkdir, rm, writeFile} from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import {test} from 'node:test';
import {agentDirFor} from '../src/agent.js';
import {accountOf, gitSshResolver, runGit, SSH_AS, sshCommand, unuseAccount, useAccount} from '../src/git.js';
import {createStore} from '../src/store.js';
import {github, tmp} from './helpers.js';

const repo = async () => {
	const dir = await tmp();
	execFileSync('git', ['init', '-q', dir]);
	return dir;
};
const config = (dir: string, key: string) => {
	const r = spawnSync('git', ['-C', dir, 'config', '--local', '--get', key], {encoding: 'utf8'});
	return r.status === 0 ? r.stdout.trim() : undefined;
};

test('use points the repository at the account, which and unuse read and undo it', async () => {
	const data = await tmp();
	const account = await createStore(data).add({name: 'yena', kind: github, fields: {login: 'yena-bot', email: 'yena@example.com'}});
	const dir = await repo();
	await mkdir(path.join(dir, 'sub'));
	assert.equal(await useAccount(runGit, path.join(dir, 'sub'), account, data), dir);
	assert.equal(config(dir, 'core.sshCommand'), sshCommand(data, 'yena'));
	assert.equal(config(dir, 'user.name'), 'yena-bot');
	assert.equal(config(dir, 'user.email'), 'yena@example.com');
	assert.deepEqual(await accountOf(runGit, dir), {root: dir, name: 'yena'});
	await unuseAccount(runGit, dir);
	assert.equal(config(dir, 'core.sshCommand'), undefined);
	assert.equal(config(dir, 'user.email'), undefined);
	assert.deepEqual(await accountOf(runGit, dir), {root: dir});
});

test('a directory that is not a repository is refused', async () => {
	const data = await tmp();
	const account = await createStore(data).add({name: 'yena', kind: github});
	await assert.rejects(useAccount(runGit, await tmp(), account, data), /is not a git repository/);
});

// ssh-as through a fake ssh on PATH that prints its arguments.
async function sshAs(data: string, name: string) {
	const bin = await tmp();
	await writeFile(path.join(bin, 'ssh'), '#!/bin/sh\necho "$@"\n');
	await chmod(path.join(bin, 'ssh'), 0o755);
	return spawnSync('sh', [SSH_AS, data, name, 'git@github.com', 'git-upload-pack'], {
		encoding: 'utf8',
		env: {...process.env, PATH: `${bin}:${process.env.PATH}`},
	});
}

test('ssh-as never uses the key file (it is encrypted): without the account agent it says so', async () => {
	const data = await tmp();
	const store = createStore(data);
	await store.add({name: 'yena', kind: github});
	const r = await sshAs(data, 'yena');
	assert.equal(r.status, 1);
	assert.equal(r.stdout, '');
	assert.match(r.stderr, /account "yena": no running ssh agent \(start yena once after the container started\)/);
});

test('ssh-as refuses a disabled, missing or malformed account', async () => {
	const data = await tmp();
	const store = createStore(data);
	await store.add({name: 'yena', kind: github});
	await store.setDisabled('yena', true);
	let r = await sshAs(data, 'yena');
	assert.equal(r.status, 1);
	assert.match(r.stderr, /is disabled/);
	r = await sshAs(data, 'ghost');
	assert.equal(r.status, 1);
	assert.match(r.stderr, /no running ssh agent/);
	r = await sshAs(data, '../x');
	assert.equal(r.status, 1);
	assert.match(r.stderr, /invalid account name/);
});

test('mod install --account gets the ssh command only for an enabled account with a key', async () => {
	const base = {kind: 'github', fields: {}, createdAt: 0};
	const accounts: Record<string, Parameters<typeof useAccount>[2]> = {
		bot: {...base, name: 'bot', publicKey: 'ssh-ed25519 AAAA', disabled: false},
		off: {...base, name: 'off', publicKey: 'ssh-ed25519 AAAA', disabled: true},
		nokey: {...base, name: 'nokey', disabled: false},
	};
	const get = async (name: string) => {
		const a = accounts[name];
		if (!a) throw new Error(`Account "${name}" does not exist. See: account list`);
		return a;
	};
	const resolve = gitSshResolver(get, '/d/acc', '/m/bin/ssh-as');
	assert.equal(await resolve('bot'), sshCommand('/d/acc', 'bot', '/m/bin/ssh-as'));
	await assert.rejects(resolve('off'), /disabled/);
	await assert.rejects(resolve('nokey'), /no SSH key/);
	await assert.rejects(resolve('ghost'), /does not exist/);
});

test('ssh-as signs through the account agent where the key cannot be read', async () => {
	const data = await tmp();
	const dir = agentDirFor(data);
	await mkdir(dir, {recursive: true, mode: 0o700});
	const socket = path.join(dir, 'yena.sock');
	const server = net.createServer().listen(socket);
	await once(server, 'listening');
	try {
		const r = await sshAs(data, 'yena');
		assert.equal(r.status, 0, r.stderr);
		assert.equal(r.stdout.trim(), `-o IdentityAgent=${socket} -o StrictHostKeyChecking=accept-new git@github.com git-upload-pack`);
	} finally {
		server.close();
		await rm(dir, {recursive: true, force: true});
	}
});
