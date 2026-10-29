import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import {test} from 'node:test';
import {fingerprintOf, generateEd25519} from '../src/openssh.js';
import {tmp} from './helpers.js';

test('a generated key is OpenSSH format with a matching public line and fingerprint', () => {
	const key = generateEd25519('bot@example.com');
	const pem = key.privateKey.toString('utf8');
	assert.match(pem, /^-----BEGIN OPENSSH PRIVATE KEY-----\n([A-Za-z0-9+/=]{1,70}\n)+-----END OPENSSH PRIVATE KEY-----\n$/);
	assert.match(key.publicKey, /^ssh-ed25519 [A-Za-z0-9+/]+=* bot@example\.com$/);
	assert.match(key.fingerprint, /^SHA256:[A-Za-z0-9+/]{43}$/);
	assert.equal(fingerprintOf(key.publicKey), key.fingerprint);
	assert.notEqual(generateEd25519('x').publicKey, generateEd25519('x').publicKey);
});

test('the real agent loads a generated key from stdin and reports its fingerprint and public key', async () => {
	const socket = path.join(await tmp(), 'agent.sock');
	const env = {PATH: process.env.PATH!, SSH_AUTH_SOCK: socket};
	const started = spawnSync('ssh-agent', ['-s', '-a', socket], {encoding: 'utf8', env: {PATH: process.env.PATH!}});
	assert.equal(started.status, 0);
	const pid = Number(/SSH_AGENT_PID=(\d+)/.exec(started.stdout)?.[1]);
	try {
		const key = generateEd25519('bot@example.com');
		const added = spawnSync('ssh-add', ['-q', '-'], {input: key.privateKey, env});
		assert.equal(added.status, 0, 'ssh-add refused the key');
		const listed = spawnSync('ssh-add', ['-l', '-E', 'sha256'], {encoding: 'utf8', env});
		assert.equal(listed.stdout.split(/\s+/)[1], key.fingerprint);
		const pub = spawnSync('ssh-add', ['-L'], {encoding: 'utf8', env});
		assert.equal(pub.stdout.trim(), key.publicKey);
	} finally {
		if (pid) process.kill(pid);
	}
});
