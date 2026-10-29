import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import path from 'node:path';
import {test} from 'node:test';
import {createKinds} from '../src/kinds.js';
import {accountDataDirFor, accountsFor, deniedPathsFor, secretDirsFor} from '../src/public.js';
import {createStore} from '../src/store.js';
import {stripe, tmp} from './helpers.js';

test('another module reaches the accounts from its own data dir, secrets by name only', async () => {
	const data = await tmp();
	const own = path.join(data, 'payments');
	await mkdir(own);
	const dir = accountDataDirFor(own);
	assert.equal(dir, path.join(data, 'account'));
	await createKinds(dir).add('stripe', ['accountId!', 'token:secret!']);
	const store = createStore(dir);
	await store.add({name: 'pay', kind: stripe, fields: {accountId: 'acct_1'}});
	assert.deepEqual((await accountsFor(own).get('pay')).missing, ['token']);
	await store.setSecret('pay', 'token', 'sk_test_123456');

	const accounts = accountsFor(own);
	assert.deepEqual((await accounts.kinds()).map(k => k.name), ['github', 'anthropic-key', 'anthropic-token', 'claude-login', 'stripe']);
	assert.deepEqual(await accounts.list('stripe'), [{name: 'pay', kind: 'stripe', fields: {accountId: 'acct_1'}, secrets: ['token'], disabled: false, ssh: false, missing: []}]);
	assert.deepEqual(await accounts.list('github'), []);
	assert.ok(!JSON.stringify(await accounts.list()).includes('sk_test'), 'list never carries secret values');
	assert.equal('secret' in accounts, false, 'values only through the host credential channel');
	await assert.rejects(accounts.get('ghost'), /does not exist/);
	const denied = ['accounts.json', 'kinds.json', 'secrets', 'keys', 'disabled', 'vault', 'grants.json'].map(p => path.join(dir, p));
	assert.deepEqual(deniedPathsFor(own), denied);
	assert.deepEqual(secretDirsFor(own), denied);
	assert.ok(!deniedPathsFor(own).includes(path.join(dir, 'ssh_config')), 'ssh reads ssh_config from the sandbox');
});
