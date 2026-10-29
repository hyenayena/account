import React from 'react';
import assert from 'node:assert/strict';
import {test} from 'node:test';
import type {MountControl} from '../../../../src/api.js';
import {createKinds} from '../../src/kinds.js';
import {createStore} from '../../src/store.js';
import {addWizard} from '../../src/ui/add-wizard.js';
import {tmp} from '../helpers.js';
import {mount, wait} from './harness.js';

const ESC = String.fromCharCode(27);
const DOWN = `${ESC}[B`;

async function setup(withStripe = false) {
	const dir = await tmp();
	const store = createStore(dir);
	const kinds = createKinds(dir);
	if (withStripe) await kinds.add('stripe', ['accountId!', 'token:secret!']);
	const copied: string[] = [];
	let closed = 0;
	const control: MountControl = {close: () => void closed++, copyToClipboard: text => (copied.push(text), true)};
	const ui = mount(<>{addWizard(control, {store, kinds}) as React.ReactElement}</>);
	await wait(40);
	return {store, ui, copied, closed: () => closed};
}

const until = async (check: () => boolean, ms = 3000) => {
	for (const start = Date.now(); !check(); ) {
		if (Date.now() - start > ms) throw new Error('timed out');
		await wait(20);
	}
};

test('github step by step: name, login, skipped email, an SSH key, a skipped token; c copies the public key', async () => {
	const {store, ui, copied, closed} = await setup();
	assert.match(ui.last(), /what is it for\?/);
	assert.match(ui.last(), /github \(built in\)/);
	await ui.press('\r');
	assert.match(ui.last(), /Name of the github account/);
	await ui.press('yena');
	await ui.press('\r');
	assert.match(ui.last(), /login \(optional\)/);
	await ui.press('yena-bot');
	await ui.press('\r');
	assert.match(ui.last(), /email \(optional\)/);
	await ui.press('\r');
	assert.match(ui.last(), /SSH key\?/);
	await ui.press('\r');
	await until(() => /token for yena/.test(ui.last()));
	await ui.press('\r');
	assert.match(ui.last(), /✓ Account "yena" \(github\) created/);
	assert.match(ui.last(), /signed in as yena-bot/);
	assert.doesNotMatch(ui.last(), /Still needed/);
	const account = await store.get('yena');
	assert.deepEqual(account.fields, {login: 'yena-bot'});
	assert.match(ui.all().replace(/\s/g, ''), new RegExp(account.publicKey!.replace(/\s/g, '').replace(/[+/]/g, '\\$&')));
	await ui.press('c');
	assert.deepEqual(copied, [account.publicKey]);
	assert.match(ui.last(), /Public key copied/);
	await ui.press('\r');
	assert.equal(closed(), 1);
	ui.unmount();
});

test('a kind of your own: a required field, then a secret that never reaches the screen', async () => {
	const {store, ui} = await setup(true);
	for (let i = 0; i < 3; i++) await ui.press(DOWN);
	await ui.press('\r');
	await ui.press('pay');
	await ui.press('\r');
	assert.match(ui.last(), /accountId\n/);
	await ui.press('\r');
	assert.match(ui.last(), /A value is needed/);
	await ui.press('acct_1');
	await ui.press('\r');
	await until(() => /token for pay · Esc skips the rest/.test(ui.last()));
	await ui.press('sk_test_wizard_value');
	await ui.press('\r');
	await until(() => /created/.test(ui.last()));
	assert.match(ui.last(), /Secrets saved: token/);
	assert.ok(!ui.all().includes('sk_test_wizard_value'), 'the secret was drawn');
	assert.equal(await store.secret('pay', 'token'), 'sk_test_wizard_value');
	assert.doesNotMatch(ui.last(), /c copy/, 'no key to copy');
	ui.unmount();
});

test('Esc before anything is saved cancels; Esc at a secret keeps the account and says what is missing', async () => {
	const first = await setup();
	await first.ui.press('\r');
	await first.ui.press(ESC, 80);
	assert.equal(first.closed(), 1);
	assert.deepEqual(await first.store.list(), []);
	first.ui.unmount();

	const second = await setup(true);
	for (let i = 0; i < 3; i++) await second.ui.press(DOWN);
	await second.ui.press('\r');
	await second.ui.press('pay');
	await second.ui.press('\r');
	await second.ui.press('acct_1');
	await second.ui.press('\r');
	await until(() => /token for pay/.test(second.ui.last()));
	await second.ui.press(ESC, 80);
	assert.match(second.ui.last(), /Still needed: token/);
	assert.equal((await second.store.list()).length, 1);
	second.ui.unmount();
});

test('the kind picker leaves out claude-login; an invalid Anthropic key shows the error and stays on the step', async () => {
	const {store, ui} = await setup();
	assert.match(ui.last(), /anthropic-key \(built in\)/);
	assert.match(ui.last(), /anthropic-token \(built in\)/);
	assert.doesNotMatch(ui.all(), /claude-login/);
	await ui.press(DOWN);
	await ui.press('\r');
	await ui.press('k1');
	await ui.press('\r');
	await until(() => /key for k1/.test(ui.last()));
	await ui.press('not-a-key');
	await ui.press('\r');
	await until(() => /Not an Anthropic API key/.test(ui.last()));
	assert.match(ui.last(), /key for k1/);
	const fake = 'sk-ant-api03-' + 'W1zard_'.repeat(5);
	await ui.press(fake);
	await ui.press('\r');
	await until(() => /created/.test(ui.last()));
	assert.ok(!ui.all().includes(fake));
	assert.equal(await store.secret('k1', 'key'), fake);
	ui.unmount();
});
