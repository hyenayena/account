import assert from 'node:assert/strict';
import {test} from 'node:test';
import {BUILTIN_KINDS} from '../src/kinds.js';
import {checkSecret, MAX_LOGIN, maxSecretOf, secretLeaves} from '../src/validate.js';
import {stripe} from './helpers.js';

const kind = (name: string) => BUILTIN_KINDS.find(k => k.name === name)!;
const fakeKey = 'sk-ant-api03-' + 'A1b2_-'.repeat(8);
const fakeToken = 'sk-ant-oat01-' + 'Z9y8_-'.repeat(8);

function refused(k: string, field: string, value: string, message: RegExp) {
	assert.throws(
		() => checkSecret(kind(k), field, value),
		(error: Error) => {
			assert.match(error.message, message);
			assert.ok(value.length < 8 || !error.message.includes(value), 'the value is echoed');
			return true;
		},
	);
}

test('anthropic-key: sk-ant- but not a subscription token', () => {
	checkSecret(kind('anthropic-key'), 'key', fakeKey);
	refused('anthropic-key', 'key', fakeToken, /^Not an Anthropic API key \(sk-ant-…\)$/);
	refused('anthropic-key', 'key', 'sk-ant-short', /Not an Anthropic API key/);
	refused('anthropic-key', 'key', 'ghp_' + 'x'.repeat(36), /Not an Anthropic API key/);
	refused('anthropic-key', 'key', `${fakeKey} extra`, /Not an Anthropic API key/);
});

test('anthropic-token: sk-ant-oat only', () => {
	checkSecret(kind('anthropic-token'), 'token', fakeToken);
	refused('anthropic-token', 'token', fakeKey, /^Not an Anthropic subscription token \(sk-ant-oat…\)$/);
	refused('anthropic-token', 'token', 'sk-ant-oat01-x', /Not an Anthropic subscription token/);
});

test('claude-login: a JSON object with an OAuth login or a Console key, at most 64 KiB', () => {
	const oauth = JSON.stringify({credentials: {claudeAiOauth: {accessToken: 'a'.repeat(30)}}});
	const consoleKey = JSON.stringify({primaryApiKey: fakeKey});
	checkSecret(kind('claude-login'), 'login', oauth);
	checkSecret(kind('claude-login'), 'login', consoleKey);
	for (const bad of ['', 'not json', '[]', '"x"', '{}', JSON.stringify({credentials: {claudeAiOauth: 'x'}}), JSON.stringify({primaryApiKey: ''})]) {
		refused('claude-login', 'login', bad, /^Not a Claude Code login/);
	}
	const big = JSON.stringify({primaryApiKey: fakeKey, pad: 'p'.repeat(MAX_LOGIN)});
	refused('claude-login', 'login', big, /at most 64 KiB/);
	assert.equal(maxSecretOf(kind('claude-login'), 'login'), MAX_LOGIN);
	assert.equal(maxSecretOf(kind('anthropic-key'), 'key'), 8192);
});

test('other fields: 1 to 8192 characters', () => {
	checkSecret(stripe, 'token', 'x');
	checkSecret(undefined, 'token', 'x'.repeat(8192));
	assert.throws(() => checkSecret(stripe, 'token', ''), /1 to 8192 characters/);
	assert.throws(() => checkSecret(stripe, 'token', 'x'.repeat(8193)), /1 to 8192 characters/);
});

test('secretLeaves: long string leaves of a JSON object, nothing for other values', () => {
	const access = 'a'.repeat(40);
	const refresh = 'r'.repeat(16);
	const blob = JSON.stringify({
		credentials: {claudeAiOauth: {accessToken: access, refreshToken: refresh, expiresAt: 123, scopes: ['user:inference', 'x'.repeat(20)]}},
		oauthAccount: {emailAddress: 'someone.long@example.com'},
		short: 'abc',
	});
	assert.deepEqual(secretLeaves(blob).sort(), [access, refresh, 'x'.repeat(20)].sort());
	assert.deepEqual(secretLeaves(fakeKey), []);
	assert.deepEqual(secretLeaves('[1,2]'), []);
});
